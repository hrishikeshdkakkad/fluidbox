//! AWS Signature Version 4 — header authentication, single-chunk payload.
//!
//! Hand-rolled on purpose (Phase F, Task 4). The archive store needs exactly
//! four S3 verbs against one prefix (PUT / GET / DELETE / ListObjectsV2);
//! `aws-sdk-s3`, `object_store` and `opendal` each drag a large dependency tree
//! through `cargo deny` for that, and the signing itself is ~150 lines of
//! HMAC-SHA256 that AWS publishes exact test vectors for.
//!
//! Everything here is PURE — the timestamp, the credentials, the headers and the
//! payload digest are all arguments — so AWS's published examples drive the real
//! signer directly rather than a re-derivation of it. See the tests at the foot
//! of this file: they assert both the intermediate canonical-request digest and
//! the final signature for four documented S3 requests plus the documented
//! signing-key derivation, so a break localizes to the stage that broke.
//!
//! NOT implemented (and not needed here): chunked/streaming payload signing
//! (`STREAMING-AWS4-HMAC-SHA256-PAYLOAD`), presigned query authentication, and
//! SigV4a. The archive PUT is one sized request whose SHA-256 the packer already
//! computed while writing the file.

use hmac::digest::KeyInit;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

/// The algorithm token that opens both the credential line and the string-to-sign.
pub const ALGORITHM: &str = "AWS4-HMAC-SHA256";

/// Static S3 credentials. `session_token` is carried so an operator CAN paste
/// STS/`AssumeRole` output, but nothing here refreshes it — see the module docs
/// on `store.rs` for what that does and does not support.
#[derive(Clone)]
pub struct Credentials {
    pub access_key_id: String,
    pub secret_access_key: String,
    pub session_token: Option<String>,
}

impl std::fmt::Debug for Credentials {
    /// Never render the secret: this type ends up inside a `Debug` store, which
    /// ends up in a log line the moment anyone adds one.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Credentials")
            .field("access_key_id", &self.access_key_id)
            .field("secret_access_key", &"<redacted>")
            .field(
                "session_token",
                &self.session_token.as_ref().map(|_| "<redacted>"),
            )
            .finish()
    }
}

/// A signed request's outputs. `canonical_request_sha256` and `signature` are
/// exposed so the published AWS vectors can assert the INTERMEDIATE stage as
/// well as the final header — a mismatch then names which half is wrong.
#[derive(Debug, PartialEq, Eq)]
pub struct Signed {
    pub authorization: String,
    pub canonical_request_sha256: String,
    pub signature: String,
}

fn hex_sha256(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn hmac(key: &[u8], msg: &[u8]) -> Vec<u8> {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("hmac accepts any key length");
    mac.update(msg);
    mac.finalize().into_bytes().to_vec()
}

/// The date/region/service-scoped signing key: `HMAC` chained four times from
/// `"AWS4" + secret`. Separate and public so AWS's own derivation vector can
/// test it in isolation.
pub fn signing_key(secret: &str, date: &str, region: &str, service: &str) -> Vec<u8> {
    let k_date = hmac(format!("AWS4{secret}").as_bytes(), date.as_bytes());
    let k_region = hmac(&k_date, region.as_bytes());
    let k_service = hmac(&k_region, service.as_bytes());
    hmac(&k_service, b"aws4_request")
}

/// RFC 3986 percent-encoding with AWS's unreserved set (`A-Za-z0-9-_.~`).
///
/// `encode_slash` is the whole subtlety: in a canonical PATH, S3 leaves `/`
/// alone (and, unlike every other AWS service, does NOT double-encode the path);
/// in a canonical QUERY, `/` must be `%2F` — which matters because a
/// ListObjectsV2 continuation token is base64 and routinely contains `/` and
/// `+`. Hex digits are UPPERCASE, as the spec requires.
pub fn uri_encode(s: &str, encode_slash: bool) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.as_bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(*b as char)
            }
            b'/' if !encode_slash => out.push('/'),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// Build the canonical query string: every key and value percent-encoded
/// (`/` included), sorted by encoded key then encoded value, always `k=v` so a
/// valueless parameter (`?lifecycle`) canonicalizes as `lifecycle=`.
pub fn canonical_query(params: &[(String, String)]) -> String {
    let mut encoded: Vec<(String, String)> = params
        .iter()
        .map(|(k, v)| (uri_encode(k, true), uri_encode(v, true)))
        .collect();
    encoded.sort();
    encoded
        .iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join("&")
}

/// Sign one request. `headers` are matched case-insensitively (lowercased here)
/// and must already include `host` and every `x-amz-*` header that will actually
/// be sent — a header on the wire but not in this map produces a signature the
/// service will reject, which is the failure mode the fake-S3 tests in
/// `store.rs` exist to catch.
#[allow(clippy::too_many_arguments)]
pub fn sign(
    creds: &Credentials,
    region: &str,
    service: &str,
    amz_date: &str,
    method: &str,
    canonical_uri: &str,
    canonical_query_string: &str,
    headers: &BTreeMap<String, String>,
    payload_sha256: &str,
) -> Signed {
    // A BTreeMap keyed on the LOWERCASED name gives the spec's ordering for
    // free; values are trimmed (the spec also collapses internal runs of
    // whitespace, which no header we send contains).
    let lowered: BTreeMap<String, String> = headers
        .iter()
        .map(|(k, v)| (k.to_ascii_lowercase(), v.trim().to_string()))
        .collect();
    let signed_headers = lowered.keys().cloned().collect::<Vec<_>>().join(";");
    let canonical_headers: String = lowered.iter().map(|(k, v)| format!("{k}:{v}\n")).collect();

    let canonical_request = format!(
        "{method}\n{canonical_uri}\n{canonical_query_string}\n{canonical_headers}\n{signed_headers}\n{payload_sha256}"
    );
    let canonical_request_sha256 = hex_sha256(canonical_request.as_bytes());

    // `amz_date` is YYYYMMDDTHHMMSSZ; the scope takes only the date half.
    let date = &amz_date[..8.min(amz_date.len())];
    let scope = format!("{date}/{region}/{service}/aws4_request");
    let string_to_sign = format!("{ALGORITHM}\n{amz_date}\n{scope}\n{canonical_request_sha256}");
    let signature = hex::encode(hmac(
        &signing_key(&creds.secret_access_key, date, region, service),
        string_to_sign.as_bytes(),
    ));

    Signed {
        authorization: format!(
            "{ALGORITHM} Credential={}/{scope}, SignedHeaders={signed_headers}, Signature={signature}",
            creds.access_key_id
        ),
        canonical_request_sha256,
        signature,
    }
}

/// SHA-256 of an empty payload — the `x-amz-content-sha256` of every GET,
/// DELETE and LIST we issue.
pub const EMPTY_PAYLOAD_SHA256: &str =
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

#[cfg(test)]
mod tests {
    use super::*;

    /// AWS's published S3 examples ("Examples: Signature Calculations for the
    /// Authorization Header, Transferring Payload in a Single Chunk"), driven
    /// through the REAL signer. All four share these credentials/scope.
    fn example_creds() -> Credentials {
        Credentials {
            access_key_id: "AKIAIOSFODNN7EXAMPLE".into(),
            secret_access_key: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY".into(),
            session_token: None,
        }
    }

    fn hdrs(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    fn check(
        method: &str,
        uri: &str,
        query: &str,
        headers: &[(&str, &str)],
        payload: &str,
        expect_cr: &str,
        expect_sig: &str,
    ) {
        let got = sign(
            &example_creds(),
            "us-east-1",
            "s3",
            "20130524T000000Z",
            method,
            uri,
            query,
            &hdrs(headers),
            payload,
        );
        assert_eq!(
            got.canonical_request_sha256, expect_cr,
            "canonical request digest for {method} {uri}"
        );
        assert_eq!(got.signature, expect_sig, "signature for {method} {uri}");
        // The Authorization header must carry the same signature and the scope.
        assert!(
            got.authorization
                .ends_with(&format!("Signature={expect_sig}")),
            "{}",
            got.authorization
        );
        assert!(got
            .authorization
            .contains("Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request"));
    }

    #[test]
    fn aws_vector_get_object() {
        check(
            "GET",
            "/test.txt",
            "",
            &[
                ("Host", "examplebucket.s3.amazonaws.com"),
                ("Range", "bytes=0-9"),
                ("x-amz-content-sha256", EMPTY_PAYLOAD_SHA256),
                ("x-amz-date", "20130524T000000Z"),
            ],
            EMPTY_PAYLOAD_SHA256,
            "7344ae5b7ee6c3e7e6b0fe0640412a37625d1fbfff95c48bbb2dc43964946972",
            "f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41",
        );
    }

    #[test]
    fn aws_vector_put_object() {
        // Body "Welcome to Amazon S3." — the vector's own payload digest, and
        // the `$` in the key exercises path percent-encoding (`%24`).
        let payload = "44ce7dd67c959e0d3524ffac1771dfbba87d2b6b4b4e99e42034a8b803f8b072";
        assert_eq!(hex_sha256(b"Welcome to Amazon S3."), payload);
        assert_eq!(uri_encode("/test$file.text", false), "/test%24file.text");
        check(
            "PUT",
            "/test%24file.text",
            "",
            &[
                ("Date", "Fri, 24 May 2013 00:00:00 GMT"),
                ("Host", "examplebucket.s3.amazonaws.com"),
                ("x-amz-content-sha256", payload),
                ("x-amz-date", "20130524T000000Z"),
                ("x-amz-storage-class", "REDUCED_REDUNDANCY"),
            ],
            payload,
            "9e0e90d9c76de8fa5b200d8c849cd5b8dc7a3be3951ddb7f6a76b4158342019d",
            "98ad721746da40c64f1a55b78f14c238d841ea1380cd77a1b5971af0ece108bd",
        );
    }

    #[test]
    fn aws_vector_get_bucket_lifecycle() {
        // `?lifecycle` — a valueless query parameter canonicalizes to `lifecycle=`.
        assert_eq!(
            canonical_query(&[("lifecycle".into(), String::new())]),
            "lifecycle="
        );
        check(
            "GET",
            "/",
            "lifecycle=",
            &[
                ("Host", "examplebucket.s3.amazonaws.com"),
                ("x-amz-content-sha256", EMPTY_PAYLOAD_SHA256),
                ("x-amz-date", "20130524T000000Z"),
            ],
            EMPTY_PAYLOAD_SHA256,
            "9766c798316ff2757b517bc739a67f6213b4ab36dd5da2f94eaebf79c77395ca",
            "fea454ca298b7da1c68078a5d1bdbfbbe0d65c699e0f91ac7a200a0136783543",
        );
    }

    #[test]
    fn aws_vector_list_objects() {
        // The list shape this store actually uses: multiple query parameters,
        // canonicalized through the REAL `canonical_query` (sorted, encoded).
        let q = canonical_query(&[
            ("prefix".into(), "J".into()),
            ("max-keys".into(), "2".into()),
        ]);
        assert_eq!(q, "max-keys=2&prefix=J");
        check(
            "GET",
            "/",
            &q,
            &[
                ("Host", "examplebucket.s3.amazonaws.com"),
                ("x-amz-content-sha256", EMPTY_PAYLOAD_SHA256),
                ("x-amz-date", "20130524T000000Z"),
            ],
            EMPTY_PAYLOAD_SHA256,
            "df57d21db20da04d7fa30298dd4488ba3a2b47ca3a489c74750e0f1e7df1b9b7",
            "34b48302e7b5fa45bde8084f4b7868a86f0a534bc59db6670ed5711ef69dc6f7",
        );
    }

    /// AWS's published signing-key derivation example (IAM, 20120215). Tests the
    /// four-stage HMAC chain on its own, so a scope/date bug is distinguishable
    /// from a canonical-request bug above.
    #[test]
    fn aws_vector_signing_key_derivation() {
        let k = signing_key(
            "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
            "20120215",
            "us-east-1",
            "iam",
        );
        assert_eq!(
            hex::encode(k),
            "f4780e2d9f65fa895f9c67b32ce1baf0b0d8a43505a000a1a9e090d414db404d"
        );
    }

    /// FALSE-GREEN guard: the vectors above would still pass if the signer
    /// ignored an input. Perturb each input in turn and require the signature to
    /// MOVE — a signer that dropped the payload digest, the region, the date or
    /// a header would otherwise look correct on every vector it was tuned to.
    #[test]
    fn every_input_changes_the_signature() {
        let base = sign(
            &example_creds(),
            "us-east-1",
            "s3",
            "20130524T000000Z",
            "GET",
            "/test.txt",
            "",
            &hdrs(&[
                ("Host", "examplebucket.s3.amazonaws.com"),
                ("x-amz-date", "20130524T000000Z"),
            ]),
            EMPTY_PAYLOAD_SHA256,
        );
        let variants: Vec<Signed> = vec![
            // different region
            sign(
                &example_creds(),
                "eu-west-1",
                "s3",
                "20130524T000000Z",
                "GET",
                "/test.txt",
                "",
                &hdrs(&[
                    ("Host", "examplebucket.s3.amazonaws.com"),
                    ("x-amz-date", "20130524T000000Z"),
                ]),
                EMPTY_PAYLOAD_SHA256,
            ),
            // different date (scope AND string-to-sign)
            sign(
                &example_creds(),
                "us-east-1",
                "s3",
                "20130525T000000Z",
                "GET",
                "/test.txt",
                "",
                &hdrs(&[
                    ("Host", "examplebucket.s3.amazonaws.com"),
                    ("x-amz-date", "20130525T000000Z"),
                ]),
                EMPTY_PAYLOAD_SHA256,
            ),
            // different method
            sign(
                &example_creds(),
                "us-east-1",
                "s3",
                "20130524T000000Z",
                "DELETE",
                "/test.txt",
                "",
                &hdrs(&[
                    ("Host", "examplebucket.s3.amazonaws.com"),
                    ("x-amz-date", "20130524T000000Z"),
                ]),
                EMPTY_PAYLOAD_SHA256,
            ),
            // different path
            sign(
                &example_creds(),
                "us-east-1",
                "s3",
                "20130524T000000Z",
                "GET",
                "/other.txt",
                "",
                &hdrs(&[
                    ("Host", "examplebucket.s3.amazonaws.com"),
                    ("x-amz-date", "20130524T000000Z"),
                ]),
                EMPTY_PAYLOAD_SHA256,
            ),
            // different query
            sign(
                &example_creds(),
                "us-east-1",
                "s3",
                "20130524T000000Z",
                "GET",
                "/test.txt",
                "list-type=2",
                &hdrs(&[
                    ("Host", "examplebucket.s3.amazonaws.com"),
                    ("x-amz-date", "20130524T000000Z"),
                ]),
                EMPTY_PAYLOAD_SHA256,
            ),
            // extra signed header
            sign(
                &example_creds(),
                "us-east-1",
                "s3",
                "20130524T000000Z",
                "GET",
                "/test.txt",
                "",
                &hdrs(&[
                    ("Host", "examplebucket.s3.amazonaws.com"),
                    ("x-amz-date", "20130524T000000Z"),
                    ("x-amz-security-token", "tok"),
                ]),
                EMPTY_PAYLOAD_SHA256,
            ),
            // different payload digest
            sign(
                &example_creds(),
                "us-east-1",
                "s3",
                "20130524T000000Z",
                "GET",
                "/test.txt",
                "",
                &hdrs(&[
                    ("Host", "examplebucket.s3.amazonaws.com"),
                    ("x-amz-date", "20130524T000000Z"),
                ]),
                "44ce7dd67c959e0d3524ffac1771dfbba87d2b6b4b4e99e42034a8b803f8b072",
            ),
            // different secret
            sign(
                &Credentials {
                    access_key_id: "AKIAIOSFODNN7EXAMPLE".into(),
                    secret_access_key: "another-secret".into(),
                    session_token: None,
                },
                "us-east-1",
                "s3",
                "20130524T000000Z",
                "GET",
                "/test.txt",
                "",
                &hdrs(&[
                    ("Host", "examplebucket.s3.amazonaws.com"),
                    ("x-amz-date", "20130524T000000Z"),
                ]),
                EMPTY_PAYLOAD_SHA256,
            ),
        ];
        for (i, v) in variants.iter().enumerate() {
            assert_ne!(
                v.signature, base.signature,
                "variant {i} did not change the signature — an input is being ignored"
            );
        }
    }

    #[test]
    fn uri_encode_matches_the_spec_sets() {
        // Unreserved survive; everything else is uppercase-hex percent-encoded.
        assert_eq!(uri_encode("aZ09-_.~", false), "aZ09-_.~");
        assert_eq!(uri_encode("a b+c", false), "a%20b%2Bc");
        // The `/` split: kept in a path, encoded in a query.
        assert_eq!(uri_encode("a/b", false), "a/b");
        assert_eq!(uri_encode("a/b", true), "a%2Fb");
        // A base64 continuation token is exactly why the query encoder exists.
        assert_eq!(uri_encode("a+b/c=", true), "a%2Bb%2Fc%3D");
        // Non-ASCII is encoded byte-wise (UTF-8), not char-wise.
        assert_eq!(uri_encode("é", false), "%C3%A9");
    }

    #[test]
    fn canonical_query_sorts_by_encoded_key() {
        let q = canonical_query(&[
            ("prefix".into(), "archives/".into()),
            ("list-type".into(), "2".into()),
            ("continuation-token".into(), "a+b/c=".into()),
        ]);
        assert_eq!(
            q,
            "continuation-token=a%2Bb%2Fc%3D&list-type=2&prefix=archives%2F"
        );
    }

    #[test]
    fn credentials_debug_never_prints_the_secret() {
        let d = format!(
            "{:?}",
            Credentials {
                access_key_id: "AKIA".into(),
                secret_access_key: "SUPERSECRET".into(),
                session_token: Some("TOKEN".into()),
            }
        );
        assert!(!d.contains("SUPERSECRET"), "{d}");
        assert!(!d.contains("TOKEN"), "{d}");
        assert!(d.contains("AKIA"), "{d}");
    }
}
