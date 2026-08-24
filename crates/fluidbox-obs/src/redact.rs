//! Secret scrubbing for the LOG path.
//!
//! # Why this exists separately from `fluidbox-core::event::Redactor`
//!
//! The core Redactor guards the **ledger**: it is the only door into
//! `append_event`, and its contract is "a `Redacted<EventEnvelope>` is
//! constructible solely via `Redactor::scrub`". That is a type-level guarantee
//! about one database table.
//!
//! Logs are a *different* egress with the same hazard and none of that
//! guarantee. A `tracing::warn!("fetch failed: {e}")` whose `e` is a reqwest
//! error carrying a URL with `?code=…`, or a sqlx error quoting a connection
//! string, walks straight out to stdout — and from there to whatever log
//! aggregator the deployment ships to, which is very often a third party with a
//! different retention policy and a different access-control list than the
//! database. Before this module, that path had no filter at all.
//!
//! # Why the pattern list is duplicated rather than shared
//!
//! Two reasons, in order of weight:
//!
//! 1. **Dependency direction.** This crate is a leaf so that every other crate
//!    can log through it. Importing `fluidbox-core` here would invert the
//!    workspace's dependency order and forbid `fluidbox-core` from ever logging.
//!
//! 2. **Independent restatement is a feature**, and the codebase already relies
//!    on it: `fluidbox-core::event::SESSION_TOKEN_PREFIX` documents that the
//!    Redactor's rule is "a DELIBERATELY independent regex literal … change the
//!    minted prefix and the samples move while the rule does not, so the test
//!    fails instead of moving with it". The same logic applies across crates.
//!
//! The hazard of duplication — a new secret shape taught to one redactor and not
//! the other — is answered by a PARITY TEST in `fluidbox-core`
//! (`event::tests::log_redactor_covers_every_ledger_secret_shape`) that feeds one
//! corpus of realistic secrets through both and fails if either lets one
//! through. Duplication without a tripwire is a bug; duplication with one is
//! defence in depth.
//!
//! # Two independent mechanisms
//!
//! **Value patterns** ([`Redactor::scrub`]) catch secrets by *shape*:
//! `fbx_sess_…`, `ghp_…`, a bearer header, a PEM block, `?code=…`. They work
//! wherever the secret appears — inside an interpolated message, inside a
//! `Debug` rendering, nested in a JSON blob.
//!
//! **Field names** ([`sensitive_field`]) catch secrets by *position*: anything
//! recorded under a field called `client_secret`, `password`, or `authorization`
//! is replaced wholesale, never inspected. This is the half that matters most,
//! because the highest-value secrets in this system have NO recognisable shape —
//! a 32-byte KEK, a LiteLLM virtual key, a webhook HMAC secret and a random
//! database password are all just entropy, and no regex will ever match them.
//! Shape-matching alone is a false sense of safety; the two together mean a
//! secret has to be BOTH shapeless AND recorded under an innocuous field name to
//! escape, which is a bug we can name in review rather than a class we cannot
//! see.

use regex::{Regex, RegexSet};
use std::borrow::Cow;

/// What a redacted span of text is replaced with. Matches the ledger
/// Redactor's marker byte-for-byte so an operator greps one string across the
/// timeline and the logs.
pub const PLACEHOLDER: &str = "‹redacted›";

/// `(pattern, replacement)` pairs. The replacement may reference capture groups
/// with `${n}` — used where keeping the *key* is useful for debugging while the
/// *value* must go (`code=‹redacted›` tells you an authorization code was
/// present, which is exactly the diagnostic you want, without being one).
///
/// Ordering is irrelevant to correctness (every matching pattern is applied),
/// but the list is grouped by family to keep review tractable.
const PATTERNS: &[(&str, &str)] = &[
    // ── fluidbox's own credentials ──────────────────────────────────────────
    // Every runner session credential (all four Gap-10 audiences), trigger
    // tokens, browser-session cookies and PATs share the `fbx_` namespace.
    (r"fbx_(sess|trig|web|pat)_[A-Za-z0-9_\-]{8,}", PLACEHOLDER),
    // ── model-provider keys ─────────────────────────────────────────────────
    (r"sk-ant-[A-Za-z0-9_\-]{8,}", PLACEHOLDER),
    (r"sk-proj-[A-Za-z0-9_\-]{16,}", PLACEHOLDER),
    (r"sk-[A-Za-z0-9]{20,}", PLACEHOLDER),
    // ── git forge ───────────────────────────────────────────────────────────
    (r"gh[pousr]_[A-Za-z0-9]{20,}", PLACEHOLDER),
    (r"github_pat_[A-Za-z0-9_]{20,}", PLACEHOLDER),
    // ── cloud / infra ───────────────────────────────────────────────────────
    (r"AKIA[0-9A-Z]{16}", PLACEHOLDER),
    (r"ASIA[0-9A-Z]{16}", PLACEHOLDER),
    (r"AIza[0-9A-Za-z_\-]{35}", PLACEHOLDER),
    (r"xox[baprs]-[A-Za-z0-9\-]{10,}", PLACEHOLDER),
    (r"npg_[A-Za-z0-9]{8,}", PLACEHOLDER),
    (r"(?i)glpat-[A-Za-z0-9_\-]{16,}", PLACEHOLDER),
    // ── transport-level credentials ─────────────────────────────────────────
    // A bearer token in a header rendering or an error string.
    (r"(?i)bearer\s+[A-Za-z0-9\._\-~\+/]{16,}=*", PLACEHOLDER),
    (r"(?i)basic\s+[A-Za-z0-9\+/]{16,}=*", PLACEHOLDER),
    // A JWT, wherever it appears — this is what an OIDC id_token, a GitHub App
    // JWT and a LiteLLM key all look like on the wire.
    (
        r"eyJ[A-Za-z0-9_\-]{8,}\.eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}",
        PLACEHOLDER,
    ),
    // ── connection strings ──────────────────────────────────────────────────
    // Any `scheme://user:password@host` — postgres, redis, amqp, https alike.
    (
        r"([a-zA-Z][a-zA-Z0-9+.\-]*://[^\s:/@]+):[^@\s/]+@",
        "${1}:‹redacted›@",
    ),
    // ── OAuth / OIDC material carried in query strings or form bodies ───────
    // TWO patterns, split on ambiguity — this is the single most delicate
    // trade-off in the list.
    //
    // (a) URL/fragment context ONLY. `code` and `state` are the parameters the
    // codebase already refuses to log ("never the query string: OAuth
    // `code`/`state` and GitHub flow tokens ride queries") — but they are also
    // two of the most common ordinary field names in any system. Requiring a
    // `?`/`&`/`#` prefix means the OAuth ones are caught and a plain
    // `state=running` or `code=404` in a message is left alone. Widening this to
    // a bare word boundary was tried and rejected: it silently redacted run
    // status out of the very lines an operator reads to debug a run.
    (
        r#"(?i)([?&#])(code|state|session_state|token|access_token|id_token|refresh_token|client_secret|code_verifier|assertion|password)=[^&\s"'>]+"#,
        "${1}${2}=‹redacted›",
    ),
    // (b) Anywhere, for names that are unambiguous wherever they appear. Accepts
    // `=` or `:` with optional quoting so it catches both a form body and a
    // `Debug` rendering of a struct or a JSON blob.
    //
    // The `Debug` case is why the `[a-z0-9]+_token` / `_secret` / `_sealed`
    // wildcards are here. [`sensitive_field`] blanks a value by the name it was
    // RECORDED under, which covers `warn!(client_secret = …)` and covers nothing
    // nested: a struct logged as `?resp` renders to one string, and a credential
    // two levels down inside it — `Headers { authorization: "…" }` — is invisible
    // to a field-name check and, if it has no recognisable shape (a stripped
    // session token, a random password), invisible to every value pattern too.
    // Matching the name INSIDE the rendering closes that.
    //
    // The optional `"` after the name is what makes this work on a JSON-ish
    // rendering (`{"cookie": "sid=…"}`) as well as a Rust `Debug` one
    // (`Headers { cookie: "sid=…" }`) — both shapes turn up in an error string,
    // and a rule that only handles one is a rule with a hole in it.
    //
    // The wildcards deliberately stop short of `[a-z0-9]+_key`: that would eat
    // `cache_key`, `idempotency_key` and `partition_key`, which are join keys an
    // operator needs. The specific `_key` names worth catching are listed above
    // by hand instead.
    (
        r#"(?i)\b(authorization|cookie|access_token|id_token|refresh_token|session_token|client_secret|code_verifier|private_key|api_key|apikey|password|passwd|passphrase|webhook_secret|secret_key|master_key|client_assertion|[a-z0-9]+_token|[a-z0-9]+_secret|[a-z0-9]+_sealed)\b"?\s*[:=]\s*"?([^\s,;}"'&]{4,})"#,
        "${1}=‹redacted›",
    ),
    // ── asymmetric key material ─────────────────────────────────────────────
    // A PEM private key — the GitHub App custody secret. `(?s)` so `.` spans the
    // newlines a real PEM block contains.
    (
        r"(?s)-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----",
        PLACEHOLDER,
    ),
    // ── shapeless secrets named in prose ────────────────────────────────────
    // The families with no recognisable shape at all: a KEK, a DEK, a webhook
    // HMAC secret. Only reachable when the name appears immediately before an
    // assignment, which is deliberately narrow — this pattern is the last line
    // of defence for a value that no other rule can recognise, not a general
    // entropy detector (there is no such thing that does not also eat digests,
    // UUIDs, and base64 diffs).
    (
        r#"(?i)\b(secret|credential|kek|dek|bearer_token|session_secret)\b(\s*[:=]\s*)"?([^\s,;}"']{6,})"#,
        "${1}${2}‹redacted›",
    ),
];

/// Compiled secret matcher. Construct once and share (`Clone` is cheap-ish but
/// the intended pattern is one process-wide instance held by the formatter).
pub struct Redactor {
    /// Single-pass "does anything match at all?" prefilter. On the overwhelming
    /// majority of log lines this answers no, and [`Redactor::scrub`] returns a
    /// borrowed `Cow` having allocated nothing.
    set: RegexSet,
    /// Per-pattern replacers, indexed in lockstep with `set`.
    pats: Vec<Regex>,
    /// Replacement templates, indexed in lockstep with `pats`.
    reps: Vec<&'static str>,
}

impl Default for Redactor {
    fn default() -> Self {
        Self::new()
    }
}

impl Redactor {
    /// Compile the pattern set.
    ///
    /// # Panics
    /// Only on a malformed literal in [`PATTERNS`], which is a compile-time-fixed
    /// list covered by tests — i.e. never at runtime in a shipped binary. This is
    /// the same posture as `fluidbox-core`'s Redactor.
    pub fn new() -> Self {
        let pats: Vec<Regex> = PATTERNS
            .iter()
            .map(|(p, _)| Regex::new(p).expect("fluidbox-obs: malformed redaction pattern"))
            .collect();
        let set = RegexSet::new(PATTERNS.iter().map(|(p, _)| *p))
            .expect("fluidbox-obs: malformed redaction pattern set");
        Self {
            set,
            pats,
            reps: PATTERNS.iter().map(|(_, r)| *r).collect(),
        }
    }

    /// Replace every secret-shaped span in `s`.
    ///
    /// Returns [`Cow::Borrowed`] unchanged when nothing matched, which is the
    /// hot path: one `RegexSet` pass, zero allocations. When something does
    /// match, only the patterns that actually matched are re-run.
    pub fn scrub<'a>(&self, s: &'a str) -> Cow<'a, str> {
        let hits = self.set.matches(s);
        if !hits.matched_any() {
            return Cow::Borrowed(s);
        }
        let mut out = Cow::Borrowed(s);
        for i in hits.iter() {
            // `replace_all` on a Cow keeps us from allocating once per pattern
            // when several match: each round consumes the previous string.
            let replaced = self.pats[i].replace_all(&out, self.reps[i]).into_owned();
            out = Cow::Owned(replaced);
        }
        out
    }

    /// True when `s` contains anything this redactor would remove. Used by tests
    /// and by the self-check that runs at subscriber init.
    pub fn is_dirty(&self, s: &str) -> bool {
        self.set.is_match(s)
    }
}

/// Field names whose VALUE is never logged, whatever it looks like.
///
/// Checked before any pattern matching and before the value is even rendered,
/// so a shapeless secret (a raw KEK, a random password, a LiteLLM virtual key)
/// is caught by *where* it was recorded rather than by *what it looks like*.
///
/// The `_id` / `_version` / structural-key exceptions are explicit: `token_id`
/// and `key_version` are join keys an operator genuinely needs, and blanket
/// substring matching on `token` or `key` would throw them away while adding no
/// safety.
pub fn sensitive_field(name: &str) -> bool {
    // Structural keys that LOOK sensitive by suffix but carry no secret. Checked
    // first so the suffix rules below cannot swallow them.
    const ALLOW: &[&str] = &[
        "token_id",
        "key_version",
        "key_id",
        "kms_key_id",
        "idempotency_key",
        "cache_key",
        "dedup_key",
        "partition_key",
        "sort_key",
        "primary_key",
        "route_key",
        "secret_id",
        "credential_id",
        "credential_kind",
        "auth_kind",
        "token_kind",
        "token_audience",
        "has_token",
        "has_secret",
        "has_credential",
        "secret_present",
        "token_prefix",
        "key_mode",
        "signing_key_id",
    ];
    if ALLOW.contains(&name) {
        return false;
    }
    const EXACT: &[&str] = &[
        "authorization",
        "proxy_authorization",
        "cookie",
        "set_cookie",
        "password",
        "passwd",
        "passphrase",
        "secret",
        "token",
        "credential",
        "credentials",
        "api_key",
        "apikey",
        "pem",
        "kek",
        "dek",
        "signature",
        "verifier",
        "code_verifier",
        "client_assertion",
        "authorization_code",
        "oauth_state",
        "session_token",
        "bearer",
        "key",
    ];
    if EXACT.contains(&name) {
        return true;
    }
    const SUFFIX: &[&str] = &[
        "_token",
        "_secret",
        "_password",
        "_passphrase",
        "_credential",
        "_credentials",
        "_key",
        "_pem",
        "_sealed",
        "_signature",
        "_verifier",
        "_cookie",
        "_authorization",
    ];
    SUFFIX.iter().any(|s| name.ends_with(s))
}

/// One realistic secret from every credential family this control plane
/// handles, published (not test-gated) so **other crates can assert parity
/// against it**.
///
/// `fluidbox-core`'s ledger Redactor and this crate's log Redactor are
/// deliberately independent restatements of the same rule; this corpus is the
/// tripwire that keeps them honest. Each entry is
/// `(family, realistic_rendering, the_substring_that_must_not_survive)` — the
/// third element matters because several patterns intentionally PRESERVE
/// context (a connection string keeps its host, an OAuth callback keeps the
/// parameter name), so "the whole string disappeared" is the wrong assertion and
/// would force the redactor to be blunter than it should be.
pub fn secret_corpus() -> Vec<(&'static str, String, String)> {
    let a = |c: char, n: usize| std::iter::repeat_n(c, n).collect::<String>();
    vec![
        (
            "fluidbox session token",
            format!("fbx_sess_{}", a('a', 32)),
            a('a', 32),
        ),
        (
            "fluidbox trigger token",
            format!("fbx_trig_{}", a('b', 32)),
            a('b', 32),
        ),
        (
            "fluidbox web session",
            format!("fbx_web_{}", a('c', 32)),
            a('c', 32),
        ),
        ("fluidbox pat", format!("fbx_pat_{}", a('d', 32)), a('d', 32)),
        (
            "anthropic key",
            format!("sk-ant-api03-{}", a('e', 40)),
            a('e', 40),
        ),
        ("openai key", format!("sk-{}", a('f', 32)), a('f', 32)),
        (
            "openai project key",
            format!("sk-proj-{}", a('g', 40)),
            a('g', 40),
        ),
        ("github pat", format!("ghp_{}", a('h', 36)), a('h', 36)),
        ("github oauth token", format!("gho_{}", a('i', 36)), a('i', 36)),
        (
            "github fine-grained pat",
            format!("github_pat_{}", a('j', 40)),
            a('j', 40),
        ),
        (
            "aws access key id",
            "AKIAIOSFODNN7EXAMPLE".into(),
            "AKIAIOSFODNN7EXAMPLE".into(),
        ),
        (
            "slack bot token",
            "xoxb-1234567890-abcdefghijkl".into(),
            "1234567890-abcdefghijkl".into(),
        ),
        (
            "neon password",
            format!("npg_{}", a('k', 20)),
            a('k', 20),
        ),
        (
            "bearer header",
            format!("authorization: Bearer {}", a('l', 40)),
            a('l', 40),
        ),
        (
            "jwt / id_token",
            format!("eyJ{}.eyJ{}.{}", a('m', 20), a('n', 20), a('o', 30)),
            a('o', 30),
        ),
        (
            "postgres connection string",
            "postgres://neondb_owner:s3cr3tp4ssw0rd@ep-x.aws.neon.tech/fbx".into(),
            "s3cr3tp4ssw0rd".into(),
        ),
        (
            "oauth callback url",
            "https://as.example/cb?code=abc123def456ghi&state=xyz789abcdef".into(),
            "abc123def456ghi".into(),
        ),
        (
            "pem private key",
            "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEAsecret\n-----END RSA PRIVATE KEY-----"
                .into(),
            "MIIEpAIBAAKCAQEAsecret".into(),
        ),
        (
            "client secret assignment",
            "client_secret=hunter2hunter2hunter2".into(),
            "hunter2hunter2hunter2".into(),
        ),
        (
            "shapeless kek",
            "kek=9f2c4a7e11b3d8650fa2c9e4b7d1a038".into(),
            "9f2c4a7e11b3d8650fa2c9e4b7d1a038".into(),
        ),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The headline property: no corpus secret survives a scrub, in any of the
    /// shapes a log line actually takes — bare, interpolated into a message,
    /// inside a `Debug` rendering, inside JSON, across a newline.
    #[test]
    fn every_known_secret_family_is_scrubbed_in_every_context() {
        let r = Redactor::new();
        for (family, text, must_go) in secret_corpus() {
            for ctx in [
                text.clone(),
                format!("request failed: {text}"),
                format!("url={text} status=500 attempt=3"),
                format!("{{\"detail\": \"{text}\"}}"),
                format!("Reqwest {{ inner: \"{text}\" }}"),
                format!("line one\n{text}\nline three"),
            ] {
                let out = r.scrub(&ctx);
                assert!(
                    !out.contains(&must_go),
                    "{family}: secret survived scrubbing\n  input:  {ctx}\n  output: {out}"
                );
            }
        }
    }

    /// Clean text is returned BORROWED — the allocation-free hot path. A
    /// regression here is a fresh allocation on every field of every log line.
    #[test]
    fn clean_text_is_not_copied() {
        let r = Redactor::new();
        let s = "session 018f2c transitioned running -> finalizing in 42ms";
        assert!(
            matches!(r.scrub(s), Cow::Borrowed(_)),
            "clean text was copied"
        );
    }

    /// Redaction must not eat the diagnostic. A scrubbed line still has to tell
    /// an operator what happened and where — otherwise people turn redaction off.
    #[test]
    fn scrubbing_preserves_surrounding_diagnostics() {
        let r = Redactor::new();
        let out =
            r.scrub("callback https://as.example/cb?code=abc123def456ghi&state=zzz999888 refused");
        assert!(out.contains("callback"), "{out}");
        assert!(out.contains("as.example"), "{out}");
        assert!(out.contains("code="), "the parameter NAME survives: {out}");
        assert!(out.contains("refused"), "{out}");
        assert!(!out.contains("abc123def456ghi"), "{out}");
        assert!(!out.contains("zzz999888"), "{out}");
    }

    /// A connection string keeps the host and the ROLE — both needed to tell an
    /// RLS misconfiguration from a network one — and loses only the password.
    #[test]
    fn connection_string_keeps_everything_but_the_password() {
        let r = Redactor::new();
        let out =
            r.scrub("pool error on postgres://fluidbox_runtime:hunter2hunter@db.internal:5432/fbx");
        assert!(out.contains("db.internal:5432"), "{out}");
        assert!(out.contains("fluidbox_runtime"), "{out}");
        assert!(!out.contains("hunter2hunter"), "{out}");
    }

    /// Several secrets in one line are ALL removed, not just the first — the
    /// `RegexSet` prefilter reports every matching pattern and each is applied.
    #[test]
    fn multiple_secrets_in_one_line_all_go() {
        let r = Redactor::new();
        let (gh, sess) = (
            "ghp_".to_string() + &"h".repeat(36),
            "fbx_sess_".to_string() + &"a".repeat(32),
        );
        let line = format!("retry with {gh} then {sess} against postgres://u:p4ssw0rdlong@h/db");
        let out = r.scrub(&line);
        assert!(!out.contains(&"h".repeat(36)), "{out}");
        assert!(!out.contains(&"a".repeat(32)), "{out}");
        assert!(!out.contains("p4ssw0rdlong"), "{out}");
    }

    /// The false-positive guard, and the reason `code`/`state` need a URL
    /// context: ordinary operational text must come through untouched, or
    /// redaction destroys the diagnostics it is supposed to protect.
    #[test]
    fn ordinary_operational_text_is_untouched() {
        let r = Redactor::new();
        for line in [
            "session 018f2c3d state=running attempt=2 code=404",
            "transition queued -> provisioning in 812ms",
            "tool mcp__github__list_issues allowed by policy rule 3",
            "digest sha256:9f86d081884c7d65 matched the frozen surface",
            "connection 4b1e-8f2a authorization_generation=3 status=active",
            "GET /v1/sessions/{id} 200 in 12ms",
        ] {
            assert_eq!(r.scrub(line), line, "false positive on: {line}");
        }
    }

    /// The nested case, which field-name blanking alone cannot reach: a struct
    /// logged as `?resp` renders to ONE string, and a credential two levels down
    /// inside it is invisible both to the field-name rule (the field is named
    /// `resp`) and — when the value has no recognisable shape — to every value
    /// pattern. This is the realistic leak: a failing HTTP client logged whole.
    #[test]
    fn a_credential_nested_inside_a_debug_rendering_is_still_caught() {
        let r = Redactor::new();
        for rendering in [
            r#"Response { status: 401, headers: Headers { authorization: "abcdefghijklmnop" } }"#,
            r#"Request { url: "https://x/y", headers: {"cookie": "sid=9f2c4a7e11b3d865"} }"#,
            r#"Conn { id: 4, credential_sealed: "AAAAAAAAAAAAAAAAAAAA", status: "active" }"#,
            r#"Flow { session_token: "9f2c4a7e11b3d8650fa2", stage: "callback" }"#,
            r#"Bag { refresh_token: "0102030405060708090a", expires_in: 3600 }"#,
        ] {
            let out = r.scrub(rendering);
            for leaked in [
                "abcdefghijklmnop",
                "9f2c4a7e11b3d865",
                "AAAAAAAAAAAAAAAAAAAA",
                "9f2c4a7e11b3d8650fa2",
                "0102030405060708090a",
            ] {
                assert!(!out.contains(leaked), "a nested credential survived: {out}");
            }
            // …and the diagnostic around it survives, which is the whole point
            // of logging the rendering in the first place.
            assert!(
                out.contains("status")
                    || out.contains("url")
                    || out.contains("stage")
                    || out.contains("expires_in"),
                "the rendering was over-redacted: {out}"
            );
        }
    }

    /// The wildcards must stop short of `_key`, or every join key an operator
    /// needs disappears from `Debug` renderings.
    #[test]
    fn structural_keys_survive_a_debug_rendering() {
        let r = Redactor::new();
        let out = r.scrub(r#"Claim { idempotency_key: "sched:2026-08-24T09:00", cache_key: "abc123", key_version: 2 }"#);
        assert!(out.contains("sched:2026-08-24T09:00"), "{out}");
        assert!(out.contains("abc123"), "{out}");
        assert!(out.contains("key_version: 2"), "{out}");
    }

    #[test]
    fn sensitive_fields_are_classified_by_position() {
        for f in [
            "authorization",
            "cookie",
            "password",
            "client_secret",
            "refresh_token",
            "access_token",
            "webhook_secret",
            "private_key",
            "api_key",
            "session_token",
            "code_verifier",
            "credential_sealed",
            "kek",
            "dek",
        ] {
            assert!(sensitive_field(f), "{f} should be treated as sensitive");
        }
    }

    /// The other half of the rule, and the one a careless deny-list breaks:
    /// join keys that merely LOOK sensitive must stay loggable, or correlation
    /// collapses and the logs stop answering questions.
    #[test]
    fn structural_join_keys_stay_loggable() {
        for f in [
            "token_id",
            "key_version",
            "idempotency_key",
            "cache_key",
            "tenant_id",
            "session_id",
            "connection_id",
            "auth_kind",
            "token_audience",
            "key_mode",
            "has_token",
            "status",
            "verdict",
        ] {
            assert!(!sensitive_field(f), "{f} must remain loggable");
        }
    }

    /// The `_sealed` suffix is a real column-naming convention in this schema
    /// (`credential_sealed`, `client_secret_sealed`, …). If the deny list stops
    /// covering it, ciphertext reaches stdout.
    #[test]
    fn real_sealed_column_names_are_denied() {
        for f in [
            "credential_sealed",
            "client_secret_sealed",
            "webhook_secret_sealed",
            "pem_sealed",
            "private_key_sealed",
        ] {
            assert!(sensitive_field(f), "{f} must be denied");
        }
    }

    /// Every pattern compiles, and the set is in lockstep with the replacements.
    #[test]
    fn pattern_table_is_well_formed() {
        let r = Redactor::new();
        assert_eq!(r.pats.len(), PATTERNS.len());
        assert_eq!(r.reps.len(), PATTERNS.len());
    }

    /// Scrubbing is idempotent: running it twice changes nothing the second
    /// time. A pattern that matched its own placeholder would loop-amplify a
    /// line on every pass through a nested formatter.
    #[test]
    fn scrubbing_is_idempotent() {
        let r = Redactor::new();
        for (_, text, _) in secret_corpus() {
            let once = r.scrub(&text).into_owned();
            let twice = r.scrub(&once).into_owned();
            assert_eq!(once, twice, "not idempotent for: {text}");
        }
    }
}

// ── Safe renderings ─────────────────────────────────────────────────────────

/// The host of a URL, or `None` if it has no recognisable authority.
///
/// Pure string work on purpose: a URL parser would be a dependency, and this is
/// used on a logging path that must never fail, allocate, or be slower than the
/// thing it describes. Anything it cannot parse yields `None`, and the caller
/// logs nothing rather than guessing.
pub fn url_host(url: &str) -> Option<&str> {
    let rest = url.split_once("://").map(|(_, r)| r).unwrap_or(url);
    // Strip userinfo — `https://user:pass@host/…` puts a credential before the
    // host, and the whole point of this function is to hand back something safe.
    let rest = rest.rsplit_once('@').map(|(_, r)| r).unwrap_or(rest);
    let host = rest
        .split(['/', '?', '#'])
        .next()
        .unwrap_or_default()
        .trim();
    if host.is_empty() {
        None
    } else {
        Some(host)
    }
}

/// A URL rendered for logging: scheme, host, and path — **never the query or
/// fragment**.
///
/// This is the rule the codebase already states for the HTTP trace span
/// ("Method and PATH only — never the query string: OAuth `code`/`state` and
/// GitHub flow tokens ride queries"), made reusable. Every site that wants to log "which
/// endpoint did we call" should call this rather than interpolating the URL,
/// because the interesting part (host + path) is exactly the safe part and the
/// dangerous part (query) adds nothing to a diagnostic that the response status
/// does not.
///
/// Userinfo is dropped. The result is still passed through pattern scrubbing by
/// the formatter, so a path segment that happens to contain a token is caught
/// too — this is the cheap first cut, not the only one.
pub fn url_for_log(url: &str) -> String {
    let (scheme, rest) = match url.split_once("://") {
        Some((s, r)) => (Some(s), r),
        None => (None, url),
    };
    let rest = rest.rsplit_once('@').map(|(_, r)| r).unwrap_or(rest);
    let no_query = rest.split(['?', '#']).next().unwrap_or_default();
    match scheme {
        Some(s) => format!("{s}://{no_query}"),
        None => no_query.to_string(),
    }
}

#[cfg(test)]
mod safe_rendering_tests {
    use super::*;

    #[test]
    fn host_is_extracted_without_userinfo_path_or_query() {
        assert_eq!(
            url_host("https://api.github.com/repos/x"),
            Some("api.github.com")
        );
        assert_eq!(
            url_host("https://u:p@mcp.example.com/mcp"),
            Some("mcp.example.com")
        );
        assert_eq!(
            url_host("http://127.0.0.1:4000/v1/messages"),
            Some("127.0.0.1:4000")
        );
        assert_eq!(url_host("mcp.example.com/x"), Some("mcp.example.com"));
        assert_eq!(url_host(""), None);
        assert_eq!(url_host("https://"), None);
    }

    /// The property that matters: the query string never survives, whatever
    /// shape the URL takes.
    #[test]
    fn query_and_fragment_never_survive() {
        for (url, want) in [
            (
                "https://as.example/callback?code=SECRETCODE&state=SECRETSTATE",
                "https://as.example/callback",
            ),
            (
                "https://github.com/login/oauth?client_secret=abc#frag",
                "https://github.com/login/oauth",
            ),
            (
                "https://u:hunter2@host.example/path?token=zzz",
                "https://host.example/path",
            ),
            ("https://plain.example/p", "https://plain.example/p"),
            ("/v1/sessions?x=1", "/v1/sessions"),
        ] {
            let got = url_for_log(url);
            assert_eq!(got, want, "input: {url}");
            assert!(!got.contains('?'), "{got}");
            assert!(!got.contains('@'), "{got}");
        }
    }
}
