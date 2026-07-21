//! OAuth 2.1 credential custody for brokered MCP connections (Phase 5.5,
//! increment 2). The connection stays the custody object; this module only
//! grows how a credential is OBTAINED — everything downstream (audience
//! binding, the gate, the frozen RunSpec, the photograph) is untouched.
//!
//! Dance (interactive exactly once, from the dashboard):
//!   probe 401 → RFC 9728 protected-resource metadata → RFC 8414/OIDC AS
//!   metadata (PKCE S256 REQUIRED else refuse) → authorize with S256
//!   challenge + RFC 8707 `resource=` → ONE stable callback
//!   (`GET /v1/oauth/callback`, unauthenticated by design — the AEAD-sealed
//!   `state` parameter is the auth, like the webhook signature on ingress)
//!   → code exchange (`resource=` again) → seal the ROTATING refresh token
//!   into the connection's `credential_sealed` → active → auto-register the
//!   pending bundle (the photograph runs with the fresh access token).
//!
//! Custody rules: access tokens live only in the in-memory cache (restart
//! re-mints); refresh rotation is one atomic DB overwrite; refreshes
//! serialize per connection; `invalid_grant` flips the connection to
//! `error`, which every downstream path already fails closed on.
//!
//! Client identity priority: pre-registered (sealed secret supported —
//! confidential clients) → CIMD (this server's URL IS the client_id; served
//! at `/.well-known/fluidbox-client.json`) → DCR (RFC 7591; minted
//! client_id stored per connection, never re-registered per connect).

use crate::auth::Principal;
use crate::error::{ApiError, ApiResult};
use crate::seal::{SealCtx, SealFamily, Sealer, TRANSIT_OAUTH_BOOT};
use crate::state::AppState;
use axum::body::Body;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::Response;
use axum::Json;
use chrono::{DateTime, Duration, Utc};
use serde::Deserialize;
use serde_json::{json, Value};
use uuid::Uuid;

const STATE_TTL_SECS: i64 = 600;
/// The initiating-browser cookie (invariant 20). Fixed name (`__Host-` requires
/// Path=/ + Secure): the connector dance is one-at-a-time per browser, so a
/// per-flow name is unnecessary and the callback reads it without knowing the
/// flow id up front.
const OAUTH_FLOW_COOKIE: &str = "__Host-fbx_oauth_flow";
/// Refresh proactively when the cached access token has less than this left.
const EXPIRY_MARGIN_SECS: i64 = 300;
const HTTP_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15);

pub fn redirect_uri(state: &AppState) -> String {
    format!("{}/v1/oauth/callback", state.cfg.public_url)
}

pub fn cimd_client_id(state: &AppState) -> String {
    format!("{}/.well-known/fluidbox-client.json", state.cfg.public_url)
}

/// CIMD is only PRESENTABLE when the authorization server can actually
/// fetch our client document: the public URL must be https (the spec
/// requires https client_ids) and not loopback (127.0.0.1 means "yourself"
/// to the AS — it would knock on its own door). Local dev deployments
/// therefore fall through to DCR, which POSTs our metadata to the AS
/// instead of asking it to fetch anything. Found the hard way against real
/// Notion (its AS advertises CIMD, then answered "Unknown OAuth client"
/// after failing to fetch a http://127.0.0.1 document).
pub fn cimd_eligible(public_url: &str) -> bool {
    let Ok(u) = reqwest::Url::parse(public_url) else {
        return false;
    };
    if u.scheme() != "https" {
        return false;
    }
    let Some(host) = u.host_str() else {
        return false;
    };
    if host.eq_ignore_ascii_case("localhost") {
        return false;
    }
    // IP-literal hosts ([::1] arrives bracketed): loopback is unreachable
    // from any AS; other IPs are the operator's call.
    if let Ok(ip) = host.trim_matches(['[', ']']).parse::<std::net::IpAddr>() {
        return !ip.is_loopback();
    }
    true
}

/// Should a STORED client identity be reused for this dance? A stale one
/// must be re-resolved instead of replayed forever at the AS:
/// - a stored `registration_id` whose shared row NO LONGER EXISTS is dead for
///   EVERY source (`registration_missing`): the row was retired because the AS
///   rejected its client (`invalid_client`), so replaying the identity it named
///   would replay exactly what the deployment just threw away — and would leave
///   the connection pointing at a dangling id forever;
/// - a CIMD identity is dead the moment CIMD stops being presentable, or
///   when the document URL no longer matches this deployment;
/// - a DCR identity is dead when the redirect_uri it was registered with
///   changed (the AS would refuse the exchange on redirect mismatch);
/// - pre-registered identities are user-owned and never auto-invalidated (they
///   carry no `registration_id`, so `registration_missing` is false for them).
fn stored_identity_stale(
    source: &str,
    client_id: &str,
    registered_redirect: Option<&str>,
    registration_missing: bool,
    cimd_ok: bool,
    current_cimd_id: &str,
    current_redirect: &str,
) -> bool {
    if registration_missing {
        return true;
    }
    match source {
        "cimd" => !cimd_ok || client_id != current_cimd_id,
        "dcr" => registered_redirect.is_some_and(|r| r != current_redirect),
        _ => false,
    }
}

pub(crate) fn b64url(bytes: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

/// application/x-www-form-urlencoded body (reqwest's `form` support is
/// feature-gated out of this build; Url's query serializer is the same
/// `form_urlencoded` encoder).
fn form_body(pairs: &[(&str, &str)]) -> String {
    let mut url = reqwest::Url::parse("http://enc.invalid").expect("static url parses");
    url.query_pairs_mut()
        .extend_pairs(pairs.iter().map(|(k, v)| (*k, *v)));
    url.query().unwrap_or_default().to_string()
}

pub(crate) fn random_urlsafe() -> String {
    let mut buf = [0u8; 32];
    getrandom::fill(&mut buf).expect("OS RNG is available");
    b64url(&buf)
}

// ─── Pure pieces (unit-tested) ────────────────────────────────────────────

/// RFC 7636 S256: BASE64URL(SHA256(verifier)).
pub fn pkce_challenge(verifier: &str) -> String {
    use sha2::{Digest, Sha256};
    b64url(&Sha256::digest(verifier.as_bytes()))
}

/// Canonical RFC 8707 resource identifier for a server URL: lowercase
/// scheme+host, default port elided, path kept without a trailing slash.
pub fn canonical_resource(url: &str) -> Result<String, String> {
    let u = reqwest::Url::parse(url).map_err(|_| format!("'{url}' is not a valid URL"))?;
    if !matches!(u.scheme(), "http" | "https") {
        return Err("resource URL must be http(s)".into());
    }
    let host = u
        .host_str()
        .ok_or("resource URL has no host")?
        .to_ascii_lowercase();
    let port = match u.port() {
        Some(p) => format!(":{p}"),
        None => String::new(),
    };
    let path = u.path().trim_end_matches('/');
    Ok(format!("{}://{host}{port}{path}", u.scheme()))
}

/// The sealed one-time boot token the go endpoint unseals: `{f: flow_id, s, c,
/// x: exp}`. `s` and `c` are two INDEPENDENT 32-byte randoms — the state secret
/// (its sha256 is the flow row's `state_hash` lookup key) and the per-flow cookie
/// value (its sha256 is `browser_hash`). The row stores ONLY the hashes; the
/// plaintexts live solely inside this AEAD-sealed transit token (and, for `c`,
/// the browser cookie the go page sets). Sealed via `seal_token` (self-describing,
/// deployment DEK) so it survives a KMS mode flip within the flow's TTL, under the
/// `TRANSIT_OAUTH_BOOT` AAD purpose — this payload carries no purpose tag of its
/// own (`open_boot_token` discriminates by required-field SHAPE), so the AAD is
/// what makes it unopenable as a login state or a github_app flow token. `exp` is
/// the row's exact `expires_at` — the go page double-checks it, but the row's own
/// `expires_at` is the authority for liveness.
pub(crate) struct BootToken {
    pub flow_id: Uuid,
    pub s: String,
    pub c: String,
}

async fn seal_boot_token(
    sealer: &Sealer,
    flow_id: Uuid,
    s: &str,
    c: &str,
    exp: i64,
) -> Result<String, String> {
    let payload = json!({ "f": flow_id, "s": s, "c": c, "x": exp });
    let sealed = sealer
        .seal_token(TRANSIT_OAUTH_BOOT, &payload.to_string())
        .await
        .map_err(|e| e.to_string())?;
    Ok(b64url(&sealed))
}

async fn open_boot_token(sealer: &Sealer, token: &str) -> Result<BootToken, String> {
    use base64::Engine;
    let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(token)
        .map_err(|_| "malformed token")?;
    let plain = sealer
        .open_token(TRANSIT_OAUTH_BOOT, &raw)
        .await
        .map_err(|_| "token failed verification")?;
    let v: Value = serde_json::from_str(&plain).map_err(|_| "token is corrupt")?;
    let exp = v["x"].as_i64().ok_or("token is corrupt")?;
    if Utc::now().timestamp() > exp {
        return Err("this link expired — start the connect flow again".into());
    }
    let flow_id = v["f"]
        .as_str()
        .and_then(|s| Uuid::parse_str(s).ok())
        .ok_or("token is corrupt")?;
    let s = v["s"].as_str().ok_or("token is corrupt")?.to_string();
    let c = v["c"].as_str().ok_or("token is corrupt")?.to_string();
    Ok(BootToken { flow_id, s, c })
}

/// Read the initiating-browser cookie value from the request headers.
fn oauth_flow_cookie(headers: &HeaderMap) -> Option<String> {
    let raw = headers.get(axum::http::header::COOKIE)?.to_str().ok()?;
    raw.split(';')
        .filter_map(|p| p.trim().split_once('='))
        .find(|(k, _)| *k == OAUTH_FLOW_COOKIE)
        .map(|(_, v)| v.to_string())
}

/// The `Set-Cookie` header for the initiating-browser cookie.
///
/// `Secure` is UNCONDITIONAL — it is not a deployment choice. The `__Host-`
/// prefix is DEFINED as `Secure` + `Path=/` + no `Domain` (RFC 6265bis §4.1.3.2);
/// a `__Host-` cookie without `Secure` is malformed and every conforming client
/// DISCARDS it outright — browsers, and curl since 7.87. The earlier
/// "omit Secure on local http, curl jars are lenient" special-case (copied from
/// github_app.rs, whose cookie is plain `fbx_gh_<flow>` and so genuinely may drop
/// it) therefore did not relax the cookie, it deleted it: on an http public URL
/// the browser never stored the flow cookie, so `callback` saw no cookie and the
/// dance ended at "This browser did not start the connect flow" — 400, flow
/// unburned, connection stuck `pending`. `login.rs`'s `__Host-fbx_web` is the
/// in-repo precedent and always sends `Secure`; browsers treat `http://localhost`
/// / `http://127.0.0.1` as trustworthy origins, so local dev keeps working.
fn set_oauth_flow_cookie(value: &str) -> String {
    format!(
        "{OAUTH_FLOW_COOKIE}={value}; HttpOnly; SameSite=Lax; Secure; Path=/; Max-Age={STATE_TTL_SECS}"
    )
}

/// Expire the initiating-browser cookie (same name/path/Secure so it matches).
fn clear_oauth_flow_cookie() -> String {
    format!("{OAUTH_FLOW_COOKIE}=gone; HttpOnly; SameSite=Lax; Secure; Path=/; Max-Age=0")
}

/// A deterministic sha256 fingerprint of the discovered AS metadata, frozen on
/// the flow row at start (design :636-641 — the state must bind a metadata
/// digest). Canonicalizes the binding-relevant fields (scopes sorted) so the same
/// discovery always yields the same digest.
fn metadata_digest(meta: &AsMeta) -> String {
    let mut scopes = meta.scopes_supported.clone();
    scopes.sort();
    let canonical = json!({
        "issuer": meta.issuer,
        "authorization_endpoint": meta.authorization_endpoint,
        "token_endpoint": meta.token_endpoint,
        "registration_endpoint": meta.registration_endpoint,
        "cimd_supported": meta.cimd_supported,
        "scopes_supported": scopes,
    });
    format!("sha256:{}", fluidbox_db::sha256_hex(&canonical.to_string()))
}

/// Rebuild the authorization-endpoint URL from the frozen flow fields (design D5:
/// the go page rebuilds FROM THE ROW so start and callback share one issuer +
/// client + redirect + resource, closing AS mix-up and discovery-change races).
/// Pure + unit-tested. `scopes` is space-joined when non-empty (mirrors the pre-D
/// dance, incl. `offline_access`).
#[allow(clippy::too_many_arguments)]
fn build_authorize_url(
    authorization_endpoint: &str,
    client_id: &str,
    redirect_uri: &str,
    state_param: &str,
    challenge: &str,
    challenge_method: &str,
    resource: &str,
    scopes: &[String],
) -> Result<String, String> {
    let mut url = reqwest::Url::parse(authorization_endpoint)
        .map_err(|_| "AS authorization_endpoint is not a valid URL".to_string())?;
    url.query_pairs_mut()
        .append_pair("response_type", "code")
        .append_pair("client_id", client_id)
        .append_pair("redirect_uri", redirect_uri)
        .append_pair("state", state_param)
        .append_pair("code_challenge", challenge)
        .append_pair("code_challenge_method", challenge_method)
        .append_pair("resource", resource);
    if !scopes.is_empty() {
        url.query_pairs_mut()
            .append_pair("scope", &scopes.join(" "));
    }
    Ok(url.to_string())
}

/// Pull `resource_metadata="…"` out of a `WWW-Authenticate` challenge
/// (RFC 9728 §5.1).
pub fn parse_www_authenticate(header: &str) -> Option<String> {
    let idx = header.find("resource_metadata=")?;
    let rest = &header[idx + "resource_metadata=".len()..];
    let rest = rest.strip_prefix('"')?;
    let end = rest.find('"')?;
    Some(rest[..end].to_string())
}

/// An SEP-835 `insufficient_scope` challenge, carrying the (optional, already
/// sanitized) `scope` the server says it needs. Its presence tells the broker to
/// stop — a re-mint cannot fix a scope the grant never had — and mark the
/// connection for reconnect-with-more-scopes.
#[derive(Debug, Clone, PartialEq)]
pub struct ScopeChallenge {
    pub scope: Option<String>,
}

/// Read one `WWW-Authenticate` param value (`key="quoted"` or bare `key=token`).
fn www_auth_param(header: &str, key: &str) -> Option<String> {
    // RFC 7235: auth-param NAMES are case-insensitive (`error=` and `Error=` are
    // the same param). Search a lowercased copy for the key, but read the VALUE
    // from the ORIGINAL header — scope/token values are case-sensitive and land
    // verbatim in a persisted note. ASCII-lowercasing preserves byte length, so
    // offsets into `hay` index `header` identically.
    let hay = header.to_ascii_lowercase();
    let needle = key.to_ascii_lowercase();
    // Match `key=` not preceded by another word char (so `error=` doesn't hit a
    // hypothetical `xerror=`), tolerating whitespace.
    let mut search = 0;
    while let Some(rel) = hay[search..].find(needle.as_str()) {
        let at = search + rel;
        let before_ok = at == 0 || !hay.as_bytes()[at - 1].is_ascii_alphanumeric();
        let after = header[at + needle.len()..].trim_start();
        if before_ok {
            if let Some(rest) = after.strip_prefix('=') {
                let rest = rest.trim_start();
                if let Some(q) = rest.strip_prefix('"') {
                    let end = q.find('"')?;
                    return Some(q[..end].to_string());
                }
                // bare token: up to the next comma / whitespace.
                let end = rest.find([',', ' ', '\t']).unwrap_or(rest.len());
                return Some(rest[..end].to_string());
            }
        }
        search = at + needle.len();
    }
    None
}

/// SEP-835 detection: `Some` iff the `WWW-Authenticate` challenge carries
/// `error="insufficient_scope"`. The optional `scope` is sanitized to the OAuth
/// scope charset and length-bounded — a hostile upstream must not smuggle a
/// control/secret-shaped string into the connection's durable error note.
pub fn parse_insufficient_scope(header: &str) -> Option<ScopeChallenge> {
    if www_auth_param(header, "error").as_deref() != Some("insufficient_scope") {
        return None;
    }
    let scope = www_auth_param(header, "scope").map(|s| sanitize_scope(&s));
    Some(ScopeChallenge { scope })
}

/// Keep only RFC 6749 scope-token characters (`%x21 / %x23-5B / %x5D-7E`,
/// approximated by the printable ASCII a scope uses) and space separators, and
/// bound the length — the value lands verbatim in a persisted note.
fn sanitize_scope(s: &str) -> String {
    s.chars()
        .filter(|c| {
            *c == ' ' || (c.is_ascii_graphic() && !matches!(c, '"' | '\\' | ',' | '<' | '>'))
        })
        .take(200)
        .collect::<String>()
        .trim()
        .to_string()
}

#[derive(Debug, Clone)]
pub struct AsMeta {
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub registration_endpoint: Option<String>,
    pub cimd_supported: bool,
    pub scopes_supported: Vec<String>,
}

/// Parse RFC 8414 / OIDC discovery metadata. Refuses an AS that does not
/// advertise PKCE S256 — OAuth 2.1 and the MCP spec both require it, and a
/// downgrade here would gut the public-client security model.
pub fn parse_as_metadata(v: &Value) -> Result<AsMeta, String> {
    let s = |k: &str| v.get(k).and_then(Value::as_str).map(str::to_string);
    let authorization_endpoint =
        s("authorization_endpoint").ok_or("AS metadata is missing authorization_endpoint")?;
    let token_endpoint = s("token_endpoint").ok_or("AS metadata is missing token_endpoint")?;
    let methods: Vec<&str> = v
        .get("code_challenge_methods_supported")
        .and_then(Value::as_array)
        .map(|a| a.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default();
    if !methods.contains(&"S256") {
        return Err(
            "authorization server does not advertise PKCE S256 (code_challenge_methods_supported) — refusing to connect"
                .into(),
        );
    }
    Ok(AsMeta {
        issuer: s("issuer").unwrap_or_default(),
        authorization_endpoint,
        token_endpoint,
        registration_endpoint: s("registration_endpoint"),
        cimd_supported: v
            .get("client_id_metadata_document_supported")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        scopes_supported: v
            .get("scopes_supported")
            .and_then(Value::as_array)
            .map(|a| {
                a.iter()
                    .filter_map(Value::as_str)
                    .map(String::from)
                    .collect()
            })
            .unwrap_or_default(),
    })
}

/// RFC 9728 protected-resource metadata → the first authorization server.
pub fn parse_resource_metadata(v: &Value) -> Result<String, String> {
    v.get("authorization_servers")
        .and_then(Value::as_array)
        .and_then(|a| a.first())
        .and_then(Value::as_str)
        .map(str::to_string)
        .ok_or_else(|| "protected-resource metadata lists no authorization_servers".into())
}

fn origin_and_path(url: &str) -> Result<(String, String), String> {
    let u = reqwest::Url::parse(url).map_err(|_| format!("'{url}' is not a valid URL"))?;
    let host = u.host_str().ok_or("URL has no host")?;
    let port = match u.port() {
        Some(p) => format!(":{p}"),
        None => String::new(),
    };
    Ok((
        format!("{}://{host}{port}", u.scheme()),
        u.path().trim_end_matches('/').to_string(),
    ))
}

/// Pre-dial egress admission for a connector-OAuth identity fetch (Phase E, C1).
///
/// `state.identity_http` filters DNS *names* at resolve time and re-validates
/// redirect hops, but reqwest dials an IP *literal* in the INITIAL request URL
/// directly — the resolver is never consulted for a literal — so an
/// `https://169.254.169.254/…` target would otherwise slip straight past the
/// per-hop guard. `egress::admit_url` closes that on the first hop (scheme
/// policy + host-literal block), and MUST be called immediately before every
/// `identity_http` request whose URL is attacker-influenced (the mcp_url probe,
/// PRM/AS-metadata discovery, DCR, code exchange, and the stored-bag refresh).
///
/// The denial reason is a static class from `admit_url` (never a resolved IP);
/// we surface it as `egress blocked: <class>` so no internal address leaks.
fn admit_oauth(url: &str, policy: &crate::egress::EgressPolicy) -> Result<(), String> {
    crate::egress::admit_url(url, policy).map_err(|e| format!("egress blocked: {e}"))
}

// ─── Discovery (network) ──────────────────────────────────────────────────

/// 401-probe the MCP endpoint, walk RFC 9728 → RFC 8414/OIDC, and return
/// validated AS metadata. Every step fails with an actionable message —
/// this runs interactively from the dashboard Connect flow.
pub async fn discover(state: &AppState, mcp_url: &str) -> Result<AsMeta, String> {
    let mut prm_urls: Vec<String> = Vec::new();
    // Phase E: connector-OAuth traffic rides the per-hop-SSRF `identity_http`
    // (the same client OIDC uses). A PRM/AS-metadata document can point discovery
    // anywhere, so every hop's scheme + resolved address is now validated — AND
    // the initial-hop literal is admitted here (C1) since reqwest dials a literal
    // IP without consulting the resolver. The mcp_url is the user's declared
    // target: a private/plain-http one is a hard discovery failure, not a probe
    // we silently skip (the same-origin PRM URLs derived below would all block
    // anyway).
    admit_oauth(mcp_url, &state.egress_policy)?;
    if let Ok(res) = state
        .identity_http
        .get(mcp_url)
        .timeout(HTTP_TIMEOUT)
        .header("accept", "application/json, text/event-stream")
        .send()
        .await
    {
        if let Some(h) = res
            .headers()
            .get("www-authenticate")
            .and_then(|v| v.to_str().ok())
        {
            if let Some(u) = parse_www_authenticate(h) {
                prm_urls.push(u);
            }
        }
    }
    let (origin, path) = origin_and_path(mcp_url)?;
    if !path.is_empty() {
        prm_urls.push(format!(
            "{origin}/.well-known/oauth-protected-resource{path}"
        ));
    }
    prm_urls.push(format!("{origin}/.well-known/oauth-protected-resource"));

    let mut as_base = None;
    for pu in &prm_urls {
        // A PRM candidate can be attacker-supplied (the WWW-Authenticate one) —
        // a blocked target is skipped like any non-answer; if ALL are blocked the
        // loop falls through to the discovery-failure error below (C1).
        if admit_oauth(pu, &state.egress_policy).is_err() {
            continue;
        }
        let Ok(mut res) = state
            .identity_http
            .get(pu)
            .timeout(HTTP_TIMEOUT)
            .send()
            .await
        else {
            continue;
        };
        if !res.status().is_success() {
            continue;
        }
        // I3: bounded like every OIDC read — an attacker-influenced AS must not
        // be able to stream hundreds of MB into memory per discovery leg.
        let Ok(v) = crate::egress::read_json_bounded(&mut res).await else {
            continue;
        };
        if let Ok(a) = parse_resource_metadata(&v) {
            as_base = Some(a);
            break;
        }
    }
    let as_base = as_base.ok_or(
        "could not discover an authorization server for this MCP endpoint \
         (no WWW-Authenticate resource_metadata and no /.well-known/oauth-protected-resource)",
    )?;

    let (a_origin, a_path) = origin_and_path(&as_base)?;
    let mut meta_urls = Vec::new();
    if !a_path.is_empty() {
        meta_urls.push(format!(
            "{a_origin}/.well-known/oauth-authorization-server{a_path}"
        ));
    }
    meta_urls.push(format!("{a_origin}/.well-known/oauth-authorization-server"));
    meta_urls.push(format!("{a_origin}/.well-known/openid-configuration"));
    for mu in &meta_urls {
        // `as_base` came from the (attacker-influenced) PRM document, so admit
        // each metadata candidate before dialing; a blocked one is skipped and
        // the loop falls through to the discovery-failure error below (C1).
        if admit_oauth(mu, &state.egress_policy).is_err() {
            continue;
        }
        let Ok(mut res) = state
            .identity_http
            .get(mu)
            .timeout(HTTP_TIMEOUT)
            .send()
            .await
        else {
            continue;
        };
        if !res.status().is_success() {
            continue;
        }
        // I3: bounded read (256 KiB), same as the OIDC discovery documents.
        let Ok(v) = crate::egress::read_json_bounded(&mut res).await else {
            continue;
        };
        // Found the document: S256-refusal must NOT fall through to the
        // next URL — this is a policy refusal, not a lookup miss.
        let meta = parse_as_metadata(&v)?;
        // RFC 8414 §3.3: the metadata's `issuer` MUST identify the server the
        // metadata was retrieved from. Unvalidated, ANY member's malicious MCP
        // server could claim a real provider's issuer, and since DCR rows are
        // keyed GLOBALLY by `(issuer, redirect_uri)` it would occupy that
        // provider's registration for the whole deployment — later, legitimate
        // tenants would then adopt the attacker-registered client_id.
        issuer_matches_discovery(&meta.issuer, &a_origin)?;
        return Ok(meta);
    }
    Err(format!(
        "authorization server '{as_base}' publishes no discoverable metadata (RFC 8414/OIDC)"
    ))
}

/// RFC 8414 §3.3 issuer validation: the `issuer` an AS publishes must identify
/// the server the metadata came FROM. Compared at ORIGIN granularity (scheme +
/// host + port) — an issuer legitimately carries a path component for
/// multi-tenant providers, but it can never name a DIFFERENT host than the one
/// that served the document. A missing/blank issuer is refused: it is what makes
/// the global registration key meaningless.
fn issuer_matches_discovery(issuer: &str, discovered_origin: &str) -> Result<(), String> {
    if issuer.trim().is_empty() {
        return Err("authorization server metadata declares no issuer (RFC 8414 §3.3)".into());
    }
    let (i_origin, _) = origin_and_path(issuer)
        .map_err(|_| "authorization server metadata declares a malformed issuer".to_string())?;
    if !i_origin.eq_ignore_ascii_case(discovered_origin) {
        return Err(
            "authorization server metadata declares an issuer on a different origin than the \
             server that published it — refusing (RFC 8414 §3.3)"
                .into(),
        );
    }
    Ok(())
}

/// The resolved OAuth client identity for a dance. `registration_id` points at
/// the shared `oauth_client_registrations` row that dedups this identity (Some
/// for cimd/dcr — the reusable identities); pre-registered identities are
/// per-connection custody and carry None (design D6).
struct ResolvedClient {
    client_id: String,
    source: String,
    registration_id: Option<Uuid>,
}

/// Which arm resolves the client identity for a dance — the PURE priority
/// decision (unit-tested). `Reuse` short-circuits with the stored identity;
/// `Cimd`/`Dcr` do the network/DB work. Priority is UNCHANGED from before
/// Task 3: a non-stale stored identity (pre-registered or a previously resolved
/// cimd/dcr id) wins, then CIMD when presentable, then DCR.
#[derive(Debug, PartialEq, Eq)]
enum ClientResolution {
    Reuse,
    Cimd,
    Dcr,
}

fn classify_client_resolution(
    stored: Option<&str>,
    stale: bool,
    cimd_ok: bool,
) -> ClientResolution {
    if stored.is_some() && !stale {
        return ClientResolution::Reuse;
    }
    if cimd_ok {
        ClientResolution::Cimd
    } else {
        ClientResolution::Dcr
    }
}

/// Resolve the client identity for this connection against this AS. Priority
/// UNCHANGED (reuse a valid stored identity → CIMD → DCR); only the CIMD and DCR
/// arms changed — they now dedup into the shared `oauth_client_registrations`
/// table (design D6) instead of minting per-connection, and return the shared
/// row id so the connection can reference it. Pre-registered identities stay
/// per-connection custody (no row).
async fn resolve_client(
    state: &AppState,
    oauth: &Value,
    meta: &AsMeta,
) -> Result<ResolvedClient, String> {
    let cimd_ok = meta.cimd_supported && cimd_eligible(&state.cfg.public_url);
    let stored = oauth.get("client_id").and_then(Value::as_str);
    let source = oauth
        .get("client_id_source")
        .and_then(Value::as_str)
        .unwrap_or("preregistered");
    let stored_registration_id = oauth
        .get("registration_id")
        .and_then(Value::as_str)
        .and_then(|s| Uuid::parse_str(s).ok());
    // A stored pointer at a shared registration row that no longer resolves is
    // STALE — the row was retired (an `invalid_client` retirement) and its identity
    // must not be replayed. Checked HERE, not just carried through: without it the
    // Reuse arm copies a dangling id into the next flow row (which then FK-nulls)
    // and keeps presenting a client the AS already rejected.
    let registration_missing = match stored_registration_id {
        Some(rid) => fluidbox_db::find_client_registration_by_id(&state.pool, rid)
            .await
            .map_err(|e| {
                tracing::warn!(registration = %rid, error = %e, "oauth: registration lookup failed");
                "client registration lookup failed".to_string()
            })?
            .is_none(),
        None => false,
    };
    // No stored identity ⇒ treat as "stale" so classify falls through to CIMD/DCR.
    let stale = stored
        .map(|cid| {
            stored_identity_stale(
                source,
                cid,
                oauth.get("redirect_uri").and_then(Value::as_str),
                registration_missing,
                cimd_ok,
                &cimd_client_id(state),
                &redirect_uri(state),
            )
        })
        .unwrap_or(true);
    let redirect = redirect_uri(state);
    match classify_client_resolution(stored, stale, cimd_ok) {
        ClientResolution::Reuse => {
            // Reuse the stored identity AND carry forward the shared registration
            // row it points at (if any — pre-registered identities have none). The
            // pointer was VERIFIED to resolve above; a missing row made the identity
            // stale and we would not be in this arm.
            Ok(ResolvedClient {
                client_id: stored
                    .expect("Reuse implies a stored client_id")
                    .to_string(),
                source: source.to_string(),
                registration_id: stored_registration_id,
            })
        }
        ClientResolution::Cimd => {
            // ADOPT: if a row already exists for this (issuer, redirect_uri) — of
            // ANY source — carry ITS identity on BOTH legs (never send cimd_url on
            // authorize while the exchange resolves a stored DCR client_id).
            let cimd_id = cimd_client_id(state);
            let registered =
                ensure_cimd_registration(state, &meta.issuer, &redirect, &cimd_id).await?;
            Ok(ResolvedClient {
                client_id: registered.client_id,
                source: registered.source,
                registration_id: Some(registered.registration_id),
            })
        }
        ClientResolution::Dcr => {
            let Some(reg_endpoint) = &meta.registration_endpoint else {
                return Err(
                    "authorization server supports neither CIMD nor dynamic client registration — \
                     supply a pre-registered client_id on the connection"
                        .into(),
                );
            };
            let registered =
                register_dcr_client(state, &meta.issuer, &redirect, reg_endpoint).await?;
            Ok(ResolvedClient {
                client_id: registered.client_id,
                source: registered.source,
                registration_id: Some(registered.registration_id),
            })
        }
    }
}

/// The identity a resolution arm ADOPTS from an existing shared registration row:
/// ALWAYS the row's own `(client_id, source)`, regardless of which arm (CIMD or
/// DCR) found it, so the authorize and exchange legs carry the SAME identity. A
/// CIMD arm must NEVER present `cimd_url` on the authorize leg while a stored DCR
/// `client_id` resolves on the exchange leg — that is RFC 6749 `invalid_grant`
/// ("code issued to another client"), which the `invalid_client` retirement never
/// catches, so every later connect to that issuer would fail forever.
///
/// Convergence if the adopted identity is dead at the AS: a DCR-sourced identity
/// (it records its `registration_endpoint`) CONVERGES ACROSS TWO DANCES — the
/// exchange returns `invalid_client`, [`retire_rejected_registration`] deletes the
/// row and the user is told to start over; that next dance finds no row, registers
/// a fresh client via DCR, and completes. (It cannot converge WITHIN one dance:
/// the authorization code is already bound to the rejected client.) A CIMD-sourced
/// identity has no `registration_endpoint`, so a dead one is a terminal clean
/// `invalid_client` (NOT a mismatch) — but a CIMD `client_id` is the doc URL,
/// which only "dies" when the AS cannot fetch it (a public-URL config problem that
/// also moves the redirect_uri = the registration key), so a stale CIMD row is not
/// even found for the current key.
fn adopt_registration(row: &fluidbox_db::OauthClientRegistrationRow) -> (String, String) {
    (row.client_id.clone(), row.source.clone())
}

/// Adopt-or-mint the shared client identity for a CIMD-eligible dance. Mirrors
/// [`register_dcr_client`]'s ADOPT semantics: if a row already exists for
/// (issuer, redirect_uri) — of ANY source — reuse ITS identity verbatim
/// (see [`adopt_registration`]); only when NONE exists mint a fresh CIMD identity
/// (client_id = the doc URL, source='cimd', no secret). The row also lets the
/// one-time state flows (Task 4) FK the client. No advisory lock — CIMD has no
/// `/register` HTTP to serialize; find-or-insert with `ON CONFLICT DO NOTHING`
/// re-select is race-safe on its own.
///
/// The two WRITES take the audited system-worker entry points: migration 0018
/// grants global rows (`tenant_id is null`) SELECT from any scope but
/// INSERT/UPDATE/DELETE only under the bypass GUC, and this resolution is
/// principal-less by construction (it runs mid-dance, before any connection is
/// active). The reads stay pool-direct — the SELECT policy already admits them.
async fn ensure_cimd_registration(
    state: &AppState,
    issuer: &str,
    redirect: &str,
    cimd_id: &str,
) -> Result<RegisteredClient, String> {
    if let Some(r) = fluidbox_db::find_client_registration(&state.pool, issuer, redirect)
        .await
        .map_err(|e| format!("registration lookup failed: {e}"))?
    {
        fluidbox_db::system_worker::touch_global_registration(&state.pool, r.id)
            .await
            .map_err(|e| format!("registration touch failed: {e}"))?;
        let (client_id, source) = adopt_registration(&r);
        return Ok(RegisteredClient {
            client_id,
            registration_id: r.id,
            source,
        });
    }
    let new = fluidbox_db::NewOauthClientRegistration {
        tenant_id: None,
        issuer,
        redirect_uri: redirect,
        source: "cimd",
        client_id: cimd_id,
        client_secret_sealed: None,
        client_secret_key_version: 1,
        registration_endpoint: None,
        registration_access_token_sealed: None,
        registration_access_token_key_version: 1,
        token_endpoint_auth_method: Some("none"),
    };
    let row = match fluidbox_db::system_worker::insert_global_registration(&state.pool, new)
        .await
        .map_err(|e| format!("registration insert failed: {e}"))?
    {
        Some(r) => r,
        None => fluidbox_db::find_client_registration(&state.pool, issuer, redirect)
            .await
            .map_err(|e| format!("registration re-select failed: {e}"))?
            .ok_or("registration race lost with no winner")?,
    };
    let (client_id, source) = adopt_registration(&row);
    Ok(RegisteredClient {
        client_id,
        registration_id: row.id,
        source,
    })
}

/// One RFC 7591 dynamic client registration POST. Returns `(client_id, secret?)`;
/// the secret is rare with `token_endpoint_auth_method: "none"` (public client).
async fn dcr_register(
    state: &AppState,
    registration_endpoint: &str,
) -> Result<(String, Option<String>), String> {
    // The registration_endpoint is read from (attacker-influenced) AS metadata —
    // admit it before POSTing (C1); a denial surfaces as a registration failure.
    admit_oauth(registration_endpoint, &state.egress_policy)?;
    let body = json!({
        "client_name": "fluidbox",
        "redirect_uris": [redirect_uri(state)],
        "grant_types": ["authorization_code", "refresh_token"],
        "response_types": ["code"],
        "token_endpoint_auth_method": "none",
    });
    let mut res = state
        .identity_http
        .post(registration_endpoint)
        .timeout(HTTP_TIMEOUT)
        .json(&body)
        .send()
        .await
        .map_err(|e| format!("dynamic client registration failed: {e}"))?;
    let status = res.status();
    // I3: bounded read — an over-cap or non-JSON body reads as `Null`, exactly
    // as a malformed one already did.
    let v: Value = crate::egress::read_json_bounded(&mut res)
        .await
        .unwrap_or(Value::Null);
    if !status.is_success() {
        return Err(format!(
            "dynamic client registration returned HTTP {status}"
        ));
    }
    let client_id = v["client_id"]
        .as_str()
        .ok_or("registration response has no client_id")?
        .to_string();
    Ok((client_id, v["client_secret"].as_str().map(String::from)))
}

/// A found-or-registered shared DCR client.
struct RegisteredClient {
    client_id: String,
    registration_id: Uuid,
    source: String,
}

/// Find-or-register the shared client for (issuer, redirect_uri): take the
/// advisory lock, reuse an existing row (bumping `last_used_at`), else DCR at
/// `registration_endpoint` and insert. The advisory lock + `ON CONFLICT DO
/// NOTHING` re-select collapse concurrent connects to the same issuer down to ONE
/// `/register`. The DCR HTTP runs UNDER the lock (like the refresh path) so a
/// second connect blocks and then reuses THIS row rather than double-registering.
///
/// The transaction is opened through `system_worker::global_registration_tx`, so
/// the audited bypass GUC spans the whole critical section — 0018 admits an INSERT
/// of a global row (`tenant_id is null`) only under it, and the UPDATE behind
/// `touch` would otherwise be filtered to zero rows in silence. Everything this tx
/// touches is the deployment-global registration (the lock, the find, the touch,
/// the insert, the re-select); no tenant-owned row is read or written under it.
async fn register_dcr_client(
    state: &AppState,
    issuer: &str,
    redirect: &str,
    registration_endpoint: &str,
) -> Result<RegisteredClient, String> {
    let mut tx = fluidbox_db::system_worker::global_registration_tx(&state.pool)
        .await
        .map_err(|e| format!("registration txn failed: {e}"))?;
    fluidbox_db::acquire_registration_lock(&mut tx, issuer, redirect)
        .await
        .map_err(|e| format!("registration lock failed: {e}"))?;
    if let Some(r) = fluidbox_db::find_client_registration(&mut *tx, issuer, redirect)
        .await
        .map_err(|e| format!("registration lookup failed: {e}"))?
    {
        fluidbox_db::touch_client_registration(&mut *tx, r.id)
            .await
            .map_err(|e| format!("registration touch failed: {e}"))?;
        tx.commit()
            .await
            .map_err(|e| format!("registration commit failed: {e}"))?;
        let (client_id, source) = adopt_registration(&r);
        return Ok(RegisteredClient {
            client_id,
            registration_id: r.id,
            source,
        });
    }
    let (client_id, secret) = dcr_register(state, registration_endpoint).await?;
    // Seal the (rare) confidential secret under the DEPLOYMENT DEK — registrations
    // are global rows (tenant_id NULL). The deployment DEK is warm from transit-
    // token sealing (every dance seals a state param), so this near-never reaches
    // for a second pooled connection while the lock's is held; and it only runs
    // for the uncommon auth-method secret at all.
    let sealer_ref = state.sealer.as_ref().ok_or("credential key missing")?;
    let sealed = match &secret {
        Some(s) => Some(
            sealer_ref
                .seal(
                    s,
                    sealer_ref.deployment_ctx(SealFamily::RegistrationClientSecret),
                )
                .await
                .map_err(|e| format!("failed to seal client secret: {e}"))?,
        ),
        None => None,
    };
    let (sealed_bytes, kv) = match &sealed {
        Some(s) => (Some(s.bytes.as_slice()), s.key_version),
        None => (None, 1),
    };
    let new = fluidbox_db::NewOauthClientRegistration {
        tenant_id: None,
        issuer,
        redirect_uri: redirect,
        source: "dcr",
        client_id: &client_id,
        client_secret_sealed: sealed_bytes,
        client_secret_key_version: kv,
        registration_endpoint: Some(registration_endpoint),
        registration_access_token_sealed: None,
        registration_access_token_key_version: 1,
        token_endpoint_auth_method: Some("none"),
    };
    let row = match fluidbox_db::insert_client_registration(&mut *tx, new)
        .await
        .map_err(|e| format!("registration insert failed: {e}"))?
    {
        Some(r) => r,
        None => {
            // A racer won the (issuer, redirect_uri) key: adopt its row and abandon
            // the client we just minted at the AS (a harmless orphan — log at debug).
            tracing::debug!(%issuer, "oauth registration race: adopting the winner's client");
            fluidbox_db::find_client_registration(&mut *tx, issuer, redirect)
                .await
                .map_err(|e| format!("registration re-select failed: {e}"))?
                .ok_or("registration race lost with no winner")?
        }
    };
    let (client_id, source) = adopt_registration(&row);
    tx.commit()
        .await
        .map_err(|e| format!("registration commit failed: {e}"))?;
    Ok(RegisteredClient {
        client_id,
        registration_id: row.id,
        source,
    })
}

// ─── The dance ────────────────────────────────────────────────────────────

/// The sealer, or the operator-facing refusal. Sealing is enabled by EITHER key
/// path (Phase D): the legacy `FLUIDBOX_CREDENTIAL_KEY` or `FLUIDBOX_KMS_MODE`
/// (`static|aws`) with its KEK — naming only the former sent KMS operators
/// hunting for a variable their deployment does not use.
pub(crate) fn sealer(state: &AppState) -> ApiResult<&Sealer> {
    state.sealer.as_ref().ok_or_else(|| {
        ApiError::BadRequest(
            "OAuth connections are disabled: configure credential sealing on the server — \
             either FLUIDBOX_KMS_MODE=static|aws (with its KEK) or FLUIDBOX_CREDENTIAL_KEY"
                .into(),
        )
    })
}

/// Shared by the start endpoint and the catalog Connect flow: run discovery and
/// client-identity resolution (idempotent — results persist on the connection),
/// then mint a one-time server-side flow row (invariant 20) and return the
/// `go_url`. `initiated_by_user_id` is the initiating fluidbox user (None for the
/// operator/admin token — the cookie still binds the browser). The authorize URL
/// is NOT built here: the go endpoint rebuilds it FROM THE ROW after binding the
/// browser cookie, so a leaked authorization URL can neither complete nor burn
/// the flow (design D5 / :646-656).
pub async fn start_dance(
    state: &AppState,
    scope: fluidbox_db::TenantScope,
    initiated_by_user_id: Option<Uuid>,
    conn_id: Uuid,
) -> ApiResult<String> {
    let sealer_ref = sealer(state)?;
    // Unfiltered read by design: the caller already established authority over
    // this connection — either the owner-checked `start` route
    // (`connection_for_mutation`) or a connection this same principal just
    // created in the catalog/manual oauth branch. The dance mechanics need the
    // row regardless of the viewer lens.
    // Tenant known (the initiating principal's scope) → scoped_tx so the RLS GUC
    // rides the executor-generic read.
    let mut conn_tx = fluidbox_db::scoped_tx(&state.pool, scope).await?;
    let conn = fluidbox_db::get_connection(&mut *conn_tx, scope, conn_id)
        .await?
        .ok_or(ApiError::NotFound)?;
    conn_tx.commit().await?;
    // THE ATTEMPT'S REAL START EPOCH (review: start-epoch race), frozen HERE —
    // before discovery, client resolution, or any other outbound HTTP. The flow
    // row's `created_at` is NOT this instant: it is stamped seconds later, after
    // those round trips, so an attempt that began BEFORE a sibling's successful
    // activation would otherwise mint a flow row that POST-DATES that activation
    // and sail through the activation CAS. See `commit_start_epoch`.
    let started_with = StartExpectation::of(&conn);
    if conn.auth_kind != "oauth" {
        return Err(ApiError::BadRequest(
            "this connection does not use OAuth — it has a static credential".into(),
        ));
    }
    if conn.status == "revoked" {
        return Err(ApiError::Conflict(
            "connection is revoked — create a new one".into(),
        ));
    }
    let mut oauth = conn.oauth.clone().unwrap_or_else(|| json!({}));
    let resource = oauth
        .get("resource")
        .and_then(Value::as_str)
        .ok_or_else(|| ApiError::BadRequest("connection has no resource URL".into()))?
        .to_string();

    let meta = discover(state, &resource)
        .await
        .map_err(ApiError::BadRequest)?;
    let ResolvedClient {
        client_id,
        source: client_source,
        registration_id,
    } = resolve_client(state, &oauth, &meta)
        .await
        .map_err(ApiError::BadRequest)?;

    // Assemble the discovered custody state. It is PERSISTED only after this
    // attempt clears the commit point below — see the write near the end.
    let scopes: Vec<String> = oauth
        .get("scopes")
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(Value::as_str)
                .map(String::from)
                .collect()
        })
        .unwrap_or_default();
    let mut scopes = scopes;
    if meta.scopes_supported.iter().any(|s| s == "offline_access")
        && !scopes.iter().any(|s| s == "offline_access")
    {
        scopes.push("offline_access".to_string());
    }
    let o = oauth.as_object_mut().expect("oauth is an object");
    o.insert("issuer".into(), json!(meta.issuer));
    o.insert(
        "authorization_endpoint".into(),
        json!(meta.authorization_endpoint),
    );
    o.insert("token_endpoint".into(), json!(meta.token_endpoint));
    o.insert("client_id".into(), json!(client_id));
    o.insert("client_id_source".into(), json!(client_source));
    // The redirect this identity was resolved for — staleness detection
    // re-registers a DCR client if the public URL later moves.
    o.insert("redirect_uri".into(), json!(redirect_uri(state)));
    // The shared registration row this identity dedups into (cimd/dcr); cleared
    // for a per-connection pre-registered identity so a stale pointer never rides.
    match registration_id {
        Some(rid) => {
            o.insert("registration_id".into(), json!(rid));
        }
        None => {
            o.remove("registration_id");
        }
    }
    o.insert("scopes".into(), json!(scopes));

    // Mint the PKCE pair. The challenge is PUBLIC (rides the authorize URL); the
    // verifier is custody (performs the exchange) and is sealed at rest so a leaked
    // flow row cannot exchange (design :638-639).
    let verifier = random_urlsafe();
    let challenge = pkce_challenge(&verifier);
    let sealed_verifier = sealer_ref
        .seal(
            &verifier,
            SealCtx::new(scope.tenant_id(), SealFamily::OauthFlowPkceVerifier),
        )
        .await
        .map_err(|e| ApiError::Internal(format!("failed to seal PKCE verifier: {e}")))?;
    // Two independent 32-byte randoms: the state `s` (its hash is the row's lookup
    // key) and the cookie `c` (its hash binds the initiating browser). The row
    // stores ONLY the hashes; the plaintext rides the sealed boot token.
    let s = random_urlsafe();
    let c = random_urlsafe();
    let digest = metadata_digest(&meta);
    let flow = fluidbox_db::insert_connector_oauth_flow(
        &state.pool,
        scope,
        fluidbox_db::NewConnectorOauthFlow {
            connection_id: conn.id,
            initiated_by_user_id,
            state_hash: &fluidbox_db::sha256_hex(&s),
            browser_hash: &fluidbox_db::sha256_hex(&c),
            issuer: &meta.issuer,
            authorization_endpoint: &meta.authorization_endpoint,
            token_endpoint: &meta.token_endpoint,
            metadata_digest: &digest,
            resource: &resource,
            redirect_uri: &redirect_uri(state),
            scopes: &json!(scopes),
            challenge: &challenge,
            challenge_method: "S256",
            client_registration_id: registration_id,
            client_id: &client_id,
            pkce_verifier_sealed: &sealed_verifier.bytes,
            pkce_verifier_key_version: sealed_verifier.key_version,
            expected_generation: conn.authorization_generation,
            ttl_secs: STATE_TTL_SECS,
        },
    )
    .await?;

    // THE COMMIT POINT for this attempt (review: start-epoch race). Nothing the
    // attempt produced is honored until the connection is proven un-reauthorized
    // since `started_with` — and the custody bag write RIDES THAT PROOF'S
    // TRANSACTION, under the same advisory lock, so the two are ONE atomic step.
    // A refusal burns the flow row we just inserted and writes nothing, so a
    // superseded attempt leaves neither a usable flow nor a repointed connection.
    if let Err(refusal) =
        commit_start_epoch(&state.pool, scope, conn.id, started_with, &oauth).await
    {
        burn_flow(state, &s, &c).await?;
        return Err(refusal);
    }

    // The boot token's expiry is the row's exact `expires_at` — one TTL.
    let boot = seal_boot_token(sealer_ref, flow.id, &s, &c, flow.expires_at.timestamp())
        .await
        .map_err(ApiError::Internal)?;
    Ok(format!("{}/v1/oauth/go?f={}", state.cfg.public_url, boot))
}

/// `POST /v1/connections/{id}/oauth/start` (admin) → `{go_url}`.
/// Also the RECONNECT path: an errored connection redoes the dance in place. The
/// browser navigates to `go_url` (the control-plane origin), which binds a
/// per-flow cookie before redirecting to the authorization server.
pub async fn start(
    principal: Principal,
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<Value>> {
    // Personal ⇒ owner-only (a non-owner 404s); organization ⇒ admin/owner.
    // The reconnect path re-authorizes the same way.
    let conn = crate::connections::connection_for_mutation(
        &state,
        &principal,
        id,
        "starting or reconnecting the OAuth flow for",
    )
    .await?;
    // The initiating user (None for the operator) is bound onto the flow row.
    let go_url = start_dance(&state, principal.scope(), principal.user_id(), conn.id).await?;
    Ok(Json(json!({ "go_url": go_url })))
}

#[derive(Deserialize)]
pub struct GoParams {
    #[serde(default)]
    pub f: Option<String>,
}

/// `GET /v1/oauth/go` — the interstitial that binds the initiating browser and
/// launches the dance. Unauthenticated by design: the AEAD-sealed boot token in
/// `f` IS the auth (a browser redirect can't carry the API token), same pattern
/// as the callback + github_app go legs. It verifies the flow row is LIVE (never
/// consuming it — the callback is the sole consumer) AND that its connection is
/// still connectable, sets the per-flow HttpOnly cookie on the CONTROL-PLANE
/// origin (why the dashboard can't set it), and 302s to the authorization
/// endpoint rebuilt FROM THE ROW with `state=s` (design D5).
pub async fn go(State(state): State<AppState>, Query(q): Query<GoParams>) -> Response {
    let Some(sealer_ref) = state.sealer.as_ref() else {
        return page(
            StatusCode::BAD_REQUEST,
            "Connection failed",
            "Credential sealing is not configured on this server.",
            None,
        );
    };
    let Some(boot) = q.f.as_deref() else {
        return page(
            StatusCode::BAD_REQUEST,
            "Connection failed",
            "Missing token.",
            None,
        );
    };
    let bt = match open_boot_token(sealer_ref, boot).await {
        Ok(v) => v,
        Err(e) => return page(StatusCode::BAD_REQUEST, "Connection failed", &e, None),
    };
    let state_hash = fluidbox_db::sha256_hex(&bt.s);
    // Peek (NEVER consume) and verify the row is live AND the one the token names.
    let row = match fluidbox_db::peek_connector_oauth_flow(&state.pool, &state_hash).await {
        Ok(Some(r))
            if r.id == bt.flow_id && r.consumed_at.is_none() && r.expires_at > Utc::now() =>
        {
            r
        }
        Ok(_) => {
            return page(
                StatusCode::BAD_REQUEST,
                "Connection failed",
                "This link expired or was already used — start the connect flow again.",
                None,
            )
        }
        Err(e) => {
            tracing::error!("oauth go: flow lookup failed: {e}");
            return page(
                StatusCode::BAD_REQUEST,
                "Connection failed",
                "Something went wrong — try again from the dashboard.",
                None,
            );
        }
    };
    // The connection can be revoked BETWEEN start and go. Refuse here rather than
    // sending the browser to the authorization server to consent for a connection
    // the callback (`complete_flow`) is going to refuse anyway. Only `revoked` —
    // `error` is the RECONNECT path (`start_dance` allows it and activation clears
    // the note), so refusing it would make an errored connection unrecoverable.
    let conn_scope = fluidbox_db::TenantScope::assume(row.tenant_id);
    let revoked = match fluidbox_db::scoped_tx(&state.pool, conn_scope).await {
        Ok(mut tx) => {
            let status = fluidbox_db::get_connection(&mut *tx, conn_scope, row.connection_id)
                .await
                .map(|c| c.map(|c| c.status));
            let _ = tx.commit().await;
            match status {
                // A vanished connection is refused for the same reason.
                Ok(Some(s)) => s == "revoked",
                Ok(None) => true,
                Err(e) => {
                    tracing::error!("oauth go: connection lookup failed: {e}");
                    return page(
                        StatusCode::BAD_REQUEST,
                        "Connection failed",
                        "Something went wrong — try again from the dashboard.",
                        None,
                    );
                }
            }
        }
        Err(e) => {
            tracing::error!("oauth go: connection lookup failed: {e}");
            return page(
                StatusCode::BAD_REQUEST,
                "Connection failed",
                "Something went wrong — try again from the dashboard.",
                None,
            );
        }
    };
    if revoked {
        return page(
            StatusCode::BAD_REQUEST,
            "Connection failed",
            "This connection is no longer available — create a new one from the dashboard.",
            None,
        );
    }
    let scopes: Vec<String> = row
        .scopes
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(Value::as_str)
                .map(String::from)
                .collect()
        })
        .unwrap_or_default();
    let authorize = match build_authorize_url(
        &row.authorization_endpoint,
        &row.client_id,
        &row.redirect_uri,
        &bt.s,
        &row.challenge,
        &row.challenge_method,
        &row.resource,
        &scopes,
    ) {
        Ok(u) => u,
        Err(e) => return page(StatusCode::BAD_REQUEST, "Connection failed", &e, None),
    };
    // 302 to the AS, binding this browser via the per-flow cookie.
    Response::builder()
        .status(StatusCode::FOUND)
        .header(axum::http::header::LOCATION, authorize)
        .header(axum::http::header::CACHE_CONTROL, "no-store")
        .header("referrer-policy", "no-referrer")
        .header(axum::http::header::SET_COOKIE, set_oauth_flow_cookie(&bt.c))
        .body(Body::empty())
        .expect("static response builds")
}

#[derive(Deserialize)]
pub struct CallbackParams {
    #[serde(default)]
    pub code: Option<String>,
    #[serde(default)]
    pub state: Option<String>,
    #[serde(default)]
    pub error: Option<String>,
    #[serde(default)]
    pub error_description: Option<String>,
}

/// Escape the five HTML metacharacters so an interpolated value can never break
/// out of text content (or the one inline attribute) into markup (R3.4). Tiny +
/// local — no new dependency; the callback page below is the sole HTML sink.
fn escape_html(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(c),
        }
    }
    out
}

/// Render the browser-facing callback page. EVERY interpolated dynamic value is
/// HTML-escaped, and the response carries a strict CSP — `default-src 'none'`
/// with `style-src 'unsafe-inline'` for the single inline `style` attribute the
/// page uses — so even a hypothetical escape gap cannot execute script. Only
/// server-authored, non-secret, non-upstream text ever reaches `body`. `cookie`
/// carries an optional `Set-Cookie` (the flow-cookie clear, on flow-ending
/// outcomes).
fn page(status: StatusCode, title: &str, body: &str, cookie: Option<String>) -> Response {
    let html = format!(
        "<!doctype html><meta charset=\"utf-8\"><title>fluidbox — {t}</title>\
         <body style=\"font-family:system-ui;max-width:38rem;margin:4rem auto;line-height:1.5\">\
         <h2>{t}</h2><p>{b}</p></body>",
        t = escape_html(title),
        b = escape_html(body),
    );
    let mut builder = Response::builder().status(status).header(
        axum::http::header::CONTENT_SECURITY_POLICY,
        "default-src 'none'; style-src 'unsafe-inline'",
    );
    if let Some(c) = cookie {
        builder = builder.header(axum::http::header::SET_COOKIE, c);
    }
    builder
        .body(Body::from(html))
        .expect("static response builds")
}

/// Log an internal (database / infrastructure) failure and hand the BROWSER one
/// generic line. The callback page is unauthenticated, so sqlx text — constraint
/// names, table names, connection strings — must never reach it; the same
/// sanitization discipline the broker applies to upstream AS error text. `stage`
/// is a fixed server-authored label, never request data.
fn internal_page_error(stage: &'static str, e: impl std::fmt::Display) -> String {
    tracing::warn!(stage, error = %e, "oauth callback: internal failure");
    "Something went wrong completing the connection — try again from the dashboard.".to_string()
}

/// Collapse an authorization-server-supplied `error` code to a known OAuth 2.0
/// slug (RFC 6749 §4.1.2.1 / §5.2), or `"other"` for anything else. The AS
/// controls this field, so only a fixed allowlist may reach the logs verbatim —
/// an arbitrary value (which could carry echoed credential material) never does.
fn known_oauth_error(code: &str) -> &'static str {
    match code {
        "invalid_grant" => "invalid_grant",
        "invalid_client" => "invalid_client",
        "invalid_request" => "invalid_request",
        "access_denied" => "access_denied",
        "server_error" => "server_error",
        "temporarily_unavailable" => "temporarily_unavailable",
        _ => "other",
    }
}

/// `GET /v1/oauth/callback` — THE one stable redirect URI. Unauthenticated by
/// design (a browser redirect can't carry the admin token). The authentication is
/// the ONE-TIME flow claim with the initiating-browser cookie hash INSIDE the
/// predicate (invariant 20): nothing is trusted before it claims. Browser-facing:
/// answers HTML, never JSON errors. Upstream-derived text is NEVER reflected — it
/// goes to the server log and the browser sees a generic line (R3.4).
///
/// Ordering is load-bearing (design D5): read cookie → claim (one-time + browser)
/// → on miss, `peek` splits wrong-browser (403, row UNBURNED, cookie kept) from
/// unknown/expired/consumed (400 generic) → on a claimed row, surface an AS error
/// FIRST (a refusal is what actually happened — reporting a coherence failure
/// instead would misdescribe it), then verify connection coherence + generation,
/// else exchange FROM THE ROW. Every flow-ending outcome clears the cookie; the
/// wrong-browser 403 does NOT (the right browser may still complete).
pub async fn callback(
    State(state): State<AppState>,
    Query(p): Query<CallbackParams>,
    headers: HeaderMap,
) -> Response {
    if state.sealer.is_none() {
        return page(
            StatusCode::BAD_REQUEST,
            "Connection failed",
            "Credential sealing is not configured on this server.",
            None,
        );
    }
    // The initiating-browser cookie is the second factor. Missing → 400 generic;
    // we do NOT touch the row (the claim's browser predicate needs it, and we must
    // not peek-and-reveal without it) — design :646-656.
    let Some(cookie) = oauth_flow_cookie(&headers) else {
        return page(
            StatusCode::BAD_REQUEST,
            "Connection failed",
            "This browser did not start the connect flow — start again from the dashboard.",
            None,
        );
    };
    let Some(state_param) = p.state.as_deref() else {
        return page(
            StatusCode::BAD_REQUEST,
            "Connection failed",
            "Missing state parameter.",
            None,
        );
    };
    let state_hash = fluidbox_db::sha256_hex(state_param);
    let browser_hash = fluidbox_db::sha256_hex(&cookie);
    // The one-time claim: `browser_hash` sits INSIDE the single-use predicate, so a
    // wrong browser matches nothing and BURNS NOTHING (invariant 20).
    let flow = match fluidbox_db::claim_connector_oauth_flow(
        &state.pool,
        &state_hash,
        &browser_hash,
    )
    .await
    {
        Ok(Some(row)) => row,
        Ok(None) => {
            // Split wrong-browser (row still live → 403, UNBURNED, cookie KEPT so
            // the right browser can still complete) from unknown/expired/consumed
            // (→ 400 generic).
            return match fluidbox_db::peek_connector_oauth_flow(&state.pool, &state_hash).await {
                Ok(Some(r)) if r.consumed_at.is_none() && r.expires_at > Utc::now() => page(
                    StatusCode::FORBIDDEN,
                    "Connection failed",
                    "This authorization was not started by this browser.",
                    None,
                ),
                _ => page(
                    StatusCode::BAD_REQUEST,
                    "Connection failed",
                    "This authorization link is invalid, expired, or already used.",
                    None,
                ),
            };
        }
        Err(e) => {
            tracing::error!("oauth callback: flow claim failed: {e}");
            return page(
                StatusCode::BAD_REQUEST,
                "Connection failed",
                "Something went wrong — try again from the dashboard.",
                None,
            );
        }
    };
    // The flow is now BURNED — every outcome from here clears the cookie.
    let clear = Some(clear_oauth_flow_cookie());
    match complete_flow(
        &state,
        &flow,
        p.code.as_deref(),
        p.error.as_deref(),
        p.error_description.as_deref(),
    )
    .await
    {
        Ok(note) => page(
            StatusCode::OK,
            "Connected",
            &format!("The connection is active.{note} You can close this tab."),
            clear,
        ),
        Err(e) => page(StatusCode::BAD_REQUEST, "Connection failed", &e, clear),
    }
}

/// The client identity resolved for a token exchange / refresh: the `client_id`
/// and the (transient, unsealed) confidential `secret` if any. `registration` is
/// the shared row when the identity is registration-sourced — the exchange's
/// `invalid_client` disposition needs it to decide whether to retire it.
struct ExchangeClient {
    client_id: String,
    secret: Option<String>,
    registration: Option<fluidbox_db::OauthClientRegistrationRow>,
}

/// Resolve the client identity for a code exchange / refresh. Prefers the shared
/// registration row (`registration_id`) — unsealing ITS secret under the
/// deployment DEK — and falls back to `client_id` + the per-connection legacy
/// secret for connections created before Task 3 (or a `registration_id` whose row
/// a different connection's retirement deleted; a public client keeps working on
/// the stored `client_id` alone — and the NEXT dance re-resolves the identity,
/// because a missing row makes it stale). The callback passes these OFF THE FROZEN FLOW
/// ROW (the row is the authority — invariant 20); the refresh path passes them off
/// the connection's `oauth` bag. Reads run THROUGH `db` so a refresh stays on its
/// single lock-holding connection (design D6).
async fn resolve_exchange_client(
    state: &AppState,
    db: &mut sqlx::PgConnection,
    scope: fluidbox_db::TenantScope,
    conn_id: Uuid,
    registration_id: Option<Uuid>,
    client_id: &str,
) -> Result<ExchangeClient, String> {
    let sealer_ref = state.sealer.as_ref().ok_or("credential key missing")?;
    if let Some(reg_id) = registration_id {
        if let Some(reg) = fluidbox_db::find_client_registration_by_id(&mut *db, reg_id)
            .await
            .map_err(|e| format!("client registration lookup failed: {e}"))?
        {
            let secret = match &reg.client_secret_sealed {
                Some(bytes) => Some(
                    sealer_ref
                        .open(
                            bytes,
                            reg.client_secret_key_version,
                            sealer_ref.deployment_ctx(SealFamily::RegistrationClientSecret),
                        )
                        .await
                        .map_err(|_| "registration client secret unseal failed")?,
                ),
                None => None,
            };
            return Ok(ExchangeClient {
                client_id: reg.client_id.clone(),
                secret,
                registration: Some(reg),
            });
        }
        // The row is gone (a retirement deleted it): fall through to the passed
        // `client_id` + per-connection legacy secret.
    }
    let secret = match fluidbox_db::connection_client_secret_sealed(&mut *db, scope, conn_id)
        .await
        .map_err(|e| format!("client secret lookup failed: {e}"))?
    {
        Some((bytes, kv)) => Some(
            sealer_ref
                .open(
                    &bytes,
                    kv,
                    SealCtx::new(scope.tenant_id(), SealFamily::ConnectionClientSecret),
                )
                .await
                .map_err(|_| "client secret unseal failed")?,
        ),
        None => None,
    };
    Ok(ExchangeClient {
        client_id: client_id.to_string(),
        secret,
        registration: None,
    })
}

/// Outcome of a code exchange. `InvalidClient` is surfaced typed so the caller can
/// retire the rejected shared registration (a repair for the NEXT dance — never a
/// retry of this code); `Other` carries a browser-safe message.
enum ExchangeOutcome {
    Ok(Value),
    InvalidClient,
    Other(String),
}

/// One authorization-code exchange round trip. Upstream error text is sanitized
/// exactly as before (allowlisted code + status + digest to the log; generic to
/// the browser). A token-endpoint `invalid_client` is returned typed.
#[allow(clippy::too_many_arguments)]
async fn do_code_exchange(
    state: &AppState,
    token_endpoint: &str,
    client_id: &str,
    secret: Option<&str>,
    code: &str,
    verifier: &str,
    redirect: &str,
    resource: Option<&str>,
) -> ExchangeOutcome {
    // Admit the token endpoint before dialing (C1). It was frozen from AS
    // metadata at flow start; a denial maps to the exchange-failure shape.
    if let Err(e) = admit_oauth(token_endpoint, &state.egress_policy) {
        return ExchangeOutcome::Other(e);
    }
    let mut form: Vec<(&str, &str)> = vec![
        ("grant_type", "authorization_code"),
        ("code", code),
        ("client_id", client_id),
        ("code_verifier", verifier),
        ("redirect_uri", redirect),
    ];
    if let Some(r) = resource {
        form.push(("resource", r));
    }
    // NO-REDIRECT client (`egress_http`, `redirect::Policy::none()`) — NOT the
    // redirect-following `identity_http`. On a 307/308 reqwest REPLAYS the body,
    // so a token-leg redirect would forward the authorization code + PKCE
    // verifier to whatever other host the AS names; stripping a cross-origin
    // `Authorization` header does nothing for a BODY. Refused outright rather
    // than same-origin-restricted: this flow FROZE `token_endpoint` at start
    // (RFC 8414 metadata names it exactly), so a redirect here means the
    // endpoint moved under us mid-flow — never something to follow. A 3xx is
    // then simply a non-success status and falls through to the error branch.
    let mut req = state
        .egress_http
        .post(token_endpoint)
        .timeout(HTTP_TIMEOUT)
        .header("content-type", "application/x-www-form-urlencoded")
        .body(form_body(&form));
    if let Some(s) = secret {
        req = req.basic_auth(client_id, Some(s));
    }
    let mut res = match req.send().await {
        Ok(r) => r,
        Err(e) => return ExchangeOutcome::Other(format!("token exchange failed: {e}")),
    };
    let status = res.status();
    // I3: bounded read (256 KiB) — the token endpoint is attacker-influenced.
    let v: Value = crate::egress::read_json_bounded(&mut res)
        .await
        .unwrap_or(Value::Null);
    if status.is_success() {
        return ExchangeOutcome::Ok(v);
    }
    // The token endpoint's JSON is attacker-controlled: a malicious AS can put the
    // code, PKCE verifier, or client secret into `error`. Log ONLY an allowlisted
    // code + status + a bounded digest — never the verbatim value (R3.4).
    let err = v["error"].as_str().unwrap_or("");
    let raw = v.get("error").map(ToString::to_string).unwrap_or_default();
    tracing::warn!(
        %status,
        oauth_error = known_oauth_error(err),
        detail = %crate::broker::msg_digest(&raw),
        "oauth callback: token exchange rejected"
    );
    if err == "invalid_client" {
        return ExchangeOutcome::InvalidClient;
    }
    ExchangeOutcome::Other(
        "the authorization server rejected the token exchange — reconnect and try again".into(),
    )
}

/// The TERMINAL disposition of an exchange-time `invalid_client` (pure): whether
/// the shared registration row should be RETIRED, plus the browser-facing message.
///
/// There is deliberately no "retry" disposition. RFC 6749 §4.1.3 binds an
/// authorization code to the client it was issued to, so re-exchanging the SAME
/// code under a freshly registered `client_id` is `invalid_grant` ("code was
/// issued to another client") — a retry could only ever have failed. Retiring the
/// rejected registration is therefore a repair for the NEXT dance, and the user is
/// told to start the flow again (which is also the only way to re-consent — no
/// user is present on this browser leg to approve a second authorization).
///
/// Only a registration-sourced identity that records its `registration_endpoint`
/// is worth retiring: that is the one a fresh resolution can replace with a
/// DIFFERENT `client_id` (DCR). A CIMD row's client_id is this deployment's
/// document URL, so re-minting it reproduces exactly what the AS just rejected; a
/// per-connection pre-registered/legacy secret has no shared row at all (the AS
/// rejected operator-supplied credentials — a human must fix them).
fn invalid_client_disposition(client: &ExchangeClient) -> (bool, &'static str) {
    let retire = client
        .registration
        .as_ref()
        .is_some_and(|r| r.registration_endpoint.is_some());
    if retire {
        (
            true,
            "the authorization server rejected this deployment's registered OAuth client — \
             start the connect flow again from the dashboard to register a fresh one",
        )
    } else {
        (
            false,
            "the authorization server rejected the client — reconnect and try again",
        )
    }
}

/// Retire the shared client registration the token endpoint rejected with
/// `invalid_client`, so the NEXT dance re-resolves a fresh identity instead of
/// replaying the dead one. Repair-for-next-time ONLY — see
/// [`invalid_client_disposition`] for why this exchange cannot be rescued.
///
/// The delete is safe by construction: `connector_oauth_flows.client_registration_id`
/// is `on delete set null` (migration 0016), so the very flow row being completed —
/// which always references this registration and is retained 7 days — cannot
/// FK-violate it. Sibling connections whose `oauth.registration_id` pointed here
/// find the row missing on their next dance and re-resolve
/// ([`stored_identity_stale`]'s `registration_missing`), so nothing dangles.
///
/// The DELETE rides the audited system-worker entry point: 0018 admits mutation of
/// a global row (`tenant_id is null`) only under the bypass GUC, and a filtered
/// DELETE would "succeed" against zero rows — leaving the dead identity adopted
/// forever, which is exactly the bug this function exists to prevent.
///
/// Best effort: a failed delete is logged and reported as "not retired" — the user
/// still restarts the flow, and the next attempt simply meets the same live row.
/// A REFRESH-path `invalid_client` deliberately does NOT come here — it flips the
/// connection to `error` and waits for human re-consent (design D6).
async fn retire_rejected_registration(state: &AppState, client: &ExchangeClient) -> bool {
    let (retire, _) = invalid_client_disposition(client);
    if !retire {
        return false;
    }
    let reg = client
        .registration
        .as_ref()
        .expect("the retire disposition proved the registration is present");
    tracing::info!(
        registration = %reg.id,
        "oauth callback: invalid_client — retiring the rejected shared client registration"
    );
    match fluidbox_db::system_worker::delete_global_registration(&state.pool, reg.id).await {
        Ok(()) => true,
        Err(e) => {
            tracing::warn!(
                registration = %reg.id,
                error = %e,
                "oauth callback: could not retire the rejected client registration"
            );
            false
        }
    }
}

/// What the user is told when this flow's activation expectation no longer
/// holds: a newer authorization for the same connection already landed. Used by
/// BOTH the pre-exchange fast refusal and the CAS refusal, so the two cannot
/// drift apart.
const SUPERSEDED_MSG: &str =
    "this authorization was superseded by a newer one — restart the connect flow";

/// The connection's last successful OAuth activation instant, as stamped by
/// `activate_connection_oauth` (DB clock, SQL-side, never caller-supplied).
///
/// `None` = never activated. A present-but-unparseable stamp yields
/// `DateTime::<Utc>::MAX_UTC`, i.e. EVERY flow reads as superseded: we cannot
/// prove freshness, and the DB CAS's `::timestamptz` cast would hard-error on
/// the same value — refusing with "restart the connect flow" is the honest
/// answer, not a 500.
fn last_activated_at(oauth: Option<&Value>) -> Option<DateTime<Utc>> {
    let raw = oauth?.get(fluidbox_db::ACTIVATED_AT_KEY)?;
    if raw.is_null() {
        return None;
    }
    Some(
        raw.as_str()
            .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
            .map(|d| d.with_timezone(&Utc))
            .unwrap_or(DateTime::<Utc>::MAX_UTC),
    )
}

/// Has a newer authorization for this connection already landed, making THIS
/// flow's expectation stale? PURE — the same two predicates the activation CAS
/// re-asserts inside its UPDATE (review H2):
///   - the frozen generation moved (a RECONNECT activated), or
///   - the connection was activated at-or-after this flow started (which is what
///     catches FIRST connect, where `pending → active` does not bump the
///     generation and two racing callbacks froze the same one).
///
/// `>=` not `>`: equal instants are unorderable, so they fail closed.
fn flow_superseded(
    conn_generation: i32,
    last_activated: Option<DateTime<Utc>>,
    expected_generation: i32,
    flow_created_at: DateTime<Utc>,
) -> bool {
    conn_generation != expected_generation || last_activated.is_some_and(|t| t >= flow_created_at)
}

/// [`flow_superseded`] against a freshly read connection row + its flow.
fn superseded_flow(
    conn: &fluidbox_db::IntegrationConnectionRow,
    flow: &fluidbox_db::ConnectorOauthFlowRow,
) -> bool {
    flow_superseded(
        conn.authorization_generation,
        last_activated_at(conn.oauth.as_ref()),
        flow.expected_generation,
        flow.created_at,
    )
}

/// The connection's authorization state as an authorization ATTEMPT found it —
/// frozen in `start_dance`'s initial read, BEFORE any outbound HTTP.
///
/// Why the flow row's `created_at` cannot play this role: it is stamped only
/// after discovery + client resolution (seconds of outbound HTTP). Two starts
/// that both read the same pending connection can therefore have their flow rows
/// materialize on OPPOSITE sides of a successful activation — the slower one's
/// row post-dating an activation its own expectation pre-dates, which passes
/// both activation-CAS predicates (the generation did not move on a first
/// connect, and `activated_at < created_at` holds). This type is that missing
/// epoch, expressed as the connection state itself rather than a clock reading,
/// so it needs no new column and no cross-clock comparison.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct StartExpectation {
    generation: i32,
    activated_at: Option<DateTime<Utc>>,
}

impl StartExpectation {
    fn of(conn: &fluidbox_db::IntegrationConnectionRow) -> Self {
        Self {
            generation: conn.authorization_generation,
            activated_at: last_activated_at(conn.oauth.as_ref()),
        }
    }
}

/// Has the connection been re-authorized since this attempt began? PURE.
///
/// Equality on BOTH halves, not the CAS's ordering test: the question here is
/// "did ANYTHING activate since I read this row", and any movement of either
/// value answers yes. `None` for `current` (the connection vanished) is movement
/// too. An unparseable activation stamp reads as `MAX_UTC` (see
/// [`last_activated_at`]) and so differs from every real one — fail closed.
fn start_expectation_moved(
    started_with: StartExpectation,
    current: Option<StartExpectation>,
) -> bool {
    current != Some(started_with)
}

/// What the commit point does with an attempt, as a VALUE — the whole decision,
/// pure, so "a superseded attempt writes nothing" is testable without a database.
/// [`commit_start_epoch`] only executes it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StartCommit {
    /// Nothing activated since the attempt began ⇒ persist its custody bag, in
    /// the very transaction that proved it.
    PersistBag,
    /// A newer authorization landed ⇒ write NOTHING (no bag, no repointed token
    /// endpoint or client identity) and refuse with [`SUPERSEDED_MSG`].
    Superseded,
}

/// The commit point's decision. ONE predicate gates BOTH consequences — whether
/// this attempt's flow row survives and whether its custody bag is persisted —
/// so the two can never drift apart.
fn start_commit_decision(
    started_with: StartExpectation,
    current: Option<StartExpectation>,
) -> StartCommit {
    if start_expectation_moved(started_with, current) {
        StartCommit::Superseded
    } else {
        StartCommit::PersistBag
    }
}

/// An authorization attempt's COMMIT POINT: prove the connection has not been
/// re-authorized since [`StartExpectation`] was frozen (the flow row is already
/// inserted), and — in the SAME transaction, under the SAME lock — persist the
/// custody bag this attempt discovered: endpoints, client identity, registration
/// pointer.
///
/// **The bag write rides this transaction rather than taking its own round trip
/// (review #32).** It is a whole-bag REPLACE closing a read-modify-write that
/// spanned discovery, so landing it on a connection a sibling flow has just
/// activated would pair THAT grant's refresh token with THIS attempt's token
/// endpoint + client identity — the winner's refresh would then authenticate to
/// the wrong client at the wrong endpoint. Guarding it with its own predicate
/// would work, but a second guarded round trip is strictly weaker than being
/// inside the transaction that already holds the lock: here there is no interval
/// between the proof and the write for an activation to occupy at all.
///
/// It is ordered against EVERY activation by the connection's OAuth advisory
/// lock, which `complete_flow` holds across its activation UPDATE *and* that
/// transaction's commit. So for a given attempt every activation `A` is in
/// exactly one of two classes:
///
///   - `A` committed before we take the lock ⇒ our re-read OBSERVES it (`A` could
///     not have been mid-UPDATE without us blocking on the lock), the frozen
///     expectation differs, and we refuse — writing no bag — while the caller
///     burns the flow row, whose callback can then never claim it.
///   - `A` takes the lock only after we RELEASE it (at this transaction's commit,
///     which is also when the bag lands) ⇒ its `clock_timestamp()` activation
///     stamp is strictly later than this read, hence later than our flow row's
///     `created_at` (inserted before this call), so the activation CAS
///     `activated_at < flow.created_at` refuses OUR flow. `A` then writes its own
///     bag over ours, which is the correct outcome: the newest authorization owns
///     the connection's custody state.
///
/// There is no third class — no activation can interleave between the proof and
/// the bag write, because they are the same transaction — so "one activation
/// invalidates every sibling flow" finally holds for attempts that merely BEGAN
/// before it, not only for flow rows that already existed when it landed.
///
/// THIS RESTS ON: `activate_connection_oauth` is only ever called while holding
/// `acquire_oauth_lock` for the same connection (today exactly one call site —
/// `complete_flow`). A second, unlocked activation writer would silently reopen
/// the race.
///
/// One pooled connection at a time (lock + read + update + commit, nothing
/// nested — no HTTP, no seal, no second acquire): the fixed-size-pool hazard
/// `complete_flow`'s activation documents applies here too, so the burn runs
/// AFTER this transaction ends. Lock-then-row is also the ordering every other
/// oauth writer uses, so the extra row lock introduces no deadlock cycle.
async fn commit_start_epoch(
    pool: &sqlx::PgPool,
    scope: fluidbox_db::TenantScope,
    conn_id: Uuid,
    started_with: StartExpectation,
    oauth: &Value,
) -> ApiResult<()> {
    let mut tx = fluidbox_db::scoped_tx(pool, scope).await?;
    fluidbox_db::acquire_oauth_lock(&mut tx, conn_id).await?;
    let current = fluidbox_db::get_connection(&mut *tx, scope, conn_id).await?;
    match start_commit_decision(started_with, current.as_ref().map(StartExpectation::of)) {
        StartCommit::Superseded => {
            // Release the connection explicitly before returning: the caller
            // burns the flow row next and that needs a pooled connection this
            // one must not still be holding. Nothing was written, so a failed
            // rollback changes no outcome — it is logged, never allowed to
            // replace the refusal the caller must surface.
            if let Err(e) = tx.rollback().await {
                tracing::warn!(error = %e, "oauth start: rollback after a superseded refusal failed");
            }
            tracing::info!(
                connection = %conn_id,
                "oauth start: the connection was reauthorized while this attempt was in discovery — refusing it"
            );
            Err(ApiError::Conflict(SUPERSEDED_MSG.into()))
        }
        StartCommit::PersistBag => {
            // Idempotent re-runs overwrite with fresh endpoints; the client
            // identity sticks. `update_connection_oauth` is executor-generic
            // precisely so this rides `tx` — see its doc comment.
            fluidbox_db::update_connection_oauth(&mut *tx, scope, conn_id, oauth).await?;
            tx.commit().await?;
            Ok(())
        }
    }
}

/// Retire a flow row this attempt inserted but must not honor, through the SAME
/// one-time claim the callback uses — after this the row can never be exchanged.
///
/// LOAD-BEARING, not best effort: the row we are burning is precisely the one the
/// activation CAS cannot catch (its `created_at` post-dates the activation that
/// superseded it), so leaving it live would leave the race open for the flow's
/// full TTL. One retry, then a hard error rather than a silent success.
async fn burn_flow(state: &AppState, s: &str, c: &str) -> ApiResult<()> {
    let (state_hash, browser_hash) = (fluidbox_db::sha256_hex(s), fluidbox_db::sha256_hex(c));
    let mut last = None;
    for _ in 0..2 {
        match fluidbox_db::claim_connector_oauth_flow(&state.pool, &state_hash, &browser_hash).await
        {
            Ok(_) => return Ok(()),
            Err(e) => last = Some(e),
        }
    }
    tracing::error!(
        error = ?last,
        "oauth start: could not retire a superseded flow row — it stays exchangeable until it expires"
    );
    Err(ApiError::Internal(
        "could not retire the superseded authorization — reconnect this connection".into(),
    ))
}

/// Complete a claimed flow (invariant 20): verify connection coherence + frozen
/// generation, unseal the PKCE verifier, exchange the code AGAINST THE FROZEN ROW
/// (its token_endpoint / client identity / resource — never re-discovered, closing
/// AS mix-up + discovery-change races), then seal the rotating refresh token,
/// activate (a RECONNECT bumps the generation — a re-consent may change the
/// account/issuer/audience, so any in-flight run bound to the old generation fails
/// closed; design :294-296), and photograph the pending snapshot. The caller has
/// already burned the flow; this never touches the flow row again.
async fn complete_flow(
    state: &AppState,
    flow: &fluidbox_db::ConnectorOauthFlowRow,
    code: Option<&str>,
    error: Option<&str>,
    error_description: Option<&str>,
) -> Result<String, String> {
    let sealer_ref = state.sealer.as_ref().ok_or("credential key missing")?;
    // The AS returned an error (denied consent, etc.) — surfaced FIRST, before any
    // connection coherence check: the AS's refusal is what actually happened, and
    // reporting "connection was reauthorized" for a user who clicked Deny during a
    // concurrent reconnect would be a lie. The flow is already claimed (burned) —
    // a denied consent is terminal for it either way. Log ONLY an allowlisted code
    // + a bounded digest (the AS text is attacker-influenceable and can echo the
    // state/code/verifier/secret); the browser sees a generic line (R3.4).
    if let Some(err) = error {
        let detail = error_description.filter(|s| !s.is_empty()).unwrap_or(err);
        tracing::warn!(
            oauth_error = known_oauth_error(err),
            detail = %crate::broker::msg_digest(detail),
            "oauth callback: authorization server refused"
        );
        return Err(
            "The authorization server refused the request. You can close this tab and try again."
                .into(),
        );
    }
    // The ROW is the authority now (its tenant was verified when the start
    // principal inserted it): load the connection under the row's own tenant scope,
    // NOT the cross-tenant system-worker loader the stateless state once required.
    let scope = fluidbox_db::TenantScope::assume(flow.tenant_id);
    // Tenant known (the flow's own, verified when the start principal inserted it)
    // → scoped_tx so the RLS GUC rides the executor-generic read.
    let mut conn_tx = fluidbox_db::scoped_tx(&state.pool, scope)
        .await
        .map_err(|e| internal_page_error("connection lookup", e))?;
    let conn = fluidbox_db::get_connection(&mut *conn_tx, scope, flow.connection_id)
        .await
        .map_err(|e| internal_page_error("connection lookup", e))?
        .ok_or("connection not found — it may have been removed")?;
    conn_tx
        .commit()
        .await
        .map_err(|e| internal_page_error("connection lookup", e))?;
    if conn.status == "revoked" {
        return Err("connection was revoked — create a new one".into());
    }
    // Generation coherence: a reconnect that landed mid-authorization bumped the
    // generation past what the flow froze — refuse rather than seal a fresh grant
    // onto a superseded binding (design :1535, generation acceptance).
    //
    // THIS CHECK IS AN OPTIMIZATION, NOT THE BOUNDARY (review H2): it runs BEFORE
    // the code exchange — a full HTTP round trip — so a sibling flow can activate
    // in the window between it and the write. It exists to avoid burning an
    // authorization code we already know we cannot use; the security boundary is
    // the compare-and-swap in `activate_connection_oauth` below, which re-asserts
    // BOTH of these predicates in the UPDATE itself.
    if superseded_flow(&conn, flow) {
        return Err(SUPERSEDED_MSG.into());
    }
    let code = code.ok_or("Missing authorization code.")?;
    // Unseal the PKCE verifier (the challenge alone cannot exchange — design
    // :638-639). ROW tenant ctx.
    let verifier = sealer_ref
        .open(
            &flow.pkce_verifier_sealed,
            flow.pkce_verifier_key_version,
            SealCtx::new(flow.tenant_id, SealFamily::OauthFlowPkceVerifier),
        )
        .await
        .map_err(|_| "PKCE verifier unseal failed — start the connect flow again")?;

    // The connection's oauth bag (for the granted-scope fallback); token_endpoint /
    // client identity / resource / redirect come from the FROZEN ROW.
    let oauth = conn.oauth.clone().unwrap_or_else(|| json!({}));
    let resource = Some(flow.resource.as_str());

    // Resolve the client identity (shared registration preferred; per-connection
    // legacy fallback) from the ROW. Uses a short-lived scoped transaction (the
    // per-connection secret read is tenant-scoped under RLS) — the activation
    // critical section below takes its own, so nothing nests.
    let mut resolve_tx = fluidbox_db::scoped_tx(&state.pool, scope)
        .await
        .map_err(|e| internal_page_error("db acquire", e))?;
    let client = resolve_exchange_client(
        state,
        &mut resolve_tx,
        scope,
        conn.id,
        flow.client_registration_id,
        &flow.client_id,
    )
    .await
    .map_err(|e| internal_page_error("client resolution", e))?;
    resolve_tx
        .commit()
        .await
        .map_err(|e| internal_page_error("db commit", e))?;

    // Exchange the code. Exactly ONE exchange: an `invalid_client` retires the
    // rejected shared registration (a repair for the NEXT dance) and reports —
    // re-exchanging this code under a fresh client_id would be `invalid_grant` by
    // construction (RFC 6749 §4.1.3; see `invalid_client_disposition`).
    let v = match do_code_exchange(
        state,
        &flow.token_endpoint,
        &client.client_id,
        client.secret.as_deref(),
        code,
        &verifier,
        &flow.redirect_uri,
        resource,
    )
    .await
    {
        ExchangeOutcome::Ok(v) => v,
        ExchangeOutcome::Other(msg) => return Err(msg),
        ExchangeOutcome::InvalidClient => {
            let (_, msg) = invalid_client_disposition(&client);
            retire_rejected_registration(state, &client).await;
            return Err(msg.to_string());
        }
    };
    let access = v["access_token"]
        .as_str()
        .ok_or("token response has no access_token")?
        .to_string();
    let refresh = v["refresh_token"].as_str().ok_or(
        "the authorization server returned no refresh token — fluidbox cannot custody this \
         connection (it would die with the first access token)",
    )?;
    let expires_in = v["expires_in"].as_i64().unwrap_or(3600);
    let granted: Vec<String> = match v["scope"].as_str() {
        Some(s) => s.split_whitespace().map(String::from).collect(),
        None => oauth
            .get("scopes")
            .and_then(Value::as_array)
            .map(|a| {
                a.iter()
                    .filter_map(Value::as_str)
                    .map(String::from)
                    .collect()
            })
            .unwrap_or_default(),
    };

    // Whether this is a FIRST connect (pending→active) or a RECONNECT (an
    // ever-activated connection re-consenting) decides the generation bump. That
    // decision is made INSIDE activate_connection_oauth from the row's pre-update
    // status under the row lock (B1) — never a boolean derived from the pre-lock
    // read above, which two racing first-connects would both compute as `false`.
    // A reconnect (from a non-`pending` status) may be a new account/issuer/
    // audience, so it bumps the generation and any in-flight run bound to the old
    // one fails closed (design :294-296).

    // Seal + activate (clears a previous error note).
    let mut clean = oauth.clone();
    if let Some(o) = clean.as_object_mut() {
        o.remove("error");
    }
    // Seal the rotating refresh token BEFORE entering the advisory-lock critical
    // section: in KMS mode the seal may mint/unwrap this tenant's DEK on a
    // SEPARATE pooled connection, which must not run while the lock's connection
    // is held (the same fixed-pool hazard the activation UPDATE routes around).
    let sealed_refresh = sealer_ref
        .seal(
            refresh,
            SealCtx::new(scope.tenant_id(), SealFamily::ConnectionCredential),
        )
        .await
        .map_err(|e| internal_page_error("refresh-token seal", e))?;

    // Serialize the activation against the refresh path (R3.2): acquire the SAME
    // per-connection in-process mutex + Postgres advisory lock `ensure_access_token`
    // uses, so a concurrent in-flight refresh rotating the OLD grant's token can
    // never clobber the NEW grant landing here (which would restore a superseded
    // grant). THE ADVISORY LOCK IS ALSO WHAT ORDERS THIS ACTIVATION AGAINST THE
    // START SIDE — `commit_start_epoch` takes it to prove no activation slipped
    // under an in-flight attempt AND to land that attempt's custody bag in the
    // same transaction — so `activate_connection_oauth` must never be called
    // outside this lock. Held only across the activation write + cache
    // update; released
    // BEFORE the photograph, which re-mints under its own lock (a nested acquire
    // of the same in-process mutex would deadlock).
    {
        let lock = {
            let mut locks = state.oauth_locks.lock().await;
            locks.entry(conn.id).or_default().clone()
        };
        let _guard = lock.lock().await;
        // scoped_tx (not a bare begin): the activate UPDATE below is tenant-scoped
        // under RLS, and the whole critical section still borrows exactly ONE pooled
        // connection (the advisory lock + activation ride this tx).
        let mut tx = fluidbox_db::scoped_tx(&state.pool, scope)
            .await
            .map_err(|e| internal_page_error("oauth lock txn", e))?;
        fluidbox_db::acquire_oauth_lock(&mut tx, conn.id)
            .await
            .map_err(|e| internal_page_error("oauth advisory lock", e))?;
        // The activate + generation bump is ONE atomic UPDATE (R1.3+R3.1): no
        // crash window where a reconnected grant is active yet still serving the
        // prior generation. The returned row carries the FINAL generation. It runs
        // THROUGH `tx` (the connection that holds the advisory lock) so the whole
        // critical section borrows exactly ONE pooled connection — routing this
        // back through `&state.pool` would need a SECOND connection while the first
        // is held, and ten concurrent callbacks each doing that deadlock the
        // fixed-size pool until the acquire timeout.
        let activated = fluidbox_db::activate_connection_oauth(
            &mut *tx,
            scope,
            conn.id,
            &sealed_refresh.bytes,
            sealed_refresh.key_version,
            &clean,
            &json!(granted),
            // THE SECURITY BOUNDARY (review H2): the activation is a
            // compare-and-swap on the flow's OWN start-time expectation —
            // the frozen generation AND "nothing has activated this
            // connection since this flow started". A flow superseded by a
            // newer authorization (a competing admin's reconnect, or a
            // sibling first-connect on the same pending row) matches ZERO
            // rows here, so it can never overwrite the newer grant's refresh
            // token. Both values are frozen at START — never re-read now,
            // which is precisely the TOCTOU the pre-exchange check has.
            flow.expected_generation,
            flow.created_at,
        )
        .await
        .map_err(|e| internal_page_error("activation", e))?
        .ok_or(SUPERSEDED_MSG)?;
        // Commit (releasing the advisory lock) BEFORE touching the token cache:
        // a cache entry must never outlive a rolled-back activation. A failed or
        // AMBIGUOUS commit fails closed: the AS may already have invalidated the
        // rotated-away refresh token, so serving this access token while the DB
        // kept the dead grant would corrupt custody. Drop every cached generation
        // and refuse — the caller reconnects/retries.
        if let Err(e) = tx.commit().await {
            invalidate_access(state, conn.id).await;
            // The sqlx text goes to the log only — this page is unauthenticated.
            tracing::warn!(stage = "activation commit", error = %e, "oauth callback: internal failure");
            return Err(
                "could not persist the connection — start the connect flow again from the \
                 dashboard"
                    .into(),
            );
        }
        // Evict any token cached under a PRIOR generation BEFORE caching the new
        // one: `invalidate_access` drops every generation for this connection, so
        // caching must come AFTER the eviction (otherwise it would strand the
        // fresh entry). Cache under the RETURNED (possibly bumped) generation.
        invalidate_access(state, conn.id).await;
        state.connector_tokens.lock().await.insert(
            (conn.id, activated.authorization_generation),
            (access, Utc::now() + Duration::seconds(expires_in)),
        );
    }

    // Photograph the pending snapshot with the fresh token (Phase C: snapshots,
    // not brokered bundles). A failed post-activation photograph marks the
    // connection `error` so Connect is visibly incomplete, never half-connected.
    let Some(url) = oauth
        .get("pending_snapshot")
        .and_then(|p| p.get("url"))
        .and_then(Value::as_str)
    else {
        return Ok(String::new());
    };
    let url = url.to_string();
    match crate::snapshots::photograph_connection(state, scope, conn.id, &url).await {
        Ok(snap) => {
            let count = snap.tools_json.as_array().map(|a| a.len()).unwrap_or(0);
            Ok(format!(
                " Discovered and snapshotted {count} tool(s) (v{}).",
                snap.snapshot_version
            ))
        }
        Err(e) => {
            // The broker already sanitizes upstream text (C: method + status +
            // code + digest, never the verbatim message). The persisted note is
            // kept GENERIC regardless — an untrusted upstream string must never
            // become durable connection state (it is serialized in listings +
            // rendered in the dashboard); the sanitized detail rides the log only.
            // Status flip → error is paired with token eviction (custody
            // discipline) so nothing serves the just-cached token.
            tracing::warn!(connection = %conn.id, error = %e, "oauth callback: tool discovery failed after authorization");
            // Best-effort status flip → error (RLS: the write is tenant-scoped, so
            // it rides a scoped_tx; a tx failure is swallowed like the write itself).
            if let Ok(mut err_tx) = fluidbox_db::scoped_tx(&state.pool, scope).await {
                fluidbox_db::mark_connection_error(
                    &mut *err_tx,
                    scope,
                    conn.id,
                    "MCP tool discovery failed after authorization — reconnect this connection",
                )
                .await
                .ok();
                err_tx.commit().await.ok();
            }
            invalidate_access(state, conn.id).await;
            Err(
                "authorized, but tool discovery failed — the connection is marked error; reconnect it"
                    .into(),
            )
        }
    }
}

// ─── Access-token custody (used by the broker) ────────────────────────────

/// Drop cached access tokens for a connection — EVERY authorization generation
/// (the cache key is `(connection_id, generation)`; a generation bump or status
/// flip must strand no stale token). Called on reactive-401, revoke, error,
/// suspend, and re-consent.
pub async fn invalidate_access(state: &AppState, connection_id: Uuid) {
    state
        .connector_tokens
        .lock()
        .await
        .retain(|(cid, _generation), _| *cid != connection_id);
}

/// KEEP predicate for [`invalidate_rejected_access`], factored out so the
/// singleflight-preserving semantic is unit-testable without an `AppState`:
/// an entry survives unless it belongs to `connection_id` AND still holds the
/// exact token the upstream rejected.
fn survives_rejection(
    entry_conn: Uuid,
    entry_token: &str,
    connection_id: Uuid,
    rejected: &str,
) -> bool {
    entry_conn != connection_id || entry_token != rejected
}

/// Reactive-401 eviction: drop the cached access token for `connection_id` ONLY
/// when the cache still holds the EXACT token the upstream just rejected.
///
/// The unconditional [`invalidate_access`] is wrong here and defeats the
/// singleflight it sits next to. N concurrent brokered calls all resolve the
/// same cached token, all 401 together, and then serialize through this path:
/// caller A evicts, refreshes, and caches a FRESH token — and caller B, arriving
/// a moment later, would blow that fresh token away and rotate the refresh token
/// a second time. `ensure_access_token`'s double-check never gets to fire,
/// because the entry it would have hit was just deleted. The result is one
/// refresh grant per concurrent 401 (a refresh storm, and needless rotation
/// churn against authorization servers that keep only a bounded number of valid
/// refresh tokens). Comparing the token makes B's eviction a no-op, so B's
/// `ensure_access_token` hits A's freshly-cached token and the retry rides it.
///
/// Every OTHER eviction (revoke, error, suspend, generation bump, re-consent)
/// stays unconditional — those invalidate the AUTHORITY, not one minted token.
pub async fn invalidate_rejected_access(state: &AppState, connection_id: Uuid, rejected: &str) {
    state
        .connector_tokens
        .lock()
        .await
        .retain(|(cid, _generation), (tok, _exp)| {
            survives_rejection(*cid, tok, connection_id, rejected)
        });
}

/// Return a live access token for an OAuth connection: cache hit inside the
/// expiry margin, else refresh — serialized per connection so rotation
/// never races itself.
pub async fn ensure_access_token(
    state: &AppState,
    conn: &fluidbox_db::IntegrationConnectionRow,
) -> Result<String, String> {
    let margin = Duration::seconds(EXPIRY_MARGIN_SECS);
    // The cache key carries the connection's CURRENT generation (read off the
    // fresh row the caller holds): a bump makes the prior generation's token
    // unreachable, so we never serve a superseded identity's token.
    let key = (conn.id, conn.authorization_generation);
    if let Some((tok, exp)) = state.connector_tokens.lock().await.get(&key) {
        if *exp - margin > Utc::now() {
            return Ok(tok.clone());
        }
    }
    // Two-level serialization of the refresh-token rotation:
    //  1. an in-process mutex avoids self-racing within ONE control plane, and
    //  2. a transaction-scoped Postgres advisory lock (keyed on the connection
    //     id) serializes ACROSS replicas — a second control plane can no longer
    //     double-rotate the refresh token into invalid_grant. The lock is held
    //     for the whole refresh (HTTP + rotation write) and released on commit.
    let lock = {
        let mut locks = state.oauth_locks.lock().await;
        locks.entry(conn.id).or_default().clone()
    };
    let _guard = lock.lock().await;
    // scoped_tx (not a bare begin): every DB touch in this critical section — the
    // fresh re-read and the rotation write — is tenant-scoped under RLS and rides
    // this ONE pooled connection (the advisory lock spans it). The scope is the
    // connection's own tenant.
    let scope = fluidbox_db::TenantScope::assume(conn.tenant_id);
    let mut tx = fluidbox_db::scoped_tx(&state.pool, scope)
        .await
        .map_err(|e| format!("oauth lock txn failed: {e}"))?;
    fluidbox_db::acquire_oauth_lock(&mut tx, conn.id)
        .await
        .map_err(|e| format!("oauth advisory lock failed: {e}"))?;
    // Double-check under both locks: another caller (here or on another
    // replica) may have refreshed while we waited.
    if let Some((tok, exp)) = state.connector_tokens.lock().await.get(&key) {
        if *exp - margin > Utc::now() {
            return Ok(tok.clone());
        }
    }
    // Re-read the connection under BOTH locks before touching custody (B2/R3.2):
    // the caller's `conn` row was fetched before we serialized here, so a
    // reconnect that bumped the generation (or a revoke/error) may have landed
    // while we waited. Operate on the FRESH row and refuse on any drift, so we
    // never unseal a superseded grant's refresh token or mint against a stale
    // binding. Early returns drop the tx (rollback releases the advisory lock).
    // `scope` was derived above (the connection's tenant) so it could open the tx.
    // Re-read THROUGH `tx` (the lock-holding connection), never `&state.pool`: the
    // whole critical section must borrow exactly ONE pooled connection, or N
    // concurrent refreshes — each holding one connection and reaching for a second
    // — deadlock the fixed-size pool until the acquire timeout.
    let fresh = match fluidbox_db::get_connection(&mut *tx, scope, conn.id).await {
        Ok(Some(f))
            if f.status == "active"
                && f.authorization_generation == conn.authorization_generation =>
        {
            f
        }
        Ok(_) => return Err("connection was reauthorized during refresh — retry".into()),
        Err(e) => return Err(format!("connection re-read failed during refresh: {e}")),
    };
    // The refresh runs its DB reads/writes through the SAME connection and the
    // advisory lock spans the HTTP token exchange ON PURPOSE — that serializes
    // refresh vs. reconnect so neither clobbers the other's grant (R3.2). The
    // exchange's position is unchanged; the only fix here is that the critical
    // section no longer reaches for a second pooled connection.
    let result = refresh_access_token(state, &mut tx, &fresh).await;
    // Commit (releasing the advisory lock) BEFORE writing the token cache: a
    // dropped/rolled-back tx releases the lock too, and a cached token must never
    // outlive an uncommitted rotation.
    let committed = tx.commit().await;
    // The commit check DOMINATES the inner result — evaluate it FIRST, before we
    // honor `result`. BOTH branches stage durable writes: a success rotated the
    // refresh token, and an `invalid_grant`/`invalid_client` failure staged
    // `status='error'` (~:1115). A failed or AMBIGUOUS commit therefore fails
    // closed regardless of `result`: otherwise the Err branch would surface
    // "re-authorize" while the row stayed `active` on a known-dead grant (new runs
    // could bind it), and the Ok branch could serve a token the AS may already
    // have invalidated. Drop every cached generation and refuse — the caller
    // retries.
    if let Err(e) = committed {
        invalidate_access(state, conn.id).await;
        return Err(format!("could not persist OAuth custody — retry: {e}"));
    }
    match result {
        Ok((access, expires_in)) => {
            // Cache under the generation THIS refresh ran against (== `fresh`'s,
            // verified equal to the caller's above). A concurrent reconnect bump
            // makes this (connection, old-generation) key unreachable to current
            // readers, so a stale entry can never be served.
            state.connector_tokens.lock().await.insert(
                (fresh.id, fresh.authorization_generation),
                (access.clone(), Utc::now() + Duration::seconds(expires_in)),
            );
            Ok(access)
        }
        Err(e) => Err(e),
    }
}

/// One refresh-grant round trip. Rotation: a new refresh token atomically
/// overwrites the sealed one the moment it arrives. `invalid_grant` ⇒ the
/// connection flips to `error` and every downstream path fails closed.
///
/// Runs ALL of its DB statements through `db` — the connection the caller's
/// transaction (and the per-connection advisory lock) is bound to — so the
/// whole refresh critical section borrows exactly ONE pooled connection.
/// Returns `(access_token, expires_in)`; the caller commits the transaction and
/// only THEN writes the token cache, so a cached token can never outlive an
/// uncommitted rotation.
async fn refresh_access_token(
    state: &AppState,
    db: &mut sqlx::PgConnection,
    conn: &fluidbox_db::IntegrationConnectionRow,
) -> Result<(String, i64), String> {
    let sealer_ref = state
        .sealer
        .as_ref()
        .ok_or("FLUIDBOX_CREDENTIAL_KEY not configured")?;
    // The connection row is already resolved and trusted (the broker fetched it
    // under the run's scope); derive the scope from its own tenant.
    let scope = fluidbox_db::TenantScope::assume(conn.tenant_id);
    let (sealed, kv) = fluidbox_db::connection_credential_sealed(&mut *db, scope, conn.id)
        .await
        .map_err(|e| format!("credential lookup failed: {e}"))?
        .ok_or("connection is not active — reconnect it in Connections")?;
    let refresh = sealer_ref
        .open(
            &sealed,
            kv,
            SealCtx::new(conn.tenant_id, SealFamily::ConnectionCredential),
        )
        .await
        .map_err(|_| "refresh token unseal failed (credential key rotated?) — reconnect")?;
    let oauth = conn.oauth.clone().unwrap_or_else(|| json!({}));
    let token_endpoint = oauth
        .get("token_endpoint")
        .and_then(Value::as_str)
        .ok_or("connection has no token endpoint — reconnect it")?;
    // Admit the token endpoint read from the STORED oauth bag before dialing
    // (C1). Defense in depth for pre-Phase-E rows sealed before admission
    // existed — a stored private/plain-http endpoint is refused here too.
    admit_oauth(token_endpoint, &state.egress_policy)?;
    let resource = oauth.get("resource").and_then(Value::as_str);
    // Resolve the client identity (shared registration preferred, per-connection
    // legacy fallback) THROUGH `db` — the refresh stays on its single lock-holding
    // connection. A refresh-path `invalid_client` is handled below (mark error;
    // NEVER re-register mid-refresh — no user is present to re-consent; design D6).
    // The refresh reads its client identity off the connection's `oauth` bag (the
    // frozen flow row belongs to the initial dance only).
    let registration_id = oauth
        .get("registration_id")
        .and_then(Value::as_str)
        .and_then(|s| Uuid::parse_str(s).ok());
    let client_id = oauth
        .get("client_id")
        .and_then(Value::as_str)
        .ok_or("connection has no client identity — reconnect it")?;
    let client =
        resolve_exchange_client(state, &mut *db, scope, conn.id, registration_id, client_id)
            .await?;

    let mut form: Vec<(&str, &str)> = vec![
        ("grant_type", "refresh_token"),
        ("refresh_token", &refresh),
        ("client_id", &client.client_id),
    ];
    if let Some(r) = resource {
        form.push(("resource", r));
    }
    // NO-REDIRECT client, same reason as the code-exchange leg: a 307/308 replays
    // the body, which here carries the REFRESH TOKEN itself — the longest-lived
    // credential in the connection. `egress_http` refuses the 3xx instead.
    let mut req = state
        .egress_http
        .post(token_endpoint)
        .timeout(HTTP_TIMEOUT)
        .header("content-type", "application/x-www-form-urlencoded")
        .body(form_body(&form));
    if let Some(secret) = &client.secret {
        req = req.basic_auth(&client.client_id, Some(secret));
    }
    let mut res = req
        .send()
        .await
        .map_err(|e| format!("token refresh failed: {e}"))?;
    let status = res.status();
    // I3: bounded read (256 KiB) — same ceiling the OIDC legs use.
    let v: Value = crate::egress::read_json_bounded(&mut res)
        .await
        .unwrap_or(Value::Null);
    if !status.is_success() {
        let err = v["error"].as_str().unwrap_or("");
        if err == "invalid_grant" || err == "invalid_client" {
            // `err` is one of the two matched literals here — never raw AS text —
            // so the persisted note carries no attacker-controlled bytes. Written
            // through `db`; the caller's commit makes it durable.
            fluidbox_db::mark_connection_error(
                &mut *db,
                scope,
                conn.id,
                &format!("{err} during token refresh — re-authorize this connection"),
            )
            .await
            .ok();
            invalidate_access(state, conn.id).await;
            return Err(format!(
                "oauth refresh was rejected ({err}) — the connection needs re-consent; reconnect it in Connections"
            ));
        }
        return Err(format!("oauth token refresh returned HTTP {status}"));
    }
    let access = v["access_token"]
        .as_str()
        .ok_or("refresh response has no access_token")?
        .to_string();
    let expires_in = v["expires_in"].as_i64().unwrap_or(3600);
    if let Some(new_refresh) = v["refresh_token"].as_str() {
        if new_refresh != refresh {
            let sealed_new = sealer_ref
                .seal(
                    new_refresh,
                    SealCtx::new(conn.tenant_id, SealFamily::ConnectionCredential),
                )
                .await
                .map_err(|e| format!("failed to seal rotated refresh token: {e}"))?;
            if !fluidbox_db::rotate_connection_refresh(
                &mut *db,
                scope,
                conn.id,
                &sealed_new.bytes,
                sealed_new.key_version,
                conn.authorization_generation,
            )
            .await
            .map_err(|e| format!("rotation persist failed: {e}"))?
            {
                // 0 rows: the connection was revoked/errored OR reauthorized (its
                // generation moved) beneath this in-flight refresh (R3.2). The token
                // just minted rides a grant that is no longer current — evict and
                // fail closed rather than persist a rotated OLD refresh token that
                // would restore a superseded grant. The caller retries and re-mints
                // under the new generation.
                invalidate_access(state, conn.id).await;
                return Err("connection was reauthorized during refresh — retry".into());
            }
        }
    }
    // Re-verify the binding is STILL the one we entered with, INDEPENDENT of
    // whether the provider rotated the refresh token (B2/R3.2): a provider that
    // omits or reuses the refresh token skips the generation-guarded rotate above,
    // so without this a token just minted for a reconnected account could be
    // cached and served for the OLD binding. Re-read under scope and refuse on any
    // status/generation drift. (The oauth locks make a mid-refresh bump
    // impossible; this fails closed regardless.)
    match fluidbox_db::get_connection(&mut *db, scope, conn.id).await {
        Ok(Some(fresh))
            if fresh.status == "active"
                && fresh.authorization_generation == conn.authorization_generation => {}
        _ => {
            invalidate_access(state, conn.id).await;
            return Err("connection was reauthorized during refresh — retry".into());
        }
    }
    // Hand the token back UNcached: the caller commits the transaction (releasing
    // the advisory lock) and only then inserts it into `connector_tokens`, so a
    // cached token can never outlive an uncommitted rotation.
    Ok((access, expires_in))
}

// ─── Client ID metadata document (CIMD, spec 2025-11-25 SHOULD) ───────────

/// `GET /.well-known/fluidbox-client.json` — this document's URL IS the
/// OAuth client_id we present to ASes that advertise CIMD support. Public
/// by nature: the AS fetches it during authorization.
pub async fn cimd_doc(State(state): State<AppState>) -> Json<Value> {
    Json(json!({
        "client_id": cimd_client_id(&state),
        "client_name": "fluidbox",
        "client_uri": state.cfg.public_url,
        "redirect_uris": [redirect_uri(&state)],
        "grant_types": ["authorization_code", "refresh_token"],
        "response_types": ["code"],
        "token_endpoint_auth_method": "none",
    }))
}

// ─── Tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn test_sealer() -> Sealer {
        Sealer::from_key_string(&"ab".repeat(32)).unwrap()
    }

    /// Issuer poisoning: DCR rows are keyed GLOBALLY by `(issuer,
    /// redirect_uri)`, so an unvalidated `issuer` lets any member's malicious
    /// server claim a real provider's identity and occupy that provider's
    /// registration deployment-wide. RFC 8414 §3.3 already forbids it.
    #[test]
    fn issuer_must_match_the_origin_that_published_the_metadata() {
        // Exact origin, and an issuer with a tenant PATH on that origin.
        issuer_matches_discovery("https://as.example.test", "https://as.example.test").unwrap();
        issuer_matches_discovery(
            "https://as.example.test/tenant-1",
            "https://as.example.test",
        )
        .unwrap();
        // Scheme is part of the origin.
        issuer_matches_discovery("HTTPS://AS.example.test", "https://as.example.test").unwrap();
        // The attack: a member's server claiming a real provider's issuer.
        let e =
            issuer_matches_discovery("https://accounts.google.com", "https://evil.example.test")
                .unwrap_err();
        assert!(e.contains("different origin"), "got: {e}");
        // A port change is a different origin too.
        assert!(issuer_matches_discovery(
            "https://as.example.test:8443",
            "https://as.example.test"
        )
        .is_err());
        // Absent/blank/malformed issuers are refused, not defaulted.
        assert!(issuer_matches_discovery("", "https://as.example.test").is_err());
        assert!(issuer_matches_discovery("   ", "https://as.example.test").is_err());
        assert!(issuer_matches_discovery("not-a-url", "https://as.example.test").is_err());
        // …and the discovery path must actually CALL it: the check is worthless
        // if `parse_as_metadata`'s result is returned unvalidated. Needle built
        // at runtime so this scan does not count its own source text.
        let src = include_str!("oauth.rs");
        let call = format!(
            "        {}(&meta.issuer, &a_origin)?;",
            "issuer_matches_discovery"
        );
        assert_eq!(
            src.matches(&call).count(),
            1,
            "AS-metadata discovery must validate the issuer against the origin it came from"
        );
    }

    /// Both token legs must ride the NO-REDIRECT client. `identity_http` follows
    /// any admitted https hop, and a 307/308 REPLAYS the request body — so the
    /// code + PKCE verifier (exchange) or the refresh token (refresh) would be
    /// forwarded to a different host of the AS's choosing. Header-level
    /// protections do not cover a body, so the client itself must refuse.
    ///
    /// Asserted against the source because these two builders are the whole
    /// property and neither is reachable without a live `AppState`.
    #[test]
    fn token_legs_use_the_no_redirect_client() {
        let src = include_str!("oauth.rs");
        // Assembled at runtime so the scan does not count its own source text.
        let needle = format!(".post({})", "token_endpoint");
        let legs: Vec<usize> = src.match_indices(&needle).map(|(i, _)| i).collect();
        assert_eq!(
            legs.len(),
            2,
            "expected exactly the code-exchange and refresh legs; found {}",
            legs.len()
        );
        for at in legs {
            let window = &src[at.saturating_sub(200)..at];
            assert!(
                window.contains("egress_http"),
                "a token leg does not use the no-redirect egress_http client"
            );
            assert!(
                !window.contains("identity_http"),
                "a token leg still uses the redirect-following identity_http client"
            );
        }
    }

    fn egress_policy(dev: bool) -> crate::egress::EgressPolicy {
        crate::egress::EgressPolicy {
            dev_loopback: dev,
            allow_cidrs: vec![],
            github_clone_base: None,
            proxy: None,
        }
    }

    // C1: every connector-OAuth surface (discover probe / PRM / AS-metadata /
    // DCR / code exchange / stored-bag refresh) funnels its pre-dial admission
    // through `admit_oauth`, so proving it here proves the whole class. reqwest
    // dials an IP LITERAL without the resolver, so admit_url is the ONLY thing
    // standing between a `https://<private-ip>` target and an open socket.
    #[test]
    fn admit_oauth_refuses_private_literals_and_plain_http_outside_dev() {
        let prod = egress_policy(false);
        // Private + metadata IP literals over https are refused in prod, with a
        // static-classed reason (no IP echoed) under the `egress blocked:` prefix.
        let blocked = admit_oauth("https://169.254.169.254/token", &prod).unwrap_err();
        assert!(blocked.starts_with("egress blocked:"), "{blocked}");
        assert!(
            !blocked.contains("169.254"),
            "reason leaked the target: {blocked}"
        );
        assert!(admit_oauth("https://10.0.0.1/register", &prod).is_err());
        assert!(admit_oauth("https://[::1]/token", &prod).is_err());
        // Plain http is refused in prod (E3); a public https AS is fine.
        assert!(admit_oauth("http://as.example.com/token", &prod).is_err());
        assert!(admit_oauth("https://as.example.com/token", &prod).is_ok());
        // Hostname-FREE form of the same two assertions. `admit_oauth` is a
        // synchronous parse + range check that resolves nothing (see the
        // hermeticity note in `egress::tests`), so neither form touches DNS.
        assert!(admit_oauth("http://93.184.216.34/token", &prod).is_err());
        assert!(admit_oauth("https://93.184.216.34/token", &prod).is_ok());
    }

    // I3: every connector-OAuth response body — PRM, AS metadata, DCR, code
    // exchange, stored-bag refresh — must be read under the SAME 256 KiB ceiling
    // the OIDC legs use. An unbounded `Response::json` read buffers whatever the
    // (attacker-influenced) authorization server streams, and with a 15 s timeout
    // that is hundreds of MB per leg, several legs per discovery.
    //
    // The ceiling itself is tested in `egress::tests`; what needs pinning HERE is
    // that no leg in this file bypasses it — a statement-level property, so it is
    // asserted against the statements. Needles are composed at runtime so these
    // literals cannot match themselves.
    #[test]
    fn every_oauth_body_read_is_bounded() {
        let src = include_str!("oauth.rs");
        let unbounded = format!("res.{}(", "json");
        assert_eq!(
            src.matches(&unbounded).count(),
            0,
            "an unbounded body read crept back into a connector-OAuth leg"
        );
        let bounded = format!("egress::read_json_{}(&mut res)", "bounded");
        assert_eq!(
            src.matches(&bounded).count(),
            5,
            "expected exactly the five bounded legs (PRM, AS metadata, DCR, exchange, refresh)"
        );
    }

    #[test]
    fn admit_oauth_allows_loopback_only_under_dev_seam() {
        let dev = egress_policy(true);
        // The e2e fake AS on loopback http is admitted under the dev seam…
        assert!(admit_oauth("http://127.0.0.1:8899/token", &dev).is_ok());
        // …but metadata/link-local stays blocked even in dev (loopback ≠ link-local)…
        assert!(admit_oauth("http://169.254.169.254/latest", &dev).is_err());
        // …and a non-loopback private http host is still refused in dev.
        assert!(admit_oauth("http://10.0.0.1/token", &dev).is_err());
    }

    // A malicious authorization server can echo the sealed state / a bearer into
    // its `error` / `error_description` — the sanitized log form (allowlisted code
    // + digest) must never carry those bytes (parity with the broker boundary).
    #[test]
    fn as_error_text_never_leaks_credential_material() {
        let smuggled = "fbx_pat_supersecrettoken_ABCDEF0123456789";
        let digest = crate::broker::msg_digest(smuggled);
        assert!(
            !digest.contains(smuggled) && !digest.contains("supersecrettoken"),
            "digest leaked the token: {digest}"
        );
        assert!(digest.starts_with("sha256:"));
        // An arbitrary (crafted) error code collapses to "other"; only the fixed
        // allowlist passes through verbatim.
        assert_eq!(known_oauth_error(smuggled), "other");
        assert_eq!(known_oauth_error("invalid_grant"), "invalid_grant");
        assert_eq!(known_oauth_error("access_denied"), "access_denied");
    }

    // Reactive-401 eviction must not defeat the refresh singleflight. Two
    // concurrent brokered calls resolve the SAME cached access token and 401
    // together; the first evicts + refreshes + caches a fresh token, and the
    // second's eviction must then be a NO-OP so `ensure_access_token`'s
    // double-check serves the fresh token instead of rotating a second time.
    #[test]
    fn rejected_eviction_spares_a_concurrently_refreshed_token() {
        let conn = Uuid::now_v7();
        let other = Uuid::now_v7();
        // The token that actually 401'd → evicted (the normal, uncontended case).
        assert!(!survives_rejection(conn, "acc-1", conn, "acc-1"));
        // A FRESHER token, already refreshed in by a concurrent caller → kept.
        assert!(survives_rejection(conn, "acc-2", conn, "acc-1"));
        // Another connection's token is never collateral, same token bytes or not.
        assert!(survives_rejection(other, "acc-1", conn, "acc-1"));
        // A non-OAuth (or missing) credential yields an empty "rejected" probe —
        // it must match nothing rather than everything.
        assert!(survives_rejection(conn, "acc-1", conn, ""));
    }

    #[tokio::test]
    async fn boot_token_roundtrips_and_fails_closed() {
        let s = test_sealer();
        let flow = Uuid::now_v7();
        let exp = Utc::now().timestamp() + STATE_TTL_SECS;
        let tok = seal_boot_token(&s, flow, "state-secret", "cookie-secret", exp)
            .await
            .unwrap();
        let bt = open_boot_token(&s, &tok).await.unwrap();
        assert_eq!(bt.flow_id, flow);
        assert_eq!(bt.s, "state-secret");
        assert_eq!(bt.c, "cookie-secret");
        // Opaque: neither secret is readable from the sealed token.
        assert!(!tok.contains("state-secret") && !tok.contains("cookie-secret"));
        // Tampering breaks verification.
        let mut chars: Vec<char> = tok.chars().collect();
        let mid = chars.len() / 2;
        chars[mid] = if chars[mid] == 'A' { 'B' } else { 'A' };
        assert!(open_boot_token(&s, &chars.into_iter().collect::<String>())
            .await
            .is_err());
        // Garbage and wrong-key tokens fail closed.
        assert!(open_boot_token(&s, "not-base64!!").await.is_err());
        let other = Sealer::from_key_string(&"cd".repeat(32)).unwrap();
        assert!(open_boot_token(&other, &tok).await.is_err());
        // Expired boot tokens are refused (BootToken deliberately isn't Debug — it
        // carries plaintext secrets — so match rather than unwrap_err).
        let stale = seal_boot_token(&s, flow, "x", "y", Utc::now().timestamp() - 1)
            .await
            .unwrap();
        match open_boot_token(&s, &stale).await {
            Err(m) => assert!(m.contains("expired")),
            Ok(_) => panic!("expired boot token must be refused"),
        }
    }

    #[test]
    fn authorize_url_rebuilds_every_param_from_the_row() {
        let url = build_authorize_url(
            "https://as.test/authorize",
            "client-1",
            "https://fbx.test/v1/oauth/callback",
            "state-secret",
            "challenge-abc",
            "S256",
            "https://mcp.test/mcp",
            &["read".into(), "offline_access".into()],
        )
        .unwrap();
        let parsed = reqwest::Url::parse(&url).unwrap();
        let q: std::collections::HashMap<_, _> = parsed.query_pairs().into_owned().collect();
        assert_eq!(parsed.path(), "/authorize");
        assert_eq!(q["response_type"], "code");
        assert_eq!(q["client_id"], "client-1");
        assert_eq!(q["redirect_uri"], "https://fbx.test/v1/oauth/callback");
        assert_eq!(q["state"], "state-secret");
        assert_eq!(q["code_challenge"], "challenge-abc");
        assert_eq!(q["code_challenge_method"], "S256");
        assert_eq!(q["resource"], "https://mcp.test/mcp");
        assert_eq!(q["scope"], "read offline_access");
        // No scopes ⇒ no `scope` param at all (mirrors the pre-D dance).
        let no_scope = build_authorize_url(
            "https://as.test/authorize",
            "c",
            "https://fbx.test/cb",
            "s",
            "ch",
            "S256",
            "https://mcp.test",
            &[],
        )
        .unwrap();
        assert!(!no_scope.contains("scope="));
        // A bad endpoint fails closed.
        assert!(build_authorize_url("not a url", "c", "r", "s", "ch", "S256", "res", &[]).is_err());
    }

    #[test]
    fn flow_cookie_header_shape() {
        // __Host- compliant (Secure + Path=/, no Domain); the clear expires it.
        let set = set_oauth_flow_cookie("abc123");
        assert!(set.starts_with("__Host-fbx_oauth_flow=abc123; "));
        assert!(set.contains("; HttpOnly"));
        assert!(set.contains("; SameSite=Lax"));
        assert!(set.contains("; Path=/"));
        assert!(set.contains("; Secure"));
        assert!(!set.contains("; Domain"));
        assert!(set.contains(&format!("; Max-Age={STATE_TTL_SECS}")));
        let clear = clear_oauth_flow_cookie();
        assert!(
            clear.contains("=gone; ")
                && clear.contains("; Max-Age=0")
                && clear.contains("; Secure")
                && clear.contains("; Path=/")
        );
        // The reader round-trips a cookie value out of a Cookie header.
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::COOKIE,
            "other=1; __Host-fbx_oauth_flow=abc123; z=2"
                .parse()
                .unwrap(),
        );
        assert_eq!(oauth_flow_cookie(&headers).as_deref(), Some("abc123"));
        assert!(oauth_flow_cookie(&HeaderMap::new()).is_none());
    }

    /// H2: the flow's activation expectation. Whatever the interleaving, the
    /// SECOND authorization to reach the write must be refused — the CAS in
    /// `activate_connection_oauth` enforces exactly these two predicates.
    #[test]
    fn a_superseded_flow_is_refused() {
        let t0 = DateTime::parse_from_rfc3339("2026-07-20T10:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let t1 = t0 + Duration::seconds(30);

        // Baseline: flow frozen at gen 5, connection never activated since.
        assert!(!flow_superseded(5, None, 5, t0));
        // …and a connection last activated BEFORE this flow started is the
        // ordinary reconnect: allowed.
        assert!(!flow_superseded(5, Some(t0 - Duration::seconds(1)), 5, t0));

        // RECONNECT RACE: a sibling reconnect activated first and moved the
        // generation. The loser's frozen 5 no longer matches.
        assert!(flow_superseded(6, Some(t1), 5, t0));

        // FIRST-CONNECT RACE: `pending → active` deliberately does NOT bump, so
        // BOTH callbacks still see the frozen generation. The activation instant
        // is what separates them — the sibling activated after this flow started.
        assert!(
            flow_superseded(1, Some(t1), 1, t0),
            "generation alone cannot separate two first-connect callbacks"
        );
        // Equal instants are unorderable ⇒ fail closed.
        assert!(flow_superseded(1, Some(t0), 1, t0));
        // A flow started AFTER that activation is a genuinely newer
        // authorization and is admitted (the newest authorization wins).
        assert!(!flow_superseded(1, Some(t0), 1, t1));

        // The stamp is read out of the connection's oauth bag, in the shape
        // Postgres `to_jsonb(clock_timestamp())` writes.
        assert_eq!(last_activated_at(None), None);
        assert_eq!(last_activated_at(Some(&json!({}))), None);
        assert_eq!(
            last_activated_at(Some(&json!({"activated_at": null}))),
            None
        );
        assert_eq!(
            last_activated_at(Some(&json!({"activated_at": "2026-07-20T10:00:00+00:00"}))),
            Some(t0)
        );
        // Unparseable ⇒ MAX ⇒ every flow reads superseded (fail closed).
        assert_eq!(
            last_activated_at(Some(&json!({"activated_at": "not-a-timestamp"}))),
            Some(DateTime::<Utc>::MAX_UTC)
        );
        assert!(flow_superseded(
            1,
            last_activated_at(Some(&json!({"activated_at": "not-a-timestamp"}))),
            1,
            t1
        ));
    }

    /// THE START-EPOCH RACE (re-verification, #32). The activation CAS compares
    /// against the flow row's `created_at` — an instant stamped only AFTER
    /// discovery + client resolution. An attempt that BEGAN before a sibling's
    /// successful activation therefore mints a row that POST-DATES it and passes
    /// BOTH CAS predicates, so the refusal has to happen on the start side.
    #[test]
    fn an_attempt_that_began_before_an_activation_is_refused_at_the_start() {
        let t_read = DateTime::parse_from_rfc3339("2026-07-20T10:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        // S1 and S2 both read the pending connection at `t_read` (gen 1, never
        // activated). S1's flow activates 30s later; S2, still in discovery,
        // inserts its flow 30s after THAT.
        let t_activate = t_read + Duration::seconds(30);
        let t_flow2 = t_activate + Duration::seconds(30);

        // The CAS alone does NOT catch it — the hole, verbatim.
        assert!(
            !flow_superseded(1, Some(t_activate), 1, t_flow2),
            "a first-connect activation leaves the generation at 1 and S2's row post-dates the \
             stamp, so both CAS predicates pass"
        );

        // The frozen start expectation does: S2 formed its attempt against a
        // connection that had never been activated.
        let s2_started = StartExpectation {
            generation: 1,
            activated_at: None,
        };
        let after_s1 = StartExpectation {
            generation: 1,
            activated_at: Some(t_activate),
        };
        assert!(start_expectation_moved(s2_started, Some(after_s1)));

        // A concurrent start that only wrote the custody bag moves NEITHER half:
        // two admins may both start, and the first callback to land wins at the
        // CAS. No false refusal.
        assert!(!start_expectation_moved(s2_started, Some(s2_started)));
        // An attempt that began AFTER that activation is genuinely newer.
        assert!(!start_expectation_moved(after_s1, Some(after_s1)));
        // A sibling RECONNECT (which does bump) is caught by the same equality…
        assert!(start_expectation_moved(
            after_s1,
            Some(StartExpectation {
                generation: 2,
                activated_at: Some(t_activate),
            })
        ));
        // …as is the connection disappearing under the attempt.
        assert!(start_expectation_moved(after_s1, None));
        // An unparseable stamp reads as MAX and so differs from every real
        // expectation — fail closed, exactly like the CAS.
        assert!(start_expectation_moved(
            s2_started,
            Some(StartExpectation {
                generation: 1,
                activated_at: last_activated_at(Some(&json!({"activated_at": "not-a-timestamp"}))),
            })
        ));
    }

    /// THE CUSTODY-BAG HALF of the same race (#32). The bag write is a whole-bag
    /// REPLACE closing a read-modify-write that spanned discovery: a superseded
    /// attempt landing it would pair the WINNER's refresh token with the loser's
    /// token endpoint + client identity. So the commit point's decision must be
    /// "write nothing", from the SAME predicate that refuses the flow row — never
    /// a second, independently-guarded write that could drift.
    #[test]
    fn a_superseded_attempt_persists_no_custody_bag() {
        let t_read = DateTime::parse_from_rfc3339("2026-07-20T10:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let t_activate = t_read + Duration::seconds(30);

        // S1 and S2 both froze a pending, never-activated connection at gen 1.
        let s2_started = StartExpectation {
            generation: 1,
            activated_at: None,
        };
        // S1's callback activated while S2 was in discovery: first connect, so
        // ONLY the stamp moved.
        let after_s1 = StartExpectation {
            generation: 1,
            activated_at: Some(t_activate),
        };
        assert_eq!(
            start_commit_decision(s2_started, Some(after_s1)),
            StartCommit::Superseded,
            "S2 must write NOTHING — not its endpoints, not its client identity"
        );
        // The winner itself still commits its own bag.
        assert_eq!(
            start_commit_decision(after_s1, Some(after_s1)),
            StartCommit::PersistBag
        );
        // Un-raced first connect: the ordinary path still persists.
        assert_eq!(
            start_commit_decision(s2_started, Some(s2_started)),
            StartCommit::PersistBag
        );
        // A sibling RECONNECT (which bumps) and a vanished connection are both
        // refusals too — one predicate, both consequences.
        assert_eq!(
            start_commit_decision(
                after_s1,
                Some(StartExpectation {
                    generation: 2,
                    activated_at: Some(t_activate),
                })
            ),
            StartCommit::Superseded
        );
        assert_eq!(
            start_commit_decision(after_s1, None),
            StartCommit::Superseded
        );
    }

    /// The same interleaving against real Postgres, through the REAL
    /// `commit_start_epoch` (self-skips without `DATABASE_URL`): a sibling
    /// activation lands between S2's connection read and S2's flow insert.
    /// Proves every half — that the CAS admits S2's row (so the start-side check
    /// is load-bearing), that the commit point refuses S2 with `SUPERSEDED_MSG`,
    /// that S2's custody bag is NOT persisted (the winner's token endpoint and
    /// client identity survive byte-for-byte), and that the burned flow can never
    /// be claimed. A positive control first proves the commit point is not
    /// vacuously refusing.
    #[tokio::test]
    async fn db_start_epoch_race_is_refused_before_the_flow_can_be_used() {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("skipping: DATABASE_URL not set");
            return;
        };
        let pool = fluidbox_db::connect(&url, None).await.expect("connect");
        let org = fluidbox_db::identity::create_org(
            &pool,
            &format!("t-{}", Uuid::now_v7().simple()),
            None,
        )
        .await
        .unwrap();
        let scope = fluidbox_db::TenantScope::assume(org.id);
        let bag = json!({ "resource": "https://mcp.example.test/mcp" });
        let conn = fluidbox_db::create_connection(
            &pool,
            scope,
            "mcp_http",
            &format!("acct-{}", Uuid::now_v7().simple()),
            "start-epoch race",
            None,
            1,
            &json!([]),
            &json!({}),
            &json!({ "base_url": "https://mcp.example.test" }),
            None,
            1,
            fluidbox_db::ConnectionAuth {
                auth_kind: "oauth",
                status: "pending",
                oauth: Some(&bag),
                client_secret_sealed: None,
                client_secret_key_version: 1,
                registration_id: None,
            },
            fluidbox_db::ConnectionOwner::Organization,
            None,
        )
        .await
        .unwrap();

        // Both starts read the same pending row BEFORE any outbound HTTP.
        let s2_started = StartExpectation::of(&conn);
        assert_eq!(s2_started.activated_at, None);

        // The two attempts discovered DIFFERENT authorization servers / client
        // identities — which is the whole point: pairing S1's refresh token with
        // S2's endpoint + client is the corruption under test.
        let s1_bag = json!({
            "resource": "https://mcp.example.test/mcp",
            "token_endpoint": "https://as-1.example.test/token",
            "client_id": "client-1",
        });
        let s2_bag = json!({
            "resource": "https://mcp.example.test/mcp",
            "token_endpoint": "https://as-2.example.test/token",
            "client_id": "client-2",
        });

        // POSITIVE CONTROL, with S2's exact inputs: while nothing has activated,
        // the commit point persists the bag. So a later refusal is the race, not
        // a commit point that refuses everything.
        commit_start_epoch(&pool, scope, conn.id, s2_started, &s2_bag)
            .await
            .expect("an un-raced attempt commits its custody bag");
        let warmed = fluidbox_db::get_connection(&pool, scope, conn.id)
            .await
            .unwrap()
            .unwrap()
            .oauth
            .unwrap();

        let mk_flow = |tag: &'static str| {
            let pool = pool.clone();
            async move {
                let (s, c) = (random_urlsafe(), random_urlsafe());
                let row = fluidbox_db::insert_connector_oauth_flow(
                    &pool,
                    scope,
                    fluidbox_db::NewConnectorOauthFlow {
                        connection_id: conn.id,
                        initiated_by_user_id: None,
                        state_hash: &fluidbox_db::sha256_hex(&s),
                        browser_hash: &fluidbox_db::sha256_hex(&c),
                        issuer: "https://as.example.test",
                        authorization_endpoint: "https://as.example.test/authorize",
                        token_endpoint: "https://as.example.test/token",
                        metadata_digest: tag,
                        resource: "https://mcp.example.test/mcp",
                        redirect_uri: "https://fluidbox.test/v1/oauth/callback",
                        scopes: &json!([]),
                        challenge: "challenge",
                        challenge_method: "S256",
                        client_registration_id: None,
                        client_id: "client",
                        pkce_verifier_sealed: b"sealed",
                        pkce_verifier_key_version: 1,
                        expected_generation: conn.authorization_generation,
                        ttl_secs: 600,
                    },
                )
                .await
                .unwrap();
                (row, s, c)
            }
        };

        // S1's flow lands first and activates, landing ITS custody bag: first
        // connect, so the generation deliberately stays put and only the DB-clock
        // stamp moves.
        let (f1, _, _) = mk_flow("f1").await;
        let activated = fluidbox_db::activate_connection_oauth(
            &pool,
            scope,
            conn.id,
            b"sealed-refresh-1",
            1,
            &s1_bag,
            &json!([]),
            f1.expected_generation,
            f1.created_at,
        )
        .await
        .unwrap()
        .expect("S1 activates");
        assert_eq!(activated.authorization_generation, 1);

        // S2 finally emerges from discovery and inserts ITS flow — younger than
        // the activation it never saw.
        let (f2, s2, c2) = mk_flow("f2").await;
        let current = fluidbox_db::get_connection(&pool, scope, conn.id)
            .await
            .unwrap();

        // The start-side verification refuses it…
        let moved = start_expectation_moved(s2_started, current.as_ref().map(StartExpectation::of));
        // …through the REAL commit point, which in the same breath must decline
        // to persist S2's bag (#32): one transaction, one advisory lock, so no
        // activation can slip between the proof and the write.
        let refusal = commit_start_epoch(&pool, scope, conn.id, s2_started, &s2_bag).await;
        let refused_with = match &refusal {
            Err(ApiError::Conflict(m)) => Some(m.clone()),
            _ => None,
        };
        let after_refusal = fluidbox_db::get_connection(&pool, scope, conn.id)
            .await
            .unwrap()
            .unwrap()
            .oauth
            .unwrap();
        // …and the burn makes the row unusable for good.
        let burned = fluidbox_db::claim_connector_oauth_flow(
            &pool,
            &fluidbox_db::sha256_hex(&s2),
            &fluidbox_db::sha256_hex(&c2),
        )
        .await
        .unwrap();
        let reclaim = fluidbox_db::claim_connector_oauth_flow(
            &pool,
            &fluidbox_db::sha256_hex(&s2),
            &fluidbox_db::sha256_hex(&c2),
        )
        .await
        .unwrap();
        // Without that refusal the CAS would have let S2 overwrite S1's grant.
        let cas_admits_f2 = fluidbox_db::activate_connection_oauth(
            &pool,
            scope,
            conn.id,
            b"sealed-refresh-2",
            1,
            &s2_bag,
            &json!([]),
            f2.expected_generation,
            f2.created_at,
        )
        .await
        .unwrap()
        .is_some();

        // Children-first cleanup BEFORE the asserts (tenant FKs are NO ACTION).
        for stmt in [
            "delete from connector_oauth_flows where tenant_id = $1",
            "delete from integration_connections where tenant_id = $1",
            "delete from tenants where id = $1",
        ] {
            let _ = sqlx::query(stmt).bind(org.id).execute(&pool).await;
        }

        assert!(f2.created_at > f1.created_at);
        assert_eq!(
            warmed["token_endpoint"], "https://as-2.example.test/token",
            "positive control: an un-raced attempt DOES persist its custody bag"
        );
        assert!(
            moved,
            "S2 froze a never-activated connection; a sibling activated since — refuse"
        );
        assert_eq!(
            refused_with.as_deref(),
            Some(SUPERSEDED_MSG),
            "the commit point refuses with the same wording the CAS uses"
        );
        // THE RESIDUAL, closed: S2 wrote NOTHING. The winner's refresh token is
        // still paired with the winner's own token endpoint + client identity, so
        // its refresh cannot authenticate to a superseded start's AS.
        assert_eq!(
            after_refusal["token_endpoint"], "https://as-1.example.test/token",
            "a superseded start must not repoint the winner's token endpoint"
        );
        assert_eq!(
            after_refusal["client_id"], "client-1",
            "a superseded start must not repoint the winner's client identity"
        );
        assert!(
            after_refusal
                .get(fluidbox_db::ACTIVATED_AT_KEY)
                .is_some_and(|v| !v.is_null()),
            "the winner's activation stamp survives the refused attempt"
        );
        assert!(burned.is_some(), "the superseded flow is consumed");
        assert!(
            reclaim.is_none(),
            "a burned flow can never be claimed again"
        );
        assert!(
            cas_admits_f2,
            "the CAS alone admits S2's younger row — which is exactly why the start-side \
             expectation is load-bearing"
        );
    }

    #[test]
    fn metadata_digest_is_deterministic() {
        let mk = || AsMeta {
            issuer: "https://as.test".into(),
            authorization_endpoint: "https://as.test/authorize".into(),
            token_endpoint: "https://as.test/token".into(),
            registration_endpoint: Some("https://as.test/register".into()),
            cimd_supported: true,
            // Different order, same set ⇒ same digest (scopes are sorted).
            scopes_supported: vec!["read".into(), "offline_access".into()],
        };
        let mut reordered = mk();
        reordered.scopes_supported = vec!["offline_access".into(), "read".into()];
        let a = metadata_digest(&mk());
        assert_eq!(
            a,
            metadata_digest(&reordered),
            "digest is order-independent"
        );
        assert!(a.starts_with("sha256:"));
        // A changed endpoint changes the digest (binds the discovered surface).
        let mut moved = mk();
        moved.token_endpoint = "https://evil.test/token".into();
        assert_ne!(a, metadata_digest(&moved));
    }

    #[test]
    fn pkce_s256_matches_rfc7636_vector() {
        // RFC 7636 appendix B.
        assert_eq!(
            pkce_challenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"),
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        );
        // Verifiers are 43 chars of base64url (32 random bytes).
        assert_eq!(random_urlsafe().len(), 43);
    }

    #[test]
    fn canonical_resource_normalizes() {
        let ok = |i: &str, o: &str| assert_eq!(canonical_resource(i).unwrap(), o);
        ok(
            "https://MCP.Example.test/mcp",
            "https://mcp.example.test/mcp",
        );
        ok(
            "https://mcp.example.test/mcp/",
            "https://mcp.example.test/mcp",
        );
        ok("https://mcp.example.test:443/", "https://mcp.example.test");
        ok("http://127.0.0.1:8897/mcp", "http://127.0.0.1:8897/mcp");
        assert!(canonical_resource("ftp://x").is_err());
        assert!(canonical_resource("not a url").is_err());
    }

    #[test]
    fn cimd_needs_a_fetchable_https_public_url() {
        // The AS must be able to GET the client document.
        assert!(cimd_eligible("https://fluidbox.example.com"));
        assert!(cimd_eligible("https://fluidbox.example.com:8443/base"));
        // http is refused by the CIMD spec; loopback is unreachable from
        // any AS ("127.0.0.1" means the AS itself).
        assert!(!cimd_eligible("http://127.0.0.1:8787"));
        assert!(!cimd_eligible("http://fluidbox.example.com"));
        assert!(!cimd_eligible("https://127.0.0.1:8787"));
        assert!(!cimd_eligible("https://localhost:8787"));
        assert!(!cimd_eligible("https://[::1]:8787"));
        assert!(!cimd_eligible("not a url"));
    }

    #[test]
    fn stored_identities_re_resolve_when_stale() {
        let cimd_id = "https://fbx.example.com/.well-known/fluidbox-client.json";
        let redirect = "https://fbx.example.com/v1/oauth/callback";
        // Healthy CIMD identity → reuse.
        assert!(!stored_identity_stale(
            "cimd", cimd_id, None, false, true, cimd_id, redirect
        ));
        // CIMD no longer presentable (e.g. the identity was minted before
        // the eligibility guard, from a loopback deployment) → stale.
        assert!(stored_identity_stale(
            "cimd", cimd_id, None, false, false, cimd_id, redirect
        ));
        // Public URL moved → the document URL no longer matches → stale.
        assert!(stored_identity_stale(
            "cimd",
            "http://127.0.0.1:8787/.well-known/fluidbox-client.json",
            None,
            false,
            true,
            cimd_id,
            redirect
        ));
        // DCR identity minted for THIS redirect → reuse; moved → stale;
        // legacy rows without a recorded redirect → reuse (old behavior).
        assert!(!stored_identity_stale(
            "dcr",
            "dcr-1",
            Some(redirect),
            false,
            false,
            cimd_id,
            redirect
        ));
        assert!(stored_identity_stale(
            "dcr",
            "dcr-1",
            Some("http://127.0.0.1:8787/v1/oauth/callback"),
            false,
            false,
            cimd_id,
            redirect
        ));
        assert!(!stored_identity_stale(
            "dcr", "dcr-1", None, false, false, cimd_id, redirect
        ));
        // Pre-registered identities are user-owned — never auto-stale.
        assert!(!stored_identity_stale(
            "preregistered",
            "pre-7",
            Some("https://old.example/cb"),
            false,
            false,
            cimd_id,
            redirect
        ));
    }

    #[test]
    fn a_retired_registration_makes_every_stored_identity_stale() {
        // `registration_missing` = the stored `oauth.registration_id` no longer
        // resolves, i.e. an `invalid_client` retirement (or a sibling connection's)
        // deleted the shared row. EVERY source must then re-resolve: replaying the
        // identity that row named would replay exactly what the AS rejected, and the
        // connection would keep a dangling pointer forever.
        let cimd_id = "https://fbx.example.com/.well-known/fluidbox-client.json";
        let redirect = "https://fbx.example.com/v1/oauth/callback";
        for source in ["dcr", "cimd", "preregistered"] {
            // Otherwise-healthy inputs (same redirect, CIMD presentable, matching
            // document URL) — the ONLY difference is the missing row.
            assert!(
                !stored_identity_stale(
                    source,
                    cimd_id,
                    Some(redirect),
                    false,
                    true,
                    cimd_id,
                    redirect
                ),
                "{source}: control — a resolvable registration reuses"
            );
            assert!(
                stored_identity_stale(
                    source,
                    cimd_id,
                    Some(redirect),
                    true,
                    true,
                    cimd_id,
                    redirect
                ),
                "{source}: a missing registration row must re-resolve"
            );
        }
        // …and a stale identity never takes the Reuse arm — it falls through to
        // CIMD/DCR, which mints or adopts a live row.
        assert_eq!(
            classify_client_resolution(Some("dcr-retired"), true, false),
            ClientResolution::Dcr
        );
        assert_eq!(
            classify_client_resolution(Some("dcr-retired"), true, true),
            ClientResolution::Cimd
        );
    }

    #[test]
    fn www_authenticate_parses_resource_metadata() {
        assert_eq!(
            parse_www_authenticate(
                r#"Bearer resource_metadata="https://mcp.example.test/.well-known/oauth-protected-resource/mcp""#
            )
            .as_deref(),
            Some("https://mcp.example.test/.well-known/oauth-protected-resource/mcp")
        );
        assert_eq!(
            parse_www_authenticate(
                r#"Bearer error="invalid_token", resource_metadata="https://x/prm", scope="a""#
            )
            .as_deref(),
            Some("https://x/prm")
        );
        assert!(parse_www_authenticate("Bearer realm=\"x\"").is_none());
    }

    #[test]
    fn insufficient_scope_challenge_parses_and_sanitizes() {
        // The SEP-835 challenge: error + the scope the server wants.
        let c = parse_insufficient_scope(
            r#"Bearer error="insufficient_scope", scope="read:issues write:issues""#,
        )
        .expect("insufficient_scope detected");
        assert_eq!(c.scope.as_deref(), Some("read:issues write:issues"));
        // A bare (unquoted) token value parses too.
        let c = parse_insufficient_scope("Bearer error=insufficient_scope, scope=admin")
            .expect("bare token");
        assert_eq!(c.scope.as_deref(), Some("admin"));
        // No scope param → challenge still detected, scope None.
        let c = parse_insufficient_scope(r#"Bearer error="insufficient_scope""#).unwrap();
        assert!(c.scope.is_none());
        // RFC 7235: the auth-param NAME is case-insensitive — a mixed-case
        // `Error=` is still an insufficient_scope challenge, and a mixed-case
        // `Scope=` value is read verbatim (values stay case-sensitive).
        let c =
            parse_insufficient_scope(r#"Bearer Error="insufficient_scope", Scope="Read:Issues""#)
                .expect("mixed-case Error= must still parse");
        assert_eq!(c.scope.as_deref(), Some("Read:Issues"));
        // A DIFFERENT error is NOT an insufficient_scope challenge.
        assert!(parse_insufficient_scope(r#"Bearer error="invalid_token""#).is_none());
        assert!(parse_insufficient_scope("Bearer realm=\"x\"").is_none());
        // Sanitize: a poison/secret-shaped scope is stripped of control/quote
        // characters before it can reach the persisted note.
        let c = parse_insufficient_scope(
            "Bearer error=\"insufficient_scope\", scope=\"ok\u{202e}evil\"",
        )
        .unwrap();
        assert_eq!(c.scope.as_deref(), Some("okevil"));
    }

    #[test]
    fn as_metadata_requires_s256() {
        let good = serde_json::json!({
            "issuer": "https://as.test",
            "authorization_endpoint": "https://as.test/authorize",
            "token_endpoint": "https://as.test/token",
            "registration_endpoint": "https://as.test/register",
            "code_challenge_methods_supported": ["S256"],
            "client_id_metadata_document_supported": true,
            "scopes_supported": ["offline_access", "read"],
        });
        let m = parse_as_metadata(&good).unwrap();
        assert_eq!(m.token_endpoint, "https://as.test/token");
        assert!(m.cimd_supported);
        assert_eq!(
            m.registration_endpoint.as_deref(),
            Some("https://as.test/register")
        );
        assert!(m.scopes_supported.iter().any(|s| s == "offline_access"));

        // "plain"-only or absent PKCE support is a refusal, not a shrug.
        let plain = serde_json::json!({
            "authorization_endpoint": "https://as.test/authorize",
            "token_endpoint": "https://as.test/token",
            "code_challenge_methods_supported": ["plain"],
        });
        assert!(parse_as_metadata(&plain).unwrap_err().contains("S256"));
        let absent = serde_json::json!({
            "authorization_endpoint": "https://as.test/authorize",
            "token_endpoint": "https://as.test/token",
        });
        assert!(parse_as_metadata(&absent).unwrap_err().contains("S256"));

        let prm = serde_json::json!({
            "resource": "https://mcp.example.test",
            "authorization_servers": ["https://as.test"],
        });
        assert_eq!(parse_resource_metadata(&prm).unwrap(), "https://as.test");
        assert!(parse_resource_metadata(&serde_json::json!({})).is_err());
    }

    fn reg_row(endpoint: Option<&str>) -> fluidbox_db::OauthClientRegistrationRow {
        fluidbox_db::OauthClientRegistrationRow {
            id: Uuid::now_v7(),
            tenant_id: None,
            issuer: "https://as.test".into(),
            redirect_uri: "https://fbx.test/v1/oauth/callback".into(),
            source: "dcr".into(),
            client_id: "dcr-client".into(),
            client_secret_sealed: None,
            client_secret_key_version: 1,
            registration_endpoint: endpoint.map(String::from),
            registration_access_token_sealed: None,
            registration_access_token_key_version: 1,
            token_endpoint_auth_method: Some("none".into()),
            created_at: Utc::now(),
            last_used_at: None,
        }
    }

    #[test]
    fn client_resolution_priority_reuse_beats_cimd_beats_dcr() {
        // A valid stored identity reuses — even when CIMD is presentable — so a
        // pre-registered client wins, and a second resolve of a DCR/CIMD identity
        // reuses the row instead of re-registering (design D6).
        assert_eq!(
            classify_client_resolution(Some("pre-1"), false, true),
            ClientResolution::Reuse
        );
        assert_eq!(
            classify_client_resolution(Some("dcr-1"), false, false),
            ClientResolution::Reuse
        );
        // No stored identity: CIMD when presentable, else DCR.
        assert_eq!(
            classify_client_resolution(None, true, true),
            ClientResolution::Cimd
        );
        assert_eq!(
            classify_client_resolution(None, true, false),
            ClientResolution::Dcr
        );
        // A STALE stored identity (reconnect after a public-URL move) never reuses
        // — it falls through to CIMD if presentable, else DCR.
        assert_eq!(
            classify_client_resolution(Some("dcr-old"), true, true),
            ClientResolution::Cimd
        );
        assert_eq!(
            classify_client_resolution(Some("dcr-old"), true, false),
            ClientResolution::Dcr
        );
    }

    #[test]
    fn invalid_client_retires_only_registration_sourced_identities() {
        // Registration-sourced with a registration_endpoint → the row is retired so
        // the NEXT dance re-registers a different client_id.
        let reg = ExchangeClient {
            client_id: "dcr-1".into(),
            secret: None,
            registration: Some(reg_row(Some("https://as.test/register"))),
        };
        assert!(invalid_client_disposition(&reg).0);
        // Registration-sourced but no endpoint recorded (a CIMD row) → re-minting
        // reproduces the same document-URL client_id, so retiring repairs nothing.
        let no_ep = ExchangeClient {
            client_id: "dcr-1".into(),
            secret: None,
            registration: Some(reg_row(None)),
        };
        assert!(!invalid_client_disposition(&no_ep).0);
        // Per-connection legacy / pre-registered identity → no shared row at all;
        // the AS rejected operator-supplied credentials, so a human must fix them.
        let legacy = ExchangeClient {
            client_id: "pre-1".into(),
            secret: Some("shhh".into()),
            registration: None,
        };
        assert!(!invalid_client_disposition(&legacy).0);
    }

    #[test]
    fn invalid_client_never_retries_the_same_code() {
        // The disposition is TERMINAL for every shape of rejected client: the repair
        // (retiring the shared registration) only takes effect on the NEXT dance,
        // and the user is told to start the flow again. Re-exchanging THIS code
        // under a freshly registered client_id is RFC 6749 `invalid_grant` ("code
        // was issued to another client"), so a retry could only ever have failed —
        // there is deliberately no retry disposition to assert against.
        for (label, client) in [
            (
                "dcr",
                ExchangeClient {
                    client_id: "dcr-1".into(),
                    secret: None,
                    registration: Some(reg_row(Some("https://as.test/register"))),
                },
            ),
            (
                "cimd",
                ExchangeClient {
                    client_id: "cimd-1".into(),
                    secret: None,
                    registration: Some(reg_row(None)),
                },
            ),
            (
                "preregistered",
                ExchangeClient {
                    client_id: "pre-1".into(),
                    secret: Some("shhh".into()),
                    registration: None,
                },
            ),
        ] {
            let (_, msg) = invalid_client_disposition(&client);
            // Every message ends the flow by telling the user to start over — none
            // promises (or performs) another exchange of the burned code.
            assert!(
                msg.contains("again"),
                "{label}: the user must be told to start over, got: {msg}"
            );
            assert!(
                !msg.contains("retry"),
                "{label}: no message may imply a same-code retry, got: {msg}"
            );
        }
    }

    #[test]
    fn adopt_uses_the_rows_identity_verbatim() {
        // A CIMD-eligible dance that FINDS a stored DCR row adopts the DCR row's
        // client_id + source (NOT cimd_url). The authorize leg uses this value and
        // the exchange leg loads the SAME row's client_id, so both legs match — no
        // RFC 6749 invalid_grant "code issued to another client" mismatch.
        let dcr = reg_row(Some("https://as.test/register"));
        let (client_id, source) = adopt_registration(&dcr);
        assert_eq!(
            client_id, dcr.client_id,
            "authorize leg carries the ROW's id"
        );
        assert_eq!(source, "dcr");
        // A found CIMD row is adopted verbatim too (whichever arm found it).
        let mut cimd = reg_row(None);
        cimd.source = "cimd".into();
        cimd.client_id = "https://fbx.test/.well-known/fluidbox-client.json".into();
        let (cid, src) = adopt_registration(&cimd);
        assert_eq!(cid, cimd.client_id);
        assert_eq!(src, "cimd");
    }
}
