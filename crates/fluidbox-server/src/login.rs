//! `/v1/auth/*` — the IdP-agnostic OIDC login surface (Phase B, Task 5).
//!
//! Design: `docs/plans/2026-07-17-idp-agnostic-identity-design.md` (login
//! routing lines 441-582, fail-closed edges 804-854). fluidbox is a generic
//! OIDC relying party: each org configures its own issuer, and one stable
//! callback (`{public_url}/v1/auth/callback`) serves every issuer because the
//! sealed `state` carries `{purpose:"login", flow_id, tenant_id,
//! idp_config_id}`. The browser never supplies a tenant.
//!
//! ID-token verification uses the `openidconnect` crate for JWKS types, the
//! signature primitive (`CoreJsonWebKey::verify_signature`), the algorithm
//! enum, and `at_hash` computation; every CLAIM rule the crate's high-level
//! verifier cannot express exactly (flow-bound `iat`, one-forced-refresh JWKS
//! policy, kid-less single-key acceptance, negative-kid cache, azp-when-present,
//! `at_hash`-without-access-token) is implemented in the [`verify`] wrapper —
//! the doc wins. Every identity fetch (discovery, JWKS, token endpoint) rides
//! ONE dedicated client, `state.identity_http` ([`build_identity_http`]), that
//! enforces the SSRF policy on EVERY hop, not just the request URL: its custom
//! redirect policy re-validates each hop's scheme + host literal, and its custom
//! DNS resolver rejects private/loopback/link-local/CGNAT/metadata addresses at
//! resolution time. That closes the intermediate-hop TOCTOU the earlier
//! request-URL-only checks left open (a redirect or DNS-rebind can no longer
//! land a fetch on an internal host). A pre-flight URL validation and a final-URL
//! check remain as cheap defense in depth. `openidconnect`'s bundled HTTP
//! clients are disabled (`default-features=off`).

use crate::auth::{AuthContext, Principal};
use crate::error::{ApiError, ApiResult};
use crate::oauth::{b64url, pkce_challenge, random_urlsafe};
use crate::seal::{SealCtx, SealFamily, Sealer, TRANSIT_LOGIN};
use crate::state::AppState;
use axum::body::Body;
use axum::extract::{ConnectInfo, Path, Query, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::Response;
use axum::Json;
use base64::Engine;
use chrono::{DateTime, Utc};
use fluidbox_db::{identity, sha256_hex, TenantScope};
use openidconnect::core::{CoreJsonWebKey, CoreJwsSigningAlgorithm};
use openidconnect::{AccessToken, AccessTokenHash, JsonWebKey, JsonWebKeyAlgorithm};
use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;
use uuid::Uuid;

const LOGIN_FLOW_TTL_SECS: i64 = 600;
const LOGIN_STATE_TTL_SECS: i64 = 600;
const HTTP_TIMEOUT: Duration = Duration::from_secs(15);
// Single-replica in-memory fixed-window limits (v1). Per-IP is checked first so
// it covers unknown/IdP-less slugs too (no org-existence signal leaks). Per-org
// and the outstanding-flow cap bound DB/IdP amplification (design 852-854).
const RATE_PER_IP_PER_MIN: u32 = 10;
const RATE_PER_ORG_PER_MIN: u32 = 30;
const MAX_OUTSTANDING_FLOWS_PER_ORG: i64 = 100;
// JWKS document bounds and the brief negative-kid cache TTL.
const MAX_JWKS_BYTES: usize = 256 * 1024;
const MAX_JWKS_KEYS: usize = 32;
const NEGATIVE_KID_TTL_SECS: i64 = 120;
// Byte ceiling on any identity fetch (discovery, JWKS, token endpoint),
// enforced BEFORE fully buffering the body (design 806-814).
const MAX_HTTP_BODY_BYTES: usize = 256 * 1024;
// Per-org callback rate bucket, applied once open_state names the org (design
// 494-496, 849-854) — distinct from start's per-org bucket.
const RATE_PER_ORG_CALLBACK_PER_MIN: u32 = 60;

/// The JWS algorithms the ID-token verifier actually implements — asymmetric
/// only; HS*/`none` are rejected unconditionally. admin_orgs' save-time
/// allowlist validation refuses anything outside this set, so a configured
/// allowlist can never carry a non-functional algorithm (EdDSA/ES256K), which
/// would otherwise fail only at login (design 169-171, 832-835). The doc's
/// default allowlist {RS256,ES256,PS256,RS384,ES384,RS512,ES512} is fully
/// inside this set.
pub const IMPLEMENTED_ALGS: &[&str] = &[
    "RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512",
];

// ─── OidcRuntime (an AppState field) ────────────────────────────────────────

/// (tenant_id, idp_config_id, generation) — the JWKS cache key (design 815-816).
type JwksKey = (Uuid, Uuid, i32);

/// A parsed signing key paired with its RAW JWK JSON. The raw entry is retained
/// so key selection can consult `use`/`key_ops` even when the openidconnect key
/// type does not surface them (design 826-831).
struct Jwk {
    key: CoreJsonWebKey,
    raw: Value,
}

struct CachedJwks {
    keys: Vec<Jwk>,
    /// The refresh generation that produced this entry. `0` marks a DB-SEEDED
    /// entry, which must NOT count as a network refresh (design 815-826); a
    /// successful network `force_refresh` stamps a monotonically increasing
    /// value from `OidcRuntime::refresh_version`.
    version: u64,
}

/// In-memory login runtime: the generation-keyed JWKS cache (with per-config
/// singleflight refresh and a brief negative-kid cache) and the fixed-window
/// rate counters. Single replica in v1; a restart re-seeds from the DB caches.
#[derive(Default)]
pub struct OidcRuntime {
    jwks: Mutex<HashMap<JwksKey, Arc<CachedJwks>>>,
    refresh_locks: Mutex<HashMap<JwksKey, Arc<Mutex<()>>>>,
    negative_kids: Mutex<HashMap<(JwksKey, String), i64>>,
    rate: Mutex<HashMap<String, (i64, u32)>>,
    /// Monotonic counter bumped by every SUCCESSFUL network JWKS refresh. A
    /// forced refresh skips the network only when this advanced past the value
    /// it captured before waiting on the singleflight lock — i.e. only when
    /// someone else genuinely refreshed, never merely because a DB seed is
    /// fresh (design 815-826).
    refresh_version: std::sync::atomic::AtomicU64,
}

impl OidcRuntime {
    /// Fixed-window: true while this window's count is within `limit`.
    async fn allow(&self, key: &str, limit: u32) -> bool {
        let minute = Utc::now().timestamp() / 60;
        let mut m = self.rate.lock().await;
        let e = m.entry(key.to_string()).or_insert((minute, 0));
        if e.0 != minute {
            *e = (minute, 0);
        }
        e.1 = e.1.saturating_add(1);
        e.1 <= limit
    }

    /// The cached JWKS, seeding from the DB-cached `jwks` document when the
    /// in-memory cache is cold. Never touches the network. A DB seed carries
    /// `version = 0` so a forced refresh never mistakes it for a refresh.
    async fn cached(&self, key: JwksKey, seed: &Value) -> Result<Arc<CachedJwks>, String> {
        if let Some(c) = self.jwks.lock().await.get(&key) {
            return Ok(c.clone());
        }
        let keys = parse_jwks(seed)?;
        let c = Arc::new(CachedJwks { keys, version: 0 });
        self.jwks.lock().await.insert(key, c.clone());
        Ok(c)
    }

    /// Exactly-one forced refresh, singleflighted per config (design 816-826).
    /// A DB-seeded entry (`version = 0`, `fetched_at = now`) does NOT satisfy
    /// the refresh: we skip the network ONLY when the cache's version advanced
    /// past the value captured before we waited on the lock — proof that a
    /// concurrent caller completed a real network refresh. A validated refresh
    /// is also persisted back to the DB as last-known-good.
    async fn force_refresh(
        &self,
        state: &AppState,
        key: JwksKey,
        view: &DiscoveryView,
    ) -> Result<Arc<CachedJwks>, String> {
        use std::sync::atomic::Ordering;
        // Captured BEFORE the singleflight lock so a refresh landing while we
        // wait is observable as an advance.
        let before = self.refresh_version.load(Ordering::SeqCst);
        let lock = {
            let mut l = self.refresh_locks.lock().await;
            l.entry(key).or_default().clone()
        };
        let _g = lock.lock().await;
        if let Some(c) = self.jwks.lock().await.get(&key) {
            if c.version > before {
                return Ok(c.clone());
            }
        }
        let doc = fetch_json_ssrf(state, &view.jwks_uri).await?;
        let keys = parse_jwks(&doc)?;
        let version = self.refresh_version.fetch_add(1, Ordering::SeqCst) + 1;
        let c = Arc::new(CachedJwks { keys, version });
        self.jwks.lock().await.insert(key, c.clone());
        // Persist last-known-good so a restart re-seeds this refreshed JWKS
        // (design 815-826). JWKS-ONLY so a key refresh never rewrites discovery
        // freshness (`discovered_at`) and masks stale discovery metadata.
        match identity::update_idp_jwks_cache(&state.pool, TenantScope::assume(key.0), key.1, &doc)
            .await
        {
            Ok(true) => {}
            // Zero rows: the config vanished or was retired concurrently — the
            // login is terminal (fail closed as config-inactive).
            Ok(false) => return Err("SSO configuration changed — sign in again.".into()),
            // A DB error is best-effort per-refresh: the in-memory cache already
            // holds the verified keys and this login has already verified, so
            // durability is not load-bearing here. Warn (config id only, no
            // secrets) and continue with the in-memory refresh.
            Err(_) => tracing::warn!(idp_config_id = %key.1, "jwks persist failed"),
        }
        Ok(c)
    }

    async fn kid_negative(&self, key: JwksKey, kid: &str) -> bool {
        let now = Utc::now().timestamp();
        self.negative_kids
            .lock()
            .await
            .get(&(key, kid.to_string()))
            .is_some_and(|&t| now - t < NEGATIVE_KID_TTL_SECS)
    }

    async fn mark_kid_negative(&self, key: JwksKey, kid: &str) {
        self.negative_kids
            .lock()
            .await
            .insert((key, kid.to_string()), Utc::now().timestamp());
    }
}

fn parse_jwks(v: &Value) -> Result<Vec<Jwk>, String> {
    // Document size bound BEFORE any parse work (design 826-831).
    let raw = serde_json::to_vec(v).map_err(|_| "jwks not serializable".to_string())?;
    if raw.len() > MAX_JWKS_BYTES {
        return Err("jwks document exceeds the size bound".into());
    }
    let raw_keys = match v.get("keys") {
        Some(Value::Array(a)) => a,
        _ => return Err("invalid jwks document: 'keys' must be an array".into()),
    };
    // Key-count bound over the RAW array: openidconnect silently DROPS entries it
    // cannot parse, so counting only the parsed keys would understate the doc.
    if raw_keys.len() > MAX_JWKS_KEYS {
        return Err("jwks document has too many keys".into());
    }
    // Deserialize each raw entry INDIVIDUALLY and keep it paired with its own raw
    // JSON. A set-level `CoreJsonWebKeySet` deserialize skips malformed entries,
    // which shifts the parsed-vs-raw index pairing when a bad entry PRECEDES a
    // good one — landing another key's `kid`/`use`/`key_ops` on the wrong key. By
    // parsing per entry, a key that fails to parse is excluded together with its
    // raw twin (never index-shifted), so each surviving key's raw metadata is
    // correct by construction (design 826-831).
    let mut keys = Vec::with_capacity(raw_keys.len());
    for entry in raw_keys {
        if let Ok(key) = serde_json::from_value::<CoreJsonWebKey>(entry.clone()) {
            keys.push(Jwk {
                key,
                raw: entry.clone(),
            });
        }
    }
    Ok(keys)
}

// ─── Cookie / header helpers ────────────────────────────────────────────────

/// Every value of `name` across all `Cookie` headers — >1 means ambiguous and
/// the caller refuses (a duplicate cannot be trusted).
fn cookie_values(headers: &HeaderMap, name: &str) -> Vec<String> {
    let mut out = Vec::new();
    for hv in headers.get_all(header::COOKIE) {
        let Ok(s) = hv.to_str() else { continue };
        for pair in s.split(';') {
            if let Some((k, v)) = pair.split_once('=') {
                if k.trim() == name {
                    out.push(v.trim().to_string());
                }
            }
        }
    }
    out
}

/// The single value of `name`, or `None` when it is absent OR duplicated.
fn single_cookie(headers: &HeaderMap, name: &str) -> Option<String> {
    match cookie_values(headers, name).as_slice() {
        [one] => Some(one.clone()),
        _ => None,
    }
}

fn login_cookie_name(flow: Uuid) -> String {
    format!("__Host-fbx_login_{}", flow.simple())
}
fn switch_cookie_name(id: Uuid) -> String {
    format!("__Host-fbx_switch_{}", id.simple())
}
const WEB_COOKIE: &str = "__Host-fbx_web";

/// `__Host-` cookies MUST be `Secure` and `Path=/` with no `Domain`.
fn set_cookie(name: &str, value: &str, ttl_secs: i64) -> String {
    format!("{name}={value}; HttpOnly; SameSite=Lax; Secure; Path=/; Max-Age={ttl_secs}")
}
fn clear_cookie(name: &str) -> String {
    format!("{name}=deleted; HttpOnly; SameSite=Lax; Secure; Path=/; Max-Age=0")
}

/// The client IP for rate-limit buckets and audit `source_ip`.
///
/// `X-Forwarded-For`/`X-Real-IP` are client-controllable and are honored ONLY
/// when `trust_forwarded_for` is set (fluidbox behind a trusted reverse proxy
/// that sets them authoritatively — see `FLUIDBOX_TRUST_FORWARDED_FOR`). Absent
/// that, the socket peer address (`ConnectInfo`) is the source of truth so a
/// client can neither spoof a rate-limit bucket nor forge an audit IP. `peer`
/// is `None` only if `ConnectInfo` was not wired (it always is at serve time).
pub(crate) fn client_ip(
    headers: &HeaderMap,
    peer: Option<std::net::SocketAddr>,
    trust_forwarded_for: bool,
) -> String {
    if trust_forwarded_for {
        for h in ["x-forwarded-for", "x-real-ip"] {
            if let Some(v) = headers.get(h).and_then(|v| v.to_str().ok()) {
                if let Some(first) = v.split(',').next() {
                    let ip = first.trim();
                    if !ip.is_empty() {
                        return ip.to_string();
                    }
                }
            }
        }
    }
    match peer {
        Some(addr) => addr.ip().to_string(),
        None => "unknown".to_string(),
    }
}

fn html_escape(s: &str) -> String {
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

/// Browser-facing page with the hostile-input policy: strict CSP, no-store,
/// no-referrer, `DENY`. `body_html` is caller-built from escaped pieces.
fn page(
    status: StatusCode,
    title: &str,
    body_html: &str,
    csp: &str,
    cookies: &[String],
) -> Response {
    let html = format!(
        "<!doctype html><html><head><meta charset=\"utf-8\"><title>fluidbox — {t}</title></head>\
         <body style=\"font-family:system-ui;max-width:38rem;margin:4rem auto;line-height:1.5\">\
         <h2>{t}</h2>{body_html}</body></html>",
        t = html_escape(title),
    );
    let mut b = Response::builder()
        .status(status)
        .header("content-type", "text/html; charset=utf-8")
        .header("cache-control", "no-store")
        .header("referrer-policy", "no-referrer")
        .header("x-frame-options", "DENY")
        .header("content-security-policy", csp);
    for c in cookies {
        b = b.header("set-cookie", c);
    }
    b.body(Body::from(html)).expect("static response builds")
}

/// The single neutral refusal shown for an unknown slug, an IdP-less org, a
/// suspended org, and a discovery failure alike — it never enumerates orgs.
fn neutral_unavailable() -> Response {
    page(
        StatusCode::OK,
        "Sign in",
        "<p>SSO is not configured for this organization.</p>",
        "default-src 'none'; style-src 'unsafe-inline'",
        &[],
    )
}

fn too_many() -> Response {
    page(
        StatusCode::TOO_MANY_REQUESTS,
        "Too many requests",
        "<p>Please wait a moment and try again.</p>",
        "default-src 'none'; style-src 'unsafe-inline'",
        &[],
    )
}

fn redirect(status: StatusCode, location: &str, cookies: &[String]) -> Response {
    let mut b = Response::builder()
        .status(status)
        .header(header::LOCATION, location)
        .header("cache-control", "no-store")
        .header("referrer-policy", "no-referrer");
    for c in cookies {
        b = b.header("set-cookie", c);
    }
    b.body(Body::empty()).expect("redirect builds")
}

// ─── redirect_to validation (design 843-848) ────────────────────────────────

/// One hex digit's value, or `None` for a non-hex byte.
fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Percent-decode ONE layer. A malformed `%` escape (truncated or non-hex) ⇒
/// `None` (fail closed), and a decode that does not produce valid UTF-8 ⇒
/// `None`.
fn percent_decode_once(s: &str) -> Option<String> {
    let b = s.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' {
            if i + 2 >= b.len() {
                return None;
            }
            out.push((hex_val(b[i + 1])? << 4) | hex_val(b[i + 2])?);
            i += 3;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    String::from_utf8(out).ok()
}

/// Every rejection class for a local-redirect path, run over a given form:
/// must be a single-slash absolute path (`//…` protocol-relative refused),
/// no backslashes, no control characters, and no `.`/`..` dot-segments in the
/// path portion. A single leading slash with no backslash cannot form a
/// userinfo/authority/scheme shape, so those are covered too.
fn path_is_safe_local(s: &str) -> bool {
    if !s.starts_with('/') || s.starts_with("//") {
        return false;
    }
    if s.contains('\\') {
        return false;
    }
    if s.chars().any(|c| c.is_control()) {
        return false;
    }
    let path = s.split(['?', '#']).next().unwrap_or("");
    !path.split('/').any(|seg| seg == "." || seg == "..")
}

/// Accept ONLY a single-slash absolute local path. Rejects protocol-relative
/// (`//`), backslashes, control chars, encoded separators (`%2f`/`%5c`),
/// userinfo/authority/scheme forms, and dot-segments — INCLUDING their
/// percent-encoded forms (`%2e`/`%2E`) and double-encoding tricks
/// (`%252e`). Empty ⇒ `/`. Pure so the unit vectors cover every class.
fn validate_redirect_to(raw: &str) -> Option<String> {
    if raw.is_empty() {
        return Some("/".to_string());
    }
    // Raw form must pass every class, plus the literal encoded-separator guard.
    if !path_is_safe_local(raw) {
        return None;
    }
    let lower = raw.to_ascii_lowercase();
    if lower.contains("%2f") || lower.contains("%5c") {
        return None; // encoded '/' or '\'
    }
    // Percent-decoding tricks: decode once and twice. A malformed escape is
    // refused; a difference between single- and double-decode means a
    // double-encoded separator/dot is hiding (e.g. `/%252e%252e/x`).
    let once = percent_decode_once(raw)?;
    let twice = percent_decode_once(&once)?;
    if once != twice {
        return None;
    }
    // Re-run every rejection class on the DECODED form (catches `%2e`/`%2E`
    // dot-segments and any decoded separator/control byte).
    if !path_is_safe_local(&once) {
        return None;
    }
    Some(raw.to_string())
}

fn valid_slug(s: &str) -> bool {
    let bytes = s.as_bytes();
    if bytes.is_empty() || bytes.len() > 63 {
        return false;
    }
    let first_ok = bytes[0].is_ascii_lowercase() || bytes[0].is_ascii_digit();
    first_ok
        && bytes
            .iter()
            .all(|&b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

// ─── Typed login state (design 462-468) ─────────────────────────────────────

struct LoginState {
    flow_id: Uuid,
    tenant_id: Uuid,
    idp_config_id: Uuid,
}

/// `{purpose:"login", v:1, flow_id, tenant_id, idp_config_id, exp}` — sealed via
/// the shared `Sealer::seal_token` transit primitive under the `TRANSIT_LOGIN`
/// AAD purpose, so a login state is CRYPTOGRAPHICALLY unopenable as any other
/// transit token; the in-payload `purpose`/`v` discriminator then keeps them
/// mutually unredeemable in legacy (AAD-less) sealing too (unit-tested).
async fn seal_login_state(
    sealer: &Sealer,
    flow_id: Uuid,
    tenant_id: Uuid,
    idp_config_id: Uuid,
) -> Result<String, String> {
    let payload = json!({
        "purpose": "login",
        "v": 1,
        "flow_id": flow_id,
        "tenant_id": tenant_id,
        "idp_config_id": idp_config_id,
        "exp": Utc::now().timestamp() + LOGIN_STATE_TTL_SECS,
    });
    // Transit-token sealing (self-describing) — survives a KMS mode flip within
    // the state's short TTL; see `Sealer::seal_token`.
    let sealed = sealer
        .seal_token(TRANSIT_LOGIN, &payload.to_string())
        .await
        .map_err(|e| e.to_string())?;
    Ok(b64url(&sealed))
}

async fn open_login_state(sealer: &Sealer, param: &str) -> Result<LoginState, String> {
    let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(param)
        .map_err(|_| "malformed state parameter")?;
    let plain = sealer
        .open_token(TRANSIT_LOGIN, &raw)
        .await
        .map_err(|_| "state parameter failed verification")?;
    let v: Value = serde_json::from_str(&plain).map_err(|_| "state parameter is corrupt")?;
    if v.get("purpose").and_then(Value::as_str) != Some("login") {
        return Err("state parameter is not a login state".into());
    }
    if v.get("v").and_then(Value::as_i64) != Some(1) {
        return Err("unsupported login state version".into());
    }
    let exp = v
        .get("exp")
        .and_then(Value::as_i64)
        .ok_or("state is corrupt")?;
    if Utc::now().timestamp() > exp {
        return Err("sign-in took too long — start again".into());
    }
    let uuid = |k: &str| {
        v.get(k)
            .and_then(Value::as_str)
            .and_then(|s| Uuid::parse_str(s).ok())
            .ok_or_else(|| "state is corrupt".to_string())
    };
    Ok(LoginState {
        flow_id: uuid("flow_id")?,
        tenant_id: uuid("tenant_id")?,
        idp_config_id: uuid("idp_config_id")?,
    })
}

// ─── SSRF-validated fetch (design 811-814) ──────────────────────────────────

fn host_is_loopback(u: &reqwest::Url) -> bool {
    match u.host_str() {
        Some(h) if h.eq_ignore_ascii_case("localhost") => true,
        Some(h) => h
            .trim_matches(['[', ']'])
            .parse::<IpAddr>()
            .map(|ip| ip.is_loopback())
            .unwrap_or(false),
        None => false,
    }
}

/// Login start refuses plain http unless the deployment IS loopback dev — the
/// same exception `cimd_eligible` makes for the public URL.
fn dev_loopback(public_url: &str) -> bool {
    let Ok(u) = reqwest::Url::parse(public_url) else {
        return false;
    };
    u.scheme() == "http" && host_is_loopback(&u)
}

/// Reject private/loopback/link-local/metadata/CGNAT ranges. Loopback is
/// permitted only in loopback-dev (`dev`). Stable-only checks (IPv6 ULA/link
/// local computed by hand — the std helpers are nightly).
fn ip_blocked(ip: IpAddr, dev: bool) -> bool {
    let blocked = match ip {
        IpAddr::V4(a) => {
            let o = a.octets();
            a.is_loopback()
                || a.is_private()
                || a.is_link_local()
                || a.is_broadcast()
                || a.is_documentation()
                || a.is_unspecified()
                || (o[0] == 100 && (o[1] & 0xc0) == 64) // 100.64/10 CGNAT
        }
        IpAddr::V6(a) => {
            if let Some(v4) = a.to_ipv4_mapped() {
                return ip_blocked(IpAddr::V4(v4), dev);
            }
            let s0 = a.segments()[0];
            a.is_loopback()
                || a.is_unspecified()
                || (s0 & 0xfe00) == 0xfc00 // fc00::/7 unique-local
                || (s0 & 0xffc0) == 0xfe80 // fe80::/10 link-local
        }
    };
    blocked && !(dev && ip.is_loopback())
}

async fn validate_fetch_target(u: &reqwest::Url, dev: bool) -> Result<(), String> {
    match u.scheme() {
        "https" => {}
        "http" if dev && host_is_loopback(u) => {}
        _ => return Err("OIDC endpoints must be https".into()),
    }
    let host = u.host_str().ok_or("URL has no host")?;
    let port = u.port_or_known_default().ok_or("URL has no port")?;
    let addrs: Vec<IpAddr> = tokio::net::lookup_host((host, port))
        .await
        .map_err(|_| "could not resolve host".to_string())?
        .map(|s| s.ip())
        .collect();
    if addrs.is_empty() {
        return Err("host did not resolve".into());
    }
    if addrs.iter().any(|ip| ip_blocked(*ip, dev)) {
        return Err("refusing to fetch a private/loopback/link-local address".into());
    }
    Ok(())
}

/// The addresses that survive the SSRF filter: every private/loopback/link-local/
/// CGNAT/metadata/reserved address is dropped (loopback kept only in dev). The
/// pure core of the identity client's DNS resolver — tested without a network.
fn filter_public_addrs(
    addrs: impl Iterator<Item = std::net::SocketAddr>,
    dev: bool,
) -> Vec<std::net::SocketAddr> {
    addrs.filter(|s| !ip_blocked(s.ip(), dev)).collect()
}

/// One redirect hop's scheme + host-literal gate: https always (loopback http
/// only in dev), and a host that is a private/loopback/link-local IP literal is
/// refused — the same host-literal checks `validate_fetch_target` applies to the
/// request URL. The DNS resolver still filters the *resolved* addresses at
/// connect time; this is the cheap host-literal defense-in-depth on every hop.
fn redirect_hop_allowed(u: &reqwest::Url, dev: bool) -> Result<(), String> {
    match u.scheme() {
        "https" => {}
        "http" if dev && host_is_loopback(u) => {}
        _ => return Err("redirect to a non-https identity endpoint refused".into()),
    }
    if let Some(host) = u.host_str() {
        if let Ok(ip) = host.trim_matches(['[', ']']).parse::<IpAddr>() {
            if ip_blocked(ip, dev) {
                return Err("redirect to a private/loopback address refused".into());
            }
        }
    }
    Ok(())
}

/// A `reqwest::dns::Resolve` that resolves via the system resolver and drops
/// every non-public address at resolution time — DNS-rebinding and per-hop
/// private targets die here (loopback survives only in dev). Empty after the
/// filter ⇒ a resolution error, so the connection never opens.
struct SsrfDnsResolver {
    dev: bool,
}

impl reqwest::dns::Resolve for SsrfDnsResolver {
    fn resolve(&self, name: reqwest::dns::Name) -> reqwest::dns::Resolving {
        let dev = self.dev;
        let host = name.as_str().to_string();
        Box::pin(async move {
            // Port 0: reqwest overrides it with the URL's port; we only care
            // about the resolved IPs.
            let resolved = tokio::net::lookup_host((host.as_str(), 0)).await?;
            let allowed = filter_public_addrs(resolved, dev);
            if allowed.is_empty() {
                return Err("refusing to resolve to a private/loopback/link-local address".into());
            }
            let addrs: reqwest::dns::Addrs = Box::new(allowed.into_iter());
            Ok(addrs)
        })
    }
}

/// Build the ONE HTTP client used for identity fetches (discovery, JWKS, token
/// endpoint — nothing else). Per-hop SSRF: a custom redirect policy re-validates
/// every hop's scheme + host literal (capped at 10 hops), and a custom DNS
/// resolver filters resolved addresses at connect time, closing the
/// intermediate-hop TOCTOU. No cookie store (the default with the `cookies`
/// feature off). The dev (loopback-http) allowance is config-static, so it is
/// baked into both the redirect closure and the resolver here at build time.
pub fn build_identity_http(public_url: &str) -> reqwest::Client {
    let dev = dev_loopback(public_url);
    let policy = reqwest::redirect::Policy::custom(move |attempt| {
        if attempt.previous().len() >= 10 {
            return attempt.error("too many redirects");
        }
        match redirect_hop_allowed(attempt.url(), dev) {
            Ok(()) => attempt.follow(),
            Err(e) => attempt.error(e),
        }
    });
    reqwest::Client::builder()
        .timeout(Duration::from_secs(15 * 60))
        .redirect(policy)
        .dns_resolver(Arc::new(SsrfDnsResolver { dev }))
        .build()
        .expect("identity HTTP client builds")
}

/// Save-time endpoint validation: parse `url` and apply the SAME https + SSRF
/// policy the login fetches use (loopback under the same `dev_loopback` gating).
/// admin_orgs calls this on the discovered `authorization_endpoint` /
/// `token_endpoint` / `jwks_uri` so a config advertising a private/loopback/
/// non-https endpoint is refused at SAVE time — the discovery save only *fetches*
/// jwks_uri, so authorize/token would otherwise first fail (or exfiltrate) at
/// redirect/callback time. Reuses `validate_fetch_target` — the SSRF policy is
/// never duplicated.
pub(crate) async fn validate_endpoint_target(state: &AppState, url: &str) -> Result<(), String> {
    let dev = dev_loopback(&state.cfg.public_url);
    let u = reqwest::Url::parse(url).map_err(|_| format!("'{url}' is not a valid URL"))?;
    validate_fetch_target(&u, dev).await
}

/// GET a JSON document under the SSRF policy over `state.identity_http`, whose
/// redirect policy + DNS resolver enforce the policy on every hop. The request
/// URL is pre-validated and the response's FINAL url re-validated as cheap
/// defense in depth (the per-hop client is the real guard).
async fn fetch_json_ssrf(state: &AppState, url: &str) -> Result<Value, String> {
    let dev = dev_loopback(&state.cfg.public_url);
    let u = reqwest::Url::parse(url).map_err(|_| format!("'{url}' is not a valid URL"))?;
    validate_fetch_target(&u, dev).await?;
    let mut res = state
        .identity_http
        .get(url)
        .timeout(HTTP_TIMEOUT)
        .header("accept", "application/json")
        .send()
        .await
        .map_err(|e| format!("fetch failed: {e}"))?;
    validate_fetch_target(&res.url().clone(), dev).await?;
    if !res.status().is_success() {
        return Err(format!("fetch returned HTTP {}", res.status()));
    }
    read_json_bounded(&mut res).await
}

/// Read a JSON body under the byte ceiling ENFORCED BEFORE full buffering: a
/// declared `Content-Length` over the cap is refused up front, and the body is
/// then read chunk-by-chunk with the running total re-checked, so a lying or
/// absent length cannot smuggle an oversized document past the bound (design
/// 806-814).
async fn read_json_bounded(res: &mut reqwest::Response) -> Result<Value, String> {
    if let Some(len) = res.content_length() {
        if len > MAX_HTTP_BODY_BYTES as u64 {
            return Err("identity response exceeds the size bound".into());
        }
    }
    let mut buf: Vec<u8> = Vec::new();
    while let Some(chunk) = res
        .chunk()
        .await
        .map_err(|e| format!("response read failed: {e}"))?
    {
        if buf.len() + chunk.len() > MAX_HTTP_BODY_BYTES {
            return Err("identity response exceeds the size bound".into());
        }
        buf.extend_from_slice(&chunk);
    }
    serde_json::from_slice::<Value>(&buf).map_err(|e| format!("response was not JSON: {e}"))
}

// ─── Discovery freshness (design 805-814) ───────────────────────────────────

pub(crate) struct DiscoveryView {
    pub(crate) authorization_endpoint: String,
    pub(crate) token_endpoint: String,
    pub(crate) jwks_uri: String,
    pub(crate) jwks: Value,
}

pub(crate) fn view_from(meta: &Value, jwks: Value) -> Result<DiscoveryView, String> {
    let s = |k: &str| {
        meta.get(k)
            .and_then(Value::as_str)
            .map(str::to_string)
            .ok_or_else(|| format!("discovery document is missing {k}"))
    };
    Ok(DiscoveryView {
        authorization_endpoint: s("authorization_endpoint")?,
        token_endpoint: s("token_endpoint")?,
        jwks_uri: s("jwks_uri")?,
        jwks,
    })
}

/// Fetch `{issuer}/.well-known/openid-configuration` + its `jwks_uri` over the
/// SSRF-hardened client, asserting the discovered `issuer` matches exactly.
/// Takes the raw issuer (not a config row) so save-time validation — which has
/// no config row yet — reuses the same fetch/SSRF machinery (Task 6).
pub(crate) async fn refresh_discovery(
    state: &AppState,
    issuer: &str,
) -> Result<(Value, Value), String> {
    let disc_url = format!(
        "{}/.well-known/openid-configuration",
        issuer.trim_end_matches('/')
    );
    let meta = fetch_json_ssrf(state, &disc_url).await?;
    // The discovered issuer must equal the configured issuer exactly.
    if meta.get("issuer").and_then(Value::as_str) != Some(issuer) {
        return Err("discovered issuer does not match the configured issuer".into());
    }
    let jwks_uri = meta
        .get("jwks_uri")
        .and_then(Value::as_str)
        .ok_or("discovery document has no jwks_uri")?;
    let jwks = fetch_json_ssrf(state, jwks_uri).await?;
    // Validate JWKS structure + key count + size BEFORE it can be cached
    // (design 826-831): a malformed/oversized JWKS must fail save-time and
    // start-time validation, not first fail at callback verification.
    parse_jwks(&jwks)?;
    Ok((meta, jwks))
}

/// Fresh cache is used as-is; a stale cache triggers a refresh; a refresh
/// failure with a still-valid cache uses the cache; with none it refuses.
async fn ensure_discovery(
    state: &AppState,
    scope: TenantScope,
    config: &identity::OrgIdpConfigRow,
) -> Result<DiscoveryView, String> {
    let max_age = state.cfg.oidc_discovery_max_age_secs;
    let fresh = config
        .discovered_at
        .map(|t| (Utc::now() - t).num_seconds() < max_age)
        .unwrap_or(false)
        && config.discovered_metadata.is_some()
        && config.jwks.is_some();
    if fresh {
        return view_from(
            config.discovered_metadata.as_ref().unwrap(),
            config.jwks.clone().unwrap(),
        );
    }
    match refresh_discovery(state, &config.issuer).await {
        Ok((meta, jwks)) => {
            let _ = identity::update_idp_discovery_cache(
                &state.pool,
                scope,
                config.id,
                &meta,
                &jwks,
                Utc::now(),
            )
            .await;
            view_from(&meta, jwks)
        }
        Err(e) => match (&config.discovered_metadata, &config.jwks) {
            (Some(meta), Some(jwks)) => view_from(meta, jwks.clone()),
            _ => Err(e),
        },
    }
}

// ─── ID-token verification wrapper ──────────────────────────────────────────

mod verify {
    use super::*;

    /// Everything the callback verifies an ID token against.
    pub struct Inputs<'a> {
        pub issuer: &'a str,
        pub client_id: &'a str,
        pub alg_allowlist: &'a [String],
        pub nonce: &'a str,
        pub access_token: &'a str,
        pub flow_created_at: DateTime<Utc>,
        pub skew_secs: i64,
        pub now: DateTime<Utc>,
    }

    pub struct Verified {
        pub subject: String,
        pub claims: Value,
    }

    /// `NoKey` / `BadSignature` = the only two cases that earn the single forced
    /// JWKS refresh; they are kept distinct so the caller can negative-cache ONLY
    /// a genuinely unknown kid (design 823-826): a `BadSignature` after refresh
    /// is the same-kid-rotation signal and must never poison the kid. `Terminal`
    /// = every other failure (claims, ambiguous keys) — no refresh, refuse now.
    #[derive(Debug)]
    pub enum Error {
        /// Key selection found no compatible/matching key. Earns the forced
        /// refresh; if it recurs after refresh the kid is genuinely unknown.
        NoKey,
        /// A key matched but the signature did not verify — earns the forced
        /// refresh (a same-kid rotation looks like this). NEVER negative-cached.
        BadSignature,
        Terminal(String),
    }

    fn b64(part: &str) -> Result<Vec<u8>, Error> {
        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(part)
            .map_err(|_| Error::Terminal("malformed JWT segment".into()))
    }

    /// The header `alg`/`kid` — the caller reads `kid` up front to key the
    /// negative-kid cache without re-parsing.
    pub fn header_meta(id_token: &str) -> Result<(String, Option<String>), String> {
        let seg = id_token.split('.').next().ok_or("malformed JWT")?;
        let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(seg)
            .map_err(|_| "malformed JWT header")?;
        let h: Value = serde_json::from_slice(&raw).map_err(|_| "malformed JWT header")?;
        let alg = h
            .get("alg")
            .and_then(Value::as_str)
            .ok_or("JWT header has no alg")?
            .to_string();
        let kid = h.get("kid").and_then(Value::as_str).map(str::to_string);
        Ok((alg, kid))
    }

    /// Map a JWS `alg` string to the concrete asymmetric algorithm, gated by the
    /// config allowlist. HS*/`none`/unknown never map — symmetric and `none` are
    /// rejected unconditionally (design 832-835).
    fn asymmetric_alg(
        alg_str: &str,
        allowlist: &[String],
    ) -> Result<CoreJwsSigningAlgorithm, Error> {
        use CoreJwsSigningAlgorithm as A;
        if !allowlist.iter().any(|a| a == alg_str) {
            return Err(Error::Terminal(format!(
                "algorithm {alg_str} is not allowlisted"
            )));
        }
        let alg = match alg_str {
            "RS256" => A::RsaSsaPkcs1V15Sha256,
            "RS384" => A::RsaSsaPkcs1V15Sha384,
            "RS512" => A::RsaSsaPkcs1V15Sha512,
            "PS256" => A::RsaSsaPssSha256,
            "PS384" => A::RsaSsaPssSha384,
            "PS512" => A::RsaSsaPssSha512,
            "ES256" => A::EcdsaP256Sha256,
            "ES384" => A::EcdsaP384Sha384,
            "ES512" => A::EcdsaP521Sha512,
            _ => {
                return Err(Error::Terminal(
                    "symmetric or 'none' algorithms are rejected".into(),
                ))
            }
        };
        Ok(alg)
    }

    fn json_str(v: &Value) -> Option<String> {
        serde_json::to_value(v)
            .ok()
            .and_then(|x| x.as_str().map(str::to_string))
    }

    /// The key's `kid`, read from the RAW JWK JSON (a string per RFC 7517).
    fn key_id_str(jwk: &Jwk) -> Option<String> {
        jwk.raw.get("kid").and_then(Value::as_str).map(String::from)
    }

    /// `use`/`key_ops` (from the RAW JWK, since the parsed key type may not
    /// surface `key_ops`), the constrained parsed `alg` (if present), and the
    /// kty family must all be compatible with the header alg (design 826-831).
    pub(super) fn key_compatible(alg_str: &str, jwk: &Jwk) -> bool {
        // `use`, when present, MUST be exactly "sig" (a signing key is never
        // `enc`, and any other value is refused rather than waved through).
        if let Some(u) = jwk.raw.get("use").and_then(Value::as_str) {
            if u != "sig" {
                return false;
            }
        }
        // `key_ops`, when present, MUST contain "verify".
        if let Some(ops) = jwk.raw.get("key_ops") {
            let has_verify = ops
                .as_array()
                .map(|a| a.iter().any(|o| o.as_str() == Some("verify")))
                .unwrap_or(false);
            if !has_verify {
                return false;
            }
        }
        if let JsonWebKeyAlgorithm::Algorithm(a) = jwk.key.signing_alg() {
            if json_str(&serde_json::to_value(a).unwrap_or(Value::Null)).as_deref() != Some(alg_str)
            {
                return false;
            }
        }
        let want = match &alg_str[..2] {
            "RS" | "PS" => "RSA",
            "ES" => "EC",
            _ => return false,
        };
        json_str(&serde_json::to_value(jwk.key.key_type()).unwrap_or(Value::Null)).as_deref()
            == Some(want)
    }

    /// Select the signing key per design 815-831: kid → exact match (ambiguous
    /// ⇒ Terminal, missing ⇒ NoKey); kid-less ⇒ exactly one compatible key
    /// (zero ⇒ NoKey, multiple ⇒ Terminal).
    fn select_key<'a>(alg_str: &str, kid: Option<&str>, keys: &'a [Jwk]) -> Result<&'a Jwk, Error> {
        let compat: Vec<&Jwk> = keys.iter().filter(|k| key_compatible(alg_str, k)).collect();
        match kid {
            Some(kid) => {
                let matched: Vec<&Jwk> = compat
                    .into_iter()
                    .filter(|k| key_id_str(k).as_deref() == Some(kid))
                    .collect();
                match matched.as_slice() {
                    [] => Err(Error::NoKey),
                    [one] => Ok(one),
                    _ => Err(Error::Terminal("multiple keys match the token kid".into())),
                }
            }
            None => match compat.as_slice() {
                [] => Err(Error::NoKey),
                [one] => Ok(one),
                _ => Err(Error::Terminal(
                    "token carries no kid and the JWKS has multiple compatible keys".into(),
                )),
            },
        }
    }

    // ─── Strictly-typed claim accessors (design 529-538, fail-closed) ─────────
    // A PRESENT-but-wrong-typed optional claim is a REJECTION, never silently
    // treated as absent. Only a MISSING key reads as absent: an explicitly
    // present JSON `null` is also a rejection (a conformant issuer omits an
    // absent claim rather than sending it as null).

    /// An optional string claim: MISSING ⇒ `None`; explicit `null` or a
    /// non-string value ⇒ error.
    fn opt_str<'a>(payload: &'a Value, k: &str) -> Result<Option<&'a str>, Error> {
        match payload.get(k) {
            None => Ok(None),
            Some(Value::Null) => Err(Error::Terminal(format!("claim '{k}' is present but null"))),
            Some(Value::String(s)) => Ok(Some(s.as_str())),
            Some(_) => Err(Error::Terminal(format!("claim '{k}' must be a string"))),
        }
    }

    /// A required integer claim: absent ⇒ error; non-integer ⇒ error.
    fn req_i64(payload: &Value, k: &str) -> Result<i64, Error> {
        match payload.get(k) {
            Some(Value::Number(n)) => n
                .as_i64()
                .ok_or_else(|| Error::Terminal(format!("claim '{k}' must be an integer"))),
            Some(_) => Err(Error::Terminal(format!("claim '{k}' must be a number"))),
            None => Err(Error::Terminal(format!("id token has no {k}"))),
        }
    }

    /// An optional integer claim: MISSING ⇒ `None`; explicit `null` or a
    /// non-integer ⇒ error.
    fn opt_i64(payload: &Value, k: &str) -> Result<Option<i64>, Error> {
        match payload.get(k) {
            None => Ok(None),
            Some(Value::Null) => Err(Error::Terminal(format!("claim '{k}' is present but null"))),
            Some(Value::Number(n)) => {
                Ok(Some(n.as_i64().ok_or_else(|| {
                    Error::Terminal(format!("claim '{k}' must be an integer"))
                })?))
            }
            Some(_) => Err(Error::Terminal(format!("claim '{k}' must be a number"))),
        }
    }

    /// Every claim rule from design step 5 + fail-closed edges 815-841, minus
    /// the signature (verified separately with the selected key).
    fn check_claims(payload: &Value, inp: &Inputs) -> Result<String, Error> {
        let t = |m: &str| Error::Terminal(m.to_string());
        // iss exact.
        if payload.get("iss").and_then(Value::as_str) != Some(inp.issuer) {
            return Err(t("issuer mismatch"));
        }
        // aud contains client_id; a non-string entry in the aud ARRAY rejects
        // (never dropped) — a present-but-malformed aud must fail closed.
        let auds: Vec<String> = match payload.get("aud") {
            Some(Value::String(s)) => vec![s.clone()],
            Some(Value::Array(a)) => {
                let mut v = Vec::with_capacity(a.len());
                for e in a {
                    match e.as_str() {
                        Some(s) => v.push(s.to_string()),
                        None => return Err(t("aud array contains a non-string entry")),
                    }
                }
                v
            }
            _ => return Err(t("id token has no audience")),
        };
        if !auds.iter().any(|a| a == inp.client_id) {
            return Err(t("audience does not include this client"));
        }
        // azp: present ⇒ must be a string AND equal client_id (multi-aud makes
        // it required). A non-string azp rejects rather than reading as absent.
        let azp = opt_str(payload, "azp")?;
        if auds.len() > 1 && azp != Some(inp.client_id) {
            return Err(t("multi-audience token requires azp == client_id"));
        }
        if let Some(azp) = azp {
            if azp != inp.client_id {
                return Err(t("azp does not equal this client"));
            }
        }
        let now = inp.now.timestamp();
        let skew = inp.skew_secs;
        // exp with skew (present-but-non-numeric rejects).
        let exp = req_i64(payload, "exp")?;
        if now >= exp + skew {
            return Err(t("id token is expired"));
        }
        // nbf with skew, if present (present-but-non-numeric rejects).
        if let Some(nbf) = opt_i64(payload, "nbf")? {
            if now < nbf - skew {
                return Err(t("id token is not yet valid (nbf)"));
            }
        }
        // iat bound to the flow lifetime (present-but-non-numeric rejects).
        let iat = req_i64(payload, "iat")?;
        let lo = inp.flow_created_at.timestamp() - skew;
        let hi = now + skew;
        if iat < lo || iat > hi {
            return Err(t("id token iat is outside the flow window"));
        }
        // nonce equals the stored nonce (present-but-non-string rejects).
        if opt_str(payload, "nonce")? != Some(inp.nonce) {
            return Err(t("nonce mismatch"));
        }
        // sub present, nonempty, ≤255 bytes (present-but-non-string rejects).
        let sub = opt_str(payload, "sub")?.unwrap_or("");
        if sub.is_empty() || sub.len() > 255 {
            return Err(t("subject is missing or too long"));
        }
        Ok(sub.to_string())
    }

    /// Verify an ID token against a specific JWKS. Called once with the cached
    /// keys; the caller retries once with force-refreshed keys on `NoKey` or
    /// `BadSignature`.
    pub fn verify(inp: &Inputs, id_token: &str, keys: &[Jwk]) -> Result<Verified, Error> {
        let mut parts = id_token.split('.');
        let (h, p, s) = match (parts.next(), parts.next(), parts.next(), parts.next()) {
            (Some(h), Some(p), Some(s), None) => (h, p, s),
            _ => return Err(Error::Terminal("id token is not a compact JWS".into())),
        };
        let header: Value = serde_json::from_slice(&b64(h)?)
            .map_err(|_| Error::Terminal("bad JWT header".into()))?;
        let alg_str = header
            .get("alg")
            .and_then(Value::as_str)
            .ok_or_else(|| Error::Terminal("JWT header has no alg".into()))?
            .to_string();
        let kid = header
            .get("kid")
            .and_then(Value::as_str)
            .map(str::to_string);
        let alg = asymmetric_alg(&alg_str, inp.alg_allowlist)?;

        let payload: Value = serde_json::from_slice(&b64(p)?)
            .map_err(|_| Error::Terminal("bad JWT payload".into()))?;
        let subject = check_claims(&payload, inp)?;

        let jwk = select_key(&alg_str, kid.as_deref(), keys)?;
        let signing_input = format!("{h}.{p}");
        let sig = b64(s)?;
        jwk.key
            .verify_signature(&alg, signing_input.as_bytes(), &sig)
            .map_err(|_| Error::BadSignature)?;

        // at_hash: verified when present; a present-but-non-string at_hash
        // rejects (never treated as absent), and present-with-no-access-token
        // fails.
        if let Some(at_hash) = opt_str(&payload, "at_hash")? {
            if inp.access_token.is_empty() {
                return Err(Error::Terminal(
                    "at_hash present but no access token".into(),
                ));
            }
            let computed = AccessTokenHash::from_token(
                &AccessToken::new(inp.access_token.to_string()),
                &alg,
                &jwk.key,
            )
            .map_err(|_| Error::Terminal("could not compute at_hash".into()))?;
            if computed != AccessTokenHash::new(at_hash.to_string()) {
                return Err(Error::Terminal("at_hash mismatch".into()));
            }
        }

        Ok(Verified {
            subject,
            claims: payload,
        })
    }
}

/// Verify with the one-forced-refresh JWKS policy: cached keys first; on `NoKey`
/// or `BadSignature`, force exactly one JWKS refresh and retry — terminal after
/// that (design 816-826).
///
/// The brief negative-kid cache scopes to UNKNOWN kids only (design 823-826): it
/// short-circuits the `NoKey` path (junk-kid refresh-storm bound) and, after the
/// refresh, marks the kid negative ONLY when key selection STILL finds no match.
/// A `BadSignature` — the same-kid-rotation signal — always earns its refresh
/// and never poisons the kid, so a real rotation is never blocked.
async fn verify_with_jwks(
    state: &AppState,
    key: JwksKey,
    view: &DiscoveryView,
    inp: &verify::Inputs<'_>,
    id_token: &str,
) -> Result<verify::Verified, String> {
    let kid = verify::header_meta(id_token).ok().and_then(|(_, k)| k);
    let cached = state.oidc.cached(key, &view.jwks).await?;
    let first = match verify::verify(inp, id_token, &cached.keys) {
        Ok(v) => return Ok(v),
        Err(verify::Error::Terminal(r)) => return Err(r),
        Err(e) => e, // NoKey | BadSignature — both earn the one forced refresh.
    };
    // The negative-kid cache short-circuits ONLY the unknown-kid path; a
    // signature failure must always reach the refresh (rotations enter here).
    if matches!(first, verify::Error::NoKey) {
        if let Some(kid) = &kid {
            if state.oidc.kid_negative(key, kid).await {
                return Err("unknown signing key".into());
            }
        }
    }
    let fresh = state.oidc.force_refresh(state, key, view).await?;
    match verify::verify(inp, id_token, &fresh.keys) {
        Ok(v) => Ok(v),
        // Only a still-unknown kid (no matching key after the refresh) is
        // negative-cached; a matched-kid signature failure is NOT.
        Err(verify::Error::NoKey) => {
            if let Some(kid) = &kid {
                state.oidc.mark_kid_negative(key, kid).await;
            }
            Err("unknown signing key".into())
        }
        Err(_) => Err("the ID token signature could not be verified".into()),
    }
}

// ─── Claim mapping (design 206-228) ─────────────────────────────────────────

struct MappedIdentity {
    email: Option<String>,
    email_normalized: Option<String>,
    email_verified: bool,
    name: Option<String>,
    roles: Vec<String>,
}

pub(crate) fn normalize_email(email: &str) -> String {
    email.trim().to_lowercase()
}

fn claim_at_path<'a>(claims: &'a Value, path: &str) -> Option<&'a Value> {
    let mut cur = claims;
    for seg in path.split('.') {
        cur = cur.get(seg)?;
    }
    Some(cur)
}

fn map_claims(claims: &Value, mappings: &Value) -> MappedIdentity {
    let attr = |k: &str, default: &str| -> String {
        mappings
            .get(k)
            .and_then(Value::as_str)
            .unwrap_or(default)
            .to_string()
    };
    let email = claims
        .get(attr("email", "email"))
        .and_then(Value::as_str)
        .map(str::to_string);
    let email_verified = claims
        .get(attr("email_verified", "email_verified"))
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let name = claims
        .get(attr("name", "name"))
        .and_then(Value::as_str)
        .map(str::to_string);

    let allow_owner = mappings
        .get("allow_owner_mapping")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let default_role = attr("default_role", "member");
    let role_map = mappings
        .get("role_map")
        .cloned()
        .unwrap_or_else(|| json!({}));
    let roles_path = attr("roles_path", "groups");

    // Collect the raw group/role claim values (array or single string).
    let raw: Vec<String> = match claim_at_path(claims, &roles_path) {
        Some(Value::Array(a)) => a
            .iter()
            .filter_map(Value::as_str)
            .map(String::from)
            .collect(),
        Some(Value::String(s)) => vec![s.clone()],
        _ => Vec::new(),
    };
    let mut roles: Vec<String> = Vec::new();
    for g in &raw {
        if let Some(mapped) = role_map.get(g).and_then(Value::as_str) {
            // Defensive: role_map may only yield member/approver/admin (+owner
            // when the operator opted in); Task 6 validates this at save time,
            // but the gate applies it here too.
            let allowed = matches!(mapped, "member" | "approver" | "admin")
                || (mapped == "owner" && allow_owner);
            if allowed && !roles.iter().any(|r| r == mapped) {
                roles.push(mapped.to_string());
            }
        }
    }
    if roles.is_empty() {
        roles.push(default_role);
    }

    MappedIdentity {
        email_normalized: email.as_deref().map(normalize_email),
        email,
        email_verified,
        name,
        roles,
    }
}

fn require_email_verified(mappings: &Value) -> bool {
    mappings
        .get("require_email_verified")
        .and_then(Value::as_bool)
        .unwrap_or(true)
}

fn mint_web_token() -> String {
    let mut buf = [0u8; 32];
    getrandom::fill(&mut buf).expect("OS RNG is available");
    format!("fbx_web_{}", hex::encode(buf))
}

// ─── Handlers ───────────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct EntryParams {
    #[serde(default)]
    org: Option<String>,
    #[serde(default)]
    redirect_to: Option<String>,
}

/// `GET /v1/auth/login` — the neutral entry page. A single "organization"
/// field; on submit it round-trips as `?org=` and 302s to the slug URL. It
/// never enumerates orgs and answers identically for unknown/invalid slugs.
pub async fn login_page(Query(p): Query<EntryParams>) -> Response {
    if let Some(org) = p.org.as_deref() {
        if valid_slug(org) {
            let mut loc = format!("/v1/auth/login/{org}/start");
            if let Some(rt) = p.redirect_to.as_deref().and_then(validate_redirect_to) {
                let enc = form_urlencode(&rt);
                loc.push_str(&format!("?redirect_to={enc}"));
            }
            return redirect(StatusCode::FOUND, &loc, &[]);
        }
        // Invalid slug: fall through and re-render the form (identical response).
    }
    let body = "<form method=\"get\" action=\"/v1/auth/login\">\
        <label>Organization <input name=\"org\" autofocus></label> \
        <button type=\"submit\">Continue</button></form>";
    page(
        StatusCode::OK,
        "Sign in",
        body,
        "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'",
        &[],
    )
}

fn form_urlencode(s: &str) -> String {
    let mut url = reqwest::Url::parse("http://x.invalid").expect("static");
    url.query_pairs_mut().append_pair("x", s);
    url.query()
        .and_then(|q| q.strip_prefix("x="))
        .unwrap_or("")
        .to_string()
}

#[derive(Deserialize)]
pub struct StartParams {
    #[serde(default)]
    redirect_to: Option<String>,
}

/// `GET /v1/auth/login/{slug}/start` — design steps 1-5.
pub async fn start(
    State(state): State<AppState>,
    Path(slug): Path<String>,
    Query(p): Query<StartParams>,
    ConnectInfo(peer): ConnectInfo<std::net::SocketAddr>,
    headers: HeaderMap,
) -> Response {
    // Per-IP rate limit first (covers unknown/IdP-less slugs — no leak).
    if !state
        .oidc
        .allow(
            &format!(
                "ip:{}",
                client_ip(&headers, Some(peer), state.cfg.trust_forwarded_for)
            ),
            RATE_PER_IP_PER_MIN,
        )
        .await
    {
        return too_many();
    }
    // Sealer required (flows/PKCE sealing).
    let Some(sealer) = state.sealer.as_ref() else {
        return neutral_unavailable();
    };
    if !valid_slug(&slug) {
        return neutral_unavailable();
    }
    // slug → active org.
    let org = match identity::get_org_by_slug(&state.pool, &slug).await {
        Ok(Some(o)) if o.status == "active" => o,
        Ok(_) => return neutral_unavailable(), // unknown OR suspended (fail closed, no leak)
        Err(_) => return neutral_unavailable(),
    };
    let scope = TenantScope::assume(org.id);
    // Per-org rate limit + outstanding-flow cap.
    if !state
        .oidc
        .allow(&format!("org:{}", org.id), RATE_PER_ORG_PER_MIN)
        .await
    {
        return too_many();
    }
    match identity::count_outstanding_login_flows(&state.pool, scope).await {
        Ok(n) if n >= MAX_OUTSTANDING_FLOWS_PER_ORG => return too_many(),
        Ok(_) => {}
        Err(_) => return neutral_unavailable(),
    }
    // Active IdP config.
    let config = match identity::active_idp_config(&state.pool, org.id).await {
        Ok(Some(c)) => c,
        _ => return neutral_unavailable(),
    };
    // Discovery freshness.
    let view = match ensure_discovery(&state, scope, &config).await {
        Ok(v) => v,
        Err(_) => return neutral_unavailable(),
    };
    // Hosted SSO requires https (loopback dev exempt).
    if state.cfg.public_url.starts_with("http://") && !dev_loopback(&state.cfg.public_url) {
        return neutral_unavailable();
    }
    // Validate redirect_to.
    let Some(redirect_to) = validate_redirect_to(p.redirect_to.as_deref().unwrap_or("/")) else {
        return page(
            StatusCode::BAD_REQUEST,
            "Sign in",
            "<p>Invalid redirect.</p>",
            "default-src 'none'; style-src 'unsafe-inline'",
            &[],
        );
    };

    // Mint the flow (sealed PKCE verifier, nonce, cookie-bound browser hash).
    let verifier = random_urlsafe();
    let cookie_nonce = random_urlsafe();
    let nonce = random_urlsafe();
    let browser_hash = sha256_hex(&cookie_nonce);
    let sealed_verifier = match sealer
        .seal(
            &verifier,
            SealCtx::new(scope.tenant_id(), SealFamily::LoginPkceVerifier),
        )
        .await
    {
        Ok(s) => s,
        Err(_) => return neutral_unavailable(),
    };
    let flow_id = match identity::create_login_flow(
        &state.pool,
        scope,
        config.id,
        &sealed_verifier.bytes,
        sealed_verifier.key_version,
        &nonce,
        &browser_hash,
        &redirect_to,
        LOGIN_FLOW_TTL_SECS,
        MAX_OUTSTANDING_FLOWS_PER_ORG,
    )
    .await
    {
        Ok(Some(id)) => id,
        // Over the outstanding-flow cap (checked atomically with the insert).
        Ok(None) => return too_many(),
        Err(_) => return neutral_unavailable(),
    };

    // Build the authorize URL. Scope from config, never `offline_access`.
    let mut scopes: Vec<&str> = config
        .scopes
        .iter()
        .map(String::as_str)
        .filter(|s| *s != "offline_access")
        .collect();
    if scopes.is_empty() {
        scopes = vec!["openid", "email", "profile"];
    }
    let state_param = match seal_login_state(sealer, flow_id, org.id, config.id).await {
        Ok(s) => s,
        Err(_) => return neutral_unavailable(),
    };
    let redirect_uri = format!("{}/v1/auth/callback", state.cfg.public_url);
    let Ok(mut url) = reqwest::Url::parse(&view.authorization_endpoint) else {
        return neutral_unavailable();
    };
    url.query_pairs_mut()
        .append_pair("response_type", "code")
        .append_pair("client_id", &config.client_id)
        .append_pair("redirect_uri", &redirect_uri)
        .append_pair("scope", &scopes.join(" "))
        .append_pair("state", &state_param)
        .append_pair("code_challenge", &pkce_challenge(&verifier))
        .append_pair("code_challenge_method", "S256")
        .append_pair("nonce", &nonce);

    redirect(
        StatusCode::FOUND,
        url.as_str(),
        &[set_cookie(
            &login_cookie_name(flow_id),
            &cookie_nonce,
            LOGIN_FLOW_TTL_SECS,
        )],
    )
}

#[derive(Deserialize)]
pub struct CallbackParams {
    #[serde(default)]
    code: Option<String>,
    #[serde(default)]
    state: Option<String>,
    #[serde(default)]
    error: Option<String>,
    #[serde(default)]
    error_description: Option<String>,
}

fn refuse_page(msg: &str) -> Response {
    page(
        StatusCode::BAD_REQUEST,
        "Sign in failed",
        &format!("<p>{}</p>", html_escape(msg)),
        "default-src 'none'; style-src 'unsafe-inline'",
        &[],
    )
}

/// A terminal refusal that ALSO clears the per-flow login cookie. Every
/// callback failure AFTER transaction A consumed the flow uses this — the flow
/// is spent, so its cookie must not linger (design 581-582). Pre-claim
/// refusals keep the cookie (the flow is still claimable).
fn refuse_page_clearing(msg: &str, login_cookie: &str) -> Response {
    page(
        StatusCode::BAD_REQUEST,
        "Sign in failed",
        &format!("<p>{}</p>", html_escape(msg)),
        "default-src 'none'; style-src 'unsafe-inline'",
        &[clear_cookie(login_cookie)],
    )
}

/// `GET /v1/auth/callback` — design steps 1-11, two-phase (transaction A = the
/// one-time flow claim, committed before any external I/O; token exchange +
/// verification hold NO DB transaction; transaction B = provisioning + session
/// mint under the config `FOR UPDATE`). Unauthenticated by design.
pub async fn callback(
    State(state): State<AppState>,
    Query(p): Query<CallbackParams>,
    ConnectInfo(peer): ConnectInfo<std::net::SocketAddr>,
    headers: HeaderMap,
) -> Response {
    if !state
        .oidc
        .allow(
            &format!(
                "cb:{}",
                client_ip(&headers, Some(peer), state.cfg.trust_forwarded_for)
            ),
            RATE_PER_IP_PER_MIN,
        )
        .await
    {
        return too_many();
    }
    let Some(sealer) = state.sealer.as_ref() else {
        return refuse_page("SSO is not configured on this server.");
    };
    // (1) open_state: purpose/version/expiry checked.
    let Some(state_param) = p.state.as_deref() else {
        return refuse_page("Missing state.");
    };
    let ls = match open_login_state(sealer, state_param).await {
        Ok(v) => v,
        Err(e) => return refuse_page(&e),
    };
    let scope = TenantScope::assume(ls.tenant_id);

    // Per-org callback rate limit (design 494-496, 849-854): now that
    // open_state has named the org, bound provisioning amplification per org —
    // the per-IP bucket above already covers the org-agnostic surface.
    if !state
        .oidc
        .allow(
            &format!("cb-org:{}", ls.tenant_id),
            RATE_PER_ORG_CALLBACK_PER_MIN,
        )
        .await
    {
        return too_many();
    }

    // (2) read the per-flow cookie; duplicates refuse.
    let login_cookie = login_cookie_name(ls.flow_id);
    let nonce_cookie = match cookie_values(&headers, &login_cookie).as_slice() {
        [one] => one.clone(),
        _ => return refuse_page("This sign-in link is no longer valid."),
    };
    let browser_hash = sha256_hex(&nonce_cookie);

    // Provider-side error: do not claim/burn the flow; the user can retry.
    if let Some(err) = &p.error {
        let desc = p.error_description.as_deref().unwrap_or("");
        return refuse_page(&format!("The identity provider refused: {err} {desc}"));
    }
    let Some(code) = p.code.as_deref() else {
        return refuse_page("Missing authorization code.");
    };

    // (3) transaction A — the one-time claim (commits immediately; zero rows
    //     fails closed WITHOUT burning anything).
    let claim = match identity::claim_login_flow(
        &state.pool,
        ls.flow_id,
        ls.tenant_id,
        ls.idp_config_id,
        &browser_hash,
    )
    .await
    {
        Ok(Some(c)) => c,
        Ok(None) => return refuse_page("This sign-in has expired or was already used."),
        Err(_) => return refuse_page("Sign-in failed."),
    };

    // Load the config + ensure discovery (token endpoint + jwks). NO DB txn held.
    // Everything from here is POST-CLAIM: the flow is spent, so every terminal
    // refusal below also clears the login cookie (design 581-582).
    let config = match identity::get_idp_config(&state.pool, scope, ls.idp_config_id).await {
        Ok(Some(c)) => c,
        _ => return refuse_page_clearing("Sign-in failed.", &login_cookie),
    };
    let view = match ensure_discovery(&state, scope, &config).await {
        Ok(v) => v,
        Err(_) => {
            return refuse_page_clearing(
                "The identity provider is temporarily unavailable.",
                &login_cookie,
            )
        }
    };

    // (4) token exchange — unseal PKCE verifier; auth per validated method.
    let verifier = match sealer
        .open(
            &claim.pkce_verifier_sealed,
            claim.pkce_verifier_key_version,
            SealCtx::new(scope.tenant_id(), SealFamily::LoginPkceVerifier),
        )
        .await
    {
        Ok(v) => v,
        Err(_) => return refuse_page_clearing("Sign-in failed.", &login_cookie),
    };
    let tokens = match token_exchange(
        &state,
        scope,
        &config,
        &view.token_endpoint,
        code,
        &verifier,
    )
    .await
    {
        Ok(t) => t,
        Err(e) => return refuse_page_clearing(&e, &login_cookie),
    };

    // (5) verify the ID token.
    let inputs = verify::Inputs {
        issuer: &config.issuer,
        client_id: &config.client_id,
        alg_allowlist: &config.alg_allowlist,
        nonce: &claim.nonce,
        access_token: &tokens.access_token,
        flow_created_at: claim.created_at,
        skew_secs: state.cfg.oidc_clock_skew_secs,
        now: Utc::now(),
    };
    let jwks_key = (ls.tenant_id, config.id, config.generation);
    let verified = match verify_with_jwks(&state, jwks_key, &view, &inputs, &tokens.id_token).await
    {
        Ok(v) => v,
        Err(e) => return refuse_page_clearing(&e, &login_cookie),
    };

    // (6) map claims; apply require_email_verified.
    let identity_claims = map_claims(&verified.claims, &config.claim_mappings);
    if require_email_verified(&config.claim_mappings) && !identity_claims.email_verified {
        return refuse_page_clearing(
            "Your email address is not verified with the identity provider.",
            &login_cookie,
        );
    }

    // Authentication context is carried verbatim from the ID token (its mere
    // presence proves nothing — the operator maps acr/amr to assurance later).
    // A PRESENT-but-malformed acr/amr rejects, never reads as absent (design
    // 529-538, fail-closed).
    let acr = match verified.claims.get("acr") {
        None | Some(Value::Null) => None,
        Some(Value::String(s)) => Some(s.clone()),
        Some(_) => {
            return refuse_page_clearing(
                "The identity provider returned a malformed acr claim.",
                &login_cookie,
            )
        }
    };
    let amr: Vec<String> = match verified.claims.get("amr") {
        None | Some(Value::Null) => Vec::new(),
        Some(Value::Array(a)) => {
            let mut v = Vec::with_capacity(a.len());
            for e in a {
                match e.as_str() {
                    Some(s) => v.push(s.to_string()),
                    None => {
                        return refuse_page_clearing(
                            "The identity provider returned a malformed amr claim.",
                            &login_cookie,
                        )
                    }
                }
            }
            v
        }
        Some(_) => {
            return refuse_page_clearing(
                "The identity provider returned a malformed amr claim.",
                &login_cookie,
            )
        }
    };
    let auth_time = verified
        .claims
        .get("auth_time")
        .and_then(Value::as_i64)
        .and_then(|t| DateTime::from_timestamp(t, 0));
    let idp_sid = verified
        .claims
        .get("sid")
        .and_then(Value::as_str)
        .map(str::to_string);

    // Detect an existing valid browser session (for the never-silent switch).
    let current = current_session(&state, &headers).await;

    // (7-11) transaction B.
    let switch_nonce = random_urlsafe();
    let outcome = provision(
        &state,
        scope,
        &config,
        &verified.subject,
        &identity_claims,
        acr.as_deref(),
        Some(amr.as_slice()),
        auth_time,
        idp_sid.as_deref(),
        current,
        &claim.redirect_to,
        &switch_nonce,
        client_ip(&headers, Some(peer), state.cfg.trust_forwarded_for),
    )
    .await;

    match outcome {
        Ok(Provision::Session { token, redirect_to }) => redirect(
            StatusCode::FOUND,
            &redirect_to,
            &[
                set_cookie(WEB_COOKIE, &token, state.cfg.session_absolute_secs),
                clear_cookie(&login_cookie),
            ],
        ),
        Ok(Provision::PendingSwitch { switch_id }) => {
            confirmation_page(switch_id, &switch_nonce, &login_cookie)
        }
        // Post-claim provisioning refusals clear the spent login cookie too.
        Ok(Provision::Refused(msg)) => refuse_page_clearing(&msg, &login_cookie),
        Err(_) => refuse_page_clearing("Sign-in failed.", &login_cookie),
    }
}

struct Tokens {
    access_token: String,
    id_token: String,
}

/// x-www-form-urlencoded token exchange at the discovered endpoint (reqwest's
/// `form` feature is compiled out; `Url`'s serializer is the same encoder).
async fn token_exchange(
    state: &AppState,
    scope: TenantScope,
    config: &identity::OrgIdpConfigRow,
    token_endpoint: &str,
    code: &str,
    verifier: &str,
) -> Result<Tokens, String> {
    // SSRF-validate the token endpoint before posting to it (the identity
    // client re-validates every redirect hop + resolved address underneath).
    let dev = dev_loopback(&state.cfg.public_url);
    let u =
        reqwest::Url::parse(token_endpoint).map_err(|_| "invalid token endpoint".to_string())?;
    validate_fetch_target(&u, dev).await?;

    let redirect_uri = format!("{}/v1/auth/callback", state.cfg.public_url);
    let mut form: Vec<(&str, &str)> = vec![
        ("grant_type", "authorization_code"),
        ("code", code),
        ("redirect_uri", &redirect_uri),
        ("code_verifier", verifier),
        ("client_id", &config.client_id),
    ];

    // Client auth per the config's validated method.
    let secret = if config.token_endpoint_auth == "none" {
        None
    } else {
        match identity::idp_client_secret_sealed(&state.pool, scope, config.id).await {
            Ok(Some((sealed, kv))) => {
                let sealer = state.sealer.as_ref().ok_or("credential key missing")?;
                Some(
                    sealer
                        .open(
                            &sealed,
                            kv,
                            SealCtx::new(scope.tenant_id(), SealFamily::IdpClientSecret),
                        )
                        .await
                        .map_err(|_| "client secret unseal failed")?,
                )
            }
            Ok(None) => None,
            Err(_) => return Err("client secret lookup failed".into()),
        }
    };
    if config.token_endpoint_auth == "client_secret_post" {
        if let Some(s) = &secret {
            form.push(("client_secret", s));
        }
    }
    let body = url_form(&form);
    let mut req = state
        .identity_http
        .post(token_endpoint)
        .timeout(HTTP_TIMEOUT)
        .header("content-type", "application/x-www-form-urlencoded")
        .header("accept", "application/json")
        .body(body);
    if config.token_endpoint_auth == "client_secret_basic" {
        if let Some(s) = &secret {
            req = req.basic_auth(&config.client_id, Some(s));
        }
    }
    let res = req
        .send()
        .await
        .map_err(|e| format!("token exchange failed: {e}"))?;
    // Final-URL re-validation for symmetry with fetch_json_ssrf (defense in
    // depth on top of the per-hop identity client).
    validate_fetch_target(&res.url().clone(), dev).await?;
    let status = res.status();
    let v: Value = res.json().await.unwrap_or(Value::Null);
    if !status.is_success() {
        let err = v
            .get("error")
            .and_then(Value::as_str)
            .unwrap_or("unknown_error");
        return Err(format!("token exchange returned {status} ({err})"));
    }
    let access_token = v
        .get("access_token")
        .and_then(Value::as_str)
        .ok_or("token response has no access token")?
        .to_string();
    let id_token = v
        .get("id_token")
        .and_then(Value::as_str)
        .ok_or("token response has no id token")?
        .to_string();
    Ok(Tokens {
        access_token,
        id_token,
    })
}

fn url_form(pairs: &[(&str, &str)]) -> String {
    let mut url = reqwest::Url::parse("http://enc.invalid").expect("static");
    url.query_pairs_mut()
        .extend_pairs(pairs.iter().map(|(k, v)| (*k, *v)));
    url.query().unwrap_or_default().to_string()
}

/// The current live browser session (if any), for switch detection.
async fn current_session(state: &AppState, headers: &HeaderMap) -> Option<(Uuid, Uuid, Uuid)> {
    let token = single_cookie(headers, WEB_COOKIE)?;
    let auth = identity::resolve_web_session(&state.pool, &token, state.cfg.session_idle_secs)
        .await
        .ok()??;
    if auth.membership_status != "active"
        || auth.user_status != "active"
        || auth.tenant_status != "active"
    {
        return None;
    }
    Some((auth.tenant_id, auth.session_id, auth.user_id))
}

enum Provision {
    Session { token: String, redirect_to: String },
    PendingSwitch { switch_id: Uuid },
    Refused(String),
}

/// Transaction B: config-locked JIT provisioning, bootstrap-owner consumption,
/// never-silent session replacement, and the session mint (design 540-582).
#[allow(clippy::too_many_arguments)]
async fn provision(
    state: &AppState,
    scope: TenantScope,
    config: &identity::OrgIdpConfigRow,
    subject: &str,
    identity_claims: &MappedIdentity,
    acr: Option<&str>,
    amr: Option<&[String]>,
    auth_time: Option<DateTime<Utc>>,
    idp_sid: Option<&str>,
    current: Option<(Uuid, Uuid, Uuid)>,
    redirect_to: &str,
    switch_nonce: &str,
    source_ip: String,
) -> sqlx::Result<Provision> {
    // Transaction B provisions the just-authenticated user under a KNOWN tenant, so
    // it rides `scoped_tx` (sets `fluidbox.tenant_id`): every executor-generic
    // identity call below (lock/upsert/mint/consume) is a tenant-scoped write that
    // RLS would otherwise refuse. The audit INSERT rides the same tx (check(true)).
    let mut tx = fluidbox_db::scoped_tx(&state.pool, scope).await?;

    // Opening lock — captures status + bootstrap arm/expiry (the expiry read is
    // the ONLY authoritative one; the consume UPDATE's RETURNING would be NULL).
    let Some(locked) = identity::lock_idp_config_for_update(&mut tx, scope, config.id).await?
    else {
        tx.rollback().await.ok();
        return Ok(Provision::Refused("Sign-in failed.".into()));
    };
    if locked.config_status != "active" {
        tx.rollback().await.ok();
        return Ok(Provision::Refused(
            "SSO configuration changed — sign in again.".into(),
        ));
    }
    if locked.tenant_status != "active" {
        tx.rollback().await.ok();
        return Ok(Provision::Refused("This organization is suspended.".into()));
    }

    // JIT user + membership.
    let user = identity::upsert_user(
        &mut tx,
        scope,
        config.id,
        subject,
        identity_claims.email.as_deref(),
        identity_claims.email_normalized.as_deref(),
        identity_claims.email_verified,
        identity_claims.name.as_deref(),
    )
    .await?;
    let membership = identity::upsert_membership_preserving_owner(
        &mut tx,
        scope,
        user.id,
        &identity_claims.roles,
    )
    .await?;
    if membership.status != "active" {
        tx.rollback().await.ok();
        // Rejected attempt: audit in a separate committed transaction.
        rejected_audit(
            state,
            Some(scope.tenant_id()),
            &user.id.to_string(),
            &source_ip,
            "login.refused_deactivated",
            Some(&membership.id.to_string()),
        )
        .await;
        return Ok(Provision::Refused(
            "Your access to this organization is deactivated.".into(),
        ));
    }

    // Bootstrap-owner consumption (single-winner; three-way decision from the
    // opening SELECT's captured expiry).
    if let Some(armed) = &locked.bootstrap_owner_email {
        let matches = identity_claims.email_verified
            && identity_claims.email_normalized.as_deref() == Some(normalize_email(armed).as_str());
        // A matching arm is ALWAYS consumed (single winner); the promote /
        // reject-and-consume decision follows from the captured expiry.
        if matches
            && identity::consume_bootstrap_arm(&mut tx, scope, config.id, armed)
                .await?
                .is_some()
        {
            let was_unexpired = locked
                .bootstrap_owner_expires_at
                .map(|e| e > Utc::now())
                .unwrap_or(false);
            let owner_exists = identity::active_owner_exists(&mut tx, scope).await?;
            let (action, success) = if was_unexpired && !owner_exists {
                identity::add_owner_role(&mut tx, scope, membership.id).await?;
                ("bootstrap_owner.promote", true)
            } else {
                ("bootstrap_owner.reject_and_consume", false)
            };
            let detail = json!({
                "subject": subject,
                "was_unexpired": was_unexpired,
                "active_owner_existed": owner_exists,
                // Correlate this consumption to the arming audit row (design 401-402).
                "arm_id": locked.bootstrap_arm_audit_id,
            });
            identity::insert_audit(
                &mut tx,
                identity::AuditEntry {
                    tenant_id: Some(scope.tenant_id()),
                    actor_kind: "user",
                    actor_id: Some(&user.id.to_string()),
                    source_ip: Some(&source_ip),
                    request_id: None,
                    action,
                    target: Some(&membership.id.to_string()),
                    success,
                    detail: Some(&detail),
                },
            )
            .await?;
        }
    }

    // Never-silent session replacement.
    if let Some((rt, rs, cu)) = current {
        let different = rt != scope.tenant_id() || cu != user.id;
        if different {
            let switch_id = identity::create_pending_switch(
                &mut tx,
                scope,
                config.id,
                membership.id,
                user.id,
                rt,
                rs,
                redirect_to,
                &sha256_hex(switch_nonce),
                acr,
                amr,
                auth_time,
            )
            .await?;
            tx.commit().await?;
            return Ok(Provision::PendingSwitch { switch_id });
        }
        // Same user + same org: re-login refresh (revoke old, mint new).
        identity::revoke_user_session_conn(&mut tx, scope, rs).await?;
    }

    let token = mint_web_token();
    identity::mint_user_session(
        &mut tx,
        scope,
        membership.id,
        user.id,
        config.id,
        &token,
        acr,
        amr,
        auth_time,
        idp_sid,
        state.cfg.session_idle_secs,
        state.cfg.session_absolute_secs,
    )
    .await?;
    tx.commit().await?;
    Ok(Provision::Session {
        token,
        redirect_to: redirect_to.to_string(),
    })
}

/// A rejected security attempt is audited in a transaction committed AFTER the
/// rollback (design 398-402) — best effort against a fully dead database. Rides
/// `insert_audit_standalone` so the row carries the tenant GUC the tightened RLS
/// INSERT policy requires (review M3), instead of a GUC-less pooled connection.
async fn rejected_audit(
    state: &AppState,
    tenant_id: Option<Uuid>,
    actor_id: &str,
    source_ip: &str,
    action: &str,
    target: Option<&str>,
) {
    let _ = identity::insert_audit_standalone(
        &state.pool,
        identity::AuditEntry {
            tenant_id,
            actor_kind: "user",
            actor_id: Some(actor_id),
            source_ip: Some(source_ip),
            request_id: None,
            action,
            target,
            success: false,
            detail: None,
        },
    )
    .await;
}

/// The same-origin confirmation interstitial: a nonce'd inline script POSTs to
/// `/v1/auth/switch/{id}` with the CSRF header (a form cannot set it). Sets the
/// switch cookie, clears the login cookie.
fn confirmation_page(switch_id: Uuid, switch_nonce: &str, login_cookie: &str) -> Response {
    let script_nonce = random_urlsafe();
    let action = format!("/v1/auth/switch/{}", switch_id.simple());
    let body = format!(
        "<p>You are already signed in as a different user or organization. \
         Continue to switch?</p>\
         <button id=\"go\">Switch</button>\
         <script nonce=\"{n}\">\
         document.getElementById('go').onclick=function(){{\
         fetch('{a}',{{method:'POST',headers:{{'x-fluidbox-csrf':'1'}}}})\
         .then(function(r){{if(r.redirected){{location=r.url;}}else{{location='/';}}}});\
         }};</script>",
        n = html_escape(&script_nonce),
        a = html_escape(&action),
    );
    let csp = format!(
        "default-src 'none'; style-src 'unsafe-inline'; script-src 'nonce-{}'; connect-src 'self'",
        script_nonce
    );
    page(
        StatusCode::OK,
        "Switch account",
        &body,
        &csp,
        &[
            set_cookie(&switch_cookie_name(switch_id), switch_nonce, 120),
            clear_cookie(login_cookie),
        ],
    )
}

/// `POST /v1/auth/switch/{id}` — the dual-tenant one-time confirmation. The
/// `Principal` extractor enforces CSRF + confirms the CURRENT browser session;
/// the raw cookie binds that session inside `claim_pending_switch`'s predicate.
pub async fn switch_confirm(
    principal: Principal,
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    headers: HeaderMap,
) -> Response {
    // Must be a browser session (a PAT/operator can never confirm a switch).
    let Principal::User(u) = &principal else {
        return refuse_page("A session switch requires a browser session.");
    };
    if !matches!(u.auth, AuthContext::BrowserSession { .. }) {
        return refuse_page("A session switch requires a browser session.");
    }
    let Some(web) = single_cookie(&headers, WEB_COOKIE) else {
        return refuse_page("Sign-in failed.");
    };
    let switch_name = switch_cookie_name(id);
    let Some(switch_nonce) = single_cookie(&headers, &switch_name) else {
        return refuse_page("This confirmation is no longer valid.");
    };
    let new_token = mint_web_token();
    match identity::claim_pending_switch(
        &state.pool,
        id,
        &sha256_hex(&switch_nonce),
        &web,
        &new_token,
        state.cfg.session_idle_secs,
        state.cfg.session_absolute_secs,
    )
    .await
    {
        Ok(Some(claim)) => redirect(
            StatusCode::FOUND,
            &claim.redirect_to,
            &[
                set_cookie(
                    WEB_COOKIE,
                    &claim.new_session_token,
                    state.cfg.session_absolute_secs,
                ),
                clear_cookie(&switch_name),
            ],
        ),
        // Fail closed keeping the original session; clear the spent switch cookie.
        _ => page(
            StatusCode::BAD_REQUEST,
            "Switch failed",
            "<p>The switch could not be completed. Your current session is unchanged.</p>",
            "default-src 'none'; style-src 'unsafe-inline'",
            &[clear_cookie(&switch_name)],
        ),
    }
}

/// `POST /v1/auth/logout` — revoke the browser session, clear the cookie
/// (CSRF enforced by the `Principal` extractor).
pub async fn logout(principal: Principal, State(state): State<AppState>) -> ApiResult<Response> {
    let Principal::User(u) = &principal else {
        return Err(ApiError::BadRequest(
            "logout applies to a browser session".into(),
        ));
    };
    let AuthContext::BrowserSession { session_id, .. } = &u.auth else {
        return Err(ApiError::BadRequest(
            "logout applies to a browser session".into(),
        ));
    };
    identity::revoke_user_session(&state.pool, TenantScope::assume(u.tenant_id), *session_id)
        .await?;
    Ok(Response::builder()
        .status(StatusCode::NO_CONTENT)
        .header("set-cookie", clear_cookie(WEB_COOKIE))
        .header("cache-control", "no-store")
        .body(Body::empty())
        .expect("logout response builds"))
}

/// `GET /v1/auth/me` — the session-shell endpoint for the dashboard. Any
/// `UserPrincipal` (browser or PAT); the operator gets a distinguishable shape.
pub async fn me(principal: Principal, State(state): State<AppState>) -> ApiResult<Json<Value>> {
    match &principal {
        Principal::Operator { .. } => Ok(Json(json!({ "operator": true }))),
        Principal::User(u) => {
            let scope = TenantScope::assume(u.tenant_id);
            let org = identity::get_org(&state.pool, scope).await?;
            let user = identity::get_user(&state.pool, scope, u.user_id).await?;
            let auth_kind = match u.auth {
                AuthContext::BrowserSession { .. } => "browser",
                AuthContext::Pat { .. } => "pat",
            };
            let org_json = org.map(|o| {
                let slug = o.slug.clone();
                json!({ "slug": slug, "display_name": o.display_name.unwrap_or(o.slug) })
            });
            let user_json = user.map(|us| json!({ "email": us.email, "name": us.name }));
            Ok(Json(json!({
                // A stable user id so the dashboard can tell "my personal
                // connection" from a teammate's (the server still owner-filters;
                // this is presentation only).
                "user_id": u.user_id,
                "org": org_json,
                "user": user_json,
                "roles": u.roles,
                "auth_kind": auth_kind,
            })))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use jsonwebtoken::{Algorithm, EncodingKey, Header};
    use serde_json::json;

    fn sealer() -> Sealer {
        Sealer::from_key_string(&"ab".repeat(32)).unwrap()
    }

    // ─── redirect_to vectors ──────────────────────────────────────────────
    #[test]
    fn redirect_to_accepts_local_paths() {
        for ok in ["/", "/dashboard", "/agents/123", "/a/b?x=1&y=2", "/x#frag"] {
            assert_eq!(validate_redirect_to(ok).as_deref(), Some(ok), "{ok}");
        }
        assert_eq!(validate_redirect_to("").as_deref(), Some("/"));
    }

    #[test]
    fn redirect_to_rejects_every_escape_class() {
        for bad in [
            "//evil.example",      // protocol-relative
            "///evil",             // multi-slash
            "http://evil.example", // absolute scheme
            "https://evil",        // absolute scheme
            "/\\evil.example",     // backslash
            "\\/\\/evil",          // backslash + not leading slash
            "/../secret",          // dot-segment
            "/./x",                // dot-segment
            "/a/../../b",          // dot-segment
            "/%2f%2fevil",         // encoded slash
            "/%2F%2Fevil",         // encoded slash upper
            "/foo%5cbar",          // encoded backslash
            "relative/path",       // not absolute
            "/foo\u{0007}bar",     // control char
            "/%2e%2e/x",           // encoded dot-segment (%2e = '.')
            "/%2E%2E/x",           // encoded dot-segment upper
            "/a/%2e%2e/b",         // encoded dot-segment mid-path
            "/%2e/x",              // encoded single-dot segment
            "/%252e%252e/x",       // DOUBLE-encoded dot-segment
            "/foo%",               // malformed percent escape
            "/foo%zz",             // non-hex percent escape
        ] {
            assert!(validate_redirect_to(bad).is_none(), "must reject {bad:?}");
        }
    }

    // ─── login-state confusion (both directions) ──────────────────────────
    #[tokio::test]
    async fn login_state_roundtrip_and_purpose_confusion() {
        let s = sealer();
        let flow = Uuid::now_v7();
        let tenant = Uuid::now_v7();
        let cfg = Uuid::now_v7();
        let tok = seal_login_state(&s, flow, tenant, cfg).await.unwrap();
        let ls = open_login_state(&s, &tok).await.unwrap();
        assert_eq!(ls.flow_id, flow);
        assert_eq!(ls.tenant_id, tenant);
        assert_eq!(ls.idp_config_id, cfg);

        // A foreign sealed token (a connector-shaped {c,v,x} transit blob, sealed
        // under the OAuth-boot AAD purpose) must NOT open as a login state — in KMS
        // mode the AAD purpose refuses it outright, and in legacy (AAD-less)
        // sealing the missing `purpose` tag does.
        let connector = crate::oauth::b64url(
            &s.seal_token(
                crate::seal::TRANSIT_OAUTH_BOOT,
                &serde_json::json!({ "c": Uuid::now_v7(), "v": "verifier", "x": 9_999_999_999i64 })
                    .to_string(),
            )
            .await
            .unwrap(),
        );
        assert!(open_login_state(&s, &connector).await.is_err());

        // Tampering + wrong key fail closed.
        assert!(open_login_state(&s, "not-base64!!").await.is_err());
        let other = Sealer::from_key_string(&"cd".repeat(32)).unwrap();
        assert!(open_login_state(&other, &tok).await.is_err());
    }

    #[tokio::test]
    async fn login_state_rejects_expiry_and_bad_version() {
        let s = sealer();
        let stale = {
            let payload = json!({
                "purpose": "login", "v": 1, "flow_id": Uuid::now_v7(),
                "tenant_id": Uuid::now_v7(), "idp_config_id": Uuid::now_v7(),
                "exp": Utc::now().timestamp() - 1,
            });
            b64url(
                &s.seal_token(TRANSIT_LOGIN, &payload.to_string())
                    .await
                    .unwrap(),
            )
        };
        assert!(open_login_state(&s, &stale).await.is_err());
        let wrong_v = {
            let payload = json!({
                "purpose": "login", "v": 2, "flow_id": Uuid::now_v7(),
                "tenant_id": Uuid::now_v7(), "idp_config_id": Uuid::now_v7(),
                "exp": Utc::now().timestamp() + 600,
            });
            b64url(
                &s.seal_token(TRANSIT_LOGIN, &payload.to_string())
                    .await
                    .unwrap(),
            )
        };
        assert!(open_login_state(&s, &wrong_v).await.is_err());
    }

    // ─── slug shape ───────────────────────────────────────────────────────
    #[test]
    fn slug_shape() {
        for ok in ["default", "acme", "a", "a-b-c", "org-12ab34cd", "0abc"] {
            assert!(valid_slug(ok), "{ok}");
        }
        for bad in ["", "-abc", "ABC", "a_b", "a b", "a/b", &"x".repeat(64)] {
            assert!(!valid_slug(bad), "{bad}");
        }
    }

    // ─── SSRF ip ranges ───────────────────────────────────────────────────
    #[test]
    fn ssrf_blocks_internal_ranges() {
        let b = |s: &str| ip_blocked(s.parse().unwrap(), false);
        assert!(b("127.0.0.1"));
        assert!(b("10.0.0.5"));
        assert!(b("192.168.1.1"));
        assert!(b("169.254.169.254")); // link-local metadata
        assert!(b("100.64.1.1")); // CGNAT
        assert!(b("::1"));
        assert!(b("fe80::1")); // link-local
        assert!(b("fc00::1")); // unique-local
        assert!(!b("93.184.216.34")); // public
                                      // loopback allowed only in dev.
        assert!(ip_blocked("127.0.0.1".parse().unwrap(), false));
        assert!(!ip_blocked("127.0.0.1".parse().unwrap(), true));
    }

    // ─── ID-token verification (a static test RSA key + its JWK) ───────────
    // A throwaway 2048-bit RSA key generated once (openssl) and embedded so the
    // tests need no key-gen and no extra dependency. `TEST_JWK_N` is the JWK
    // modulus (base64url) of this exact key; `e` is 65537 (`AQAB`).
    const TEST_PRIV_PEM: &str = "-----BEGIN PRIVATE KEY-----
MIIEuQIBADANBgkqhkiG9w0BAQEFAASCBKMwggSfAgEAAoIBAQCf9ynOg8m2PcSR
T4hUBqp4to8cRD17prcniy8IP2IycFsTVe+tH5LnOylfURsBLyYQ809P4QVBW5Ta
mvS2vHHhlkM0aaYThhD8fwwlp94KCohdzDv+21I+1uAI+EwBCpqLgPlzSYOgv0aw
02Agc2elE2JosDIX5s7pEAu1s/ZG+5F4CrDRGIW+1r8MoP0lGfCND9x1IJ8altnD
8rbkYiDqcv69vR/8h5Pr0Buv5jQoE0qc/InhFhJgf0Fg5JVYcXQ3Xm8SXhtEhZZF
AJ7muGYMdjLXs5nhJWeixE72GcCGdtRbaHY1lfavFlHAMcknZaVkXS8B948s2z4T
rX6ZlAArAgMBAAECgf4aqRb5VFL0t1a2Nossy0TzhCRV5wmtkhufJj4FzIqRMtNQ
Zazh2GFOKI4R/3KAwAWYIvUVBcEvzhOrsNJtolADSQfqXwakOl6aYTz6Xv/4Aclj
LfwnKGaMvUNEO3MaDqpd6yD9a0Mvh1xAxvnpGVLXhbjhDydKKdhSVQTz7l/IHzbv
lOpDAhFkeedLQRgMcNdAxF1JE8XgRA9tdzWYpkAMvkPSDfuA8jbfGK5VVflqZ1EB
nNn6E0zHiFsLyrl1zv8DCcZcopREmFEF2o4+0n47Jf9cHT8Ov5t1Y4wowltKRJvY
lKapYd6rYJje2758HAq9EHAv3xOUosbqHBTJHQKBgQDhmuyy07Kr12IQ0QuWpvpF
LsNlMHuTD396HR5uVKtQtwQAhS+l2i7c1WnR7xV+0EBMyFumDOXJGv9NepEP0ck0
EuuE/Wzg/LH6ut98bFFlukkjzn8h1Oi6EVmS1si5wuUtrkzWOf7xEcV0WQF82xKq
YTCod0eZpu+BF6wI1QP0pwKBgQC1hFbi7dvfgDDnnKMSrOpVNKbC8/6yUtvBfax2
MI+8AXka1qKoyMZoLoj5LLbc1Y6ZXw2+SqCgJIEkbXDmA3WDOD4xrnuU3MgZ1Rup
4iKSAFOv/IjVBESwU3Cy1Xnud9JB/fikh2PVTdVD6nScPTPR7Il3CNRgz6WXrq98
ZWVU3QKBgDw28X45arLa5d2/Leyj3KCifpx/eDwkIs4g/4JLLv54GqVY5wLJXUCr
5XaW7ZHPW5oiz/Nd9ebbQdEYKaejQqSXeC0ixvC2AXr+ba/z6TXRprvb3arV/NfM
0a+TjDeogSrUHsX+7MDDEYSgTPlaL30yO557V6z3FW3LN6uTz155AoGADnlxHENv
ZxEn1TBOaKzVOtop+h3Oz5V/5JwK5pnUvF85swQukFsCR0h+r6/7HP0ClARaajQ1
Ps/qZGc9u3nHIyGXBAsv250Hb9fojtFzhET2Z3Ax0Rq4B39/2yLeyD9RyuVfsG8D
bPz55qKJjfPrb+/2vkE7/kRQphnN8JN9UxkCgYAlsDhqweDtwCvm8FCRwW4SO4AG
neHizZKGUxPNzssuaw/C3ut/YESUwdbX4Rs7KW7ytsAB6NWuiXorDOCqNVkr1c8P
uIATiz1iFxtbjHI9UNGig2aiz3j22PuZSNeJqpxryrgzfWd1s828kecc31+KEIP6
4BoNR3Y4XzI4tO4xtg==
-----END PRIVATE KEY-----
";
    const TEST_JWK_N: &str = "n_cpzoPJtj3EkU-IVAaqeLaPHEQ9e6a3J4svCD9iMnBbE1XvrR-S5zspX1EbAS8mEPNPT-EFQVuU2pr0trxx4ZZDNGmmE4YQ_H8MJafeCgqIXcw7_ttSPtbgCPhMAQqai4D5c0mDoL9GsNNgIHNnpRNiaLAyF-bO6RALtbP2RvuReAqw0RiFvta_DKD9JRnwjQ_cdSCfGpbZw_K25GIg6nL-vb0f_IeT69Abr-Y0KBNKnPyJ4RYSYH9BYOSVWHF0N15vEl4bRIWWRQCe5rhmDHYy17OZ4SVnosRO9hnAhnbUW2h2NZX2rxZRwDHJJ2WlZF0vAfePLNs-E61-mZQAKw";

    struct Tk {
        jwks: Value,
    }

    fn rsa_test_key(kid: &str) -> Tk {
        Tk {
            jwks: json!({"keys":[
                {"kty":"RSA","use":"sig","alg":"RS256","kid":kid,"n":TEST_JWK_N,"e":"AQAB"}
            ]}),
        }
    }

    fn mint(_tk: &Tk, kid: Option<&str>, alg: Algorithm, claims: &Value) -> String {
        let mut header = Header::new(alg);
        header.kid = kid.map(str::to_string);
        let key = EncodingKey::from_rsa_pem(TEST_PRIV_PEM.as_bytes()).unwrap();
        jsonwebtoken::encode(&header, claims, &key).unwrap()
    }

    fn b64url_json(v: &Value) -> String {
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(serde_json::to_vec(v).unwrap())
    }

    fn base_claims(now: i64) -> Value {
        json!({
            "iss": "https://issuer.example",
            "aud": "client-abc",
            "sub": "subject-1",
            "exp": now + 300,
            "iat": now,
            "nonce": "nonce-1",
            "email": "a@example.com",
            "email_verified": true,
        })
    }

    fn inputs<'a>(alg_allowlist: &'a [String], now: i64) -> verify::Inputs<'a> {
        verify::Inputs {
            issuer: "https://issuer.example",
            client_id: "client-abc",
            alg_allowlist,
            nonce: "nonce-1",
            access_token: "",
            flow_created_at: DateTime::from_timestamp(now - 5, 0).unwrap(),
            skew_secs: 60,
            now: DateTime::from_timestamp(now, 0).unwrap(),
        }
    }

    fn keys(tk: &Tk) -> Vec<Jwk> {
        parse_jwks(&tk.jwks).unwrap()
    }

    /// Build a `Jwk` from a raw JWK JSON object (for `use`/`key_ops` vectors).
    fn jwk_from_raw(raw: Value) -> Jwk {
        let set = json!({ "keys": [raw] });
        parse_jwks(&set).unwrap().pop().unwrap()
    }

    #[test]
    fn verify_accepts_a_valid_token() {
        let now = Utc::now().timestamp();
        let tk = rsa_test_key("k1");
        let allow = vec!["RS256".to_string()];
        let tok = mint(&tk, Some("k1"), Algorithm::RS256, &base_claims(now));
        let v = verify::verify(&inputs(&allow, now), &tok, &keys(&tk)).unwrap();
        assert_eq!(v.subject, "subject-1");
    }

    #[test]
    fn verify_kidless_single_key_accepts_but_multi_refuses() {
        let now = Utc::now().timestamp();
        let allow = vec!["RS256".to_string()];
        let tk = rsa_test_key("k1");
        let tok = mint(&tk, None, Algorithm::RS256, &base_claims(now));
        // single compatible key → accept
        assert!(verify::verify(&inputs(&allow, now), &tok, &keys(&tk)).is_ok());
        // two compatible keys, no kid → refuse (Terminal)
        let tk2 = rsa_test_key("k2");
        let mut two = keys(&tk);
        two.extend(keys(&tk2));
        assert!(matches!(
            verify::verify(&inputs(&allow, now), &tok, &two),
            Err(verify::Error::Terminal(_))
        ));
    }

    #[test]
    fn verify_rejects_hs256_and_none_and_wrong_iss() {
        let now = Utc::now().timestamp();
        let allow = vec!["RS256".to_string()];
        let tk = rsa_test_key("k1");
        // HS256 is symmetric — rejected even before signature (Terminal).
        let hs = {
            let key = EncodingKey::from_secret(b"shared");
            let mut h = Header::new(Algorithm::HS256);
            h.kid = Some("k1".into());
            jsonwebtoken::encode(&h, &base_claims(now), &key).unwrap()
        };
        assert!(matches!(
            verify::verify(&inputs(&allow, now), &hs, &keys(&tk)),
            Err(verify::Error::Terminal(_))
        ));
        // Wrong issuer.
        let mut c = base_claims(now);
        c["iss"] = json!("https://evil.example");
        let tok = mint(&tk, Some("k1"), Algorithm::RS256, &c);
        assert!(matches!(
            verify::verify(&inputs(&allow, now), &tok, &keys(&tk)),
            Err(verify::Error::Terminal(_))
        ));
    }

    #[test]
    fn verify_aud_azp_rules() {
        let now = Utc::now().timestamp();
        let allow = vec!["RS256".to_string()];
        let tk = rsa_test_key("k1");
        // aud without client → refuse
        let mut c = base_claims(now);
        c["aud"] = json!("someone-else");
        let tok = mint(&tk, Some("k1"), Algorithm::RS256, &c);
        assert!(verify::verify(&inputs(&allow, now), &tok, &keys(&tk)).is_err());
        // multi-aud missing azp → refuse
        let mut c = base_claims(now);
        c["aud"] = json!(["client-abc", "other"]);
        let tok = mint(&tk, Some("k1"), Algorithm::RS256, &c);
        assert!(verify::verify(&inputs(&allow, now), &tok, &keys(&tk)).is_err());
        // multi-aud with azp==client → ok
        let mut c = base_claims(now);
        c["aud"] = json!(["client-abc", "other"]);
        c["azp"] = json!("client-abc");
        let tok = mint(&tk, Some("k1"), Algorithm::RS256, &c);
        assert!(verify::verify(&inputs(&allow, now), &tok, &keys(&tk)).is_ok());
        // azp present but wrong → refuse
        let mut c = base_claims(now);
        c["azp"] = json!("wrong");
        let tok = mint(&tk, Some("k1"), Algorithm::RS256, &c);
        assert!(verify::verify(&inputs(&allow, now), &tok, &keys(&tk)).is_err());
    }

    #[test]
    fn verify_time_and_nonce_and_sub() {
        let now = Utc::now().timestamp();
        let allow = vec!["RS256".to_string()];
        let tk = rsa_test_key("k1");
        // expired
        let mut c = base_claims(now);
        c["exp"] = json!(now - 3600);
        let tok = mint(&tk, Some("k1"), Algorithm::RS256, &c);
        assert!(verify::verify(&inputs(&allow, now), &tok, &keys(&tk)).is_err());
        // iat before the flow window
        let mut c = base_claims(now);
        c["iat"] = json!(now - 10_000);
        let tok = mint(&tk, Some("k1"), Algorithm::RS256, &c);
        assert!(verify::verify(&inputs(&allow, now), &tok, &keys(&tk)).is_err());
        // nonce mismatch
        let mut c = base_claims(now);
        c["nonce"] = json!("other");
        let tok = mint(&tk, Some("k1"), Algorithm::RS256, &c);
        assert!(verify::verify(&inputs(&allow, now), &tok, &keys(&tk)).is_err());
        // oversized sub
        let mut c = base_claims(now);
        c["sub"] = json!("x".repeat(256));
        let tok = mint(&tk, Some("k1"), Algorithm::RS256, &c);
        assert!(verify::verify(&inputs(&allow, now), &tok, &keys(&tk)).is_err());
    }

    #[test]
    fn verify_at_hash_rules() {
        let now = Utc::now().timestamp();
        let allow = vec!["RS256".to_string()];
        let tk = rsa_test_key("k1");
        // at_hash present but no access token → Terminal
        let mut c = base_claims(now);
        c["at_hash"] = json!("deadbeef");
        let tok = mint(&tk, Some("k1"), Algorithm::RS256, &c);
        assert!(matches!(
            verify::verify(&inputs(&allow, now), &tok, &keys(&tk)),
            Err(verify::Error::Terminal(_))
        ));
        // at_hash present, access token present, but hash mismatched → Terminal
        let mut inp = inputs(&allow, now);
        inp.access_token = "some-access-token";
        assert!(matches!(
            verify::verify(&inp, &tok, &keys(&tk)),
            Err(verify::Error::Terminal(_))
        ));
        // at_hash present but NON-STRING (a number) → Terminal, never absent.
        let mut c = base_claims(now);
        c["at_hash"] = json!(12345);
        let tok = mint(&tk, Some("k1"), Algorithm::RS256, &c);
        assert!(matches!(
            verify::verify(&inputs(&allow, now), &tok, &keys(&tk)),
            Err(verify::Error::Terminal(_))
        ));
    }

    // ─── fix 5: JWK use / key_ops selection (design 826-831) ───────────────
    #[test]
    fn key_use_and_key_ops_selection() {
        // use=sig, key_ops=[verify] → compatible.
        let ok = jwk_from_raw(json!({
            "kty":"RSA","use":"sig","key_ops":["verify"],"alg":"RS256",
            "kid":"k1","n":TEST_JWK_N,"e":"AQAB"
        }));
        assert!(verify::key_compatible("RS256", &ok));
        // use=enc → refused.
        let enc = jwk_from_raw(json!({
            "kty":"RSA","use":"enc","alg":"RS256","kid":"k1","n":TEST_JWK_N,"e":"AQAB"
        }));
        assert!(!verify::key_compatible("RS256", &enc));
        // use is some other value (not "sig") → refused, never waved through.
        let other = jwk_from_raw(json!({
            "kty":"RSA","use":"tls","alg":"RS256","kid":"k1","n":TEST_JWK_N,"e":"AQAB"
        }));
        assert!(!verify::key_compatible("RS256", &other));
        // key_ops present WITHOUT "verify" → refused.
        let noverify = jwk_from_raw(json!({
            "kty":"RSA","key_ops":["encrypt"],"alg":"RS256","kid":"k1",
            "n":TEST_JWK_N,"e":"AQAB"
        }));
        assert!(!verify::key_compatible("RS256", &noverify));
        // no use / no key_ops (only kty+alg) → still compatible.
        let bare = jwk_from_raw(json!({
            "kty":"RSA","alg":"RS256","kid":"k1","n":TEST_JWK_N,"e":"AQAB"
        }));
        assert!(verify::key_compatible("RS256", &bare));
    }

    // ─── parse_jwks: malformed entry excluded, never index-shifted ─────────
    #[test]
    fn parse_jwks_excludes_malformed_without_shifting_metadata() {
        // A JWKS whose FIRST entry is malformed (no `kty` ⇒ fails to parse) and
        // whose SECOND is a valid key. A set-level deserialize skips the bad
        // entry and would shift the raw metadata by one; per-entry parsing must
        // exclude the bad entry WITH its raw twin so the valid key keeps its OWN
        // kid/use/key_ops (design 826-831).
        let set = json!({"keys":[
            {"kid":"malformed","use":"sig","alg":"RS256"},
            {"kty":"RSA","use":"sig","key_ops":["verify"],"alg":"RS256",
             "kid":"good","n":TEST_JWK_N,"e":"AQAB"},
        ]});
        let keys = parse_jwks(&set).unwrap();
        assert_eq!(keys.len(), 1, "the malformed entry is excluded");
        // The surviving key carries the SECOND entry's raw metadata, not the
        // malformed first entry's.
        assert_eq!(keys[0].raw.get("kid").and_then(Value::as_str), Some("good"));
        assert!(verify::key_compatible("RS256", &keys[0]));
        // And it verifies a token whose kid selects it — proving the parsed key
        // and its raw kid are correctly paired.
        let now = Utc::now().timestamp();
        let allow = vec!["RS256".to_string()];
        let tok = mint(
            &rsa_test_key("good"),
            Some("good"),
            Algorithm::RS256,
            &base_claims(now),
        );
        let v = verify::verify(&inputs(&allow, now), &tok, &keys).unwrap();
        assert_eq!(v.subject, "subject-1");
    }

    #[test]
    fn parse_jwks_rejects_non_array_keys() {
        assert!(parse_jwks(&json!({"keys":"nope"})).is_err());
        assert!(parse_jwks(&json!({})).is_err());
    }

    // ─── fix 6: present-but-malformed optional claims fail closed ──────────
    #[test]
    fn malformed_optional_claims_reject() {
        let now = Utc::now().timestamp();
        let allow = vec!["RS256".to_string()];
        let tk = rsa_test_key("k1");
        let bad = |c: Value| {
            let tok = mint(&tk, Some("k1"), Algorithm::RS256, &c);
            assert!(
                verify::verify(&inputs(&allow, now), &tok, &keys(&tk)).is_err(),
                "must reject {c}"
            );
        };
        // azp as a number.
        let mut c = base_claims(now);
        c["azp"] = json!(7);
        bad(c);
        // azp explicitly PRESENT-but-null → reject (not read as absent).
        let mut c = base_claims(now);
        c["azp"] = json!(null);
        bad(c);
        // nbf explicitly PRESENT-but-null → reject (not read as absent).
        let mut c = base_claims(now);
        c["nbf"] = json!(null);
        bad(c);
        // aud array with a non-string entry.
        let mut c = base_claims(now);
        c["aud"] = json!(["client-abc", 9]);
        bad(c);
        // nbf as a string.
        let mut c = base_claims(now);
        c["nbf"] = json!("soon");
        bad(c);
        // exp as a string.
        let mut c = base_claims(now);
        c["exp"] = json!("later");
        bad(c);
        // iat as a boolean.
        let mut c = base_claims(now);
        c["iat"] = json!(true);
        bad(c);
        // nonce as a number.
        let mut c = base_claims(now);
        c["nonce"] = json!(1);
        bad(c);
        // sub as a number.
        let mut c = base_claims(now);
        c["sub"] = json!(42);
        bad(c);
    }

    #[test]
    fn verify_unknown_kid_needs_refresh() {
        let now = Utc::now().timestamp();
        let allow = vec!["RS256".to_string()];
        let tk = rsa_test_key("k1");
        let tok = mint(
            &tk,
            Some("does-not-exist"),
            Algorithm::RS256,
            &base_claims(now),
        );
        assert!(matches!(
            verify::verify(&inputs(&allow, now), &tok, &keys(&tk)),
            Err(verify::Error::NoKey)
        ));
    }

    #[test]
    fn verify_rejects_alg_none_unsigned() {
        let now = Utc::now().timestamp();
        let allow = vec!["RS256".to_string()];
        let tk = rsa_test_key("k1");
        // A literal {"alg":"none"} header with an empty signature segment.
        let header = b64url_json(&json!({ "alg": "none", "kid": "k1" }));
        let payload = b64url_json(&base_claims(now));
        let tok = format!("{header}.{payload}.");
        assert!(matches!(
            verify::verify(&inputs(&allow, now), &tok, &keys(&tk)),
            Err(verify::Error::Terminal(_))
        ));
        // Even if an operator wrongly allowlists "none", the asymmetric map still
        // refuses it.
        let allow_none = vec!["RS256".to_string(), "none".to_string()];
        assert!(matches!(
            verify::verify(&inputs(&allow_none, now), &tok, &keys(&tk)),
            Err(verify::Error::Terminal(_))
        ));
    }

    #[test]
    fn verify_rejects_hs256_even_when_allowlisted() {
        let now = Utc::now().timestamp();
        // Operator misconfiguration: HS256 present IN the allowlist. The
        // asymmetric-map backstop must still reject it (a shared client_secret
        // must never forge identities — design 832-835).
        let allow = vec!["RS256".to_string(), "HS256".to_string()];
        let tk = rsa_test_key("k1");
        let hs = {
            let key = EncodingKey::from_secret(b"shared");
            let mut h = Header::new(Algorithm::HS256);
            h.kid = Some("k1".into());
            jsonwebtoken::encode(&h, &base_claims(now), &key).unwrap()
        };
        assert!(matches!(
            verify::verify(&inputs(&allow, now), &hs, &keys(&tk)),
            Err(verify::Error::Terminal(_))
        ));
    }

    #[test]
    fn verify_nbf_skew() {
        let now = Utc::now().timestamp();
        let allow = vec!["RS256".to_string()];
        let tk = rsa_test_key("k1");
        // skew is 60 (see `inputs`). nbf 120s in the future is beyond skew →
        // reject (now < nbf - skew).
        let mut c = base_claims(now);
        c["nbf"] = json!(now + 120);
        let tok = mint(&tk, Some("k1"), Algorithm::RS256, &c);
        assert!(verify::verify(&inputs(&allow, now), &tok, &keys(&tk)).is_err());
        // nbf 30s in the future is within skew → accept.
        let mut c = base_claims(now);
        c["nbf"] = json!(now + 30);
        let tok = mint(&tk, Some("k1"), Algorithm::RS256, &c);
        assert!(verify::verify(&inputs(&allow, now), &tok, &keys(&tk)).is_ok());
    }

    // ─── per-hop SSRF: redirect closure + DNS filter (pure fns) ────────────
    #[test]
    fn redirect_hop_validation() {
        let u = |s: &str| reqwest::Url::parse(s).unwrap();
        // https public host → allowed.
        assert!(redirect_hop_allowed(&u("https://issuer.example/x"), false).is_ok());
        // http public host, not dev → refused.
        assert!(redirect_hop_allowed(&u("http://issuer.example/x"), false).is_err());
        // https to a private / metadata / loopback IP literal → refused.
        assert!(redirect_hop_allowed(&u("https://169.254.169.254/latest"), false).is_err());
        assert!(redirect_hop_allowed(&u("https://10.0.0.1/x"), false).is_err());
        assert!(redirect_hop_allowed(&u("https://[::1]/x"), false).is_err());
        // http loopback in dev → allowed; the same not-in-dev → refused.
        assert!(redirect_hop_allowed(&u("http://127.0.0.1:5556/x"), true).is_ok());
        assert!(redirect_hop_allowed(&u("http://127.0.0.1:5556/x"), false).is_err());
    }

    #[test]
    fn dns_filter_range_logic() {
        use std::net::SocketAddr;
        let p = |s: &str| s.parse::<SocketAddr>().unwrap();
        let addrs = || {
            vec![
                p("93.184.216.34:443"),   // public
                p("10.0.0.1:443"),        // private
                p("127.0.0.1:443"),       // loopback
                p("169.254.169.254:443"), // link-local metadata
            ]
            .into_iter()
        };
        // Not dev: only the public address survives.
        assert_eq!(
            filter_public_addrs(addrs(), false),
            vec![p("93.184.216.34:443")]
        );
        // Dev: public + loopback survive; private / link-local still dropped.
        let out = filter_public_addrs(addrs(), true);
        assert!(out.contains(&p("93.184.216.34:443")));
        assert!(out.contains(&p("127.0.0.1:443")));
        assert!(!out.contains(&p("10.0.0.1:443")));
        assert!(!out.contains(&p("169.254.169.254:443")));
    }

    // ─── client_ip trust decision table (pure fn) ─────────────────────────
    #[test]
    fn client_ip_trust_decision_table() {
        use std::net::SocketAddr;
        let peer: SocketAddr = "198.51.100.7:54321".parse().unwrap();
        let mut with_xff = HeaderMap::new();
        with_xff.insert("x-forwarded-for", "203.0.113.9, 10.0.0.1".parse().unwrap());
        let no_xff = HeaderMap::new();

        // Trusted + header present → the FIRST XFF hop.
        assert_eq!(client_ip(&with_xff, Some(peer), true), "203.0.113.9");
        // Trusted + no header → fall through to the socket peer.
        assert_eq!(client_ip(&no_xff, Some(peer), true), "198.51.100.7");
        // Untrusted + header present → header IGNORED, socket peer wins.
        assert_eq!(client_ip(&with_xff, Some(peer), false), "198.51.100.7");
        // No ConnectInfo wired (should not happen at serve time) → "unknown".
        assert_eq!(client_ip(&with_xff, None, false), "unknown");
    }

    // ─── claim mapping ────────────────────────────────────────────────────
    #[test]
    fn claim_mapping_dotted_path_and_role_map() {
        let claims = json!({
            "email": "A@Example.com",
            "email_verified": true,
            "name": "Alice",
            "realm_access": { "roles": ["staff", "leads"] },
        });
        let mappings = json!({
            "email": "email", "email_verified": "email_verified", "name": "name",
            "roles_path": "realm_access.roles",
            "role_map": { "staff": "member", "leads": "admin" },
            "default_role": "member",
        });
        let m = map_claims(&claims, &mappings);
        assert_eq!(m.email_normalized.as_deref(), Some("a@example.com"));
        assert!(m.roles.contains(&"member".to_string()));
        assert!(m.roles.contains(&"admin".to_string()));
    }

    #[test]
    fn claim_mapping_default_role_and_owner_refusal() {
        let claims = json!({ "groups": ["random"] });
        // owner mapping without allow_owner_mapping is dropped → default_role.
        let mappings = json!({
            "roles_path": "groups",
            "role_map": { "random": "owner" },
            "default_role": "member",
        });
        let m = map_claims(&claims, &mappings);
        assert_eq!(m.roles, vec!["member".to_string()]);
        // with the opt-in, owner maps.
        let mappings = json!({
            "roles_path": "groups",
            "role_map": { "random": "owner" },
            "allow_owner_mapping": true,
        });
        let m = map_claims(&claims, &mappings);
        assert_eq!(m.roles, vec!["owner".to_string()]);
    }

    #[test]
    fn require_email_verified_default_true() {
        assert!(require_email_verified(&json!({})));
        assert!(!require_email_verified(
            &json!({ "require_email_verified": false })
        ));
    }
}
