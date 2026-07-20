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
use crate::seal::{SealCtx, SealFamily, Sealer};
use crate::state::AppState;
use axum::extract::{Path, Query, State};
use axum::response::Html;
use axum::Json;
use chrono::{Duration, Utc};
use serde::Deserialize;
use serde_json::{json, Value};
use uuid::Uuid;

const STATE_TTL_SECS: i64 = 600;
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
/// - a CIMD identity is dead the moment CIMD stops being presentable, or
///   when the document URL no longer matches this deployment;
/// - a DCR identity is dead when the redirect_uri it was registered with
///   changed (the AS would refuse the exchange on redirect mismatch);
/// - pre-registered identities are user-owned and never auto-invalidated.
fn stored_identity_stale(
    source: &str,
    client_id: &str,
    registered_redirect: Option<&str>,
    cimd_ok: bool,
    current_cimd_id: &str,
    current_redirect: &str,
) -> bool {
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

/// The opaque signed `state` parameter: AEAD-sealed (tamper-proof AND
/// unreadable to the AS/browser it transits), carrying the connection and
/// the PKCE verifier — stateless, so a control-plane restart mid-dance
/// changes nothing.
pub async fn seal_state(
    sealer: &Sealer,
    connection_id: Uuid,
    verifier: &str,
) -> Result<String, String> {
    let payload = json!({
        "c": connection_id,
        "v": verifier,
        "x": Utc::now().timestamp() + STATE_TTL_SECS,
    });
    // Transit-token sealing (self-describing) — survives a KMS mode flip within
    // the dance's short TTL; see `Sealer::seal_token`.
    let sealed = sealer
        .seal_token(&payload.to_string())
        .await
        .map_err(|e| e.to_string())?;
    Ok(b64url(&sealed))
}

pub async fn open_state(sealer: &Sealer, state_param: &str) -> Result<(Uuid, String), String> {
    use base64::Engine;
    let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(state_param)
        .map_err(|_| "malformed state parameter")?;
    let plain = sealer
        .open_token(&raw)
        .await
        .map_err(|_| "state parameter failed verification")?;
    let v: Value = serde_json::from_str(&plain).map_err(|_| "state parameter is corrupt")?;
    let exp = v["x"].as_i64().ok_or("state parameter is corrupt")?;
    if Utc::now().timestamp() > exp {
        return Err("authorization took too long — start the connect flow again".into());
    }
    let cid = v["c"]
        .as_str()
        .and_then(|s| Uuid::parse_str(s).ok())
        .ok_or("state parameter is corrupt")?;
    let verifier = v["v"].as_str().ok_or("state parameter is corrupt")?;
    Ok((cid, verifier.to_string()))
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

// ─── Discovery (network) ──────────────────────────────────────────────────

/// 401-probe the MCP endpoint, walk RFC 9728 → RFC 8414/OIDC, and return
/// validated AS metadata. Every step fails with an actionable message —
/// this runs interactively from the dashboard Connect flow.
pub async fn discover(state: &AppState, mcp_url: &str) -> Result<AsMeta, String> {
    let mut prm_urls: Vec<String> = Vec::new();
    if let Ok(res) = state
        .http
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
        let Ok(res) = state.http.get(pu).timeout(HTTP_TIMEOUT).send().await else {
            continue;
        };
        if !res.status().is_success() {
            continue;
        }
        let Ok(v) = res.json::<Value>().await else {
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
        let Ok(res) = state.http.get(mu).timeout(HTTP_TIMEOUT).send().await else {
            continue;
        };
        if !res.status().is_success() {
            continue;
        }
        let Ok(v) = res.json::<Value>().await else {
            continue;
        };
        // Found the document: S256-refusal must NOT fall through to the
        // next URL — this is a policy refusal, not a lookup miss.
        return parse_as_metadata(&v);
    }
    Err(format!(
        "authorization server '{as_base}' publishes no discoverable metadata (RFC 8414/OIDC)"
    ))
}

/// Resolve the client identity for this connection against this AS.
/// Priority: whatever the connection already carries (pre-registered or a
/// previously minted DCR id — never re-register while it's still valid) →
/// CIMD when advertised AND presentable from this deployment → DCR.
/// Returns (client_id, source).
async fn resolve_client(
    state: &AppState,
    scope: fluidbox_db::TenantScope,
    conn_id: Uuid,
    oauth: &Value,
    meta: &AsMeta,
) -> Result<(String, String), String> {
    let cimd_ok = meta.cimd_supported && cimd_eligible(&state.cfg.public_url);
    if let Some(existing) = oauth.get("client_id").and_then(Value::as_str) {
        let source = oauth
            .get("client_id_source")
            .and_then(Value::as_str)
            .unwrap_or("preregistered");
        if !stored_identity_stale(
            source,
            existing,
            oauth.get("redirect_uri").and_then(Value::as_str),
            cimd_ok,
            &cimd_client_id(state),
            &redirect_uri(state),
        ) {
            return Ok((existing.to_string(), source.to_string()));
        }
        // Stale — fall through and mint a fresh identity (reconnect after
        // an ineligible-CIMD dance or a public-URL move lands here).
    }
    if cimd_ok {
        return Ok((cimd_client_id(state), "cimd".to_string()));
    }
    let Some(reg) = &meta.registration_endpoint else {
        return Err(
            "authorization server supports neither CIMD nor dynamic client registration — \
             supply a pre-registered client_id on the connection"
                .into(),
        );
    };
    let body = json!({
        "client_name": "fluidbox",
        "redirect_uris": [redirect_uri(state)],
        "grant_types": ["authorization_code", "refresh_token"],
        "response_types": ["code"],
        "token_endpoint_auth_method": "none",
    });
    let res = state
        .http
        .post(reg)
        .timeout(HTTP_TIMEOUT)
        .json(&body)
        .send()
        .await
        .map_err(|e| format!("dynamic client registration failed: {e}"))?;
    let status = res.status();
    let v: Value = res.json().await.unwrap_or(Value::Null);
    if !status.is_success() {
        return Err(format!(
            "dynamic client registration returned HTTP {status}"
        ));
    }
    let client_id = v["client_id"]
        .as_str()
        .ok_or("registration response has no client_id")?
        .to_string();
    // A DCR-minted secret (rare with auth method "none") is custodied like
    // any other: sealed, never echoed.
    if let Some(secret) = v["client_secret"].as_str() {
        if let Some(sealer) = &state.sealer {
            let sealed = sealer
                .seal(
                    secret,
                    SealCtx::new(scope.tenant_id(), SealFamily::ConnectionClientSecret),
                )
                .await
                .map_err(|e| format!("failed to seal client secret: {e}"))?;
            fluidbox_db::set_connection_client_secret(
                &state.pool,
                scope,
                conn_id,
                &sealed.bytes,
                sealed.key_version,
            )
            .await
            .map_err(|e| format!("failed to store client secret: {e}"))?;
        }
    }
    Ok((client_id, "dcr".to_string()))
}

// ─── The dance ────────────────────────────────────────────────────────────

pub(crate) fn sealer(state: &AppState) -> ApiResult<&Sealer> {
    state.sealer.as_ref().ok_or_else(|| {
        ApiError::BadRequest(
            "OAuth connections are disabled: set FLUIDBOX_CREDENTIAL_KEY on the server".into(),
        )
    })
}

/// Shared by the start endpoint and the catalog Connect flow: run discovery
/// and client-identity resolution (idempotent — results persist on the
/// connection), then mint the PKCE pair and return the authorize URL.
pub async fn start_dance(
    state: &AppState,
    scope: fluidbox_db::TenantScope,
    conn_id: Uuid,
) -> ApiResult<String> {
    let sealer_ref = sealer(state)?;
    // Unfiltered read by design: the caller already established authority over
    // this connection — either the owner-checked `start` route
    // (`connection_for_mutation`) or a connection this same principal just
    // created in the catalog/manual oauth branch. The dance mechanics need the
    // row regardless of the viewer lens.
    let conn = fluidbox_db::get_connection(&state.pool, scope, conn_id)
        .await?
        .ok_or(ApiError::NotFound)?;
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
    let (client_id, client_source) = resolve_client(state, scope, conn.id, &oauth, &meta)
        .await
        .map_err(ApiError::BadRequest)?;

    // Persist the discovered custody state (idempotent re-runs overwrite
    // with fresh endpoints; the client identity sticks).
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
    o.insert("scopes".into(), json!(scopes));
    fluidbox_db::update_connection_oauth(&state.pool, scope, conn.id, &oauth).await?;

    let verifier = random_urlsafe();
    let state_param = seal_state(sealer_ref, conn.id, &verifier)
        .await
        .map_err(ApiError::Internal)?;
    let mut url = reqwest::Url::parse(&meta.authorization_endpoint)
        .map_err(|_| ApiError::BadRequest("AS authorization_endpoint is not a valid URL".into()))?;
    url.query_pairs_mut()
        .append_pair("response_type", "code")
        .append_pair("client_id", &client_id)
        .append_pair("redirect_uri", &redirect_uri(state))
        .append_pair("state", &state_param)
        .append_pair("code_challenge", &pkce_challenge(&verifier))
        .append_pair("code_challenge_method", "S256")
        .append_pair("resource", &resource);
    if !scopes.is_empty() {
        url.query_pairs_mut()
            .append_pair("scope", &scopes.join(" "));
    }
    Ok(url.to_string())
}

/// `POST /v1/connections/{id}/oauth/start` (admin) → `{authorize_url}`.
/// Also the RECONNECT path: an errored connection redoes the dance in place.
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
    let authorize_url = start_dance(&state, principal.scope(), conn.id).await?;
    Ok(Json(json!({ "authorize_url": authorize_url })))
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
/// server-authored, non-secret, non-upstream text ever reaches `body`.
fn page(status: axum::http::StatusCode, title: &str, body: &str) -> axum::response::Response {
    use axum::response::IntoResponse;
    let html = Html(format!(
        "<!doctype html><meta charset=\"utf-8\"><title>fluidbox — {t}</title>\
         <body style=\"font-family:system-ui;max-width:38rem;margin:4rem auto;line-height:1.5\">\
         <h2>{t}</h2><p>{b}</p></body>",
        t = escape_html(title),
        b = escape_html(body),
    ));
    (
        status,
        [(
            axum::http::header::CONTENT_SECURITY_POLICY,
            "default-src 'none'; style-src 'unsafe-inline'",
        )],
        html,
    )
        .into_response()
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

/// `GET /v1/oauth/callback` — THE one stable redirect URI. Unauthenticated
/// by design (a browser redirect can't carry the admin token); the sealed
/// `state` parameter is the authentication, and nothing is trusted before
/// it verifies. Browser-facing: answers HTML, never JSON errors. Upstream-
/// derived text (the AS `error`/`error_description`, MCP discovery errors) is
/// NEVER reflected — it goes to the server log and the browser sees a generic
/// line (R3.4).
pub async fn callback(
    State(state): State<AppState>,
    Query(p): Query<CallbackParams>,
) -> axum::response::Response {
    use axum::http::StatusCode;
    let Some(sealer_ref) = state.sealer.as_ref() else {
        return page(
            StatusCode::BAD_REQUEST,
            "Connection failed",
            "FLUIDBOX_CREDENTIAL_KEY is not configured.",
        );
    };
    let Some(state_param) = p.state.as_deref() else {
        return page(
            StatusCode::BAD_REQUEST,
            "Connection failed",
            "Missing state parameter.",
        );
    };
    let (conn_id, verifier) = match open_state(sealer_ref, state_param).await {
        Ok(v) => v,
        Err(e) => return page(StatusCode::BAD_REQUEST, "Connection failed", &e),
    };
    if let Some(err) = &p.error {
        // The AS `error`/`error_description` are attacker-influenceable (they ride
        // the redirect query) and can echo the sealed state, the authorization
        // code, the PKCE verifier, or the client secret. Log ONLY an allowlisted
        // error code + a bounded digest of the raw text — never the verbatim
        // strings (R3.4, parity with the broker boundary in d87fb88). The browser
        // sees a generic line.
        let detail = p
            .error_description
            .as_deref()
            .filter(|s| !s.is_empty())
            .unwrap_or(err.as_str());
        tracing::warn!(
            oauth_error = known_oauth_error(err),
            detail = %crate::broker::msg_digest(detail),
            "oauth callback: authorization server refused"
        );
        return page(
            StatusCode::BAD_REQUEST,
            "Authorization refused",
            "The authorization server refused the request. You can close this tab and try again.",
        );
    }
    let Some(code) = p.code.as_deref() else {
        return page(
            StatusCode::BAD_REQUEST,
            "Connection failed",
            "Missing authorization code.",
        );
    };
    match complete_dance(&state, conn_id, &verifier, code).await {
        Ok(bundle_note) => page(
            StatusCode::OK,
            "Connected",
            &format!("The connection is active.{bundle_note} You can close this tab."),
        ),
        Err(e) => page(StatusCode::BAD_REQUEST, "Connection failed", &e),
    }
}

/// Exchange the code, seal the rotating refresh token, activate the connection,
/// bump the authorization generation on a RECONNECT (fail-closed — a re-consent
/// may change the account/issuer/audience, so any in-flight run bound to the old
/// generation must fail closed; design :294-296), and photograph the pending
/// snapshot with the freshly minted access token (Phase C: snapshots replace the
/// old brokered-bundle auto-register).
async fn complete_dance(
    state: &AppState,
    conn_id: Uuid,
    verifier: &str,
    code: &str,
) -> Result<String, String> {
    let sealer_ref = state.sealer.as_ref().ok_or("credential key missing")?;
    // The AEAD-sealed `state` param carrying conn_id IS the auth (like a webhook
    // signature) — this browser leg has no principal. Resolve the connection
    // cross-tenant (UUID-only system-worker loader), then its OWN tenant is the
    // operative scope for the exchange, exactly parallel to events.rs ingress.
    let conn = fluidbox_db::system_worker::get_connection(&state.pool, conn_id)
        .await
        .map_err(|e| format!("connection lookup failed: {e}"))?
        .ok_or("connection not found")?;
    let scope = fluidbox_db::TenantScope::assume(conn.tenant_id);
    if conn.status == "revoked" {
        return Err("connection was revoked — create a new one".into());
    }
    let oauth = conn.oauth.clone().unwrap_or_else(|| json!({}));
    let token_endpoint = oauth
        .get("token_endpoint")
        .and_then(Value::as_str)
        .ok_or("connection has no token endpoint — start the connect flow again")?;
    let client_id = oauth
        .get("client_id")
        .and_then(Value::as_str)
        .ok_or("connection has no client identity — start the connect flow again")?;
    let resource = oauth.get("resource").and_then(Value::as_str);

    let mut form: Vec<(&str, &str)> = vec![
        ("grant_type", "authorization_code"),
        ("code", code),
        ("client_id", client_id),
        ("code_verifier", verifier),
    ];
    let ru = redirect_uri(state);
    form.push(("redirect_uri", &ru));
    if let Some(r) = resource {
        form.push(("resource", r));
    }
    let mut req = state
        .http
        .post(token_endpoint)
        .timeout(HTTP_TIMEOUT)
        .header("content-type", "application/x-www-form-urlencoded")
        .body(form_body(&form));
    if let Some((sealed, kv)) =
        fluidbox_db::connection_client_secret_sealed(&state.pool, scope, conn.id)
            .await
            .map_err(|e| format!("client secret lookup failed: {e}"))?
    {
        let secret = sealer_ref
            .open(
                &sealed,
                kv,
                SealCtx::new(scope.tenant_id(), SealFamily::ConnectionClientSecret),
            )
            .await
            .map_err(|_| "client secret unseal failed")?;
        req = req.basic_auth(client_id, Some(secret));
    }
    let res = req
        .send()
        .await
        .map_err(|e| format!("token exchange failed: {e}"))?;
    let status = res.status();
    let v: Value = res.json().await.unwrap_or(Value::Null);
    if !status.is_success() {
        // The token endpoint's JSON is attacker-controlled: a malicious AS can put
        // the code, PKCE verifier, or client secret into the `error` value. Log
        // ONLY an allowlisted code + status + a bounded digest of the raw error
        // text — never the verbatim value (R3.4). The browser gets a generic line.
        let raw = v.get("error").map(ToString::to_string).unwrap_or_default();
        tracing::warn!(
            %status,
            oauth_error = known_oauth_error(v["error"].as_str().unwrap_or("")),
            detail = %crate::broker::msg_digest(&raw),
            "oauth callback: token exchange rejected"
        );
        return Err(
            "the authorization server rejected the token exchange — reconnect and try again".into(),
        );
    }
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
        .map_err(|e| format!("failed to seal refresh token: {e}"))?;

    // Serialize the activation against the refresh path (R3.2): acquire the SAME
    // per-connection in-process mutex + Postgres advisory lock `ensure_access_token`
    // uses, so a concurrent in-flight refresh rotating the OLD grant's token can
    // never clobber the NEW grant landing here (which would restore a superseded
    // grant). Held only across the activation write + cache update; released
    // BEFORE the photograph, which re-mints under its own lock (a nested acquire
    // of the same in-process mutex would deadlock).
    {
        let lock = {
            let mut locks = state.oauth_locks.lock().await;
            locks.entry(conn.id).or_default().clone()
        };
        let _guard = lock.lock().await;
        let mut tx = state
            .pool
            .begin()
            .await
            .map_err(|e| format!("oauth lock txn failed: {e}"))?;
        fluidbox_db::acquire_oauth_lock(&mut tx, conn.id)
            .await
            .map_err(|e| format!("oauth advisory lock failed: {e}"))?;
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
        )
        .await
        .map_err(|e| format!("activation failed: {e}"))?
        .ok_or("connection changed state during the exchange")?;
        // Commit (releasing the advisory lock) BEFORE touching the token cache:
        // a cache entry must never outlive a rolled-back activation. A failed or
        // AMBIGUOUS commit fails closed: the AS may already have invalidated the
        // rotated-away refresh token, so serving this access token while the DB
        // kept the dead grant would corrupt custody. Drop every cached generation
        // and refuse — the caller reconnects/retries.
        if let Err(e) = tx.commit().await {
            invalidate_access(state, conn.id).await;
            return Err(format!("could not persist OAuth custody — retry: {e}"));
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
            fluidbox_db::mark_connection_error(
                &state.pool,
                scope,
                conn.id,
                "MCP tool discovery failed after authorization — reconnect this connection",
            )
            .await
            .ok();
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
    let mut tx = state
        .pool
        .begin()
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
    let scope = fluidbox_db::TenantScope::assume(conn.tenant_id);
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
    let client_id = oauth
        .get("client_id")
        .and_then(Value::as_str)
        .ok_or("connection has no client identity — reconnect it")?;
    let resource = oauth.get("resource").and_then(Value::as_str);

    let mut form: Vec<(&str, &str)> = vec![
        ("grant_type", "refresh_token"),
        ("refresh_token", &refresh),
        ("client_id", client_id),
    ];
    if let Some(r) = resource {
        form.push(("resource", r));
    }
    let mut req = state
        .http
        .post(token_endpoint)
        .timeout(HTTP_TIMEOUT)
        .header("content-type", "application/x-www-form-urlencoded")
        .body(form_body(&form));
    if let Some((sealed_secret, cs_kv)) =
        fluidbox_db::connection_client_secret_sealed(&mut *db, scope, conn.id)
            .await
            .map_err(|e| format!("client secret lookup failed: {e}"))?
    {
        let secret = sealer_ref
            .open(
                &sealed_secret,
                cs_kv,
                SealCtx::new(conn.tenant_id, SealFamily::ConnectionClientSecret),
            )
            .await
            .map_err(|_| "client secret unseal failed")?;
        req = req.basic_auth(client_id, Some(secret));
    }
    let res = req
        .send()
        .await
        .map_err(|e| format!("token refresh failed: {e}"))?;
    let status = res.status();
    let v: Value = res.json().await.unwrap_or(Value::Null);
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

    #[tokio::test]
    async fn state_roundtrip_tamper_and_expiry() {
        let s = test_sealer();
        let cid = Uuid::now_v7();
        let tok = seal_state(&s, cid, "verifier-123").await.unwrap();
        let (got_cid, got_v) = open_state(&s, &tok).await.unwrap();
        assert_eq!(got_cid, cid);
        assert_eq!(got_v, "verifier-123");
        // Opaque: the verifier is not readable from the parameter.
        assert!(!tok.contains("verifier-123"));
        // Tampering breaks verification.
        let mut chars: Vec<char> = tok.chars().collect();
        let mid = chars.len() / 2;
        chars[mid] = if chars[mid] == 'A' { 'B' } else { 'A' };
        assert!(open_state(&s, &chars.into_iter().collect::<String>())
            .await
            .is_err());
        // Garbage and wrong-key states fail closed.
        assert!(open_state(&s, "not-base64!!").await.is_err());
        let other = Sealer::from_key_string(&"cd".repeat(32)).unwrap();
        assert!(open_state(&other, &tok).await.is_err());
        // Expired states are refused.
        let stale = {
            use base64::Engine;
            let payload = serde_json::json!({
                "c": cid, "v": "x", "x": Utc::now().timestamp() - 1,
            });
            base64::engine::general_purpose::URL_SAFE_NO_PAD
                .encode(s.seal_token(&payload.to_string()).await.unwrap())
        };
        let err = open_state(&s, &stale).await.unwrap_err();
        assert!(err.contains("too long"));
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
            "cimd", cimd_id, None, true, cimd_id, redirect
        ));
        // CIMD no longer presentable (e.g. the identity was minted before
        // the eligibility guard, from a loopback deployment) → stale.
        assert!(stored_identity_stale(
            "cimd", cimd_id, None, false, cimd_id, redirect
        ));
        // Public URL moved → the document URL no longer matches → stale.
        assert!(stored_identity_stale(
            "cimd",
            "http://127.0.0.1:8787/.well-known/fluidbox-client.json",
            None,
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
            cimd_id,
            redirect
        ));
        assert!(stored_identity_stale(
            "dcr",
            "dcr-1",
            Some("http://127.0.0.1:8787/v1/oauth/callback"),
            false,
            cimd_id,
            redirect
        ));
        assert!(!stored_identity_stale(
            "dcr", "dcr-1", None, false, cimd_id, redirect
        ));
        // Pre-registered identities are user-owned — never auto-stale.
        assert!(!stored_identity_stale(
            "preregistered",
            "pre-7",
            Some("https://old.example/cb"),
            false,
            cimd_id,
            redirect
        ));
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
}
