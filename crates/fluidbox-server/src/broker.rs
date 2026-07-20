//! The brokered-tool gateway's MCP side (design §8.3 class 2): the control
//! plane speaks MCP Streamable HTTP to remote servers so the sandbox never
//! has to — the sealed credential is unsealed here, used for one call, and
//! dropped. Fourth instance of the credential inversion (LLM facade, git
//! fetch, webhook verify, tool broker).
//!
//! Deliberately minimal client: JSON-RPC POSTs to the single MCP endpoint,
//! accepting both `application/json` and SSE-framed responses (the spec
//! requires clients to handle both). Stateless-first: `tools/*` is attempted
//! directly; if the server demands a session (pre-2026 revisions), one
//! `initialize` handshake runs and the call retries once — safe because a
//! session-required rejection means the tool never executed.

use crate::state::AppState;
use fluidbox_core::capability::{CapabilityServer, ToolSnapshot};
use futures::StreamExt;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::time::Duration;

const MCP_TIMEOUT: Duration = Duration::from_secs(30);
/// Protocol revision we offer at initialize; we echo whatever the server
/// negotiates on subsequent requests.
const OFFERED_PROTOCOL: &str = "2025-06-18";
/// Discovery pagination bound (tools beyond this are a config smell; the
/// per-server tool cap in fluidbox-core rejects them at validation anyway).
const MAX_LIST_PAGES: usize = 4;
/// Result payloads larger than this are replaced by a truncated text block
/// — the ledger stores only digests either way.
const MAX_RESULT_BYTES: usize = 256 * 1024;
/// Hard ceiling on an MCP response we will buffer: a server advertising a
/// Content-Length over this is refused BEFORE the body is read into memory
/// (R3.3), AND the decoded body is streamed into a buffer capped at the same
/// ceiling (D) so a chunked/compressed response without Content-Length cannot
/// buffer unboundedly. `cap_content` still truncates tool results after the fact,
/// and discovery re-validates the whole surface against fluidbox-core's 2 MiB
/// serialized ceiling.
const MAX_RESPONSE_BYTES: u64 = 8 * 1024 * 1024;

/// A resolved outbound credential: which header to set, its full value, and
/// — for OAuth connections — the connection whose access token can be
/// re-minted after a 401 (`None` = static credential; a 401 is terminal).
pub struct BrokeredAuth {
    pub header: String,
    pub value: String,
    pub oauth_connection: Option<uuid::Uuid>,
}

/// Compose the header VALUE from the connection's scheme and the sealed
/// raw secret: `Bearer` prefixes, `Basic` base64-encodes (the stored secret
/// is `email:token`), empty scheme sends the bare token (the Sentry shape).
pub fn compose_header_value(scheme: &str, secret: &str) -> String {
    use base64::Engine;
    match scheme {
        "Bearer" => format!("Bearer {secret}"),
        "Basic" => format!(
            "Basic {}",
            base64::engine::general_purpose::STANDARD.encode(secret)
        ),
        _ => secret.to_string(),
    }
}

/// RFC 7230 token charset, with headers the MCP transport itself owns
/// denylisted — a connection must not be able to smuggle protocol fields.
pub fn valid_header_name(name: &str) -> bool {
    const DENY: &[&str] = &[
        "host",
        "content-length",
        "content-type",
        "accept",
        "mcp-session-id",
        "mcp-protocol-version",
    ];
    !name.is_empty()
        && name.len() <= 64
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
        && !DENY.contains(&name.to_ascii_lowercase().as_str())
}

/// Resolve the auth header for a brokered server (frozen-RunSpec path): fetch
/// the embedded connection fresh, then defer to [`brokered_auth_for_conn`].
/// `Ok(None)` = the server declared no connection (credential-free legacy
/// bundle).
pub async fn brokered_auth(
    state: &AppState,
    scope: fluidbox_db::TenantScope,
    server: &CapabilityServer,
) -> Result<Option<BrokeredAuth>, String> {
    let CapabilityServer::Brokered {
        name,
        url,
        connection_id,
        ..
    } = server
    else {
        return Err("not a brokered server".into());
    };
    let Some(cid) = connection_id else {
        return Ok(None);
    };
    // Unfiltered read by design: the LEGACY broker path's authority comes from
    // the frozen RunSpec's embedded `connection_id`, never a request viewer — so
    // no owner-visibility filter applies. This path (a pre-Phase-C bundle) froze
    // no binding, so there is no generation/owner to recheck; the status read
    // below is the only live check. Phase C runs route through the binding path
    // ([`recheck_binding`] + [`call_tool_for_conn`]), never here.
    let conn = fluidbox_db::get_connection(&state.pool, scope, *cid)
        .await
        .map_err(|e| format!("connection lookup failed: {e}"))?
        .ok_or_else(|| format!("capability server '{name}': connection {cid} is missing"))?;
    brokered_auth_for_conn(state, scope, &conn, url)
        .await
        .map_err(|e| format!("capability server '{name}': {e}"))
}

/// Credential-resolution CORE, callable with an ALREADY-FETCHED connection row
/// and an explicit endpoint url — the single function serving the frozen-RunSpec
/// broker path ([`brokered_auth`]), snapshot discovery ([`discover_snapshot`]),
/// and (Task 6) binding resolution. Enforces the same audience binding (the
/// connection pins `base_url`, and its credential is only ever sent to URLs
/// under that base — our RFC-8707 equivalent), the same custom header/scheme
/// composition, and the same OAuth minting. `Ok(None)` = no credential to send
/// (`auth_kind = "none"`, a credentialless remote).
pub async fn brokered_auth_for_conn(
    state: &AppState,
    scope: fluidbox_db::TenantScope,
    conn: &fluidbox_db::IntegrationConnectionRow,
    url: &str,
) -> Result<Option<BrokeredAuth>, String> {
    if conn.status != "active" {
        return Err(format!(
            "connection {} is {} — reconnect it",
            conn.id, conn.status
        ));
    }
    if conn.provider != "mcp_http" {
        return Err(format!(
            "connection provider '{}' does not hold MCP credentials",
            conn.provider
        ));
    }
    let base = conn
        .metadata
        .get("base_url")
        .and_then(|v| v.as_str())
        .ok_or_else(|| format!("connection {} has no base_url — reconnect it", conn.id))?;
    if !url_within_base(url, base) {
        return Err(
            "url is outside the connection's base_url — refusing to send its credential (audience binding)".into(),
        );
    }
    // Credentialless remote (`auth_kind = "none"`): no header at all. MUST come
    // BEFORE the static branch, which would fail on the NULL sealed credential.
    if conn.auth_kind == "none" {
        return Ok(None);
    }
    if conn.auth_kind == "oauth" {
        let access = crate::oauth::ensure_access_token(state, conn).await?;
        return Ok(Some(BrokeredAuth {
            header: "authorization".into(),
            value: format!("Bearer {access}"),
            oauth_connection: Some(conn.id),
        }));
    }
    let sealer = state
        .sealer
        .as_ref()
        .ok_or("FLUIDBOX_CREDENTIAL_KEY not configured")?;
    let (sealed, kv) = fluidbox_db::connection_credential_sealed(&state.pool, scope, conn.id)
        .await
        .map_err(|e| format!("credential lookup failed: {e}"))?
        .ok_or("connection is not active (revoked or missing)")?;
    let token = sealer
        .open(
            &sealed,
            kv,
            crate::seal::SealCtx::new(
                scope.tenant_id(),
                crate::seal::SealFamily::ConnectionCredential,
            ),
        )
        .await
        .map_err(|e| e.to_string())?;
    let header = conn
        .metadata
        .get("header_name")
        .and_then(|v| v.as_str())
        .unwrap_or("authorization")
        .to_string();
    let scheme = conn
        .metadata
        .get("scheme")
        .and_then(|v| v.as_str())
        .unwrap_or("Bearer");
    Ok(Some(BrokeredAuth {
        header,
        value: compose_header_value(scheme, &token),
        oauth_connection: None,
    }))
}

/// Revocation recheck for a CONNECTION-authority run resource binding (design
/// `:705-723`, invariant 21): fresh-read the connection and fail closed on
/// anything that would let a stale or revoked authority still execute. Called
/// by every credentialed consumer — the brokered MCP call, the workspace fetch,
/// and the GitHub result publish — IMMEDIATELY before secret access, so a
/// revoke takes effect on in-flight runs within one call.
///
/// Refuses when: the connection is non-active; its `authorization_generation`
/// no longer equals the generation the run froze (it was reauthorized to a new
/// account/audience since — a rotation within the same generation is fine);
/// the binding is user-owned and the owner's tenant membership is not active
/// (UNCONDITIONAL for user-owned — design `:713-716`); or the binding does not
/// belong to `scope`'s tenant (belt-and-braces). Returns the freshly-read row so
/// the caller sends the credential without a second lookup.
///
/// NOT this function's job: `subscription_secret` authorities (the delivery
/// worker compares the subscription row's generation itself) and the mechanical
/// `resource_scope` match for workspace/publish slots (the consumer enforces it
/// — the mcp scope is enforced by the upstream grant, design `:718-720`).
pub async fn recheck_binding(
    state: &AppState,
    scope: fluidbox_db::TenantScope,
    binding: &fluidbox_db::RunResourceBindingRow,
) -> Result<fluidbox_db::IntegrationConnectionRow, String> {
    recheck_binding_pool(&state.pool, scope, binding).await
}

/// Revalidate the RUN's invoking authority (design `:716-717`), which is
/// ORTHOGONAL to the binding's own connection/secret authority: a run bound to a
/// still-valid org connection may nonetheless have been started by a user since
/// deactivated, or by a subscription since disabled/deleted. Applied at the same
/// seam as [`recheck_binding`] (and by the signed-webhook publish path, which
/// carries no connection authority to recheck) so EVERY credentialed use fails
/// closed on a revoked invoker.
///
/// The invoking principal is read straight off the binding row: `create_run`
/// stamps `resolved_by_principal_id` with the invoking USER's id for `user` runs,
/// the invoking TRIGGER TOKEN's id for `trigger` runs (E1/design :741/:748), and
/// the acting SUBSCRIPTION's id for `schedule`/`webhook` runs (run_service.rs), so
/// no session/trigger-context lookup is needed — the minimal correct source.
/// `operator` (break-glass admin) and `system` (worker) hold no revocable
/// membership/subscription and pass; any OTHER kind fails closed (E2).
pub(crate) async fn recheck_invoking_authority(
    pool: &sqlx::PgPool,
    scope: fluidbox_db::TenantScope,
    principal_kind: &str,
    principal_id: Option<&str>,
) -> Result<(), String> {
    match principal_kind {
        "user" => {
            let uid = principal_id
                .and_then(|s| s.parse::<uuid::Uuid>().ok())
                .ok_or("run's invoking user id is missing or malformed")?;
            let active = fluidbox_db::identity::get_membership_by_user(pool, scope, uid)
                .await
                .map_err(|e| format!("invoking-user membership lookup failed: {e}"))?
                .is_some_and(|m| m.status == "active");
            if !active {
                return Err(
                    "the run's invoking user is no longer an active member — its authority is revoked".into(),
                );
            }
            Ok(())
        }
        // A trigger run froze the exact TOKEN as its principal: the token row must
        // still be a live trigger token AND its (immutable-FK) subscription must
        // still exist + be enabled — so a revoked/expired token fails closed, not
        // just a disabled subscription (E1).
        "trigger" => {
            let tid = principal_id
                .and_then(|s| s.parse::<uuid::Uuid>().ok())
                .ok_or("run's invoking trigger token id is missing or malformed")?;
            let active = fluidbox_db::trigger_token_active(pool, scope, tid)
                .await
                .map_err(|e| format!("invoking-token lookup failed: {e}"))?;
            if !active {
                return Err(
                    "the run's invoking trigger token was revoked or expired, or its subscription \
                     was disabled — its authority is revoked"
                        .into(),
                );
            }
            Ok(())
        }
        "schedule" | "webhook" => {
            let sid = principal_id
                .and_then(|s| s.parse::<uuid::Uuid>().ok())
                .ok_or("run's invoking subscription id is missing or malformed")?;
            let sub = fluidbox_db::get_trigger_subscription(pool, scope, sid)
                .await
                .map_err(|e| format!("invoking-subscription lookup failed: {e}"))?
                .ok_or(
                    "the run's invoking subscription no longer exists — its authority is revoked",
                )?;
            if !sub.enabled {
                return Err(
                    "the run's invoking subscription is disabled — its authority is revoked".into(),
                );
            }
            Ok(())
        }
        // operator / system: no revocable membership or subscription to check.
        "operator" | "system" => Ok(()),
        // Fail closed on any unrecognized principal kind (E2) — never pass an
        // authority we cannot revalidate.
        other => Err(format!(
            "run has an unrecognized invoking principal kind '{other}' — refusing"
        )),
    }
}

/// Pool-based core of [`recheck_binding`] — the public fn (fixed to take
/// `&AppState` by the Phase C plan) only unwraps `state.pool`. Split out so the
/// matrix DB tests drive it without an `AppState` (matching `bindings.rs`).
async fn recheck_binding_pool(
    pool: &sqlx::PgPool,
    scope: fluidbox_db::TenantScope,
    binding: &fluidbox_db::RunResourceBindingRow,
) -> Result<fluidbox_db::IntegrationConnectionRow, String> {
    // Tenant equality (belt-and-braces): the scoped reads below already pin the
    // tenant, but a binding row handed in from elsewhere must match it.
    if binding.tenant_id != scope.tenant_id() {
        return Err("run resource binding belongs to a different tenant".into());
    }
    // R2.2: the run's INVOKING authority must still be valid — orthogonal to the
    // connection authority below and checked before any secret access.
    recheck_invoking_authority(
        pool,
        scope,
        &binding.resolved_by_principal_kind,
        binding.resolved_by_principal_id.as_deref(),
    )
    .await?;
    let cid = binding
        .connection_id
        .ok_or("run resource binding has no connection authority to recheck")?;
    let expected_generation = binding
        .authority_generation
        .ok_or("connection binding froze no authorization generation")?;
    let conn = fluidbox_db::get_connection(pool, scope, cid)
        .await
        .map_err(|e| format!("connection lookup failed: {e}"))?
        .ok_or_else(|| format!("connection {cid} is missing"))?;
    if conn.status != "active" {
        return Err(format!(
            "connection {} is {} — reconnect it",
            conn.id, conn.status
        ));
    }
    if conn.authorization_generation != expected_generation {
        return Err(format!(
            "connection {} was reauthorized after this run started — its binding is stale",
            conn.id
        ));
    }
    // R1.4(a): the connection's owner fields are immutable in v1, so the fresh
    // row MUST still match the owner the binding froze. A divergence is
    // corruption (or a would-be ownership swap) — fail closed rather than serve
    // a credential under a different owner than the run authorized.
    if conn.owner_type != binding.connection_owner_type.as_deref().unwrap_or_default()
        || conn.owner_user_id != binding.connection_owner_user_id
    {
        return Err(format!(
            "connection {} ownership changed since this run bound it — its binding is stale",
            conn.id
        ));
    }
    // User-owned connections: the owner must still hold an active membership —
    // unconditionally, never "where applicable" (design `:713-716`). A missing
    // membership row fails closed exactly like a deactivated one.
    if binding.connection_owner_type.as_deref() == Some("user") {
        let owner = binding
            .connection_owner_user_id
            .ok_or("user-owned binding is missing its owner id")?;
        let active = fluidbox_db::identity::get_membership_by_user(pool, scope, owner)
            .await
            .map_err(|e| format!("owner membership lookup failed: {e}"))?
            .is_some_and(|m| m.status == "active");
        if !active {
            return Err("the connection owner's tenant membership is not active".into());
        }
    }
    Ok(conn)
}

/// scheme + host + port must match; the base path must prefix the url path
/// at a `/` boundary. Case-insensitive host; default ports normalized by
/// the Url parser.
pub fn url_within_base(url: &str, base: &str) -> bool {
    let (Ok(u), Ok(b)) = (reqwest::Url::parse(url), reqwest::Url::parse(base)) else {
        return false;
    };
    if u.scheme() != b.scheme()
        || !u
            .host_str()
            .unwrap_or("")
            .eq_ignore_ascii_case(b.host_str().unwrap_or("?"))
        || u.port_or_known_default() != b.port_or_known_default()
    {
        return false;
    }
    let bp = b.path().trim_end_matches('/');
    if bp.is_empty() {
        return true;
    }
    let up = u.path();
    up == bp || up.starts_with(&format!("{bp}/"))
}

// ─── Minimal MCP Streamable HTTP client ───────────────────────────────────

/// Errors where HTTP 401 stays distinguishable: an OAuth connection may
/// re-mint its access token and retry exactly once (the 401 happened at the
/// auth layer, so the tool provably never executed — the same reasoning
/// that makes the session-handshake retry safe).
enum CallErr {
    Unauthorized,
    Other(String),
}

impl CallErr {
    fn into_msg(self) -> String {
        match self {
            CallErr::Unauthorized => "mcp server rejected the credential (HTTP 401)".into(),
            CallErr::Other(m) => m,
        }
    }
}

impl From<String> for CallErr {
    fn from(m: String) -> Self {
        CallErr::Other(m)
    }
}

impl From<&str> for CallErr {
    fn from(m: &str) -> Self {
        CallErr::Other(m.into())
    }
}

struct McpSession {
    session_id: Option<String>,
    protocol_version: Option<String>,
}

async fn post_rpc(
    state: &AppState,
    url: &str,
    auth: Option<&BrokeredAuth>,
    session: Option<&McpSession>,
    body: &Value,
) -> Result<(reqwest::StatusCode, Option<String>, Value), String> {
    let mut req = state
        .http
        .post(url)
        .timeout(MCP_TIMEOUT)
        .header("content-type", "application/json")
        .header("accept", "application/json, text/event-stream");
    if let Some(a) = auth {
        req = req.header(a.header.as_str(), a.value.as_str());
    }
    if let Some(s) = session {
        if let Some(sid) = &s.session_id {
            req = req.header("mcp-session-id", sid);
        }
        if let Some(v) = &s.protocol_version {
            req = req.header("mcp-protocol-version", v);
        }
    }
    let res = req
        .json(body)
        .send()
        .await
        .map_err(|e| format!("mcp server unreachable: {e}"))?;
    let status = res.status();
    let session_id = res
        .headers()
        .get("mcp-session-id")
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    let is_sse = res
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.contains("event-stream"))
        .unwrap_or(false);
    // R3.3: refuse an over-large advertised body BEFORE buffering it in memory.
    if let Some(len) = res.content_length() {
        if len > MAX_RESPONSE_BYTES {
            return Err(format!(
                "mcp response advertises {len} bytes, over the {MAX_RESPONSE_BYTES}-byte cap"
            ));
        }
    }
    // The Content-Length pre-check only bounds a body that ADVERTISES its length;
    // a chunked or compressed response slips it and `text()` would then buffer
    // unboundedly (D). Read the DECODED body through the byte stream and abort the
    // moment the accumulated size would exceed the same hard cap. The per-call
    // tools/call result path still truncates via `cap_content` after this.
    let mut stream = res.bytes_stream();
    let mut buf: Vec<u8> = Vec::new();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|e| format!("mcp response unreadable: {e}"))?;
        if buf.len() + chunk.len() > MAX_RESPONSE_BYTES as usize {
            return Err(format!(
                "mcp response exceeds the {MAX_RESPONSE_BYTES}-byte cap while streaming"
            ));
        }
        buf.extend_from_slice(&chunk);
    }
    let text = String::from_utf8_lossy(&buf).into_owned();
    let value = if text.trim().is_empty() {
        Value::Null
    } else if is_sse {
        parse_sse_json(&text, body.get("id")).unwrap_or(Value::Null)
    } else {
        serde_json::from_str(&text).unwrap_or(Value::Null)
    };
    Ok((status, session_id, value))
}

/// Extract the JSON-RPC response object from an SSE-framed body: scan
/// `data:` lines for the message whose id matches (or the last parseable
/// message when the request carried no id).
pub fn parse_sse_json(body: &str, want_id: Option<&Value>) -> Option<Value> {
    let mut last = None;
    for line in body.lines() {
        let Some(data) = line.trim().strip_prefix("data:") else {
            continue;
        };
        let data = data.trim();
        if data.is_empty() {
            continue;
        }
        let Ok(v) = serde_json::from_str::<Value>(data) else {
            continue;
        };
        match want_id {
            Some(id) if v.get("id") == Some(id) => return Some(v),
            _ => last = Some(v),
        }
    }
    last
}

/// One JSON-RPC call with the stateless-first strategy. `handshake_retry`
/// is only safe for calls that a session-required rejection provably did
/// not execute (the server refused them before dispatch).
async fn rpc(
    state: &AppState,
    url: &str,
    auth: Option<&BrokeredAuth>,
    method: &str,
    params: Value,
) -> Result<Value, CallErr> {
    let body = json!({ "jsonrpc": "2.0", "id": 1, "method": method, "params": params });
    let (status, _, value) = post_rpc(state, url, auth, None, &body).await?;
    if status == reqwest::StatusCode::UNAUTHORIZED {
        return Err(CallErr::Unauthorized);
    }
    if status.is_success() && value.get("error").is_none() && !value.is_null() {
        return unwrap_result(value, method).map_err(Into::into);
    }
    // Pre-2026 servers may demand an initialize handshake / session. Those
    // rejections happen before the method dispatches, so one retry is safe.
    let session_needed = status == reqwest::StatusCode::BAD_REQUEST
        || status == reqwest::StatusCode::NOT_FOUND
        || value
            .get("error")
            .and_then(|e| e.get("message"))
            .and_then(|m| m.as_str())
            .map(|m| {
                let m = m.to_ascii_lowercase();
                m.contains("initial") || m.contains("session")
            })
            .unwrap_or(false);
    if !session_needed {
        return unwrap_result(rpc_error_to_err(status, value, method)?, method).map_err(Into::into);
    }
    let session = handshake(state, url, auth).await?;
    let (status, _, value) = post_rpc(state, url, auth, Some(&session), &body).await?;
    if status == reqwest::StatusCode::UNAUTHORIZED {
        return Err(CallErr::Unauthorized);
    }
    if !status.is_success() {
        return Err(CallErr::Other(format!(
            "mcp {method} returned HTTP {status}"
        )));
    }
    unwrap_result(rpc_error_to_err(status, value, method)?, method).map_err(Into::into)
}

/// A short, non-reversible fingerprint of an UNTRUSTED upstream error message
/// (C). A malicious MCP server can echo the bearer we just sent inside its
/// JSON-RPC error message; that string must never leave the broker verbatim (it
/// would flow into logs, the connection's persisted `oauth.error`, and the
/// dashboard). We surface method + HTTP status + JSON-RPC code + this digest so
/// an operator can still correlate repeated failures without the bytes. Shared
/// with `oauth.rs`, whose AS-error log boundary needs the identical treatment
/// (an authorization server can echo the sealed state/code/verifier/secret).
pub(crate) fn msg_digest(msg: &str) -> String {
    format!(
        "sha256:{}",
        hex::encode(&Sha256::digest(msg.as_bytes())[..8])
    )
}

fn rpc_error_to_err(
    status: reqwest::StatusCode,
    value: Value,
    method: &str,
) -> Result<Value, String> {
    if let Some(err) = value.get("error") {
        let code = err.get("code").and_then(|c| c.as_i64()).unwrap_or(0);
        // The upstream message is untrusted — surface only its digest (C).
        let digest = err
            .get("message")
            .and_then(|m| m.as_str())
            .map(msg_digest)
            .unwrap_or_else(|| "none".into());
        return Err(format!(
            "mcp {method} failed (HTTP {status}, code {code}, msg {digest})"
        ));
    }
    if !status.is_success() {
        return Err(format!("mcp {method} returned HTTP {status}"));
    }
    Ok(value)
}

fn unwrap_result(value: Value, method: &str) -> Result<Value, String> {
    if let Some(err) = value.get("error") {
        let code = err.get("code").and_then(|c| c.as_i64()).unwrap_or(0);
        // The upstream message is untrusted — surface only its digest (C).
        let digest = err
            .get("message")
            .and_then(|m| m.as_str())
            .map(msg_digest)
            .unwrap_or_else(|| "none".into());
        return Err(format!("mcp {method} failed (code {code}, msg {digest})"));
    }
    value
        .get("result")
        .cloned()
        .ok_or_else(|| format!("mcp {method} returned no result"))
}

async fn handshake(
    state: &AppState,
    url: &str,
    auth: Option<&BrokeredAuth>,
) -> Result<McpSession, CallErr> {
    let body = json!({
        "jsonrpc": "2.0", "id": 0, "method": "initialize",
        "params": {
            "protocolVersion": OFFERED_PROTOCOL,
            "capabilities": {},
            "clientInfo": { "name": "fluidbox-broker", "version": env!("CARGO_PKG_VERSION") },
        }
    });
    let (status, session_id, value) = post_rpc(state, url, auth, None, &body).await?;
    if status == reqwest::StatusCode::UNAUTHORIZED {
        return Err(CallErr::Unauthorized);
    }
    if !status.is_success() {
        return Err(CallErr::Other(format!(
            "mcp initialize returned HTTP {status}"
        )));
    }
    let result = unwrap_result(value, "initialize")?;
    let session = McpSession {
        session_id,
        protocol_version: result
            .get("protocolVersion")
            .and_then(|v| v.as_str())
            .map(str::to_string),
    };
    // `notifications/initialized` only matters once a session was established;
    // fire-and-forget per spec (servers answer 202).
    if session.session_id.is_some() {
        let note = json!({ "jsonrpc": "2.0", "method": "notifications/initialized" });
        let _ = post_rpc(state, url, auth, Some(&session), &note).await;
    }
    Ok(session)
}

// ─── The two operations fluidbox performs ─────────────────────────────────

/// Map one `tools/list` result page into snapshot shape (camelCase
/// `inputSchema` → snake `input_schema`; annotations kept verbatim), appending
/// to `out`, and return the page's `nextCursor` (absent = last page). Shared by
/// the stateless registration/probe path and the forced-negotiation snapshot
/// discovery so both map identically.
fn map_tools_page(result: &Value, out: &mut Vec<ToolSnapshot>) -> Result<Option<String>, CallErr> {
    for t in result
        .get("tools")
        .and_then(|v| v.as_array())
        .ok_or("mcp tools/list result has no tools array")?
    {
        out.push(ToolSnapshot {
            name: t
                .get("name")
                .and_then(|v| v.as_str())
                .ok_or("mcp tools/list entry has no name")?
                .to_string(),
            description: t
                .get("description")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string(),
            input_schema: t
                .get("inputSchema")
                .cloned()
                .unwrap_or_else(|| json!({ "type": "object" })),
            annotations: t.get("annotations").cloned(),
        });
    }
    Ok(result
        .get("nextCursor")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .map(str::to_string))
}

/// Registration-time discovery — THE (stateless-first) photograph for the
/// legacy bundle probe path. Paginates tools/list; on hitting the page cap with
/// a cursor still pending it freezes what it has (acceptable for the probe/BYO
/// preview — the snapshot path below is stricter). Validation happens in
/// fluidbox-core after this returns.
async fn discover_tools(
    state: &AppState,
    url: &str,
    auth: Option<&BrokeredAuth>,
) -> Result<Vec<ToolSnapshot>, CallErr> {
    let mut tools = Vec::new();
    let mut cursor: Option<String> = None;
    for _ in 0..MAX_LIST_PAGES {
        let params = match &cursor {
            Some(c) => json!({ "cursor": c }),
            None => json!({}),
        };
        let result = rpc(state, url, auth, "tools/list", params).await?;
        cursor = map_tools_page(&result, &mut tools)?;
        if cursor.is_none() {
            break;
        }
    }
    if tools.is_empty() {
        return Err(CallErr::Other("mcp server advertises no tools".into()));
    }
    Ok(tools)
}

/// One `tools/list` page carrying an ESTABLISHED session (the negotiated
/// protocol-version + any session-id headers ride along) — the discovery
/// counterpart to the stateless-first `rpc`. No handshake retry: discovery
/// already initialized.
async fn list_tools_page_session(
    state: &AppState,
    url: &str,
    auth: Option<&BrokeredAuth>,
    session: &McpSession,
    cursor: Option<&str>,
) -> Result<Value, CallErr> {
    let params = match cursor {
        Some(c) => json!({ "cursor": c }),
        None => json!({}),
    };
    let body = json!({ "jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": params });
    let (status, _, value) = post_rpc(state, url, auth, Some(session), &body).await?;
    if status == reqwest::StatusCode::UNAUTHORIZED {
        return Err(CallErr::Unauthorized);
    }
    if !status.is_success() {
        return Err(CallErr::Other(format!(
            "mcp tools/list returned HTTP {status}"
        )));
    }
    unwrap_result(rpc_error_to_err(status, value, "tools/list")?, "tools/list").map_err(Into::into)
}

/// The forced-negotiation photograph (design :298-343; Phase C). UNLIKE the
/// stateless-first paths above, discovery ALWAYS `initialize`s first so it can
/// record a REAL negotiated protocol version — the whole point of a snapshot
/// (survey A §2e: the legacy photograph negotiates none and cannot be trusted).
/// Fails closed when the server negotiates no/empty `protocolVersion`, and —
/// per design :1282-1283 — when a `nextCursor` still remains after the page cap
/// (freeze the whole surface or none, never a partial list). The remote list is
/// untrusted input: it passes core's IDENTICAL `validate_tools` screen (charset,
/// poison-screen, caps) before it can become a snapshot.
pub async fn discover_snapshot(
    state: &AppState,
    scope: fluidbox_db::TenantScope,
    conn: &fluidbox_db::IntegrationConnectionRow,
    endpoint_url: &str,
) -> anyhow::Result<(String, Vec<ToolSnapshot>)> {
    let auth = brokered_auth_for_conn(state, scope, conn, endpoint_url)
        .await
        .map_err(|e| anyhow::anyhow!(e))?;
    // Always initialize first, and require a negotiated protocol version.
    let session = handshake(state, endpoint_url, auth.as_ref())
        .await
        .map_err(|e| anyhow::anyhow!(e.into_msg()))?;
    let protocol_version = session
        .protocol_version
        .clone()
        .filter(|v| !v.trim().is_empty())
        .ok_or_else(|| {
            anyhow::anyhow!(
                "mcp server negotiated no protocolVersion at initialize — cannot record a trustworthy snapshot"
            )
        })?;
    // Paginate tools/list WITH the session; fail (not freeze) on a leftover cursor.
    let mut tools = Vec::new();
    let mut cursor: Option<String> = None;
    let mut complete = false;
    for _ in 0..MAX_LIST_PAGES {
        let result = list_tools_page_session(
            state,
            endpoint_url,
            auth.as_ref(),
            &session,
            cursor.as_deref(),
        )
        .await
        .map_err(|e| anyhow::anyhow!(e.into_msg()))?;
        cursor = map_tools_page(&result, &mut tools).map_err(|e| anyhow::anyhow!(e.into_msg()))?;
        if cursor.is_none() {
            complete = true;
            break;
        }
    }
    if !complete {
        anyhow::bail!(
            "mcp server advertises more tools than the discovery page cap — refusing to freeze a partial snapshot"
        );
    }
    fluidbox_core::capability::validate_tools("mcp connection", &tools)
        .map_err(|e| anyhow::anyhow!("discovered tool snapshot failed validation: {e}"))?;
    Ok((protocol_version, tools))
}

/// One brokered tool execution. Returns (content, is_error) from the MCP
/// result. At-least-once under network failure by design — the caller
/// ledgers every attempt; we never blind-retry after a request was sent.
async fn call_tool(
    state: &AppState,
    url: &str,
    auth: Option<&BrokeredAuth>,
    tool: &str,
    arguments: &Value,
) -> Result<(Value, bool), CallErr> {
    let result = rpc(
        state,
        url,
        auth,
        "tools/call",
        json!({ "name": tool, "arguments": arguments }),
    )
    .await?;
    let is_error = result
        .get("isError")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let content = result.get("content").cloned().unwrap_or(json!([]));
    Ok((cap_content(content), is_error))
}

/// Reactive-401 recovery, OAuth connections only: drop the cached access
/// token and mint a fresh one. A static credential that 401s is terminal —
/// there is nothing to refresh.
async fn reauth_after_401(
    state: &AppState,
    scope: fluidbox_db::TenantScope,
    server: &CapabilityServer,
    auth: Option<BrokeredAuth>,
) -> Result<Option<BrokeredAuth>, String> {
    let Some(cid) = auth.as_ref().and_then(|a| a.oauth_connection) else {
        return Err("mcp server rejected the credential (HTTP 401)".into());
    };
    crate::oauth::invalidate_access(state, cid).await;
    brokered_auth(state, scope, server).await
}

fn server_url(server: &CapabilityServer) -> Result<&str, String> {
    match server {
        CapabilityServer::Brokered { url, .. } => Ok(url),
        _ => Err("not a brokered server".into()),
    }
}

/// Execute one brokered tool with credential resolution + the single
/// reactive-401 retry (safe: a 401 at the auth layer proves the tool never
/// executed). This is the broker's public execution surface.
pub async fn call_tool_auth(
    state: &AppState,
    scope: fluidbox_db::TenantScope,
    server: &CapabilityServer,
    tool: &str,
    arguments: &Value,
) -> Result<(Value, bool), String> {
    let url = server_url(server)?;
    let auth = brokered_auth(state, scope, server).await?;
    match call_tool(state, url, auth.as_ref(), tool, arguments).await {
        Err(CallErr::Unauthorized) => {
            let auth = reauth_after_401(state, scope, server, auth).await?;
            call_tool(state, url, auth.as_ref(), tool, arguments)
                .await
                .map_err(CallErr::into_msg)
        }
        r => r.map_err(CallErr::into_msg),
    }
}

/// Execute one brokered tool against a run resource binding's connection (the
/// Phase C path). The caller has ALREADY run [`recheck_binding`] on this exact
/// connection immediately before — so the credential resolved here rides an
/// authority just verified live (status + generation + owner + invoker). The
/// counterpart to [`call_tool_auth`], but the credential comes from a connection
/// row + an explicit endpoint (the binding's frozen surface url) rather than a
/// `CapabilityServer::Brokered`. Same single reactive-401 retry: OAuth re-mints
/// once (a 401 proves the tool never executed); a static credential is terminal.
///
/// R2.5 / invariant 9: the retry is a SECOND upstream call, so it RE-runs
/// [`recheck_binding`] before re-minting — a revoke/reauthorize/deactivate that
/// lands between the first call and the 401 fails the retry closed. It re-mints
/// against the FRESH connection row the recheck returns.
pub async fn call_tool_for_conn(
    state: &AppState,
    scope: fluidbox_db::TenantScope,
    conn: &fluidbox_db::IntegrationConnectionRow,
    url: &str,
    tool: &str,
    arguments: &Value,
    binding: &fluidbox_db::RunResourceBindingRow,
) -> Result<(Value, bool), String> {
    let auth = brokered_auth_for_conn(state, scope, conn, url).await?;
    match call_tool(state, url, auth.as_ref(), tool, arguments).await {
        Err(CallErr::Unauthorized) => {
            let fresh = recheck_binding(state, scope, binding).await?;
            let auth = reauth_after_401_conn(state, scope, &fresh, url, auth).await?;
            call_tool(state, url, auth.as_ref(), tool, arguments)
                .await
                .map_err(CallErr::into_msg)
        }
        r => r.map_err(CallErr::into_msg),
    }
}

/// Reactive-401 recovery for the binding path — OAuth connections only, re-minting
/// against the SAME connection + endpoint just rechecked. Mirrors
/// [`reauth_after_401`] but resolves via [`brokered_auth_for_conn`] (no
/// `CapabilityServer` in hand). A static credential that 401s is terminal.
async fn reauth_after_401_conn(
    state: &AppState,
    scope: fluidbox_db::TenantScope,
    conn: &fluidbox_db::IntegrationConnectionRow,
    url: &str,
    auth: Option<BrokeredAuth>,
) -> Result<Option<BrokeredAuth>, String> {
    let Some(cid) = auth.as_ref().and_then(|a| a.oauth_connection) else {
        return Err("mcp server rejected the credential (HTTP 401)".into());
    };
    crate::oauth::invalidate_access(state, cid).await;
    brokered_auth_for_conn(state, scope, conn, url).await
}

/// Oversized results are replaced by a truncated text block so a hostile or
/// chatty server can't balloon the runner/context; the ledger stores only a
/// digest either way.
fn cap_content(content: Value) -> Value {
    let serialized = content.to_string();
    if serialized.len() <= MAX_RESULT_BYTES {
        return content;
    }
    let text: String = content
        .as_array()
        .map(|blocks| {
            blocks
                .iter()
                .filter_map(|b| b.get("text").and_then(|t| t.as_str()))
                .collect::<Vec<_>>()
                .join("\n")
        })
        .unwrap_or(serialized);
    let truncated: String = text.chars().take(MAX_RESULT_BYTES / 4).collect();
    json!([{ "type": "text", "text": format!("{truncated}\n… (result truncated by fluidbox broker)") }])
}

/// The three outcomes of a NON-COMMITTING, credential-free probe of a remote
/// MCP endpoint. `Unauthorized` (a clean 401) is a *signal* the server wants
/// auth — the wizard branches on it; `Unreachable` is a genuine error. This
/// distinction is exactly why the probe rides the private `discover_tools`,
/// which surfaces `CallErr::Unauthorized` rather than collapsing a 401 into an
/// opaque credential-rejection message.
pub enum ProbeOutcome {
    /// Authless server — these tools are for DISPLAY only, never persisted;
    /// the authoritative photograph still happens at connect.
    Tools(Vec<ToolSnapshot>),
    /// The server answered 401 — it wants a credential (api_key or oauth).
    Unauthorized,
    /// Not reachable / not a well-behaved MCP endpoint (message for `notes`).
    Unreachable(String),
}

/// Credential-free discovery for the pre-connect probe. Persists nothing and
/// sends no secret. Reuses all of `discover_tools`' paging/SSE/handshake-retry
/// logic; bounded by `MCP_TIMEOUT` per request.
pub async fn probe_tools(state: &AppState, url: &str) -> ProbeOutcome {
    match discover_tools(state, url, None).await {
        Ok(tools) => ProbeOutcome::Tools(tools),
        Err(CallErr::Unauthorized) => ProbeOutcome::Unauthorized,
        Err(CallErr::Other(m)) => ProbeOutcome::Unreachable(m),
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn upstream_error_message_never_leaks_verbatim() {
        // A malicious server echoes the bearer it just received into its error
        // message. rpc_error_to_err / unwrap_result must surface method + code +
        // a digest — NEVER the token-shaped substring (C).
        let secret = "sk-live-abc123SECRETtoken";
        let value = json!({
            "jsonrpc": "2.0", "id": 1,
            "error": { "code": -32000, "message": format!("bad bearer {secret} rejected") }
        });
        let e = rpc_error_to_err(
            reqwest::StatusCode::BAD_REQUEST,
            value.clone(),
            "tools/list",
        )
        .unwrap_err();
        assert!(
            !e.contains(secret),
            "sanitized rpc error leaked the token: {e}"
        );
        assert!(
            e.contains("code -32000") && e.contains("tools/list") && e.contains("sha256:"),
            "sanitized rpc error dropped method/code/digest: {e}"
        );
        let e2 = unwrap_result(value, "tools/call").unwrap_err();
        assert!(
            !e2.contains(secret),
            "sanitized unwrap error leaked the token: {e2}"
        );
        assert!(
            e2.contains("code -32000") && e2.contains("sha256:"),
            "sanitized unwrap error dropped code/digest: {e2}"
        );
    }

    #[test]
    fn sse_framed_responses_parse_by_id() {
        let body = "event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":9,\"result\":{\"x\":1}}\n\n\
                    data: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"tools\":[]}}\n\n";
        let v = parse_sse_json(body, Some(&serde_json::json!(1))).unwrap();
        assert_eq!(v["result"]["tools"], serde_json::json!([]));
        // No id preference → last parseable message.
        let v = parse_sse_json(body, None).unwrap();
        assert_eq!(v["id"], 1);
        // Junk and empty data lines are skipped.
        assert!(parse_sse_json("data: not-json\n\n", None).is_none());
        assert!(parse_sse_json(": comment\n\n", None).is_none());
    }

    #[test]
    fn audience_binding_is_scheme_host_port_and_path_prefix() {
        let ok = |u: &str, b: &str| assert!(url_within_base(u, b), "{u} within {b}");
        let no = |u: &str, b: &str| assert!(!url_within_base(u, b), "{u} NOT within {b}");
        ok("https://mcp.example.test/mcp", "https://mcp.example.test");
        ok("https://mcp.example.test/mcp", "https://mcp.example.test/");
        ok(
            "https://MCP.example.test/mcp/sub",
            "https://mcp.example.test/mcp",
        );
        ok(
            "https://mcp.example.test:443/mcp",
            "https://mcp.example.test",
        );
        ok("http://127.0.0.1:8899/mcp", "http://127.0.0.1:8899");
        no("https://evil.test/mcp", "https://mcp.example.test");
        no("http://mcp.example.test/mcp", "https://mcp.example.test"); // scheme downgrade
        no(
            "https://mcp.example.test:8443/mcp",
            "https://mcp.example.test",
        );
        no(
            "https://mcp.example.test/mcpx",
            "https://mcp.example.test/mcp",
        ); // path boundary
        no(
            "https://mcp.example.test.evil.test/mcp",
            "https://mcp.example.test",
        );
        no("not a url", "https://mcp.example.test");
    }

    #[test]
    fn header_values_compose_per_scheme() {
        assert_eq!(compose_header_value("Bearer", "tok"), "Bearer tok");
        // Basic base64-encodes the stored email:token composite.
        assert_eq!(
            compose_header_value("Basic", "a@b.c:tok"),
            format!("Basic {}", {
                use base64::Engine;
                base64::engine::general_purpose::STANDARD.encode("a@b.c:tok")
            })
        );
        // Empty scheme = the bare token (Sentry's custom-header shape).
        assert_eq!(compose_header_value("", "raw-token"), "raw-token");
    }

    #[test]
    fn header_names_validate_and_denylist_protocol_fields() {
        assert!(valid_header_name("authorization"));
        assert!(valid_header_name("Sentry-Bearer"));
        assert!(valid_header_name("x-api-key"));
        assert!(!valid_header_name(""));
        assert!(!valid_header_name("bad header"));
        assert!(!valid_header_name("bad:header"));
        assert!(!valid_header_name("Content-Type"));
        assert!(!valid_header_name("mcp-session-id"));
        assert!(!valid_header_name("Host"));
        assert!(!valid_header_name(&"x".repeat(65)));
    }

    #[test]
    fn oversized_content_is_capped_to_a_text_block() {
        let small = serde_json::json!([{ "type": "text", "text": "ok" }]);
        assert_eq!(cap_content(small.clone()), small);
        let big = serde_json::json!([{ "type": "text", "text": "x".repeat(MAX_RESULT_BYTES + 1) }]);
        let capped = cap_content(big);
        let s = capped.to_string();
        assert!(s.len() < MAX_RESULT_BYTES);
        assert!(s.contains("truncated by fluidbox broker"));
    }

    // ── recheck_binding matrix (real Neon; self-skips when DATABASE_URL unset) ──
    //
    // Drives the pool-based core with directly-constructed binding rows pointed
    // at real seeded connections + memberships: the happy paths pass, and each
    // single revocation-recheck violation refuses. Children-first cleanup runs
    // BEFORE the asserts so a failing assert never leaks fixtures.

    use chrono::Utc;
    use fluidbox_db::{
        connect, identity, ConnectionAuth, ConnectionOwner, IntegrationConnectionRow,
        RunResourceBindingRow, TenantScope,
    };
    use uuid::Uuid;

    async fn seed_user(
        pool: &sqlx::PgPool,
        scope: TenantScope,
        subject: &str,
        member: bool,
    ) -> Uuid {
        let cfg_id = Uuid::now_v7();
        sqlx::query(
            "insert into org_idp_configs
               (id, tenant_id, generation, issuer, client_id, claim_mappings, status)
             values ($1, $2,
                     coalesce((select max(generation) from org_idp_configs where tenant_id = $2), 0) + 1,
                     $3, 'client-test', '{}'::jsonb, 'staged')",
        )
        .bind(cfg_id)
        .bind(scope.tenant_id())
        .bind(format!("https://idp.test/{subject}"))
        .execute(pool)
        .await
        .unwrap();
        let user_id = Uuid::now_v7();
        sqlx::query(
            "insert into users
               (id, tenant_id, idp_config_id, subject, email, email_normalized, email_verified, status)
             values ($1, $2, $3, $4, $5, $5, true, 'active')",
        )
        .bind(user_id)
        .bind(scope.tenant_id())
        .bind(cfg_id)
        .bind(subject)
        .bind(format!("{subject}@example.com"))
        .execute(pool)
        .await
        .unwrap();
        if member {
            sqlx::query(
                "insert into org_memberships (id, tenant_id, user_id, roles, status)
                 values ($1, $2, $3, '{member}', 'active')",
            )
            .bind(Uuid::now_v7())
            .bind(scope.tenant_id())
            .bind(user_id)
            .execute(pool)
            .await
            .unwrap();
        }
        user_id
    }

    async fn seed_conn(
        pool: &sqlx::PgPool,
        scope: TenantScope,
        owner: ConnectionOwner,
        display: &str,
    ) -> IntegrationConnectionRow {
        fluidbox_db::create_connection(
            pool,
            scope,
            "mcp_http",
            &format!("acct-{}", Uuid::now_v7().simple()),
            display,
            Some(b"sealed-token"),
            1,
            &serde_json::json!([]),
            &serde_json::json!({}),
            &serde_json::json!({ "base_url": "https://mcp.example.test" }),
            None,
            1,
            ConnectionAuth::static_active(),
            owner,
            None,
        )
        .await
        .unwrap()
    }

    #[allow(clippy::too_many_arguments)]
    fn binding_row(
        tenant: Uuid,
        conn: &IntegrationConnectionRow,
        generation: i32,
        owner_type: &str,
        owner_user_id: Option<Uuid>,
    ) -> RunResourceBindingRow {
        RunResourceBindingRow {
            id: Uuid::now_v7(),
            tenant_id: tenant,
            session_id: Uuid::now_v7(),
            requirement_slot: "github".into(),
            slot_kind: "mcp".into(),
            authority_kind: "connection".into(),
            connection_id: Some(conn.id),
            subscription_id: None,
            authority_generation: Some(generation),
            connection_owner_type: Some(owner_type.into()),
            connection_owner_user_id: owner_user_id,
            snapshot_version: Some(1),
            effective_tools_json: None,
            effective_tools_digest: None,
            resource_scope: serde_json::json!({}),
            // `operator` invoker: the invoking-authority recheck (R2.2) is a
            // no-op for operator/system, so this matrix stays focused on the
            // CONNECTION-authority checks. A dedicated test below drives the
            // user/subscription invoker paths.
            resolved_by_principal_kind: "operator".into(),
            resolved_by_principal_id: None,
            binding_mode: "invoking_user".into(),
            created_at: Utc::now(),
        }
    }

    async fn cleanup(pool: &sqlx::PgPool, tenant: Uuid) {
        for stmt in [
            "delete from integration_connections where tenant_id = $1",
            "delete from org_memberships where tenant_id = $1",
            "delete from users where tenant_id = $1",
            "delete from org_idp_configs where tenant_id = $1",
            "delete from tenants where id = $1",
        ] {
            let _ = sqlx::query(stmt).bind(tenant).execute(pool).await;
        }
    }

    #[tokio::test]
    async fn recheck_binding_matrix_passes_happy_and_refuses_each_violation() {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("skipping: DATABASE_URL not set");
            return;
        };
        let pool = connect(&url).await.expect("connect");
        let org = identity::create_org(&pool, &format!("t-{}", Uuid::now_v7().simple()), None)
            .await
            .unwrap();
        let scope = TenantScope::assume(org.id);
        let alice = seed_user(&pool, scope, "alice@test.dev", true).await;
        let ghost = seed_user(&pool, scope, "ghost@test.dev", false).await; // no membership

        let org_conn = seed_conn(&pool, scope, ConnectionOwner::Organization, "Org").await;
        let alice_conn = seed_conn(&pool, scope, ConnectionOwner::User(alice), "Alice").await;
        let ghost_conn = seed_conn(&pool, scope, ConnectionOwner::User(ghost), "Ghost").await;
        // Connections start at authorization_generation = 1.
        let gen = org_conn.authorization_generation;

        // Collect (label, result) so ALL asserts run after cleanup.
        let happy_org = recheck_binding_pool(
            &pool,
            scope,
            &binding_row(org.id, &org_conn, gen, "organization", None),
        )
        .await;
        let happy_user = recheck_binding_pool(
            &pool,
            scope,
            &binding_row(org.id, &alice_conn, gen, "user", Some(alice)),
        )
        .await;
        let gen_mismatch = recheck_binding_pool(
            &pool,
            scope,
            &binding_row(org.id, &org_conn, gen + 1, "organization", None),
        )
        .await;
        let tenant_mismatch = recheck_binding_pool(
            &pool,
            scope,
            &binding_row(Uuid::now_v7(), &org_conn, gen, "organization", None),
        )
        .await;
        let missing_membership = recheck_binding_pool(
            &pool,
            scope,
            &binding_row(org.id, &ghost_conn, gen, "user", Some(ghost)),
        )
        .await;

        // Deactivate Alice's membership → her user binding now fails closed.
        sqlx::query("update org_memberships set status = 'deactivated' where tenant_id = $1 and user_id = $2")
            .bind(org.id)
            .bind(alice)
            .execute(&pool)
            .await
            .unwrap();
        let deactivated_owner = recheck_binding_pool(
            &pool,
            scope,
            &binding_row(org.id, &alice_conn, gen, "user", Some(alice)),
        )
        .await;

        // Revoke the org connection → its binding now fails closed.
        fluidbox_db::set_connection_status(&pool, scope, org_conn.id, "revoked", &["active"])
            .await
            .unwrap();
        let non_active = recheck_binding_pool(
            &pool,
            scope,
            &binding_row(org.id, &org_conn, gen, "organization", None),
        )
        .await;

        cleanup(&pool, org.id).await;

        // Happy paths pass; each single violation refuses with a distinct reason.
        assert_eq!(happy_org.expect("org happy").id, org_conn.id);
        assert_eq!(happy_user.expect("user happy").id, alice_conn.id);
        assert!(gen_mismatch
            .expect_err("gen mismatch")
            .contains("reauthorized"));
        assert!(tenant_mismatch
            .expect_err("tenant mismatch")
            .contains("different tenant"));
        assert!(missing_membership
            .expect_err("missing membership")
            .contains("membership is not active"));
        assert!(deactivated_owner
            .expect_err("deactivated owner")
            .contains("membership is not active"));
        assert!(non_active.expect_err("non active").contains("revoked"));
    }

    // ── invoking-authority recheck (R2.2): a run bound to a VALID org connection
    // still fails closed when its invoking user was deactivated or its invoking
    // subscription was disabled/deleted. The connection authority is held
    // constant (a live org connection) so the only variable is the invoker.
    #[tokio::test]
    async fn recheck_binding_refuses_revoked_invoker() {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("skipping: DATABASE_URL not set");
            return;
        };
        let pool = connect(&url).await.expect("connect");
        let org = identity::create_org(&pool, &format!("t-{}", Uuid::now_v7().simple()), None)
            .await
            .unwrap();
        let scope = TenantScope::assume(org.id);

        let conn = seed_conn(&pool, scope, ConnectionOwner::Organization, "Org").await;
        let gen = conn.authorization_generation;
        let member = seed_user(&pool, scope, "member@test.dev", true).await;
        let gone = seed_user(&pool, scope, "gone@test.dev", true).await;

        // A subscription to invoke under (needs agent + policy + revision).
        let policy = fluidbox_db::upsert_policy(
            &pool,
            scope,
            "inv-pol",
            "name: inv",
            &serde_json::json!({"name":"inv"}),
        )
        .await
        .unwrap();
        let agent = fluidbox_db::create_agent(&pool, scope, "inv-agent", None)
            .await
            .unwrap();
        let rev = fluidbox_db::append_agent_revision(
            &pool,
            scope,
            agent.id,
            "claude-agent-sdk",
            "img:test",
            "claude-haiku-4-5",
            Some("p"),
            policy.id,
            &serde_json::json!({}),
            None,
            &serde_json::json!([]),
            &serde_json::json!([]),
        )
        .await
        .unwrap();
        let sub = fluidbox_db::create_trigger_subscription(
            &pool,
            scope,
            agent.id,
            "inv-sub",
            "api",
            Some(rev.id),
            Some("t"),
            false,
            false,
            None,
            "allow",
            None,
            None,
            &serde_json::json!([]),
            None,
            1,
            None,
            None,
            None,
            None,
            None,
        )
        .await
        .unwrap();

        // A connection binding with an overridable invoking principal.
        let invoker_binding = |kind: &str, id: Option<String>| {
            let mut b = binding_row(org.id, &conn, gen, "organization", None);
            b.resolved_by_principal_kind = kind.into();
            b.resolved_by_principal_id = id;
            b
        };

        let user_ok = recheck_binding_pool(
            &pool,
            scope,
            &invoker_binding("user", Some(member.to_string())),
        )
        .await;
        // A trigger run freezes the exact TOKEN as its principal (E1): mint a live
        // trigger token for the subscription and recheck against ITS id.
        let tok_plain = format!("fbx_trig_{}", Uuid::now_v7().simple());
        fluidbox_db::create_trigger_token(&pool, scope, sub.id, &tok_plain)
            .await
            .unwrap();
        let tok_id = fluidbox_db::subscription_for_token(&pool, &tok_plain)
            .await
            .unwrap()
            .unwrap()
            .token_id;
        let sub_ok = recheck_binding_pool(
            &pool,
            scope,
            &invoker_binding("trigger", Some(tok_id.to_string())),
        )
        .await;
        // A forged/unknown trigger token id fails closed (E1).
        let trigger_bad = recheck_binding_pool(
            &pool,
            scope,
            &invoker_binding("trigger", Some(Uuid::now_v7().to_string())),
        )
        .await;
        // An unrecognized principal kind fails closed (E2).
        let unknown_kind = recheck_binding_pool(
            &pool,
            scope,
            &invoker_binding("martian", Some(Uuid::now_v7().to_string())),
        )
        .await;
        let missing_sub = recheck_binding_pool(
            &pool,
            scope,
            &invoker_binding("schedule", Some(Uuid::now_v7().to_string())),
        )
        .await;

        sqlx::query("update org_memberships set status = 'deactivated' where tenant_id = $1 and user_id = $2")
            .bind(org.id)
            .bind(gone)
            .execute(&pool)
            .await
            .unwrap();
        let user_revoked = recheck_binding_pool(
            &pool,
            scope,
            &invoker_binding("user", Some(gone.to_string())),
        )
        .await;

        fluidbox_db::set_trigger_subscription_enabled(&pool, scope, sub.id, false)
            .await
            .unwrap();
        let sub_disabled = recheck_binding_pool(
            &pool,
            scope,
            &invoker_binding("webhook", Some(sub.id.to_string())),
        )
        .await;

        for stmt in [
            "delete from trigger_subscriptions where tenant_id = $1",
            "delete from agent_revisions where agent_id in (select id from agents where tenant_id = $1)",
            "delete from agents where tenant_id = $1",
            "delete from policies where tenant_id = $1",
        ] {
            let _ = sqlx::query(stmt).bind(org.id).execute(&pool).await;
        }
        cleanup(&pool, org.id).await;

        assert_eq!(user_ok.expect("active member invoker").id, conn.id);
        assert_eq!(sub_ok.expect("live trigger token invoker").id, conn.id);
        assert!(trigger_bad
            .expect_err("forged trigger token")
            .contains("revoked or expired"));
        assert!(unknown_kind
            .expect_err("unrecognized principal kind")
            .contains("unrecognized invoking principal kind"));
        assert!(missing_sub
            .expect_err("missing subscription")
            .contains("no longer exists"));
        assert!(user_revoked
            .expect_err("deactivated invoker")
            .contains("no longer an active member"));
        assert!(sub_disabled
            .expect_err("disabled subscription")
            .contains("disabled"));
    }
}
