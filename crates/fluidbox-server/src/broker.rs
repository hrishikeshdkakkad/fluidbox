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
use serde_json::{json, Value};
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
    let sealed = fluidbox_db::connection_credential_sealed(&state.pool, scope, conn.id)
        .await
        .map_err(|e| format!("credential lookup failed: {e}"))?
        .ok_or("connection is not active (revoked or missing)")?;
    let token = sealer.open(&sealed).map_err(|e| e.to_string())?;
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
    let text = res
        .text()
        .await
        .map_err(|e| format!("mcp response unreadable: {e}"))?;
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

fn rpc_error_to_err(
    status: reqwest::StatusCode,
    value: Value,
    method: &str,
) -> Result<Value, String> {
    if let Some(err) = value.get("error") {
        let msg: String = err
            .get("message")
            .and_then(|m| m.as_str())
            .unwrap_or("unknown error")
            .chars()
            .take(300)
            .collect();
        let code = err.get("code").and_then(|c| c.as_i64()).unwrap_or(0);
        return Err(format!("mcp {method} failed ({code}): {msg}"));
    }
    if !status.is_success() {
        return Err(format!("mcp {method} returned HTTP {status}"));
    }
    Ok(value)
}

fn unwrap_result(value: Value, method: &str) -> Result<Value, String> {
    if let Some(err) = value.get("error") {
        let msg: String = err
            .get("message")
            .and_then(|m| m.as_str())
            .unwrap_or("unknown error")
            .chars()
            .take(300)
            .collect();
        return Err(format!("mcp {method} failed: {msg}"));
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
}
