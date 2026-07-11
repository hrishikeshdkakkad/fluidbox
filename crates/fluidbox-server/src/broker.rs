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

use crate::error::{ApiError, ApiResult};
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

/// Resolve the auth header for a brokered server, enforcing audience
/// binding: the connection pins a `base_url`, and its credential is only
/// ever sent to URLs under that base (our RFC-8707-equivalent — a bundle
/// can never point connection X's token at attacker.example).
/// `Ok(None)` = the server declared no credential.
/// Static connections send the sealed secret (per header_name/scheme);
/// OAuth connections mint/refresh an access token first — the ONLY growth
/// this phase adds to the broker's credential resolution.
pub async fn brokered_auth(
    state: &AppState,
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
    let conn = fluidbox_db::get_connection(&state.pool, *cid)
        .await
        .map_err(|e| format!("connection lookup failed: {e}"))?
        .filter(|c| c.tenant_id == state.tenant_id)
        .ok_or_else(|| format!("capability server '{name}': connection {cid} is missing"))?;
    if conn.status != "active" {
        return Err(format!(
            "capability server '{name}': connection {cid} is {} — reconnect it",
            conn.status
        ));
    }
    if conn.provider != "mcp_http" {
        return Err(format!(
            "capability server '{name}': connection provider '{}' does not hold MCP credentials",
            conn.provider
        ));
    }
    let base = conn
        .metadata
        .get("base_url")
        .and_then(|v| v.as_str())
        .ok_or_else(|| format!("connection {cid} has no base_url — reconnect it"))?;
    if !url_within_base(url, base) {
        return Err(format!(
            "capability server '{name}': url is outside the connection's base_url — refusing to send its credential (audience binding)"
        ));
    }
    if conn.auth_kind == "oauth" {
        let access = crate::oauth::ensure_access_token(state, &conn).await?;
        return Ok(Some(BrokeredAuth {
            header: "authorization".into(),
            value: format!("Bearer {access}"),
            oauth_connection: Some(*cid),
        }));
    }
    let sealer = state
        .sealer
        .as_ref()
        .ok_or("FLUIDBOX_CREDENTIAL_KEY not configured")?;
    let sealed = fluidbox_db::connection_credential_sealed(&state.pool, *cid)
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
    // Fire-and-forget per spec; servers answer 202.
    let note = json!({ "jsonrpc": "2.0", "method": "notifications/initialized" });
    let _ = post_rpc(state, url, auth, Some(&session), &note).await;
    Ok(session)
}

// ─── The two operations fluidbox performs ─────────────────────────────────

/// Registration-time discovery — THE photograph (design §8.2). Paginates
/// tools/list and maps the wire shape (camelCase `inputSchema`) into our
/// frozen snapshot shape. Validation (charsets, lint, caps) happens in
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
        for t in result
            .get("tools")
            .and_then(|v| v.as_array())
            .ok_or("mcp tools/list result has no tools array")?
        {
            tools.push(ToolSnapshot {
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
        cursor = result
            .get("nextCursor")
            .and_then(|v| v.as_str())
            .map(str::to_string);
        if cursor.is_none() {
            break;
        }
    }
    if tools.is_empty() {
        return Err(CallErr::Other("mcp server advertises no tools".into()));
    }
    Ok(tools)
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
    server: &CapabilityServer,
    auth: Option<BrokeredAuth>,
) -> Result<Option<BrokeredAuth>, String> {
    let Some(cid) = auth.as_ref().and_then(|a| a.oauth_connection) else {
        return Err("mcp server rejected the credential (HTTP 401)".into());
    };
    crate::oauth::invalidate_access(state, cid).await;
    brokered_auth(state, server).await
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
    server: &CapabilityServer,
    tool: &str,
    arguments: &Value,
) -> Result<(Value, bool), String> {
    let url = server_url(server)?;
    let auth = brokered_auth(state, server).await?;
    match call_tool(state, url, auth.as_ref(), tool, arguments).await {
        Err(CallErr::Unauthorized) => {
            let auth = reauth_after_401(state, server, auth).await?;
            call_tool(state, url, auth.as_ref(), tool, arguments)
                .await
                .map_err(CallErr::into_msg)
        }
        r => r.map_err(CallErr::into_msg),
    }
}

/// Discover with the same resolution/retry semantics as execution — used by
/// the photograph.
pub async fn discover_tools_auth(
    state: &AppState,
    server: &CapabilityServer,
) -> Result<Vec<ToolSnapshot>, String> {
    let url = server_url(server)?;
    let auth = brokered_auth(state, server).await?;
    match discover_tools(state, url, auth.as_ref()).await {
        Err(CallErr::Unauthorized) => {
            let auth = reauth_after_401(state, server, auth).await?;
            discover_tools(state, url, auth.as_ref())
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

/// Registration helper shared by the capabilities API: resolve auth for a
/// (possibly credentialed) brokered server and photograph its tools.
pub async fn photograph_brokered(
    state: &AppState,
    server: &CapabilityServer,
) -> ApiResult<Vec<ToolSnapshot>> {
    let CapabilityServer::Brokered { name, .. } = server else {
        return Err(ApiError::Internal("not a brokered server".into()));
    };
    discover_tools_auth(state, server)
        .await
        .map_err(|e| ApiError::BadRequest(format!("capability server '{name}': {e}")))
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
