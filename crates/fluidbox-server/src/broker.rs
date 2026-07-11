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

/// Resolve the Authorization header for a brokered server, enforcing
/// audience binding: the connection pins a `base_url`, and its credential is
/// only ever sent to URLs under that base (our RFC-8707-equivalent — a
/// bundle can never point connection X's token at attacker.example).
/// `Ok(None)` = the server declared no credential.
pub async fn brokered_auth(
    state: &AppState,
    server: &CapabilityServer,
) -> Result<Option<String>, String> {
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
    let sealer = state
        .sealer
        .as_ref()
        .ok_or("FLUIDBOX_CREDENTIAL_KEY not configured")?;
    let sealed = fluidbox_db::connection_credential_sealed(&state.pool, *cid)
        .await
        .map_err(|e| format!("credential lookup failed: {e}"))?
        .ok_or("connection is not active (revoked or missing)")?;
    let token = sealer.open(&sealed).map_err(|e| e.to_string())?;
    Ok(Some(format!("Bearer {token}")))
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

struct McpSession {
    session_id: Option<String>,
    protocol_version: Option<String>,
}

async fn post_rpc(
    state: &AppState,
    url: &str,
    auth: Option<&str>,
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
        req = req.header("authorization", a);
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
    auth: Option<&str>,
    method: &str,
    params: Value,
) -> Result<Value, String> {
    let body = json!({ "jsonrpc": "2.0", "id": 1, "method": method, "params": params });
    let (status, _, value) = post_rpc(state, url, auth, None, &body).await?;
    if status.is_success() && value.get("error").is_none() && !value.is_null() {
        return unwrap_result(value, method);
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
        return unwrap_result(rpc_error_to_err(status, value, method)?, method);
    }
    let session = handshake(state, url, auth).await?;
    let (status, _, value) = post_rpc(state, url, auth, Some(&session), &body).await?;
    if !status.is_success() {
        return Err(format!("mcp {method} returned HTTP {status}"));
    }
    unwrap_result(rpc_error_to_err(status, value, method)?, method)
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

async fn handshake(state: &AppState, url: &str, auth: Option<&str>) -> Result<McpSession, String> {
    let body = json!({
        "jsonrpc": "2.0", "id": 0, "method": "initialize",
        "params": {
            "protocolVersion": OFFERED_PROTOCOL,
            "capabilities": {},
            "clientInfo": { "name": "fluidbox-broker", "version": env!("CARGO_PKG_VERSION") },
        }
    });
    let (status, session_id, value) = post_rpc(state, url, auth, None, &body).await?;
    if !status.is_success() {
        return Err(format!("mcp initialize returned HTTP {status}"));
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
pub async fn discover_tools(
    state: &AppState,
    url: &str,
    auth: Option<&str>,
) -> Result<Vec<ToolSnapshot>, String> {
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
        return Err("mcp server advertises no tools".into());
    }
    Ok(tools)
}

/// One brokered tool execution. Returns (content, is_error) from the MCP
/// result. At-least-once under network failure by design — the caller
/// ledgers every attempt; we never blind-retry after a request was sent.
pub async fn call_tool(
    state: &AppState,
    url: &str,
    auth: Option<&str>,
    tool: &str,
    arguments: &Value,
) -> Result<(Value, bool), String> {
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
    let CapabilityServer::Brokered { name, url, .. } = server else {
        return Err(ApiError::Internal("not a brokered server".into()));
    };
    let auth = brokered_auth(state, server)
        .await
        .map_err(ApiError::BadRequest)?;
    discover_tools(state, url, auth.as_deref())
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
