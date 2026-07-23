//! An in-process fake MCP upstream.
//!
//! WHY THE HARNESS HOSTS IT. The design's upstream-failure matrix (401/404/429/
//! 5xx) is a statement about how the CONTROL PLANE behaves when a brokered
//! upstream misbehaves. To drive it, the harness needs an upstream whose answer
//! it can change per arm — so it owns one. That also settles constraint 1 of the
//! brief: this harness contacts nothing but the deployment and its own fake, and
//! never a model provider.
//!
//! It speaks just enough Streamable-HTTP MCP for the broker's conformance
//! contract (Phase E, Gap 8): `initialize` answers a supported protocol version
//! and hands back an `mcp-session-id`, `notifications/initialized` is accepted,
//! `tools/list` publishes two typed tools, `tools/call` answers per mode, and a
//! server→client response POST is acked.
//!
//! REACHABILITY IS A PRECONDITION, NOT A FEATURE. It binds loopback, so the
//! deployment must be able to dial loopback: that means a `FLUIDBOX_PUBLIC_URL`
//! of `http://127.0.0.1:<port>`, which is the ONLY switch that opens the
//! dev-loopback egress seam. A remote deployment cannot reach it — and a remote
//! deployment is refused by the production guard anyway.

use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::Router;
use serde_json::{json, Value};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

/// The offered protocol version. `2025-06-18` is in the control plane's
/// SUPPORTED set alongside `2025-11-25`; the older one is chosen so a snapshot
/// photographed by this fake selects the draft-07 schema dialect, which is the
/// dialect the majority of real connectors are still on.
pub const FAKE_PROTOCOL: &str = "2025-06-18";

/// How `tools/call` answers. Every arm of the upstream-failure matrix is one of
/// these; the mode is swapped between arms without restarting the fake.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    /// A normal successful tool result.
    Ok,
    /// An HTTP error status. `401`/`403` are DEFINITIVE upstream responses, so
    /// the control plane classifies them `failed_upstream` (terminal) rather
    /// than re-claimable.
    Http(u16),
    /// A JSON-RPC error object (a definitive upstream response, not a transport
    /// failure).
    RpcError,
    /// A successful call whose result carries `isError: true`.
    IsError,
    /// SEP-835: a 403 naming `insufficient_scope`. TERMINAL — it marks the
    /// connection `status='error'`, so an arm using it must be run LAST.
    InsufficientScope,
    /// Answer after a delay, to drive the ambiguous/timeout classification.
    SlowMs(u64),
}

pub struct FakeState {
    mode: Mutex<Mode>,
    accept: String,
    pub hits: AtomicU64,
    pub tool_calls: AtomicU64,
}

impl FakeState {
    pub fn set_mode(&self, m: Mode) {
        if let Ok(mut g) = self.mode.lock() {
            *g = m;
        }
    }
    fn mode(&self) -> Mode {
        self.mode.lock().map(|g| *g).unwrap_or(Mode::Ok)
    }
}

pub struct FakeUpstream {
    pub state: Arc<FakeState>,
    pub url: String,
    pub token: String,
    handle: tokio::task::JoinHandle<()>,
}

impl FakeUpstream {
    pub fn shutdown(self) {
        self.handle.abort();
    }
}

/// The two tools the fake publishes. Typed and `required`-bearing on purpose:
/// the frozen-schema gate (Phase E, Gap 12) only has something to enforce if the
/// photographed schema constrains something.
pub fn tools_json() -> Value {
    json!([
        {
            "name": "lg_search",
            "description": "loadgen fake search",
            "inputSchema": {
                "type": "object",
                "properties": {"query": {"type": "string"}},
                "required": ["query"],
                "additionalProperties": false
            }
        },
        {
            "name": "lg_count",
            "description": "loadgen fake count",
            "inputSchema": {
                "type": "object",
                "properties": {"n": {"type": "integer"}},
                "required": ["n"],
                "additionalProperties": false
            }
        }
    ])
}

pub const TOOL_NAMES: [&str; 2] = ["lg_search", "lg_count"];

/// Bind loopback on an ephemeral port and serve until `shutdown()`.
pub async fn start(token: &str) -> anyhow::Result<FakeUpstream> {
    let state = Arc::new(FakeState {
        mode: Mutex::new(Mode::Ok),
        accept: format!("Bearer {token}"),
        hits: AtomicU64::new(0),
        tool_calls: AtomicU64::new(0),
    });
    let app = Router::new()
        .route("/mcp", post(handle))
        .with_state(state.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let port = listener.local_addr()?.port();
    let handle = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    Ok(FakeUpstream {
        state,
        url: format!("http://127.0.0.1:{port}/mcp"),
        token: token.to_string(),
        handle,
    })
}

async fn handle(
    State(state): State<Arc<FakeState>>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    state.hits.fetch_add(1, Ordering::Relaxed);
    let req: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
    let id = req.get("id").cloned().unwrap_or(Value::Null);
    let method = req.get("method").and_then(|m| m.as_str()).unwrap_or("");

    // A server→client REQUEST we sent gets answered on this same endpoint: that
    // inbound message carries an id but NO method. Ack it and stop.
    if method.is_empty() && !id.is_null() {
        return (StatusCode::ACCEPTED, axum::Json(json!({"ok": true}))).into_response();
    }

    // Credential first — a rejected credential must never reach a method, or a
    // broker that turned the WRONG credential would look healthy.
    let auth = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();
    if auth != state.accept {
        return (
            StatusCode::UNAUTHORIZED,
            axum::Json(
                json!({"jsonrpc":"2.0","id":id,"error":{"code":-32001,"message":"unauthorized"}}),
            ),
        )
            .into_response();
    }

    match method {
        "initialize" => {
            let mut h = HeaderMap::new();
            h.insert(
                "mcp-session-id",
                uuid::Uuid::now_v7()
                    .to_string()
                    .parse()
                    .expect("a uuid is a valid header value"),
            );
            (
                StatusCode::OK,
                h,
                axum::Json(json!({
                    "jsonrpc": "2.0", "id": id,
                    "result": {
                        "protocolVersion": FAKE_PROTOCOL,
                        "capabilities": {"tools": {}},
                        "serverInfo": {"name": "fluidbox-loadgen-fake", "version": "0"}
                    }
                })),
            )
                .into_response()
        }
        "notifications/initialized" => (StatusCode::ACCEPTED, "").into_response(),
        "tools/list" => (
            StatusCode::OK,
            axum::Json(json!({"jsonrpc":"2.0","id":id,"result":{"tools": tools_json()}})),
        )
            .into_response(),
        "tools/call" => {
            state.tool_calls.fetch_add(1, Ordering::Relaxed);
            answer_tool_call(state.mode(), id).await
        }
        // Anything else is a method we do not implement — the same `-32601` a
        // real server would answer, never a 200 that would look like success.
        _ => (
            StatusCode::OK,
            axum::Json(
                json!({"jsonrpc":"2.0","id":id,"error":{"code":-32601,"message":"method not found"}}),
            ),
        )
            .into_response(),
    }
}

async fn answer_tool_call(mode: Mode, id: Value) -> Response {
    let ok_result = json!({
        "jsonrpc":"2.0","id":id,
        "result":{"content":[{"type":"text","text":"loadgen fake result"}],"isError":false}
    });
    match mode {
        Mode::Ok => (StatusCode::OK, axum::Json(ok_result)).into_response(),
        Mode::SlowMs(ms) => {
            tokio::time::sleep(std::time::Duration::from_millis(ms)).await;
            (StatusCode::OK, axum::Json(ok_result)).into_response()
        }
        Mode::IsError => (
            StatusCode::OK,
            axum::Json(json!({
                "jsonrpc":"2.0","id":id,
                "result":{"content":[{"type":"text","text":"upstream says no"}],"isError":true}
            })),
        )
            .into_response(),
        Mode::RpcError => (
            StatusCode::OK,
            axum::Json(
                json!({"jsonrpc":"2.0","id":id,"error":{"code":-32000,"message":"upstream refused"}}),
            ),
        )
            .into_response(),
        Mode::InsufficientScope => (
            StatusCode::FORBIDDEN,
            [(
                "www-authenticate",
                "Bearer error=\"insufficient_scope\", scope=\"tools:write\"",
            )],
            axum::Json(json!({"error":"insufficient_scope"})),
        )
            .into_response(),
        Mode::Http(code) => (
            StatusCode::from_u16(code).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
            axum::Json(json!({"error": format!("fake upstream status {code}")})),
        )
            .into_response(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_published_tools_are_typed_and_required_bearing() {
        let tools = tools_json();
        let arr = tools.as_array().expect("an array of tools");
        assert_eq!(arr.len(), TOOL_NAMES.len());
        for t in arr {
            let name = t["name"].as_str().expect("a name");
            assert!(TOOL_NAMES.contains(&name), "unexpected tool {name}");
            let schema = &t["inputSchema"];
            assert_eq!(schema["type"], "object");
            assert!(
                schema["required"].as_array().is_some_and(|r| !r.is_empty()),
                "{name}: the frozen-schema gate has nothing to enforce without a `required`"
            );
            assert_eq!(
                schema["additionalProperties"], false,
                "{name}: an open schema cannot reject an unknown argument"
            );
        }
    }

    /// The version the fake negotiates must be one the control plane accepts, or
    /// every brokered call in the matrix would deny on version drift and the
    /// matrix would prove nothing about upstream failures.
    #[test]
    fn the_offered_protocol_is_in_the_control_planes_supported_set() {
        assert!(
            ["2025-11-25", "2025-06-18"].contains(&FAKE_PROTOCOL),
            "FAKE_PROTOCOL {FAKE_PROTOCOL} is outside broker.rs's SUPPORTED set"
        );
    }

    async fn rpc(
        c: &reqwest::Client,
        url: &str,
        bearer: &str,
        body: serde_json::Value,
    ) -> (u16, String) {
        let r = c
            .post(url)
            .bearer_auth(bearer)
            .json(&body)
            .send()
            .await
            .expect("the fake is listening");
        let status = r.status().as_u16();
        (status, r.text().await.unwrap_or_default())
    }

    /// The fake is the ONLY upstream the failure matrix ever talks to, so a fake
    /// that does not actually speak the protocol would make every arm of that
    /// matrix a measurement of a broken fixture. This drives it end to end over
    /// real HTTP — no database, no control plane.
    #[tokio::test]
    async fn the_fake_speaks_the_protocol_and_honours_every_mode() {
        let up = start("tok-under-test")
            .await
            .expect("the fake binds loopback");
        let c = reqwest::Client::new();

        // A wrong credential never reaches a method.
        let (status, _) = rpc(
            &c,
            &up.url,
            "wrong",
            json!({"jsonrpc":"2.0","id":1,"method":"initialize"}),
        )
        .await;
        assert_eq!(status, 401, "a rejected credential must not reach a method");
        assert_eq!(
            up.state.tool_calls.load(Ordering::Relaxed),
            0,
            "an unauthorized request must never count as a tool call"
        );

        let (status, body) = rpc(
            &c,
            &up.url,
            &up.token,
            json!({"jsonrpc":"2.0","id":1,"method":"initialize"}),
        )
        .await;
        assert_eq!(status, 200);
        assert!(
            body.contains(FAKE_PROTOCOL),
            "initialize must answer the negotiated version: {body}"
        );

        let (_, body) = rpc(
            &c,
            &up.url,
            &up.token,
            json!({"jsonrpc":"2.0","id":2,"method":"tools/list"}),
        )
        .await;
        for name in TOOL_NAMES {
            assert!(body.contains(name), "tools/list omitted {name}: {body}");
        }

        let call = json!({"jsonrpc":"2.0","id":3,"method":"tools/call",
                          "params":{"name":TOOL_NAMES[0],"arguments":{"query":"x"}}});

        up.state.set_mode(Mode::Ok);
        let (status, body) = rpc(&c, &up.url, &up.token, call.clone()).await;
        assert_eq!(status, 200);
        assert!(body.contains("\"isError\":false"), "{body}");

        up.state.set_mode(Mode::IsError);
        let (status, body) = rpc(&c, &up.url, &up.token, call.clone()).await;
        assert_eq!(
            status, 200,
            "an isError result is still a 200 — that is the point"
        );
        assert!(body.contains("\"isError\":true"), "{body}");

        up.state.set_mode(Mode::RpcError);
        let (status, body) = rpc(&c, &up.url, &up.token, call.clone()).await;
        assert_eq!(status, 200);
        assert!(body.contains("-32000"), "{body}");

        for code in [401u16, 404, 429, 500] {
            up.state.set_mode(Mode::Http(code));
            let (status, _) = rpc(&c, &up.url, &up.token, call.clone()).await;
            assert_eq!(status, code, "Mode::Http({code}) must answer {code}");
        }

        up.state.set_mode(Mode::InsufficientScope);
        let (status, body) = rpc(&c, &up.url, &up.token, call.clone()).await;
        assert_eq!(status, 403);
        assert!(body.contains("insufficient_scope"), "{body}");

        up.state.set_mode(Mode::SlowMs(120));
        let t = std::time::Instant::now();
        let (status, _) = rpc(&c, &up.url, &up.token, call.clone()).await;
        assert_eq!(status, 200);
        assert!(
            t.elapsed() >= std::time::Duration::from_millis(100),
            "Mode::SlowMs did not actually delay ({:?})",
            t.elapsed()
        );

        // Every tools/call above (and only those) is counted.
        assert_eq!(up.state.tool_calls.load(Ordering::Relaxed), 3 + 4 + 1 + 1);
        up.shutdown();
    }
}
