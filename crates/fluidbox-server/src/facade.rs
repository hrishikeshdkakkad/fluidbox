//! The LLM session facade — the second enforcement boundary.
//!
//! The sandbox's fake provider API key is its fluidbox session token; this
//! endpoint authenticates the session, enforces the budget stop, validates
//! the request against the FROZEN RunSpec (exact upstream suffix, model pin,
//! client-executed tool types only, codex forced stateless), swaps in the
//! real upstream credential, forwards to the gateway (LiteLLM or, in
//! fallback, api.anthropic.com), and tees the SSE stream to meter usage into
//! the ledger. Two dialects ride one route, dispatched on RunSpec.harness:
//! `claude-agent-sdk` (Anthropic Messages) and `codex` (OpenAI Responses).
//! Response bytes reach the runner verbatim; claude request bytes are
//! forwarded verbatim, codex request bytes are re-serialized after the
//! statelessness rewrite (`store=false`).

use crate::error::{ApiError, ApiResult};
use crate::harness;
use crate::ledger;
use crate::state::AppState;
use axum::body::Body;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::Response;
use fluidbox_core::event::{Actor, EventBody};
use fluidbox_core::spec::RunSpec;
use fluidbox_core::usage::{estimate_cost_usd, UsageDelta};
use futures::StreamExt;
use serde_json::{json, Value};
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Dialect {
    Anthropic,
    OpenAi,
}

fn dialect_for(harness_id: &str) -> Option<Dialect> {
    match harness_id {
        harness::CLAUDE_AGENT_SDK => Some(Dialect::Anthropic),
        harness::CODEX => Some(Dialect::OpenAi),
        _ => None,
    }
}

/// Exact upstream suffix allowlist per dialect. The matched CONSTANT (never
/// the caller's string) builds the upstream URL, so percent-encoded slashes
/// or any other smuggling in `{*rest}` cannot reach the master-keyed
/// gateway: anything that doesn't decode to exactly an allowlisted suffix
/// is refused. This closes the pre-existing verbatim-suffix proxy hole.
fn resolve_suffix(dialect: Dialect, rest: &str) -> Option<&'static str> {
    match dialect {
        Dialect::Anthropic => match rest {
            // The Agent SDK appends /v1/messages to ANTHROPIC_BASE_URL;
            // empty is the defensive legacy mapping.
            "" | "v1/messages" => Some("v1/messages"),
            "v1/messages/count_tokens" => Some("v1/messages/count_tokens"),
            _ => None,
        },
        Dialect::OpenAi => match rest {
            "v1/responses" => Some("v1/responses"),
            _ => None,
        },
    }
}

/// Dialect-shaped error body: the runner-side SDK/binary parses these, so
/// each dialect gets its native error envelope.
fn dialect_error(dialect: Dialect, status: StatusCode, message: &str) -> Response {
    let body = match dialect {
        Dialect::Anthropic => json!({
            "type": "error",
            "error": { "type": "invalid_request_error", "message": message }
        }),
        Dialect::OpenAi => json!({
            "error": {
                "message": message,
                "type": "invalid_request_error",
                "param": null,
                "code": null
            }
        }),
    };
    Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .unwrap()
}

/// Request-body screen, shared by both dialects:
/// - the body's `model` MUST equal the frozen RunSpec model (422) — the
///   facade never lets a sandbox pick its own model;
/// - tool entries may only be CLIENT-executed types (custom tools). Server-
///   executed tool types (web_search, computer use, code interpreter, MCP
///   passthrough, …) would run outside the permission gate — rejected.
///
/// Allowlists come from what the two pinned SDKs actually send.
fn validate_body(
    dialect: Dialect,
    frozen_model: &str,
    parsed: &Value,
) -> Result<(), (StatusCode, String)> {
    let model = parsed.get("model").and_then(|m| m.as_str()).unwrap_or("");
    if model != frozen_model {
        return Err((
            StatusCode::UNPROCESSABLE_ENTITY,
            format!("model '{model}' does not match the run's frozen model '{frozen_model}'"),
        ));
    }
    if let Some(tools) = parsed.get("tools").and_then(|t| t.as_array()) {
        for t in tools {
            let ty = t.get("type").and_then(|x| x.as_str());
            let ok = match dialect {
                // Anthropic client tools carry no type or "custom";
                // anything versioned ("web_search_20250305", …) is a
                // server-executed tool.
                Dialect::Anthropic => matches!(ty, None | Some("custom")),
                // Codex 0.144.1 sends "function" and (freeform) "custom".
                Dialect::OpenAi => matches!(ty, Some("function") | Some("custom")),
            };
            if !ok {
                return Err((
                    StatusCode::UNPROCESSABLE_ENTITY,
                    format!(
                        "tool type '{}' is server-executed upstream and cannot cross the governed facade",
                        ty.unwrap_or("<missing>")
                    ),
                ));
            }
        }
    }
    if dialect == Dialect::OpenAi {
        // Statelessness screen: the facade never lets upstream conversation
        // state substitute for the audited request body.
        for field in ["previous_response_id", "conversation"] {
            if parsed.get(field).map(|v| !v.is_null()).unwrap_or(false) {
                return Err((
                    StatusCode::UNPROCESSABLE_ENTITY,
                    format!("'{field}' is not supported: the facade is stateless (store=false)"),
                ));
            }
        }
        if parsed
            .get("background")
            .and_then(|v| v.as_bool())
            .unwrap_or(false)
        {
            return Err((
                StatusCode::UNPROCESSABLE_ENTITY,
                "'background' responses are not supported through the facade".into(),
            ));
        }
    }
    Ok(())
}

/// POST /internal/llm/{*rest} — both dialects, one route.
pub async fn messages(
    Path(rest): Path<String>,
    State(state): State<AppState>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> ApiResult<Response> {
    let token = session_token(&headers).ok_or(ApiError::Unauthorized)?;
    let session_id = fluidbox_db::session_for_token(&state.pool, &token)
        .await?
        .ok_or(ApiError::Unauthorized)?;

    let session = fluidbox_db::get_session(&state.pool, session_id)
        .await?
        .ok_or(ApiError::NotFound)?;
    if session.status_enum().is_terminal() {
        return Err(ApiError::BadRequest("session is not active".into()));
    }
    let run_spec: RunSpec = serde_json::from_value(session.run_spec.clone())
        .map_err(|e| ApiError::Internal(format!("bad run_spec: {e}")))?;

    let Some(dialect) = dialect_for(&run_spec.harness) else {
        // create_run refuses unknown harnesses; a row that still gets here
        // fails closed.
        return Err(ApiError::BadRequest(format!(
            "run harness '{}' has no LLM dialect",
            run_spec.harness
        )));
    };

    // Deployment sanity: the direct-Anthropic fallback upstream cannot serve
    // the OpenAI Responses dialect.
    if dialect == Dialect::OpenAi && state.cfg.llm_upstream_is_anthropic {
        return Ok(dialect_error(
            dialect,
            StatusCode::BAD_GATEWAY,
            "this deployment's LLM upstream is direct-Anthropic; codex runs need the gateway",
        ));
    }

    // Budget stop (pre-proxy, dialect-shaped): cost, then tokens summed
    // across ALL categories — uncached input, output, cache reads, cache
    // writes. A cached-heavy run can no longer fly under the token budget.
    let totals = fluidbox_db::usage_totals(&state.pool, session_id).await?;
    if let Some(max_cost) = run_spec.budgets.max_cost_usd {
        if totals.cost_usd >= max_cost {
            trigger_budget_stop(&state, session_id, "max_cost_usd", max_cost, totals.cost_usd)
                .await;
            return Ok(dialect_error(
                dialect,
                StatusCode::BAD_REQUEST,
                "cost budget exhausted",
            ));
        }
    }
    if let Some(max_tokens) = run_spec.budgets.max_tokens {
        let used = (totals.input_tokens
            + totals.output_tokens
            + totals.cache_read_tokens
            + totals.cache_write_tokens) as u64;
        if used >= max_tokens {
            trigger_budget_stop(
                &state,
                session_id,
                "max_tokens",
                max_tokens as f64,
                used as f64,
            )
            .await;
            return Ok(dialect_error(
                dialect,
                StatusCode::BAD_REQUEST,
                "token budget exhausted",
            ));
        }
    }

    // Exact suffix allowlist; the matched constant builds the upstream URL.
    let Some(suffix) = resolve_suffix(dialect, &rest) else {
        return Ok(dialect_error(
            dialect,
            StatusCode::NOT_FOUND,
            &format!("'{rest}' is not an allowed facade path"),
        ));
    };

    // Body screen (both dialects parse; claude bytes still forward verbatim).
    let mut parsed: Value = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(e) => {
            return Ok(dialect_error(
                dialect,
                StatusCode::BAD_REQUEST,
                &format!("request body is not valid JSON: {e}"),
            ));
        }
    };
    if let Err((status, msg)) = validate_body(dialect, &run_spec.model, &parsed) {
        return Ok(dialect_error(dialect, status, &msg));
    }

    // Codex is forced stateless: no upstream-persisted responses, ever.
    let upstream_body: axum::body::Bytes = match dialect {
        Dialect::Anthropic => body.clone(),
        Dialect::OpenAi => {
            if let Some(obj) = parsed.as_object_mut() {
                obj.insert("store".into(), json!(false));
            }
            serde_json::to_vec(&parsed)
                .map_err(|e| ApiError::Internal(format!("body rewrite: {e}")))?
                .into()
        }
    };

    let upstream = format!(
        "{}/{}",
        state.cfg.llm_upstream_url.trim_end_matches('/'),
        suffix
    );

    let mut req = state.http.post(&upstream).body(upstream_body);
    req = req.header("content-type", "application/json");
    match dialect {
        Dialect::Anthropic => {
            // Forward version + beta headers verbatim (native contract).
            if let Some(v) = headers
                .get("anthropic-version")
                .and_then(|h| h.to_str().ok())
            {
                req = req.header("anthropic-version", v);
            } else {
                req = req.header("anthropic-version", "2023-06-01");
            }
            if let Some(b) = headers.get("anthropic-beta").and_then(|h| h.to_str().ok()) {
                req = req.header("anthropic-beta", b);
            }
            if state.cfg.llm_upstream_is_anthropic {
                req = req.header("x-api-key", &state.cfg.llm_upstream_key);
            } else {
                req = req
                    .header(
                        "authorization",
                        format!("Bearer {}", state.cfg.llm_upstream_key),
                    )
                    .header("x-api-key", &state.cfg.llm_upstream_key);
            }
        }
        Dialect::OpenAi => {
            // Bearer only — the OpenAI dialect never sees x-api-key.
            req = req.header(
                "authorization",
                format!("Bearer {}", state.cfg.llm_upstream_key),
            );
        }
    }

    let resp = req
        .send()
        .await
        .map_err(|e| ApiError::Internal(format!("upstream: {e}")))?;
    let status = resp.status();
    let is_stream = resp
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.contains("event-stream"))
        .unwrap_or(false);

    let model_hint = run_spec.model.clone();

    if !is_stream {
        // Non-streaming: read fully, meter, forward.
        let bytes = resp
            .bytes()
            .await
            .map_err(|e| ApiError::Internal(format!("upstream body: {e}")))?;
        if status.is_success() {
            if let Some(usage) = parse_usage_json(dialect, &bytes) {
                record_usage(&state, session_id, &model_hint, usage, None).await;
            }
        }
        let mut builder = Response::builder().status(status);
        builder = builder.header("content-type", "application/json");
        return Ok(builder.body(Body::from(bytes)).unwrap());
    }

    // Streaming: tee bytes verbatim to the runner while metering. On client
    // disconnect the upstream is DRAINED, not aborted — the tee is the only
    // meter (the LiteLLM callback stays a stub), so dropping the tail would
    // silently lose the whole response's usage.
    let state2 = state.clone();
    let model2 = model_hint.clone();
    let upstream_status = StatusCode::from_u16(status.as_u16()).unwrap_or(StatusCode::OK);

    let (tx, rx) = tokio::sync::mpsc::channel::<Result<axum::body::Bytes, std::io::Error>>(64);
    tokio::spawn(async move {
        let mut meter = Meter::for_dialect(dialect);
        let mut decoder = SseLineDecoder::default();
        let mut stream = resp.bytes_stream();
        let mut client_gone = false;
        while let Some(chunk) = stream.next().await {
            match chunk {
                Ok(bytes) => {
                    decoder.feed(&bytes, |line| meter.on_line(line));
                    if !client_gone && tx.send(Ok(bytes)).await.is_err() {
                        client_gone = true; // runner hung up — keep draining
                    }
                }
                Err(e) => {
                    if !client_gone {
                        let _ = tx.send(Err(std::io::Error::other(e))).await;
                    }
                    break;
                }
            }
        }
        decoder.finish(|line| meter.on_line(line));
        // Meter on stream end.
        if meter.any() {
            record_usage(&state2, session_id, &model2, meter.into_delta(), None).await;
        } else {
            // Still record a zero-usage marker so we know a call happened.
            ledger::record(
                &state2,
                session_id,
                Actor::System,
                EventBody::AgentMessage {
                    role: "system".into(),
                    text: "model stream completed (usage unparsed)".into(),
                },
            )
            .await;
        }
    });

    let body_stream = tokio_stream::wrappers::ReceiverStream::new(rx);
    let response = Response::builder()
        .status(upstream_status)
        .header("content-type", "text/event-stream")
        .header("cache-control", "no-cache")
        .body(Body::from_stream(body_stream))
        .unwrap();
    Ok(response)
}

fn session_token(headers: &HeaderMap) -> Option<String> {
    // The Agent SDK sends the key as `x-api-key` (Anthropic native); codex
    // and the SDK both can send `authorization: Bearer`. Accept either.
    if let Some(k) = headers.get("x-api-key").and_then(|v| v.to_str().ok()) {
        return Some(k.to_string());
    }
    headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .map(|s| s.to_string())
}

async fn trigger_budget_stop(
    state: &AppState,
    session_id: Uuid,
    budget: &str,
    limit: f64,
    spent: f64,
) {
    ledger::record(
        state,
        session_id,
        Actor::System,
        EventBody::BudgetExceeded {
            budget: budget.into(),
            limit: format!("{limit}"),
            spent: format!("{spent:.4}"),
        },
    )
    .await;
    if let Ok(Some(session)) = fluidbox_db::get_session(&state.pool, session_id).await {
        let state2 = state.clone();
        let reason = format!("{budget} budget exceeded");
        tokio::spawn(async move {
            crate::orchestrator::finalize(&state2, &session, "budget_exceeded", Some(&reason))
                .await;
        });
    }
}

async fn record_usage(
    state: &AppState,
    session_id: Uuid,
    model: &str,
    usage: UsageDelta,
    external_id: Option<&str>,
) {
    let cost = estimate_cost_usd(model, &usage);
    fluidbox_db::add_usage(
        &state.pool,
        session_id,
        model,
        usage.input_tokens as i64,
        usage.output_tokens as i64,
        usage.cache_read_tokens as i64,
        usage.cache_write_tokens as i64,
        cost,
        "facade",
        external_id,
    )
    .await
    .ok();
    ledger::record(
        state,
        session_id,
        Actor::System,
        EventBody::ModelResponse {
            model: model.into(),
            input_tokens: usage.input_tokens,
            output_tokens: usage.output_tokens,
            cache_read_tokens: usage.cache_read_tokens,
            cache_write_tokens: usage.cache_write_tokens,
            cost_usd: cost,
        },
    )
    .await;
}

// ─── Usage parsing ─────────────────────────────────────────────────────────

fn parse_usage_json(dialect: Dialect, body: &[u8]) -> Option<UsageDelta> {
    let v: serde_json::Value = serde_json::from_slice(body).ok()?;
    let u = v.get("usage")?;
    Some(match dialect {
        Dialect::Anthropic => anthropic_usage_from_value(u),
        Dialect::OpenAi => openai_usage_from_value(u),
    })
}

fn anthropic_usage_from_value(u: &Value) -> UsageDelta {
    let g = |k: &str| u.get(k).and_then(|x| x.as_u64()).unwrap_or(0);
    UsageDelta {
        input_tokens: g("input_tokens"),
        output_tokens: g("output_tokens"),
        cache_read_tokens: g("cache_read_input_tokens"),
        cache_write_tokens: g("cache_creation_input_tokens"),
    }
}

/// OpenAI Responses usage → the canonical split. `input_tokens` INCLUDES
/// cached reads upstream, so uncached input = input − cached (saturating —
/// LiteLLM has been seen emitting cached > input on edge paths).
/// `output_tokens` already includes reasoning; `reasoning_tokens` in the
/// details is informational and must never be re-added. LiteLLM sometimes
/// normalizes to prompt_/completion_ spellings — both accepted.
fn openai_usage_from_value(u: &Value) -> UsageDelta {
    let num = |v: Option<&Value>| v.and_then(|x| x.as_u64()).unwrap_or(0);
    let input_total = num(u.get("input_tokens").or_else(|| u.get("prompt_tokens")));
    let cached = num(u
        .get("input_tokens_details")
        .or_else(|| u.get("prompt_tokens_details"))
        .and_then(|d| d.get("cached_tokens")));
    let output = num(u
        .get("output_tokens")
        .or_else(|| u.get("completion_tokens")));
    UsageDelta {
        input_tokens: input_total.saturating_sub(cached),
        output_tokens: output,
        cache_read_tokens: cached,
        cache_write_tokens: 0,
    }
}

/// Incremental SSE line decoder. Buffers partial lines across chunk
/// boundaries — a `data:` JSON line split mid-token still parses when its
/// tail arrives (the pre-Phase-6 decoder dropped those lines: a latent
/// usage undercount whenever the gateway flushed mid-line).
#[derive(Default)]
struct SseLineDecoder {
    pending: Vec<u8>,
}

impl SseLineDecoder {
    fn feed(&mut self, chunk: &[u8], mut on_line: impl FnMut(&str)) {
        self.pending.extend_from_slice(chunk);
        let mut start = 0usize;
        while let Some(rel) = self.pending[start..].iter().position(|&b| b == b'\n') {
            let end = start + rel;
            let line = String::from_utf8_lossy(&self.pending[start..end]);
            on_line(line.trim());
            start = end + 1;
        }
        if start > 0 {
            self.pending.drain(..start);
        }
    }

    fn finish(mut self, mut on_line: impl FnMut(&str)) {
        if !self.pending.is_empty() {
            let line = String::from_utf8_lossy(&self.pending).to_string();
            on_line(line.trim());
            self.pending.clear();
        }
    }
}

enum Meter {
    Anthropic(AnthropicAccumulator),
    OpenAi(OpenAiAccumulator),
}

impl Meter {
    fn for_dialect(dialect: Dialect) -> Self {
        match dialect {
            Dialect::Anthropic => Meter::Anthropic(AnthropicAccumulator::default()),
            Dialect::OpenAi => Meter::OpenAi(OpenAiAccumulator::default()),
        }
    }

    fn on_line(&mut self, line: &str) {
        let Some(data) = line.strip_prefix("data:") else {
            return;
        };
        let data = data.trim();
        if data.is_empty() || data == "[DONE]" {
            return;
        }
        let Ok(v) = serde_json::from_str::<Value>(data) else {
            return;
        };
        match self {
            Meter::Anthropic(a) => a.on_event(&v),
            Meter::OpenAi(o) => o.on_event(&v),
        }
    }

    fn any(&self) -> bool {
        match self {
            Meter::Anthropic(a) => a.seen,
            Meter::OpenAi(o) => o.seen,
        }
    }

    fn into_delta(self) -> UsageDelta {
        match self {
            Meter::Anthropic(a) => a.into_delta(),
            Meter::OpenAi(o) => o.delta,
        }
    }
}

/// Anthropic SSE usage: `message_start` carries input + cache tokens;
/// `message_delta` carries the running (cumulative) output count.
#[derive(Default)]
struct AnthropicAccumulator {
    input: u64,
    output: u64,
    cache_read: u64,
    cache_write: u64,
    seen: bool,
}

impl AnthropicAccumulator {
    fn on_event(&mut self, v: &Value) {
        match v.get("type").and_then(|t| t.as_str()) {
            Some("message_start") => {
                if let Some(u) = v.get("message").and_then(|m| m.get("usage")) {
                    let d = anthropic_usage_from_value(u);
                    self.input = d.input_tokens;
                    self.cache_read = d.cache_read_tokens;
                    self.cache_write = d.cache_write_tokens;
                    self.output = d.output_tokens; // usually 0 here
                    self.seen = true;
                }
            }
            Some("message_delta") => {
                if let Some(u) = v.get("usage") {
                    if let Some(out) = u.get("output_tokens").and_then(|x| x.as_u64()) {
                        self.output = out; // cumulative
                        self.seen = true;
                    }
                    // Some providers repeat input on delta; keep max.
                    if let Some(inp) = u.get("input_tokens").and_then(|x| x.as_u64()) {
                        self.input = self.input.max(inp);
                    }
                }
            }
            _ => {}
        }
    }

    fn into_delta(self) -> UsageDelta {
        UsageDelta {
            input_tokens: self.input,
            output_tokens: self.output,
            cache_read_tokens: self.cache_read,
            cache_write_tokens: self.cache_write,
        }
    }
}

/// OpenAI Responses SSE usage: authoritative on `response.completed` /
/// `response.incomplete` (last wins — an incomplete response still bills).
#[derive(Default)]
struct OpenAiAccumulator {
    delta: UsageDelta,
    seen: bool,
}

impl OpenAiAccumulator {
    fn on_event(&mut self, v: &Value) {
        match v.get("type").and_then(|t| t.as_str()) {
            Some("response.completed") | Some("response.incomplete") => {
                if let Some(u) = v
                    .get("response")
                    .and_then(|r| r.get("usage"))
                    .filter(|u| !u.is_null())
                {
                    self.delta = openai_usage_from_value(u);
                    self.seen = true;
                }
            }
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn suffix_allowlist_is_exact_per_dialect() {
        assert_eq!(
            resolve_suffix(Dialect::Anthropic, "v1/messages"),
            Some("v1/messages")
        );
        assert_eq!(
            resolve_suffix(Dialect::Anthropic, "v1/messages/count_tokens"),
            Some("v1/messages/count_tokens")
        );
        assert_eq!(resolve_suffix(Dialect::Anthropic, ""), Some("v1/messages"));
        // The master-key proxy hole: arbitrary suffixes must die.
        assert_eq!(resolve_suffix(Dialect::Anthropic, "v1/chat/completions"), None);
        assert_eq!(resolve_suffix(Dialect::Anthropic, "key/info"), None);
        assert_eq!(resolve_suffix(Dialect::Anthropic, "v1/messages/../key/info"), None);
        assert_eq!(resolve_suffix(Dialect::Anthropic, "v1/responses"), None);
        // Codex: responses only — no anthropic paths, no empty legacy map.
        assert_eq!(
            resolve_suffix(Dialect::OpenAi, "v1/responses"),
            Some("v1/responses")
        );
        assert_eq!(resolve_suffix(Dialect::OpenAi, "v1/messages"), None);
        assert_eq!(resolve_suffix(Dialect::OpenAi, ""), None);
        assert_eq!(resolve_suffix(Dialect::OpenAi, "v1/responses/abc"), None);
    }

    #[test]
    fn model_pin_is_enforced() {
        let body = json!({"model": "claude-haiku-4-5", "messages": []});
        assert!(validate_body(Dialect::Anthropic, "claude-haiku-4-5", &body).is_ok());
        let err = validate_body(Dialect::Anthropic, "claude-opus-4-8", &body).unwrap_err();
        assert_eq!(err.0, StatusCode::UNPROCESSABLE_ENTITY);
        // Missing model never passes.
        let body = json!({"messages": []});
        assert!(validate_body(Dialect::Anthropic, "claude-haiku-4-5", &body).is_err());
    }

    #[test]
    fn server_executed_tools_are_rejected_client_tools_pass() {
        // Anthropic: no type / "custom" = client tools.
        let ok = json!({"model": "m", "tools": [
            {"name": "Bash", "input_schema": {}},
            {"type": "custom", "name": "Edit", "input_schema": {}}
        ]});
        assert!(validate_body(Dialect::Anthropic, "m", &ok).is_ok());
        let bad = json!({"model": "m", "tools": [
            {"type": "web_search_20250305", "name": "web_search"}
        ]});
        assert!(validate_body(Dialect::Anthropic, "m", &bad).is_err());

        // OpenAI: function/custom pass; hosted tools rejected.
        let ok = json!({"model": "m", "tools": [
            {"type": "function", "name": "shell"},
            {"type": "custom", "name": "apply_patch"}
        ]});
        assert!(validate_body(Dialect::OpenAi, "m", &ok).is_ok());
        for hosted in ["web_search", "file_search", "code_interpreter", "computer_use_preview", "mcp", "local_shell"] {
            let bad = json!({"model": "m", "tools": [{"type": hosted}]});
            assert!(
                validate_body(Dialect::OpenAi, "m", &bad).is_err(),
                "hosted tool '{hosted}' must be rejected"
            );
        }
    }

    #[test]
    fn codex_statelessness_screen() {
        let bad = json!({"model": "m", "previous_response_id": "resp_123"});
        assert!(validate_body(Dialect::OpenAi, "m", &bad).is_err());
        let bad = json!({"model": "m", "conversation": "conv_1"});
        assert!(validate_body(Dialect::OpenAi, "m", &bad).is_err());
        let bad = json!({"model": "m", "background": true});
        assert!(validate_body(Dialect::OpenAi, "m", &bad).is_err());
        // null is as-absent (serde default emission).
        let ok = json!({"model": "m", "previous_response_id": null});
        assert!(validate_body(Dialect::OpenAi, "m", &ok).is_ok());
        // The same fields are fine for the anthropic dialect (it never
        // sends them; screen is per-dialect).
        let ok = json!({"model": "m"});
        assert!(validate_body(Dialect::Anthropic, "m", &ok).is_ok());
    }

    #[test]
    fn sse_decoder_survives_lines_split_across_chunks() {
        let mut dec = SseLineDecoder::default();
        let mut lines: Vec<String> = Vec::new();
        // One data line delivered in three chunks, split mid-JSON.
        dec.feed(b"data: {\"type\":\"response.com", &mut |l: &str| {
            lines.push(l.to_string())
        });
        assert!(lines.is_empty(), "no complete line yet");
        dec.feed(b"pleted\",\"response\":{\"usage\":{\"input_tokens\":10,", &mut |l: &str| {
            lines.push(l.to_string())
        });
        assert!(lines.is_empty());
        dec.feed(
            b"\"output_tokens\":5}}}\n\ndata: [DONE]\n",
            &mut |l: &str| lines.push(l.to_string()),
        );
        // The reassembled line + the blank + [DONE].
        assert_eq!(lines.len(), 3);
        assert!(lines[0].contains("response.completed"));

        // And the meter parses the reassembled line.
        let mut meter = Meter::for_dialect(Dialect::OpenAi);
        for l in &lines {
            meter.on_line(l);
        }
        assert!(meter.any());
        let d = meter.into_delta();
        assert_eq!(d.input_tokens, 10);
        assert_eq!(d.output_tokens, 5);
    }

    #[test]
    fn sse_decoder_finish_flushes_unterminated_tail() {
        let mut dec = SseLineDecoder::default();
        let mut lines: Vec<String> = Vec::new();
        dec.feed(b"data: {\"type\":\"message_delta\",\"usage\":{\"output_tokens\":7}}", &mut |l: &str| {
            lines.push(l.to_string())
        });
        assert!(lines.is_empty());
        dec.finish(|l: &str| lines.push(l.to_string()));
        assert_eq!(lines.len(), 1);
        let mut meter = Meter::for_dialect(Dialect::Anthropic);
        meter.on_line(&lines[0]);
        assert!(meter.any());
        assert_eq!(meter.into_delta().output_tokens, 7);
    }

    #[test]
    fn openai_usage_cached_subtract_is_saturating_and_reasoning_not_double_counted() {
        // OpenAI-shaped with reasoning detail present.
        let u = json!({
            "input_tokens": 1000,
            "input_tokens_details": {"cached_tokens": 800},
            "output_tokens": 300,
            "output_tokens_details": {"reasoning_tokens": 250},
            "total_tokens": 1300
        });
        let d = openai_usage_from_value(&u);
        assert_eq!(d.input_tokens, 200); // 1000 - 800
        assert_eq!(d.cache_read_tokens, 800);
        assert_eq!(d.output_tokens, 300); // reasoning INCLUDED, not re-added
        assert_eq!(d.cache_write_tokens, 0);

        // Degenerate LiteLLM edge: cached > input must not underflow.
        let u = json!({
            "input_tokens": 100,
            "input_tokens_details": {"cached_tokens": 150},
            "output_tokens": 1
        });
        let d = openai_usage_from_value(&u);
        assert_eq!(d.input_tokens, 0);
        assert_eq!(d.cache_read_tokens, 150);
    }

    #[test]
    fn openai_usage_accepts_litellm_prompt_completion_spelling() {
        let u = json!({
            "prompt_tokens": 500,
            "prompt_tokens_details": {"cached_tokens": 100},
            "completion_tokens": 42
        });
        let d = openai_usage_from_value(&u);
        assert_eq!(d.input_tokens, 400);
        assert_eq!(d.cache_read_tokens, 100);
        assert_eq!(d.output_tokens, 42);
    }

    #[test]
    fn openai_meter_takes_completed_and_incomplete_last_wins() {
        let mut meter = Meter::for_dialect(Dialect::OpenAi);
        meter.on_line(r#"data: {"type":"response.created","response":{}}"#);
        assert!(!meter.any(), "created carries no usage");
        meter.on_line(
            r#"data: {"type":"response.incomplete","response":{"usage":{"input_tokens":50,"output_tokens":10}}}"#,
        );
        assert!(meter.any(), "incomplete responses still bill");
        meter.on_line(
            r#"data: {"type":"response.completed","response":{"usage":{"input_tokens":60,"output_tokens":20}}}"#,
        );
        let d = meter.into_delta();
        assert_eq!((d.input_tokens, d.output_tokens), (60, 20));
    }

    #[test]
    fn anthropic_meter_unchanged_semantics() {
        let mut meter = Meter::for_dialect(Dialect::Anthropic);
        meter.on_line(
            r#"data: {"type":"message_start","message":{"usage":{"input_tokens":11,"cache_read_input_tokens":3,"cache_creation_input_tokens":2,"output_tokens":0}}}"#,
        );
        meter.on_line(r#"data: {"type":"message_delta","usage":{"output_tokens":4}}"#);
        meter.on_line(r#"data: {"type":"message_delta","usage":{"output_tokens":9}}"#);
        let d = meter.into_delta();
        assert_eq!(d.input_tokens, 11);
        assert_eq!(d.cache_read_tokens, 3);
        assert_eq!(d.cache_write_tokens, 2);
        assert_eq!(d.output_tokens, 9, "delta output is cumulative, last wins");
    }

    #[test]
    fn nonstream_usage_parses_per_dialect() {
        let anthropic = serde_json::to_vec(&json!({
            "usage": {"input_tokens": 5, "output_tokens": 6,
                       "cache_read_input_tokens": 7, "cache_creation_input_tokens": 8}
        }))
        .unwrap();
        let d = parse_usage_json(Dialect::Anthropic, &anthropic).unwrap();
        assert_eq!(
            (d.input_tokens, d.output_tokens, d.cache_read_tokens, d.cache_write_tokens),
            (5, 6, 7, 8)
        );
        let openai = serde_json::to_vec(&json!({
            "usage": {"input_tokens": 100, "input_tokens_details": {"cached_tokens": 40},
                       "output_tokens": 9}
        }))
        .unwrap();
        let d = parse_usage_json(Dialect::OpenAi, &openai).unwrap();
        assert_eq!((d.input_tokens, d.cache_read_tokens, d.output_tokens), (60, 40, 9));
    }
}
