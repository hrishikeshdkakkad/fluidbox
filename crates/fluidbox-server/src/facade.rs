//! The LLM session facade. The sandbox's ANTHROPIC_API_KEY is its fluidbox
//! session token; this endpoint authenticates the session, enforces the
//! budget stop, swaps in the real upstream credential, forwards to the
//! gateway (LiteLLM or, in fallback, api.anthropic.com), and tees the SSE
//! stream to meter usage into the ledger. Bytes reach the runner verbatim.

use crate::error::{ApiError, ApiResult};
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
use uuid::Uuid;

fn session_token(headers: &HeaderMap) -> Option<String> {
    // The Agent SDK sends the key as `x-api-key` (Anthropic native) and/or
    // `authorization: Bearer`. Accept either.
    if let Some(k) = headers.get("x-api-key").and_then(|v| v.to_str().ok()) {
        return Some(k.to_string());
    }
    headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .map(|s| s.to_string())
}

/// POST /internal/llm/v1/messages  (the Agent SDK appends /v1/messages to
/// ANTHROPIC_BASE_URL). We accept the whole suffix.
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

    // Budget stop: refuse further model calls once cost/token budget is spent.
    let totals = fluidbox_db::usage_totals(&state.pool, session_id).await?;
    if let Some(max_cost) = run_spec.budgets.max_cost_usd {
        if totals.cost_usd >= max_cost {
            trigger_budget_stop(&state, session_id, "max_cost_usd", max_cost, totals.cost_usd).await;
            return Err(ApiError::BadRequest("cost budget exhausted".into()));
        }
    }
    if let Some(max_tokens) = run_spec.budgets.max_tokens {
        let used = (totals.input_tokens + totals.output_tokens) as u64;
        if used >= max_tokens {
            trigger_budget_stop(&state, session_id, "max_tokens", max_tokens as f64, used as f64).await;
            return Err(ApiError::BadRequest("token budget exhausted".into()));
        }
    }

    // Build the upstream request. In LiteLLM mode we authenticate with the
    // master key; in fallback (direct Anthropic) with the real Anthropic key.
    let suffix = if rest.is_empty() { "v1/messages".to_string() } else { rest };
    let upstream = format!("{}/{}", state.cfg.llm_upstream_url.trim_end_matches('/'), suffix);

    let mut req = state.http.post(&upstream).body(body.clone());
    // Forward version + beta headers verbatim (native Anthropic contract).
    if let Some(v) = headers.get("anthropic-version").and_then(|h| h.to_str().ok()) {
        req = req.header("anthropic-version", v);
    } else {
        req = req.header("anthropic-version", "2023-06-01");
    }
    if let Some(b) = headers.get("anthropic-beta").and_then(|h| h.to_str().ok()) {
        req = req.header("anthropic-beta", b);
    }
    req = req.header("content-type", "application/json");
    if state.cfg.llm_upstream_is_anthropic {
        req = req.header("x-api-key", &state.cfg.llm_upstream_key);
    } else {
        req = req
            .header("authorization", format!("Bearer {}", state.cfg.llm_upstream_key))
            .header("x-api-key", &state.cfg.llm_upstream_key);
    }

    let resp = req.send().await.map_err(|e| ApiError::Internal(format!("upstream: {e}")))?;
    let status = resp.status();
    let is_stream = resp
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.contains("event-stream"))
        .unwrap_or(false);

    let model_hint = extract_model(&body).unwrap_or_else(|| run_spec.model.clone());

    if !is_stream {
        // Non-streaming: read fully, meter, forward.
        let bytes = resp
            .bytes()
            .await
            .map_err(|e| ApiError::Internal(format!("upstream body: {e}")))?;
        if status.is_success() {
            if let Some(usage) = parse_usage_json(&bytes) {
                record_usage(&state, session_id, &model_hint, usage, None).await;
            }
        }
        let mut builder = Response::builder().status(status);
        builder = builder.header("content-type", "application/json");
        return Ok(builder.body(Body::from(bytes)).unwrap());
    }

    // Streaming: tee bytes verbatim to the runner while accumulating usage.
    let state2 = state.clone();
    let model2 = model_hint.clone();
    let upstream_status = StatusCode::from_u16(status.as_u16()).unwrap_or(StatusCode::OK);

    let (tx, rx) = tokio::sync::mpsc::channel::<Result<axum::body::Bytes, std::io::Error>>(64);
    tokio::spawn(async move {
        let mut acc = UsageAccumulator::default();
        let mut stream = resp.bytes_stream();
        let mut buf = Vec::new();
        while let Some(chunk) = stream.next().await {
            match chunk {
                Ok(bytes) => {
                    buf.extend_from_slice(&bytes);
                    acc.feed(&buf);
                    buf.clear();
                    if tx.send(Ok(bytes)).await.is_err() {
                        break; // runner hung up
                    }
                }
                Err(e) => {
                    let _ = tx.send(Err(std::io::Error::other(e))).await;
                    break;
                }
            }
        }
        // Meter on stream end.
        if acc.any() {
            record_usage(&state2, session_id, &model2, acc.into_delta(), None).await;
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

async fn trigger_budget_stop(state: &AppState, session_id: Uuid, budget: &str, limit: f64, spent: f64) {
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
            crate::orchestrator::finalize(&state2, &session, "budget_exceeded", Some(&reason)).await;
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

fn extract_model(body: &[u8]) -> Option<String> {
    let v: serde_json::Value = serde_json::from_slice(body).ok()?;
    v.get("model").and_then(|m| m.as_str()).map(|s| s.to_string())
}

fn parse_usage_json(body: &[u8]) -> Option<UsageDelta> {
    let v: serde_json::Value = serde_json::from_slice(body).ok()?;
    let u = v.get("usage")?;
    Some(usage_from_value(u))
}

fn usage_from_value(u: &serde_json::Value) -> UsageDelta {
    let g = |k: &str| u.get(k).and_then(|x| x.as_u64()).unwrap_or(0);
    UsageDelta {
        input_tokens: g("input_tokens"),
        output_tokens: g("output_tokens"),
        cache_read_tokens: g("cache_read_input_tokens"),
        cache_write_tokens: g("cache_creation_input_tokens"),
    }
}

/// Accumulates usage from an Anthropic SSE stream. `message_start` carries
/// input + cache tokens; `message_delta` carries the running output count.
#[derive(Default)]
struct UsageAccumulator {
    input: u64,
    output: u64,
    cache_read: u64,
    cache_write: u64,
    seen: bool,
}

impl UsageAccumulator {
    fn feed(&mut self, bytes: &[u8]) {
        let text = String::from_utf8_lossy(bytes);
        for line in text.lines() {
            let line = line.trim();
            let Some(data) = line.strip_prefix("data:") else { continue };
            let data = data.trim();
            if data.is_empty() || data == "[DONE]" {
                continue;
            }
            let Ok(v) = serde_json::from_str::<serde_json::Value>(data) else { continue };
            match v.get("type").and_then(|t| t.as_str()) {
                Some("message_start") => {
                    if let Some(u) = v.get("message").and_then(|m| m.get("usage")) {
                        let d = usage_from_value(u);
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
    }

    fn any(&self) -> bool {
        self.seen
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
