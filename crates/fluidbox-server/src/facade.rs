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
//! Response bytes reach the runner verbatim; request bytes are RE-SERIALIZED
//! from the validated body for BOTH dialects (so what we validated is exactly
//! what we forward — no duplicate-key differential), with codex additionally
//! forced stateless (`store=false`).

use crate::error::{ApiError, ApiResult};
use crate::harness;
use crate::ledger;
use crate::llm_keys;
use crate::state::AppState;
use axum::body::Body;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::Response;
use fluidbox_core::event::{Actor, EventBody};
use fluidbox_core::spec::RunSpec;
use fluidbox_core::usage::{estimate_cost_usd, UsageDelta};
use fluidbox_db::TenantScope;
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

/// Error-shape hint for exits that fire BEFORE the session's dialect is
/// resolved (terminal-session, unknown-harness): the requested suffix is
/// enough — only codex uses v1/responses. Auth/lookup failures upstream of
/// this still use the generic envelope (a runner that can't authenticate
/// never gets far enough for the shape to matter).
fn shape_hint(rest: &str) -> Dialect {
    if rest == "v1/responses" {
        Dialect::OpenAi
    } else {
        Dialect::Anthropic
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

/// Forward an upstream response we had to BUFFER (the tenant-key rejection
/// classifier reads the body before deciding). Same shape the non-streaming path
/// forwards with: verbatim status + bytes, `application/json`. Used only for
/// small auth-error bodies — never a stream.
fn forward_buffered(status: reqwest::StatusCode, body: axum::body::Bytes) -> Response {
    Response::builder()
        .status(StatusCode::from_u16(status.as_u16()).unwrap_or(StatusCode::UNAUTHORIZED))
        .header("content-type", "application/json")
        .body(Body::from(body))
        .unwrap()
}

/// A 503 facade refusal carrying a STABLE machine-readable `code`
/// (`tenant_llm_key_unavailable` / `tenant_llm_keys_required`), dialect-shaped so
/// the runner SDK still parses it. The code rides the dialect's machine-readable
/// slot (Anthropic `error.type`, OpenAI `error.code`) AND the message, so a
/// consumer keys on it regardless of dialect. This is the D7 fail-closed exit: a
/// tenant-key resolution failure, or the forbidden SSO+shared posture, stops the
/// call cold — NEVER a fallback to the shared/master key.
fn facade_refusal(dialect: Dialect, code: &str, message: &str) -> Response {
    let full = format!("{message} ({code})");
    let body = match dialect {
        Dialect::Anthropic => json!({
            "type": "error",
            "error": { "type": code, "message": full }
        }),
        Dialect::OpenAi => json!({
            "error": {
                "message": full,
                "type": "invalid_request_error",
                "param": null,
                "code": code
            }
        }),
    };
    Response::builder()
        .status(StatusCode::SERVICE_UNAVAILABLE)
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .unwrap()
}

/// Is a tool entry a CLIENT-executed (governed) tool for this dialect? Client
/// tools run in the sandbox and cross the permission gate; server-executed
/// tools (web_search, file_search, computer use, code interpreter, MCP
/// passthrough, image generation, …) run UPSTREAM, outside the gate — never
/// allowed through. Allowlist, fail-closed: an unknown type is treated as
/// server-executed.
fn is_client_tool(dialect: Dialect, tool: &Value) -> bool {
    let ty = tool.get("type").and_then(|x| x.as_str());
    match dialect {
        // Anthropic client tools carry no type or "custom"; anything
        // versioned ("web_search_20250305", …) is server-executed.
        Dialect::Anthropic => matches!(ty, None | Some("custom")),
        // Codex's real tools (exec/shell, apply_patch, view_image, plan,
        // goals) are "function" / "custom"; it ALSO bundles "web_search"
        // (server-executed) into every request by construction.
        Dialect::OpenAi => match ty {
            Some("function") | Some("custom") => true,
            // codex 0.144.1 ALWAYS defers MCP tools behind `tool_search`
            // (`tool_search_always_defer_mcp_tools` is baked true, not
            // configurable): the tool list carries this one entry instead of
            // the MCP tools, codex executes the BM25 search LOCALLY
            // (`execution:"client"`), and matches are inlined as ordinary
            // `function` tools on the NEXT call. Stripping it hid every
            // brokered/MCP tool from every codex run. Only the declared
            // client-executed shape passes; execution stays governed — each
            // actual MCP call still crosses the gate at /tools/call.
            Some("tool_search") => tool.get("execution").and_then(|x| x.as_str()) == Some("client"),
            _ => false,
        },
    }
}

/// Remove every server-executed tool entry from `parsed.tools` in place,
/// keeping only client-executed (governed) tools. Returns the count removed.
/// The gate/policy still judge the client tools that remain; this only
/// guarantees no UPSTREAM-executed tool survives into the request.
fn strip_server_tools(dialect: Dialect, parsed: &mut Value) -> usize {
    let Some(tools) = parsed.get_mut("tools").and_then(|t| t.as_array_mut()) else {
        return 0;
    };
    let before = tools.len();
    tools.retain(|t| is_client_tool(dialect, t));
    before - tools.len()
}

/// Request-body screen (model pin + statelessness + Anthropic tool reject).
/// Codex's server-executed tools are handled by STRIPPING (see
/// `strip_server_tools`), not rejecting — codex bundles them into every
/// request, so a reject would break every codex turn.
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
    // Anthropic: a server-executed tool is misconfiguration (the Agent SDK
    // never sends one unless explicitly asked) — reject LOUD. Codex: don't
    // reject here; strip_server_tools sanitizes below.
    if dialect == Dialect::Anthropic {
        if let Some(tools) = parsed.get("tools").and_then(|t| t.as_array()) {
            for t in tools {
                if !is_client_tool(dialect, t) {
                    let ty = t.get("type").and_then(|x| x.as_str());
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
    }
    if dialect == Dialect::OpenAi {
        // Statelessness screen: the facade never lets UPSTREAM server-side
        // state substitute for the audited request body. `store=false` is
        // forced below, so a reference to stored state is either dead (this
        // run stored nothing) or reaches shared-account state OUTSIDE this run
        // on the master credential — refuse it. Covers response chaining
        // (`previous_response_id`), conversation state (`conversation`), and
        // stored prompt templates (`prompt` = {id, version, variables}).
        for field in ["previous_response_id", "conversation", "prompt"] {
            if parsed.get(field).map(|v| !v.is_null()).unwrap_or(false) {
                return Err((
                    StatusCode::UNPROCESSABLE_ENTITY,
                    format!("'{field}' is not supported: the facade is stateless (store=false)"),
                ));
            }
        }
        // An `input` array may carry `{type:"item_reference", id:…}` elements
        // that pull in a prior response's items by id — the array-level twin
        // of `previous_response_id`. Reject any such reference: codex re-sends
        // full inline input under store=false (proven by previous_response_id
        // already being refused without breaking it), so a legitimate
        // stateless turn never contains one.
        if let Some(items) = parsed.get("input").and_then(|v| v.as_array()) {
            if items
                .iter()
                .any(|it| it.get("type").and_then(|t| t.as_str()) == Some("item_reference"))
            {
                return Err((
                    StatusCode::UNPROCESSABLE_ENTITY,
                    "input 'item_reference' is not supported: the facade is stateless (store=false)"
                        .into(),
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

/// Build and send ONE upstream model request with the given credential. Extracted
/// from `messages` so the reactive tenant-key recovery can replay the identical
/// request under a re-provisioned key (see
/// [`llm_keys::recover_rejected_tenant_key`]) — the dialect's auth-header shape
/// lives here, in one place, rather than being duplicated at the retry site.
async fn send_upstream(
    state: &AppState,
    dialect: Dialect,
    upstream: &str,
    headers: &HeaderMap,
    body: axum::body::Bytes,
    upstream_key: &str,
) -> reqwest::Result<reqwest::Response> {
    let mut req = state
        .http
        .post(upstream)
        .body(body)
        .header("content-type", "application/json");
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
                req = req.header("x-api-key", upstream_key);
            } else {
                req = req
                    .header("authorization", format!("Bearer {upstream_key}"))
                    .header("x-api-key", upstream_key);
            }
        }
        Dialect::OpenAi => {
            // Bearer only — the OpenAI dialect never sees x-api-key.
            req = req.header("authorization", format!("Bearer {upstream_key}"));
        }
    }
    req.send().await
}

/// POST /internal/llm/{*rest} — both dialects, one route.
pub async fn messages(
    Path(rest): Path<String>,
    State(state): State<AppState>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> ApiResult<Response> {
    let token = session_token(&headers).ok_or(ApiError::Unauthorized)?;
    let sess_auth = fluidbox_db::session_for_token(&state.pool, &token)
        .await?
        .ok_or(ApiError::Unauthorized)?;
    // Gap 10: model egress is the LLM audience. The sandbox's fake provider key
    // is now the LLM-scoped token ONLY — a runner-control or tool-intent
    // credential can no longer spend the run's model budget. Refused at the auth
    // layer (like an unresolvable token), not as a dialect-shaped body.
    if !crate::auth::audience_allows("llm", &sess_auth.audience) {
        return Err(ApiError::Forbidden("wrong_audience".into()));
    }
    let session_id = sess_auth.session_id;
    let scope = TenantScope::assume(sess_auth.tenant_id);

    let session = fluidbox_db::get_session(&state.pool, scope, session_id)
        .await?
        .ok_or(ApiError::NotFound)?;
    // No model spend for a terminal OR winding-down run — the budget stop and
    // the finalizer both rely on the facade refusing once a run is over.
    if !session.status_enum().accepts_work() {
        return Ok(dialect_error(
            shape_hint(&rest),
            StatusCode::BAD_REQUEST,
            "session is not active",
        ));
    }
    let run_spec: RunSpec = serde_json::from_value(session.run_spec.clone())
        .map_err(|e| ApiError::Internal(format!("bad run_spec: {e}")))?;

    let Some(dialect) = dialect_for(&run_spec.harness) else {
        // create_run refuses unknown harnesses; a row that still gets here
        // fails closed.
        return Ok(dialect_error(
            shape_hint(&rest),
            StatusCode::BAD_REQUEST,
            &format!("run harness '{}' has no LLM dialect", run_spec.harness),
        ));
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
    let totals = fluidbox_db::usage_totals(&state.pool, scope, session_id).await?;
    if let Some(max_cost) = run_spec.budgets.max_cost_usd {
        if totals.cost_usd >= max_cost {
            trigger_budget_stop(
                &state,
                scope,
                session_id,
                "max_cost_usd",
                max_cost,
                totals.cost_usd,
            )
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
                scope,
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

    // Body screen (both dialects parse; both then forward the reserialized
    // validated Value — see the store=false block below).
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

    // Forward the RE-SERIALIZED validated body for BOTH dialects, never the
    // raw request bytes. Validating a parsed Value while forwarding raw bytes
    // opens a duplicate-key differential: a body like {"model":A,"model":B}
    // passes the model/tool screen under serde's last-wins read while an
    // upstream parser might honor the other occurrence — bypassing the model
    // pin and server-tool rejection. Re-serializing guarantees "what we
    // validated" == "what we forward". Codex is additionally forced stateless
    // AND has its server-executed tools stripped (it bundles web_search /
    // tool_search into EVERY request by construction; stripping keeps codex
    // working while removing the ungoverned upstream capability — rejecting
    // would break every codex turn).
    if dialect == Dialect::OpenAi {
        if let Some(obj) = parsed.as_object_mut() {
            obj.insert("store".into(), json!(false));
        }
        let stripped = strip_server_tools(dialect, &mut parsed);
        if stripped > 0 {
            tracing::debug!(
                "facade: stripped {stripped} server-executed tool(s) from the codex request"
            );
        }
    }
    let upstream_body: axum::body::Bytes = serde_json::to_vec(&parsed)
        .map_err(|e| ApiError::Internal(format!("body reserialize: {e}")))?
        .into();

    let upstream = format!(
        "{}/{}",
        state.cfg.llm_upstream_url.trim_end_matches('/'),
        suffix
    );

    // Resolve the outbound credential ONCE, before dialect dispatch (D7). Shared
    // mode presents the deployment key (today's behavior, now explicit); tenant
    // mode resolves/mints the session tenant's LiteLLM virtual key so the master
    // key never rides a model request; SSO+shared is the forbidden hosted posture.
    // Every failure is fail-closed — a 503 with a stable code, NEVER the master
    // key as a fallback.
    let key_source = llm_keys::key_source(state.cfg.llm_key_mode, state.cfg.require_sso);
    let upstream_key: String = match key_source {
        llm_keys::KeySource::Shared => state.cfg.llm_upstream_key.clone(),
        llm_keys::KeySource::Tenant => {
            match llm_keys::ensure_tenant_key(&state, sess_auth.tenant_id).await {
                Ok(k) => k,
                Err(e) => {
                    tracing::warn!(
                        "facade: tenant LLM key unavailable for tenant {}: {e}",
                        sess_auth.tenant_id
                    );
                    return Ok(facade_refusal(
                        dialect,
                        "tenant_llm_key_unavailable",
                        "the tenant's LLM key could not be provisioned",
                    ));
                }
            }
        }
        llm_keys::KeySource::RefuseSsoShared => {
            return Ok(facade_refusal(
                dialect,
                "tenant_llm_keys_required",
                "this deployment requires per-tenant LLM keys (set FLUIDBOX_LLM_KEY_MODE=tenant)",
            ));
        }
    };

    let mut resp = match send_upstream(
        &state,
        dialect,
        &upstream,
        &headers,
        upstream_body.clone(),
        &upstream_key,
    )
    .await
    {
        Ok(r) => r,
        Err(e) => {
            return Ok(dialect_error(
                dialect,
                StatusCode::BAD_GATEWAY,
                &format!("upstream request failed: {e}"),
            ));
        }
    };
    // Reactive tenant-key recovery (tenant mode only). A 401 whose body proves
    // LITELLM'S OWN key check rejected the virtual key we presented — LiteLLM
    // redeployed with a fresh database, or an operator pruned keys — is the one
    // failure nothing else recovers from: a cold cache re-reads the same sealed
    // row, so even a restart keeps 401ing.
    //
    // The proof requirement is the point (review H3). LiteLLM answers 401 for
    // BOTH that and "my own upstream provider credential was refused", and 403 for
    // policy/budget refusals; re-provisioning on all of them let one authenticated
    // tenant amplify a provider outage into unbounded `/key/generate` traffic and
    // unbounded key-table growth. So the small auth-error body is buffered and
    // classified, ambiguity forwards the rejection verbatim, and
    // `recover_rejected_tenant_key` bounds what survives that (stale-rejection
    // compare, durable per-tenant cooldown, CAS, per-replica mint budget).
    //
    // "Classified" now means LiteLLM's OWN proxy-auth structure, not a generic
    // phrase (re-verification, #32): `{"error":{"message":"OpenAI API key not
    // found","type":"auth_error"}}` is provider-originated and no longer qualifies.
    //
    // The replay is still EXACTLY ONCE — a 401 proves the request never executed
    // upstream, the same reasoning as the connector-token reactive 401 in
    // `oauth.rs` — and whatever the replay answers is final.
    if key_source == llm_keys::KeySource::Tenant && resp.status().as_u16() == 401 {
        let status = resp.status();
        let body = match resp.bytes().await {
            Ok(b) => b,
            Err(e) => {
                return Ok(dialect_error(
                    dialect,
                    StatusCode::BAD_GATEWAY,
                    &format!("upstream body read failed: {e}"),
                ));
            }
        };
        if !llm_keys::virtual_key_rejected(key_source, status.as_u16(), &body) {
            // Not our key: an upstream/provider or otherwise unattributable 401.
            // Forward it verbatim — never re-provision on a guess.
            return Ok(forward_buffered(status, body));
        }
        tracing::warn!(
            tenant = %sess_auth.tenant_id,
            "facade: LiteLLM rejected the tenant's virtual key — attempting recovery"
        );
        let fresh =
            match llm_keys::recover_rejected_tenant_key(&state, sess_auth.tenant_id, &upstream_key)
                .await
            {
                llm_keys::KeyRecovery::Retry(k) => k,
                llm_keys::KeyRecovery::Refused(reason) => {
                    tracing::warn!(
                        tenant = %sess_auth.tenant_id,
                        reason,
                        "facade: tenant LLM key not re-provisioned — forwarding the rejection"
                    );
                    return Ok(forward_buffered(status, body));
                }
            };
        match send_upstream(&state, dialect, &upstream, &headers, upstream_body, &fresh).await {
            Ok(r) => resp = r,
            Err(e) => {
                return Ok(dialect_error(
                    dialect,
                    StatusCode::BAD_GATEWAY,
                    &format!("upstream request failed: {e}"),
                ));
            }
        }
    }
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
        let bytes = match resp.bytes().await {
            Ok(b) => b,
            Err(e) => {
                return Ok(dialect_error(
                    dialect,
                    StatusCode::BAD_GATEWAY,
                    &format!("upstream body read failed: {e}"),
                ));
            }
        };
        if status.is_success() {
            if let Some(usage) = parse_usage_json(dialect, &bytes) {
                record_usage(&state, scope, session_id, &model_hint, usage, None).await;
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
            record_usage(
                &state2,
                scope,
                session_id,
                &model2,
                meter.into_delta(),
                None,
            )
            .await;
        } else {
            // Still record a zero-usage marker so we know a call happened.
            ledger::record(
                &state2,
                scope,
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
    scope: TenantScope,
    session_id: Uuid,
    budget: &str,
    limit: f64,
    spent: f64,
) {
    ledger::record(
        state,
        scope,
        session_id,
        Actor::System,
        EventBody::BudgetExceeded {
            budget: budget.into(),
            limit: format!("{limit}"),
            spent: format!("{spent:.4}"),
        },
    )
    .await;
    if let Ok(Some(session)) = fluidbox_db::get_session(&state.pool, scope, session_id).await {
        let state2 = state.clone();
        let reason = format!("{budget} budget exceeded");
        tokio::spawn(async move {
            // Forced stop (runner is live → quiesce first). Retried with
            // backoff: the facade re-enforces on the runner's next request,
            // but an idle runner makes none — this task must converge alone.
            for attempt in 0..5u32 {
                match crate::orchestrator::finalize_forced(
                    &state2,
                    session.id,
                    "budget_exceeded",
                    &reason,
                )
                .await
                {
                    crate::orchestrator::FinalizeStart::DbError => {
                        tokio::time::sleep(std::time::Duration::from_secs(10u64 << attempt.min(3)))
                            .await;
                    }
                    _ => return,
                }
            }
            tracing::error!(
                "budget finalize for {} did not persist after retries",
                session.id
            );
        });
    }
}

async fn record_usage(
    state: &AppState,
    scope: TenantScope,
    session_id: Uuid,
    model: &str,
    usage: UsageDelta,
    external_id: Option<&str>,
) {
    let cost = estimate_cost_usd(model, &usage);
    fluidbox_db::add_usage(
        &state.pool,
        scope,
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
        scope,
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

/// A single SSE line we care about (usage JSON) is tiny; anything past this
/// with no newline is a pathological or hostile upstream. Cap the retained
/// partial so a never-terminated stream can't grow memory unbounded during
/// the post-disconnect drain (whose wall-clock is bounded by the shared
/// reqwest client timeout).
const MAX_PENDING_LINE: usize = 512 * 1024;

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
        // An over-long unterminated tail can't be a usage line — drop it to
        // bound memory (we resync at the next newline).
        if self.pending.len() > MAX_PENDING_LINE {
            self.pending.clear();
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

    #[tokio::test]
    async fn facade_refusal_is_503_with_machine_code_per_dialect() {
        // Both D7 refusal codes, both dialects: status 503, code in the dialect's
        // machine-readable slot AND the message (never the master key as fallback).
        for (dialect, code) in [
            (Dialect::Anthropic, "tenant_llm_keys_required"),
            (Dialect::OpenAi, "tenant_llm_key_unavailable"),
        ] {
            let resp = facade_refusal(dialect, code, "nope");
            assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
            let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
                .await
                .unwrap();
            let v: Value = serde_json::from_slice(&bytes).unwrap();
            match dialect {
                Dialect::Anthropic => {
                    assert_eq!(v["type"], "error");
                    assert_eq!(v["error"]["type"], code);
                }
                Dialect::OpenAi => {
                    assert_eq!(v["error"]["code"], code);
                }
            }
            assert!(v["error"]["message"].as_str().unwrap().contains(code));
        }
    }

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
        assert_eq!(
            resolve_suffix(Dialect::Anthropic, "v1/chat/completions"),
            None
        );
        assert_eq!(resolve_suffix(Dialect::Anthropic, "key/info"), None);
        assert_eq!(
            resolve_suffix(Dialect::Anthropic, "v1/messages/../key/info"),
            None
        );
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
    fn anthropic_server_tools_rejected_client_tools_pass() {
        // Anthropic: no type / "custom" = client tools; a server tool is
        // misconfiguration → reject LOUD (the SDK never sends one unasked).
        let ok = json!({"model": "m", "tools": [
            {"name": "Bash", "input_schema": {}},
            {"type": "custom", "name": "Edit", "input_schema": {}}
        ]});
        assert!(validate_body(Dialect::Anthropic, "m", &ok).is_ok());
        let bad = json!({"model": "m", "tools": [
            {"type": "web_search_20250305", "name": "web_search"}
        ]});
        assert!(validate_body(Dialect::Anthropic, "m", &bad).is_err());
    }

    #[test]
    fn openai_server_tools_are_stripped_not_rejected() {
        // Codex bundles web_search into EVERY request, so the facade must
        // STRIP server tools (not reject) — the request itself validates.
        let body = json!({"model": "m", "tools": [
            {"type": "function", "name": "shell_command"},
            {"type": "custom", "name": "apply_patch"},
            {"type": "function", "name": "view_image"},
            {"type": "web_search", "name": null},
            {"type": "tool_search", "name": null}
        ]});
        assert!(
            validate_body(Dialect::OpenAi, "m", &body).is_ok(),
            "codex body validates"
        );
        let mut parsed = body.clone();
        let stripped = strip_server_tools(Dialect::OpenAi, &mut parsed);
        assert_eq!(
            stripped, 2,
            "web_search + execution-less tool_search stripped"
        );
        let kept: Vec<&str> = parsed["tools"]
            .as_array()
            .unwrap()
            .iter()
            .map(|t| t["type"].as_str().unwrap())
            .collect();
        assert_eq!(kept, vec!["function", "custom", "function"]);
        // An unknown/future server tool type is stripped too (fail-closed).
        let mut p2 =
            json!({"tools": [{"type": "image_generation"}, {"type":"function","name":"x"}]});
        assert_eq!(strip_server_tools(Dialect::OpenAi, &mut p2), 1);
        // A body with no tools array is a no-op.
        let mut none = json!({"model": "m"});
        assert_eq!(strip_server_tools(Dialect::OpenAi, &mut none), 0);
    }

    #[test]
    fn openai_client_executed_tool_search_survives_the_strip() {
        // codex 0.144.1 always defers MCP tools behind `tool_search`
        // (`tool_search_always_defer_mcp_tools` baked true) and executes the
        // search LOCALLY (`execution:"client"`). Stripping that entry hid
        // every brokered/MCP tool from codex runs — the model could never
        // discover them. The client-executed shape must survive; web_search
        // (upstream) and a server-executed tool_search must not.
        let mut body = json!({"tools": [
            {"type": "tool_search", "execution": "client", "description": "…"},
            {"type": "tool_search", "execution": "server"},
            {"type": "tool_search"},
            {"type": "web_search", "external_web_access": true},
            {"type": "function", "name": "shell_command"}
        ]});
        let stripped = strip_server_tools(Dialect::OpenAi, &mut body);
        assert_eq!(
            stripped, 3,
            "server/execution-less tool_search + web_search stripped"
        );
        let kept: Vec<&str> = body["tools"]
            .as_array()
            .unwrap()
            .iter()
            .map(|t| t["type"].as_str().unwrap())
            .collect();
        assert_eq!(kept, vec!["tool_search", "function"]);
        // Anthropic dialect is untouched by the codex carve-out: a
        // client-executed tool_search is still not an Anthropic client tool.
        let mut a = json!({"tools": [{"type": "tool_search", "execution": "client"}]});
        assert_eq!(strip_server_tools(Dialect::Anthropic, &mut a), 1);
    }

    #[test]
    fn codex_statelessness_screen() {
        let bad = json!({"model": "m", "previous_response_id": "resp_123"});
        assert!(validate_body(Dialect::OpenAi, "m", &bad).is_err());
        let bad = json!({"model": "m", "conversation": "conv_1"});
        assert!(validate_body(Dialect::OpenAi, "m", &bad).is_err());
        let bad = json!({"model": "m", "background": true});
        assert!(validate_body(Dialect::OpenAi, "m", &bad).is_err());
        // Stored prompt template reference — reaches shared-account state.
        let bad = json!({"model": "m", "prompt": {"id": "pmpt_abc"}});
        assert!(validate_body(Dialect::OpenAi, "m", &bad).is_err());
        // input[] item_reference — the array-level previous_response_id.
        let bad = json!({"model": "m", "input": [
            {"type": "message", "role": "user", "content": "hi"},
            {"type": "item_reference", "id": "item_xyz"}
        ]});
        assert!(validate_body(Dialect::OpenAi, "m", &bad).is_err());
        // null is as-absent (serde default emission).
        let ok = json!({"model": "m", "previous_response_id": null, "prompt": null});
        assert!(validate_body(Dialect::OpenAi, "m", &ok).is_ok());
        // A NORMAL stateless codex turn (inline message input, no references)
        // must still pass — the screen only rejects upstream-state pulls.
        let ok = json!({"model": "m", "input": [
            {"type": "message", "role": "user", "content": [{"type": "input_text", "text": "do the task"}]},
            {"type": "function_call_output", "call_id": "c1", "output": "ok"}
        ]});
        assert!(validate_body(Dialect::OpenAi, "m", &ok).is_ok());
        // The same fields are fine for the anthropic dialect (it never
        // sends them; screen is per-dialect). `prompt` is not a reserved
        // Anthropic field, so its presence must not trip the Anthropic path.
        let ok = json!({"model": "m", "prompt": {"id": "x"}});
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
        dec.feed(
            b"pleted\",\"response\":{\"usage\":{\"input_tokens\":10,",
            &mut |l: &str| lines.push(l.to_string()),
        );
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
    fn reserialize_collapses_duplicate_keys_so_validation_matches_forward() {
        // serde_json is last-wins on duplicate keys. The facade validates the
        // parsed Value, then FORWARDS the re-serialized Value — so the
        // upstream can only ever see what we validated. Prove the round-trip
        // collapses a duplicate `model` to the last (validated) occurrence.
        let raw = br#"{"model":"claude-opus-4-8","model":"claude-haiku-4-5","messages":[]}"#;
        let parsed: Value = serde_json::from_slice(raw).unwrap();
        assert_eq!(parsed.get("model").unwrap(), "claude-haiku-4-5");
        // Validation sees haiku; if the run is pinned to haiku it passes, and
        // the forwarded bytes contain exactly one model = haiku.
        assert!(validate_body(Dialect::Anthropic, "claude-haiku-4-5", &parsed).is_ok());
        let forwarded = serde_json::to_vec(&parsed).unwrap();
        let reparsed: Value = serde_json::from_slice(&forwarded).unwrap();
        assert_eq!(reparsed.get("model").unwrap(), "claude-haiku-4-5");
        assert_eq!(reparsed.as_object().unwrap().get("model").iter().count(), 1);
    }

    #[test]
    fn sse_decoder_caps_unterminated_buffer() {
        let mut dec = SseLineDecoder::default();
        // A megabyte with no newline must not be retained.
        let junk = vec![b'x'; MAX_PENDING_LINE + 1024];
        dec.feed(&junk, &mut |_l: &str| {});
        assert!(dec.pending.len() <= MAX_PENDING_LINE);
        // After the cap resets, a following complete line still parses.
        let mut seen = Vec::new();
        dec.feed(b"\ndata: [DONE]\n", &mut |l: &str| seen.push(l.to_string()));
        assert!(seen.iter().any(|l| l.contains("[DONE]")));
    }

    #[test]
    fn sse_decoder_finish_flushes_unterminated_tail() {
        let mut dec = SseLineDecoder::default();
        let mut lines: Vec<String> = Vec::new();
        dec.feed(
            b"data: {\"type\":\"message_delta\",\"usage\":{\"output_tokens\":7}}",
            &mut |l: &str| lines.push(l.to_string()),
        );
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
            (
                d.input_tokens,
                d.output_tokens,
                d.cache_read_tokens,
                d.cache_write_tokens
            ),
            (5, 6, 7, 8)
        );
        let openai = serde_json::to_vec(&json!({
            "usage": {"input_tokens": 100, "input_tokens_details": {"cached_tokens": 40},
                       "output_tokens": 9}
        }))
        .unwrap();
        let d = parse_usage_json(Dialect::OpenAi, &openai).unwrap();
        assert_eq!(
            (d.input_tokens, d.cache_read_tokens, d.output_tokens),
            (60, 40, 9)
        );
    }
}
