//! The internal gateway (per-session token). The runner talks only to this.
//!
//! ONE server-side gate decides every tool call (`decide_tool_call`):
//! budget ceiling → capability availability (the frozen RunSpec set) →
//! policy verdict + trust-tier floor → approval machinery. `/permission`
//! runs it for sandbox/built-in tools (the runner's canUseTool);
//! `/tools/call` runs it for brokered tools and then executes them
//! control-plane-side — the runner never calls `/permission` for those, so
//! each call is decided exactly once, always server-side. A runner that
//! skips its callback changes nothing: the broker gates regardless.

use crate::auth::SessionAuth;
use crate::error::{ApiError, ApiResult};
use crate::ledger;
use crate::orchestrator;
use crate::state::AppState;
use axum::extract::State;
use axum::Json;
use fluidbox_core::capability::{self, CapabilityServer};
use fluidbox_core::event::{digest_json, Actor, EventBody};
use fluidbox_core::policy::{EvaluationOutcome, Policy, ToolCallRequest, Verdict};
use fluidbox_core::spec::RunSpec;
use fluidbox_core::state::SessionStatus;
use serde::Deserialize;
use serde_json::{json, Value};
use std::time::Duration;

/// Outcome of the shared gate. `message` carries the deny reason (or the
/// approval note) for the caller's wire shape.
struct GateDecision {
    allowed: bool,
    message: Option<String>,
}

impl GateDecision {
    fn allow() -> Self {
        Self {
            allowed: true,
            message: None,
        }
    }
    fn deny(message: impl Into<String>) -> Self {
        Self {
            allowed: false,
            message: Some(message.into()),
        }
    }
}

/// The heart of the system: one decision per tool call, made server-side
/// against the FROZEN RunSpec (never live config). Idempotent by
/// tool_call_id through the approvals table, so retries re-attach instead
/// of re-asking.
async fn decide_tool_call(
    state: &AppState,
    session: &fluidbox_db::SessionRow,
    run_spec: &RunSpec,
    tool_call_id: &str,
    tool: &str,
    input: &Value,
) -> ApiResult<GateDecision> {
    let policy: Policy = run_spec.policy_snapshot.clone();

    // ── Intent registration + digest binding (Phase 6 hardening). One
    // persistent row per (session, tool_call_id) is the budget's counting
    // unit, the idempotency anchor, AND the digest binding: a reused id
    // must carry the SAME tool + input digest — a mismatch is a protocol
    // violation that hard-denies without ever touching the stored verdict.
    let digest = digest_json(input);
    let (intent, inserted) = fluidbox_db::register_tool_intent(
        &state.pool,
        session.id,
        tool_call_id,
        tool,
        &summarize(tool, input),
        &digest,
    )
    .await?;
    if inserted {
        // The server (not the runner) writes the canonical tool.requested —
        // exactly once per intent. Runner-posted copies are dropped at
        // ingest; budget parity never trusts runner cooperation.
        ledger::record(
            state,
            session.id,
            Actor::Agent,
            EventBody::ToolRequested {
                tool_call_id: tool_call_id.to_string(),
                tool: tool.to_string(),
                summary: summarize(tool, input),
                input_digest: digest.clone(),
            },
        )
        .await;
    } else {
        let tool_mismatch = intent.tool != tool;
        // Fail CLOSED: a stored NULL digest (legacy or otherwise) is a
        // mismatch, never a wildcard that lets a row inherit a verdict for
        // arbitrary input.
        let digest_mismatch = intent.input_digest.as_deref() != Some(digest.as_str());
        if tool_mismatch || digest_mismatch {
            ledger::record(
                state,
                session.id,
                Actor::System,
                EventBody::ToolDecision {
                    tool_call_id: tool_call_id.to_string(),
                    tool: tool.to_string(),
                    verdict: "deny".into(),
                    source: "protocol_violation".into(),
                    original_verdict: None,
                    reason: Some(format!(
                        "tool_call_id reused with different content (first seen as '{}'); \
                         a reused id never inherits a verdict",
                        intent.tool
                    )),
                },
            )
            .await;
            return Ok(GateDecision::deny(
                "tool_call_id reused with a different tool or input",
            ));
        }
        // Faithful retry: a decided intent re-attaches to its recorded
        // verdict — no re-evaluation, no duplicate ledger events.
        match intent.status.as_str() {
            "auto_allowed" | "approved_once" | "approved_session" => {
                return Ok(GateDecision::allow());
            }
            "auto_denied" | "denied" | "expired" => {
                return Ok(GateDecision::deny("not approved"));
            }
            // 'intent' (a crash between registration and verdict) or
            // 'pending' (an approval wait in flight) — run the gate; the
            // approval path re-attaches to the pending row.
            _ => {}
        }
    }

    // Budget: tool-call ceiling enforced at the gate. Counts unique intents
    // (this call's registration included). CAS the verdict FIRST — only the
    // winner ledgers the overage and finalizes the session; a concurrent
    // loser adopts the durable outcome (never a second finalize or a deny
    // that contradicts an already-recorded verdict).
    if let Some(max) = run_spec.budgets.max_tool_calls {
        let used = fluidbox_db::tool_call_count(&state.pool, session.id).await?;
        if used as u64 > max {
            if fluidbox_db::record_intent_verdict(&state.pool, intent.id, "auto_denied").await? {
                ledger::record(
                    state,
                    session.id,
                    Actor::System,
                    EventBody::BudgetExceeded {
                        budget: "max_tool_calls".into(),
                        limit: max.to_string(),
                        spent: used.to_string(),
                    },
                )
                .await;
                let session_clone = session.clone();
                let state2 = state.clone();
                tokio::spawn(async move {
                    orchestrator::finalize(
                        &state2,
                        &session_clone,
                        "budget_exceeded",
                        Some("tool-call budget exceeded"),
                    )
                    .await;
                });
                return Ok(GateDecision::deny("tool-call budget exceeded"));
            }
            return adopt_terminal_or_deny(state, intent.id).await;
        }
    }

    // Capability availability (design §8): an mcp__* call must name a tool
    // in the run's FROZEN capability set. Attach ≠ allow — but not-attached
    // = unavailable, whatever the policy says. This is also the rug-pull
    // defense: a tool the live server started advertising after the
    // photograph simply does not exist for this run.
    if let Some(reason) = capability::capability_denial(&run_spec.capabilities, tool) {
        // CAS the verdict FIRST; only the handler that owns the decision
        // emits the ledger event (concurrent duplicates of a deterministic
        // deny neither double-ledger nor contradict each other).
        if fluidbox_db::record_intent_verdict(&state.pool, intent.id, "auto_denied").await? {
            ledger::record(
                state,
                session.id,
                Actor::System,
                EventBody::ToolDecision {
                    tool_call_id: tool_call_id.to_string(),
                    tool: tool.to_string(),
                    verdict: "deny".into(),
                    source: "capability".into(),
                    original_verdict: None,
                    reason: Some(reason.clone()),
                },
            )
            .await;
            return Ok(GateDecision::deny(reason));
        }
        // Lost the CAS to a concurrent handler for the same intent. A
        // capability denial is deterministic on the frozen set, so the
        // durable outcome is the matching terminal deny — adopt it.
        return adopt_terminal_or_deny(state, intent.id).await;
    }

    let tool_req = ToolCallRequest {
        tool: tool.to_string(),
        input: input.clone(),
    };
    let outcome: EvaluationOutcome = policy.evaluate(&tool_req, run_spec.autonomy);

    // Trust-tier floor (design §7.3): fork/untrusted event sources run hard
    // read-only. Applied ABOVE the policy verdict and BEFORE the approval
    // machinery — no policy, subscription, or human approval can widen past
    // it. Both the tier denial and the policy's own verdict are ledgered.
    if run_spec.trust_tier == fluidbox_core::spec::TrustTier::ReadOnly {
        if let Some(reason) = fluidbox_core::policy::read_only_denial(&tool_req) {
            if fluidbox_db::record_intent_verdict(&state.pool, intent.id, "auto_denied").await? {
                ledger::record(
                    state,
                    session.id,
                    Actor::System,
                    EventBody::ToolDecision {
                        tool_call_id: tool_call_id.to_string(),
                        tool: tool.to_string(),
                        verdict: "deny".into(),
                        source: "trust_tier".into(),
                        original_verdict: Some(outcome.original.name().into()),
                        reason: Some(reason.clone()),
                    },
                )
                .await;
                return Ok(GateDecision::deny(reason));
            }
            return adopt_terminal_or_deny(state, intent.id).await;
        }
    }

    match &outcome.effective {
        Verdict::Allow => {
            if fluidbox_db::record_intent_verdict(&state.pool, intent.id, "auto_allowed").await? {
                emit_decision(state, session.id, tool_call_id, tool, &outcome, "allow", None).await;
                Ok(GateDecision::allow())
            } else {
                adopt_terminal_or_deny(state, intent.id).await
            }
        }
        Verdict::Deny { reason } => {
            if fluidbox_db::record_intent_verdict(&state.pool, intent.id, "auto_denied").await? {
                emit_decision(state, session.id, tool_call_id, tool, &outcome, "deny", Some(reason))
                    .await;
                Ok(GateDecision::deny(reason.clone()))
            } else {
                adopt_terminal_or_deny(state, intent.id).await
            }
        }
        Verdict::RequireApproval {
            risk,
            ttl_secs,
            scope,
            scope_key,
        } => {
            // Session-scope grant already given for this key? Adopt the
            // durable outcome if a concurrent handler moved the row first —
            // including a wait-join if that handler promoted it to pending
            // (the narrow grant-lands-mid-flight race).
            if fluidbox_db::has_session_grant(&state.pool, session.id, scope_key).await? {
                if fluidbox_db::record_intent_verdict(&state.pool, intent.id, "auto_allowed").await?
                {
                    emit_decision(
                        state,
                        session.id,
                        tool_call_id,
                        tool,
                        &outcome,
                        "allow",
                        Some("session-approved"),
                    )
                    .await;
                    return Ok(GateDecision::allow());
                }
                let row = fluidbox_db::get_approval(&state.pool, intent.id)
                    .await?
                    .ok_or(ApiError::NotFound)?;
                if row.status == "pending" {
                    return await_pending_decision(
                        state,
                        session.id,
                        row,
                        tool_call_id,
                        tool,
                        &outcome,
                    )
                    .await;
                }
                return Ok(decision_from_status(&row.status));
            }

            let scope_str = match scope {
                fluidbox_core::policy::ApprovalScope::Once => "once",
                fluidbox_core::policy::ApprovalScope::Session => "session",
            };
            // Promote the registered intent into the human approval
            // lifecycle. None = a concurrent handler already promoted (or a
            // verdict landed) — re-read and act on the current status.
            let promoted = fluidbox_db::promote_intent_to_pending(
                &state.pool,
                intent.id,
                risk.as_deref(),
                scope_str,
                scope_key,
                *ttl_secs as i64,
            )
            .await?;
            let newly_pending = promoted.is_some();
            let approval = match promoted {
                Some(row) => row,
                None => fluidbox_db::get_approval(&state.pool, intent.id)
                    .await?
                    .ok_or(ApiError::NotFound)?,
            };

            // Restart / lost-the-promotion case: already decided.
            if approval.status != "pending" {
                return Ok(decision_from_status(&approval.status));
            }

            if newly_pending {
                ledger::record(
                    state,
                    session.id,
                    Actor::System,
                    EventBody::ApprovalRequested {
                        approval_id: approval.id,
                        tool_call_id: tool_call_id.to_string(),
                        tool: tool.to_string(),
                        summary: approval.summary.clone(),
                        risk: risk.clone(),
                        expires_at: approval.expires_at,
                    },
                )
                .await;
                fluidbox_db::transition_session(
                    &state.pool,
                    session.id,
                    SessionStatus::AwaitingApproval,
                    Some("awaiting human approval"),
                )
                .await
                .ok();
            }

            await_pending_decision(state, session.id, approval, tool_call_id, tool, &outcome).await
        }
    }
}

/// After losing a verdict CAS on a DETERMINISTIC gate path (capability /
/// trust-tier / policy allow|deny — every concurrent handler for the same
/// intent computes the identical verdict), adopt the durable terminal
/// outcome the winner recorded. A row that is somehow still non-terminal
/// fails safe to deny.
async fn adopt_terminal_or_deny(
    state: &AppState,
    intent_id: uuid::Uuid,
) -> ApiResult<GateDecision> {
    let row = fluidbox_db::get_approval(&state.pool, intent_id)
        .await?
        .ok_or(ApiError::NotFound)?;
    Ok(decision_from_status(&row.status))
}

/// Block on a pending approval row until it is decided (DB is truth; the
/// Notify only wakes us early), then record the human decision and return
/// it. Shared by the promoter and any handler that adopts a pending row.
async fn await_pending_decision(
    state: &AppState,
    session_id: uuid::Uuid,
    approval: fluidbox_db::ApprovalRow,
    tool_call_id: &str,
    tool: &str,
    outcome: &EvaluationOutcome,
) -> ApiResult<GateDecision> {
    let notifier = state.approvals.notifier(approval.id).await;
    let final_status = loop {
        let cur = fluidbox_db::get_approval(&state.pool, approval.id)
            .await?
            .ok_or(ApiError::NotFound)?;
        if cur.status != "pending" {
            break cur.status;
        }
        if cur.expires_at <= chrono::Utc::now() {
            // Timeout → auto-deny (fail-safe), but as a CAS: if a human
            // decision won the row between our read and here, decide_approval
            // affects nothing — adopt the human's verdict rather than
            // fabricating a deny that contradicts the durable row.
            match fluidbox_db::decide_approval(&state.pool, approval.id, "denied", "timeout")
                .await?
            {
                Some(_) => break "denied".to_string(),
                None => {
                    let row = fluidbox_db::get_approval(&state.pool, approval.id)
                        .await?
                        .ok_or(ApiError::NotFound)?;
                    break row.status;
                }
            }
        }
        let until_expiry = (cur.expires_at - chrono::Utc::now())
            .to_std()
            .unwrap_or(Duration::from_secs(1));
        let tick = until_expiry.min(Duration::from_secs(2));
        tokio::select! {
            _ = notifier.notified() => {}
            _ = tokio::time::sleep(tick) => {}
        }
    };
    state.approvals.forget(approval.id).await;

    let decided_by = fluidbox_db::get_approval(&state.pool, approval.id)
        .await?
        .and_then(|a| a.decided_by)
        .unwrap_or_else(|| "system".into());
    ledger::record(
        state,
        session_id,
        Actor::Human,
        EventBody::ApprovalDecided {
            approval_id: approval.id,
            tool_call_id: tool_call_id.to_string(),
            decision: final_status.clone(),
            decided_by: decided_by.clone(),
        },
    )
    .await;

    let allowed = final_status == "approved_once" || final_status == "approved_session";
    emit_decision(
        state,
        session_id,
        tool_call_id,
        tool,
        outcome,
        if allowed { "allow" } else { "deny" },
        Some(&format!("human:{decided_by}")),
    )
    .await;

    maybe_resume(state, session_id).await;
    Ok(decision_from_status(&final_status))
}

#[derive(Deserialize)]
pub struct PermissionReq {
    pub tool_call_id: String,
    pub tool: String,
    #[serde(default)]
    pub input: Value,
}

/// The canUseTool callback endpoint. Blocks (supervised) until a human
/// decides or the approval expires; answers instantly (autonomous) with the
/// policy's pre-resolved verdict. Idempotent by tool_call_id.
pub async fn permission(
    auth: SessionAuth,
    State(state): State<AppState>,
    Json(req): Json<PermissionReq>,
) -> ApiResult<Json<Value>> {
    let session = fluidbox_db::get_session(&state.pool, auth.session_id)
        .await?
        .ok_or(ApiError::NotFound)?;
    // A terminal session never gets a fresh decision — the primary guard,
    // independent of token revocation (which is best-effort defense in depth).
    if session.status_enum().is_terminal() {
        return Ok(Json(json!({
            "decision": "deny",
            "message": "session is not active",
        })));
    }
    let run_spec: RunSpec = serde_json::from_value(session.run_spec.clone())
        .map_err(|e| ApiError::Internal(format!("bad run_spec: {e}")))?;
    let decision = decide_tool_call(
        &state,
        &session,
        &run_spec,
        &req.tool_call_id,
        &req.tool,
        &req.input,
    )
    .await?;
    Ok(Json(if decision.allowed {
        json!({ "decision": "allow" })
    } else {
        json!({
            "decision": "deny",
            "message": decision.message.unwrap_or_else(|| "not approved".into()),
        })
    }))
}

// ─── Brokered tool execution (design §8.3 class 2) ────────────────────────

#[derive(Deserialize)]
pub struct BrokeredCallReq {
    pub tool_call_id: String,
    pub tool: String,
    #[serde(default)]
    pub input: Value,
}

/// `POST /internal/sessions/{id}/tools/call` — intent in, governed result
/// out. The sealed credential turns server-side (broker.rs); the sandbox
/// sees only the tool result. Ledger trail per call: tool.requested →
/// tool.decision → tool.brokered (identity, digests, latency — never
/// inputs, outputs, or secrets).
pub async fn tool_call(
    auth: SessionAuth,
    State(state): State<AppState>,
    Json(req): Json<BrokeredCallReq>,
) -> ApiResult<Json<Value>> {
    let session = fluidbox_db::get_session(&state.pool, auth.session_id)
        .await?
        .ok_or(ApiError::NotFound)?;
    if session.status_enum().is_terminal() {
        return Err(ApiError::BadRequest("session is not active".into()));
    }
    let run_spec: RunSpec = serde_json::from_value(session.run_spec.clone())
        .map_err(|e| ApiError::Internal(format!("bad run_spec: {e}")))?;

    // Class check: only brokered tools cross this endpoint. A tool the
    // frozen set doesn't know falls through to the gate for a uniform,
    // ledgered capability denial.
    let server = capability::parse_mcp_tool(&req.tool)
        .and_then(|(srv, tool)| capability::find_tool(&run_spec.capabilities, srv, tool))
        .map(|(srv, _)| srv);
    if let Some(srv) = server {
        if !srv.is_brokered() {
            return Err(ApiError::BadRequest(format!(
                "tool '{}' is sandbox-class — it executes inside the sandbox, not through the broker",
                req.tool
            )));
        }
    }

    // The gate registers the intent and writes tool.requested itself
    // (exactly once per unique tool_call_id) — same trail for brokered and
    // sandbox calls, counted once each.
    let decision = decide_tool_call(
        &state,
        &session,
        &run_spec,
        &req.tool_call_id,
        &req.tool,
        &req.input,
    )
    .await?;
    if !decision.allowed {
        return Ok(Json(json!({
            "ok": false,
            "denied": true,
            "message": decision
                .message
                .unwrap_or_else(|| "denied by fluidbox policy".into()),
        })));
    }

    let srv = server.expect("gate allowed the call, so the tool is in the frozen set");
    let CapabilityServer::Brokered {
        name: server_name, ..
    } = srv
    else {
        unreachable!("class-checked above")
    };
    let (_, tool_name) = capability::parse_mcp_tool(&req.tool).expect("found in the frozen set");

    let record_exec = |ok: bool, latency_ms: u64, digest: Option<String>, error: Option<String>| {
        ledger::record(
            &state,
            session.id,
            Actor::System,
            EventBody::BrokeredToolCall {
                tool_call_id: req.tool_call_id.clone(),
                tool: req.tool.clone(),
                server: server_name.clone(),
                ok,
                latency_ms,
                result_digest: digest,
                error,
            },
        )
    };

    // Credential turn happens inside the broker: resolved (static compose
    // or OAuth mint/refresh), sent to the (audience-bound) server, dropped.
    // Resolution failure is an execution failure, not a policy denial —
    // visibly ledgered either way.
    let started = std::time::Instant::now();
    let outcome = crate::broker::call_tool_auth(&state, srv, tool_name, &req.input).await;
    let latency_ms = started.elapsed().as_millis() as u64;
    match outcome {
        Ok((content, is_error)) => {
            record_exec(!is_error, latency_ms, Some(digest_json(&content)), None).await;
            Ok(Json(json!({
                "ok": true,
                "result": { "content": content, "is_error": is_error },
            })))
        }
        Err(e) => {
            let msg: String = e.chars().take(300).collect();
            record_exec(false, latency_ms, None, Some(msg.clone())).await;
            Ok(Json(json!({ "ok": false, "error": msg })))
        }
    }
}

async fn maybe_resume(state: &AppState, session_id: uuid::Uuid) {
    // If nothing else is pending, return the session to running.
    if let Ok(approvals) = fluidbox_db::session_approvals(&state.pool, session_id).await {
        let still_pending = approvals.iter().any(|a| a.status == "pending");
        if !still_pending {
            fluidbox_db::transition_session(&state.pool, session_id, SessionStatus::Running, None)
                .await
                .ok();
        }
    }
}

fn decision_from_status(status: &str) -> GateDecision {
    match status {
        "approved_once" | "approved_session" | "auto_allowed" => GateDecision::allow(),
        // pending / intent / auto_denied / denied / expired all fail safe.
        _ => GateDecision::deny("not approved"),
    }
}

async fn emit_decision(
    state: &AppState,
    session: uuid::Uuid,
    tool_call_id: &str,
    tool: &str,
    outcome: &EvaluationOutcome,
    verdict: &str,
    reason: Option<&str>,
) {
    let source = if outcome.autonomy_rewritten {
        "autonomy_rewrite"
    } else if reason.map(|r| r.starts_with("human:")).unwrap_or(false) {
        "human"
    } else if reason == Some("session-approved") {
        "session_scope"
    } else {
        "policy"
    };
    let original = if outcome.autonomy_rewritten {
        Some(outcome.original.name().to_string())
    } else {
        None
    };
    ledger::record(
        state,
        session,
        Actor::System,
        EventBody::ToolDecision {
            tool_call_id: tool_call_id.to_string(),
            tool: tool.to_string(),
            verdict: verdict.into(),
            source: source.into(),
            original_verdict: original,
            reason: reason.map(|s| s.to_string()),
        },
    )
    .await;
}

fn summarize(tool: &str, input: &Value) -> String {
    if let Some(cmd) = input.get("command").and_then(|v| v.as_str()) {
        return cmd.chars().take(200).collect();
    }
    // MultiEdit / codex apply_patch: list the edited file paths (so the
    // timeline + audit show WHICH files — incl. a move destination).
    if let Some(edits) = input.get("edits").and_then(|v| v.as_array()) {
        let paths: Vec<&str> = edits
            .iter()
            .filter_map(|e| e.get("file_path").and_then(|v| v.as_str()))
            .collect();
        if !paths.is_empty() {
            return format!("{tool}: {}", paths.join(", ")).chars().take(200).collect();
        }
    }
    for k in ["file_path", "path", "pattern"] {
        if let Some(s) = input.get(k).and_then(|v| v.as_str()) {
            return format!("{tool}: {s}");
        }
    }
    tool.to_string()
}

// ─── events / heartbeat / result ──────────────────────────────────────────

#[derive(Deserialize)]
pub struct EventIn {
    pub actor: String,
    pub body: Value,
}

pub async fn events(
    auth: SessionAuth,
    State(state): State<AppState>,
    Json(ev): Json<EventIn>,
) -> ApiResult<Json<Value>> {
    let actor = match ev.actor.as_str() {
        "agent" => Actor::Agent,
        "human" => Actor::Human,
        "harness" => Actor::Harness,
        _ => Actor::System,
    };
    let body: EventBody = serde_json::from_value(ev.body)
        .unwrap_or_else(|_| EventBody::Unknown(json!({"type": "unknown"})));
    // tool.requested is server-authoritative (Phase 6): the gate writes it
    // exactly once per registered intent. Runner-posted copies are dropped
    // so the timeline and the tool-call budget never double-count — and
    // never trust — runner cooperation.
    if matches!(body, EventBody::ToolRequested { .. }) {
        return Ok(Json(json!({ "seq": Value::Null, "dropped": "tool.requested" })));
    }
    let seq = ledger::record(&state, auth.session_id, actor, body).await;
    Ok(Json(json!({ "seq": seq })))
}

pub async fn heartbeat(auth: SessionAuth, State(state): State<AppState>) -> ApiResult<Json<Value>> {
    fluidbox_db::heartbeat(&state.pool, auth.session_id).await?;
    Ok(Json(json!({ "ok": true })))
}

#[derive(Deserialize)]
pub struct ResultIn {
    pub outcome: String,
    #[serde(default)]
    pub summary: Option<String>,
}

/// `/result` does NOT use the strict SessionAuth extractor: its whole job is
/// to terminalize the run, and the terminal transition REVOKES the session's
/// tokens — so a lost-response retry arrives with a now-revoked token. We
/// resolve the token leniently (incl. revoked/expired): a terminal session
/// ACKs idempotently (the result is already recorded); a live session with a
/// still-valid token finalizes; anything else (a bogus token, or a revoked
/// token on a non-terminal session — an anomaly, since revoke only fires on
/// terminal) is 401. This keeps /result idempotent across the revoke without
/// weakening any other endpoint (all keep strict SessionAuth).
pub async fn result(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Json(res): Json<ResultIn>,
) -> ApiResult<Json<Value>> {
    let token = crate::auth::bearer_from_headers(&headers).ok_or(ApiError::Unauthorized)?;
    let session_id = fluidbox_db::session_for_token_incl_revoked(&state.pool, &token)
        .await?
        .ok_or(ApiError::Unauthorized)?;
    let session = fluidbox_db::get_session(&state.pool, session_id)
        .await?
        .ok_or(ApiError::NotFound)?;
    if session.status_enum().is_terminal() {
        return Ok(Json(json!({ "ok": true, "note": "already terminal" })));
    }
    // Non-terminal: the token must still be live to drive a finalize (revoke
    // only happens on terminal, so this is the ordinary first-post path).
    if fluidbox_db::session_for_token(&state.pool, &token)
        .await?
        .is_none()
    {
        return Err(ApiError::Unauthorized);
    }
    let state2 = state.clone();
    tokio::spawn(async move {
        orchestrator::finalize(&state2, &session, &res.outcome, res.summary.as_deref()).await;
    });
    Ok(Json(json!({ "ok": true })))
}

#[derive(Deserialize)]
pub struct RenewReq {
    #[serde(default = "default_renew_ttl")]
    pub ttl_secs: i64,
}
fn default_renew_ttl() -> i64 {
    3 * 3600
}
/// A renew can never mint more than this much runway at once — a runner
/// (compromised or buggy) can't extend its token past the server's control
/// by asking for a huge TTL. Long agents renew repeatedly, each capped.
const MAX_RENEW_TTL_SECS: i64 = 3 * 3600;

/// Long-running agents renew their session token before it expires. Hardened:
/// the requested TTL is server-capped, a terminal session is refused (its
/// tokens are revoked on the terminal transition anyway), and a runner whose
/// token was already revoked gets `renewed:false` (no resurrection).
pub async fn token_renew(
    auth: SessionAuth,
    State(state): State<AppState>,
    Json(req): Json<RenewReq>,
) -> ApiResult<Json<Value>> {
    let session = fluidbox_db::get_session(&state.pool, auth.session_id)
        .await?
        .ok_or(ApiError::NotFound)?;
    if session.status_enum().is_terminal() {
        return Err(ApiError::BadRequest(
            "session is terminal — token cannot be renewed".into(),
        ));
    }
    let ttl = req.ttl_secs.clamp(1, MAX_RENEW_TTL_SECS);
    let ok = fluidbox_db::extend_session_token(&state.pool, &auth.token, ttl).await?;
    Ok(Json(json!({ "renewed": ok, "ttl_secs": ttl })))
}
