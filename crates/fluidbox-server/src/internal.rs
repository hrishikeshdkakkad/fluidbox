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
use fluidbox_db::TenantScope;
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
    // Every gate DB call scopes to the session's own tenant (derived from the
    // frozen session row, never state.tenant_id).
    let scope = TenantScope::assume(session.tenant_id);

    // ── Intent registration + digest binding (Phase 6 hardening). One
    // persistent row per (session, tool_call_id) is the budget's counting
    // unit, the idempotency anchor, AND the digest binding: a reused id
    // must carry the SAME tool + input digest — a mismatch is a protocol
    // violation that hard-denies without ever touching the stored verdict.
    let digest = digest_json(input);
    let (intent, inserted) = fluidbox_db::register_tool_intent(
        &state.pool,
        scope,
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
            scope,
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
                scope,
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
        let used = fluidbox_db::tool_call_count(&state.pool, scope, session.id).await?;
        if used as u64 > max {
            if fluidbox_db::record_intent_verdict(&state.pool, scope, intent.id, "auto_denied")
                .await?
            {
                ledger::record(
                    state,
                    scope,
                    session.id,
                    Actor::System,
                    EventBody::BudgetExceeded {
                        budget: "max_tool_calls".into(),
                        limit: max.to_string(),
                        spent: used.to_string(),
                    },
                )
                .await;
                let session_id = session.id;
                let state2 = state.clone();
                tokio::spawn(async move {
                    // Forced stop (runner live → quiesce first). The deny
                    // verdict below is already out, so this task retries with
                    // backoff — a budget-less runner that makes no further
                    // request has no other same-channel driver.
                    for attempt in 0..5u32 {
                        match orchestrator::finalize_forced(
                            &state2,
                            session_id,
                            "budget_exceeded",
                            "tool-call budget exceeded",
                        )
                        .await
                        {
                            orchestrator::FinalizeStart::DbError => {
                                tokio::time::sleep(std::time::Duration::from_secs(
                                    10u64 << attempt.min(3),
                                ))
                                .await;
                            }
                            _ => return,
                        }
                    }
                    tracing::error!(
                        "tool-call budget finalize for {session_id} did not persist after retries"
                    );
                });
                return Ok(GateDecision::deny("tool-call budget exceeded"));
            }
            return adopt_terminal_or_deny(state, scope, intent.id).await;
        }
    }

    // Capability availability (design §8): an mcp__* call must name a tool
    // in the run's FROZEN set. Attach ≠ allow — but not-attached = unavailable,
    // whatever the policy says. This is also the rug-pull defense: a tool the
    // live server started advertising after the photograph simply does not
    // exist for this run. Phase C unions BOTH attachment paths — the legacy
    // frozen `capabilities` bundles and the binding-backed `brokered` surfaces
    // — so a connection-free run's tools are available; the message contract is
    // byte-identical to the legacy check, so the ledger stays uniform. This
    // union swap is the ONLY change to the gate's decision order.
    if let Some(reason) =
        capability::brokered_surface_denial(&run_spec.brokered, &run_spec.capabilities, tool)
    {
        // CAS the verdict FIRST; only the handler that owns the decision
        // emits the ledger event (concurrent duplicates of a deterministic
        // deny neither double-ledger nor contradict each other).
        if fluidbox_db::record_intent_verdict(&state.pool, scope, intent.id, "auto_denied").await? {
            ledger::record(
                state,
                scope,
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
        return adopt_terminal_or_deny(state, scope, intent.id).await;
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
            if fluidbox_db::record_intent_verdict(&state.pool, scope, intent.id, "auto_denied")
                .await?
            {
                ledger::record(
                    state,
                    scope,
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
            return adopt_terminal_or_deny(state, scope, intent.id).await;
        }
    }

    match &outcome.effective {
        Verdict::Allow => {
            if fluidbox_db::record_intent_verdict(&state.pool, scope, intent.id, "auto_allowed")
                .await?
            {
                emit_decision(
                    state,
                    scope,
                    session.id,
                    tool_call_id,
                    tool,
                    &outcome,
                    "allow",
                    None,
                )
                .await;
                Ok(GateDecision::allow())
            } else {
                adopt_terminal_or_deny(state, scope, intent.id).await
            }
        }
        Verdict::Deny { reason } => {
            if fluidbox_db::record_intent_verdict(&state.pool, scope, intent.id, "auto_denied")
                .await?
            {
                emit_decision(
                    state,
                    scope,
                    session.id,
                    tool_call_id,
                    tool,
                    &outcome,
                    "deny",
                    Some(reason),
                )
                .await;
                Ok(GateDecision::deny(reason.clone()))
            } else {
                adopt_terminal_or_deny(state, scope, intent.id).await
            }
        }
        Verdict::RequireApproval {
            risk,
            ttl_secs,
            scope: approval_scope,
            scope_key,
        } => {
            // Session-scope grant already given for this key? Adopt the
            // durable outcome if a concurrent handler moved the row first —
            // including a wait-join if that handler promoted it to pending
            // (the narrow grant-lands-mid-flight race).
            if fluidbox_db::has_session_grant(&state.pool, scope, session.id, scope_key).await? {
                if fluidbox_db::record_intent_verdict(&state.pool, scope, intent.id, "auto_allowed")
                    .await?
                {
                    emit_decision(
                        state,
                        scope,
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
                let row = fluidbox_db::get_approval(&state.pool, scope, intent.id)
                    .await?
                    .ok_or(ApiError::NotFound)?;
                if row.status == "pending" {
                    return await_pending_decision(
                        state,
                        scope,
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

            let scope_str = match approval_scope {
                fluidbox_core::policy::ApprovalScope::Once => "once",
                fluidbox_core::policy::ApprovalScope::Session => "session",
            };
            // Promote the registered intent into the human approval
            // lifecycle. None = a concurrent handler already promoted (or a
            // verdict landed) — re-read and act on the current status.
            let promoted = fluidbox_db::promote_intent_to_pending(
                &state.pool,
                scope,
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
                None => fluidbox_db::get_approval(&state.pool, scope, intent.id)
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
                    scope,
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
                    scope,
                    session.id,
                    SessionStatus::AwaitingApproval,
                    Some("awaiting human approval"),
                )
                .await
                .ok();
            }

            await_pending_decision(
                state,
                scope,
                session.id,
                approval,
                tool_call_id,
                tool,
                &outcome,
            )
            .await
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
    scope: TenantScope,
    intent_id: uuid::Uuid,
) -> ApiResult<GateDecision> {
    let row = fluidbox_db::get_approval(&state.pool, scope, intent_id)
        .await?
        .ok_or(ApiError::NotFound)?;
    Ok(decision_from_status(&row.status))
}

/// Block on a pending approval row until it is decided (DB is truth; the
/// Notify only wakes us early), then record the human decision and return
/// it. Shared by the promoter and any handler that adopts a pending row.
async fn await_pending_decision(
    state: &AppState,
    scope: TenantScope,
    session_id: uuid::Uuid,
    approval: fluidbox_db::ApprovalRow,
    tool_call_id: &str,
    tool: &str,
    outcome: &EvaluationOutcome,
) -> ApiResult<GateDecision> {
    let notifier = state.approvals.notifier(approval.id).await;
    let final_status = loop {
        let cur = fluidbox_db::get_approval(&state.pool, scope, approval.id)
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
            match fluidbox_db::decide_approval(&state.pool, scope, approval.id, "denied", "timeout")
                .await?
            {
                Some(_) => break "denied".to_string(),
                None => {
                    let row = fluidbox_db::get_approval(&state.pool, scope, approval.id)
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

    let decided_by = fluidbox_db::get_approval(&state.pool, scope, approval.id)
        .await?
        .and_then(|a| a.decided_by)
        .unwrap_or_else(|| "system".into());
    ledger::record(
        state,
        scope,
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
        scope,
        session_id,
        tool_call_id,
        tool,
        outcome,
        if allowed { "allow" } else { "deny" },
        Some(&format!("human:{decided_by}")),
    )
    .await;

    maybe_resume(state, scope, session_id).await;
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
    let session = fluidbox_db::get_session(&state.pool, auth.scope, auth.session_id)
        .await?
        .ok_or(ApiError::NotFound)?;
    // A terminal OR winding-down session never gets a fresh decision — the
    // primary guard, independent of token revocation (which is best-effort
    // defense in depth). A run being finalized/cancelled admits no new tools.
    if !session.status_enum().accepts_work() {
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
    let session = fluidbox_db::get_session(&state.pool, auth.scope, auth.session_id)
        .await?
        .ok_or(ApiError::NotFound)?;
    if !session.status_enum().accepts_work() {
        return Err(ApiError::BadRequest("session is not active".into()));
    }
    let run_spec: RunSpec = serde_json::from_value(session.run_spec.clone())
        .map_err(|e| ApiError::Internal(format!("bad run_spec: {e}")))?;
    let scope = auth.scope;

    // Phase C: a binding-backed brokered surface (the connection-free RunSpec
    // successor to an embedded `connection_id`). Resolved from the tool's server
    // alias; takes precedence over any legacy bundle so a Phase C run always
    // routes through the binding path (recheck + call_tool_for_conn).
    let surface = capability::parse_mcp_tool(&req.tool)
        .and_then(|(srv, _)| run_spec.find_brokered_surface(srv))
        .cloned();

    // Legacy: a brokered server still embedded in a frozen capability bundle
    // (pre-Phase-C / in-flight runs). A tool the frozen set doesn't know falls
    // through to the gate for a uniform, ledgered capability denial.
    let legacy_server = capability::parse_mcp_tool(&req.tool)
        .and_then(|(srv, tool)| capability::find_tool(&run_spec.capabilities, srv, tool))
        .map(|(srv, _)| srv);

    // Class check: a sandbox-class tool executes inside the sandbox, not here.
    // A binding surface is broker-only by construction, so this only guards the
    // legacy bundle path.
    if surface.is_none() {
        if let Some(srv) = legacy_server {
            if !srv.is_brokered() {
                return Err(ApiError::BadRequest(format!(
                    "tool '{}' is sandbox-class — it executes inside the sandbox, not through the broker",
                    req.tool
                )));
            }
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

    // ── Phase C binding path (takes precedence over legacy bundles) ──
    if let Some(surface) = surface {
        return broker_call_via_binding(&state, scope, &session, &req, &surface).await;
    }

    // ── Legacy path (byte-for-byte today's behavior): the credential comes
    // from the connection_id embedded in the frozen bundle server, and the only
    // live check is broker.rs's status read (a legacy run froze no generation
    // or owner to compare — the residual invariant-21 gap the binding path
    // closes for new runs). ──
    let srv = legacy_server.expect("gate allowed the call, so the tool is in the frozen set");
    let CapabilityServer::Brokered {
        name: server_name, ..
    } = srv
    else {
        unreachable!("class-checked above")
    };
    let (_, tool_name) = capability::parse_mcp_tool(&req.tool).expect("found in the frozen set");

    // Credential turn happens inside the broker: resolved (static compose
    // or OAuth mint/refresh), sent to the (audience-bound) server, dropped.
    // Resolution failure is an execution failure, not a policy denial —
    // visibly ledgered either way.
    let started = std::time::Instant::now();
    let outcome = crate::broker::call_tool_auth(&state, scope, srv, tool_name, &req.input).await;
    let latency_ms = started.elapsed().as_millis() as u64;
    match outcome {
        Ok((content, is_error)) => {
            record_brokered_exec(
                &state,
                scope,
                session.id,
                &req.tool_call_id,
                &req.tool,
                server_name,
                None,
                !is_error,
                latency_ms,
                Some(digest_json(&content)),
                None,
            )
            .await;
            Ok(Json(json!({
                "ok": true,
                "result": { "content": content, "is_error": is_error },
            })))
        }
        Err(e) => {
            let msg: String = e.chars().take(300).collect();
            record_brokered_exec(
                &state,
                scope,
                session.id,
                &req.tool_call_id,
                &req.tool,
                server_name,
                None,
                false,
                latency_ms,
                None,
                Some(msg.clone()),
            )
            .await;
            Ok(Json(json!({ "ok": false, "error": msg })))
        }
    }
}

/// The Phase C brokered-execution path: the requested tool resolved to a
/// binding-backed surface. Recheck the run resource binding (status +
/// generation + owner membership) IMMEDIATELY before the credential turns
/// server-side, then execute against the frozen surface url. A binding refusal
/// ledgers `tool.decision` (source="binding") — the same audit shape as a
/// capability denial — before the denial returns; a corrupt surface⇄binding
/// link is a 500-class integrity error (both written in one transaction).
async fn broker_call_via_binding(
    state: &AppState,
    scope: TenantScope,
    session: &fluidbox_db::SessionRow,
    req: &BrokeredCallReq,
    surface: &fluidbox_core::spec::BrokeredSurface,
) -> ApiResult<Json<Value>> {
    let binding =
        fluidbox_db::find_session_binding(&state.pool, scope, session.id, "mcp", &surface.slot)
            .await?;
    let binding = match binding {
        Some(b) if b.id == surface.binding_id => b,
        _ => {
            let reason = format!(
                "brokered surface '{}' has no matching run resource binding",
                surface.slot
            );
            record_binding_denial(
                state,
                scope,
                session.id,
                &req.tool_call_id,
                &req.tool,
                &reason,
            )
            .await;
            return Err(ApiError::Internal(reason));
        }
    };

    // Revocation recheck immediately before secret access (design :705-723): a
    // revoked/reauthorized connection or a deactivated owner fails closed here.
    let conn = match crate::broker::recheck_binding(state, scope, &binding).await {
        Ok(conn) => conn,
        Err(e) => {
            let reason: String = e.chars().take(300).collect();
            record_binding_denial(
                state,
                scope,
                session.id,
                &req.tool_call_id,
                &req.tool,
                &reason,
            )
            .await;
            return Ok(Json(json!({
                "ok": false,
                "denied": true,
                "message": reason,
            })));
        }
    };

    let (_, tool_name) = capability::parse_mcp_tool(&req.tool)
        .expect("gate allowed an mcp surface tool, so it parses");

    // Credential turns server-side inside the broker against the just-rechecked
    // connection + the frozen surface url; sent to the (audience-bound) server,
    // dropped. Resolution/transport failure is an execution failure, ledgered.
    let started = std::time::Instant::now();
    let outcome = crate::broker::call_tool_for_conn(
        state,
        scope,
        &conn,
        &surface.url,
        tool_name,
        &req.input,
        &binding,
    )
    .await;
    let latency_ms = started.elapsed().as_millis() as u64;
    match outcome {
        Ok((content, is_error)) => {
            record_brokered_exec(
                state,
                scope,
                session.id,
                &req.tool_call_id,
                &req.tool,
                &surface.slot,
                Some(surface.binding_id),
                !is_error,
                latency_ms,
                Some(digest_json(&content)),
                None,
            )
            .await;
            Ok(Json(json!({
                "ok": true,
                "result": { "content": content, "is_error": is_error },
            })))
        }
        Err(e) => {
            let msg: String = e.chars().take(300).collect();
            record_brokered_exec(
                state,
                scope,
                session.id,
                &req.tool_call_id,
                &req.tool,
                &surface.slot,
                Some(surface.binding_id),
                false,
                latency_ms,
                None,
                Some(msg.clone()),
            )
            .await;
            Ok(Json(json!({ "ok": false, "error": msg })))
        }
    }
}

/// Ledger one `tool.brokered` event (identity + digests + latency; never
/// inputs, outputs, or secrets). `binding_id` is Some on the Phase C binding
/// path, None on the legacy embedded-connection path.
#[allow(clippy::too_many_arguments)]
async fn record_brokered_exec(
    state: &AppState,
    scope: TenantScope,
    session_id: uuid::Uuid,
    tool_call_id: &str,
    tool: &str,
    server: &str,
    binding_id: Option<uuid::Uuid>,
    ok: bool,
    latency_ms: u64,
    result_digest: Option<String>,
    error: Option<String>,
) {
    ledger::record(
        state,
        scope,
        session_id,
        Actor::System,
        EventBody::BrokeredToolCall {
            tool_call_id: tool_call_id.to_string(),
            tool: tool.to_string(),
            server: server.to_string(),
            binding_id,
            ok,
            latency_ms,
            result_digest,
            error,
        },
    )
    .await;
}

/// Ledger a brokered-binding refusal as `tool.decision` (source="binding") —
/// the same audit shape as a capability denial — before the endpoint returns
/// it. The gate already allowed the call on the frozen set; the binding recheck
/// is the live revocation layer above it (design :705-723).
async fn record_binding_denial(
    state: &AppState,
    scope: TenantScope,
    session_id: uuid::Uuid,
    tool_call_id: &str,
    tool: &str,
    reason: &str,
) {
    ledger::record(
        state,
        scope,
        session_id,
        Actor::System,
        EventBody::ToolDecision {
            tool_call_id: tool_call_id.to_string(),
            tool: tool.to_string(),
            verdict: "deny".into(),
            source: "binding".into(),
            original_verdict: None,
            reason: Some(reason.to_string()),
        },
    )
    .await;
}

async fn maybe_resume(state: &AppState, scope: TenantScope, session_id: uuid::Uuid) {
    // If nothing else is pending, return the session to running.
    if let Ok(approvals) = fluidbox_db::session_approvals(&state.pool, scope, session_id).await {
        let still_pending = approvals.iter().any(|a| a.status == "pending");
        if !still_pending {
            fluidbox_db::transition_session(
                &state.pool,
                scope,
                session_id,
                SessionStatus::Running,
                None,
            )
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

#[allow(clippy::too_many_arguments)]
async fn emit_decision(
    state: &AppState,
    scope: TenantScope,
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
        scope,
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
            return format!("{tool}: {}", paths.join(", "))
                .chars()
                .take(200)
                .collect();
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
        return Ok(Json(
            json!({ "seq": Value::Null, "dropped": "tool.requested" }),
        ));
    }
    let seq = ledger::record(&state, auth.scope, auth.session_id, actor, body).await;
    Ok(Json(json!({ "seq": seq })))
}

/// `GET /internal/sessions/{id}/workspace` — the immutable workspace archive
/// the sandbox's init container pulls (Kubernetes transport). The session is
/// derived from the BEARER TOKEN, not the path `{id}` (informational, like
/// every other internal route). The archive is credential-free and
/// digest-verified by the init container before unpack; serving it grants the
/// pod nothing it couldn't already reach with the token it holds.
pub async fn workspace_archive(
    auth: SessionAuth,
    State(state): State<AppState>,
) -> ApiResult<axum::response::Response> {
    use axum::response::IntoResponse;
    use tokio::io::AsyncReadExt;
    // A terminal/winding-down session's archive is moot (the run is over) —
    // gate on accepts_work(), like every sibling internal endpoint.
    let session = fluidbox_db::get_session(&state.pool, auth.scope, auth.session_id)
        .await?
        .ok_or(ApiError::NotFound)?;
    if !session.status_enum().accepts_work() {
        return Err(ApiError::BadRequest("session is not active".into()));
    }
    let path = crate::orchestrator::archive_path(&state.cfg.data_dir, auth.session_id);
    // Streamed straight off disk — a large archive must never transit
    // control-plane RAM (M4). The explicit Content-Length lets the client
    // detect truncation cheaply; the init container's digest check remains
    // the integrity authority.
    let mut file = tokio::fs::File::open(&path)
        .await
        .map_err(|_| ApiError::NotFound)?;
    let len = file.metadata().await.map_err(|_| ApiError::NotFound)?.len();
    let stream = async_stream::stream! {
        let mut buf = vec![0u8; 64 * 1024];
        loop {
            match file.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => yield Ok::<_, std::io::Error>(bytes::Bytes::copy_from_slice(&buf[..n])),
                Err(e) => {
                    yield Err(e);
                    break;
                }
            }
        }
    };
    Ok((
        [
            (
                axum::http::header::CONTENT_TYPE,
                "application/gzip".to_string(),
            ),
            (axum::http::header::CONTENT_LENGTH, len.to_string()),
        ],
        axum::body::Body::from_stream(stream),
    )
        .into_response())
}

pub async fn heartbeat(auth: SessionAuth, State(state): State<AppState>) -> ApiResult<Json<Value>> {
    fluidbox_db::heartbeat(&state.pool, auth.scope, auth.session_id).await?;
    // Deliberately NO eager archive deletion here: Kubernetes documents that
    // init containers may re-execute (pod-infrastructure restart), and a
    // re-executed `workspaced init` re-fetches the archive — deleting it on
    // the first runner heartbeat would 404 that fetch and fail an otherwise
    // recoverable pod. The archive lives until terminal cleanup; the TTL
    // sweep is the leak backstop (L3).
    // Quiesce channel (the ONLY runner-contract change in the K8s design):
    // once a session enters `cancelling`, its heartbeat response carries
    // {"action":"quiesce"} — the runner stops the agent and exits WITHOUT
    // posting /result, so the cancel finalizer collects a settled worktree.
    // Level-triggered: every heartbeat repeats it until the runner exits.
    let action = match fluidbox_db::get_session(&state.pool, auth.scope, auth.session_id).await? {
        Some(s) if s.status_enum() == SessionStatus::Cancelling => Some("quiesce"),
        _ => None,
    };
    Ok(Json(json!({ "ok": true, "action": action })))
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
    let sess_auth = fluidbox_db::session_for_token_incl_revoked(&state.pool, &token)
        .await?
        .ok_or(ApiError::Unauthorized)?;
    let session_id = sess_auth.session_id;
    let scope = TenantScope::assume(sess_auth.tenant_id);
    let session = fluidbox_db::get_session(&state.pool, scope, session_id)
        .await?
        .ok_or(ApiError::NotFound)?;
    let st = session.status_enum();
    if st.is_terminal() {
        return Ok(Json(json!({ "ok": true, "note": "already terminal" })));
    }
    // Already winding down: a cancel (or a prior /result) owns finalization —
    // but ONLY if its intent actually persisted. A wind-down state WITHOUT an
    // intent is the stranded-wedge shape (nothing for recovery to drive);
    // fall through and (re)persist one instead of falsely ACKing.
    if st.is_winding_down() {
        match fluidbox_db::get_finalization(&state.pool, scope, session_id).await {
            Ok(Some(_)) => return Ok(Json(json!({ "ok": true, "note": "finalizing" }))),
            Ok(None) => {}
            Err(_) => {
                return Err(ApiError::ServiceUnavailable(
                    "finalization state unavailable; retry".into(),
                ))
            }
        }
    }
    // Non-terminal: the token must still be live to drive a finalize (revoke
    // only happens on terminal, so this is the ordinary first-post path).
    if fluidbox_db::session_for_token(&state.pool, &token)
        .await?
        .is_none()
    {
        // TOCTOU: a racing driver may have terminalized (revoking the token)
        // after our status read — a lost-response /result retry must get its
        // idempotent 200. Unknown state must be RETRYABLE (503): the runner
        // treats 4xx as final, so a transient read error returned as 401
        // would convert a completed run into a runner-side failure.
        match fluidbox_db::get_session(&state.pool, scope, session_id).await {
            Ok(Some(s)) if s.status_enum().is_terminal() => {
                return Ok(Json(json!({ "ok": true, "note": "already terminal" })));
            }
            Ok(_) => return Err(ApiError::Unauthorized),
            Err(_) => {
                return Err(ApiError::ServiceUnavailable(
                    "session state unavailable; retry".into(),
                ))
            }
        }
    }
    // Persist the finalization intent BEFORE ACKing — and NEVER ACK success
    // when it did not persist: the runner exits on ok:true, and with no
    // durable intent the watchdog would later record this completed run as
    // failed. The runner contract retries /result on 5xx.
    use orchestrator::FinalizeStart;
    match orchestrator::finalize_reported(&state, session_id, &res.outcome, res.summary.as_deref())
        .await
    {
        FinalizeStart::Persisted { .. } => Ok(Json(json!({ "ok": true }))),
        FinalizeStart::AlreadyTerminal => {
            Ok(Json(json!({ "ok": true, "note": "already terminal" })))
        }
        FinalizeStart::Missing => Err(ApiError::NotFound),
        FinalizeStart::DbError => Err(ApiError::ServiceUnavailable(
            "finalization intent not persisted; retry".into(),
        )),
    }
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
    let session = fluidbox_db::get_session(&state.pool, auth.scope, auth.session_id)
        .await?
        .ok_or(ApiError::NotFound)?;
    if !session.status_enum().accepts_work() {
        return Err(ApiError::BadRequest(
            "session is not active — token cannot be renewed".into(),
        ));
    }
    let ttl = req.ttl_secs.clamp(1, MAX_RENEW_TTL_SECS);
    let ok = fluidbox_db::extend_session_token(&state.pool, &auth.token, ttl).await?;
    Ok(Json(json!({ "renewed": ok, "ttl_secs": ttl })))
}
