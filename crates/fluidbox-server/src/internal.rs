//! The internal gateway (per-session token). The runner talks only to this.

use crate::auth::SessionAuth;
use crate::error::{ApiError, ApiResult};
use crate::ledger;
use crate::orchestrator;
use crate::state::AppState;
use axum::extract::State;
use axum::Json;
use fluidbox_core::event::{digest_json, Actor, EventBody};
use fluidbox_core::policy::{EvaluationOutcome, Policy, ToolCallRequest, Verdict};
use fluidbox_core::spec::RunSpec;
use fluidbox_core::state::SessionStatus;
use serde::Deserialize;
use serde_json::{json, Value};
use std::time::Duration;

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
    let run_spec: RunSpec = serde_json::from_value(session.run_spec.clone())
        .map_err(|e| ApiError::Internal(format!("bad run_spec: {e}")))?;
    let policy: Policy = run_spec.policy_snapshot.clone();

    // Budget: tool-call ceiling enforced at the gate.
    if let Some(max) = run_spec.budgets.max_tool_calls {
        let used = fluidbox_db::tool_call_count(&state.pool, session.id).await?;
        if used as u64 > max {
            ledger::record(
                &state,
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
                orchestrator::finalize(&state2, &session_clone, "budget_exceeded", Some("tool-call budget exceeded")).await;
            });
            return Ok(Json(json!({ "decision": "deny", "message": "tool-call budget exceeded" })));
        }
    }

    let tool_req = ToolCallRequest { tool: req.tool.clone(), input: req.input.clone() };
    let outcome: EvaluationOutcome = policy.evaluate(&tool_req, run_spec.autonomy);

    match &outcome.effective {
        Verdict::Allow => {
            emit_decision(&state, session.id, &req, &outcome, "allow", None).await;
            Ok(Json(json!({ "decision": "allow" })))
        }
        Verdict::Deny { reason } => {
            emit_decision(&state, session.id, &req, &outcome, "deny", Some(reason)).await;
            Ok(Json(json!({ "decision": "deny", "message": reason })))
        }
        Verdict::RequireApproval { risk, ttl_secs, scope, scope_key } => {
            // Session-scope grant already given for this key?
            if fluidbox_db::has_session_grant(&state.pool, session.id, scope_key).await? {
                emit_decision(&state, session.id, &req, &outcome, "allow", Some("session-approved")).await;
                return Ok(Json(json!({ "decision": "allow" })));
            }

            let scope_str = match scope {
                fluidbox_core::policy::ApprovalScope::Once => "once",
                fluidbox_core::policy::ApprovalScope::Session => "session",
            };
            let digest = digest_json(&req.input);
            let (approval, inserted) = fluidbox_db::upsert_pending_approval(
                &state.pool,
                session.id,
                &req.tool_call_id,
                &req.tool,
                &summarize(&req.tool, &req.input),
                Some(&digest),
                risk.as_deref(),
                scope_str,
                scope_key,
                *ttl_secs as i64,
            )
            .await?;

            // Restart case: the row was already decided while we were away.
            if approval.status != "pending" {
                return Ok(Json(decision_response(&approval.status)));
            }

            if inserted {
                ledger::record(
                    &state,
                    session.id,
                    Actor::System,
                    EventBody::ApprovalRequested {
                        approval_id: approval.id,
                        tool_call_id: req.tool_call_id.clone(),
                        tool: req.tool.clone(),
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

            // Wait for a decision (DB is truth; Notify just wakes us early).
            let notifier = state.approvals.notifier(approval.id).await;
            let final_status = loop {
                let cur = fluidbox_db::get_approval(&state.pool, approval.id)
                    .await?
                    .ok_or(ApiError::NotFound)?;
                if cur.status != "pending" {
                    break cur.status;
                }
                if cur.expires_at <= chrono::Utc::now() {
                    // Timeout → auto-deny (fail-safe).
                    fluidbox_db::decide_approval(&state.pool, approval.id, "denied", "timeout")
                        .await
                        .ok();
                    break "denied".to_string();
                }
                // Wake on decision, or re-poll every 2s, or at expiry.
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

            // Record the decision + wake the session back to running if no
            // other approvals are pending.
            let decided_by = fluidbox_db::get_approval(&state.pool, approval.id)
                .await?
                .and_then(|a| a.decided_by)
                .unwrap_or_else(|| "system".into());
            ledger::record(
                &state,
                session.id,
                Actor::Human,
                EventBody::ApprovalDecided {
                    approval_id: approval.id,
                    tool_call_id: req.tool_call_id.clone(),
                    decision: final_status.clone(),
                    decided_by: decided_by.clone(),
                },
            )
            .await;

            let allowed = final_status == "approved_once" || final_status == "approved_session";
            emit_decision(
                &state,
                session.id,
                &req,
                &outcome,
                if allowed { "allow" } else { "deny" },
                Some(&format!("human:{decided_by}")),
            )
            .await;

            maybe_resume(&state, session.id).await;

            Ok(Json(decision_response(&final_status)))
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

fn decision_response(status: &str) -> Value {
    match status {
        "approved_once" | "approved_session" => json!({ "decision": "allow" }),
        _ => json!({ "decision": "deny", "message": "not approved" }),
    }
}

async fn emit_decision(
    state: &AppState,
    session: uuid::Uuid,
    req: &PermissionReq,
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
            tool_call_id: req.tool_call_id.clone(),
            tool: req.tool.clone(),
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
    let seq = ledger::record(&state, auth.session_id, actor, body).await;
    Ok(Json(json!({ "seq": seq })))
}

pub async fn heartbeat(
    auth: SessionAuth,
    State(state): State<AppState>,
) -> ApiResult<Json<Value>> {
    fluidbox_db::heartbeat(&state.pool, auth.session_id).await?;
    Ok(Json(json!({ "ok": true })))
}

#[derive(Deserialize)]
pub struct ResultIn {
    pub outcome: String,
    #[serde(default)]
    pub summary: Option<String>,
}

pub async fn result(
    auth: SessionAuth,
    State(state): State<AppState>,
    Json(res): Json<ResultIn>,
) -> ApiResult<Json<Value>> {
    let session = fluidbox_db::get_session(&state.pool, auth.session_id)
        .await?
        .ok_or(ApiError::NotFound)?;
    if session.status_enum().is_terminal() {
        return Ok(Json(json!({ "ok": true, "note": "already terminal" })));
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

/// Long-running agents renew their session token before it expires.
pub async fn token_renew(
    auth: SessionAuth,
    State(state): State<AppState>,
    Json(req): Json<RenewReq>,
) -> ApiResult<Json<Value>> {
    let ok = fluidbox_db::extend_session_token(&state.pool, &auth.token, req.ttl_secs).await?;
    Ok(Json(json!({ "renewed": ok })))
}
