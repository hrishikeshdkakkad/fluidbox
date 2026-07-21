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
    /// The canonical `digest_json(input)` the gate bound to the intent (Phase E,
    /// #33). The brokered dispatch keys its durable execution claim on THIS exact
    /// digest — never a re-serialization — so a claim can never diverge from the
    /// approval's digest. Empty until stamped by [`decide_tool_call`]; only the
    /// brokered `tool_call` path reads it.
    input_digest: String,
}

impl GateDecision {
    fn allow() -> Self {
        Self {
            allowed: true,
            message: None,
            input_digest: String::new(),
        }
    }
    fn deny(message: impl Into<String>) -> Self {
        Self {
            allowed: false,
            message: Some(message.into()),
            input_digest: String::new(),
        }
    }
}

/// A reference into the run's FROZEN set for one `mcp__*` tool: the untrusted
/// input schema, the snapshot's protocol version (the dialect selector), and a
/// stable digest for the compiled-validator cache key. Resolved from EITHER
/// attachment path — a Phase C binding-backed surface (precedence, matching
/// `tool_call`'s routing) or a legacy frozen capability bundle.
struct FrozenToolRef<'a> {
    schema: &'a Value,
    protocol_version: Option<&'a str>,
    digest: &'a str,
}

/// Locate the frozen `inputSchema` (and its dialect + cache digest) for an
/// `mcp__*` tool. `None` for a non-`mcp__` (built-in) tool, or an `mcp__` tool
/// not in the frozen set — the latter was already denied by the availability
/// check, so a `None` here means "no schema to enforce", never "not attached".
fn locate_frozen_schema<'a>(run_spec: &'a RunSpec, tool: &str) -> Option<FrozenToolRef<'a>> {
    let (server, tool_name) = capability::parse_mcp_tool(tool)?;
    // Phase C brokered surface first (same precedence `tool_call` routes on): its
    // frozen `protocol_version` selects the JSON Schema dialect.
    if let Some(surface) = run_spec.find_brokered_surface(server) {
        if let Some(t) = surface.tools.iter().find(|t| t.name == tool_name) {
            return Some(FrozenToolRef {
                schema: &t.input_schema,
                protocol_version: surface.protocol_version.as_deref(),
                digest: &surface.tools_digest,
            });
        }
    }
    // Legacy capability bundle: no protocol version was frozen, so the dialect
    // defaults to 2020-12 (SEP-1613). The bundle's definition digest keys the
    // cache (drift ⇒ a new digest ⇒ a fresh compilation).
    for bundle in &run_spec.capabilities {
        for srv in &bundle.servers {
            if srv.name() == server {
                if let Some(t) = srv.tools().iter().find(|t| t.name == tool_name) {
                    return Some(FrozenToolRef {
                        schema: &t.input_schema,
                        protocol_version: None,
                        digest: &bundle.definition_digest,
                    });
                }
            }
        }
    }
    None
}

/// The frozen-schema gate decision for one tool call (Gap 12; PURE — no DB, so
/// it is unit-tested directly). `None` = no schema objection (built-in, non-mcp,
/// no frozen schema, or the args satisfy it) → the call proceeds to the
/// trust-tier/policy stages. `Some(reason)` = a `source="schema"` deny, in one of
/// two shapes: the frozen schema is itself invalid/uncompilable ("frozen schema
/// invalid — refresh the snapshot") vs the args violate a valid schema
/// ("arguments rejected by frozen schema: <bounded JSON-pointer paths>", never
/// argument values). Deterministic on the frozen set + args, so a faithful retry
/// recomputes the identical verdict.
fn schema_gate_decision(
    cache: &fluidbox_core::schema_guard::SchemaCache,
    run_spec: &RunSpec,
    tool: &str,
    input: &Value,
) -> Option<String> {
    use fluidbox_core::schema_guard as sg;
    let frozen = locate_frozen_schema(run_spec, tool)?;
    // 1. Compile (cached) under the snapshot's dialect. The cache screens the
    //    UNTRUSTED frozen schema (size/depth/local-$ref) on a MISS only — a hit
    //    was already guarded, and a frozen schema is stable, so its verdict is
    //    too. A guard failure OR a compile failure is the same schema-invalid
    //    deny (malformed schema, not an args problem).
    let dialect = sg::dialect_for(frozen.protocol_version);
    let validator = match cache.get_or_compile(frozen.digest, tool, frozen.schema, dialect) {
        Ok(v) => v,
        Err(_) => return Some("frozen schema invalid — refresh the snapshot".to_string()),
    };
    // 2. Validate the args (size/depth pre-guarded inside). Report bounded
    //    JSON-pointer PATHS — never values (secrets-adjacent).
    match sg::validate_instance(&validator, input) {
        Ok(()) => None,
        Err(rej) => Some(format!(
            "arguments rejected by frozen schema: {}",
            rej.summary()
        )),
    }
}

/// The shared gate entry point (`permission` and brokered `tool_call` both call
/// it). Runs the full ordered gate ([`gate_tool_call`]) and stamps the canonical
/// input digest onto the decision so the brokered dispatch keys its execution
/// claim on the SAME digest the intent bound (`digest_json` is a pure fn of the
/// in-memory `Value`, identical to `register_tool_intent`'s — computed here at the
/// gate boundary, never re-derived inside the broker path).
async fn decide_tool_call(
    state: &AppState,
    session: &fluidbox_db::SessionRow,
    run_spec: &RunSpec,
    tool_call_id: &str,
    tool: &str,
    input: &Value,
) -> ApiResult<GateDecision> {
    let mut decision = gate_tool_call(state, session, run_spec, tool_call_id, tool, input).await?;
    decision.input_digest = digest_json(input);
    Ok(decision)
}

/// The heart of the system: one decision per tool call, made server-side
/// against the FROZEN RunSpec (never live config). Idempotent by
/// tool_call_id through the approvals table, so retries re-attach instead
/// of re-asking.
async fn gate_tool_call(
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

    // Frozen-schema argument enforcement (Gap 12, invariants 13/17; design
    // `:1352`, plan E9). For an `mcp__*` call whose tool carries a frozen
    // inputSchema, the arguments must satisfy that schema — under the dialect the
    // snapshot's MCP protocol version selects — BEFORE the trust-tier floor and
    // the policy verdict. Placed AFTER availability (it needs the ToolSnapshot the
    // frozen set yields) and BEFORE trust tier: the ONE sanctioned insertion in
    // the load-bearing gate order. Built-in tools are never `mcp__`-prefixed and
    // carry no frozen schema, so they bypass entirely. The decision is
    // deterministic on the frozen set + args, so it CASes-then-ledgers exactly
    // like the capability denial above: only the verdict-CAS winner writes
    // `tool.decision` (source="schema"); a concurrent loser — or a faithful retry
    // — adopts the durable terminal deny.
    if let Some(reason) = schema_gate_decision(&state.schema_cache, run_spec, tool, input) {
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
                    source: "schema".into(),
                    original_verdict: None,
                    reason: Some(reason.clone()),
                },
            )
            .await;
            return Ok(GateDecision::deny(reason));
        }
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
    // E12 slice (Task 4, plan): the session may have terminalized DURING a
    // minutes-long wait (cancel / budget sweep). A post-wait ALLOW must not
    // execute against a tearing-down run — re-read status and deny if it no longer
    // accepts work, mirroring the handler-top terminal guard (a deny with no fresh
    // tool.decision; the human's approval, already ledgered above, was real). This
    // closes the sandbox-tool half; the brokered half is additionally fenced by
    // the execution claim's in-tx nonterminal check (E10).
    if allowed {
        if let Some(sess) = fluidbox_db::get_session(&state.pool, scope, session_id).await? {
            if !sess.status_enum().accepts_work() {
                return Ok(GateDecision::deny("session terminal during approval wait"));
            }
        }
    }
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

    // ── The gate allowed the call; wrap the ALLOWED dispatch in a durable
    // execution claim (Phase E, #33; Gap 11). The claim keys on the intent's
    // input digest so exactly ONE upstream send happens per (session, call,
    // digest), taken under the same sessions-row lock order as cancellation and
    // refused once the session stops accepting work. ──
    let input_digest = decision.input_digest;

    // Phase C binding path (takes precedence over legacy bundles). Binding
    // resolution (integrity 500) + the live revocation recheck (a governance
    // denial) both happen BEFORE the claim — a recheck refusal is a denial, never
    // a re-claimable dispatch failure; the credential-turn is the only thing the
    // claim wraps.
    if let Some(surface) = surface {
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
                    &state,
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
        // Revocation recheck immediately before secret access (design :705-723):
        // a revoked/reauthorized connection or a deactivated owner fails closed.
        let conn = match crate::broker::recheck_binding(&state, scope, &binding).await {
            Ok(conn) => conn,
            Err(e) => {
                let reason: String = e.chars().take(300).collect();
                record_binding_denial(
                    &state,
                    scope,
                    session.id,
                    &req.tool_call_id,
                    &req.tool,
                    &reason,
                )
                .await;
                return Ok(Json(
                    json!({ "ok": false, "denied": true, "message": reason }),
                ));
            }
        };
        let (_, tool_name) = capability::parse_mcp_tool(&req.tool)
            .expect("gate allowed an mcp surface tool, so it parses");
        let dispatch = BrokerDispatch::Binding {
            conn: Box::new(conn),
            surface: &surface,
            binding: Box::new(binding),
            tool_name,
        };
        return execute_with_claim(
            &state,
            scope,
            session.id,
            &req.tool_call_id,
            &req.tool,
            &req.input,
            &input_digest,
            &dispatch,
        )
        .await;
    }

    // ── Legacy path (pre-Phase-C / in-flight runs): the credential comes from the
    // connection_id embedded in the frozen bundle server; the only live check is
    // broker.rs's status read (a legacy run froze no generation or owner to
    // compare — the residual invariant-21 gap the binding path closes). ──
    let srv = legacy_server.expect("gate allowed the call, so the tool is in the frozen set");
    let CapabilityServer::Brokered {
        name: server_name, ..
    } = srv
    else {
        unreachable!("class-checked above")
    };
    let (_, tool_name) = capability::parse_mcp_tool(&req.tool).expect("found in the frozen set");
    let dispatch = BrokerDispatch::Legacy {
        server: srv,
        server_name,
        tool_name,
    };
    execute_with_claim(
        &state,
        scope,
        session.id,
        &req.tool_call_id,
        &req.tool,
        &req.input,
        &input_digest,
        &dispatch,
    )
    .await
}

/// The execution-claim TTL (Phase E, #33; Gap 11): 10 minutes. This comfortably
/// covers a whole dispatch (the 30 s `MCP_TIMEOUT`, the single 401-reauth retry,
/// and a loser's up-to-30 s in-flight poll) with margin, so a live dispatch is
/// never swept to `ambiguous` under it — while a genuinely crashed `claimed` row
/// is reclaimed for classification promptly enough.
const TOOL_EXECUTION_CLAIM_TTL_SECS: i64 = 600;

/// The resolved brokered dispatch target (post-gate, post-recheck). Both the
/// Phase C binding path and the legacy embedded-connection path funnel through
/// the SAME execution-claim machinery; this is the only per-path difference — the
/// actual send + its ledger identity.
enum BrokerDispatch<'a> {
    Binding {
        // Boxed (large rows; this transient descriptor lives one request).
        conn: Box<fluidbox_db::IntegrationConnectionRow>,
        surface: &'a fluidbox_core::spec::BrokeredSurface,
        binding: Box<fluidbox_db::RunResourceBindingRow>,
        tool_name: &'a str,
    },
    Legacy {
        server: &'a CapabilityServer,
        server_name: &'a str,
        tool_name: &'a str,
    },
}

impl BrokerDispatch<'_> {
    /// One logical dispatch (incl. the broker's single sanctioned 401-reauth
    /// retry) → a classified [`crate::broker::DispatchOutcome`].
    async fn run(
        &self,
        state: &AppState,
        scope: TenantScope,
        session_id: uuid::Uuid,
        input: &Value,
    ) -> crate::broker::DispatchOutcome {
        match self {
            BrokerDispatch::Binding {
                conn,
                surface,
                binding,
                tool_name,
            } => {
                crate::broker::call_tool_for_conn(
                    state,
                    scope,
                    conn,
                    &surface.url,
                    tool_name,
                    input,
                    binding,
                    // Gap 12: pin the runtime MCP negotiation to the frozen version.
                    surface.protocol_version.as_deref(),
                )
                .await
            }
            BrokerDispatch::Legacy {
                server, tool_name, ..
            } => {
                crate::broker::call_tool_auth(state, scope, server, tool_name, input, session_id)
                    .await
            }
        }
    }
    /// The `tool.brokered` ledger server label (binding slot vs legacy server).
    fn server_label(&self) -> &str {
        match self {
            BrokerDispatch::Binding { surface, .. } => &surface.slot,
            BrokerDispatch::Legacy { server_name, .. } => server_name,
        }
    }
    /// The binding id for the ledger (Some on the Phase C path, None on legacy).
    fn binding_id(&self) -> Option<uuid::Uuid> {
        match self {
            BrokerDispatch::Binding { surface, .. } => Some(surface.binding_id),
            BrokerDispatch::Legacy { .. } => None,
        }
    }
}

/// Wrap the ALLOWED brokered dispatch in the durable execution claim (Phase E,
/// #33; Gap 11, plan E10). Take (or find) the claim keyed on the intent's exact
/// input digest, then:
///   - [`ClaimOutcome::SessionTerminal`] → the session stopped accepting work
///     (cancel-during-approval brokered half) → deny;
///   - [`ClaimOutcome::Won`] → dispatch once, complete the claim, respond;
///   - [`ClaimOutcome::Existing`] → adopt a terminal outcome (the duplicate-
///     return contract), re-claim a `failed_before_send` row for a fresh
///     dispatch, or bounded-poll a `claimed`/`ambiguous` row.
#[allow(clippy::too_many_arguments)]
async fn execute_with_claim(
    state: &AppState,
    scope: TenantScope,
    session_id: uuid::Uuid,
    tool_call_id: &str,
    tool: &str,
    input: &Value,
    input_digest: &str,
    dispatch: &BrokerDispatch<'_>,
) -> ApiResult<Json<Value>> {
    match fluidbox_db::claim_tool_execution(
        &state.pool,
        scope,
        session_id,
        tool_call_id,
        input_digest,
        TOOL_EXECUTION_CLAIM_TTL_SECS,
    )
    .await?
    {
        fluidbox_db::ClaimOutcome::SessionTerminal => Ok(Json(json!({
            "ok": false,
            "denied": true,
            "message": "session is terminal",
        }))),
        fluidbox_db::ClaimOutcome::Won { claim_id } => {
            finish_won_claim(
                state,
                scope,
                session_id,
                tool_call_id,
                tool,
                input,
                dispatch,
                claim_id,
            )
            .await
        }
        fluidbox_db::ClaimOutcome::Existing(row) => match row.state.as_str() {
            // Terminal → adopt the stored outcome verbatim (the duplicate-return
            // contract): a faithful retry returns byte-for-byte what the original did.
            "succeeded" | "failed_upstream" => Ok(Json(claim_response(
                &row.state,
                row.result_content.as_ref(),
                row.error_message.as_deref(),
            ))),
            // Ambiguous is NEVER auto-redispatched (invariant 15).
            "ambiguous" => Ok(Json(claim_response("ambiguous", None, None))),
            // The ONLY re-claimable state: re-claim (same row) and dispatch fresh;
            // a lost re-claim means another handler is in flight → poll.
            "failed_before_send" => {
                if fluidbox_db::reclaim_failed_before_send(
                    &state.pool,
                    scope,
                    session_id,
                    tool_call_id,
                    input_digest,
                    TOOL_EXECUTION_CLAIM_TTL_SECS,
                )
                .await?
                {
                    finish_won_claim(
                        state,
                        scope,
                        session_id,
                        tool_call_id,
                        tool,
                        input,
                        dispatch,
                        row.id,
                    )
                    .await
                } else {
                    poll_in_flight(state, scope, session_id, tool_call_id, input_digest).await
                }
            }
            // `claimed` (a concurrent dispatch in flight) → bounded poll.
            _ => poll_in_flight(state, scope, session_id, tool_call_id, input_digest).await,
        },
    }
}

/// Dispatch a WON claim once, settle the claim from its classified outcome, ledger
/// `tool.brokered` (with the settled `outcome`), and return the runner response.
#[allow(clippy::too_many_arguments)]
async fn finish_won_claim(
    state: &AppState,
    scope: TenantScope,
    session_id: uuid::Uuid,
    tool_call_id: &str,
    tool: &str,
    input: &Value,
    dispatch: &BrokerDispatch<'_>,
    claim_id: uuid::Uuid,
) -> ApiResult<Json<Value>> {
    let started = std::time::Instant::now();
    let outcome = dispatch.run(state, scope, session_id, input).await;
    let latency_ms = started.elapsed().as_millis() as u64;
    let comp = dispatch_to_completion(outcome);
    // Settle the claim (CAS from 'claimed'). A loser (already swept to ambiguous)
    // returns false — we still answer this request from the completion we computed;
    // the swept row is the durable truth a future duplicate adopts.
    fluidbox_db::complete_tool_execution(
        &state.pool,
        scope,
        claim_id,
        comp.state,
        comp.result_digest.as_deref(),
        comp.is_error,
        comp.result_content.as_ref(),
        comp.error_message.as_deref(),
    )
    .await?;
    record_brokered_exec(
        state,
        scope,
        session_id,
        tool_call_id,
        tool,
        dispatch.server_label(),
        dispatch.binding_id(),
        comp.ledger_ok,
        latency_ms,
        comp.result_digest.clone(),
        comp.ledger_error.clone(),
        Some(comp.state.to_string()),
    )
    .await;
    Ok(Json(claim_response(
        comp.state,
        comp.result_content.as_ref(),
        comp.error_message.as_deref(),
    )))
}

/// Bounded poll of an in-flight `claimed` row (every 500 ms, up to 30 s): a
/// terminal state adopts; still-`claimed` (or reset to `failed_before_send` by the
/// in-flight dispatcher's pre-send failure) returns a retryable in-flight tool
/// error the runner may re-request against.
async fn poll_in_flight(
    state: &AppState,
    scope: TenantScope,
    session_id: uuid::Uuid,
    tool_call_id: &str,
    input_digest: &str,
) -> ApiResult<Json<Value>> {
    for _ in 0..60 {
        tokio::time::sleep(Duration::from_millis(500)).await;
        if let Some(row) = fluidbox_db::get_tool_execution(
            &state.pool,
            scope,
            session_id,
            tool_call_id,
            input_digest,
        )
        .await?
        {
            match row.state.as_str() {
                "succeeded" | "failed_upstream" => {
                    return Ok(Json(claim_response(
                        &row.state,
                        row.result_content.as_ref(),
                        row.error_message.as_deref(),
                    )))
                }
                "ambiguous" => return Ok(Json(claim_response("ambiguous", None, None))),
                _ => {} // still claimed / failed_before_send → keep waiting.
            }
        }
    }
    Ok(Json(
        json!({ "ok": false, "error": "execution in flight; retry later" }),
    ))
}

/// The claim-completion columns + ledger meta a [`crate::broker::DispatchOutcome`]
/// settles to (plan E10). Kept as a plain struct so [`dispatch_to_completion`]
/// stays a PURE, unit-tested mapping.
struct Completion {
    state: &'static str,
    result_content: Option<Value>,
    is_error: Option<bool>,
    error_message: Option<String>,
    result_digest: Option<String>,
    ledger_ok: bool,
    ledger_error: Option<String>,
}

/// Map a broker outcome to the claim's terminal columns (plan E10): PURE.
/// `Definitive && !is_error → succeeded`; `Definitive && is_error →
/// failed_upstream` (an MCP isError result OR a synthesized upstream/transport
/// error, carrying the result so a duplicate adopts it); `NeverSent →
/// failed_before_send`; `Ambiguous → ambiguous`.
fn dispatch_to_completion(outcome: crate::broker::DispatchOutcome) -> Completion {
    use crate::broker::DispatchOutcome as D;
    match outcome {
        D::Definitive {
            content,
            is_error,
            structured,
        } => {
            let result_obj = brokered_result_obj(&content, is_error, structured.as_ref());
            let digest = brokered_result_digest(&content, structured.as_ref());
            // An error result (isError, or a synthesized upstream/transport error)
            // logs its text for the audit trail; a success logs only the digest.
            let err_text = if is_error {
                Some(first_text_block(&content))
            } else {
                None
            };
            Completion {
                state: if is_error {
                    "failed_upstream"
                } else {
                    "succeeded"
                },
                result_content: Some(result_obj),
                is_error: Some(is_error),
                error_message: err_text.clone(),
                result_digest: Some(digest),
                ledger_ok: !is_error,
                ledger_error: err_text,
            }
        }
        D::NeverSent(msg) => {
            let m: String = msg.chars().take(300).collect();
            Completion {
                state: "failed_before_send",
                result_content: None,
                is_error: Some(false),
                error_message: Some(m.clone()),
                result_digest: None,
                ledger_ok: false,
                ledger_error: Some(m),
            }
        }
        D::Ambiguous(msg) => {
            let m: String = msg.chars().take(300).collect();
            Completion {
                state: "ambiguous",
                result_content: None,
                is_error: Some(true),
                error_message: Some(m.clone()),
                result_digest: None,
                ledger_ok: false,
                ledger_error: Some(m),
            }
        }
    }
}

/// The runner-facing `{content, is_error, structured_content?}` result object
/// (E7-additive: `structured_content` only when present).
fn brokered_result_obj(content: &Value, is_error: bool, structured: Option<&Value>) -> Value {
    let mut r = json!({ "content": content, "is_error": is_error });
    if let Some(s) = structured {
        r["structured_content"] = s.clone();
    }
    r
}

/// The first text block of an MCP content array (capped) — the ledger error text.
fn first_text_block(content: &Value) -> String {
    content
        .as_array()
        .and_then(|a| {
            a.iter()
                .find_map(|b| b.get("text").and_then(|t| t.as_str()))
        })
        .unwrap_or("brokered call failed")
        .chars()
        .take(300)
        .collect()
}

/// The runner-facing JSON for a settled claim state + its stored columns. Used
/// IDENTICALLY for a fresh completion AND a duplicate's adoption, so a duplicate
/// returns byte-for-byte what the original did. PURE — unit-tested.
fn claim_response(
    state: &str,
    result_content: Option<&Value>,
    error_message: Option<&str>,
) -> Value {
    match state {
        "succeeded" | "failed_upstream" => match result_content {
            Some(rc) => json!({ "ok": true, "result": rc }),
            None => {
                json!({ "ok": false, "error": error_message.unwrap_or("brokered call failed") })
            }
        },
        // Never retried — the outcome is genuinely unknown (invariant 15).
        "ambiguous" => {
            json!({ "ok": false, "error": "brokered call outcome ambiguous — not retried" })
        }
        // failed_before_send / claimed (in-flight) → retryable.
        _ => json!({
            "ok": false,
            "error": error_message.unwrap_or("brokered dispatch did not complete; retry"),
        }),
    }
}

/// The ledger result digest for a brokered call (E7). Back-compatible: with no
/// `structuredContent` it is `digest_json(&content)` exactly as before; when the
/// result carried structured output, the digest covers both (still digest-only —
/// no payload reaches the ledger).
fn brokered_result_digest(content: &Value, structured: Option<&Value>) -> String {
    match structured {
        Some(s) => digest_json(&json!({ "content": content, "structuredContent": s })),
        None => digest_json(content),
    }
}

/// Ledger one `tool.brokered` event (identity + digests + latency; never
/// inputs, outputs, or secrets). `binding_id` is Some on the Phase C binding
/// path, None on the legacy embedded-connection path. `outcome` is the durable
/// execution-claim state this call settled at (Phase E, #33; Gap 11).
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
    outcome: Option<String>,
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
            outcome,
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

// ─── Frozen-schema gate decision (Gap 12, plan E9) — pure, no DB ───────────
#[cfg(test)]
mod schema_gate_tests {
    use super::*;
    use fluidbox_core::capability::{CapabilityServer, FrozenBundle, ToolSnapshot};
    use fluidbox_core::schema_guard::SchemaCache;
    use fluidbox_core::spec::{Autonomy, BrokeredSurface, Budgets, TrustTier, WorkspaceSpec};
    use uuid::Uuid;

    fn base_spec(trust_tier: TrustTier) -> RunSpec {
        RunSpec {
            agent_id: Uuid::now_v7(),
            agent_revision_id: Uuid::now_v7(),
            agent_name: "a".into(),
            harness: "claude-agent-sdk".into(),
            runner_image: "img".into(),
            model: "m".into(),
            system_prompt: None,
            task: "t".into(),
            workspace: WorkspaceSpec::Scratch,
            autonomy: Autonomy::Supervised,
            trust_tier,
            budgets: Budgets::default(),
            policy_id: Uuid::now_v7(),
            policy_version: 1,
            policy_snapshot: fluidbox_core::policy::Policy::parse_yaml("name: p").unwrap(),
            invocation: Default::default(),
            result_destinations: vec![],
            capabilities: vec![],
            brokered: vec![],
        }
    }

    fn surface(schema: Value, protocol_version: Option<&str>) -> BrokeredSurface {
        BrokeredSurface {
            slot: "gh".into(),
            url: "https://mcp.test/mcp".into(),
            binding_id: Uuid::now_v7(),
            snapshot_version: 1,
            tools: vec![ToolSnapshot {
                name: "act".into(),
                description: "d".into(),
                input_schema: schema,
                output_schema: None,
                annotations: None,
            }],
            // Unique digest per surface so distinct schemas key distinct cache
            // entries (the gate never mixes compilations across surfaces).
            tools_digest: format!("sha256:{}", Uuid::now_v7().simple()),
            protocol_version: protocol_version.map(str::to_string),
        }
    }

    /// A run with one brokered surface exposing `mcp__gh__act` under `schema`.
    fn brokered_run(schema: Value, protocol_version: Option<&str>) -> RunSpec {
        let mut spec = base_spec(TrustTier::Trusted);
        spec.brokered = vec![surface(schema, protocol_version)];
        spec
    }

    /// An object schema that requires an integer member `n`.
    fn int_field_schema() -> Value {
        json!({
            "type": "object",
            "properties": {"n": {"type": "integer"}},
            "required": ["n"]
        })
    }

    #[test]
    fn bad_args_are_denied_with_a_schema_reason() {
        let cache = SchemaCache::new(8);
        let spec = brokered_run(int_field_schema(), Some("2025-11-25"));
        let reason = schema_gate_decision(&cache, &spec, "mcp__gh__act", &json!({"n": "notint"}))
            .expect("bad args must be denied");
        assert!(
            reason.starts_with("arguments rejected by frozen schema:"),
            "got: {reason}"
        );
        // A JSON-pointer PATH to the failing member, never the value.
        assert!(
            reason.contains("/n"),
            "expected a pointer to /n, got: {reason}"
        );
    }

    #[test]
    fn good_args_proceed() {
        let cache = SchemaCache::new(8);
        let spec = brokered_run(int_field_schema(), Some("2025-11-25"));
        assert_eq!(
            schema_gate_decision(&cache, &spec, "mcp__gh__act", &json!({"n": 7})),
            None,
            "valid args must proceed to the next gate stage"
        );
    }

    #[test]
    fn builtins_bypass_schema_entirely() {
        let cache = SchemaCache::new(8);
        // Even a run that HAS a brokered surface must not schema-check built-ins:
        // they are never mcp__-prefixed and carry no frozen schema.
        let spec = brokered_run(int_field_schema(), Some("2025-11-25"));
        for (tool, input) in [
            ("Bash", json!({"command": "ls"})),
            (
                "Edit",
                json!({"file_path": "/x", "old_string": "a", "new_string": "b"}),
            ),
            ("Read", json!({"file_path": "/x"})),
        ] {
            assert_eq!(
                schema_gate_decision(&cache, &spec, tool, &input),
                None,
                "built-in {tool} must bypass schema validation"
            );
        }
    }

    #[test]
    fn an_invalid_frozen_schema_denies_with_refresh_hint() {
        let cache = SchemaCache::new(8);
        // `type` must be a string; a number is not a valid schema → uncompilable.
        let spec = brokered_run(json!({"type": 123}), Some("2025-11-25"));
        let reason = schema_gate_decision(&cache, &spec, "mcp__gh__act", &json!({"n": 1}))
            .expect("an invalid frozen schema must deny");
        assert_eq!(reason, "frozen schema invalid — refresh the snapshot");
    }

    #[test]
    fn a_non_local_ref_schema_denies_before_reaching_args() {
        let cache = SchemaCache::new(8);
        // A remote $ref is refused by guard_schema — the tool is un-callable.
        let spec = brokered_run(
            json!({"$ref": "https://evil.test/s.json"}),
            Some("2025-11-25"),
        );
        assert_eq!(
            schema_gate_decision(&cache, &spec, "mcp__gh__act", &json!({"anything": true})),
            Some("frozen schema invalid — refresh the snapshot".to_string())
        );
    }

    #[test]
    fn order_readonly_records_the_schema_denial_not_trust_tier() {
        // This pins ONLY the PURE decision: `schema_gate_decision` produces a
        // schema deny for bad mcp args regardless of trust tier (it never consults
        // the tier). The actual GATE-ORDER placement — that `gate_tool_call`
        // consults schema BEFORE the trust-tier floor — is a DB-coupled property
        // proven by the governance/hardening e2e (a ReadOnly run with bad args
        // records source="schema", not source="trust_tier"), not by this unit test.
        let cache = SchemaCache::new(8);
        let mut spec = base_spec(TrustTier::ReadOnly);
        spec.brokered = vec![surface(int_field_schema(), Some("2025-11-25"))];
        let reason = schema_gate_decision(&cache, &spec, "mcp__gh__act", &json!({"n": "bad"}))
            .expect("the schema decision must be available before the tier check");
        assert!(
            reason.starts_with("arguments rejected by frozen schema:"),
            "a ReadOnly run with bad args must record the SCHEMA denial, got: {reason}"
        );
    }

    #[test]
    fn deterministic_so_a_faithful_retry_adopts_the_same_verdict() {
        // The decision is a pure function of (frozen set, args) — a faithful retry
        // recomputes the identical deny, so the CAS-then-ledger adoption is safe.
        let cache = SchemaCache::new(8);
        let spec = brokered_run(int_field_schema(), Some("2025-11-25"));
        let first = schema_gate_decision(&cache, &spec, "mcp__gh__act", &json!({"n": "x"}));
        let second = schema_gate_decision(&cache, &spec, "mcp__gh__act", &json!({"n": "x"}));
        assert!(first.is_some());
        assert_eq!(first, second, "the schema verdict must be deterministic");
    }

    #[test]
    fn legacy_bundle_without_protocol_version_validates_under_2020_12() {
        // A legacy capability bundle carries NO protocol_version ⇒ dialect_for
        // defaults it to 2020-12. `prefixItems` is a 2020-12 assertion (ignored by
        // draft-07), so a run under the 2020-12 default MUST enforce it.
        let cache = SchemaCache::new(8);
        let mut spec = base_spec(TrustTier::Trusted);
        let bundle = FrozenBundle {
            id: Uuid::now_v7(),
            name: "kb-tools".into(),
            version: 1,
            definition_digest: format!("sha256:{}", Uuid::now_v7().simple()),
            servers: vec![CapabilityServer::Sandbox {
                name: "kb".into(),
                command: "node".into(),
                args: vec![],
                identity: None,
                tools: vec![ToolSnapshot {
                    name: "search".into(),
                    description: "d".into(),
                    input_schema: json!({"type": "array", "prefixItems": [{"type": "string"}]}),
                    output_schema: None,
                    annotations: None,
                }],
            }],
        };
        spec.capabilities = vec![bundle];
        // A numeric item-0 violates prefixItems under 2020-12 → denied.
        assert!(
            schema_gate_decision(&cache, &spec, "mcp__kb__search", &json!([42])).is_some(),
            "legacy bundle must validate under the 2020-12 default"
        );
        // A string item-0 satisfies it → proceeds.
        assert_eq!(
            schema_gate_decision(&cache, &spec, "mcp__kb__search", &json!(["ok"])),
            None
        );
    }

    // ── Execution-claim response mapping (Phase E, #33; Gap 11) — PURE ────────

    #[test]
    fn dispatch_to_completion_maps_every_state() {
        use crate::broker::DispatchOutcome as D;
        // Definitive success → succeeded, carries the result object + digest.
        let c = dispatch_to_completion(D::Definitive {
            content: json!([{"type":"text","text":"ok"}]),
            is_error: false,
            structured: None,
        });
        assert_eq!(c.state, "succeeded");
        assert!(c.ledger_ok);
        assert!(c.result_content.is_some() && c.result_digest.is_some());
        assert!(c.ledger_error.is_none());
        // Definitive error → failed_upstream, STILL carries the result (adoption),
        // and logs the error text.
        let c = dispatch_to_completion(D::Definitive {
            content: json!([{"type":"text","text":"boom"}]),
            is_error: true,
            structured: None,
        });
        assert_eq!(c.state, "failed_upstream");
        assert!(!c.ledger_ok);
        assert!(c.result_content.is_some());
        assert_eq!(c.ledger_error.as_deref(), Some("boom"));
        // NeverSent → failed_before_send (re-claimable), no stored result.
        let c = dispatch_to_completion(D::NeverSent("connect refused".into()));
        assert_eq!(c.state, "failed_before_send");
        assert!(c.result_content.is_none() && !c.ledger_ok);
        // Ambiguous → ambiguous, no stored result.
        let c = dispatch_to_completion(D::Ambiguous("timeout".into()));
        assert_eq!(c.state, "ambiguous");
        assert!(c.result_content.is_none());
    }

    #[test]
    fn claim_response_shapes_per_state() {
        let result = json!({ "content": [{"type":"text","text":"ok"}], "is_error": false });
        // succeeded/failed_upstream with a stored result → {ok:true, result}.
        let r = claim_response("succeeded", Some(&result), None);
        assert_eq!(r["ok"], true);
        assert_eq!(r["result"], result);
        assert_eq!(
            claim_response("failed_upstream", Some(&result), None)["ok"],
            true
        );
        // ambiguous → a not-retried error (invariant 15), never {ok:true}.
        let r = claim_response("ambiguous", None, None);
        assert_eq!(r["ok"], false);
        assert!(r["error"].as_str().unwrap().contains("ambiguous"));
        // failed_before_send / claimed → retryable error.
        assert_eq!(
            claim_response("failed_before_send", None, Some("x"))["ok"],
            false
        );
        assert_eq!(claim_response("claimed", None, None)["ok"], false);
    }

    #[test]
    fn fresh_completion_and_adoption_use_the_same_pure_mapping() {
        // The duplicate-adopt contract rests on ONE pure fn: the fresh Won path and
        // the adoption path BOTH call `claim_response` with the columns
        // `dispatch_to_completion` produced / `complete_tool_execution` stored. So a
        // duplicate returns byte-for-byte what the original did — proven here for
        // the pure layer; the DB round-trip + single-dispatch is the DB test's job.
        use crate::broker::DispatchOutcome as D;
        let comp = dispatch_to_completion(D::Definitive {
            content: json!([{"type":"text","text":"payload"}]),
            is_error: false,
            structured: Some(json!({ "k": "v" })),
        });
        let fresh = claim_response(
            comp.state,
            comp.result_content.as_ref(),
            comp.error_message.as_deref(),
        );
        // A duplicate reads back the SAME stored columns and maps them identically.
        let adopted = claim_response(
            comp.state,
            comp.result_content.as_ref(),
            comp.error_message.as_deref(),
        );
        assert_eq!(fresh, adopted);
        assert_eq!(fresh["ok"], true);
        // structuredContent survives into the stored/returned result object (E7).
        assert_eq!(fresh["result"]["structured_content"], json!({ "k": "v" }));
    }
}
