//! Background workers: heartbeat watchdog, budget sweeper (wall-clock),
//! approval expiry, the restart-recoverable finalize driver, and boot-time
//! orphan reaping.

use crate::orchestrator;
use crate::state::AppState;
use fluidbox_core::spec::RunSpec;
use fluidbox_core::traits::SandboxHandle;
use fluidbox_db::TenantScope;
use std::time::Duration;

/// Reap any sandboxes the provider manages that have no matching live session
/// (or whose session is already terminal), and resume any finalization the
/// control plane was driving when it went down. Runs once at boot.
pub async fn boot_orphan_sweep(state: AppState) {
    // Resume interrupted finalizations FIRST, so a crash mid-collect finishes
    // (and reaps its own sandbox) before the orphan sweep would kill it.
    recover_finalizations(&state).await;

    match state.provider.list_managed().await {
        Ok(managed) => {
            for (session_id, handle) in managed {
                // Same discipline as the periodic reconcile: strict status
                // parse (a status written by a NEWER deploy is not proof of
                // death — a rollback restart must not kill its live pods),
                // and a DB error skips rather than terminates.
                let terminal =
                    match fluidbox_db::system_worker::get_session(&state.pool, session_id).await {
                        Ok(None) => true, // unknown session → orphan
                        Ok(Some(s)) => {
                            match fluidbox_core::state::SessionStatus::parse(&s.status) {
                                Some(st) => st.is_terminal(),
                                None => {
                                    tracing::warn!(
                                        "boot sweep: session {session_id} has unknown status '{}' \
                                     (newer deploy?); leaving its sandbox alone",
                                        s.status
                                    );
                                    false
                                }
                            }
                        }
                        Err(e) => {
                            tracing::warn!("boot sweep: session lookup {session_id} failed: {e}");
                            false
                        }
                    };
                if terminal {
                    tracing::info!("boot sweep: reaping orphan sandbox for {session_id}");
                    let _ = state.provider.terminate(&handle).await;
                }
            }
        }
        Err(e) => tracing::warn!("boot orphan sweep failed: {e}"),
    }
}

/// Re-drive every session that has a persisted finalization intent but hasn't
/// reached terminal — the restart-recovery + crashed-driver path. Claim-
/// guarded in `drive_finalization`, so this never double-finalizes.
async fn recover_finalizations(state: &AppState) {
    match fluidbox_db::system_worker::pending_finalizations(&state.pool).await {
        Ok(ids) => {
            for id in ids {
                tracing::info!("resuming interrupted finalization for {id}");
                // Bounded so one hung drive cannot starve the rest of the
                // backlog (this worker is serial). An abandoned drive's
                // claim goes stale and is retried; 300 s comfortably covers
                // the worst healthy path (quiesce 30 + exit-wait 30 +
                // collect 120 + terminate 60) while staying under the 420 s
                // claim window, so drivers never overlap.
                if tokio::time::timeout(
                    Duration::from_secs(300),
                    orchestrator::drive_finalization(state, id),
                )
                .await
                .is_err()
                {
                    tracing::warn!("finalization drive for {id} timed out; will retry");
                }
            }
        }
        Err(e) => tracing::warn!("finalization recovery query failed: {e}"),
    }
}

pub fn spawn_all(state: AppState) {
    tokio::spawn(watchdog(state.clone()));
    tokio::spawn(budget_sweeper(state.clone()));
    tokio::spawn(approval_expiry(state.clone()));
    // Archive-transport providers only: host-dir providers (Docker) never
    // store archives, so the sweep would scan an absent directory forever.
    if state.provider.workspace_transport() == fluidbox_core::traits::WorkspaceTransport::Archive {
        tokio::spawn(archive_ttl_sweep(state.clone()));
    }
    tokio::spawn(reconcile_managed(state.clone()));
    tokio::spawn(finalize_worker(state));
}

/// What the periodic reconcile does with one managed sandbox (M5). Pure so
/// the decision table is unit-testable.
#[derive(Debug, PartialEq, Eq)]
enum ReconcileAction {
    /// Orphan (unknown session) or leak (terminal session): kill the sandbox.
    Terminate,
    /// Live session that lost the crash race between provision and
    /// `set_sandbox_handle`: persist the handle so every sweeper sees it.
    Adopt,
    /// Healthy, or owned by the finalizer (winding down): never touch.
    Leave,
}

/// What the reconciler could learn about a sandbox's session. `Unparseable`
/// is distinct from `Missing` on purpose: an unknown status string means a
/// NEWER deploy wrote it (statuses are unconstrained text by design) — an
/// older replica must never read that as "dead" and kill a live sandbox.
#[derive(Debug, PartialEq, Eq)]
enum SessionLookup {
    Missing,
    Known(fluidbox_core::state::SessionStatus),
    Unparseable,
}

fn reconcile_action(session: SessionLookup, has_handle: bool) -> ReconcileAction {
    match session {
        SessionLookup::Missing => ReconcileAction::Terminate,
        SessionLookup::Unparseable => ReconcileAction::Leave,
        SessionLookup::Known(s) if s.is_terminal() => ReconcileAction::Terminate,
        // The finalizer owns winding-down sandboxes — collection may be in
        // flight; it reaps on completion, and recovery re-drives it.
        SessionLookup::Known(s) if s.is_winding_down() => ReconcileAction::Leave,
        SessionLookup::Known(_) if !has_handle => ReconcileAction::Adopt,
        SessionLookup::Known(_) => ReconcileAction::Leave,
    }
}

/// Periodic managed-sandbox reconcile (M5) — the boot sweep, made continuous
/// and adoption-capable. Closes two windows the boot-only sweep left open:
/// a crash between `provision` and `set_sandbox_handle` produced a session
/// invisible to EVERY sweeper at once (heartbeats refresh `updated_at`, the
/// boot sweep skips live sessions, the budget sweeper needs `running`) with a
/// pod nobody owned; and a cancel-during-provisioning reaped before the
/// handle landed, leaking the pod until the next restart.
async fn reconcile_managed(state: AppState) {
    let mut tick = tokio::time::interval(Duration::from_secs(60));
    loop {
        tick.tick().await;
        let managed = match state.provider.list_managed().await {
            Ok(m) => m,
            Err(e) => {
                tracing::warn!("reconcile: list_managed failed: {e}");
                continue;
            }
        };
        for (session_id, handle) in managed {
            let session =
                match fluidbox_db::system_worker::get_session(&state.pool, session_id).await {
                    Ok(s) => s,
                    // A transient DB error is NOT proof the session is unknown —
                    // unlike the boot sweep, a periodic worker must never kill a
                    // possibly-live sandbox on a blip. Next tick retries.
                    Err(e) => {
                        tracing::warn!("reconcile: session lookup {session_id} failed: {e}");
                        continue;
                    }
                };
            // STRICT status parse — never status_enum(), whose unparseable→
            // Failed fallback would read a newer deploy's status as terminal.
            let lookup = match &session {
                None => SessionLookup::Missing,
                Some(s) => match fluidbox_core::state::SessionStatus::parse(&s.status) {
                    Some(st) => SessionLookup::Known(st),
                    None => {
                        tracing::warn!(
                            "reconcile: session {session_id} has unknown status '{}' \
                             (newer deploy?); leaving its sandbox alone",
                            s.status
                        );
                        SessionLookup::Unparseable
                    }
                },
            };
            let has_handle = session
                .as_ref()
                .map(|s| s.sandbox_handle.is_some())
                .unwrap_or(false);
            let label = session
                .as_ref()
                .map(|s| s.status.clone())
                .unwrap_or_else(|| "unknown".into());
            match reconcile_action(lookup, has_handle) {
                ReconcileAction::Leave => {}
                ReconcileAction::Terminate => {
                    tracing::info!(
                        "reconcile: terminating sandbox {} (session {session_id}: {label})",
                        handle.external_id,
                    );
                    let _ = state.provider.terminate(&handle).await;
                }
                ReconcileAction::Adopt => {
                    // The handle from list_managed carries the LIVE object's
                    // UID (validated there: session label, namespace, uid) —
                    // every later mutation is preconditioned on it. The
                    // adoption itself is a GUARDED update (handle still null,
                    // status still active), so racing run()'s own
                    // set_sandbox_handle, a concurrent cancel, or a terminal
                    // transition can never be overwritten or resurrected.
                    let Ok(v) = serde_json::to_value(&handle) else {
                        continue;
                    };
                    // Adopt implies a Known session — scope to its own tenant.
                    let Some(scope) = session.as_ref().map(|s| TenantScope::assume(s.tenant_id))
                    else {
                        continue;
                    };
                    match fluidbox_db::adopt_sandbox_handle(&state.pool, scope, session_id, &v)
                        .await
                    {
                        Ok(true) => {
                            tracing::warn!(
                                "reconcile: adopted sandbox {} for handle-less session {session_id}",
                                handle.external_id,
                            );
                            crate::ledger::record(
                                &state,
                                scope,
                                session_id,
                                fluidbox_core::event::Actor::System,
                                fluidbox_core::event::EventBody::AgentMessage {
                                    role: "system".into(),
                                    text: format!(
                                        "sandbox adopted after control-plane interruption ({})",
                                        handle.external_id.chars().take(48).collect::<String>()
                                    ),
                                },
                            )
                            .await;
                        }
                        Ok(false) => {} // Lost the race to run()/cancel — correct.
                        Err(e) => {
                            tracing::warn!("reconcile: adoption of {session_id} failed: {e}")
                        }
                    }
                }
            }
        }
    }
}

/// The stored-archive leak backstop (L3): archives are deleted at finalize —
/// this sweep reclaims the crash windows (pre-launch death, or a crash after
/// the terminal transition but before `delete_archive`). The TTL is floored
/// at 6 h so a mis-set value can never race an archive a live session still
/// needs (init re-execution re-fetches it for the pod's whole lifetime).
const ARCHIVE_TTL_FLOOR_SECS: u64 = 6 * 3600;

async fn archive_ttl_sweep(state: AppState) {
    let configured = state.cfg.archive_ttl_secs;
    let ttl = Duration::from_secs(configured.max(ARCHIVE_TTL_FLOOR_SECS));
    if configured < ARCHIVE_TTL_FLOOR_SECS {
        tracing::warn!(
            "FLUIDBOX_ARCHIVE_TTL_SECS={configured} is below the {ARCHIVE_TTL_FLOOR_SECS}s floor; using the floor"
        );
    }
    let mut tick = tokio::time::interval(Duration::from_secs(3600));
    loop {
        tick.tick().await;
        let data_dir = state.cfg.data_dir.clone();
        let candidates = tokio::task::spawn_blocking(move || {
            orchestrator::stale_archive_candidates(&data_dir, ttl)
        })
        .await
        .unwrap_or_else(|e| {
            tracing::warn!("archive TTL sweep task failed: {e}");
            Vec::new()
        });
        let mut removed = 0usize;
        for path in candidates {
            // Age alone is not proof of leak: a run with a wall-clock budget
            // longer than the TTL still needs its archive for a possible
            // init re-execution. Only a terminal/unknown session's archive
            // is reclaimable; a DB blip keeps the file for the next pass.
            let deletable = match orchestrator::archive_session_id(&path) {
                None => true, // not a name this server writes — reclaim
                Some(sid) => {
                    match fluidbox_db::system_worker::get_session(&state.pool, sid).await {
                        Ok(None) => true,
                        Ok(Some(s)) => {
                            match fluidbox_core::state::SessionStatus::parse(&s.status) {
                                Some(st) => st.is_terminal(),
                                None => false, // newer deploy's status — fail safe
                            }
                        }
                        Err(e) => {
                            tracing::warn!("archive TTL sweep: session lookup failed: {e}");
                            false
                        }
                    }
                }
            };
            if !deletable {
                tracing::warn!(
                    "archive TTL sweep: {} outlived the TTL but its session is still live; keeping",
                    path.display()
                );
                continue;
            }
            match std::fs::remove_file(&path) {
                Ok(()) => {
                    tracing::info!("archive TTL sweep removed {}", path.display());
                    removed += 1;
                }
                Err(e) => tracing::warn!("archive TTL sweep failed on {}: {e}", path.display()),
            }
        }
        if removed > 0 {
            tracing::info!("archive TTL sweep reclaimed {removed} stale archive(s)");
        }
    }
}

/// Launch age is measured from `created_at` — a timestamp heartbeats can NOT
/// refresh (M5) — so this is an ABSOLUTE deadline for the whole launch
/// (materialize + pack + provision), not a progress detector. 30 min covers
/// a large repo comfortably; operators with outliers can raise it via
/// `FLUIDBOX_STALE_LAUNCH_MINS`.
fn stale_launch_mins() -> i32 {
    // Floored at 5: zero/negative would make every prelaunch session "stale"
    // and the 15 s watchdog would fail healthy launches instantly.
    std::env::var("FLUIDBOX_STALE_LAUNCH_MINS")
        .ok()
        .and_then(|v| v.parse::<i32>().ok())
        .map(|v| v.max(5))
        .unwrap_or(30)
}

/// Fail sessions whose sandbox died or whose heartbeat went stale.
async fn watchdog(state: AppState) {
    let stale_launch_mins = stale_launch_mins();
    let mut tick = tokio::time::interval(Duration::from_secs(15));
    loop {
        tick.tick().await;
        let active = match fluidbox_db::system_worker::sessions_in_status(
            &state.pool,
            &["running", "awaiting_approval", "initializing"],
        )
        .await
        {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!("watchdog query failed: {e}");
                continue;
            }
        };
        let now = chrono::Utc::now();
        for s in active {
            // Stale heartbeat (only meaningful once running).
            if s.status == "running" {
                if let Some(hb) = s.last_heartbeat_at {
                    if (now - hb).num_seconds() > 60 {
                        // Confirm the sandbox is actually gone before failing.
                        if sandbox_dead(&state, &s.sandbox_handle).await {
                            tracing::warn!("watchdog: {} heartbeat stale + sandbox dead", s.id);
                            // A DbError start is retried by the next tick.
                            let _ =
                                orchestrator::fail(&state, s.id, "sandbox died (stale heartbeat)")
                                    .await;
                        }
                    }
                }
            }
        }

        // Sessions stuck before launch (created/provisioning/initializing).
        match fluidbox_db::system_worker::stale_nonstarted_sessions(&state.pool, stale_launch_mins)
            .await
        {
            Ok(stale) => {
                for s in stale {
                    tracing::warn!(
                        "watchdog: {} stalled in '{}' for >{}m — failing",
                        s.id,
                        s.status,
                        stale_launch_mins
                    );
                    // A DbError start is retried by the next tick.
                    let _ = orchestrator::fail(
                        &state,
                        s.id,
                        "stalled before launch (control plane interrupted)",
                    )
                    .await;
                }
            }
            Err(e) => tracing::warn!("stale-launch sweep failed: {e}"),
        }
    }
}

async fn sandbox_dead(state: &AppState, handle_json: &Option<serde_json::Value>) -> bool {
    let Some(json) = handle_json else { return true };
    let Ok(handle) = serde_json::from_value::<SandboxHandle>(json.clone()) else {
        return true;
    };
    match state.provider.state(&handle).await {
        Ok(st) => !st.is_live(),
        // A transient provider error is NOT proof of death — leave it for the
        // next tick rather than failing a possibly-live session.
        Err(_) => false,
    }
}

/// Enforce wall-clock budgets (token/cost budgets are enforced inline in the
/// facade; tool-call budgets inline in the permission gate).
async fn budget_sweeper(state: AppState) {
    let mut tick = tokio::time::interval(Duration::from_secs(10));
    loop {
        tick.tick().await;

        // Phase E (#33; Gap 11): sweep stale execution claims on the same 10s
        // cadence. A `claimed` row whose control-plane dispatcher crashed
        // mid-flight is CAS'd to `ambiguous` past its TTL (never auto-retried —
        // invariant 15) and ledgered so the timeline records the unknown outcome.
        match fluidbox_db::system_worker::sweep_stale_execution_claims(
            &state.pool,
            chrono::Utc::now(),
        )
        .await
        {
            Ok(swept) => {
                for (tenant_id, session_id, tool_call_id, tool) in swept {
                    // Scope from the returned row's tenant, like every worker.
                    let scope = TenantScope::assume(tenant_id);
                    let tool = tool.unwrap_or_else(|| "(unknown)".to_string());
                    let server = fluidbox_core::capability::parse_mcp_tool(&tool)
                        .map(|(s, _)| s.to_string())
                        .unwrap_or_else(|| "broker".to_string());
                    crate::ledger::record(
                        &state,
                        scope,
                        session_id,
                        fluidbox_core::event::Actor::System,
                        fluidbox_core::event::EventBody::BrokeredToolCall {
                            tool_call_id,
                            tool,
                            server,
                            binding_id: None,
                            ok: false,
                            latency_ms: 0,
                            result_digest: None,
                            error: Some("execution claim expired — outcome unknown".into()),
                            outcome: Some("ambiguous".into()),
                        },
                    )
                    .await;
                }
            }
            Err(e) => tracing::warn!("stale execution-claim sweep failed: {e}"),
        }

        let active = match fluidbox_db::system_worker::sessions_in_status(
            &state.pool,
            &["running", "awaiting_approval"],
        )
        .await
        {
            Ok(s) => s,
            Err(_) => continue,
        };
        let now = chrono::Utc::now();
        for s in active {
            let Ok(run_spec) = serde_json::from_value::<RunSpec>(s.run_spec.clone()) else {
                continue;
            };
            // Budget reads scope to the session's own tenant (from the fetched row).
            let scope = TenantScope::assume(s.tenant_id);
            if let Some(max) = run_spec.budgets.max_wall_clock_secs {
                if let Some(started) = s.started_at {
                    if (now - started).num_seconds() as u64 > max {
                        crate::ledger::record(
                            &state,
                            scope,
                            s.id,
                            fluidbox_core::event::Actor::System,
                            fluidbox_core::event::EventBody::BudgetExceeded {
                                budget: "max_wall_clock_secs".into(),
                                limit: max.to_string(),
                                spent: (now - started).num_seconds().to_string(),
                            },
                        )
                        .await;
                        // Forced stop: the runner is live and must be told to
                        // quiesce before collection. A DbError start is
                        // retried by the next sweep tick (the session is
                        // still active until the intent lands).
                        let _ = orchestrator::finalize_forced(
                            &state,
                            s.id,
                            "budget_exceeded",
                            "wall-clock budget exceeded",
                        )
                        .await;
                        continue;
                    }
                }
            }

            // Token / cost / tool-call budgets, from the same DB truth the
            // facade and permission gate read. Those enforce inline, but
            // their finalize starts ride detached in-memory retries — this
            // sweep is the crash-durable driver, and the only one for an
            // idle runner that makes no further requests. Thresholds mirror
            // the inline checks exactly (>=).
            let mut over: Option<&'static str> = None;
            if run_spec.budgets.max_tokens.is_some() || run_spec.budgets.max_cost_usd.is_some() {
                if let Ok(totals) = fluidbox_db::usage_totals(&state.pool, scope, s.id).await {
                    if let Some(max) = run_spec.budgets.max_cost_usd {
                        if totals.cost_usd >= max {
                            over = Some("max_cost_usd");
                        }
                    }
                    if over.is_none() {
                        if let Some(max) = run_spec.budgets.max_tokens {
                            let used = (totals.input_tokens
                                + totals.output_tokens
                                + totals.cache_read_tokens
                                + totals.cache_write_tokens)
                                as u64;
                            if used >= max {
                                over = Some("max_tokens");
                            }
                        }
                    }
                }
            }
            if over.is_none() {
                if let Some(max) = run_spec.budgets.max_tool_calls {
                    if let Ok(n) = fluidbox_db::tool_call_count(&state.pool, scope, s.id).await {
                        // STRICTLY greater — the gate permits exactly `max`
                        // calls (it denies at used > max, with the current
                        // call's intent already counted); firing at >= would
                        // kill a session whose max-th call is legitimately
                        // mid-flight.
                        if n as u64 > max {
                            over = Some("max_tool_calls");
                        }
                    }
                }
            }
            if let Some(which) = over {
                let _ = orchestrator::finalize_forced(
                    &state,
                    s.id,
                    "budget_exceeded",
                    &format!("{which} budget exceeded"),
                )
                .await;
            }
        }
    }
}

/// Expire pending approvals whose deadline passed, and wake their waiters.
async fn approval_expiry(state: AppState) {
    let mut tick = tokio::time::interval(Duration::from_secs(5));
    loop {
        tick.tick().await;
        match fluidbox_db::system_worker::expire_stale_approvals(&state.pool).await {
            Ok(expired) => {
                for a in expired {
                    state.approvals.wake(a.id).await;
                }
            }
            Err(e) => tracing::warn!("approval expiry sweep failed: {e}"),
        }
    }
}

/// Kubernetes netpol run-gate (design 2026-07-15): probe that the CNI enforces
/// NetworkPolicy (+:8788 / -:8787) before admitting runs, and re-check
/// periodically. FAILS CLOSED — `netpol_verified` stays false until proven.
pub fn spawn_netpol_gate(state: AppState) {
    tokio::spawn(async move {
        use std::sync::atomic::Ordering;
        // The public service pairs with the internal one by Helm naming.
        let Some(internal_svc) = state.cfg.internal_service.clone() else {
            tracing::warn!(
                "netpol gate: no internal Service configured; cannot verify — runs stay gated"
            );
            return;
        };
        let ns = state
            .cfg
            .internal_service_namespace
            .clone()
            .unwrap_or_default();
        let public_svc = internal_svc
            .strip_suffix("-internal")
            .map(|p| format!("{p}-server"))
            .unwrap_or_else(|| internal_svc.clone());
        // The probe must carry the SANDBOX placement (nodeSelector,
        // tolerations, runtimeClass, priorityClass, pull secrets) so the gate
        // certifies the pool sandboxes actually run on — same env the
        // provider itself reads.
        let k8s_cfg = fluidbox_provider_k8s::config::K8sConfig::from_env();

        loop {
            let internal_ip =
                fluidbox_provider_k8s::netpol::resolve_service_clusterip(&ns, &internal_svc)
                    .await
                    .ok()
                    .flatten();
            let public_ip =
                fluidbox_provider_k8s::netpol::resolve_service_clusterip(&ns, &public_svc)
                    .await
                    .ok()
                    .flatten();
            match (internal_ip, public_ip) {
                (Some(i), Some(p)) => {
                    let r = fluidbox_provider_k8s::netpol::verify_netpol(
                        &k8s_cfg,
                        &state.cfg.netpol_probe_image,
                        &i,
                        &p,
                    )
                    .await;
                    use fluidbox_provider_k8s::netpol::NetpolResult;
                    let ok = r == NetpolResult::Enforced;
                    state.netpol_verified.store(ok, Ordering::SeqCst);
                    if ok {
                        tracing::info!("netpol gate: enforcement verified (+:8788 -:8787)");
                    } else {
                        tracing::warn!("netpol gate: NOT verified ({r:?}) — runs blocked");
                    }
                }
                _ => {
                    // Fail closed like the probe branch: an unresolvable
                    // Service is NOT continued proof of enforcement — a
                    // previously-true gate must not coast on stale evidence.
                    state.netpol_verified.store(false, Ordering::SeqCst);
                    tracing::warn!(
                        "netpol gate: could not resolve Service ClusterIPs; runs stay gated"
                    );
                }
            }
            // Once enforced, re-check every 6h; while unverified, retry sooner.
            if state.netpol_verified.load(Ordering::SeqCst) {
                tokio::time::sleep(Duration::from_secs(6 * 3600)).await;
            } else {
                tokio::time::sleep(Duration::from_secs(30)).await;
            }
        }
    });
}

/// Restart-recoverable finalize driver: re-drives any session stuck in
/// `cancelling`/`finalizing` with a persisted intent whose driver died
/// (stale claim). The claim in `drive_finalization` makes this idempotent —
/// a healthy in-progress finalization is never disturbed.
async fn finalize_worker(state: AppState) {
    let mut tick = tokio::time::interval(Duration::from_secs(20));
    loop {
        tick.tick().await;
        recover_finalizations(&state).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fluidbox_core::state::SessionStatus;

    #[test]
    fn reconcile_decision_table() {
        use ReconcileAction::*;
        use SessionLookup::*;
        // Unknown session → the pod is an orphan: terminate.
        assert_eq!(reconcile_action(Missing, false), Terminate);
        assert_eq!(reconcile_action(Missing, true), Terminate);
        // A session row whose status this binary cannot parse was written by
        // a NEWER deploy — that is not proof of death. Never terminate on it
        // (Codex round 2: status_enum's Failed fallback would have).
        assert_eq!(reconcile_action(Unparseable, false), Leave);
        assert_eq!(reconcile_action(Unparseable, true), Leave);
        // Terminal session → the pod is a leak: terminate.
        assert_eq!(
            reconcile_action(Known(SessionStatus::Completed), true),
            Terminate
        );
        assert_eq!(
            reconcile_action(Known(SessionStatus::Cancelled), false),
            Terminate
        );
        // Winding down → the finalizer owns the pod (collection may be in
        // flight): never touch it here.
        assert_eq!(
            reconcile_action(Known(SessionStatus::Cancelling), true),
            Leave
        );
        assert_eq!(
            reconcile_action(Known(SessionStatus::Finalizing), false),
            Leave
        );
        // Active session without a handle → the M5 crash window: adopt.
        assert_eq!(
            reconcile_action(Known(SessionStatus::Initializing), false),
            Adopt
        );
        assert_eq!(
            reconcile_action(Known(SessionStatus::Running), false),
            Adopt
        );
        // Active session with its handle → healthy: leave.
        assert_eq!(reconcile_action(Known(SessionStatus::Running), true), Leave);
        assert_eq!(
            reconcile_action(Known(SessionStatus::AwaitingApproval), true),
            Leave
        );
    }
}
