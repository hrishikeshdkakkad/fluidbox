//! Background workers: heartbeat watchdog, budget sweeper (wall-clock),
//! approval expiry, the restart-recoverable finalize driver, and boot-time
//! orphan reaping.

use crate::orchestrator;
use crate::state::AppState;
use fluidbox_core::spec::RunSpec;
use fluidbox_core::traits::SandboxHandle;
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
                let terminal = match fluidbox_db::get_session(&state.pool, session_id).await {
                    Ok(Some(s)) => s.status_enum().is_terminal(),
                    _ => true, // unknown session → orphan
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
    match fluidbox_db::pending_finalizations(&state.pool).await {
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
    tokio::spawn(finalize_worker(state));
}

/// A healthy orchestrator moves created → provisioning → initializing in
/// seconds (initializing: minutes at worst for a big repo copy). Older than
/// this, the control plane died mid-launch and nothing owns the session.
const STALE_LAUNCH_MINS: i32 = 15;

/// Fail sessions whose sandbox died or whose heartbeat went stale.
async fn watchdog(state: AppState) {
    let mut tick = tokio::time::interval(Duration::from_secs(15));
    loop {
        tick.tick().await;
        let active = match fluidbox_db::sessions_in_status(
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
        match fluidbox_db::stale_nonstarted_sessions(&state.pool, STALE_LAUNCH_MINS).await {
            Ok(stale) => {
                for s in stale {
                    tracing::warn!(
                        "watchdog: {} stalled in '{}' for >{}m — failing",
                        s.id,
                        s.status,
                        STALE_LAUNCH_MINS
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
        let active =
            match fluidbox_db::sessions_in_status(&state.pool, &["running", "awaiting_approval"])
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
            if let Some(max) = run_spec.budgets.max_wall_clock_secs {
                if let Some(started) = s.started_at {
                    if (now - started).num_seconds() as u64 > max {
                        crate::ledger::record(
                            &state,
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
                if let Ok(totals) = fluidbox_db::usage_totals(&state.pool, s.id).await {
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
                    if let Ok(n) = fluidbox_db::tool_call_count(&state.pool, s.id).await {
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
        match fluidbox_db::expire_stale_approvals(&state.pool).await {
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
        let sandbox_ns =
            std::env::var("FLUIDBOX_K8S_NAMESPACE").unwrap_or_else(|_| "fluidbox-sandboxes".into());

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
                        &sandbox_ns,
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
