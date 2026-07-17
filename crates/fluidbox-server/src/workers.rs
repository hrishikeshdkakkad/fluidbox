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
                orchestrator::drive_finalization(state, id).await;
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
    tokio::spawn(finalize_worker(state));
}

/// The stored-archive leak backstop (L3): archives are single-use init
/// transport, deleted on the first runner heartbeat and again at finalize —
/// this sweep reclaims the crash windows (pre-launch death, or a crash after
/// the terminal transition but before `delete_archive`).
async fn archive_ttl_sweep(state: AppState) {
    let ttl = Duration::from_secs(state.cfg.archive_ttl_secs);
    let mut tick = tokio::time::interval(Duration::from_secs(3600));
    loop {
        tick.tick().await;
        let data_dir = state.cfg.data_dir.clone();
        let removed =
            tokio::task::spawn_blocking(move || orchestrator::sweep_stale_archives(&data_dir, ttl))
                .await
                .unwrap_or(0);
        if removed > 0 {
            tracing::info!("archive TTL sweep reclaimed {removed} stale archive(s)");
        }
    }
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
                    orchestrator::fail(
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
                        orchestrator::finalize(
                            &state,
                            &s,
                            "budget_exceeded",
                            Some("wall-clock budget exceeded"),
                        )
                        .await;
                    }
                }
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
        // The probe must carry the SANDBOX placement (nodeSelector,
        // tolerations, runtimeClass, priorityClass, pull secrets) so the gate
        // certifies the pool sandboxes actually run on — same env the
        // provider itself reads.
        let k8s_cfg = fluidbox_provider_k8s::config::K8sConfig::from_env();

        let mut tick = tokio::time::interval(Duration::from_secs(6 * 3600));
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
                _ => tracing::warn!(
                    "netpol gate: could not resolve Service ClusterIPs; runs stay gated"
                ),
            }
            // Once enforced, re-check every 6h; while unverified, retry sooner.
            if state.netpol_verified.load(Ordering::SeqCst) {
                tick.tick().await;
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
