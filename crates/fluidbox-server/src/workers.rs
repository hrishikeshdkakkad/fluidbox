//! Background workers: heartbeat watchdog, budget sweeper (wall-clock),
//! approval expiry, and boot-time orphan reaping.

use crate::orchestrator;
use crate::state::AppState;
use fluidbox_core::spec::RunSpec;
use fluidbox_core::traits::{ExecutionProvider, SandboxHandle, SandboxState};
use std::time::Duration;

/// Reap any sandboxes labelled ours that have no matching live session (or
/// whose session is already terminal). Runs once at boot.
pub async fn boot_orphan_sweep(state: AppState) {
    match state.provider.list_orphans().await {
        Ok(orphans) => {
            for (session_id, handle) in orphans {
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

pub fn spawn_all(state: AppState) {
    tokio::spawn(watchdog(state.clone()));
    tokio::spawn(budget_sweeper(state.clone()));
    tokio::spawn(approval_expiry(state));
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
                            orchestrator::fail(&state, s.id, "sandbox died (stale heartbeat)").await;
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
                    orchestrator::fail(&state, s.id, "stalled before launch (control plane interrupted)")
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
    matches!(
        state.provider.state(&handle).await,
        Ok(SandboxState::Exited(_)) | Ok(SandboxState::Gone)
    )
}

/// Enforce wall-clock budgets (token/cost budgets are enforced inline in the
/// facade; tool-call budgets inline in the permission gate).
async fn budget_sweeper(state: AppState) {
    let mut tick = tokio::time::interval(Duration::from_secs(10));
    loop {
        tick.tick().await;
        let active =
            match fluidbox_db::sessions_in_status(&state.pool, &["running", "awaiting_approval"]).await {
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
                        orchestrator::finalize(&state, &s, "budget_exceeded", Some("wall-clock budget exceeded")).await;
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
