//! Capacity dispatcher (design 2026-08-23 §7): the state-driven admission
//! worker.
//!
//! One per replica, and there is deliberately no leader election. The dispatch
//! DECISION is serialized in Postgres — an advisory try-lock taken inside
//! [`fluidbox_db::system_worker::dispatch_claim`], with occupancy derived from
//! the session rows inside that same section — so replicas cannot double-admit
//! and a losing tick simply re-polls. That is what lets every replica run the
//! identical loop with no coordination protocol of our own.
//!
//! Poll-only at 1 s by design. A `fluidbox_dispatch` NOTIFY channel is a NAMED
//! omission (design §13): each `PgListener` is a permanent extra connection per
//! replica, and a ≤1 s admission delay is invisible next to provisioning
//! latency. It becomes worth building when a latency requirement names it.
//!
//! The whole module is inert unless `FLUIDBOX_MAX_CONCURRENT_RUNS` is set —
//! [`spawn`] returns without starting anything.

use crate::state::AppState;
use fluidbox_core::state::SessionStatus;
use fluidbox_db::TenantScope;
use std::time::Duration;

/// Ticks between sweep passes (age expiry + orphan adoption): ~15 s at a 1 s
/// tick. The sweeps are backstops for bounded-rate events, not hot paths, and
/// running them every tick would put two extra scans per second on the database
/// to catch conditions that change on the scale of minutes.
const SWEEP_EVERY_TICKS: u64 = 15;

/// A `created` row this old with no live lease was orphaned between the
/// create-commit and the park transition (or predates the feature being
/// enabled). Comfortably longer than any healthy create-to-park gap, which is
/// two statements; the live-lease predicate is what actually keeps this off
/// rows a running `run()` is driving, so the age is a second belt.
const ADOPT_CREATED_AFTER_SECS: i64 = 120;

pub fn spawn(state: AppState) {
    if state.cfg.queue.is_none() {
        return; // inert by default
    }
    tokio::spawn(dispatch_loop(state));
}

async fn dispatch_loop(state: AppState) {
    let q = state
        .cfg
        .queue
        .clone()
        .expect("spawn() gates on queue being configured");
    let mut tick = crate::workers::periodic(Duration::from_secs(1));
    let mut n: u64 = 0;
    loop {
        tick.tick().await;
        n = n.wrapping_add(1);
        match fluidbox_db::system_worker::dispatch_claim(
            &state.pool,
            q.max_concurrent_runs,
            crate::workers::SWEEP_BATCH,
            crate::orchestrator::replica_id(),
            crate::orchestrator::SESSION_LEASE_TTL_SECS,
        )
        .await
        {
            Ok(Some(out)) => {
                for run in out.claimed {
                    // Observed at the CLAIM, which is the moment the wait
                    // actually ends — not at `running`, which would fold
                    // provisioning latency into the queue's number.
                    if let Some(t) = run.queued_at {
                        let waited = (chrono::Utc::now() - t).num_milliseconds().max(0);
                        state
                            .metrics
                            .queue_wait_seconds
                            .observe(waited as f64 / 1000.0);
                    }
                    state.metrics.queue_dispatched.inc();
                    crate::orchestrator::spawn_run(state.clone(), run.id);
                }
            }
            // Another replica holds the dispatch lock this instant; its work
            // covers the deployment and this tick has nothing to add.
            Ok(None) => {}
            Err(e) => tracing::warn!("dispatch tick failed: {e}"),
        }
        if n.is_multiple_of(SWEEP_EVERY_TICKS) {
            sweep(&state, &q).await;
        }
    }
}

/// Age expiry + orphan adoption (design §7.6).
///
/// Both arms are safe to run on every replica concurrently: `fail` is the
/// idempotent request-side intent (deliberately UNFENCED — a run that has
/// waited too long must be resolvable regardless of which replica holds the
/// driver lease), and the adoption transition is CAS-guarded by
/// `can_transition_to`, so a row that left `created` meanwhile is simply
/// refused.
async fn sweep(state: &AppState, q: &crate::config::QueueCfg) {
    match fluidbox_db::system_worker::expired_queued_sessions(
        &state.pool,
        q.max_wait_secs,
        crate::workers::SWEEP_BATCH,
    )
    .await
    {
        Ok(expired) => {
            for s in expired {
                tracing::warn!(
                    "queue: {} waited longer than {}s — failing",
                    s.id,
                    q.max_wait_secs
                );
                state.metrics.queue_shed.inc("age");
                // A DbError start is retried by the next sweep.
                let _ = crate::orchestrator::fail(
                    state,
                    s.id,
                    "queued for longer than the configured maximum wait \
                     (FLUIDBOX_QUEUE_MAX_WAIT_SECS)",
                )
                .await;
            }
        }
        Err(e) => tracing::warn!("queue expiry scan failed: {e}"),
    }

    match fluidbox_db::system_worker::orphaned_created_sessions(
        &state.pool,
        ADOPT_CREATED_AFTER_SECS,
        crate::workers::SWEEP_BATCH,
    )
    .await
    {
        Ok(orphans) => {
            for s in orphans {
                let scope = TenantScope::assume(s.tenant_id);
                crate::orchestrator::transition(
                    state,
                    scope,
                    s.id,
                    SessionStatus::Queued,
                    Some("adopted by the dispatcher (orphaned before park)"),
                )
                .await;
            }
        }
        Err(e) => tracing::warn!("orphan adoption scan failed: {e}"),
    }
}

#[cfg(test)]
mod tests {
    /// The Gap-13 periodic-worker rule, applied to this module — the same
    /// property `workers.rs`'s own source guard asserts for the watchdog,
    /// budget sweeper and approval expiry: a worker that runs on EVERY replica
    /// must not perform a side effect itself, because it would fire N times.
    ///
    /// The sweep arms obey it directly: `fail` is the single-winner intent
    /// (`begin_finalization`'s `on conflict do nothing`) and the adoption
    /// transition is a CAS the state machine refuses if the row moved.
    ///
    /// The dispatch arm is the interesting case, because it DOES cause a
    /// provision — via `spawn_run`. It is safe for a different reason: the run
    /// was CLAIMED inside `dispatch_claim`'s serialized section, which stamped
    /// this replica's lease on the row, so exactly one replica can reach
    /// `spawn_run` for a given run. This test pins that coupling — a future
    /// edit that spawns something the claim did not return would reintroduce
    /// the N-replicas problem the whole serialized decision exists to prevent.
    ///
    /// A source guard, so it needs no database. The needles are split with
    /// `concat!` so this test's own text is not what it counts.
    #[test]
    fn the_dispatcher_only_spawns_what_it_claimed() {
        let src = include_str!("dispatcher.rs");

        for mutation in [
            concat!(".provider.", "terminate("),
            concat!(".provider.", "provision("),
            concat!(".provider.", "collect_artifacts("),
        ] {
            assert!(
                !src.contains(mutation),
                "the dispatcher must not call {mutation} — it runs on every replica. \
                 Claim the run and let the lease-holding driver act."
            );
        }

        let spawn = concat!("spawn_", "run(");
        assert_eq!(
            src.matches(spawn).count(),
            1,
            "exactly one spawn site, and it must be the claimed one"
        );
        let claim = concat!("dispatch_", "claim(");
        assert!(
            src.find(claim).expect("the claim is what feeds the spawn")
                < src.find(spawn).expect("the spawn exists"),
            "the spawn must be fed by the claim, not issued beside it"
        );

        // The expiry arm records an INTENT; it never terminalises a session
        // itself and never touches a sandbox.
        assert!(src.contains(concat!("orchestrator::", "fail(")));
    }
}
