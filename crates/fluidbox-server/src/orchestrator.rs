//! Session lifecycle driver. The server is the single status writer; the
//! runner only reports events/heartbeats/result. This module owns the
//! transitions, the sandbox, workspace init, budget enforcement, and the
//! durable terminal finalizer.
//!
//! **Durable finalizer (K8s design 2026-07-15, Phase 0).** Every terminal
//! path — result, cancel, fail, watchdog, budget — funnels through
//! `begin_finalize` → a persisted `session_finalizations` intent + a
//! `cancelling`/`finalizing` state → `drive_finalization`, which collects the
//! diff artifact BEFORE the terminal transition. Because delivery enqueue
//! rides terminal entry (in `transition`), collection can never race the
//! artifact. The intent is persisted before `/result` ACKs, and a
//! restart-recoverable worker re-drives any interrupted finalization, so a
//! crash mid-finalize strands nothing.

use crate::ledger;
use crate::state::AppState;
use fluidbox_core::event::{Actor, EventBody};
use fluidbox_core::spec::{RunSpec, WorkspaceSpec};
use fluidbox_core::state::SessionStatus;
use fluidbox_core::traits::{CollectContext, CollectedArtifacts, SandboxHandle, SandboxSpec};
use fluidbox_db::{SessionRow, TenantScope};
use std::path::PathBuf;
use std::time::Duration;
use uuid::Uuid;

const SESSION_TOKEN_TTL_SECS: i64 = 3 * 3600;

/// Cancellation quiesce deadline: three 10 s heartbeat opportunities + jitter
/// (settled Q5; 20 s rejected as only two opportunities). Past it, a racing
/// worktree is never collected — the diff is recorded `artifact_missing`.
const QUIESCE_DEADLINE_SECS: i64 = 30;

/// Bounded wait for the runner container to exit before terminal collection
/// on paths where no cooperative quiesce ran — the design's "await
/// runner-container termination → collect" applies to EVERY path (M1), and
/// a live worktree is never read (a torn diff must not become the
/// authoritative audit artifact).
const EXIT_WAIT_SECS: i64 = 30;

/// Every provider `state()` probe inside the finalizer is individually
/// bounded so one hung provider call can never overrun the claim.
const PROBE_TIMEOUT: Duration = Duration::from_secs(5);

/// A finalization claim older than this is re-drivable (the previous driver
/// crashed). Derived from the worst healthy path — quiesce wait (30 s) +
/// exit wait (30 s) + collection (120 s) + terminate (60 s) + bounded probes
/// and DB writes — and every driver entry point is itself time-boxed at
/// 300 s, so two drivers can never overlap and overwrite evidence.
const FINALIZE_CLAIM_STALE_SECS: i64 = 420;

/// A finalize whose session has NO stored handle may be racing provisioning:
/// Docker creates and starts the container BEFORE `provision` returns, and
/// discovery is only a snapshot (the container may appear a moment later).
/// Collection therefore waits this long after the intent landed — enough for
/// the provisioning path to either persist the handle or hit the attach
/// fence (which terminates the orphan) — before trusting "no sandbox".
/// Applies only when a diff is expected (a pre-launch failure with no
/// workspace never waits).
const PROVISION_SETTLE_SECS: i64 = 120;

/// Terminal artifact collection is bounded: a hostile or huge worktree can
/// waste the cap, never wedge `finalizing`.
const COLLECT_TIMEOUT: Duration = Duration::from_secs(120);

/// Spawn the full run of a freshly-created session in the background.
pub fn spawn_run(state: AppState, session_id: Uuid) {
    tokio::spawn(async move {
        if let Err(e) = run(state.clone(), session_id).await {
            tracing::error!("run {session_id} failed: {e}");
            fail(&state, session_id, &format!("{e}")).await;
        }
    });
}

async fn transition(
    state: &AppState,
    scope: TenantScope,
    id: Uuid,
    next: SessionStatus,
    reason: Option<&str>,
) -> bool {
    match fluidbox_db::transition_session(&state.pool, scope, id, next, reason).await {
        Ok(Some((from, _))) => {
            ledger::record(
                state,
                scope,
                id,
                Actor::System,
                EventBody::StatusChanged {
                    from: from.as_str().into(),
                    to: next.as_str().into(),
                    reason: reason.map(|s| s.to_string()),
                },
            )
            .await;
            if next.is_terminal() {
                // Defense-in-depth: kill the session's tokens the moment it
                // goes terminal so a still-running or leaked token can't reach
                // the facade/gateway. The PRIMARY guard is each endpoint's own
                // terminal/wind-down check.
                if let Err(e) = fluidbox_db::revoke_session_tokens(&state.pool, scope, id).await {
                    tracing::warn!("revoke_session_tokens {id} failed: {e}");
                }
                // Publication is decoupled: enqueue rows; the delivery worker
                // owns retries. Fires on terminal entry — reachable ONLY from
                // `finalizing`, so the diff artifact is already stored when
                // delivery is enqueued. A partial/failed enqueue here is
                // healed by the terminal reconciler (per-destination
                // idempotent) before the intent is ever released.
                let _ = crate::deliveries::enqueue_for_session(state, id).await;
            }
            true
        }
        Ok(None) => false,
        Err(e) => {
            tracing::error!("transition {id}->{next:?} failed: {e}");
            false
        }
    }
}

/// What a finalize entry point achieved — callers key their ACK/retry off
/// this. `DbError` means the intent was NOT durably persisted: the caller
/// must surface a retryable error (a 5xx to the runner), never a success.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FinalizeStart {
    /// Intent durably persisted (`created` iff by this call); driver kicked.
    Persisted {
        created: bool,
    },
    AlreadyTerminal,
    Missing,
    DbError,
}

/// The named request shape all entry points reduce to (summary and reason
/// are distinct fields on the intent row — never the same string twice).
struct FinalizeParams<'a> {
    outcome: &'a str,
    summary: Option<&'a str>,
    reason: Option<&'a str>,
    want_quiesce: bool,
}

/// The runner reported its own result (`/result`): it is exiting by
/// contract, so no quiesce — the universal exit-wait before collection
/// covers the shutdown tail.
pub async fn finalize_reported(
    state: &AppState,
    id: Uuid,
    outcome: &str,
    summary: Option<&str>,
) -> FinalizeStart {
    begin_finalize(
        state,
        id,
        FinalizeParams {
            outcome,
            summary,
            reason: None,
            want_quiesce: false, // the runner exits on its own after /result
        },
        None,
    )
    .await
}

/// The control plane is stopping a run the runner did not end itself
/// (wall-clock / token / cost / tool-call budgets): the runner is LIVE, so
/// it must be told to stop (quiesce via its heartbeat) and given the
/// deadline BEFORE collection — Docker enforces no pod deadline, and a
/// still-writing worktree must never be collected.
pub async fn finalize_forced(
    state: &AppState,
    id: Uuid,
    outcome: &str,
    reason: &str,
) -> FinalizeStart {
    begin_finalize(
        state,
        id,
        FinalizeParams {
            outcome,
            summary: None,
            reason: Some(reason),
            want_quiesce: true,
        },
        None,
    )
    .await
}

/// Terminal failure. Same durable path — a failed run still collects
/// whatever the agent produced, after the runner stopped (quiesce for live
/// runners; pre-launch/dead sessions skip it via the locked snapshot).
pub async fn fail(state: &AppState, id: Uuid, reason: &str) -> FinalizeStart {
    // A worker/system entry with only a bare id: resolve the owning tenant once
    // (cross-tenant loader) so the RunError event is scoped, then hand the SAME
    // scope to begin_finalize so it does not re-load.
    let scope = match fluidbox_db::system_worker::get_session(&state.pool, id).await {
        Ok(Some(s)) => TenantScope::assume(s.tenant_id),
        Ok(None) => return FinalizeStart::Missing,
        Err(e) => {
            tracing::error!("fail {id} tenant resolve failed: {e}");
            return FinalizeStart::DbError;
        }
    };
    ledger::record(
        state,
        scope,
        id,
        Actor::System,
        EventBody::RunError {
            message: reason.into(),
        },
    )
    .await;
    begin_finalize(
        state,
        id,
        FinalizeParams {
            outcome: "failed",
            summary: None,
            reason: Some(reason),
            want_quiesce: true,
        },
        Some(scope),
    )
    .await
}

/// Cancel a session (admin action, or a `replace` concurrency policy). Rides
/// the durable finalizer WITH quiesce: the runner is asked (via its heartbeat
/// response) to stop and NOT post `/result`, we wait up to 30 s for a clean
/// worktree, then collect. `Persisted { created: true }` means THIS call
/// recorded the cancellation; a lost race means some other outcome already
/// owns the run — callers must not report "cancelled" then.
pub async fn cancel(state: &AppState, scope: TenantScope, id: Uuid, reason: &str) -> FinalizeStart {
    // Callers reach this only after loading the session UNDER `scope` (the
    // authenticated handler proved ownership; the concurrency-replace path holds
    // the run it just resolved), so the tenant is already authorized — pass it
    // through instead of re-resolving it cross-tenant in begin_finalize.
    begin_finalize(
        state,
        id,
        FinalizeParams {
            outcome: "cancelled",
            summary: None,
            reason: Some(reason),
            want_quiesce: true,
        },
        Some(scope),
    )
    .await
}

/// Persist the terminal intent (transactionally, under the session row lock),
/// enter the wind-down state THE WINNING INTENT implies, and kick the driver.
/// Idempotent: a racing second caller receives the winner's row and derives
/// everything from it — its own outcome/quiesce arguments are discarded.
async fn begin_finalize(
    state: &AppState,
    id: Uuid,
    params: FinalizeParams<'_>,
    // Some when the caller ALREADY resolved (and authorized) the session's
    // tenant — the authenticated cancel path passes its scoped row's scope so
    // this does not re-load cross-tenant. None on the worker/system entries
    // (finalize_reported/forced, the crash-recovery `fail`), which hold only a
    // bare id and resolve it here.
    pre_scope: Option<TenantScope>,
) -> FinalizeStart {
    use fluidbox_db::BeginFinalization as B;
    let scope = match pre_scope {
        Some(s) => s,
        None => match fluidbox_db::system_worker::get_session(&state.pool, id).await {
            Ok(Some(s)) => TenantScope::assume(s.tenant_id),
            Ok(None) => return FinalizeStart::Missing,
            Err(e) => {
                tracing::error!("begin_finalization {id} tenant resolve failed: {e}");
                return FinalizeStart::DbError;
            }
        },
    };
    let begun = fluidbox_db::begin_finalization(
        &state.pool,
        scope,
        id,
        params.outcome,
        params.summary,
        params.reason,
        params.want_quiesce,
        QUIESCE_DEADLINE_SECS,
    )
    .await;
    let (row, created, status) = match begun {
        Ok(B::Persisted {
            row,
            created,
            session_status,
        }) => (row, created, session_status),
        Ok(B::AlreadyTerminal) => return FinalizeStart::AlreadyTerminal,
        Ok(B::Missing) => return FinalizeStart::Missing,
        Err(e) => {
            // Fail closed: no durable intent → no wind-down transition and no
            // success ACK. The recovery worker joins on `session_finalizations`,
            // so an intent-less wind-down state would strand forever.
            tracing::error!("begin_finalization {id} failed, not winding down: {e}");
            return FinalizeStart::DbError;
        }
    };

    // Enter the wind-down state the WINNING row implies (never this caller's
    // arguments — the /result⇄cancel race fix). Failure here is fine: the
    // driver re-materializes the state from the intent.
    if SessionStatus::parse(&status).is_some_and(|s| !s.is_winding_down()) {
        enter_winddown(state, scope, id, &row).await;
    }

    let state2 = state.clone();
    tokio::spawn(async move {
        // Same bound as the recovery worker: EVERY driver entry point is
        // time-boxed well under the 420 s claim, so two drivers can never
        // overlap and overwrite each other's evidence.
        let _ = tokio::time::timeout(Duration::from_secs(300), async {
            drive_finalization(&state2, id).await;
        })
        .await;
    });
    FinalizeStart::Persisted { created }
}

/// Apply the wind-down state an intent implies — `Cancelling` iff the intent
/// wants quiesce (the runner's heartbeat channel keys off that status) —
/// emitting `QuiesceRequested` only when Cancelling actually LANDS, wherever
/// that happens (first caller or crash recovery). Derives only from the row.
async fn enter_winddown(
    state: &AppState,
    scope: TenantScope,
    id: Uuid,
    intent: &fluidbox_db::FinalizationRow,
) -> bool {
    let target = if intent.needs_quiesce {
        SessionStatus::Cancelling
    } else {
        SessionStatus::Finalizing
    };
    let applied = transition(state, scope, id, target, intent.reason.as_deref()).await;
    if applied && intent.needs_quiesce {
        ledger::record(
            state,
            scope,
            id,
            Actor::System,
            EventBody::QuiesceRequested {
                deadline_secs: QUIESCE_DEADLINE_SECS as u64,
            },
        )
        .await;
    }
    applied
}

/// The next wind-down action, derived EXCLUSIVELY from the persisted intent
/// and the current status (H5: a caller that lost the intent race acts on
/// the winner's row, never its own arguments). Pure — the race matrix is
/// unit-tested below without a database.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WinddownStep {
    /// Apply active → Cancelling (the intent wants quiesce; the runner's
    /// heartbeat channel keys off that status).
    EnterCancelling,
    /// Apply active/Cancelling → Finalizing (no quiesce owed, or it resolved).
    EnterFinalizing,
    /// Wait for runner exit until the intent's deadline, then Finalizing.
    AwaitQuiesce(chrono::DateTime<chrono::Utc>),
    /// The intent wants quiesce but carries no deadline — malformed; leave it
    /// for retry/alerting, NEVER treat as an already-expired deadline (the
    /// old instant-timeout bug that discarded completed runs' diffs).
    Malformed,
    /// Already Finalizing → collect and terminalize.
    Collect,
    /// Already terminal → terminal-side effects + cleanup are still owed.
    Reconcile,
}

fn plan_step(
    needs_quiesce: bool,
    deadline: Option<chrono::DateTime<chrono::Utc>>,
    status: SessionStatus,
) -> WinddownStep {
    use SessionStatus::*;
    if status.is_terminal() {
        return WinddownStep::Reconcile;
    }
    match (status, needs_quiesce) {
        (Finalizing, _) => WinddownStep::Collect,
        (Cancelling, true) => match deadline {
            Some(d) => WinddownStep::AwaitQuiesce(d),
            None => WinddownStep::Malformed,
        },
        (Cancelling, false) => WinddownStep::EnterFinalizing,
        (_, true) => WinddownStep::EnterCancelling,
        (_, false) => WinddownStep::EnterFinalizing,
    }
}

/// Drive one session's finalization to a terminal state — and its terminal
/// cleanup to completion. Claim-guarded (one driver at a time), idempotent,
/// and safe to call repeatedly: every early return leaves the intent in
/// place, and the finalize worker re-drives it. Transient DB errors NEVER
/// release the intent — only a session that verifiably does not exist, or a
/// fully reconciled terminal session, does.
pub async fn drive_finalization(state: &AppState, id: Uuid) {
    // Recovery/terminal entry carries only a bare id (from the recovery worker
    // or a spawned finalize). Resolve the owning tenant once via the
    // cross-tenant loader; a finalization intent always has a session (FK), so
    // None here means nothing is left to drive.
    let scope = match fluidbox_db::system_worker::get_session(&state.pool, id).await {
        Ok(Some(s)) => TenantScope::assume(s.tenant_id),
        Ok(None) => return,
        Err(e) => {
            tracing::warn!("drive_finalization {id}: tenant resolve failed: {e}");
            return;
        }
    };
    let claimed =
        fluidbox_db::claim_finalization(&state.pool, scope, id, FINALIZE_CLAIM_STALE_SECS).await;
    let intent = match claimed {
        Ok(Some(i)) => i,
        Ok(None) => return, // another driver owns it, or no intent — nothing to do
        Err(e) => {
            tracing::warn!("claim_finalization {id} failed: {e}");
            return;
        }
    };

    let mut skip_collection = false;
    // Each arm either returns or strictly advances the machine
    // (active → Cancelling → Finalizing → collect/terminal → reconciled);
    // the bound is a belt against status flapping ever regressing.
    for _ in 0..6 {
        let session = match fluidbox_db::get_session(&state.pool, scope, id).await {
            Ok(Some(s)) => s,
            Ok(None) => {
                // Verifiably gone (not a transient error) — nothing left to
                // reconcile; release the intent.
                fluidbox_db::delete_finalization(&state.pool, scope, id)
                    .await
                    .ok();
                return;
            }
            Err(e) => {
                tracing::warn!("drive_finalization {id}: session read failed: {e}");
                return; // transient — leave the intent for the next drive
            }
        };

        match plan_step(
            intent.needs_quiesce,
            intent.quiesce_deadline,
            session.status_enum(),
        ) {
            WinddownStep::Reconcile => {
                finish_terminal_cleanup(state, &session, &intent).await;
                return;
            }
            WinddownStep::Malformed => {
                tracing::error!(
                    "finalization intent for {id} wants quiesce but has no deadline — malformed; leaving for retry"
                );
                return;
            }
            WinddownStep::EnterCancelling | WinddownStep::EnterFinalizing => {
                // Re-materialize the wind-down state the intent implies
                // (covers the crash-between-persist-and-transition window).
                // On failure the loop re-reads: a racing writer may have
                // moved the session (fine — plan again); a transient DB
                // error leaves the intent for the next drive.
                if !enter_winddown(state, scope, id, &intent).await {
                    match fluidbox_db::get_session(&state.pool, scope, id).await {
                        Ok(Some(s))
                            if s.status_enum().is_winding_down()
                                || s.status_enum().is_terminal() => {} // progressed — re-plan
                        _ => return,
                    }
                }
            }
            WinddownStep::AwaitQuiesce(deadline) => {
                // Overwrite, never latch: a transient Finalizing-transition
                // failure loops back here, and a runner that exited by the
                // re-check must CLEAR an earlier skip verdict — a sticky flag
                // would discard a now-safe diff as quiesce_timeout.
                skip_collection = match session_handle(&session) {
                    Some(handle) => !wait_runner_exit(state, &handle, deadline).await,
                    None => false,
                };
                transition(
                    state,
                    scope,
                    id,
                    SessionStatus::Finalizing,
                    intent.reason.as_deref(),
                )
                .await;
            }
            WinddownStep::Collect => {
                collect_and_terminalize(state, scope, id, &intent, skip_collection).await;
                return;
            }
        }
    }
}

/// The stored handle, distinguishing "never had one" from "stored but
/// unparseable" — the latter must NOT read as "sandbox gone" (a live
/// sandbox could hide behind garbage JSON).
enum StoredHandle {
    None,
    Unparseable,
    Handle(SandboxHandle),
}

fn session_handle_state(session: &SessionRow) -> StoredHandle {
    match &session.sandbox_handle {
        None => StoredHandle::None,
        Some(j) => match serde_json::from_value::<SandboxHandle>(j.clone()) {
            Ok(h) => StoredHandle::Handle(h),
            Err(_) => StoredHandle::Unparseable,
        },
    }
}

fn session_handle(session: &SessionRow) -> Option<SandboxHandle> {
    match session_handle_state(session) {
        StoredHandle::Handle(h) => Some(h),
        _ => None,
    }
}

/// Provider-truth fallback for sessions whose stored handle is absent or
/// unparseable: `list_managed` finds the sandbox by its session label, so a
/// cancel that raced provisioning (the handle not yet persisted — Docker
/// starts the container BEFORE `provision` returns) still gets waited on and
/// reaped instead of having its live worktree collected. `Err` is a provider
/// failure — the caller must treat the sandbox state as UNKNOWN and retry,
/// never as "gone".
async fn discover_handle(state: &AppState, id: Uuid) -> Result<Option<SandboxHandle>, ()> {
    match tokio::time::timeout(PROBE_TIMEOUT, state.provider.list_managed()).await {
        Ok(Ok(managed)) => Ok(managed
            .into_iter()
            .find(|(sid, _)| *sid == id)
            .map(|(_, h)| h)),
        _ => Err(()),
    }
}

/// Poll until the runner container is no longer live or the deadline passes;
/// returns true iff the runner exited. Probes FIRST — crash recovery with an
/// already-expired deadline still gets one look (the runner may have exited
/// in time; L6) — and each probe is individually bounded so a hung provider
/// call cannot overrun the finalize claim.
async fn wait_runner_exit(
    state: &AppState,
    handle: &SandboxHandle,
    deadline: chrono::DateTime<chrono::Utc>,
) -> bool {
    loop {
        match tokio::time::timeout(PROBE_TIMEOUT, state.provider.state(handle)).await {
            Ok(Ok(st)) if !st.is_live() => return true,
            _ => {}
        }
        let remaining = deadline - chrono::Utc::now();
        if remaining <= chrono::Duration::zero() {
            return false;
        }
        let nap = remaining.num_milliseconds().clamp(50, 750) as u64;
        tokio::time::sleep(Duration::from_millis(nap)).await;
    }
}

/// The prefix `record_missing` stores — also the evidence guard's test for
/// "only a missing-marker, not a real diff" (missing → collected upgrades on
/// retry are allowed; the reverse never is).
const MISSING_DIFF_PREFIX: &str = "(diff unavailable";

/// Collect the diff (unless skipped or already collected), store the
/// artifact or an explicit `artifact_missing`, make the single terminal
/// transition, then reconcile terminal side effects + cleanup. Every
/// persistence failure leaves the intent in place and returns — the finalize
/// worker re-drives; NOTHING destructive happens before the terminal
/// transition is confirmed.
async fn collect_and_terminalize(
    state: &AppState,
    scope: TenantScope,
    id: Uuid,
    intent: &fluidbox_db::FinalizationRow,
    skip_collection: bool,
) {
    let Ok(Some(session)) = fluidbox_db::get_session(&state.pool, scope, id).await else {
        return;
    };

    // A diff is only "expected" once the session had a workspace/sandbox — a
    // pre-launch failure records no artifact_missing noise.
    let expected_diff = session.started_at.is_some()
        || session.base_commit.is_some()
        || session.sandbox_handle.is_some();

    // Evidence guard: a re-driven finalization must never regress what a
    // previous drive stored. A real diff (including "(no changes)") is
    // final; a missing-marker may be upgraded by a successful re-collection
    // but never re-recorded.
    let stored = match fluidbox_db::diff_artifact_content(&state.pool, scope, id).await {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!("diff artifact read failed for {id}: {e} — retrying next drive");
            return;
        }
    };
    let have_real_diff = stored
        .as_deref()
        .is_some_and(|c| !c.starts_with(MISSING_DIFF_PREFIX));
    let have_any_diff = stored.is_some();
    let record_missing_once = |reason: String| async move {
        if expected_diff && !have_any_diff {
            record_missing(state, scope, id, &reason).await
        } else {
            Ok(())
        }
    };

    // Collection itself is gated on `expected_diff`: a session that never
    // had a workspace/sandbox has nothing to collect BY DEFINITION, and a
    // finalize racing mid-materialization (base_commit/started_at/handle all
    // still unset) must not read — or store a "diff" of — a half-written
    // workspace. The launch path stops at its ownership checks; anything it
    // already wrote is removed by terminal cleanup.
    if !have_real_diff && expected_diff {
        if skip_collection {
            if record_missing_once("quiesce_timeout".into()).await.is_err() {
                return;
            }
        } else {
            // M1, universal: never read a worktree the runner may still be
            // writing — bounded wait for runner-container exit on EVERY
            // collect path, then collect; still live at the bound records
            // missing (a torn diff must not become the audit artifact).
            // A missing/unparseable stored handle is NOT "gone": Docker
            // starts the container before `provision` returns, so a finalize
            // that raced provisioning first lets provisioning settle (the
            // attach fence terminates the orphan), then consults provider
            // truth (list_managed by session label) before touching the
            // worktree.
            let handle = match session_handle_state(&session) {
                StoredHandle::Handle(h) => Some(h),
                StoredHandle::None
                    if chrono::Utc::now()
                        < intent.created_at + chrono::Duration::seconds(PROVISION_SETTLE_SECS) =>
                {
                    tracing::info!(
                        "collect for {id} deferred: no stored handle yet (provisioning may be in flight)"
                    );
                    // A deliberate wait, not a failure: release the claim so
                    // the finalize worker retries at its cadence instead of
                    // waiting out the 420 s stale window.
                    fluidbox_db::release_finalization_claim(&state.pool, scope, id)
                        .await
                        .ok();
                    return;
                }
                StoredHandle::None | StoredHandle::Unparseable => {
                    match discover_handle(state, id).await {
                        Ok(h) => h,
                        Err(()) => {
                            tracing::warn!(
                                "sandbox discovery for {id} failed — retrying next drive"
                            );
                            return;
                        }
                    }
                }
            };
            let runner_gone = match &handle {
                Some(h) => {
                    let deadline = chrono::Utc::now() + chrono::Duration::seconds(EXIT_WAIT_SECS);
                    wait_runner_exit(state, h, deadline).await
                }
                None => true,
            };
            if !runner_gone {
                if record_missing_once("runner_still_live".into())
                    .await
                    .is_err()
                {
                    return;
                }
            } else {
                let ctx = CollectContext {
                    session_id: id,
                    base_commit: session.base_commit.clone(),
                };
                let collected = tokio::time::timeout(
                    COLLECT_TIMEOUT,
                    state.provider.collect_artifacts(handle.as_ref(), &ctx),
                )
                .await;
                let stored_ok = match collected {
                    Ok(Ok(CollectedArtifacts::Collected(arts))) => {
                        store_collected(state, scope, id, arts).await
                    }
                    Ok(Ok(CollectedArtifacts::Missing { reason })) => {
                        record_missing_once(reason).await
                    }
                    Ok(Err(e)) => record_missing_once(format!("collector error: {e}")).await,
                    Err(_) => record_missing_once("collection_timeout".into()).await,
                };
                if stored_ok.is_err() {
                    tracing::warn!("artifact persistence failed for {id} — retrying next drive");
                    return;
                }
            }
        }
    }

    // Summary — MUST land before the terminal transition: terminalizing
    // destroys the retry path (the intent is released after cleanup), so a
    // swallowed write here would lose the summary forever.
    if let Some(s) = intent.summary.as_deref() {
        if fluidbox_db::set_result_summary(&state.pool, scope, id, s)
            .await
            .is_err()
        {
            return;
        }
        if fluidbox_db::upsert_artifact(
            &state.pool,
            scope,
            id,
            "summary",
            "summary.md",
            s,
            "text/markdown",
        )
        .await
        .is_err()
        {
            return;
        }
    }

    let terminal = match intent.outcome.as_str() {
        "completed" => SessionStatus::Completed,
        "cancelled" => SessionStatus::Cancelled,
        "budget_exceeded" => SessionStatus::BudgetExceeded,
        _ => SessionStatus::Failed,
    };
    // The single-winner gate: delivery enqueue rides this transition;
    // RunResult and the rest of the terminal side effects are reconciled
    // exactly-once by the cleanup below (emit-if-missing under the claim).
    if transition(state, scope, id, terminal, intent.reason.as_deref()).await {
        finish_terminal_cleanup(state, &session, intent).await;
    } else {
        // The transition did not apply. If another driver already
        // terminalized, cleanup may still be owed; a transient failure
        // leaves the intent for the next drive. H2: the intent (and the
        // workspace, archive, and sandbox) are NEVER destroyed on this path.
        match fluidbox_db::get_session(&state.pool, scope, id).await {
            Ok(Some(s)) if s.status_enum().is_terminal() => {
                finish_terminal_cleanup(state, &s, intent).await;
            }
            _ => {}
        }
    }
}

/// Terminal-side effects + cleanup, re-driven under the claim until ALL of it
/// succeeds — only then is the intent released (it is the retry ticket).
/// Everything here is idempotent: token revocation is an UPDATE, delivery
/// enqueue is per-destination idempotent (and this path is
/// claim-serialized), both providers' terminate treat already-gone as
/// success, and the file removals tolerate absence. Also closes the
/// terminal-commit → side-effects crash gap (`transition` normally does
/// revoke + enqueue; a crash between the UPDATE and those calls leaves them
/// owed — this reconciler re-runs them).
async fn finish_terminal_cleanup(
    state: &AppState,
    session: &SessionRow,
    intent: &fluidbox_db::FinalizationRow,
) {
    let id = session.id;
    let scope = TenantScope::assume(session.tenant_id);
    // Exactly-once RunResult: emitted only after a CONFIRMED terminal
    // transition, and emit-if-missing under the claim — a crash between the
    // terminal commit and the emit is healed here, and a re-drive after a
    // successful emit skips it.
    match fluidbox_db::has_run_result_event(&state.pool, scope, id).await {
        Ok(true) => {}
        Ok(false) => {
            ledger::record(
                state,
                scope,
                id,
                Actor::Harness,
                EventBody::RunResult {
                    outcome: intent.outcome.clone(),
                    summary: intent.summary.clone(),
                },
            )
            .await;
            // `record` swallows append failures — VERIFY before the intent
            // may ever be released, or a failed append loses the event
            // forever (exactly-once requires at-least-once first).
            match fluidbox_db::has_run_result_event(&state.pool, scope, id).await {
                Ok(true) => {}
                _ => {
                    tracing::warn!(
                        "terminal reconcile {id}: run.result append unverified — retrying next drive"
                    );
                    return;
                }
            }
        }
        Err(e) => {
            tracing::warn!("terminal reconcile {id}: run.result check failed: {e}");
            return;
        }
    }
    if let Err(e) = fluidbox_db::revoke_session_tokens(&state.pool, scope, id).await {
        tracing::warn!("terminal reconcile {id}: token revoke failed: {e}");
        return;
    }
    // Delivery enqueue is owed only when the RunSpec names destinations.
    // enqueue_for_session is per-destination idempotent and returns true only
    // when EVERY destination has a row — partial success (destination A
    // enqueued, B failed) must not be mistaken for complete reconciliation.
    let wants_delivery = serde_json::from_value::<RunSpec>(session.run_spec.clone())
        .map(|rs| !rs.result_destinations.is_empty())
        .unwrap_or(false);
    if wants_delivery && !crate::deliveries::enqueue_for_session(state, id).await {
        tracing::warn!(
            "terminal reconcile {id}: delivery enqueue incomplete — retrying next drive"
        );
        return;
    }
    // Reap MUST succeed (or the sandbox be verifiably gone) before the
    // workspace, archive, and intent go away — especially on Docker, where
    // nothing else ever kills the container.
    if reap(state, scope, id).await.is_err() {
        return;
    }
    if !state.cfg.keep_workspaces {
        if let Err(e) = fluidbox_workspace::cleanup_workspace(&state.cfg.data_dir, id) {
            tracing::warn!("workspace cleanup failed for {id}: {e} — retrying next drive");
            return;
        }
        if let Err(e) = delete_archive(&state.cfg.data_dir, id) {
            tracing::warn!("archive removal failed for {id}: {e} — retrying next drive");
            return;
        }
    }
    fluidbox_db::delete_finalization(&state.pool, scope, id)
        .await
        .ok();
}

async fn store_collected(
    state: &AppState,
    scope: TenantScope,
    id: Uuid,
    arts: Vec<fluidbox_core::traits::CollectedArtifact>,
) -> sqlx::Result<()> {
    for a in arts {
        // A clean worktree is a real (empty) result, not a missing diff — the
        // artifact contract keeps a diff row on every collected run.
        let (content, content_type): (String, String) =
            if a.kind == "diff" && a.content.trim().is_empty() {
                ("(no changes)".into(), "text/plain".into())
            } else {
                (a.content.clone(), a.content_type.clone())
            };
        fluidbox_db::upsert_artifact(
            &state.pool,
            scope,
            id,
            &a.kind,
            &a.name,
            &content,
            &content_type,
        )
        .await?;
        ledger::record(
            state,
            scope,
            id,
            Actor::System,
            EventBody::ArtifactCollected {
                kind: a.kind,
                name: a.name,
                bytes: a.bytes,
                sha256: a.sha256,
                truncated: a.truncated,
            },
        )
        .await;
    }
    Ok(())
}

async fn record_missing(
    state: &AppState,
    scope: TenantScope,
    id: Uuid,
    reason: &str,
) -> sqlx::Result<()> {
    fluidbox_db::upsert_artifact(
        &state.pool,
        scope,
        id,
        "diff",
        "changes.patch",
        &format!("{MISSING_DIFF_PREFIX}: {reason})"),
        "text/plain",
    )
    .await?;
    ledger::record(
        state,
        scope,
        id,
        Actor::System,
        EventBody::ArtifactMissing {
            kind: "diff".into(),
            reason: reason.into(),
        },
    )
    .await;
    Ok(())
}

async fn run(state: AppState, session_id: Uuid) -> anyhow::Result<()> {
    // Spawned with only a bare session id; resolve the owning tenant once via
    // the cross-tenant loader, then scope every lifecycle write to it.
    let session = fluidbox_db::system_worker::get_session(&state.pool, session_id)
        .await?
        .ok_or_else(|| anyhow::anyhow!("session vanished"))?;
    let scope = TenantScope::assume(session.tenant_id);
    let run_spec: RunSpec = serde_json::from_value(session.run_spec.clone())?;

    // created → provisioning
    if !transition(&state, scope, session_id, SessionStatus::Provisioning, None).await {
        anyhow::bail!("could not enter provisioning");
    }

    // Mint the session token the sandbox authenticates with.
    let session_token = format!("fbx_sess_{}", uuid_token());
    fluidbox_db::create_session_token(
        &state.pool,
        scope,
        session_id,
        &session_token,
        SESSION_TOKEN_TTL_SECS,
    )
    .await?;

    // provisioning → initializing (workspace materialization, control-plane
    // side, BEFORE the agent starts — a bad repo fails here at zero model
    // spend). A refused transition means a finalizer took ownership (cancel,
    // watchdog): stop BEFORE materializing or provisioning anything.
    if !transition(&state, scope, session_id, SessionStatus::Initializing, None).await {
        anyhow::bail!("session left active state before workspace init");
    }
    let (workspace_dir, base_commit) =
        materialize_workspace(&state, scope, session_id, &run_spec).await?;

    // Ownership gate AFTER materialization, BEFORE anything else is created
    // (the K8s archive write included): a finalizer that took the session
    // while we copied may already have run terminal cleanup and released its
    // intent — the loser must remove what IT created or nothing ever will.
    if !launch_ownership(&state, scope, session_id).await? {
        abandon_launch(&state, scope, session_id).await;
        anyhow::bail!("session ownership lost during workspace init; launch abandoned");
    }

    let control_url = state.cfg.public_control_url.clone();
    let env = build_runner_env(&run_spec, &control_url, session_id, &session_token);

    // 512 KiB serialized runner-env ceiling (env injection is the v1 config
    // channel; a Kubernetes Secret caps ~1 MiB). Fail closed at zero spend.
    let env_bytes = serialized_env_len(&env);
    if env_bytes > crate::config::MAX_RUNNER_ENV_BYTES {
        anyhow::bail!(
            "runner env is {env_bytes} bytes, over the {} byte ceiling ({})",
            crate::config::MAX_RUNNER_ENV_BYTES,
            env_size_breakdown(&env)
        );
    }

    // Archive-transport providers (Kubernetes) pull an immutable, credential-
    // free archive the control plane packs here. Host-dir providers (Docker)
    // bind mount and skip this. Authority stays control-plane-side either way.
    let workspace_archive = if state.provider.workspace_transport()
        == fluidbox_core::traits::WorkspaceTransport::Archive
    {
        match &workspace_dir {
            Some(_) => Some(pack_and_store_archive(&state, session_id, base_commit.clone()).await?),
            None => None,
        }
    } else {
        None
    };

    let sandbox_spec = SandboxSpec {
        session_id,
        image: run_spec.runner_image.clone(),
        env,
        workspace_host_dir: workspace_dir.as_ref().map(|p| p.display().to_string()),
        workspace_archive,
        active_deadline_secs: run_spec.budgets.max_wall_clock_secs,
        network: state.cfg.network_mode,
    };

    // Ownership re-check immediately before creating a sandbox: a finalizer
    // that took the session during archive packing must find no container to
    // race (the attach fence below catches the residual instants).
    if !launch_ownership(&state, scope, session_id).await? {
        abandon_launch(&state, scope, session_id).await;
        anyhow::bail!("session ownership lost before provisioning; launch abandoned");
    }
    let handle = state.provider.provision(&sandbox_spec).await?;
    let attached = fluidbox_db::set_sandbox_handle(
        &state.pool,
        scope,
        session_id,
        &serde_json::to_value(&handle)?,
    )
    .await?;
    if !attached {
        // The session entered wind-down or terminal while we were
        // provisioning — the finalizer owns it now. Best-effort immediate
        // kill; if this terminate fails, the finalizer's discovery-reap
        // (list_managed by session label) retries until the sandbox is
        // verifiably gone, so nothing rides on this call succeeding.
        if let Err(e) = state.provider.terminate(&handle).await {
            tracing::warn!(
                "late-provision terminate for {session_id} failed ({e}); finalizer discovery will reap"
            );
        }
        abandon_launch(&state, scope, session_id).await;
        anyhow::bail!(
            "session left active state during provisioning; sandbox handed to the finalizer"
        );
    }

    // initializing → running (traffic is now expected)
    transition(&state, scope, session_id, SessionStatus::Running, None).await;
    fluidbox_db::heartbeat(&state.pool, scope, session_id)
        .await
        .ok();

    ledger::record(
        &state,
        scope,
        session_id,
        Actor::System,
        EventBody::AgentMessage {
            role: "system".into(),
            text: format!(
                "sandbox launched ({})",
                handle.external_id.chars().take(12).collect::<String>()
            ),
        },
    )
    .await;

    Ok(())
}

/// Assemble the runner env. The generic FLUIDBOX_* block is the harness-neutral
/// runner contract; per-harness extras ride `harness::runner_env`.
pub fn build_runner_env(
    run_spec: &RunSpec,
    control_url: &str,
    session_id: Uuid,
    session_token: &str,
) -> Vec<(String, String)> {
    let mut env = vec![
        ("FLUIDBOX_CONTROL_URL".into(), control_url.to_string()),
        ("FLUIDBOX_SESSION_ID".into(), session_id.to_string()),
        ("FLUIDBOX_SESSION_TOKEN".into(), session_token.to_string()),
        ("FLUIDBOX_TASK".into(), run_spec.task.clone()),
        (
            "FLUIDBOX_AUTONOMY".into(),
            run_spec.autonomy.as_str().into(),
        ),
        ("FLUIDBOX_MODEL".into(), run_spec.model.clone()),
        ("FLUIDBOX_WORKSPACE".into(), "/workspace".into()),
    ];
    env.extend(crate::harness::runner_env(
        &run_spec.harness,
        control_url,
        session_token,
        &run_spec.model,
    ));
    if let Some(sp) = &run_spec.system_prompt {
        env.push(("FLUIDBOX_SYSTEM_PROMPT".into(), sp.clone()));
    }
    if !run_spec.capabilities.is_empty() {
        env.push((
            "FLUIDBOX_CAPABILITIES".into(),
            runner_capability_manifest(&run_spec.capabilities).to_string(),
        ));
    }
    env
}

/// Serialized size the provider must transport (env-var form: `K=V\0`).
pub fn serialized_env_len(env: &[(String, String)]) -> usize {
    env.iter().map(|(k, v)| k.len() + v.len() + 2).sum()
}

/// The on-disk archive path for a session (PVC-backed in Kubernetes; survives
/// a `Recreate` upgrade so init can still pull after a control-plane restart).
pub fn archive_path(data_dir: &std::path::Path, session_id: Uuid) -> PathBuf {
    data_dir
        .join("archives")
        .join(format!("{session_id}.tar.gz"))
}

/// Pack the materialized workspace into an immutable archive, store it, and
/// return the descriptor the init container verifies. The archive URL is on
/// the INTERNAL listener (the pod reaches it with the session token it already
/// holds — nothing new becomes reachable).
async fn pack_and_store_archive(
    state: &AppState,
    session_id: Uuid,
    base_commit: Option<String>,
) -> anyhow::Result<fluidbox_core::traits::WorkspaceArchive> {
    let data_dir = state.cfg.data_dir.clone();
    let max_bytes = state.cfg.max_archive_bytes;
    let dest = archive_path(&data_dir, session_id);
    // Streamed to disk (GzEncoder<File>) — the archive never lives in RAM,
    // and the size cap fails the run HERE, before any sandbox or model spend.
    let packed = tokio::task::spawn_blocking(move || {
        let root = fluidbox_workspace::session_workspace_root(&data_dir, session_id);
        if let Some(parent) = dest.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let packed = fluidbox_workspace::pack_workspace_to_file(&root, &dest, max_bytes)?;
        Ok::<_, anyhow::Error>(packed)
    })
    .await??;

    // The pod pulls from the internal control URL (the same base the runner
    // uses for every other internal call).
    let url = format!(
        "{}/internal/sessions/{}/workspace",
        state.cfg.public_control_url.trim_end_matches('/'),
        session_id
    );
    Ok(fluidbox_core::traits::WorkspaceArchive {
        url,
        sha256: packed.sha256,
        len: packed.len,
        base_commit,
    })
}

/// Delete a session's stored archive. Absence is success (idempotent);
/// any other failure surfaces so the terminal reconciler retries instead of
/// leaking the archive permanently. Called at finalize; the periodic TTL
/// sweep (`workers::archive_ttl_sweep`) is the backstop for the crash window
/// between the terminal transition and this call. NOT called on heartbeats:
/// init containers may legitimately re-execute and re-fetch.
pub fn delete_archive(data_dir: &std::path::Path, session_id: Uuid) -> std::io::Result<()> {
    match std::fs::remove_file(archive_path(data_dir, session_id)) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
}

/// List stored archives (incl. orphaned `.partial`s) whose mtime is older
/// than `ttl` — sweep CANDIDATES only. Deletion is decided by the caller
/// against SESSION STATE: age alone must never kill an archive a long-budget
/// run could still re-fetch on an init re-execution. Failures are LOGGED,
/// never silent — a persistent PVC error would otherwise retain a leak with
/// no operational evidence.
pub fn stale_archive_candidates(
    data_dir: &std::path::Path,
    ttl: std::time::Duration,
) -> Vec<PathBuf> {
    let dir = data_dir.join("archives");
    let entries = match std::fs::read_dir(&dir) {
        Ok(e) => e,
        // No archives ever stored (e.g. the Docker provider): quiet no-op.
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Vec::new(),
        Err(e) => {
            tracing::warn!("archive TTL sweep cannot read {}: {e}", dir.display());
            return Vec::new();
        }
    };
    let now = std::time::SystemTime::now();
    let mut out = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        let meta = match entry.metadata() {
            Ok(m) => m,
            Err(e) => {
                tracing::warn!("archive TTL sweep cannot stat {}: {e}", path.display());
                continue;
            }
        };
        if !meta.is_file() {
            continue;
        }
        let mtime = match meta.modified() {
            Ok(t) => t,
            Err(e) => {
                tracing::warn!("archive TTL sweep: no mtime for {}: {e}", path.display());
                continue;
            }
        };
        // A future-dated mtime (clock skew) reads as fresh — conservative.
        let stale = now
            .duration_since(mtime)
            .map(|age| age >= ttl)
            .unwrap_or(false);
        if stale {
            out.push(path);
        }
    }
    out
}

/// The session a stored archive belongs to, from its `{uuid}.tar.gz`
/// (or `.partial`) filename. None = not an archive this server named.
pub fn archive_session_id(path: &std::path::Path) -> Option<Uuid> {
    let name = path.file_name()?.to_str()?;
    let stem = name
        .strip_suffix(".tar.gz.partial")
        .or_else(|| name.strip_suffix(".tar.gz"))?;
    Uuid::parse_str(stem).ok()
}

pub fn env_size_breakdown(env: &[(String, String)]) -> String {
    let mut parts: Vec<(usize, &str)> = env
        .iter()
        .map(|(k, v)| (k.len() + v.len(), k.as_str()))
        .collect();
    parts.sort_by_key(|&(n, _)| std::cmp::Reverse(n)); // largest first
    parts
        .iter()
        .take(4)
        .map(|(n, k)| format!("{k}={n}B"))
        .collect::<Vec<_>>()
        .join(", ")
}

/// The sandbox-facing slice of the frozen capability set. The runner needs:
/// sandbox servers' launch specs (command/args), and brokered servers'
/// frozen tool snapshots (to advertise them via the broker shim). Broker
/// internals — URLs, connection ids — stay out of the sandbox.
fn runner_capability_manifest(
    capabilities: &[fluidbox_core::capability::FrozenBundle],
) -> serde_json::Value {
    use fluidbox_core::capability::CapabilityServer;
    let servers: Vec<serde_json::Value> = capabilities
        .iter()
        .flat_map(|b| &b.servers)
        .map(|s| match s {
            CapabilityServer::Sandbox {
                name,
                command,
                args,
                ..
            } => serde_json::json!({
                "class": "sandbox", "name": name, "command": command, "args": args,
            }),
            CapabilityServer::Brokered { name, tools, .. } => serde_json::json!({
                "class": "brokered", "name": name,
                "tools": tools.iter().map(|t| serde_json::json!({
                    "name": t.name,
                    "description": t.description,
                    "input_schema": t.input_schema,
                })).collect::<Vec<_>>(),
            }),
        })
        .collect();
    serde_json::json!({ "servers": servers })
}

async fn materialize_workspace(
    state: &AppState,
    scope: TenantScope,
    session_id: Uuid,
    run_spec: &RunSpec,
) -> anyhow::Result<(Option<PathBuf>, Option<String>)> {
    let data_dir = state.cfg.data_dir.clone();
    let (ws, repo, r#ref) = match &run_spec.workspace {
        WorkspaceSpec::LocalCopy { path } => {
            let src = PathBuf::from(path);
            let ws = tokio::task::spawn_blocking(move || {
                fluidbox_workspace::materialize_local(&data_dir, session_id, &src)
            })
            .await??;
            (ws, None, None)
        }
        WorkspaceSpec::GitRepository {
            connection_id,
            binding_id,
            clone_url,
            r#ref,
            commit_sha,
            ..
        } => {
            // The credential is unsealed here, used for the fetch, and
            // dropped — it never reaches the RunSpec, sandbox env, ledger,
            // or artifacts.
            let auth_header = match binding_id {
                // Phase C: the fetch credential rides the run's frozen
                // `workspace_fetch` binding — recheck it (status + generation +
                // owner membership) and mechanically enforce the frozen resource
                // scope IMMEDIATELY before credential injection (design
                // :705-723). Authority `none` = public fetch, no credential.
                Some(bid) => {
                    workspace_binding_auth_header(
                        state,
                        scope,
                        session_id,
                        *bid,
                        clone_url,
                        r#ref.as_deref(),
                        commit_sha.as_deref(),
                    )
                    .await?
                }
                // Legacy runs froze no binding — the embedded connection_id
                // path, unchanged (status-only fresh check inside
                // connection_auth_header).
                None => match connection_id {
                    Some(cid) => Some(connection_auth_header(state, scope, *cid).await?),
                    None => None,
                },
            };
            let (url, rf, sha) = (clone_url.clone(), r#ref.clone(), commit_sha.clone());
            // Phase E: derive the clone egress policy from the shared boundary
            // (dev seam + operator allowlist + proxy). The configured clone base
            // becomes the file:// prefix gate; git runs out-of-process, so this
            // resolve-and-validate is its SSRF boundary (TOCTOU residual disclosed).
            let git_egress = fluidbox_workspace::GitEgressPolicy {
                dev_loopback: state.egress_policy.dev_loopback,
                allow_cidrs: state.egress_policy.allow_cidrs.clone(),
                clone_base_file_prefix: state.egress_policy.github_clone_base.clone(),
                proxy: state.egress_policy.proxy.clone(),
            };
            let ws = tokio::task::spawn_blocking(move || {
                fluidbox_workspace::materialize_git(
                    &data_dir,
                    session_id,
                    &url,
                    rf.as_deref(),
                    sha.as_deref(),
                    auth_header.as_deref(),
                    &git_egress,
                )
            })
            .await??;
            (ws, Some(clone_url.clone()), r#ref.clone())
        }
        WorkspaceSpec::Scratch => {
            // A scratch workspace so the agent still has somewhere to write.
            let dir = data_dir
                .join("workspaces")
                .join(session_id.to_string())
                .join("repo");
            std::fs::create_dir_all(&dir)?;
            let ws = tokio::task::spawn_blocking(move || {
                fluidbox_workspace::materialize_local(&data_dir, session_id, &dir)
            })
            .await??;
            (ws, None, None)
        }
    };

    if let Some(bc) = &ws.base_commit {
        fluidbox_db::set_base_commit(&state.pool, scope, session_id, bc)
            .await
            .ok();
    }
    ledger::record(
        state,
        scope,
        session_id,
        Actor::System,
        EventBody::WorkspaceInitialized {
            base_commit: ws.base_commit.clone(),
            files: Some(ws.file_count),
            repo,
            r#ref,
        },
    )
    .await;
    Ok((Some(ws.host_dir), ws.base_commit))
}

/// Is this session still ours to launch? Ownership is the ABSENCE of a
/// finalization intent (the single source of truth — it commits BEFORE the
/// wind-down transition, so a status-only check has a gap) on a session
/// still in an active state. Transient read errors are retried here: a
/// blip must not fail a healthy, fully materialized run.
async fn launch_ownership(state: &AppState, scope: TenantScope, id: Uuid) -> anyhow::Result<bool> {
    let mut last_err: Option<anyhow::Error> = None;
    for attempt in 0..3u32 {
        if attempt > 0 {
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
        let session = match fluidbox_db::get_session(&state.pool, scope, id).await {
            Ok(Some(s)) => s,
            Ok(None) => return Ok(false),
            Err(e) => {
                last_err = Some(e.into());
                continue;
            }
        };
        if !session.status_enum().accepts_work() {
            return Ok(false);
        }
        match fluidbox_db::get_finalization(&state.pool, scope, id).await {
            Ok(Some(_)) => return Ok(false),
            Ok(None) => return Ok(true),
            Err(e) => {
                last_err = Some(e.into());
            }
        }
    }
    Err(last_err.unwrap_or_else(|| anyhow::anyhow!("ownership read failed")))
}

/// Best-effort cleanup of a launch this task lost — but ONLY when no
/// finalization intent survives: a live intent means the finalizer still
/// owns collection (Docker reads the host workspace!) and its own terminal
/// cleanup removes everything afterward. Deleting under a live intent would
/// destroy the very evidence the finalizer is about to collect (a fast
/// runner that posted /result before its handle attached would lose its
/// patch). Only a fully reconciled session (terminal, intent released)
/// leaves the loser's debris with no other owner.
async fn abandon_launch(state: &AppState, scope: TenantScope, id: Uuid) {
    if state.cfg.keep_workspaces {
        return;
    }
    match fluidbox_db::get_finalization(&state.pool, scope, id).await {
        Ok(None) => {}
        Ok(Some(_)) => return, // the finalizer owns collection + cleanup
        Err(e) => {
            tracing::warn!("abandon_launch {id}: intent read failed ({e}); leaving files");
            return;
        }
    }
    if let Err(e) = fluidbox_workspace::cleanup_workspace(&state.cfg.data_dir, id) {
        tracing::warn!("abandoned-launch workspace cleanup for {id}: {e}");
    }
    let _ = delete_archive(&state.cfg.data_dir, id);
}

/// Phase C workspace fetch: resolve the git auth header from the run's frozen
/// `workspace_fetch` binding. Mechanically enforces the frozen resource scope
/// (the URL — and ref/commit when pinned — actually about to be fetched must
/// equal what the binding froze, design `:718`) BEFORE any credential access,
/// then reruns the connection-authority recheck (status + generation + owner
/// membership) IMMEDIATELY before minting the credential. Authority `none`
/// binding ⇒ public fetch, no credential (`Ok(None)`). Fails closed: a stale
/// binding, drifted scope, or revoked authority stops the run during
/// `initializing`, before any model spend.
async fn workspace_binding_auth_header(
    state: &AppState,
    scope: TenantScope,
    session_id: Uuid,
    binding_id: Uuid,
    clone_url: &str,
    r#ref: Option<&str>,
    commit_sha: Option<&str>,
) -> anyhow::Result<Option<String>> {
    let binding = fluidbox_db::get_run_resource_binding(&state.pool, scope, binding_id)
        .await?
        .ok_or_else(|| anyhow::anyhow!("workspace binding {binding_id} not found"))?;
    // Belt-and-braces: the binding must belong to THIS session (both frozen in
    // one transaction — a mismatch is corruption).
    if binding.session_id != session_id {
        anyhow::bail!("workspace binding {binding_id} does not belong to this session");
    }
    // Mechanical resource-scope enforcement BEFORE credential resolution.
    enforce_workspace_scope(&binding.resource_scope, clone_url, r#ref, commit_sha)?;
    // Public / credentialless fetch: no authority to recheck, no header to mint.
    if binding.authority_kind == "none" {
        return Ok(None);
    }
    // Connection authority: recheck immediately before the credential mints.
    let conn = crate::broker::recheck_binding(state, scope, &binding)
        .await
        .map_err(|e| anyhow::anyhow!("workspace binding recheck failed: {e}"))?;
    Ok(Some(
        crate::connectors::fetch_auth_header(state, &conn).await?,
    ))
}

/// The mechanical `workspace_fetch` scope check (design `:718-720`): the URL
/// about to be fetched must equal the frozen `resource_scope.url`, and the
/// ref/commit must match when the scope pins them (a null pin is unconstrained).
/// A clone of an admitted repo is not authority over some other url the RunSpec
/// might carry — so a mismatch refuses before any credential is read.
fn enforce_workspace_scope(
    resource_scope: &serde_json::Value,
    clone_url: &str,
    r#ref: Option<&str>,
    commit_sha: Option<&str>,
) -> anyhow::Result<()> {
    let scope_url = resource_scope.get("url").and_then(|v| v.as_str());
    if scope_url != Some(clone_url) {
        anyhow::bail!("workspace fetch url does not match the frozen binding scope");
    }
    if let Some(pinned) = resource_scope.get("ref").and_then(|v| v.as_str()) {
        if r#ref != Some(pinned) {
            anyhow::bail!("workspace fetch ref does not match the frozen binding scope");
        }
    }
    if let Some(pinned) = resource_scope.get("commit").and_then(|v| v.as_str()) {
        if commit_sha != Some(pinned) {
            anyhow::bail!("workspace fetch commit does not match the frozen binding scope");
        }
    }
    Ok(())
}

/// Resolve a connection into an `Authorization` header value for git fetch
/// via the provider's connector (PAT, or a minted App installation token).
/// Fails closed: missing/revoked connection or missing key stops the run
/// during `initializing` — before any model spend.
async fn connection_auth_header(
    state: &AppState,
    scope: TenantScope,
    connection_id: Uuid,
) -> anyhow::Result<String> {
    // Unfiltered read by design: workspace init runs from the frozen RunSpec's
    // resolved binding (control-plane side, no request principal) — authority is
    // the binding, not an owner-visibility viewer. The tenant is known (the run's
    // scope), so this executor-generic read rides a scoped_tx (RLS: set the GUC).
    let mut conn_tx = fluidbox_db::scoped_tx(&state.pool, scope).await?;
    let conn = fluidbox_db::get_connection(&mut *conn_tx, scope, connection_id)
        .await?
        .ok_or_else(|| anyhow::anyhow!("connection {connection_id} not found"))?;
    conn_tx.commit().await?;
    crate::connectors::fetch_auth_header(state, &conn).await
}

/// How long one terminate attempt may run — keeps every finalizer phase
/// individually bounded so the worst healthy drive stays far inside the
/// 420 s claim window (no driver overlap by construction).
const TERMINATE_TIMEOUT: Duration = Duration::from_secs(60);

/// Tear down the sandbox for a session. Idempotent — both providers treat
/// already-gone as success — so Err means the provider could NOT confirm
/// teardown: finalizer callers must stop (not destroy evidence or release
/// the intent) and retry. A missing or unparseable stored handle consults
/// provider truth (`list_managed` by session label) — a live sandbox must
/// never survive because its handle was lost or is garbage.
pub async fn reap(state: &AppState, scope: TenantScope, id: Uuid) -> Result<(), ()> {
    let session = match fluidbox_db::get_session(&state.pool, scope, id).await {
        Ok(Some(s)) => s,
        Ok(None) => return Ok(()),
        Err(e) => {
            tracing::warn!("reap {id}: session read failed: {e}");
            return Err(());
        }
    };
    let handle = match session_handle_state(&session) {
        StoredHandle::Handle(h) => Some(h),
        StoredHandle::None | StoredHandle::Unparseable => match discover_handle(state, id).await {
            Ok(h) => h,
            Err(()) => {
                tracing::warn!("reap {id}: sandbox discovery failed — retrying");
                return Err(());
            }
        },
    };
    let Some(handle) = handle else {
        return Ok(()); // verifiably gone (provider truth, not a parse quirk)
    };
    match tokio::time::timeout(TERMINATE_TIMEOUT, state.provider.terminate(&handle)).await {
        Ok(Ok(())) => Ok(()),
        Ok(Err(e)) => {
            tracing::warn!("reap {id}: {e}");
            Err(())
        }
        Err(_) => {
            tracing::warn!("reap {id}: terminate timed out");
            Err(())
        }
    }
}

fn uuid_token() -> String {
    // 32 hex chars of entropy from a v4 uuid (no extra deps).
    Uuid::new_v4().simple().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use fluidbox_core::state::SessionStatus::*;

    fn dl() -> chrono::DateTime<chrono::Utc> {
        chrono::Utc::now() + chrono::Duration::seconds(30)
    }

    /// H5's poster race: /result wins the intent (no quiesce, NULL deadline);
    /// the losing cancel still parked the session in Cancelling. The plan
    /// must go straight to Finalizing — never an instant quiesce timeout
    /// that discards a completed run's diff.
    #[test]
    fn result_wins_cancel_loses_goes_straight_to_finalizing() {
        assert_eq!(
            plan_step(false, None, Cancelling),
            WinddownStep::EnterFinalizing
        );
    }

    /// Cancel's intent persisted but the server crashed before the
    /// Cancelling transition landed: recovery re-materializes the quiesce
    /// path from the row, whatever active state the session is in.
    #[test]
    fn crash_before_transition_rematerializes_cancelling() {
        for st in [
            Created,
            Provisioning,
            Initializing,
            Running,
            AwaitingApproval,
        ] {
            assert_eq!(
                plan_step(true, Some(dl()), st),
                WinddownStep::EnterCancelling
            );
        }
    }

    #[test]
    fn quiesce_intent_in_cancelling_waits_until_its_deadline() {
        let d = dl();
        assert_eq!(
            plan_step(true, Some(d), Cancelling),
            WinddownStep::AwaitQuiesce(d)
        );
    }

    /// A quiesce intent without a deadline is malformed — leave it for
    /// retry, never treat it as an already-expired deadline.
    #[test]
    fn quiesce_without_deadline_is_malformed_not_instant_timeout() {
        assert_eq!(plan_step(true, None, Cancelling), WinddownStep::Malformed);
    }

    /// Completed/failed intents recovered in any active state skip quiesce.
    #[test]
    fn no_quiesce_intent_enters_finalizing_from_any_active_state() {
        for st in [
            Created,
            Provisioning,
            Initializing,
            Running,
            AwaitingApproval,
        ] {
            assert_eq!(plan_step(false, None, st), WinddownStep::EnterFinalizing);
        }
    }

    #[test]
    fn finalizing_collects_regardless_of_intent_shape() {
        assert_eq!(
            plan_step(true, Some(dl()), Finalizing),
            WinddownStep::Collect
        );
        assert_eq!(plan_step(false, None, Finalizing), WinddownStep::Collect);
    }

    /// Terminal sessions with a surviving intent owe cleanup (the crash gap
    /// between the terminal commit and its side effects) — never a
    /// re-finalize, never a release without reconciling.
    #[test]
    fn terminal_with_intent_reconciles_cleanup() {
        for st in [Completed, Failed, Cancelled, BudgetExceeded] {
            assert_eq!(plan_step(true, Some(dl()), st), WinddownStep::Reconcile);
            assert_eq!(plan_step(false, None, st), WinddownStep::Reconcile);
        }
    }

    #[test]
    fn ttl_sweep_removes_only_stale_archives() {
        let tmp = std::env::temp_dir().join(format!("fbx-ttl-{}", uuid::Uuid::now_v7()));
        let archives = tmp.join("archives");
        std::fs::create_dir_all(&archives).unwrap();
        let sid = uuid::Uuid::now_v7();
        std::fs::write(archives.join(format!("{sid}.tar.gz")), b"x").unwrap();
        std::fs::write(archives.join("b.tar.gz"), b"y").unwrap();

        // A generous TTL keeps fresh archives.
        assert!(stale_archive_candidates(&tmp, std::time::Duration::from_secs(3600)).is_empty());
        assert!(archives.join("b.tar.gz").exists());

        // TTL zero: everything with mtime <= now is a candidate — nothing is
        // DELETED here; the worker decides against session state.
        let mut candidates = stale_archive_candidates(&tmp, std::time::Duration::ZERO);
        candidates.sort();
        assert_eq!(candidates.len(), 2);
        assert!(archives.join("b.tar.gz").exists());

        // A missing archives dir (Docker provider) is a quiet no-op.
        assert!(stale_archive_candidates(&tmp.join("nope"), std::time::Duration::ZERO).is_empty());
        std::fs::remove_dir_all(&tmp).ok();
    }

    #[test]
    fn archive_filenames_map_back_to_their_session() {
        let sid = uuid::Uuid::now_v7();
        let p = std::path::PathBuf::from(format!("/data/archives/{sid}.tar.gz"));
        assert_eq!(archive_session_id(&p), Some(sid));
        let partial = std::path::PathBuf::from(format!("/data/archives/{sid}.tar.gz.partial"));
        assert_eq!(archive_session_id(&partial), Some(sid));
        assert_eq!(
            archive_session_id(std::path::Path::new("/data/archives/junk.tar.gz")),
            None
        );
        assert_eq!(
            archive_session_id(std::path::Path::new("/data/archives/notatar")),
            None
        );
    }
}
