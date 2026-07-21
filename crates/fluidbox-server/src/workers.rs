//! Background workers: heartbeat watchdog, budget sweeper (wall-clock),
//! approval expiry, the restart-recoverable finalize driver, and boot-time
//! orphan reaping.

use crate::orchestrator;
use crate::state::AppState;
use fluidbox_core::spec::RunSpec;
use fluidbox_core::traits::SandboxHandle;
use fluidbox_db::TenantScope;
use std::time::Duration;
use tokio::time::MissedTickBehavior;

/// How many rows one tick of a periodic sweep may take. Each swept row costs at
/// least one SERIAL follow-up write (a ledger append), so the batch — not the
/// backlog — is what a tick's duration is sized against.
const SWEEP_BATCH: i64 = 200;

/// How long after a run goes TERMINAL the deployment-wide GC may retire its
/// leftover `mcp_upstream_sessions` rows (Phase F, Task 3).
///
/// This is a deliberate handicap, not a timeout. The run-terminal teardown path
/// (`broker::run_terminal_mcp_cleanup`) is the ONLY thing that ever sends the
/// upstream `DELETE`, it now sees every replica's rows, and — because the rows are
/// durable — a reconciler pass that could not finish is re-driven. The grace period
/// exists so the sweeper never retires a row out from under a teardown that is
/// still owed a retry. 15 minutes is comfortably past both the finalize driver's
/// re-drive cadence and the longest single teardown (a peer count × the 5 s
/// `MCP_DELETE_TIMEOUT`).
const MCP_SESSION_GRACE_SECS: i64 = 900;

/// Every periodic worker uses this. `tokio::time::interval` defaults to `Burst`:
/// after a tick that overran its period, the missed ticks fire BACK-TO-BACK to
/// "catch up", so one slow sweep is immediately followed by several with no gap —
/// exactly when the database is least able to take them. `Delay` re-phases from
/// the moment the slow tick finished, guaranteeing a full period of breathing
/// room afterwards.
///
/// `Delay` rather than `Skip` because every one of these ticks is a scan of
/// "whatever is due NOW" — never work bound to a wall-clock slot — so nothing is
/// lost by re-phasing, and `Skip` (which preserves the original phase) can still
/// leave a fraction-of-a-period gap after a long tick.
fn periodic(period: Duration) -> tokio::time::Interval {
    let mut tick = tokio::time::interval(period);
    tick.set_missed_tick_behavior(MissedTickBehavior::Delay);
    tick
}

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
    // Cross-replica approval wakeups (Gap 13): every replica wakes its OWN
    // waiters off the shared NOTIFY channel.
    spawn_approval_wakeups(state.clone());
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
    let mut tick = periodic(Duration::from_secs(60));
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
    let mut tick = periodic(Duration::from_secs(3600));
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
    let mut tick = periodic(Duration::from_secs(15));
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
    let mut tick = periodic(Duration::from_secs(10));
    loop {
        tick.tick().await;

        // Phase E (#33; Gap 11): sweep stale execution claims on the same 10s
        // cadence. A `claimed` row whose control-plane dispatcher crashed
        // mid-flight is CAS'd to `ambiguous` past its TTL (never auto-retried —
        // invariant 15) and ledgered so the timeline records the unknown outcome.
        // BOUNDED like the reservation sweep below (review, minor): each swept row
        // costs a SERIAL ledger append, so an unbounded batch could make one tick
        // outrun its own 10 s period. A backlog drains over several ticks instead.
        match fluidbox_db::system_worker::sweep_stale_execution_claims(
            &state.pool,
            chrono::Utc::now(),
            SWEEP_BATCH,
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

        // Phase E (#33; Gap 14): reconcile expired LLM budget reservations on the
        // same tick, BEFORE the budget loop reads usage totals — so a booking whose
        // facade request died is already counted as (conservative) usage by the
        // time this session's budget is judged, rather than a tick late. The
        // conversion is one statement in the DB (usage row keyed on the request id,
        // then the CAS), so it is idempotent against a late drain in either order.
        match fluidbox_db::system_worker::sweep_expired_llm_reservations(
            &state.pool,
            chrono::Utc::now(),
            SWEEP_BATCH,
        )
        .await
        {
            Ok(swept) => {
                for r in swept {
                    let scope = TenantScope::assume(r.tenant_id);
                    let cost = r
                        .reserved_cost_usd
                        .map(|c| format!(", ~${c:.4}"))
                        .unwrap_or_default();
                    crate::ledger::record(
                        &state,
                        scope,
                        r.session_id,
                        fluidbox_core::event::Actor::System,
                        fluidbox_core::event::EventBody::AgentMessage {
                            role: "system".into(),
                            text: format!(
                                "model request {} never reported usage — charging the \
                                 conservative reservation ({} tokens{cost})",
                                r.request_id, r.reserved_tokens
                            ),
                        },
                    )
                    .await;
                }
            }
            Err(e) => tracing::warn!("expired LLM-reservation sweep failed: {e}"),
        }

        // Phase F (Task 3): retire `mcp_upstream_sessions` rows whose run has been
        // terminal for at least the grace period.
        //
        // This is a GARBAGE COLLECTOR, not a delivery mechanism: it does NOT send
        // the upstream DELETE (the reasoning lives on
        // `mcp_sessions::sweep_orphaned_upstream_sessions`). What reaches it is the
        // residue the run-terminal path could not send — dominated by rows whose
        // credential is unresolvable, which is exactly where invariant 9 forbids
        // sending one. The disclosed cost is that such an upstream session stays
        // allocated until the upstream expires it itself; the alternative is a
        // second retry/backoff system dialing a wedged server on a timer.
        //
        // Bounded like the sweeps above, and no ledger row per swept session — the
        // row is a teardown receipt, not a run event, and a run that ended 15
        // minutes ago should not gain timeline entries.
        let terminal_before =
            chrono::Utc::now() - chrono::Duration::seconds(MCP_SESSION_GRACE_SECS);
        match fluidbox_db::mcp_sessions::sweep_orphaned_upstream_sessions(
            &state.pool,
            terminal_before,
            SWEEP_BATCH,
        )
        .await
        {
            Ok(swept) if !swept.is_empty() => tracing::info!(
                "retired {} orphaned upstream MCP session row(s) without an upstream DELETE \
                 (their sessions expire on the upstream's own schedule)",
                swept.len()
            ),
            Ok(_) => {}
            Err(e) => tracing::warn!("orphaned upstream MCP session sweep failed: {e}"),
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
            //
            // Phase E (#33; Gap 14): the projection now includes LIVE reservations
            // (`state='reserved'`), not just recorded usage — a budget check that
            // ignores booked-but-unreported spend is the very bug Gap 14 names.
            //
            // DISCLOSED CONSEQUENCE, at its real bound (review, minor). In steady
            // state a healthy run holds one reservation at a time, so this stops it
            // within ONE conservative reservation of the ceiling. That is NOT the
            // worst case: a reservation is drained by the facade request that made
            // it, so a control-plane RESTART (or any crash between booking and
            // drain) leaves reservations stranded `reserved` until the 30-min TTL
            // sweep converts them — and up to the per-session ceiling
            // (`FLUIDBOX_LLM_MAX_CONCURRENT_RESERVATIONS`, default 32) can be
            // stranded at once. Every stranded booking counts here immediately, so a
            // run whose SANDBOX survived the restart can be `finalize_forced` early
            // by up to `ceiling` conservative reservations' worth of phantom spend,
            // not one. It self-heals as the sweep charges them (they become real
            // usage rows, so the projection stops double-counting) — but the early
            // stop happens on the tick, not after the heal.
            //
            // Still the "over-charge in the safe direction" the design asks for
            // (:1122-1123) and the counterpart to the facade's sole-claimant
            // admission — that carve-out keeps a lone request from livelocking on
            // 429s, and this is where such a run is stopped properly instead:
            // once, with a ledgered BudgetExceeded.
            let mut over: Option<&'static str> = None;
            if run_spec.budgets.max_tokens.is_some() || run_spec.budgets.max_cost_usd.is_some() {
                if let Ok(totals) = fluidbox_db::usage_totals(&state.pool, scope, s.id).await {
                    let booked = fluidbox_db::active_reservation_totals(&state.pool, scope, s.id)
                        .await
                        .unwrap_or_default();
                    if let Some(max) = run_spec.budgets.max_cost_usd {
                        if totals.cost_usd + booked.cost_usd >= max {
                            over = Some("max_cost_usd");
                        }
                    }
                    if over.is_none() {
                        if let Some(max) = run_spec.budgets.max_tokens {
                            let used = (totals.input_tokens
                                + totals.output_tokens
                                + totals.cache_read_tokens
                                + totals.cache_write_tokens
                                + booked.tokens) as u64;
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
///
/// Phase E (#33; Gap 13): the sweep is now a cross-tenant READ followed by a
/// per-row, tenant-SCOPED decision transaction. Three things fall out of that
/// split, all of them the point:
///   * the expiry decision emits its canonical `approval.decided` +
///     `tool.decision` INSIDE the CAS that makes it, like every other decision
///     site — waiters no longer emit, so this is the only place those rows can
///     come from on the timeout path;
///   * the CAS (`status = 'pending' and expires_at < now()`) is the single-winner
///     test, so N replicas sweeping the same row still produce ONE decision and
///     ONE pair of events;
///   * the same transaction `pg_notify`s `fluidbox_approvals`, so a waiter on
///     ANOTHER replica wakes on the expiry instead of only on its ≤2 s poll floor
///     (the local `wake` below stays as the zero-latency path for this replica).
async fn approval_expiry(state: AppState) {
    let mut tick = periodic(Duration::from_secs(5));
    loop {
        tick.tick().await;
        let due =
            match fluidbox_db::system_worker::expired_pending_approvals(&state.pool, 200).await {
                Ok(d) => d,
                Err(e) => {
                    tracing::warn!("approval expiry scan failed: {e}");
                    continue;
                }
            };
        for a in due {
            let scope = TenantScope::assume(a.tenant_id);
            let events = crate::internal::approval_decision_events(
                &state,
                a.session_id,
                a.id,
                &a.tool_call_id,
                &a.tool,
                "expired",
                "timeout",
            );
            match fluidbox_db::expire_approval_tx(&state.pool, scope, a.id, events).await {
                // Lost the CAS (a human decided it, or another replica expired it
                // first) — that winner ledgered and notified; nothing owed here.
                Ok(None) => {}
                Ok(Some(_)) => state.approvals.wake(a.id).await,
                Err(e) => tracing::warn!("approval {} expiry failed: {e}", a.id),
            }
        }
    }
}

/// Relay committed approval decisions from the `fluidbox_approvals` LISTEN
/// channel into THIS replica's in-memory waiter registry (Phase E, #33; Gap 13).
///
/// Without it, a `/permission` handler blocked on replica B never learns that
/// replica A served the approve — it only discovers the decision on its next
/// ≤2 s poll. That poll stays (it is the missed-notify and Neon scale-to-zero
/// backstop, exactly as `events_after` is for SSE); this makes the common case
/// immediate. A lagged/closed broadcast receiver is not an error: the poll floor
/// covers it, so the loop just keeps consuming.
pub fn spawn_approval_wakeups(state: AppState) {
    tokio::spawn(async move {
        let mut rx = state.approvals_tx.subscribe();
        loop {
            match rx.recv().await {
                Ok(id) => state.approvals.wake(id).await,
                Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                    tracing::warn!("approval wakeup relay lagged {n} notifications; waiters fall back to the poll floor");
                }
                Err(tokio::sync::broadcast::error::RecvError::Closed) => return,
            }
        }
    });
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
    let mut tick = periodic(Duration::from_secs(20));
    loop {
        tick.tick().await;
        recover_finalizations(&state).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fluidbox_core::state::SessionStatus;

    /// The Gap-13 worker rule, asserted rather than asserted-in-prose (Phase E,
    /// #33; design :1094-1096): the three PERIODIC lifecycle workers — watchdog,
    /// budget sweeper, approval expiry — run on EVERY replica and must never
    /// perform a side effect themselves. They may only record a single-winner
    /// intent (`orchestrator::fail` / `orchestrator::finalize_forced`, both of
    /// which reduce to `begin_finalization`'s `on conflict do nothing`) or CAS an
    /// approval; the cleanup / artifact collection / publication that follows is
    /// performed by `drive_finalization` alone, under the finalization claim AND
    /// the epoch-fenced session lease. So two replicas double-firing a worker is
    /// benign by construction.
    ///
    /// A source guard, so it runs without a database. It slices each worker's
    /// body and refuses any provider MUTATION in it. `state()` (a read probe) is
    /// deliberately allowed — the watchdog must confirm a sandbox is dead before
    /// recording its verdict.
    ///
    /// NOT covered, deliberately: `boot_orphan_sweep` and `reconcile_managed` DO
    /// terminate sandboxes without a lease. They are not lifecycle drivers — they
    /// reap sandboxes whose session is already terminal or unknown, which is
    /// durable truth rather than a race, and their mutation is idempotent
    /// (terminate treats already-gone as success) and UID-preconditioned on
    /// Kubernetes against name reuse.
    #[test]
    fn periodic_lifecycle_workers_perform_no_provider_side_effects() {
        let src = include_str!("workers.rs");
        for (worker, next_item) in [
            ("async fn watchdog(", "async fn sandbox_dead("),
            ("async fn budget_sweeper(", "/// Expire pending approvals"),
            ("async fn approval_expiry(", "/// Relay committed approval"),
        ] {
            let start = src
                .find(worker)
                .unwrap_or_else(|| panic!("{worker} exists"));
            let end = src[start..]
                .find(next_item)
                .map(|i| start + i)
                .unwrap_or_else(|| panic!("{worker} body is delimited by {next_item}"));
            let body = &src[start..end];
            for mutation in [
                ".provider.terminate(",
                ".provider.provision(",
                ".provider.collect_artifacts(",
            ] {
                assert!(
                    !body.contains(mutation),
                    "{worker} must not call {mutation}: a periodic worker runs on every \
                     replica, so its side effects would fire N times. Record the intent \
                     (fail / finalize_forced) and let the lease-holding finalization \
                     driver act."
                );
            }
        }
    }

    /// Gap 14's half of the budget sweeper, asserted from source so it stays
    /// mutation-provable without a database. TWO properties:
    ///   * expired reservations are RECONCILED on this tick, and BEFORE the
    ///     budget loop reads usage totals — otherwise a crashed request's
    ///     conservative charge is counted a tick late;
    ///   * the token AND cost projections include LIVE reservations. A budget
    ///     check that sees only recorded usage is precisely the Gap-14 defect,
    ///     and this worker is the crash-durable driver for an idle runner.
    #[test]
    fn budget_sweeper_reconciles_and_projects_live_reservations() {
        let src = include_str!("workers.rs");
        let start = src
            .find("async fn budget_sweeper(")
            .expect("budget_sweeper exists");
        let end = src[start..]
            .find("/// Expire pending approvals")
            .map(|i| start + i)
            .expect("budget_sweeper's body is delimited");
        let body = &src[start..end];

        let sweep = body
            .find("sweep_expired_llm_reservations(")
            .expect("the sweeper converts expired LLM reservations into usage");
        let totals = body
            .find("fluidbox_db::usage_totals(")
            .expect("the budget loop reads usage totals");
        assert!(
            sweep < totals,
            "expired reservations must be converted BEFORE usage totals are read, \
             so a crashed request's conservative charge is judged on this tick"
        );
        assert!(
            body.contains("active_reservation_totals("),
            "the budget projection must count LIVE reservations, not just recorded usage"
        );
        assert!(
            body.contains("totals.cost_usd + booked.cost_usd >= max"),
            "the COST arm must include live reservations"
        );
        assert!(
            body.contains("+ booked.tokens) as u64"),
            "the TOKEN arm must include live reservations"
        );
    }

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
