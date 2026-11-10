//! Sessions: creation, status transitions, the orchestrator lease, sandbox handles.

use crate::run_resource_bindings::{insert_run_resource_bindings, NewRunResourceBinding};
use crate::scope::{scoped_tx, TenantScope};
use chrono::{DateTime, Utc};
use fluidbox_core::state::SessionStatus;
use serde_json::Value;
use sqlx::PgPool;
use uuid::Uuid;

#[derive(Debug, Clone, sqlx::FromRow, serde::Serialize)]
pub struct SessionRow {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub agent_id: Uuid,
    pub agent_revision_id: Uuid,
    pub status: String,
    pub status_reason: Option<String>,
    pub autonomy: String,
    pub trust_tier: String,
    pub task: String,
    pub repo_source: Value,
    pub run_spec: Value,
    /// InvocationContext envelope (design §3.4). Null for pre-Phase-2 rows.
    pub trigger: Option<Value>,
    pub sandbox_handle: Option<Value>,
    pub budgets: Value,
    pub base_commit: Option<String>,
    pub result_summary: Option<String>,
    pub event_seq: i64,
    pub last_heartbeat_at: Option<DateTime<Utc>>,
    pub started_at: Option<DateTime<Utc>>,
    pub finished_at: Option<DateTime<Utc>>,
    /// First entry into `queued` (coalesce-stamped, like `started_at`). The
    /// queue-age bound measures from here, never `created_at`, so a run that
    /// spent days parked for a human authorization is not expired the moment
    /// it becomes dispatchable (design 2026-08-23 §5).
    pub queued_at: Option<DateTime<Utc>>,
    /// First entry into `provisioning` — the stale-launch watchdog's age
    /// anchor. `created_at` is refreshed by nothing, which is why the watchdog
    /// used it; but a run may lawfully sit parked for days before launching,
    /// so launch age needs its own timestamp (design §3.10).
    pub launched_at: Option<DateTime<Utc>>,
    /// Not-before gate for redispatch after a provider capacity bounce.
    pub dispatch_after: Option<DateTime<Utc>>,
    /// Dispatch attempts (the claim increments it); bounded by config.
    pub dispatch_attempts: i32,
    /// Who invoked this run (design "tenant/user audit fields"): the invocation
    /// class, and the authenticated user id when one exists (None for
    /// operator-token / trigger / schedule / webhook). Drives run visibility.
    pub invoked_by_kind: Option<String>,
    pub invoked_by_user_id: Option<Uuid>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl SessionRow {
    pub fn status_enum(&self) -> SessionStatus {
        SessionStatus::parse(&self.status).unwrap_or(SessionStatus::Failed)
    }
}

// ─── Sessions ─────────────────────────────────────────────────────────────

#[allow(clippy::too_many_arguments)]
pub async fn create_session(
    pool: &PgPool,
    scope: TenantScope,
    agent_id: Uuid,
    agent_revision_id: Uuid,
    autonomy: &str,
    trust_tier: &str,
    task: &str,
    repo_source: &Value,
    run_spec: &Value,
    budgets: &Value,
    trigger: Option<&Value>,
    invoked_by_kind: Option<&str>,
    invoked_by_user_id: Option<Uuid>,
    bind_invocation: Option<Uuid>,
    bind_dispatch: Option<Uuid>,
    bindings: &[NewRunResourceBinding],
    network_grant: Option<&crate::network_grants::NewNetworkGrant>,
) -> sqlx::Result<SessionRow> {
    let mut tx = scoped_tx(pool, scope).await?;
    // Prove the agent AND the pinned revision both belong to this tenant in SQL
    // (the run builder resolves them under scope first; this is the relational
    // backstop). A miss yields zero rows → fetch_one RowNotFound, surfaced via
    // `?` like any other create failure.
    let row: SessionRow = sqlx::query_as(
        "insert into sessions
           (id, tenant_id, agent_id, agent_revision_id, autonomy, trust_tier, task, repo_source, run_spec, budgets, trigger, invoked_by_kind, invoked_by_user_id)
         select $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13
         where exists (select 1 from agents a where a.id = $3 and a.tenant_id = $2)
           and exists (select 1 from agent_revisions r where r.id = $4 and r.agent_id = $3)
         returning *",
    )
    .bind(Uuid::now_v7())
    .bind(scope.tenant_id())
    .bind(agent_id)
    .bind(agent_revision_id)
    .bind(autonomy)
    .bind(trust_tier)
    .bind(task)
    .bind(repo_source)
    .bind(run_spec)
    .bind(budgets)
    .bind(trigger)
    .bind(invoked_by_kind)
    .bind(invoked_by_user_id)
    .fetch_one(&mut *tx)
    .await?;
    // Resolved run resource bindings are written INSIDE this transaction — a run
    // and the frozen record of what it resolved commit together, or not at all
    // (design :391-463; invariant 21). The composite FK refuses a binding whose
    // (tenant, session) does not match this session's.
    if !bindings.is_empty() {
        insert_run_resource_bindings(&mut tx, scope, row.id, bindings).await?;
    }
    // The network grant commits with the run for the same reason (design
    // "governed sandbox network access"): a session whose grant row is missing
    // cannot be provisioned at all, because the orchestrator gate fails closed
    // on it — atomicity turns that unrecoverable state into a create failure.
    if let Some(g) = network_grant {
        crate::network_grants::insert_network_grant(&mut tx, scope, row.id, g).await?;
    }
    // Atomic claim bind: the run and its idempotency claim commit together,
    // so a crash can never orphan a created run from its claim (which would
    // let the stale-claim takeover duplicate it).
    if let Some(invocation) = bind_invocation {
        // EXISTS-scoped through the owning subscription so the claim can only
        // bind an invocation in this session's tenant (matches the predicate
        // style in `mark_invocation_skipped`).
        sqlx::query(
            "update trigger_invocations set session_id = $2
             where id = $1
               and exists (select 1 from trigger_subscriptions sub
                           where sub.id = trigger_invocations.subscription_id
                             and sub.tenant_id = $3)",
        )
        .bind(invocation)
        .bind(row.id)
        .bind(scope.tenant_id())
        .execute(&mut *tx)
        .await?;
    }
    // Same discipline for the event fan-out claim (level-2 dedup): the
    // dispatch row and the session commit together.
    if let Some(dispatch) = bind_dispatch {
        // EXISTS-scoped through the owning delivery → connection so the claim
        // can only bind a dispatch in this session's tenant (matches the
        // predicate style in `list_delivery_dispatches`).
        sqlx::query(
            "update trigger_dispatches set session_id = $2
             where id = $1
               and exists (select 1 from trigger_deliveries d
                           join integration_connections c on c.id = d.connection_id
                           where d.id = trigger_dispatches.delivery_id
                             and c.tenant_id = $3)",
        )
        .bind(dispatch)
        .bind(row.id)
        .bind(scope.tenant_id())
        .execute(&mut *tx)
        .await?;
    }
    tx.commit().await?;
    Ok(row)
}

pub async fn get_session(
    pool: &PgPool,
    scope: TenantScope,
    id: Uuid,
) -> sqlx::Result<Option<SessionRow>> {
    let mut tx = scoped_tx(pool, scope).await?;

    let __rls_out = sqlx::query_as("select * from sessions where id = $1 and tenant_id = $2")
        .bind(id)
        .bind(scope.tenant_id())
        .fetch_optional(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(__rls_out)
}

/// List a tenant's sessions, newest first. `invoked_by` narrows to a single
/// user's runs (the run-visibility rule for a plain member); `None` returns
/// every session in the tenant (operator / `runs.read_all` holders).
pub async fn list_sessions(
    pool: &PgPool,
    scope: TenantScope,
    invoked_by: Option<Uuid>,
    limit: i64,
) -> sqlx::Result<Vec<SessionRow>> {
    let mut tx = scoped_tx(pool, scope).await?;

    let __rls_out = sqlx::query_as(
        "select * from sessions
         where tenant_id = $1 and ($2::uuid is null or invoked_by_user_id = $2)
         order by created_at desc limit $3",
    )
    .bind(scope.tenant_id())
    .bind(invoked_by)
    .bind(limit)
    .fetch_all(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(__rls_out)
}

/// The single status writer. Validates the transition inside a transaction;
/// returns Ok(None) if the transition is not legal (caller decides whether
/// that is an error or a benign race).
pub async fn transition_session(
    pool: &PgPool,
    scope: TenantScope,
    id: Uuid,
    next: SessionStatus,
    reason: Option<&str>,
) -> sqlx::Result<Option<(SessionStatus, SessionRow)>> {
    let mut tx = scoped_tx(pool, scope).await?;
    let row: Option<(String,)> =
        sqlx::query_as("select status from sessions where id = $1 and tenant_id = $2 for update")
            .bind(id)
            .bind(scope.tenant_id())
            .fetch_optional(&mut *tx)
            .await?;
    let Some((current,)) = row else {
        return Ok(None);
    };
    let current = SessionStatus::parse(&current).unwrap_or(SessionStatus::Failed);
    if !current.can_transition_to(next) {
        tx.rollback().await.ok();
        return Ok(None);
    }
    let updated: SessionRow = sqlx::query_as(
        "update sessions set
            status = $2,
            status_reason = $3,
            updated_at = now(),
            started_at = case when $2 = 'running'
                              then coalesce(started_at, now()) else started_at end,
            queued_at = case when $2 = 'queued'
                             then coalesce(queued_at, now()) else queued_at end,
            launched_at = case when $2 = 'provisioning'
                               then coalesce(launched_at, now()) else launched_at end,
            finished_at = case when $2 in ('completed','failed','cancelled','budget_exceeded')
                               then now() else finished_at end
         where id = $1 and tenant_id = $4 returning *",
    )
    .bind(id)
    .bind(next.as_str())
    .bind(reason)
    .bind(scope.tenant_id())
    .fetch_one(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(Some((current, updated)))
}

/// The epoch-fenced sibling of [`transition_session`] (Phase E, #33; Gap 13).
/// Identical semantics plus ONE extra condition: the session's
/// `orchestrator_epoch` must still equal the epoch the caller acquired with its
/// lease. A driver that was paused, partitioned, or simply slow — and whose lease
/// another replica then stole — carries a STALE epoch, so its lifecycle mutation
/// matches zero rows and returns `Ok(None)` instead of overwriting the new
/// owner's work. The epoch is checked UNDER the same `for update` row lock the
/// status guard uses, so the fence and the state-machine check see one snapshot.
///
/// Deliberately a separate entry point rather than an `Option<i64>` parameter on
/// `transition_session`: request-side intent writes (cancel, `finalize_forced`,
/// `maybe_resume`) are NOT driver mutations and must stay unfenced — they are
/// idempotent CAS inserts whose whole job is to be accepted from any replica.
pub async fn transition_session_fenced(
    pool: &PgPool,
    scope: TenantScope,
    id: Uuid,
    next: SessionStatus,
    reason: Option<&str>,
    expected_epoch: i64,
) -> sqlx::Result<Option<(SessionStatus, SessionRow)>> {
    let mut tx = scoped_tx(pool, scope).await?;
    let row: Option<(String, i64)> = sqlx::query_as(
        "select status, orchestrator_epoch from sessions
         where id = $1 and tenant_id = $2 for update",
    )
    .bind(id)
    .bind(scope.tenant_id())
    .fetch_optional(&mut *tx)
    .await?;
    let Some((current, epoch)) = row else {
        return Ok(None);
    };
    if epoch != expected_epoch {
        tx.rollback().await.ok();
        return Ok(None);
    }
    let current = SessionStatus::parse(&current).unwrap_or(SessionStatus::Failed);
    if !current.can_transition_to(next) {
        tx.rollback().await.ok();
        return Ok(None);
    }
    let updated: SessionRow = sqlx::query_as(
        "update sessions set
            status = $2,
            status_reason = $3,
            updated_at = now(),
            started_at = case when $2 = 'running'
                              then coalesce(started_at, now()) else started_at end,
            queued_at = case when $2 = 'queued'
                             then coalesce(queued_at, now()) else queued_at end,
            launched_at = case when $2 = 'provisioning'
                               then coalesce(launched_at, now()) else launched_at end,
            finished_at = case when $2 in ('completed','failed','cancelled','budget_exceeded')
                               then now() else finished_at end
         where id = $1 and tenant_id = $4 and orchestrator_epoch = $5 returning *",
    )
    .bind(id)
    .bind(next.as_str())
    .bind(reason)
    .bind(scope.tenant_id())
    .bind(expected_epoch)
    .fetch_one(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(Some((current, updated)))
}

/// Acquire, STEAL, or renew this replica's driver lease on one session, and
/// return the fencing epoch to carry (Phase E, #33; Gap 13; design :1067-1078).
///
/// Predicate — take it iff the lease is free, expired, or already mine:
/// `owner is null OR lease_until < now() OR owner = $me`. `None` means another
/// replica holds an UNEXPIRED lease: this driver must not mutate the session.
///
/// **The epoch increments ONLY on an owner CHANGE.** A renew by the same owner
/// keeps it, so a healthy driver's fence never moves under its own feet.
/// Re-taking a lease of OURS that merely lapsed (nobody stole it) also keeps the
/// epoch — the bump is gated on the owner actually changing. A takeover by a
/// DIFFERENT replica bumps it, which instantly invalidates every mutation the
/// previous holder had in flight. That asymmetry is what makes the epoch a
/// fencing TOKEN rather than a counter.
///
/// Time-based takeover, exactly like `claim_finalization` — NEVER a Postgres
/// advisory lock. The design rejects advisory locks here (`:1067-1072`): they are
/// tied to one connection, fragile under pool reconnects and Neon scale-to-zero,
/// and poorly observable. A lease column survives all three and is queryable.
/// Beneath this replica-scope fence the Kubernetes provider's UID-preconditioned
/// delete stays as the PROVIDER-scope fence.
pub async fn acquire_session_lease(
    pool: &PgPool,
    scope: TenantScope,
    id: Uuid,
    owner: Uuid,
    ttl_secs: i64,
) -> sqlx::Result<Option<i64>> {
    let mut tx = scoped_tx(pool, scope).await?;
    let row: Option<(i64,)> = sqlx::query_as(
        "update sessions set
            orchestrator_owner_id = $3,
            orchestrator_lease_until = now() + make_interval(secs => $4),
            orchestrator_epoch = case
                when orchestrator_owner_id is distinct from $3
                then orchestrator_epoch + 1 else orchestrator_epoch end,
            updated_at = now()
         where id = $1 and tenant_id = $2
           and (orchestrator_owner_id is null
                or orchestrator_lease_until is null
                or orchestrator_lease_until < now()
                or orchestrator_owner_id = $3)
         returning orchestrator_epoch",
    )
    .bind(id)
    .bind(scope.tenant_id())
    .bind(owner)
    .bind(ttl_secs.max(1) as f64)
    .fetch_optional(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(row.map(|(e,)| e))
}

/// The session's current lease holder + fencing epoch — the read half of
/// [`acquire_session_lease`], used by tests and by side-effect guards that want to
/// confirm ownership without extending the lease.
pub async fn session_lease(
    pool: &PgPool,
    scope: TenantScope,
    id: Uuid,
) -> sqlx::Result<Option<(Option<Uuid>, Option<DateTime<Utc>>, i64)>> {
    let mut tx = scoped_tx(pool, scope).await?;
    let row: Option<(Option<Uuid>, Option<DateTime<Utc>>, i64)> = sqlx::query_as(
        "select orchestrator_owner_id, orchestrator_lease_until, orchestrator_epoch
         from sessions where id = $1 and tenant_id = $2",
    )
    .bind(id)
    .bind(scope.tenant_id())
    .fetch_optional(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(row)
}

/// How many queued runs are ahead of one — the per-run answer to "why is my run
/// not running yet" (design 2026-08-23 §13). `0` = next up.
///
/// TENANT-SCOPED ON PURPOSE, and the choice is worth stating because the number
/// is therefore NOT the run's position in the deployment-wide FIFO the
/// dispatcher actually walks. A deployment-wide position would need a bypass
/// and would leak another tenant's load through an ordinary run API — a caller
/// could watch the number move and infer a competitor's traffic. Within one
/// tenant it is exact; across tenants it is a lower bound, which is the honest
/// thing to show a user who may not be able to see the rest of the deployment.
///
/// Anchored on `created_at` (the dispatcher's own ordering key), not
/// `queued_at`, so the answer matches the order runs will actually be admitted
/// in — a capacity-bounced run keeps its place rather than going to the back.
pub async fn queued_position(
    pool: &PgPool,
    scope: TenantScope,
    created_at: DateTime<Utc>,
) -> sqlx::Result<i64> {
    let mut tx = scoped_tx(pool, scope).await?;
    let (n,): (i64,) = sqlx::query_as(
        "select count(*) from sessions
          where tenant_id = $1 and status = 'queued' and created_at < $2",
    )
    .bind(scope.tenant_id())
    .bind(created_at)
    .fetch_one(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(n)
}

/// Gate a capacity-bounced run behind a not-before instant and RELEASE its
/// driver lease (run admission, design 2026-08-23 §7.4).
///
/// Tenant-scoped, NOT a bypass: the caller is the orchestrator driving one
/// known run, so it already holds a verified scope.
///
/// Two properties are deliberate:
///
/// * **The lease columns are cleared, the epoch is NOT bumped here.** Clearing
///   the lease is what returns the row to the claim predicate; the next
///   claimant is then a different owner, so the CLAIM's own
///   `owner is distinct from` rule bumps the epoch. Bumping it here as well
///   would fence the bounced driver twice for one handover and break the
///   "epoch moves only on owner CHANGE" rule the whole fencing scheme rests on.
/// * **`dispatch_after` is set AFTER the re-park transition, never with it.**
///   A crash in between leaves a queued row with a live lease: it simply
///   re-enters the claim pool when that lease expires, without a backoff gate.
///   Bounded and harmless — the alternative (gate first, transition second)
///   would gate a row that never re-parked.
pub async fn set_dispatch_backoff(
    pool: &PgPool,
    scope: TenantScope,
    id: Uuid,
    not_before_secs: i64,
) -> sqlx::Result<()> {
    let mut tx = scoped_tx(pool, scope).await?;
    sqlx::query(
        "update sessions set
            dispatch_after           = now() + make_interval(secs => $3),
            orchestrator_owner_id    = null,
            orchestrator_lease_until = null,
            updated_at               = now()
          where id = $1 and tenant_id = $2",
    )
    .bind(id)
    .bind(scope.tenant_id())
    .bind(not_before_secs.max(0) as f64)
    .execute(&mut *tx)
    .await?;
    tx.commit().await
}

/// Attach the sandbox handle — REFUSED (returns false) unless the session is
/// still in an ACTIVE (pre-wind-down) state AND no finalization intent
/// exists: the intent is the single source of truth for ownership, and it
/// commits BEFORE the wind-down transition — a status-only fence would let a
/// launch attach a live sandbox inside that gap. The caller must terminate
/// the sandbox on refusal.
///
/// Deliberately a lock-then-check-then-update TRANSACTION, not one UPDATE:
/// a single statement's `not exists` subquery keeps the command snapshot
/// even after blocking on `begin_finalization`'s session row lock (Postgres
/// re-checks only the target tuple on unblock), so it could attach past a
/// just-committed intent. Taking the same row lock first and reading the
/// intent in a SECOND statement gets a fresh snapshot that must see it.
pub async fn set_sandbox_handle(
    pool: &PgPool,
    scope: TenantScope,
    id: Uuid,
    handle: &Value,
) -> sqlx::Result<bool> {
    use fluidbox_core::state::SessionStatus;
    let mut tx = scoped_tx(pool, scope).await?;
    let locked: Option<(String,)> =
        sqlx::query_as("select status from sessions where id = $1 and tenant_id = $2 for update")
            .bind(id)
            .bind(scope.tenant_id())
            .fetch_optional(&mut *tx)
            .await?;
    let Some((status,)) = locked else {
        return Ok(false);
    };
    let active = SessionStatus::parse(&status).is_some_and(|s| s.accepts_work());
    if !active {
        return Ok(false);
    }
    // EXISTS-scoped through the owning session so the intent probe stays inside
    // this tenant (belt-and-braces: the row above is already locked and
    // tenant-checked; `session_finalizations` has no tenant column of its own).
    let (intent_exists,): (bool,) = sqlx::query_as(
        "select exists(
             select 1 from session_finalizations f
             where f.session_id = $1
               and exists (select 1 from sessions s
                           where s.id = f.session_id and s.tenant_id = $2))",
    )
    .bind(id)
    .bind(scope.tenant_id())
    .fetch_one(&mut *tx)
    .await?;
    if intent_exists {
        return Ok(false);
    }
    sqlx::query(
        "update sessions set sandbox_handle = $2, updated_at = now()
         where id = $1 and tenant_id = $3",
    )
    .bind(id)
    .bind(handle)
    .bind(scope.tenant_id())
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(true)
}

/// Adopt a DISCOVERED sandbox handle into a session atomically: only while no
/// handle is stored AND the session is still in an active (pre-wind-down)
/// status. The predicate is in the UPDATE itself, so the reconciler racing
/// `run()`'s own `set_sandbox_handle`, a concurrent cancel, or a terminal
/// transition can never overwrite a real handle or resurrect a closed
/// session. Returns whether the adoption landed.
pub async fn adopt_sandbox_handle(
    pool: &PgPool,
    scope: TenantScope,
    id: Uuid,
    handle: &Value,
) -> sqlx::Result<bool> {
    let mut tx = scoped_tx(pool, scope).await?;
    let res = sqlx::query(
        "update sessions set sandbox_handle = $2, updated_at = now()
         where id = $1 and tenant_id = $3 and sandbox_handle is null
           and status in ('created','provisioning','initializing','running','awaiting_approval')",
    )
    .bind(id)
    .bind(handle)
    .bind(scope.tenant_id())
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(res.rows_affected() > 0)
}

pub async fn set_base_commit(
    pool: &PgPool,
    scope: TenantScope,
    id: Uuid,
    commit: &str,
) -> sqlx::Result<()> {
    let mut tx = scoped_tx(pool, scope).await?;
    sqlx::query(
        "update sessions set base_commit = $2, updated_at = now()
         where id = $1 and tenant_id = $3",
    )
    .bind(id)
    .bind(commit)
    .bind(scope.tenant_id())
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(())
}

pub async fn set_result_summary(
    pool: &PgPool,
    scope: TenantScope,
    id: Uuid,
    summary: &str,
) -> sqlx::Result<()> {
    let mut tx = scoped_tx(pool, scope).await?;
    sqlx::query(
        "update sessions set result_summary = $2, updated_at = now()
         where id = $1 and tenant_id = $3",
    )
    .bind(id)
    .bind(summary)
    .bind(scope.tenant_id())
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(())
}

pub async fn heartbeat(pool: &PgPool, scope: TenantScope, id: Uuid) -> sqlx::Result<()> {
    let mut tx = scoped_tx(pool, scope).await?;
    sqlx::query(
        "update sessions set last_heartbeat_at = now(), updated_at = now()
         where id = $1 and tenant_id = $2",
    )
    .bind(id)
    .bind(scope.tenant_id())
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(())
}
