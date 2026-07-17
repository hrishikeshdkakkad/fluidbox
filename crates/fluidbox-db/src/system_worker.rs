//! System-worker repositories: the narrowly named, deliberately tenant-less
//! scans and lookups the parent design permits (`docs/plans/2026-07-14-
//! multi-user-mcp-control-plane-design.md`, "Database isolation": *"Generic
//! UUID-only methods are forbidden OUTSIDE narrowly named system-worker
//! repositories"*). These serve cross-tenant background workers — the
//! heartbeat watchdog, budget sweeper, approval-expiry sweep, the
//! restart-recoverable finalize driver, the managed-sandbox reconciler, and
//! the delivery worker — which act on ids/status across ALL tenants by
//! construction.
//!
//! Every row they return carries `tenant_id`; the invariant is that a caller
//! derives a [`TenantScope`](crate::TenantScope) from that fetched row before
//! touching any tenant-scoped repository. Nothing here decides authorization
//! — they are the trusted entry point that resolves which tenant a bare id
//! belongs to, never a bypass of the scoped surface.

use crate::approval_cols;
use crate::{
    ApprovalRow, GithubAppRegistrationRow, IntegrationConnectionRow, ResultDeliveryRow,
    ScheduleRow, SessionRow, TriggerSubscriptionRow,
};
use crate::{CONNECTION_COLS, GH_REG_COLS, SUBSCRIPTION_COLS};
use sqlx::PgPool;
use uuid::Uuid;

/// Load a session by id with NO tenant predicate — the cross-tenant loader for
/// workers that hold only a bare session id sourced from a provider list
/// (`ExecutionProvider::list_managed`) or a global scan (a spawned run task, a
/// delivery row, a finalization intent). The returned row carries `tenant_id`,
/// from which the caller builds the `TenantScope` for every subsequent scoped
/// call. Request handlers must use the scoped [`get_session`](crate::get_session).
pub async fn get_session(pool: &PgPool, id: Uuid) -> sqlx::Result<Option<SessionRow>> {
    sqlx::query_as("select * from sessions where id = $1")
        .bind(id)
        .fetch_optional(pool)
        .await
}

/// Load a connection by id with NO tenant predicate — the cross-tenant loader
/// for the UNAUTHENTICATED webhook ingress path (`POST /v1/ingress/...`), which
/// receives a bare connection id in the URL and no principal: the webhook
/// signature (verified against the connection's sealed secret) IS the auth, and
/// the connection's own `tenant_id` becomes the operative scope for the rest of
/// the delivery spine. Request handlers must use the scoped
/// [`get_connection`](crate::get_connection). Selects the same explicit column
/// list (never the sealed credential).
pub async fn get_connection(
    pool: &PgPool,
    id: Uuid,
) -> sqlx::Result<Option<IntegrationConnectionRow>> {
    sqlx::query_as(sqlx::AssertSqlSafe(format!(
        "select {CONNECTION_COLS} from integration_connections where id = $1"
    )))
    .bind(id)
    .fetch_optional(pool)
    .await
}

/// Load a trigger subscription by id with NO tenant predicate — the
/// cross-tenant loader for the scheduler, which holds only a bare
/// subscription id sourced from the global `due_schedules` scan. The returned
/// row carries `tenant_id`, from which the scheduler builds the `TenantScope`
/// for every subsequent scoped call (claim_invocation, mark_invocation_skipped,
/// create_run, advance_schedule). Request handlers must use the scoped
/// [`get_trigger_subscription`](crate::get_trigger_subscription).
pub async fn get_trigger_subscription(
    pool: &PgPool,
    id: Uuid,
) -> sqlx::Result<Option<TriggerSubscriptionRow>> {
    sqlx::query_as(sqlx::AssertSqlSafe(format!(
        "select {SUBSCRIPTION_COLS} from trigger_subscriptions where id = $1"
    )))
    .bind(id)
    .fetch_optional(pool)
    .await
}

/// Load a GitHub App registration by id with NO tenant predicate — the
/// cross-tenant loader for the UNAUTHENTICATED app-level webhook ingress
/// (`POST /v1/ingress/github/app/{registration_id}`), which receives a bare
/// registration id in the URL and no principal: the HMAC against the
/// registration's own sealed webhook secret IS the auth, and the
/// registration's `tenant_id` becomes the operative scope for the rest of the
/// delivery spine (exactly parallel to [`get_connection`] on the per-connection
/// ingress). Request handlers must use the scoped
/// [`get_github_app_registration`](crate::get_github_app_registration).
pub async fn get_github_app_registration(
    pool: &PgPool,
    id: Uuid,
) -> sqlx::Result<Option<GithubAppRegistrationRow>> {
    sqlx::query_as(sqlx::AssertSqlSafe(format!(
        "select {GH_REG_COLS} from github_app_registrations where id = $1"
    )))
    .bind(id)
    .fetch_optional(pool)
    .await
}

pub async fn sessions_in_status(pool: &PgPool, statuses: &[&str]) -> sqlx::Result<Vec<SessionRow>> {
    let list: Vec<String> = statuses.iter().map(|s| s.to_string()).collect();
    sqlx::query_as("select * from sessions where status = any($1)")
        .bind(&list)
        .fetch_all(pool)
        .await
}

/// Sessions stuck before launch. The orchestrator moves created →
/// provisioning → initializing in seconds (initializing: minutes at worst
/// for a big repo copy), so a stale row means the control plane died
/// mid-launch and nothing owns the session anymore.
///
/// Age is measured from `created_at` — a timestamp NOTHING refreshes. It used
/// to be `updated_at`, which every runner heartbeat bumps: a crash between
/// runner start and `set_sandbox_handle` left a heartbeating `initializing`
/// session this sweep could never age out (M5).
pub async fn stale_nonstarted_sessions(
    pool: &PgPool,
    max_age_mins: i32,
) -> sqlx::Result<Vec<SessionRow>> {
    sqlx::query_as(
        "select * from sessions
         where status = any($1) and created_at < now() - make_interval(mins => $2)",
    )
    .bind(vec![
        "created".to_string(),
        "provisioning".to_string(),
        "initializing".to_string(),
    ])
    .bind(max_age_mins)
    .fetch_all(pool)
    .await
}

/// Every persisted finalization intent, oldest first — the restart-recovery
/// worklist. Status-blind BY DESIGN: an intent whose session is still ACTIVE
/// is the crash-between-persist-and-transition window (the wind-down state
/// never landed), and an intent whose session is already TERMINAL is cleanup
/// still owed (reap, workspace/archive removal, delivery reconciliation).
/// Both must be re-driven; the intent row is deleted only once nothing is
/// owed, so this list self-drains.
pub async fn pending_finalizations(pool: &PgPool) -> sqlx::Result<Vec<Uuid>> {
    let rows: Vec<(Uuid,)> =
        sqlx::query_as("select session_id from session_finalizations order by created_at asc")
            .fetch_all(pool)
            .await?;
    Ok(rows.into_iter().map(|(id,)| id).collect())
}

pub async fn pending_approvals(pool: &PgPool) -> sqlx::Result<Vec<ApprovalRow>> {
    sqlx::query_as(concat!(
        "select ",
        approval_cols!(),
        " from approvals where status = 'pending' order by requested_at"
    ))
    .fetch_all(pool)
    .await
}

pub async fn expire_stale_approvals(pool: &PgPool) -> sqlx::Result<Vec<ApprovalRow>> {
    sqlx::query_as(concat!(
        "update approvals set status = 'expired', decided_at = now(), decided_by = 'timeout'
         where status = 'pending' and expires_at < now()
         returning ",
        approval_cols!()
    ))
    .fetch_all(pool)
    .await
}

/// Due work for the (single, sequential) scheduler worker — a cross-tenant
/// global scan, like the other system-worker queries. No row locking: there
/// is one scheduler task per server and firings are awaited one at a time. A
/// disabled subscription's schedule is not due and does NOT advance:
/// re-enabling turns the gap into a missed-run case, exactly like an outage.
/// Each row carries its subscription; the caller resolves the owning tenant
/// (via `get_trigger_subscription`) before firing through `create_run`.
pub async fn due_schedules(pool: &PgPool, limit: i64) -> sqlx::Result<Vec<ScheduleRow>> {
    sqlx::query_as(
        "select sc.* from schedules sc
         join trigger_subscriptions sub on sub.id = sc.subscription_id
         where sc.next_fire_at is not null and sc.next_fire_at <= now() and sub.enabled
         order by sc.next_fire_at limit $1",
    )
    .bind(limit)
    .fetch_all(pool)
    .await
}

/// Due work for the (single, sequential) delivery worker — a cross-tenant
/// global scan. No row locking: there is one worker task per server and
/// attempts are awaited one at a time, so a row can never be attempted twice
/// concurrently. Delivery is at-least-once by design — receivers dedup on the
/// delivery id. Each row carries its session; the caller derives the owning
/// tenant from it before touching any scoped repository.
pub async fn due_result_deliveries(
    pool: &PgPool,
    limit: i64,
) -> sqlx::Result<Vec<ResultDeliveryRow>> {
    sqlx::query_as(
        "select * from result_deliveries
         where status = 'pending' and next_attempt_at <= now()
         order by next_attempt_at limit $1",
    )
    .bind(limit)
    .fetch_all(pool)
    .await
}
