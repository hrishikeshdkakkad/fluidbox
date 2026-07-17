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
use crate::{ApprovalRow, SessionRow};
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
