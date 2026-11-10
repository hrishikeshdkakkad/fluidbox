//! The durable finalization intent.

use crate::scope::{scoped_tx, TenantScope};
use chrono::{DateTime, Utc};
use serde_json::Value;
use sqlx::PgPool;
use uuid::Uuid;

// ─── Durable finalization intent (K8s design 2026-07-15, migration 0011) ──

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct FinalizationRow {
    pub session_id: Uuid,
    pub outcome: String,
    pub summary: Option<String>,
    pub reason: Option<String>,
    pub needs_quiesce: bool,
    pub quiesce_deadline: Option<DateTime<Utc>>,
    pub claimed_at: Option<DateTime<Utc>>,
    pub attempts: i32,
    pub created_at: DateTime<Utc>,
}

/// The outcome of persisting a finalization intent.
#[derive(Debug)]
pub enum BeginFinalization {
    /// The intent is durably persisted (by this call or a previous one).
    /// `row` is the AUTHORITATIVE intent — a loser of the insert race
    /// receives the winner's row and must derive every wind-down decision
    /// (target state, quiesce, deadline) from it, never from its own
    /// arguments. `session_status` is the status observed under the lock.
    Persisted {
        row: FinalizationRow,
        created: bool,
        session_status: String,
    },
    /// The session is already terminal — no intent may be (re)created.
    AlreadyTerminal,
    /// The session does not exist.
    Missing,
}

/// Persist the intent to finalize a session (idempotent), in ONE transaction
/// that locks the session row: the terminal check, the quiesce computation,
/// and the insert all see the same snapshot, so a late caller can never
/// recreate an intent after terminalization, and `needs_quiesce`/deadline
/// always match the state they were derived from. Holding the session lock
/// also fences the conflict→select read: terminalization (and the intent
/// delete that follows it) updates the sessions row, so it cannot slip
/// between our conflict and our read of the winning row. The first writer
/// wins the outcome; a racing second caller receives the winner's row with
/// `created: false` and defers to it.
#[allow(clippy::too_many_arguments)]
pub async fn begin_finalization(
    pool: &PgPool,
    scope: TenantScope,
    session: Uuid,
    outcome: &str,
    summary: Option<&str>,
    reason: Option<&str>,
    want_quiesce: bool,
    quiesce_deadline_secs: i64,
) -> sqlx::Result<BeginFinalization> {
    use fluidbox_core::state::SessionStatus;
    let mut tx = scoped_tx(pool, scope).await?;
    let locked: Option<(String, Option<Value>)> = sqlx::query_as(
        "select status, sandbox_handle from sessions where id = $1 and tenant_id = $2 for update",
    )
    .bind(session)
    .bind(scope.tenant_id())
    .fetch_optional(&mut *tx)
    .await?;
    let Some((status, handle)) = locked else {
        return Ok(BeginFinalization::Missing);
    };
    if SessionStatus::parse(&status).is_some_and(|s| s.is_terminal()) {
        return Ok(BeginFinalization::AlreadyTerminal);
    }
    // Quiesce only makes sense while a runner is live to receive the
    // heartbeat signal — computed from the LOCKED snapshot, not the caller's
    // (possibly stale) read.
    let quiesce = want_quiesce
        && matches!(status.as_str(), "running" | "awaiting_approval")
        && handle.is_some();
    let deadline = quiesce.then(|| Utc::now() + chrono::Duration::seconds(quiesce_deadline_secs));
    let inserted: Option<FinalizationRow> = sqlx::query_as(
        "insert into session_finalizations
           (session_id, outcome, summary, reason, needs_quiesce, quiesce_deadline)
         values ($1,$2,$3,$4,$5,$6)
         on conflict (session_id) do nothing
         returning *",
    )
    .bind(session)
    .bind(outcome)
    .bind(summary)
    .bind(reason)
    .bind(quiesce)
    .bind(deadline)
    .fetch_optional(&mut *tx)
    .await?;
    let (row, created) = match inserted {
        Some(r) => (r, true),
        None => (
            sqlx::query_as("select * from session_finalizations where session_id = $1")
                .bind(session)
                .fetch_one(&mut *tx)
                .await?,
            false,
        ),
    };
    tx.commit().await?;
    Ok(BeginFinalization::Persisted {
        row,
        created,
        session_status: status,
    })
}

pub async fn get_finalization(
    pool: &PgPool,
    scope: TenantScope,
    session: Uuid,
) -> sqlx::Result<Option<FinalizationRow>> {
    let mut tx = scoped_tx(pool, scope).await?;

    let __rls_out = sqlx::query_as(
        "select * from session_finalizations
         where session_id = $1
           and exists (select 1 from sessions s where s.id = $1 and s.tenant_id = $2)",
    )
    .bind(session)
    .bind(scope.tenant_id())
    .fetch_optional(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(__rls_out)
}

/// Claim a finalization for driving: succeeds when the row is unclaimed OR its
/// claim went stale (the previous driver crashed). Bumps `attempts` and stamps
/// `claimed_at`. A concurrent driver that loses the CAS gets None and backs
/// off — the finalizing→terminal transition is the ultimate single-winner
/// gate regardless, so a double-claim can never double-finalize.
pub async fn claim_finalization(
    pool: &PgPool,
    scope: TenantScope,
    session: Uuid,
    stale_secs: i64,
) -> sqlx::Result<Option<FinalizationRow>> {
    let mut tx = scoped_tx(pool, scope).await?;

    let __rls_out = sqlx::query_as(
        "update session_finalizations
            set claimed_at = now(), attempts = attempts + 1
          where session_id = $1
            and (claimed_at is null or claimed_at < now() - make_interval(secs => $2))
            and exists (select 1 from sessions s where s.id = $1 and s.tenant_id = $3)
          returning *",
    )
    .bind(session)
    .bind(stale_secs as f64)
    .bind(scope.tenant_id())
    .fetch_optional(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(__rls_out)
}

/// Release a driver's claim early — for DELIBERATE deferrals (e.g. the
/// provisioning settle window), so the finalize worker retries at its own
/// cadence instead of waiting out the stale-claim threshold.
pub async fn release_finalization_claim(
    pool: &PgPool,
    scope: TenantScope,
    session: Uuid,
) -> sqlx::Result<()> {
    let mut tx = scoped_tx(pool, scope).await?;
    sqlx::query(
        "update session_finalizations set claimed_at = null
         where session_id = $1
           and exists (select 1 from sessions s where s.id = $1 and s.tenant_id = $2)",
    )
    .bind(session)
    .bind(scope.tenant_id())
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(())
}

pub async fn delete_finalization(
    pool: &PgPool,
    scope: TenantScope,
    session: Uuid,
) -> sqlx::Result<()> {
    let mut tx = scoped_tx(pool, scope).await?;
    sqlx::query(
        "delete from session_finalizations
         where session_id = $1
           and exists (select 1 from sessions s where s.id = $1 and s.tenant_id = $2)",
    )
    .bind(session)
    .bind(scope.tenant_id())
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(())
}
