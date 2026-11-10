//! Outbound result deliveries and the stable identity of what they published.

use crate::scope::{scoped_tx, TenantScope};
use chrono::{DateTime, Utc};
use serde_json::Value;
use sqlx::PgPool;
use uuid::Uuid;

// ─── Result deliveries ────────────────────────────────────────────────────

#[derive(Debug, Clone, sqlx::FromRow, serde::Serialize)]
pub struct ResultDeliveryRow {
    pub id: Uuid,
    pub session_id: Uuid,
    pub subscription_id: Option<Uuid>,
    pub destination: Value,
    pub status: String,
    pub attempts: i32,
    pub next_attempt_at: DateTime<Utc>,
    pub last_error: Option<String>,
    pub payload_digest: Option<String>,
    pub delivered_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// True if a delivery row exists for this session AND destination — the
/// per-destination idempotency check both enqueue paths (the terminal
/// transition and the claim-serialized reconciler) run before inserting:
/// a crash after destination A but before destination B is healed by
/// enqueueing exactly B, never duplicating A, and "some rows exist" is
/// never mistaken for "all destinations enqueued".
pub async fn result_delivery_exists_for(
    pool: &PgPool,
    scope: TenantScope,
    session: Uuid,
    destination: &Value,
) -> sqlx::Result<bool> {
    let mut tx = scoped_tx(pool, scope).await?;
    let (exists,): (bool,) = sqlx::query_as(
        "select exists(select 1 from result_deliveries
           where session_id = $1 and destination = $2
             and exists (select 1 from sessions s where s.id = $1 and s.tenant_id = $3))",
    )
    .bind(session)
    .bind(destination)
    .bind(scope.tenant_id())
    .fetch_one(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(exists)
}

/// True if the session already has a `run.result` ledger event — the
/// reconciler's exactly-once guard (emit-if-missing under the finalize
/// claim, which serializes drivers).
pub async fn has_run_result_event(
    pool: &PgPool,
    scope: TenantScope,
    session: Uuid,
) -> sqlx::Result<bool> {
    let mut tx = scoped_tx(pool, scope).await?;
    let (exists,): (bool,) = sqlx::query_as(
        "select exists(select 1 from events where session_id = $1 and type = 'run.result'
           and exists (select 1 from sessions s where s.id = $1 and s.tenant_id = $2))",
    )
    .bind(session)
    .bind(scope.tenant_id())
    .fetch_one(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(exists)
}

pub async fn enqueue_result_delivery(
    pool: &PgPool,
    scope: TenantScope,
    session: Uuid,
    subscription: Option<Uuid>,
    destination: &Value,
) -> sqlx::Result<ResultDeliveryRow> {
    let mut tx = scoped_tx(pool, scope).await?;

    // The session must be in scope AND — when a subscription is named — it must
    // belong to the SAME tenant (a cross-tenant subscription is proven
    // impossible here, not just Rust-side). A miss → fetch_one RowNotFound, the
    // existing not-in-scope-session shape.
    let __rls_out = sqlx::query_as(
        "insert into result_deliveries (id, session_id, subscription_id, destination)
         select $1, $2, $3, $4
         where exists (select 1 from sessions s where s.id = $2 and s.tenant_id = $5)
           and ($3::uuid is null or exists (
                 select 1 from trigger_subscriptions sub where sub.id = $3 and sub.tenant_id = $5))
         returning *",
    )
    .bind(Uuid::now_v7())
    .bind(session)
    .bind(subscription)
    .bind(destination)
    .bind(scope.tenant_id())
    .fetch_one(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(__rls_out)
}

/// RE-STAMP this replica's claim on ONE delivery row, immediately before its
/// attempt (Phase E, #33; review I2). Returns true iff we still own it.
///
/// WHY THIS EXISTS. [`crate::system_worker::claim_due_deliveries`] stamps a whole BATCH
/// at once, but the worker then attempts the rows SEQUENTIALLY: the last row of a
/// batch of 10 can sit unattempted for nine attempts' worth of wall clock, so a
/// TTL measured from the batch is long expired by the time its turn comes. Two
/// failures follow from that, and both are user-visible:
///   * another replica steals the row and delivers it AGAIN (a second GitHub
///     comment, a second webhook POST) — the exact duplicate the claim exists to
///     prevent; and
///   * whichever replica finishes second loses [`mark_delivery_attempt`]'s owner
///     guard, so `attempts` and `next_attempt_at` DO NOT MOVE. The row is
///     immediately due again, and with every replica overrunning its claim the
///     cycle repeats forever: the backoff never advances, `max_attempts` is never
///     reached, and the external side effect repeats on every pass.
///
/// Re-stamping per row makes the TTL measure ONE attempt instead of a whole batch,
/// which is what lets the caller size it against a single worst-case attempt.
///
/// STRICTLY OWNER-GUARDED, never a steal: if another replica already took the row
/// (`claimed_by` moved), this matches zero rows and the caller SKIPS it without
/// performing the external side effect — the new owner does it exactly once. The
/// CAS is atomic against a concurrent claim scan: whoever takes the row lock first
/// wins, and the loser's predicate no longer holds.
pub async fn extend_delivery_claim(
    pool: &PgPool,
    scope: TenantScope,
    id: Uuid,
    owner: Uuid,
    ttl_secs: i64,
) -> sqlx::Result<bool> {
    let mut tx = scoped_tx(pool, scope).await?;
    let res = sqlx::query(
        "update result_deliveries
            set claimed_until = now() + make_interval(secs => $3),
                updated_at = now()
          where id = $1 and claimed_by = $2 and status = 'pending'
            and exists (select 1 from sessions s
                        where s.id = result_deliveries.session_id and s.tenant_id = $4)",
    )
    .bind(id)
    .bind(owner)
    .bind(ttl_secs.max(1) as f64)
    .bind(scope.tenant_id())
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(res.rows_affected() > 0)
}

/// Record one attempt. ok → delivered; failure → attempts+1 and either
/// rescheduled (`retry_in_secs`) or terminally 'failed' at `max_attempts`.
///
/// GUARDED on the caller still holding the row's claim (Phase E, #33; Gap 13).
/// `owner` is the replica id that
/// [`crate::system_worker::claim_due_deliveries`] stamped; a replica whose claim expired
/// and was stolen mid-attempt matches zero rows and gets `None`, so it can never
/// stomp the new owner's attempt counter or backoff. The claim is RELEASED here
/// (both columns nulled) so the next backoff window is open to any replica.
///
/// `None` IS A REAL FAILURE MODE, NOT A NO-OP (review I2): nothing was recorded,
/// so neither `attempts` nor `next_attempt_at` moved — the caller MUST log it
/// (see `deliveries::attempt`) and rely on the new owner to record the attempt it
/// is running. [`extend_delivery_claim`] makes this rare by re-stamping the claim
/// per attempt; it stays possible when an attempt outruns even that fresh TTL.
#[allow(clippy::too_many_arguments)]
pub async fn mark_delivery_attempt(
    pool: &PgPool,
    scope: TenantScope,
    id: Uuid,
    owner: Uuid,
    ok: bool,
    error: Option<&str>,
    payload_digest: Option<&str>,
    retry_in_secs: i64,
    max_attempts: i32,
) -> sqlx::Result<Option<ResultDeliveryRow>> {
    let mut tx = scoped_tx(pool, scope).await?;

    let __rls_out = sqlx::query_as(
        "update result_deliveries set
            attempts = attempts + 1,
            status = case when $2 then 'delivered'
                          when attempts + 1 >= $6 then 'failed'
                          else 'pending' end,
            delivered_at = case when $2 then now() else delivered_at end,
            last_error = $3,
            payload_digest = coalesce($4, payload_digest),
            next_attempt_at = now() + make_interval(secs => $5),
            claimed_by = null,
            claimed_until = null,
            updated_at = now()
         where id = $1 and claimed_by = $8
           and exists (select 1 from sessions s
                       where s.id = result_deliveries.session_id and s.tenant_id = $7)
         returning *",
    )
    .bind(id)
    .bind(ok)
    .bind(error)
    .bind(payload_digest)
    .bind(retry_in_secs as f64)
    .bind(max_attempts)
    .bind(scope.tenant_id())
    .bind(owner)
    .fetch_optional(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(__rls_out)
}

pub async fn list_session_deliveries(
    pool: &PgPool,
    scope: TenantScope,
    session: Uuid,
) -> sqlx::Result<Vec<ResultDeliveryRow>> {
    let mut tx = scoped_tx(pool, scope).await?;

    let __rls_out = sqlx::query_as(
        "select * from result_deliveries where session_id = $1
           and exists (select 1 from sessions s where s.id = $1 and s.tenant_id = $2)
         order by created_at",
    )
    .bind(session)
    .bind(scope.tenant_id())
    .fetch_all(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(__rls_out)
}

pub async fn list_subscription_deliveries(
    pool: &PgPool,
    scope: TenantScope,
    subscription: Uuid,
    limit: i64,
) -> sqlx::Result<Vec<ResultDeliveryRow>> {
    let mut tx = scoped_tx(pool, scope).await?;

    let __rls_out = sqlx::query_as(
        "select * from result_deliveries where subscription_id = $1
           and exists (select 1 from trigger_subscriptions sub
                       where sub.id = $1 and sub.tenant_id = $3)
         order by created_at desc limit $2",
    )
    .bind(subscription)
    .bind(limit)
    .bind(scope.tenant_id())
    .fetch_all(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(__rls_out)
}

// ─── External results (§17 #3: stable update-in-place identity) ───────────

#[derive(Debug, Clone, sqlx::FromRow, serde::Serialize)]
pub struct ExternalResultRow {
    pub id: Uuid,
    pub subscription_id: Uuid,
    pub kind: String,
    pub resource_key: String,
    pub external_id: String,
    pub external_url: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

pub async fn get_external_result(
    pool: &PgPool,
    scope: TenantScope,
    subscription: Uuid,
    kind: &str,
    resource_key: &str,
) -> sqlx::Result<Option<ExternalResultRow>> {
    let mut tx = scoped_tx(pool, scope).await?;

    let __rls_out = sqlx::query_as(
        "select * from external_results
         where subscription_id = $1 and kind = $2 and resource_key = $3
           and exists (select 1 from trigger_subscriptions sub
                       where sub.id = $1 and sub.tenant_id = $4)",
    )
    .bind(subscription)
    .bind(kind)
    .bind(resource_key)
    .bind(scope.tenant_id())
    .fetch_optional(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(__rls_out)
}

pub async fn upsert_external_result(
    pool: &PgPool,
    scope: TenantScope,
    subscription: Uuid,
    kind: &str,
    resource_key: &str,
    external_id: &str,
    external_url: Option<&str>,
) -> sqlx::Result<ExternalResultRow> {
    let mut tx = scoped_tx(pool, scope).await?;

    let __rls_out = sqlx::query_as(
        "insert into external_results
           (id, subscription_id, kind, resource_key, external_id, external_url)
         select $1,$2,$3,$4,$5,$6
         where exists (select 1 from trigger_subscriptions sub
                       where sub.id = $2 and sub.tenant_id = $7)
         on conflict (subscription_id, kind, resource_key)
           do update set external_id = excluded.external_id,
                         external_url = excluded.external_url,
                         updated_at = now()
         returning *",
    )
    .bind(Uuid::now_v7())
    .bind(subscription)
    .bind(kind)
    .bind(resource_key)
    .bind(external_id)
    .bind(external_url)
    .bind(scope.tenant_id())
    .fetch_one(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(__rls_out)
}
