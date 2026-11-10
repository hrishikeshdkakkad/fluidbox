//! Schedules — the clock on a subscription.

use crate::scope::{scoped_tx, TenantScope};
use chrono::{DateTime, Utc};
use sqlx::PgPool;
use uuid::Uuid;

// ─── Schedules (Phase 3: the clock on a subscription) ────────────────────

#[derive(Debug, Clone, sqlx::FromRow, serde::Serialize)]
pub struct ScheduleRow {
    pub id: Uuid,
    pub subscription_id: Uuid,
    pub cron: String,
    pub timezone: String,
    pub next_fire_at: Option<DateTime<Utc>>,
    pub missed_run_policy: String,
    pub last_fired_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

pub async fn create_schedule(
    pool: &PgPool,
    scope: TenantScope,
    subscription: Uuid,
    cron: &str,
    timezone: &str,
    next_fire_at: DateTime<Utc>,
    missed_run_policy: &str,
) -> sqlx::Result<ScheduleRow> {
    let mut tx = scoped_tx(pool, scope).await?;
    let __rls_out = create_schedule_tx(
        &mut tx,
        scope.tenant_id(),
        subscription,
        cron,
        timezone,
        next_fire_at,
        missed_run_policy,
    )
    .await?;
    tx.commit().await?;
    Ok(__rls_out)
}

/// [`create_schedule`] inside a caller-owned transaction (the recipes deploy
/// engine's atomic stamp).
pub async fn create_schedule_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    tenant_id: Uuid,
    subscription: Uuid,
    cron: &str,
    timezone: &str,
    next_fire_at: DateTime<Utc>,
    missed_run_policy: &str,
) -> sqlx::Result<ScheduleRow> {
    let __rls_out = sqlx::query_as(
        "insert into schedules (id, subscription_id, cron, timezone, next_fire_at, missed_run_policy)
         select $1, $2, $3, $4, $5, $6
         where exists (select 1 from trigger_subscriptions where id = $2 and tenant_id = $7)
         returning *",
    )
    .bind(Uuid::now_v7())
    .bind(subscription)
    .bind(cron)
    .bind(timezone)
    .bind(next_fire_at)
    .bind(missed_run_policy)
    .bind(tenant_id)
    .fetch_one(&mut **tx)
    .await?;
    Ok(__rls_out)
}

pub async fn schedule_for_subscription(
    pool: &PgPool,
    scope: TenantScope,
    subscription: Uuid,
) -> sqlx::Result<Option<ScheduleRow>> {
    let mut tx = scoped_tx(pool, scope).await?;

    let __rls_out = sqlx::query_as(
        "select * from schedules where subscription_id = $1
           and exists (select 1 from trigger_subscriptions sub
                       where sub.id = $1 and sub.tenant_id = $2)",
    )
    .bind(subscription)
    .bind(scope.tenant_id())
    .fetch_optional(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(__rls_out)
}

pub async fn schedules_for_tenant(
    pool: &PgPool,
    scope: TenantScope,
) -> sqlx::Result<Vec<ScheduleRow>> {
    let mut tx = scoped_tx(pool, scope).await?;

    let __rls_out = sqlx::query_as(
        "select sc.* from schedules sc
         join trigger_subscriptions sub on sub.id = sc.subscription_id
         where sub.tenant_id = $1",
    )
    .bind(scope.tenant_id())
    .fetch_all(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(__rls_out)
}

/// CAS advance: only moves the clock if next_fire_at is still the fire time
/// this worker processed — two workers can never double-advance past an
/// unhandled fire time.
pub async fn advance_schedule(
    pool: &PgPool,
    scope: TenantScope,
    id: Uuid,
    from: DateTime<Utc>,
    to: Option<DateTime<Utc>>,
    fired_at: Option<DateTime<Utc>>,
) -> sqlx::Result<bool> {
    let mut tx = scoped_tx(pool, scope).await?;
    let res = sqlx::query(
        "update schedules set
            next_fire_at = $2,
            last_fired_at = coalesce($3, last_fired_at),
            updated_at = now()
         where id = $1 and next_fire_at = $4
           and exists (select 1 from trigger_subscriptions sub
                       where sub.id = schedules.subscription_id and sub.tenant_id = $5)",
    )
    .bind(id)
    .bind(to)
    .bind(fired_at)
    .bind(from)
    .bind(scope.tenant_id())
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(res.rows_affected() > 0)
}
