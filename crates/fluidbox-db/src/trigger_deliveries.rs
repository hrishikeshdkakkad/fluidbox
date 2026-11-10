//! Webhook delivery and dispatch dedup — the two unique levels behind event fan-out.

use crate::scope::{scoped_tx, TenantScope};
use chrono::{DateTime, Utc};
use serde_json::Value;
use sqlx::PgPool;
use uuid::Uuid;

// ─── Event deliveries & dispatches (design §6.4) ──────────────────────────

#[derive(Debug, Clone, sqlx::FromRow, serde::Serialize)]
pub struct TriggerDeliveryRow {
    pub id: Uuid,
    pub connection_id: Uuid,
    pub external_event_id: String,
    pub event_type: String,
    pub payload: Value,
    pub payload_digest: String,
    pub occurred_at: Option<DateTime<Utc>>,
    pub received_at: DateTime<Utc>,
}

#[derive(Debug, Clone, sqlx::FromRow, serde::Serialize)]
pub struct TriggerDispatchRow {
    pub id: Uuid,
    pub delivery_id: Uuid,
    pub subscription_id: Uuid,
    pub session_id: Option<Uuid>,
    pub status: String,
    pub skip_reason: Option<String>,
    pub created_at: DateTime<Utc>,
}

/// Level-1 dedup: store the delivery once; a retry returns the stored row
/// with `fresh = false` and the caller re-walks dispatch (which is itself
/// idempotent) — so a retry can only ever HEAL a partial fan-out.
#[allow(clippy::too_many_arguments)]
pub async fn insert_trigger_delivery(
    pool: &PgPool,
    scope: TenantScope,
    connection: Uuid,
    external_event_id: &str,
    event_type: &str,
    payload: &Value,
    payload_digest: &str,
    occurred_at: Option<DateTime<Utc>>,
) -> sqlx::Result<(TriggerDeliveryRow, bool)> {
    let mut tx = scoped_tx(pool, scope).await?;
    let inserted: Option<TriggerDeliveryRow> = sqlx::query_as(
        "insert into trigger_deliveries
           (id, connection_id, external_event_id, event_type, payload, payload_digest, occurred_at)
         select $1,$2,$3,$4,$5,$6,$7
         where exists (select 1 from integration_connections c where c.id = $2 and c.tenant_id = $8)
         on conflict (connection_id, external_event_id) do nothing
         returning *",
    )
    .bind(Uuid::now_v7())
    .bind(connection)
    .bind(external_event_id)
    .bind(event_type)
    .bind(payload)
    .bind(payload_digest)
    .bind(occurred_at)
    .bind(scope.tenant_id())
    .fetch_optional(&mut *tx)
    .await?;
    if let Some(row) = inserted {
        tx.commit().await?;
        return Ok((row, true));
    }
    let existing = sqlx::query_as(
        "select * from trigger_deliveries where connection_id = $1 and external_event_id = $2
           and exists (select 1 from integration_connections c where c.id = $1 and c.tenant_id = $3)",
    )
    .bind(connection)
    .bind(external_event_id)
    .bind(scope.tenant_id())
    .fetch_one(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok((existing, false))
}

/// Level-2 dedup: claim the (delivery, subscription) slot. `None` means the
/// slot already produced its outcome (a bound run, a recorded skip/error, or
/// a fresh in-flight creation) — the caller fires nothing. Like
/// `claim_invocation`, an unbound `created` claim older than 60s is
/// stealable (crashed creator); skipped/errored rows are terminal.
pub async fn claim_trigger_dispatch(
    pool: &PgPool,
    scope: TenantScope,
    delivery: Uuid,
    subscription: Uuid,
) -> sqlx::Result<Option<TriggerDispatchRow>> {
    // Both the subscription AND the delivery's connection must sit in this
    // tenant (the delivery→connection→tenant join is the same proof
    // `list_delivery_dispatches` uses). A miss → zero rows → None, the existing
    // no-claim shape.
    let mut tx = scoped_tx(pool, scope).await?;
    let inserted: Option<TriggerDispatchRow> = sqlx::query_as(
        "insert into trigger_dispatches (id, delivery_id, subscription_id)
         select $1,$2,$3
         where exists (select 1 from trigger_subscriptions sub
                       where sub.id = $3 and sub.tenant_id = $4)
           and exists (select 1 from trigger_deliveries d
                       join integration_connections c on c.id = d.connection_id
                       where d.id = $2 and c.tenant_id = $4)
         on conflict (delivery_id, subscription_id) do nothing
         returning *",
    )
    .bind(Uuid::now_v7())
    .bind(delivery)
    .bind(subscription)
    .bind(scope.tenant_id())
    .fetch_optional(&mut *tx)
    .await?;
    if inserted.is_some() {
        tx.commit().await?;
        return Ok(inserted);
    }
    let __rls_out = sqlx::query_as(
        "update trigger_dispatches
            set created_at = now()
          where delivery_id = $1 and subscription_id = $2
            and session_id is null and status = 'created'
            and created_at < now() - interval '60 seconds'
            and exists (select 1 from trigger_subscriptions sub
                        where sub.id = $2 and sub.tenant_id = $3)
            and exists (select 1 from trigger_deliveries d
                        join integration_connections c on c.id = d.connection_id
                        where d.id = $1 and c.tenant_id = $3)
          returning *",
    )
    .bind(delivery)
    .bind(subscription)
    .bind(scope.tenant_id())
    .fetch_optional(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(__rls_out)
}

/// Terminal bookkeeping for a claimed-but-not-run dispatch (skipped |
/// error). Guarded on session_id so a bound run can never be relabelled.
pub async fn mark_dispatch_outcome(
    pool: &PgPool,
    scope: TenantScope,
    dispatch: Uuid,
    status: &str,
    skip_reason: Option<&str>,
) -> sqlx::Result<()> {
    let mut tx = scoped_tx(pool, scope).await?;
    sqlx::query(
        "update trigger_dispatches set status = $2, skip_reason = $3
         where id = $1 and session_id is null
           and exists (select 1 from trigger_subscriptions sub
                       where sub.id = trigger_dispatches.subscription_id and sub.tenant_id = $4)",
    )
    .bind(dispatch)
    .bind(status)
    .bind(skip_reason)
    .bind(scope.tenant_id())
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(())
}

pub async fn list_delivery_dispatches(
    pool: &PgPool,
    scope: TenantScope,
    delivery: Uuid,
) -> sqlx::Result<Vec<TriggerDispatchRow>> {
    let mut tx = scoped_tx(pool, scope).await?;

    let __rls_out = sqlx::query_as(
        "select * from trigger_dispatches where delivery_id = $1
           and exists (select 1 from trigger_deliveries d
                       join integration_connections c on c.id = d.connection_id
                       where d.id = $1 and c.tenant_id = $2)
         order by created_at",
    )
    .bind(delivery)
    .bind(scope.tenant_id())
    .fetch_all(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(__rls_out)
}

pub async fn list_connection_deliveries(
    pool: &PgPool,
    scope: TenantScope,
    connection: Uuid,
    limit: i64,
) -> sqlx::Result<Vec<TriggerDeliveryRow>> {
    let mut tx = scoped_tx(pool, scope).await?;

    let __rls_out = sqlx::query_as(
        "select * from trigger_deliveries where connection_id = $1
           and exists (select 1 from integration_connections c where c.id = $1 and c.tenant_id = $3)
         order by received_at desc limit $2",
    )
    .bind(connection)
    .bind(limit)
    .bind(scope.tenant_id())
    .fetch_all(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(__rls_out)
}
