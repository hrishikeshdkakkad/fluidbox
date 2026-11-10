//! Idempotent invocation claims and the per-subscription run listings.

use crate::scope::{scoped_tx, TenantScope};
use crate::sessions::SessionRow;
use chrono::{DateTime, Utc};
use sqlx::{PgPool, Row};
use uuid::Uuid;

// ─── Trigger invocations (Idempotency-Key) ────────────────────────────────

#[derive(Debug)]
pub enum InvocationClaim {
    /// We own this key — create the run, binding this claim atomically via
    /// create_session's bind_invocation param.
    Claimed { invocation_id: Uuid },
    /// This key already produced a run — return it (after digest check).
    Replay {
        session_id: Uuid,
        request_digest: String,
    },
    /// This key's firing was skipped (overlap | missed | error: …) — a
    /// terminal outcome; replays of the key return it forever.
    Skipped { reason: String },
    /// Another request holds the key mid-creation — caller should 409.
    InFlight,
}

/// Claim an idempotency key. Exactly one concurrent caller wins the insert;
/// a claim whose creation crashed (bound to no session) becomes re-claimable
/// after 60s so a dangling row can't wedge the key forever.
pub async fn claim_invocation(
    pool: &PgPool,
    scope: TenantScope,
    subscription: Uuid,
    idempotency_key: &str,
    request_digest: &str,
) -> sqlx::Result<InvocationClaim> {
    let mut tx = scoped_tx(pool, scope).await?;
    let inserted = sqlx::query(
        "insert into trigger_invocations (id, subscription_id, idempotency_key, request_digest)
         select $1, $2, $3, $4
         where exists (select 1 from trigger_subscriptions where id = $2 and tenant_id = $5)
         on conflict (subscription_id, idempotency_key) do nothing
         returning id",
    )
    .bind(Uuid::now_v7())
    .bind(subscription)
    .bind(idempotency_key)
    .bind(request_digest)
    .bind(scope.tenant_id())
    .fetch_optional(&mut *tx)
    .await?;
    if let Some(row) = inserted {
        let invocation_id: Uuid = row.get("id");
        tx.commit().await?;
        return Ok(InvocationClaim::Claimed { invocation_id });
    }
    let existing = sqlx::query(
        "select id, session_id, request_digest, skip_reason, created_at from trigger_invocations
         where subscription_id = $1 and idempotency_key = $2
           and exists (select 1 from trigger_subscriptions where id = $1 and tenant_id = $3)",
    )
    .bind(subscription)
    .bind(idempotency_key)
    .bind(scope.tenant_id())
    .fetch_one(&mut *tx)
    .await?;
    if let Some(session_id) = existing.get::<Option<Uuid>, _>("session_id") {
        let request_digest: String = existing.get("request_digest");
        tx.commit().await?;
        return Ok(InvocationClaim::Replay {
            session_id,
            request_digest,
        });
    }
    if let Some(reason) = existing.get::<Option<String>, _>("skip_reason") {
        tx.commit().await?;
        return Ok(InvocationClaim::Skipped { reason });
    }
    // Unbound claim: take it over only once it is stale (crashed creator).
    // Skipped rows are terminal — never stealable.
    let takeover = sqlx::query(
        "update trigger_invocations
            set created_at = now(), request_digest = $3
          where subscription_id = $1 and idempotency_key = $2
            and session_id is null and skip_reason is null
            and created_at < now() - interval '60 seconds'
            and exists (select 1 from trigger_subscriptions where id = $1 and tenant_id = $4)
          returning id",
    )
    .bind(subscription)
    .bind(idempotency_key)
    .bind(request_digest)
    .bind(scope.tenant_id())
    .fetch_optional(&mut *tx)
    .await?;
    let out = match takeover {
        Some(row) => InvocationClaim::Claimed {
            invocation_id: row.get("id"),
        },
        None => InvocationClaim::InFlight,
    };
    tx.commit().await?;
    Ok(out)
}

/// A skipped firing is the terminal state of its claim row: visibly
/// recorded, never re-claimable. Guarded on session_id so a bound run can
/// never be relabelled a skip.
pub async fn mark_invocation_skipped(
    pool: &PgPool,
    scope: TenantScope,
    invocation: Uuid,
    reason: &str,
) -> sqlx::Result<()> {
    let mut tx = scoped_tx(pool, scope).await?;
    sqlx::query(
        "update trigger_invocations set skip_reason = $2
         where id = $1 and session_id is null
           and exists (select 1 from trigger_subscriptions sub
                       where sub.id = trigger_invocations.subscription_id
                         and sub.tenant_id = $3)",
    )
    .bind(invocation)
    .bind(reason)
    .bind(scope.tenant_id())
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(())
}

#[derive(Debug, Clone, sqlx::FromRow, serde::Serialize)]
pub struct TriggerInvocationRow {
    pub id: Uuid,
    pub subscription_id: Uuid,
    pub idempotency_key: String,
    pub session_id: Option<Uuid>,
    pub skip_reason: Option<String>,
    pub created_at: DateTime<Utc>,
}

pub async fn list_subscription_invocations(
    pool: &PgPool,
    scope: TenantScope,
    subscription: Uuid,
    limit: i64,
) -> sqlx::Result<Vec<TriggerInvocationRow>> {
    let mut tx = scoped_tx(pool, scope).await?;

    let __rls_out = sqlx::query_as(
        "select id, subscription_id, idempotency_key, session_id, skip_reason, created_at
         from trigger_invocations where subscription_id = $1
           and exists (select 1 from trigger_subscriptions where id = $1 and tenant_id = $3)
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

/// Non-terminal runs of a subscription — the concurrency-policy input.
pub async fn active_subscription_sessions(
    pool: &PgPool,
    scope: TenantScope,
    subscription: Uuid,
) -> sqlx::Result<Vec<SessionRow>> {
    let mut tx = scoped_tx(pool, scope).await?;

    let __rls_out = sqlx::query_as(
        "select s.* from sessions s
         join trigger_invocations i on i.session_id = s.id
         where i.subscription_id = $1 and s.tenant_id = $2
           and s.status not in ('completed','failed','cancelled','budget_exceeded')
         order by s.created_at",
    )
    .bind(subscription)
    .bind(scope.tenant_id())
    .fetch_all(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(__rls_out)
}

/// Free a claim whose run creation failed, so an immediate retry can re-try.
pub async fn release_invocation(
    pool: &PgPool,
    scope: TenantScope,
    invocation: Uuid,
) -> sqlx::Result<()> {
    let mut tx = scoped_tx(pool, scope).await?;
    sqlx::query(
        "delete from trigger_invocations where id = $1 and session_id is null
           and exists (select 1 from trigger_subscriptions sub
                       where sub.id = trigger_invocations.subscription_id
                         and sub.tenant_id = $2)",
    )
    .bind(invocation)
    .bind(scope.tenant_id())
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(())
}

pub async fn list_subscription_sessions(
    pool: &PgPool,
    scope: TenantScope,
    subscription: Uuid,
    limit: i64,
) -> sqlx::Result<Vec<SessionRow>> {
    let mut tx = scoped_tx(pool, scope).await?;

    let __rls_out = sqlx::query_as(
        "select s.* from sessions s
         join trigger_invocations i on i.session_id = s.id
         where i.subscription_id = $1 and s.tenant_id = $3
         order by s.created_at desc limit $2",
    )
    .bind(subscription)
    .bind(limit)
    .bind(scope.tenant_id())
    .fetch_all(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(__rls_out)
}

/// Scopes the trigger-token polling endpoint to runs this subscription made.
pub async fn subscription_owns_session(
    pool: &PgPool,
    scope: TenantScope,
    subscription: Uuid,
    session: Uuid,
) -> sqlx::Result<bool> {
    let mut tx = scoped_tx(pool, scope).await?;
    let row = sqlx::query(
        "select exists(
           select 1 from trigger_invocations ti
           join trigger_subscriptions sub on sub.id = ti.subscription_id
           where ti.subscription_id = $1 and ti.session_id = $2 and sub.tenant_id = $3
         ) as owned",
    )
    .bind(subscription)
    .bind(session)
    .bind(scope.tenant_id())
    .fetch_one(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(row.get::<bool, _>("owned"))
}
