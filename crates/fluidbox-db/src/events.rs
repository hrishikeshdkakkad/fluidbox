//! The append-only event ledger.

use crate::event_log;
use crate::scope::{scoped_tx, TenantScope};
use chrono::{DateTime, Utc};
use fluidbox_core::event::{EventEnvelope, Redacted};
use serde_json::Value;
use sqlx::{PgPool, Row};
use uuid::Uuid;

#[derive(Debug, Clone, sqlx::FromRow, serde::Serialize)]
pub struct EventRow {
    pub event_id: Uuid,
    pub session_id: Uuid,
    pub seq: i64,
    pub actor: String,
    pub r#type: String,
    pub payload: Value,
    pub occurred_at: DateTime<Utc>,
}

// ─── Events (append-only; Redacted enforced at the type level) ────────────

pub async fn append_event(
    pool: &PgPool,
    scope: TenantScope,
    event: Redacted<EventEnvelope>,
) -> sqlx::Result<i64> {
    let mut tx = scoped_tx(pool, scope).await?;
    let seq = append_event_in_tx(&mut tx, scope, &event).await?;
    commit_and_mirror_events(
        tx,
        scope,
        std::slice::from_ref(&event),
        std::slice::from_ref(&seq),
    )
    .await?;
    Ok(seq)
}

/// Commit a transaction and only then mirror the canonical events it made
/// durable. Keeping the ordering in one helper prevents both phantom log
/// records (an append that later rolls back) and forgotten transactional append
/// paths (approval decisions append without calling the server's ledger helper).
pub(crate) async fn commit_and_mirror_events(
    tx: sqlx::Transaction<'_, sqlx::Postgres>,
    scope: TenantScope,
    events: &[Redacted<EventEnvelope>],
    seqs: &[i64],
) -> sqlx::Result<()> {
    assert_eq!(
        events.len(),
        seqs.len(),
        "every appended event must retain its committed sequence"
    );
    tx.commit().await?;
    for (event, seq) in events.iter().zip(seqs) {
        event_log::log_committed_event(scope.tenant_id(), event.get(), *seq);
    }
    Ok(())
}

/// `append_event` on an EXISTING transaction — the in-tx emission primitive the
/// approval decision transactions ride (Phase E, #33; Gap 13, plan E12), so the
/// canonical ledger event commits atomically with the decision CAS that produced
/// it and a loser of that CAS emits nothing.
///
/// The caller MUST already have set the tenant GUC on this connection
/// (`scoped_tx`) or the audited bypass (`worker_tx`): the plpgsql
/// `append_event(...)` is SECURITY INVOKER, so its `update sessions` +
/// `insert events` run under the caller's policies.
///
/// Gate: the `where exists(...)` guards the target list, so the side-effecting
/// function is NOT invoked on a scope miss (no seq bump, no NOTIFY) — zero rows →
/// `RowNotFound`.
pub(crate) async fn append_event_in_tx(
    tx: &mut sqlx::PgConnection,
    scope: TenantScope,
    event: &Redacted<EventEnvelope>,
) -> sqlx::Result<i64> {
    let env = event.get();
    let payload = serde_json::to_value(&env.body).unwrap_or(Value::Null);
    let type_name = env.body.type_name();
    let row = sqlx::query(
        "select append_event($1, $2, $3, $4, $5, $6) as seq
         where exists (select 1 from sessions s where s.id = $1 and s.tenant_id = $7)",
    )
    .bind(env.session_id)
    .bind(env.event_id)
    .bind(env.actor.as_str())
    .bind(&type_name)
    .bind(&payload)
    .bind(env.occurred_at)
    .bind(scope.tenant_id())
    .fetch_optional(&mut *tx)
    .await?;
    match row {
        Some(r) => Ok(r.get::<i64, _>("seq")),
        None => Err(sqlx::Error::RowNotFound),
    }
}

pub async fn events_after(
    pool: &PgPool,
    scope: TenantScope,
    session: Uuid,
    after_seq: i64,
    limit: i64,
) -> sqlx::Result<Vec<EventRow>> {
    let mut tx = scoped_tx(pool, scope).await?;

    let __rls_out = sqlx::query_as(
        "select event_id, session_id, seq, actor, type, payload, occurred_at
         from events
         where session_id = $1 and seq > $2
           and exists (select 1 from sessions s where s.id = $1 and s.tenant_id = $4)
         order by seq limit $3",
    )
    .bind(session)
    .bind(after_seq)
    .bind(limit)
    .bind(scope.tenant_id())
    .fetch_all(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(__rls_out)
}
