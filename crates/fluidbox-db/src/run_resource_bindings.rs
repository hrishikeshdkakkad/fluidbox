//! Per-run resource bindings, frozen at session creation.

use crate::scope::{scoped_tx, TenantScope};
use chrono::{DateTime, Utc};
use serde_json::Value;
use sqlx::PgPool;
use uuid::Uuid;

// ─── Run resource bindings ────────────────────────────────────────────────

/// One per-run resolved authority (design :391-463): what a run bound for a
/// requirement slot, frozen write-once. The tagged authority union is realized
/// as typed `connection_id`/`subscription_id` columns discriminated by
/// `authority_kind`; the CHECK constraints (migration 0013) enforce the shape.
#[derive(Debug, Clone, sqlx::FromRow, serde::Serialize)]
pub struct RunResourceBindingRow {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub session_id: Uuid,
    pub requirement_slot: String,
    pub slot_kind: String,
    pub authority_kind: String,
    pub connection_id: Option<Uuid>,
    pub subscription_id: Option<Uuid>,
    pub authority_generation: Option<i32>,
    pub connection_owner_type: Option<String>,
    pub connection_owner_user_id: Option<Uuid>,
    pub snapshot_version: Option<i32>,
    pub effective_tools_json: Option<Value>,
    pub effective_tools_digest: Option<String>,
    pub resource_scope: Value,
    pub resolved_by_principal_kind: String,
    pub resolved_by_principal_id: Option<String>,
    pub binding_mode: String,
    pub created_at: DateTime<Utc>,
}

/// A binding to insert — [`RunResourceBindingRow`] minus the columns the writer
/// stamps (tenant_id from the scope, session_id from the run, created_at). The
/// `id` is pre-minted by the resolver so the frozen RunSpec can reference it.
#[derive(Debug, Clone)]
pub struct NewRunResourceBinding {
    pub id: Uuid,
    pub requirement_slot: String,
    pub slot_kind: String,
    pub authority_kind: String,
    pub connection_id: Option<Uuid>,
    pub subscription_id: Option<Uuid>,
    pub authority_generation: Option<i32>,
    pub connection_owner_type: Option<String>,
    pub connection_owner_user_id: Option<Uuid>,
    pub snapshot_version: Option<i32>,
    pub effective_tools_json: Option<Value>,
    pub effective_tools_digest: Option<String>,
    pub resource_scope: Value,
    pub resolved_by_principal_kind: String,
    pub resolved_by_principal_id: Option<String>,
    pub binding_mode: String,
}

/// Write a run's resolved bindings (plain multi-insert; write-once — the
/// `unique (tenant_id, session_id, slot_kind, requirement_slot)` key rejects a
/// second write for the same slot). Takes a `&mut PgConnection` so it runs
/// inside `create_session`'s transaction. The composite `(tenant_id, session_id)`
/// FK refuses a binding for a missing / other-tenant session.
pub async fn insert_run_resource_bindings(
    tx: &mut sqlx::PgConnection,
    scope: TenantScope,
    session_id: Uuid,
    rows: &[NewRunResourceBinding],
) -> sqlx::Result<()> {
    for b in rows {
        sqlx::query(
            "insert into run_resource_bindings
               (id, tenant_id, session_id, requirement_slot, slot_kind, authority_kind,
                connection_id, subscription_id, authority_generation, connection_owner_type,
                connection_owner_user_id, snapshot_version, effective_tools_json,
                effective_tools_digest, resource_scope, resolved_by_principal_kind,
                resolved_by_principal_id, binding_mode)
             values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18)",
        )
        .bind(b.id)
        .bind(scope.tenant_id())
        .bind(session_id)
        .bind(&b.requirement_slot)
        .bind(&b.slot_kind)
        .bind(&b.authority_kind)
        .bind(b.connection_id)
        .bind(b.subscription_id)
        .bind(b.authority_generation)
        .bind(&b.connection_owner_type)
        .bind(b.connection_owner_user_id)
        .bind(b.snapshot_version)
        .bind(&b.effective_tools_json)
        .bind(&b.effective_tools_digest)
        .bind(&b.resource_scope)
        .bind(&b.resolved_by_principal_kind)
        .bind(&b.resolved_by_principal_id)
        .bind(&b.binding_mode)
        .execute(&mut *tx)
        .await?;
    }
    Ok(())
}

/// One binding by id, tenant-scoped.
pub async fn get_run_resource_binding(
    pool: &PgPool,
    scope: TenantScope,
    id: Uuid,
) -> sqlx::Result<Option<RunResourceBindingRow>> {
    let mut tx = scoped_tx(pool, scope).await?;

    let __rls_out =
        sqlx::query_as("select * from run_resource_bindings where id = $1 and tenant_id = $2")
            .bind(id)
            .bind(scope.tenant_id())
            .fetch_optional(&mut *tx)
            .await?;
    tx.commit().await?;
    Ok(__rls_out)
}

/// Every binding a run resolved, ordered by slot for stable display.
pub async fn session_resource_bindings(
    pool: &PgPool,
    scope: TenantScope,
    session_id: Uuid,
) -> sqlx::Result<Vec<RunResourceBindingRow>> {
    let mut tx = scoped_tx(pool, scope).await?;

    let __rls_out = sqlx::query_as(
        "select * from run_resource_bindings
         where session_id = $1 and tenant_id = $2
         order by slot_kind, requirement_slot",
    )
    .bind(session_id)
    .bind(scope.tenant_id())
    .fetch_all(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(__rls_out)
}

/// The one binding for a run's (slot_kind, requirement_slot) — the consumer's
/// lookup before a credentialed use.
pub async fn find_session_binding(
    pool: &PgPool,
    scope: TenantScope,
    session_id: Uuid,
    slot_kind: &str,
    slot: &str,
) -> sqlx::Result<Option<RunResourceBindingRow>> {
    let mut tx = scoped_tx(pool, scope).await?;

    let __rls_out = sqlx::query_as(
        "select * from run_resource_bindings
         where session_id = $1 and tenant_id = $2 and slot_kind = $3 and requirement_slot = $4",
    )
    .bind(session_id)
    .bind(scope.tenant_id())
    .bind(slot_kind)
    .bind(slot)
    .fetch_optional(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(__rls_out)
}
