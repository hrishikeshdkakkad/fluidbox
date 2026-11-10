//! Append-only tool-surface snapshots photographed from a connection.

use crate::scope::{scoped_tx, TenantScope};
use chrono::{DateTime, Utc};
use serde_json::Value;
use sqlx::PgPool;
use uuid::Uuid;

// ─── Connection tool snapshots ────────────────────────────────────────────

/// One append-only photograph of a brokered connection's `tools/list` (design
/// :298-318): versioned per (tenant, connection), carrying the tools + digest a
/// run freezes. Never carries a credential — only tool metadata.
#[derive(Debug, Clone, sqlx::FromRow, serde::Serialize)]
pub struct ConnectionToolSnapshotRow {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub connection_id: Uuid,
    pub snapshot_version: i32,
    pub authorization_generation: i32,
    pub protocol_version: String,
    pub tools_json: Value,
    pub tools_digest: String,
    pub discovered_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
}

/// Append a new snapshot (version = max+1 within (tenant, connection), exactly
/// like a bundle version). Executor-generic so it can run inside a caller's
/// transaction. The `exists` guard proves the connection is in scope AND still
/// at `authorization_generation` — a cross-tenant connection_id OR one whose
/// generation moved since discovery began (a concurrent reconnect) yields
/// RowNotFound, so a snapshot never lands stamped at a generation the connection
/// has already left (design :294-296, :306). The composite FK is the backstop.
pub async fn insert_connection_tool_snapshot<'e, E>(
    exec: E,
    scope: TenantScope,
    connection_id: Uuid,
    authorization_generation: i32,
    protocol_version: &str,
    tools_json: &Value,
    tools_digest: &str,
) -> sqlx::Result<ConnectionToolSnapshotRow>
where
    E: sqlx::PgExecutor<'e>,
{
    sqlx::query_as(
        "insert into connection_tool_snapshots
           (id, tenant_id, connection_id, snapshot_version, authorization_generation,
            protocol_version, tools_json, tools_digest)
         select $1, $2, $3,
           coalesce((select max(s.snapshot_version) from connection_tool_snapshots s
                     where s.tenant_id = $2 and s.connection_id = $3), 0) + 1,
           $4, $5, $6, $7
         where exists (select 1 from integration_connections c
                       where c.id = $3 and c.tenant_id = $2
                         and c.authorization_generation = $4)
         returning *",
    )
    .bind(Uuid::now_v7())
    .bind(scope.tenant_id())
    .bind(connection_id)
    .bind(authorization_generation)
    .bind(protocol_version)
    .bind(tools_json)
    .bind(tools_digest)
    .fetch_one(exec)
    .await
}

/// The newest snapshot for a connection, or None if it has never been
/// photographed.
pub async fn latest_connection_tool_snapshot(
    pool: &PgPool,
    scope: TenantScope,
    connection_id: Uuid,
) -> sqlx::Result<Option<ConnectionToolSnapshotRow>> {
    let mut tx = scoped_tx(pool, scope).await?;

    let __rls_out = sqlx::query_as(
        "select * from connection_tool_snapshots
         where tenant_id = $1 and connection_id = $2
         order by snapshot_version desc limit 1",
    )
    .bind(scope.tenant_id())
    .bind(connection_id)
    .fetch_optional(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(__rls_out)
}

/// Every snapshot for a connection, newest first.
pub async fn list_connection_tool_snapshots(
    pool: &PgPool,
    scope: TenantScope,
    connection_id: Uuid,
) -> sqlx::Result<Vec<ConnectionToolSnapshotRow>> {
    let mut tx = scoped_tx(pool, scope).await?;

    let __rls_out = sqlx::query_as(
        "select * from connection_tool_snapshots
         where tenant_id = $1 and connection_id = $2
         order by snapshot_version desc",
    )
    .bind(scope.tenant_id())
    .bind(connection_id)
    .fetch_all(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(__rls_out)
}

/// One specific snapshot version for a connection (the pin a run froze).
pub async fn get_connection_tool_snapshot(
    pool: &PgPool,
    scope: TenantScope,
    connection_id: Uuid,
    version: i32,
) -> sqlx::Result<Option<ConnectionToolSnapshotRow>> {
    let mut tx = scoped_tx(pool, scope).await?;

    let __rls_out = sqlx::query_as(
        "select * from connection_tool_snapshots
         where tenant_id = $1 and connection_id = $2 and snapshot_version = $3",
    )
    .bind(scope.tenant_id())
    .bind(connection_id)
    .bind(version)
    .fetch_optional(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(__rls_out)
}
