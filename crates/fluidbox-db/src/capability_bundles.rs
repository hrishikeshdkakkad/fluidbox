//! The sandbox capability-bundle registry.

use crate::scope::{scoped_tx, TenantScope};
use chrono::{DateTime, Utc};
use serde_json::Value;
use sqlx::PgPool;
use uuid::Uuid;

/// One version of a capability bundle (design §3.6): append-only like
/// agent revisions — publishing a change = a new (name, version) row. The
/// definition carries the photographed tool snapshots; definition_digest is
/// the supply-chain anchor frozen into RunSpecs.
#[derive(Debug, Clone, sqlx::FromRow, serde::Serialize)]
pub struct CapabilityBundleRow {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub name: String,
    pub version: i32,
    pub description: Option<String>,
    pub definition: Value,
    pub definition_digest: String,
    pub created_at: DateTime<Utc>,
}

// ─── Capability bundles (Phase 5: the registry) ───────────────────────────

/// Appends a new immutable bundle version (version = max+1 within the
/// name). Publishing a change is always an append — never an update — by
/// construction, exactly like agent revisions.
pub async fn create_capability_bundle(
    pool: &PgPool,
    scope: TenantScope,
    name: &str,
    description: Option<&str>,
    definition: &Value,
    definition_digest: &str,
) -> sqlx::Result<CapabilityBundleRow> {
    let mut tx = scoped_tx(pool, scope).await?;

    let __rls_out = sqlx::query_as(
        "insert into capability_bundles
           (id, tenant_id, name, version, description, definition, definition_digest)
         values ($1, $2, $3,
           coalesce((select max(version) from capability_bundles
                     where tenant_id = $2 and name = $3), 0) + 1,
           $4, $5, $6)
         returning *",
    )
    .bind(Uuid::now_v7())
    .bind(scope.tenant_id())
    .bind(name)
    .bind(description)
    .bind(definition)
    .bind(definition_digest)
    .fetch_one(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(__rls_out)
}

pub async fn list_capability_bundles(
    pool: &PgPool,
    scope: TenantScope,
) -> sqlx::Result<Vec<CapabilityBundleRow>> {
    let mut tx = scoped_tx(pool, scope).await?;

    let __rls_out = sqlx::query_as(
        "select * from capability_bundles where tenant_id = $1
         order by name, version desc",
    )
    .bind(scope.tenant_id())
    .fetch_all(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(__rls_out)
}

pub async fn get_capability_bundle(
    pool: &PgPool,
    scope: TenantScope,
    id: Uuid,
) -> sqlx::Result<Option<CapabilityBundleRow>> {
    let mut tx = scoped_tx(pool, scope).await?;

    let __rls_out =
        sqlx::query_as("select * from capability_bundles where id = $1 and tenant_id = $2")
            .bind(id)
            .bind(scope.tenant_id())
            .fetch_optional(&mut *tx)
            .await?;
    tx.commit().await?;
    Ok(__rls_out)
}

pub async fn latest_capability_bundle(
    pool: &PgPool,
    scope: TenantScope,
    name: &str,
) -> sqlx::Result<Option<CapabilityBundleRow>> {
    let mut tx = scoped_tx(pool, scope).await?;

    let __rls_out = sqlx::query_as(
        "select * from capability_bundles where tenant_id = $1 and name = $2
         order by version desc limit 1",
    )
    .bind(scope.tenant_id())
    .bind(name)
    .fetch_optional(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(__rls_out)
}

pub async fn get_capability_bundle_version(
    pool: &PgPool,
    scope: TenantScope,
    name: &str,
    version: i32,
) -> sqlx::Result<Option<CapabilityBundleRow>> {
    let mut tx = scoped_tx(pool, scope).await?;

    let __rls_out = sqlx::query_as(
        "select * from capability_bundles
         where tenant_id = $1 and name = $2 and version = $3",
    )
    .bind(scope.tenant_id())
    .bind(name)
    .bind(version)
    .fetch_optional(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(__rls_out)
}
