//! The connector catalog: global reference rows plus tenant-scoped custom entries.

use crate::scope::{scoped_tx, TenantScope};
use chrono::{DateTime, Utc};
use serde_json::Value;
use sqlx::PgPool;
use uuid::Uuid;

// ─── Connector catalog ────────────────────────────────────────────────────

/// One catalog entry — GLOBAL (tenant-less) reference data, a superset of
/// the MCP registry's server.json. UNTRUSTED everywhere it is consumed:
/// tool_hints are policy-default seeds for display, never enforcement.
#[derive(Debug, Clone, sqlx::FromRow, serde::Serialize)]
pub struct ConnectorCatalogRow {
    pub id: Uuid,
    pub slug: String,
    pub name: String,
    pub icon: Option<String>,
    pub description: Option<String>,
    pub categories: Value,
    pub tier: String,
    pub url: Option<String>,
    pub transport: String,
    pub auth_mode: String,
    pub auth_hints: Value,
    pub scopes: Value,
    pub egress: Value,
    pub tool_hints: Value,
    pub sandbox_launch: Option<Value>,
    /// {source, source_ref?, upstream_id?, imported_at?}. Curated seed rows
    /// carry {"source":"fluidbox"} and are never overwritten by an import
    /// (plan D4/D6). Imported reference rows carry an import source
    /// ("mcp-registry" | "open-connector") + pinned snapshot/commit so a future
    /// re-import can diff by (source, upstream_id).
    pub provenance: Value,
    /// NULL = GLOBAL reference row (curated `fluidbox` seeds + registry
    /// imports, visible to every tenant); Some = a tenant-owned custom (BYO)
    /// entry, visible only to that tenant and shadowing a same-slug global row
    /// (design :262-266).
    pub tenant_id: Option<Uuid>,
    /// Soft-disable: an unattributable custom row (migration 0013 could not
    /// place it under a single tenant) is disabled, never inherited by every
    /// tenant. Disabled rows are excluded from `list_catalog`/`get_catalog_by_slug`.
    pub disabled_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Active catalog visible to a tenant: global-active ∪ tenant-active, with a
/// tenant custom row SHADOWING a same-slug global row (design :262-266).
pub async fn list_catalog(
    pool: &PgPool,
    scope: TenantScope,
) -> sqlx::Result<Vec<ConnectorCatalogRow>> {
    let mut tx = scoped_tx(pool, scope).await?;

    let __rls_out = sqlx::query_as(
        "select * from connector_catalog c
         where c.disabled_at is null
           and (c.tenant_id = $1
                or (c.tenant_id is null
                    and not exists (select 1 from connector_catalog t
                                    where t.tenant_id = $1 and t.slug = c.slug
                                      and t.disabled_at is null)))
         order by case tier when 'verified' then 0 when 'community' then 1 else 2 end, name",
    )
    .bind(scope.tenant_id())
    .fetch_all(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(__rls_out)
}

/// Resolve one slug for a tenant: the tenant's custom row first, else the
/// global row; disabled rows excluded (design :262-266).
pub async fn get_catalog_by_slug(
    pool: &PgPool,
    scope: TenantScope,
    slug: &str,
) -> sqlx::Result<Option<ConnectorCatalogRow>> {
    let mut tx = scoped_tx(pool, scope).await?;

    let __rls_out = sqlx::query_as(
        "select * from connector_catalog
         where slug = $1 and disabled_at is null and (tenant_id = $2 or tenant_id is null)
         order by (tenant_id is not null) desc
         limit 1",
    )
    .bind(slug)
    .bind(scope.tenant_id())
    .fetch_optional(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(__rls_out)
}

/// API-added entries are always tier `custom` — verified/community are
/// curation judgements the API cannot self-award — and land tenant-scoped.
/// Returns None (→ 409 at the server) when the slug collides with a GLOBAL row;
/// a same-tenant duplicate is refused by the `connector_catalog_slug_tenant`
/// unique index (surfaced as an Err).
#[allow(clippy::too_many_arguments)]
pub async fn create_catalog_entry(
    pool: &PgPool,
    scope: TenantScope,
    slug: &str,
    name: &str,
    icon: Option<&str>,
    description: Option<&str>,
    categories: &Value,
    url: Option<&str>,
    transport: &str,
    auth_mode: &str,
    auth_hints: &Value,
    scopes: &Value,
    egress: &Value,
    tool_hints: &Value,
    sandbox_launch: Option<&Value>,
) -> sqlx::Result<Option<ConnectorCatalogRow>> {
    let mut tx = scoped_tx(pool, scope).await?;

    // tier AND provenance are forced 'custom': verified/community are curation
    // judgements the API cannot self-award, and a 'custom' provenance keeps a
    // user's BYO entry distinguishable from both the fluidbox seed and an
    // import (the generated import upsert only ever refreshes rows whose
    // provenance.source is an import source — 'mcp-registry' or 'open-connector'
    // — so it can never clobber this custom row; see the importer). The
    // `not exists (global)` guard fails closed on a global-slug collision — a
    // tenant can never mask a curated slug with a divergent definition.
    let __rls_out = sqlx::query_as(
        "insert into connector_catalog
           (id, tenant_id, slug, name, icon, description, categories, tier, url, transport,
            auth_mode, auth_hints, scopes, egress, tool_hints, sandbox_launch,
            provenance)
         select $1,$2,$3,$4,$5,$6,$7,'custom',$8,$9,$10,$11,$12,$13,$14,$15,
                 '{\"source\":\"custom\"}'
         where not exists (select 1 from connector_catalog g
                           where g.slug = $3 and g.tenant_id is null)
         returning *",
    )
    .bind(Uuid::now_v7())
    .bind(scope.tenant_id())
    .bind(slug)
    .bind(name)
    .bind(icon)
    .bind(description)
    .bind(categories)
    .bind(url)
    .bind(transport)
    .bind(auth_mode)
    .bind(auth_hints)
    .bind(scopes)
    .bind(egress)
    .bind(tool_hints)
    .bind(sandbox_launch)
    .fetch_optional(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(__rls_out)
}

/// Delete a tenant's custom catalog entry by slug (tenant rows only — a global
/// row is never touched). Used to roll back a just-created custom (BYO) entry
/// when its one-shot connect fails — custom entries are untrusted reference
/// data with no dependents until a bundle references them, so a hard delete is
/// safe. Returns the number of rows removed.
pub async fn delete_catalog_entry(
    pool: &PgPool,
    scope: TenantScope,
    slug: &str,
) -> sqlx::Result<u64> {
    let mut tx = scoped_tx(pool, scope).await?;
    let r = sqlx::query("delete from connector_catalog where slug = $1 and tenant_id = $2")
        .bind(slug)
        .bind(scope.tenant_id())
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(r.rows_affected())
}
