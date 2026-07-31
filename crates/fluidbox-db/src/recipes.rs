//! Recipe catalog + instances store (migration 0027; design
//! docs/plans/2026-07-31-enterprise-recipes-design.md).
//!
//! Tenancy contract: every function here takes a [`TenantScope`] and rides
//! [`crate::scoped_tx`]. The catalog tables (`recipes`, `recipe_versions`)
//! hold deployment-GLOBAL rows (`tenant_id NULL`) any scope may read — the
//! connector_catalog split — while custom rows are tenant-owned; instances and
//! object links are always tenant-owned. Nothing in this module reaches a
//! bypass: global catalog rows are written only by migrations.
//!
//! The `_tx` functions exist for the deploy engine's ATOMIC stamp: one
//! transaction creates policy + agents + subscriptions (+schedule +tokens) +
//! the instance + its object links, so a mid-stamp failure leaves nothing
//! behind (design §3.5 — the Helm-atomic school, never Terraform partial
//! state).

use crate::{scoped_tx, TenantScope};
use chrono::{DateTime, Utc};
use serde_json::Value;
use sqlx::PgPool;
use uuid::Uuid;

#[derive(Debug, Clone, sqlx::FromRow, serde::Serialize)]
pub struct RecipeRow {
    pub id: Uuid,
    /// NULL = deployment-global curated row.
    pub tenant_id: Option<Uuid>,
    pub slug: String,
    pub name: String,
    pub tagline: String,
    pub description: String,
    pub category: String,
    pub tags: Value,
    pub tier: String,
    pub icon: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub disabled_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, sqlx::FromRow, serde::Serialize)]
pub struct RecipeVersionRow {
    pub id: Uuid,
    pub tenant_id: Option<Uuid>,
    pub recipe_id: Uuid,
    pub version: i32,
    pub definition: Value,
    pub params_schema: Value,
    pub changelog: Option<String>,
    pub author: String,
    pub created_at: DateTime<Utc>,
}

/// Catalog listing row: identity + the latest version number (the list never
/// ships definition blobs; the detail endpoint does).
#[derive(Debug, Clone, sqlx::FromRow, serde::Serialize)]
pub struct RecipeListRow {
    pub id: Uuid,
    pub tenant_id: Option<Uuid>,
    pub slug: String,
    pub name: String,
    pub tagline: String,
    pub description: String,
    pub category: String,
    pub tags: Value,
    pub tier: String,
    pub icon: String,
    pub latest_version: i32,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, sqlx::FromRow, serde::Serialize)]
pub struct RecipeInstanceRow {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub recipe_id: Uuid,
    pub recipe_slug: String,
    pub recipe_version: i32,
    pub name: String,
    pub params: Value,
    pub params_digest: String,
    pub status: String,
    pub created_by_user_id: Option<Uuid>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub deleted_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, sqlx::FromRow, serde::Serialize)]
pub struct RecipeInstanceObjectRow {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub instance_id: Uuid,
    pub kind: String,
    pub object_id: Uuid,
    pub slot: String,
    pub created_at: DateTime<Utc>,
}

/// An instance object hydrated with its target's display name (agents /
/// subscriptions / policies) or the session's status — one query instead of N
/// per-kind lookups. A dangling link (target hard-deleted out of band) still
/// lists, with NULLs.
#[derive(Debug, Clone, sqlx::FromRow, serde::Serialize)]
pub struct InstanceObjectDetail {
    pub kind: String,
    pub object_id: Uuid,
    pub slot: String,
    pub name: Option<String>,
    pub session_status: Option<String>,
    pub subscription_enabled: Option<bool>,
    pub created_at: DateTime<Utc>,
}

// ─── Catalog reads ────────────────────────────────────────────────────────

/// List the catalog visible to this scope: global rows + the tenant's custom
/// rows, a tenant row SHADOWING a same-slug global (the connector_catalog
/// rule), disabled rows excluded, joined with the latest version number.
pub async fn list_recipes(pool: &PgPool, scope: TenantScope) -> sqlx::Result<Vec<RecipeListRow>> {
    let mut tx = scoped_tx(pool, scope).await?;
    let out = sqlx::query_as(
        "select r.id, r.tenant_id, r.slug, r.name, r.tagline, r.description, r.category,
                r.tags, r.tier, r.icon,
                coalesce((select max(v.version) from recipe_versions v
                          where v.recipe_id = r.id), 0)::int as latest_version,
                r.created_at, r.updated_at
           from recipes r
          where r.disabled_at is null
            and (r.tenant_id = $1
                 or (r.tenant_id is null and not exists (
                       select 1 from recipes t
                        where t.tenant_id = $1 and t.slug = r.slug
                          and t.disabled_at is null)))
          order by r.tier = 'official' desc, r.category, r.name",
    )
    .bind(scope.tenant_id())
    .fetch_all(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(out)
}

/// Resolve a slug to its recipe (tenant custom row shadows a global) plus the
/// LATEST version. None when unknown, disabled, or version-less (a bug state
/// for seeded rows; surfaced as not-found rather than a 500).
pub async fn get_recipe_by_slug(
    pool: &PgPool,
    scope: TenantScope,
    slug: &str,
) -> sqlx::Result<Option<(RecipeRow, RecipeVersionRow)>> {
    let mut tx = scoped_tx(pool, scope).await?;
    let recipe: Option<RecipeRow> = sqlx::query_as(
        "select * from recipes
          where slug = $1 and disabled_at is null
            and (tenant_id = $2 or tenant_id is null)
          order by (tenant_id is not null) desc
          limit 1",
    )
    .bind(slug)
    .bind(scope.tenant_id())
    .fetch_optional(&mut *tx)
    .await?;
    let out = match recipe {
        None => None,
        Some(r) => {
            let version: Option<RecipeVersionRow> = sqlx::query_as(
                "select * from recipe_versions where recipe_id = $1
                  order by version desc limit 1",
            )
            .bind(r.id)
            .fetch_optional(&mut *tx)
            .await?;
            version.map(|v| (r, v))
        }
    };
    tx.commit().await?;
    Ok(out)
}

pub async fn get_recipe_version(
    pool: &PgPool,
    scope: TenantScope,
    recipe_id: Uuid,
    version: i32,
) -> sqlx::Result<Option<RecipeVersionRow>> {
    let mut tx = scoped_tx(pool, scope).await?;
    let out = sqlx::query_as(
        "select v.* from recipe_versions v
          join recipes r on r.id = v.recipe_id
         where v.recipe_id = $1 and v.version = $2
           and (r.tenant_id = $3 or r.tenant_id is null)",
    )
    .bind(recipe_id)
    .bind(version)
    .bind(scope.tenant_id())
    .fetch_optional(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(out)
}

/// Version history (metadata only — no blobs) for a recipe's detail page.
#[derive(Debug, Clone, sqlx::FromRow, serde::Serialize)]
pub struct RecipeVersionMeta {
    pub version: i32,
    pub changelog: Option<String>,
    pub author: String,
    pub created_at: DateTime<Utc>,
}

pub async fn list_recipe_versions(
    pool: &PgPool,
    scope: TenantScope,
    recipe_id: Uuid,
) -> sqlx::Result<Vec<RecipeVersionMeta>> {
    let mut tx = scoped_tx(pool, scope).await?;
    let out = sqlx::query_as(
        "select v.version, v.changelog, v.author, v.created_at
           from recipe_versions v
           join recipes r on r.id = v.recipe_id
          where v.recipe_id = $1 and (r.tenant_id = $2 or r.tenant_id is null)
          order by v.version desc",
    )
    .bind(recipe_id)
    .bind(scope.tenant_id())
    .fetch_all(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(out)
}

// ─── Custom recipes (tenant-authored) ─────────────────────────────────────

/// Create a tenant custom recipe + its version 1 in one transaction. `None`
/// when the slug collides with a GLOBAL row (the API answers 409 — shadowing
/// is a read-time affordance, not a write-time one for NEW custom recipes:
/// silently shadowing an official recipe invites confusion); a same-tenant
/// duplicate bubbles as the 23505 unique violation.
#[allow(clippy::too_many_arguments)]
pub async fn create_custom_recipe(
    pool: &PgPool,
    scope: TenantScope,
    slug: &str,
    name: &str,
    tagline: &str,
    description: &str,
    category: &str,
    tags: &Value,
    icon: &str,
    definition: &Value,
    params_schema: &Value,
    changelog: Option<&str>,
) -> sqlx::Result<Option<(RecipeRow, RecipeVersionRow)>> {
    let mut tx = scoped_tx(pool, scope).await?;
    let recipe: Option<RecipeRow> = sqlx::query_as(
        "insert into recipes (id, tenant_id, slug, name, tagline, description, category,
                              tags, tier, icon)
         select $1, $2, $3, $4, $5, $6, $7, $8, 'custom', $9
          where not exists (select 1 from recipes g
                             where g.slug = $3 and g.tenant_id is null
                               and g.disabled_at is null)
         returning *",
    )
    .bind(Uuid::now_v7())
    .bind(scope.tenant_id())
    .bind(slug)
    .bind(name)
    .bind(tagline)
    .bind(description)
    .bind(category)
    .bind(tags)
    .bind(icon)
    .fetch_optional(&mut *tx)
    .await?;
    let Some(recipe) = recipe else {
        tx.rollback().await?;
        return Ok(None);
    };
    let version: RecipeVersionRow = sqlx::query_as(
        "insert into recipe_versions (id, tenant_id, recipe_id, version, definition,
                                      params_schema, changelog, author)
         values ($1, $2, $3, 1, $4, $5, $6, 'api')
         returning *",
    )
    .bind(Uuid::now_v7())
    .bind(scope.tenant_id())
    .bind(recipe.id)
    .bind(definition)
    .bind(params_schema)
    .bind(changelog)
    .fetch_one(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(Some((recipe, version)))
}

/// Append a version to a TENANT custom recipe (official rows version via
/// migrations only — a global recipe_id yields None → 404/403 upstream).
/// Locks the parent row so `head + 1` cannot race itself.
pub async fn append_custom_recipe_version(
    pool: &PgPool,
    scope: TenantScope,
    recipe_id: Uuid,
    definition: &Value,
    params_schema: &Value,
    changelog: Option<&str>,
) -> sqlx::Result<Option<RecipeVersionRow>> {
    let mut tx = scoped_tx(pool, scope).await?;
    let owned: Option<(Uuid,)> = sqlx::query_as(
        "select id from recipes where id = $1 and tenant_id = $2 for update",
    )
    .bind(recipe_id)
    .bind(scope.tenant_id())
    .fetch_optional(&mut *tx)
    .await?;
    if owned.is_none() {
        tx.rollback().await?;
        return Ok(None);
    }
    let row: RecipeVersionRow = sqlx::query_as(
        "insert into recipe_versions (id, tenant_id, recipe_id, version, definition,
                                      params_schema, changelog, author)
         values ($1, $2, $3,
                 coalesce((select max(version) from recipe_versions where recipe_id = $3), 0) + 1,
                 $4, $5, $6, 'api')
         returning *",
    )
    .bind(Uuid::now_v7())
    .bind(scope.tenant_id())
    .bind(recipe_id)
    .bind(definition)
    .bind(params_schema)
    .bind(changelog)
    .fetch_one(&mut *tx)
    .await?;
    sqlx::query("update recipes set updated_at = now() where id = $1 and tenant_id = $2")
        .bind(recipe_id)
        .bind(scope.tenant_id())
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(Some(row))
}

// ─── Instances ────────────────────────────────────────────────────────────

/// Insert the instance row inside the deploy transaction. A duplicate live
/// name bubbles as the 23505 unique violation (→ 409 upstream) and, because
/// the WHOLE stamp is one transaction, aborts every stamped object with it.
#[allow(clippy::too_many_arguments)]
pub async fn create_recipe_instance_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    tenant_id: Uuid,
    recipe_id: Uuid,
    recipe_slug: &str,
    recipe_version: i32,
    name: &str,
    params: &Value,
    params_digest: &str,
    created_by_user_id: Option<Uuid>,
) -> sqlx::Result<RecipeInstanceRow> {
    sqlx::query_as(
        "insert into recipe_instances
           (id, tenant_id, recipe_id, recipe_slug, recipe_version, name, params,
            params_digest, created_by_user_id)
         values ($1, $2, $3, $4, $5, $6, $7, $8, $9)
         returning *",
    )
    .bind(Uuid::now_v7())
    .bind(tenant_id)
    .bind(recipe_id)
    .bind(recipe_slug)
    .bind(recipe_version)
    .bind(name)
    .bind(params)
    .bind(params_digest)
    .bind(created_by_user_id)
    .fetch_one(&mut **tx)
    .await
}

pub async fn insert_instance_object_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    tenant_id: Uuid,
    instance_id: Uuid,
    kind: &str,
    object_id: Uuid,
    slot: &str,
) -> sqlx::Result<RecipeInstanceObjectRow> {
    sqlx::query_as(
        "insert into recipe_instance_objects (id, tenant_id, instance_id, kind, object_id, slot)
         values ($1, $2, $3, $4, $5, $6)
         returning *",
    )
    .bind(Uuid::now_v7())
    .bind(tenant_id)
    .bind(instance_id)
    .bind(kind)
    .bind(object_id)
    .bind(slot)
    .fetch_one(&mut **tx)
    .await
}

/// Link a post-commit run (first run / run-now) to its instance. Sessions are
/// recorded OUTSIDE the stamp transaction by construction — a first-run
/// failure reports on the instance, never unwinds the deploy.
pub async fn record_instance_session(
    pool: &PgPool,
    scope: TenantScope,
    instance_id: Uuid,
    session_id: Uuid,
    slot: &str,
) -> sqlx::Result<()> {
    let mut tx = scoped_tx(pool, scope).await?;
    insert_instance_object_tx(
        &mut tx,
        scope.tenant_id(),
        instance_id,
        "session",
        session_id,
        slot,
    )
    .await?;
    tx.commit().await?;
    Ok(())
}

/// Live (non-deleted) instances, newest first.
pub async fn list_recipe_instances(
    pool: &PgPool,
    scope: TenantScope,
) -> sqlx::Result<Vec<RecipeInstanceRow>> {
    let mut tx = scoped_tx(pool, scope).await?;
    let out = sqlx::query_as(
        "select * from recipe_instances
          where tenant_id = $1 and deleted_at is null
          order by created_at desc",
    )
    .bind(scope.tenant_id())
    .fetch_all(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(out)
}

pub async fn get_recipe_instance(
    pool: &PgPool,
    scope: TenantScope,
    id: Uuid,
) -> sqlx::Result<Option<RecipeInstanceRow>> {
    let mut tx = scoped_tx(pool, scope).await?;
    let out = sqlx::query_as("select * from recipe_instances where id = $1 and tenant_id = $2")
        .bind(id)
        .bind(scope.tenant_id())
        .fetch_optional(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(out)
}

pub async fn instance_objects(
    pool: &PgPool,
    scope: TenantScope,
    instance_id: Uuid,
) -> sqlx::Result<Vec<RecipeInstanceObjectRow>> {
    let mut tx = scoped_tx(pool, scope).await?;
    let out = sqlx::query_as(
        "select o.* from recipe_instance_objects o
          where o.instance_id = $1 and o.tenant_id = $2
          order by o.created_at",
    )
    .bind(instance_id)
    .bind(scope.tenant_id())
    .fetch_all(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(out)
}

/// Hydrated object list for the instance detail page (names + session
/// status + subscription enabled flags in one round trip).
pub async fn instance_objects_detailed(
    pool: &PgPool,
    scope: TenantScope,
    instance_id: Uuid,
) -> sqlx::Result<Vec<InstanceObjectDetail>> {
    let mut tx = scoped_tx(pool, scope).await?;
    let out = sqlx::query_as(
        "select o.kind, o.object_id, o.slot,
                coalesce(a.name, s.name, p.name) as name,
                se.status as session_status,
                s.enabled as subscription_enabled,
                o.created_at
           from recipe_instance_objects o
           left join agents a on o.kind = 'agent' and a.id = o.object_id
           left join trigger_subscriptions s on o.kind = 'subscription' and s.id = o.object_id
           left join policies p on o.kind = 'policy' and p.id = o.object_id
           left join sessions se on o.kind = 'session' and se.id = o.object_id
          where o.instance_id = $1 and o.tenant_id = $2
          order by o.created_at",
    )
    .bind(instance_id)
    .bind(scope.tenant_id())
    .fetch_all(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(out)
}

/// Flip an instance's status inside a caller-owned transaction (pause/resume/
/// delete flip the stamped subscriptions in the same tx). Delete stamps
/// `deleted_at`, freeing the live-name uniqueness slot.
pub async fn set_instance_status_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    tenant_id: Uuid,
    id: Uuid,
    status: &str,
) -> sqlx::Result<Option<RecipeInstanceRow>> {
    sqlx::query_as(
        "update recipe_instances
            set status = $3,
                deleted_at = case when $3 = 'deleted' then now() else deleted_at end,
                updated_at = now()
          where id = $1 and tenant_id = $2 and deleted_at is null
          returning *",
    )
    .bind(id)
    .bind(tenant_id)
    .bind(status)
    .fetch_optional(&mut **tx)
    .await
}

/// Record a successful upgrade: bump the provenance version + params inside
/// the upgrade transaction.
pub async fn bump_instance_version_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    tenant_id: Uuid,
    id: Uuid,
    recipe_version: i32,
    params: &Value,
    params_digest: &str,
) -> sqlx::Result<Option<RecipeInstanceRow>> {
    sqlx::query_as(
        "update recipe_instances
            set recipe_version = $3, params = $4, params_digest = $5, updated_at = now()
          where id = $1 and tenant_id = $2 and deleted_at is null
          returning *",
    )
    .bind(id)
    .bind(tenant_id)
    .bind(recipe_version)
    .bind(params)
    .bind(params_digest)
    .fetch_optional(&mut **tx)
    .await
}
