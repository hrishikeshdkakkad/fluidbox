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
    let owned: Option<(Uuid,)> =
        sqlx::query_as("select id from recipes where id = $1 and tenant_id = $2 for update")
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

/// Sessions by explicit ids (the instance detail page's first-run /
/// run-now sessions, which belong to no subscription).
pub async fn sessions_by_ids(
    pool: &PgPool,
    scope: TenantScope,
    ids: &[Uuid],
) -> sqlx::Result<Vec<crate::SessionRow>> {
    if ids.is_empty() {
        return Ok(vec![]);
    }
    let mut tx = scoped_tx(pool, scope).await?;
    let out = sqlx::query_as(
        "select * from sessions where id = any($1) and tenant_id = $2
          order by created_at desc",
    )
    .bind(ids)
    .bind(scope.tenant_id())
    .fetch_all(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(out)
}

/// Upgrade-path subscription update: the recipe-mutable surface only (name,
/// task_template, overrides, concurrency). Kind/agent/connection/events/
/// publish/destinations are structurally immutable — the engine 422s before
/// reaching here.
#[allow(clippy::too_many_arguments)]
pub async fn update_subscription_recipe_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    tenant_id: Uuid,
    id: Uuid,
    name: &str,
    task_template: Option<&str>,
    allow_task_override: bool,
    allow_workspace_override: bool,
    concurrency_policy: &str,
) -> sqlx::Result<bool> {
    let res = sqlx::query(
        "update trigger_subscriptions
            set name = $2, task_template = $3, allow_task_override = $4,
                allow_workspace_override = $5, concurrency_policy = $6, updated_at = now()
          where id = $1 and tenant_id = $7",
    )
    .bind(id)
    .bind(name)
    .bind(task_template)
    .bind(allow_task_override)
    .bind(allow_workspace_override)
    .bind(concurrency_policy)
    .bind(tenant_id)
    .execute(&mut **tx)
    .await?;
    Ok(res.rows_affected() > 0)
}

/// Upgrade-path schedule cadence update. `next_fire_at` is Some only when the
/// cadence actually changed (the caller recomputed it); a cadence-neutral
/// update preserves the clock — the PATCH handler's rule.
pub async fn update_schedule_cadence_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    tenant_id: Uuid,
    subscription_id: Uuid,
    cron: &str,
    timezone: &str,
    missed_run_policy: &str,
    next_fire_at: Option<DateTime<Utc>>,
) -> sqlx::Result<bool> {
    let res = sqlx::query(
        "update schedules
            set cron = $2, timezone = $3, missed_run_policy = $4,
                next_fire_at = coalesce($5, next_fire_at), updated_at = now()
          where subscription_id = $1
            and exists (select 1 from trigger_subscriptions s
                         where s.id = $1 and s.tenant_id = $6)",
    )
    .bind(subscription_id)
    .bind(cron)
    .bind(timezone)
    .bind(missed_run_policy)
    .bind(next_fire_at)
    .bind(tenant_id)
    .execute(&mut **tx)
    .await?;
    Ok(res.rows_affected() > 0)
}

/// Record a successful upgrade: bump the provenance version + params inside
/// the upgrade transaction.
#[allow(clippy::too_many_arguments)]
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

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    async fn pool() -> Option<PgPool> {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("skipping: DATABASE_URL not set");
            return None;
        };
        Some(crate::test_connect(&url).await.expect("connect"))
    }

    async fn tenant(pool: &PgPool, tag: &str) -> TenantScope {
        let id = Uuid::now_v7();
        sqlx::query("insert into tenants (id, name, slug) values ($1, $2, $3)")
            .bind(id)
            .bind(format!("recipes-test-{tag}"))
            .bind(format!("recipes-test-{tag}-{id}"))
            .execute(pool)
            .await
            .expect("tenant fixture");
        TenantScope::assume(id)
    }

    async fn cleanup(pool: &PgPool, scope: TenantScope) {
        // Children-first; the fixture pool carries the session-level bypass.
        for sql in [
            "delete from recipe_instance_objects where tenant_id = $1",
            "delete from recipe_instances where tenant_id = $1",
            "delete from recipe_versions where tenant_id = $1",
            "delete from recipes where tenant_id = $1",
            "delete from tenants where id = $1",
        ] {
            sqlx::query(sql)
                .bind(scope.tenant_id())
                .execute(pool)
                .await
                .expect("cleanup");
        }
    }

    /// THE seed-drift test: every migration-seeded recipe must parse under the
    /// CURRENT fluidbox-core types, its params schema must pass the untrusted
    /// guard and yield renderable widgets, and every referenced parameter must
    /// be declared. A 0027 seed edit that drifts from the Rust contract fails
    /// here, against a real migrated database.
    #[tokio::test]
    async fn seeded_catalog_parses_and_is_renderable() {
        let Some(pool) = pool().await else { return };
        let scope = tenant(&pool, "seed").await;
        let listed = list_recipes(&pool, scope).await.expect("list");
        let official: Vec<_> = listed.iter().filter(|r| r.tier == "official").collect();
        assert!(
            official.len() >= 5,
            "expected the five seeded recipes, got {}",
            official.len()
        );
        for r in official {
            let (_, version) = get_recipe_by_slug(&pool, scope, &r.slug)
                .await
                .expect("get")
                .expect("seeded recipe has a version");
            let def = fluidbox_core::recipe::RecipeDefinition::parse(&version.definition)
                .unwrap_or_else(|e| panic!("{}: definition drifted: {e}", r.slug));
            fluidbox_core::schema_guard::guard_schema(&version.params_schema)
                .unwrap_or_else(|e| panic!("{}: schema guard: {e}", r.slug));
            let specs = fluidbox_core::recipe::param_specs(&version.params_schema)
                .unwrap_or_else(|e| panic!("{}: params not renderable: {e}", r.slug));
            let declared: std::collections::BTreeSet<&str> =
                specs.iter().map(|s| s.name.as_str()).collect();
            for referenced in fluidbox_core::recipe::referenced_params(&version.definition) {
                assert!(
                    declared.contains(referenced.as_str()),
                    "{}: references undeclared param '{referenced}'",
                    r.slug
                );
            }
            assert!(!def.agents.is_empty(), "{}: no agents", r.slug);
        }
        cleanup(&pool, scope).await;
    }

    #[tokio::test]
    async fn custom_recipes_shadow_and_isolate() {
        let Some(pool) = pool().await else { return };
        let (t1, t2) = (
            tenant(&pool, "shadow-a").await,
            tenant(&pool, "shadow-b").await,
        );
        let def = json!({
            "schema": 1,
            "agents": [{ "slot": "main", "name": "x", "harness": "claude-agent-sdk" }]
        });
        let schema = json!({ "type": "object", "additionalProperties": false, "properties": {} });
        // Official slug collision refused (returns None).
        let collided = create_custom_recipe(
            &pool,
            t1,
            "pr-review-panel",
            "shadow",
            "",
            "",
            "general",
            &json!([]),
            "custom",
            &def,
            &schema,
            None,
        )
        .await
        .expect("query ok");
        assert!(collided.is_none(), "global slug collision must refuse");
        // A fresh slug creates, lists for its tenant, and stays invisible to
        // the other tenant.
        let (recipe, v1) = create_custom_recipe(
            &pool,
            t1,
            "my-recipe",
            "Mine",
            "",
            "",
            "general",
            &json!([]),
            "custom",
            &def,
            &schema,
            None,
        )
        .await
        .expect("query ok")
        .expect("created");
        assert_eq!(v1.version, 1);
        assert!(list_recipes(&pool, t1)
            .await
            .unwrap()
            .iter()
            .any(|r| r.slug == "my-recipe"));
        assert!(!list_recipes(&pool, t2)
            .await
            .unwrap()
            .iter()
            .any(|r| r.slug == "my-recipe"));
        assert!(get_recipe_by_slug(&pool, t2, "my-recipe")
            .await
            .unwrap()
            .is_none());
        // Versions append monotonically; appending to a GLOBAL recipe refuses.
        let v2 = append_custom_recipe_version(&pool, t1, recipe.id, &def, &schema, Some("v2"))
            .await
            .expect("query ok")
            .expect("appended");
        assert_eq!(v2.version, 2);
        let (global, _) = get_recipe_by_slug(&pool, t1, "pr-review-panel")
            .await
            .unwrap()
            .unwrap();
        assert!(
            append_custom_recipe_version(&pool, t1, global.id, &def, &schema, None)
                .await
                .expect("query ok")
                .is_none()
        );
        cleanup(&pool, t1).await;
        cleanup(&pool, t2).await;
    }

    #[tokio::test]
    async fn instance_lifecycle_isolation_and_name_reuse() {
        let Some(pool) = pool().await else { return };
        let (t1, t2) = (tenant(&pool, "inst-a").await, tenant(&pool, "inst-b").await);
        let (recipe, version) = get_recipe_by_slug(&pool, t1, "codebase-brief")
            .await
            .unwrap()
            .unwrap();
        let mut tx = crate::scoped_tx(&pool, t1).await.unwrap();
        let inst = create_recipe_instance_tx(
            &mut tx,
            t1.tenant_id(),
            recipe.id,
            &recipe.slug,
            version.version,
            "brief one",
            &json!({}),
            "digest",
            None,
        )
        .await
        .unwrap();
        insert_instance_object_tx(
            &mut tx,
            t1.tenant_id(),
            inst.id,
            "agent",
            Uuid::now_v7(),
            "guide",
        )
        .await
        .unwrap();
        tx.commit().await.unwrap();
        // Tenant isolation both ways.
        assert!(get_recipe_instance(&pool, t1, inst.id)
            .await
            .unwrap()
            .is_some());
        assert!(get_recipe_instance(&pool, t2, inst.id)
            .await
            .unwrap()
            .is_none());
        assert_eq!(instance_objects(&pool, t1, inst.id).await.unwrap().len(), 1);
        assert!(instance_objects(&pool, t2, inst.id)
            .await
            .unwrap()
            .is_empty());
        // Duplicate live name refused; delete frees it.
        let mut tx = crate::scoped_tx(&pool, t1).await.unwrap();
        let dup = create_recipe_instance_tx(
            &mut tx,
            t1.tenant_id(),
            recipe.id,
            &recipe.slug,
            version.version,
            "brief one",
            &json!({}),
            "digest",
            None,
        )
        .await;
        assert!(matches!(&dup,
            Err(sqlx::Error::Database(e)) if e.is_unique_violation()));
        drop(dup);
        tx.rollback().await.unwrap();
        let mut tx = crate::scoped_tx(&pool, t1).await.unwrap();
        let gone = set_instance_status_tx(&mut tx, t1.tenant_id(), inst.id, "deleted")
            .await
            .unwrap()
            .expect("deleted");
        assert_eq!(gone.status, "deleted");
        tx.commit().await.unwrap();
        assert!(list_recipe_instances(&pool, t1).await.unwrap().is_empty());
        let mut tx = crate::scoped_tx(&pool, t1).await.unwrap();
        create_recipe_instance_tx(
            &mut tx,
            t1.tenant_id(),
            recipe.id,
            &recipe.slug,
            version.version,
            "brief one",
            &json!({}),
            "digest",
            None,
        )
        .await
        .expect("deleted instance frees its name");
        tx.rollback().await.unwrap();
        cleanup(&pool, t1).await;
        cleanup(&pool, t2).await;
    }

    /// The atomicity property the deploy engine leans on: a failure ANYWHERE
    /// in the stamp transaction leaves zero rows — instance, links, and any
    /// objects created earlier in the same tx all roll back together.
    #[tokio::test]
    async fn stamp_transaction_is_atomic() {
        let Some(pool) = pool().await else { return };
        let scope = tenant(&pool, "atomic").await;
        let (recipe, version) = get_recipe_by_slug(&pool, scope, "codebase-brief")
            .await
            .unwrap()
            .unwrap();
        let mut tx = crate::scoped_tx(&pool, scope).await.unwrap();
        let inst = create_recipe_instance_tx(
            &mut tx,
            scope.tenant_id(),
            recipe.id,
            &recipe.slug,
            version.version,
            "atomic test",
            &json!({}),
            "digest",
            None,
        )
        .await
        .unwrap();
        insert_instance_object_tx(
            &mut tx,
            scope.tenant_id(),
            inst.id,
            "agent",
            Uuid::now_v7(),
            "guide",
        )
        .await
        .unwrap();
        // Induce a mid-stamp failure: the duplicate name violates the live
        // unique index inside the SAME transaction.
        let boom = create_recipe_instance_tx(
            &mut tx,
            scope.tenant_id(),
            recipe.id,
            &recipe.slug,
            version.version,
            "atomic test",
            &json!({}),
            "digest",
            None,
        )
        .await;
        assert!(boom.is_err());
        drop(boom);
        tx.rollback().await.unwrap();
        assert!(
            list_recipe_instances(&pool, scope)
                .await
                .unwrap()
                .is_empty(),
            "rollback must leave nothing"
        );
        cleanup(&pool, scope).await;
    }
}
