//! Agents and their append-only revisions.

use crate::scope::{scoped_tx, TenantScope};
use chrono::{DateTime, Utc};
use serde_json::Value;
use sqlx::PgPool;
use uuid::Uuid;

#[derive(Debug, Clone, sqlx::FromRow, serde::Serialize)]
pub struct AgentRow {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, sqlx::FromRow, serde::Serialize)]
pub struct AgentRevisionRow {
    pub id: Uuid,
    pub agent_id: Uuid,
    pub rev: i32,
    pub harness: String,
    pub runner_image: String,
    pub model: String,
    pub system_prompt: Option<String>,
    pub policy_id: Uuid,
    pub budgets: Value,
    pub capability_bundles: Value,
    /// Optional WorkspaceSpec jsonb — the agent's default workspace.
    pub default_workspace: Option<Value>,
    /// Brokered connection requirements (design :349-389): a validated
    /// `Vec<ConnectionRequirement>` jsonb (slot / connector / tools / mode).
    /// Append-only with the revision; validated app-side, never an FK
    /// (agent_revisions has no tenant column). Defaults to `[]`.
    pub connection_requirements: Value,
    /// The DECLARED sandbox network request (a `NetworkRequest` jsonb: mode +
    /// targets + duration). `None` = offline, which is what every revision
    /// written before governed networking means — and keeps meaning.
    pub network: Option<Value>,
    pub created_at: DateTime<Utc>,
}

// ─── Agents & revisions ───────────────────────────────────────────────────

pub async fn create_agent(
    pool: &PgPool,
    scope: TenantScope,
    name: &str,
    description: Option<&str>,
) -> sqlx::Result<AgentRow> {
    let mut tx = scoped_tx(pool, scope).await?;

    let __rls_out = sqlx::query_as(
        "insert into agents (id, tenant_id, name, description) values ($1,$2,$3,$4)
         on conflict (tenant_id, name) do update set description = excluded.description
         returning *",
    )
    .bind(Uuid::now_v7())
    .bind(scope.tenant_id())
    .bind(name)
    .bind(description)
    .fetch_one(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(__rls_out)
}

pub async fn list_agents(pool: &PgPool, scope: TenantScope) -> sqlx::Result<Vec<AgentRow>> {
    let mut tx = scoped_tx(pool, scope).await?;

    let __rls_out = sqlx::query_as("select * from agents where tenant_id = $1 order by name")
        .bind(scope.tenant_id())
        .fetch_all(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(__rls_out)
}

pub async fn get_agent(
    pool: &PgPool,
    scope: TenantScope,
    id: Uuid,
) -> sqlx::Result<Option<AgentRow>> {
    let mut tx = scoped_tx(pool, scope).await?;

    let __rls_out = sqlx::query_as("select * from agents where id = $1 and tenant_id = $2")
        .bind(id)
        .bind(scope.tenant_id())
        .fetch_optional(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(__rls_out)
}

pub async fn get_agent_by_name(
    pool: &PgPool,
    scope: TenantScope,
    name: &str,
) -> sqlx::Result<Option<AgentRow>> {
    let mut tx = scoped_tx(pool, scope).await?;

    let __rls_out = sqlx::query_as("select * from agents where tenant_id = $1 and name = $2")
        .bind(scope.tenant_id())
        .bind(name)
        .fetch_optional(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(__rls_out)
}

/// Appends a new immutable revision (rev = max+1). Editing an agent is
/// always an append — never an update — by construction.
/// `capability_bundles` is the §17 #7 pin list (BundleRef json array): exact
/// versions resolved at attach time, never floating.
#[allow(clippy::too_many_arguments)]
pub async fn append_agent_revision(
    pool: &PgPool,
    scope: TenantScope,
    agent_id: Uuid,
    harness: &str,
    runner_image: &str,
    model: &str,
    system_prompt: Option<&str>,
    policy_id: Uuid,
    budgets: &Value,
    default_workspace: Option<&Value>,
    capability_bundles: &Value,
    connection_requirements: &Value,
    network: Option<&Value>,
) -> sqlx::Result<AgentRevisionRow> {
    let mut tx = scoped_tx(pool, scope).await?;
    let __rls_out = append_agent_revision_tx(
        &mut tx,
        scope.tenant_id(),
        agent_id,
        harness,
        runner_image,
        model,
        system_prompt,
        policy_id,
        budgets,
        default_workspace,
        capability_bundles,
        connection_requirements,
        network,
    )
    .await?;
    tx.commit().await?;
    Ok(__rls_out)
}

/// [`append_agent_revision`] inside a caller-owned transaction (the recipes
/// deploy engine's atomic stamp).
#[allow(clippy::too_many_arguments)]
pub async fn append_agent_revision_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    tenant_id: Uuid,
    agent_id: Uuid,
    harness: &str,
    runner_image: &str,
    model: &str,
    system_prompt: Option<&str>,
    policy_id: Uuid,
    budgets: &Value,
    default_workspace: Option<&Value>,
    capability_bundles: &Value,
    connection_requirements: &Value,
    network: Option<&Value>,
) -> sqlx::Result<AgentRevisionRow> {
    // Revisions carry no tenant column of their own; the tenant boundary is the
    // parent agent — the insert only lands when the agent AND the referenced
    // policy both belong to the scope (a cross-tenant policy_id is proven
    // impossible in SQL, not just Rust-side). Zero rows → RowNotFound (the
    // existing contract for a not-in-scope agent), which callers already map to
    // a 404. `connection_requirements` is validated app-side (Task 2) before it
    // reaches here.
    let __rls_out = sqlx::query_as(
        "insert into agent_revisions
           (id, agent_id, rev, harness, runner_image, model, system_prompt, policy_id, budgets,
            default_workspace, capability_bundles, connection_requirements, network)
         select $1, $2,
           coalesce((select max(rev) from agent_revisions where agent_id = $2), 0) + 1,
           $3, $4, $5, $6, $7, $8, $9, $10, $11, $13
         where exists (select 1 from agents a where a.id = $2 and a.tenant_id = $12)
           and exists (select 1 from policies p where p.id = $7 and p.tenant_id = $12)
         returning *",
    )
    .bind(Uuid::now_v7())
    .bind(agent_id)
    .bind(harness)
    .bind(runner_image)
    .bind(model)
    .bind(system_prompt)
    .bind(policy_id)
    .bind(budgets)
    .bind(default_workspace)
    .bind(capability_bundles)
    .bind(connection_requirements)
    .bind(tenant_id)
    .bind(network)
    .fetch_one(&mut **tx)
    .await?;
    Ok(__rls_out)
}

pub async fn latest_revision(
    pool: &PgPool,
    scope: TenantScope,
    agent_id: Uuid,
) -> sqlx::Result<Option<AgentRevisionRow>> {
    let mut tx = scoped_tx(pool, scope).await?;

    let __rls_out = sqlx::query_as(
        "select r.* from agent_revisions r
         join agents a on a.id = r.agent_id
         where r.agent_id = $1 and a.tenant_id = $2
         order by r.rev desc limit 1",
    )
    .bind(agent_id)
    .bind(scope.tenant_id())
    .fetch_optional(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(__rls_out)
}

pub async fn list_revisions(
    pool: &PgPool,
    scope: TenantScope,
    agent_id: Uuid,
) -> sqlx::Result<Vec<AgentRevisionRow>> {
    let mut tx = scoped_tx(pool, scope).await?;

    let __rls_out = sqlx::query_as(
        "select r.* from agent_revisions r
         join agents a on a.id = r.agent_id
         where r.agent_id = $1 and a.tenant_id = $2
         order by r.rev desc",
    )
    .bind(agent_id)
    .bind(scope.tenant_id())
    .fetch_all(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(__rls_out)
}

pub async fn get_revision(
    pool: &PgPool,
    scope: TenantScope,
    id: Uuid,
) -> sqlx::Result<Option<AgentRevisionRow>> {
    let mut tx = scoped_tx(pool, scope).await?;

    let __rls_out = sqlx::query_as(
        "select r.* from agent_revisions r
         join agents a on a.id = r.agent_id
         where r.id = $1 and a.tenant_id = $2",
    )
    .bind(id)
    .bind(scope.tenant_id())
    .fetch_optional(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(__rls_out)
}
