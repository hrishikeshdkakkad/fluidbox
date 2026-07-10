//! fluidbox-db — sqlx repositories over Neon Postgres.
//!
//! Connection rule: the DIRECT (non-pooler) connection string. NOTIFY is
//! only a wakeup; the seq catch-up query is the delivery source of truth.

use chrono::{DateTime, Utc};
use fluidbox_core::event::{EventEnvelope, Redacted};
use fluidbox_core::state::SessionStatus;
use serde_json::Value;
use sqlx::postgres::{PgListener, PgPoolOptions};
use sqlx::{PgPool, Row};
use uuid::Uuid;

pub mod seed;

pub async fn connect(database_url: &str) -> anyhow::Result<PgPool> {
    let pool = PgPoolOptions::new()
        .max_connections(10)
        .acquire_timeout(std::time::Duration::from_secs(15))
        .connect(database_url)
        .await?;
    sqlx::migrate!("../../migrations").run(&pool).await?;
    Ok(pool)
}

pub fn sha256_hex(s: &str) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(Sha256::digest(s.as_bytes()))
}

// ─── Rows ─────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, sqlx::FromRow, serde::Serialize)]
pub struct PolicyRow {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub name: String,
    pub version: i32,
    pub yaml_source: String,
    pub parsed: Value,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

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
    pub created_at: DateTime<Utc>,
}

/// Deliberately has NO credential field: every query selects explicit
/// columns, so the sealed credential can never ride along into an API
/// response or log. `connection_credential_sealed` is the only reader.
#[derive(Debug, Clone, sqlx::FromRow, serde::Serialize)]
pub struct IntegrationConnectionRow {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub provider: String,
    pub external_account_id: String,
    pub display_name: String,
    pub granted_scopes: Value,
    pub resource_selection: Value,
    pub status: String,
    pub metadata: Value,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, sqlx::FromRow, serde::Serialize)]
pub struct SessionRow {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub agent_id: Uuid,
    pub agent_revision_id: Uuid,
    pub status: String,
    pub status_reason: Option<String>,
    pub autonomy: String,
    pub trust_tier: String,
    pub task: String,
    pub repo_source: Value,
    pub run_spec: Value,
    /// InvocationContext envelope (design §3.4). Null for pre-Phase-2 rows.
    pub trigger: Option<Value>,
    pub sandbox_handle: Option<Value>,
    pub budgets: Value,
    pub base_commit: Option<String>,
    pub result_summary: Option<String>,
    pub event_seq: i64,
    pub last_heartbeat_at: Option<DateTime<Utc>>,
    pub started_at: Option<DateTime<Utc>>,
    pub finished_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl SessionRow {
    pub fn status_enum(&self) -> SessionStatus {
        SessionStatus::parse(&self.status).unwrap_or(SessionStatus::Failed)
    }
}

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

#[derive(Debug, Clone, sqlx::FromRow, serde::Serialize)]
pub struct ApprovalRow {
    pub id: Uuid,
    pub session_id: Uuid,
    pub tool_call_id: String,
    pub tool: String,
    pub summary: String,
    pub risk: Option<String>,
    pub scope: String,
    pub scope_key: String,
    pub status: String,
    pub requested_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub decided_at: Option<DateTime<Utc>>,
    pub decided_by: Option<String>,
}

#[derive(Debug, Clone, sqlx::FromRow, serde::Serialize)]
pub struct ArtifactRow {
    pub id: Uuid,
    pub session_id: Uuid,
    pub kind: String,
    pub name: String,
    pub content: String,
    pub content_type: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Default, sqlx::FromRow, serde::Serialize)]
pub struct UsageTotals {
    pub input_tokens: i64,
    pub output_tokens: i64,
    pub cache_read_tokens: i64,
    pub cache_write_tokens: i64,
    pub cost_usd: f64,
    pub requests: i64,
}

// ─── Tenants ──────────────────────────────────────────────────────────────

pub async fn ensure_default_tenant(pool: &PgPool) -> sqlx::Result<Uuid> {
    let id = Uuid::now_v7();
    let row = sqlx::query(
        "insert into tenants (id, name) values ($1, 'default')
         on conflict (name) do update set name = excluded.name
         returning id",
    )
    .bind(id)
    .fetch_one(pool)
    .await?;
    Ok(row.get("id"))
}

// ─── Policies ─────────────────────────────────────────────────────────────

pub async fn upsert_policy(
    pool: &PgPool,
    tenant: Uuid,
    name: &str,
    yaml_source: &str,
    parsed: &Value,
) -> sqlx::Result<PolicyRow> {
    sqlx::query_as(
        "insert into policies (id, tenant_id, name, yaml_source, parsed)
         values ($1, $2, $3, $4, $5)
         on conflict (tenant_id, name) do update
           set yaml_source = excluded.yaml_source,
               parsed = excluded.parsed,
               version = policies.version + 1,
               updated_at = now()
         returning *",
    )
    .bind(Uuid::now_v7())
    .bind(tenant)
    .bind(name)
    .bind(yaml_source)
    .bind(parsed)
    .fetch_one(pool)
    .await
}

/// Bootstrap a policy from a seed file only if it does not already exist.
/// Returns the existing or newly-inserted row — so UI edits (which bump the
/// version) are never clobbered by a later boot re-reading the disk YAML.
pub async fn seed_policy_if_absent(
    pool: &PgPool,
    tenant: Uuid,
    name: &str,
    yaml_source: &str,
    parsed: &Value,
) -> sqlx::Result<(PolicyRow, bool)> {
    if let Some(existing) = get_policy_by_name(pool, tenant, name).await? {
        return Ok((existing, false));
    }
    let row = sqlx::query_as(
        "insert into policies (id, tenant_id, name, yaml_source, parsed)
         values ($1, $2, $3, $4, $5)
         on conflict (tenant_id, name) do update set name = excluded.name
         returning *",
    )
    .bind(Uuid::now_v7())
    .bind(tenant)
    .bind(name)
    .bind(yaml_source)
    .bind(parsed)
    .fetch_one(pool)
    .await?;
    Ok((row, true))
}

pub async fn list_policies(pool: &PgPool, tenant: Uuid) -> sqlx::Result<Vec<PolicyRow>> {
    sqlx::query_as("select * from policies where tenant_id = $1 order by name")
        .bind(tenant)
        .fetch_all(pool)
        .await
}

pub async fn get_policy(pool: &PgPool, id: Uuid) -> sqlx::Result<Option<PolicyRow>> {
    sqlx::query_as("select * from policies where id = $1")
        .bind(id)
        .fetch_optional(pool)
        .await
}

pub async fn get_policy_by_name(
    pool: &PgPool,
    tenant: Uuid,
    name: &str,
) -> sqlx::Result<Option<PolicyRow>> {
    sqlx::query_as("select * from policies where tenant_id = $1 and name = $2")
        .bind(tenant)
        .bind(name)
        .fetch_optional(pool)
        .await
}

// ─── Agents & revisions ───────────────────────────────────────────────────

pub async fn create_agent(
    pool: &PgPool,
    tenant: Uuid,
    name: &str,
    description: Option<&str>,
) -> sqlx::Result<AgentRow> {
    sqlx::query_as(
        "insert into agents (id, tenant_id, name, description) values ($1,$2,$3,$4)
         on conflict (tenant_id, name) do update set description = excluded.description
         returning *",
    )
    .bind(Uuid::now_v7())
    .bind(tenant)
    .bind(name)
    .bind(description)
    .fetch_one(pool)
    .await
}

pub async fn list_agents(pool: &PgPool, tenant: Uuid) -> sqlx::Result<Vec<AgentRow>> {
    sqlx::query_as("select * from agents where tenant_id = $1 order by name")
        .bind(tenant)
        .fetch_all(pool)
        .await
}

pub async fn get_agent(pool: &PgPool, id: Uuid) -> sqlx::Result<Option<AgentRow>> {
    sqlx::query_as("select * from agents where id = $1")
        .bind(id)
        .fetch_optional(pool)
        .await
}

pub async fn get_agent_by_name(
    pool: &PgPool,
    tenant: Uuid,
    name: &str,
) -> sqlx::Result<Option<AgentRow>> {
    sqlx::query_as("select * from agents where tenant_id = $1 and name = $2")
        .bind(tenant)
        .bind(name)
        .fetch_optional(pool)
        .await
}

/// Appends a new immutable revision (rev = max+1). Editing an agent is
/// always an append — never an update — by construction.
#[allow(clippy::too_many_arguments)]
pub async fn append_agent_revision(
    pool: &PgPool,
    agent_id: Uuid,
    harness: &str,
    runner_image: &str,
    model: &str,
    system_prompt: Option<&str>,
    policy_id: Uuid,
    budgets: &Value,
    default_workspace: Option<&Value>,
) -> sqlx::Result<AgentRevisionRow> {
    sqlx::query_as(
        "insert into agent_revisions
           (id, agent_id, rev, harness, runner_image, model, system_prompt, policy_id, budgets,
            default_workspace)
         values ($1, $2,
           coalesce((select max(rev) from agent_revisions where agent_id = $2), 0) + 1,
           $3, $4, $5, $6, $7, $8, $9)
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
    .fetch_one(pool)
    .await
}

pub async fn latest_revision(
    pool: &PgPool,
    agent_id: Uuid,
) -> sqlx::Result<Option<AgentRevisionRow>> {
    sqlx::query_as("select * from agent_revisions where agent_id = $1 order by rev desc limit 1")
        .bind(agent_id)
        .fetch_optional(pool)
        .await
}

pub async fn list_revisions(pool: &PgPool, agent_id: Uuid) -> sqlx::Result<Vec<AgentRevisionRow>> {
    sqlx::query_as("select * from agent_revisions where agent_id = $1 order by rev desc")
        .bind(agent_id)
        .fetch_all(pool)
        .await
}

pub async fn get_revision(pool: &PgPool, id: Uuid) -> sqlx::Result<Option<AgentRevisionRow>> {
    sqlx::query_as("select * from agent_revisions where id = $1")
        .bind(id)
        .fetch_optional(pool)
        .await
}

// ─── Integration connections ──────────────────────────────────────────────

// Every connection query selects this explicit column list (never `*`) so
// the sealed credential can't ride along; keep the four copies in sync.
#[allow(clippy::too_many_arguments)]
pub async fn create_connection(
    pool: &PgPool,
    tenant: Uuid,
    provider: &str,
    external_account_id: &str,
    display_name: &str,
    credential_sealed: &[u8],
    granted_scopes: &Value,
    resource_selection: &Value,
    metadata: &Value,
) -> sqlx::Result<IntegrationConnectionRow> {
    sqlx::query_as(
        "insert into integration_connections
           (id, tenant_id, provider, external_account_id, display_name, credential_sealed,
            granted_scopes, resource_selection, metadata)
         values ($1,$2,$3,$4,$5,$6,$7,$8,$9)
         returning id, tenant_id, provider, external_account_id, display_name,
                   granted_scopes, resource_selection, status, metadata, created_at, updated_at",
    )
    .bind(Uuid::now_v7())
    .bind(tenant)
    .bind(provider)
    .bind(external_account_id)
    .bind(display_name)
    .bind(credential_sealed)
    .bind(granted_scopes)
    .bind(resource_selection)
    .bind(metadata)
    .fetch_one(pool)
    .await
}

pub async fn list_connections(
    pool: &PgPool,
    tenant: Uuid,
) -> sqlx::Result<Vec<IntegrationConnectionRow>> {
    sqlx::query_as(
        "select id, tenant_id, provider, external_account_id, display_name,
                granted_scopes, resource_selection, status, metadata, created_at, updated_at
         from integration_connections
         where tenant_id = $1 order by created_at desc",
    )
    .bind(tenant)
    .fetch_all(pool)
    .await
}

pub async fn get_connection(
    pool: &PgPool,
    id: Uuid,
) -> sqlx::Result<Option<IntegrationConnectionRow>> {
    sqlx::query_as(
        "select id, tenant_id, provider, external_account_id, display_name,
                granted_scopes, resource_selection, status, metadata, created_at, updated_at
         from integration_connections where id = $1",
    )
    .bind(id)
    .fetch_optional(pool)
    .await
}

pub async fn revoke_connection(
    pool: &PgPool,
    id: Uuid,
) -> sqlx::Result<Option<IntegrationConnectionRow>> {
    sqlx::query_as(
        "update integration_connections set status = 'revoked', updated_at = now()
         where id = $1 and status <> 'revoked'
         returning id, tenant_id, provider, external_account_id, display_name,
                   granted_scopes, resource_selection, status, metadata, created_at, updated_at",
    )
    .bind(id)
    .fetch_optional(pool)
    .await
}

/// The only reader of the sealed credential. Returns None unless the
/// connection exists AND is active — a revoked connection can never again
/// produce a credential.
pub async fn connection_credential_sealed(
    pool: &PgPool,
    id: Uuid,
) -> sqlx::Result<Option<Vec<u8>>> {
    let row = sqlx::query(
        "select credential_sealed from integration_connections
         where id = $1 and status = 'active'",
    )
    .bind(id)
    .fetch_optional(pool)
    .await?;
    Ok(row.map(|r| r.get::<Vec<u8>, _>("credential_sealed")))
}

// ─── Trigger subscriptions ────────────────────────────────────────────────

/// Deliberately has NO callback-secret field — every query selects explicit
/// columns so the sealed secret can never ride into an API response.
/// `subscription_callback_secret_sealed` is the only reader.
#[derive(Debug, Clone, sqlx::FromRow, serde::Serialize)]
pub struct TriggerSubscriptionRow {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub agent_id: Uuid,
    pub name: String,
    pub trigger_kind: String,
    pub pinned_revision_id: Option<Uuid>,
    pub enabled: bool,
    pub task_template: Option<String>,
    pub allow_task_override: bool,
    pub allow_workspace_override: bool,
    pub autonomy: Option<String>,
    pub budget_override: Option<Value>,
    pub workspace_override: Option<Value>,
    pub result_destinations: Value,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

const SUBSCRIPTION_COLS: &str = "id, tenant_id, agent_id, name, trigger_kind, pinned_revision_id, \
     enabled, task_template, allow_task_override, allow_workspace_override, autonomy, \
     budget_override, workspace_override, result_destinations, created_at, updated_at";

#[allow(clippy::too_many_arguments)]
pub async fn create_trigger_subscription(
    pool: &PgPool,
    tenant: Uuid,
    agent_id: Uuid,
    name: &str,
    trigger_kind: &str,
    pinned_revision_id: Option<Uuid>,
    task_template: Option<&str>,
    allow_task_override: bool,
    allow_workspace_override: bool,
    autonomy: Option<&str>,
    budget_override: Option<&Value>,
    workspace_override: Option<&Value>,
    result_destinations: &Value,
    callback_secret_sealed: Option<&[u8]>,
) -> sqlx::Result<TriggerSubscriptionRow> {
    sqlx::query_as(sqlx::AssertSqlSafe(format!(
        "insert into trigger_subscriptions
           (id, tenant_id, agent_id, name, trigger_kind, pinned_revision_id, task_template,
            allow_task_override, allow_workspace_override, autonomy, budget_override,
            workspace_override, result_destinations, callback_secret_sealed)
         values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)
         returning {SUBSCRIPTION_COLS}"
    )))
    .bind(Uuid::now_v7())
    .bind(tenant)
    .bind(agent_id)
    .bind(name)
    .bind(trigger_kind)
    .bind(pinned_revision_id)
    .bind(task_template)
    .bind(allow_task_override)
    .bind(allow_workspace_override)
    .bind(autonomy)
    .bind(budget_override)
    .bind(workspace_override)
    .bind(result_destinations)
    .bind(callback_secret_sealed)
    .fetch_one(pool)
    .await
}

pub async fn list_trigger_subscriptions(
    pool: &PgPool,
    tenant: Uuid,
) -> sqlx::Result<Vec<TriggerSubscriptionRow>> {
    sqlx::query_as(sqlx::AssertSqlSafe(format!(
        "select {SUBSCRIPTION_COLS} from trigger_subscriptions
         where tenant_id = $1 order by created_at desc"
    )))
    .bind(tenant)
    .fetch_all(pool)
    .await
}

pub async fn get_trigger_subscription(
    pool: &PgPool,
    id: Uuid,
) -> sqlx::Result<Option<TriggerSubscriptionRow>> {
    sqlx::query_as(sqlx::AssertSqlSafe(format!(
        "select {SUBSCRIPTION_COLS} from trigger_subscriptions where id = $1"
    )))
    .bind(id)
    .fetch_optional(pool)
    .await
}

pub async fn set_trigger_subscription_enabled(
    pool: &PgPool,
    id: Uuid,
    enabled: bool,
) -> sqlx::Result<Option<TriggerSubscriptionRow>> {
    sqlx::query_as(sqlx::AssertSqlSafe(format!(
        "update trigger_subscriptions set enabled = $2, updated_at = now()
         where id = $1 returning {SUBSCRIPTION_COLS}"
    )))
    .bind(id)
    .bind(enabled)
    .fetch_optional(pool)
    .await
}

/// The only reader of the sealed callback secret. Deliveries for in-flight
/// runs must still sign after a disable, so this does not require `enabled`.
pub async fn subscription_callback_secret_sealed(
    pool: &PgPool,
    id: Uuid,
) -> sqlx::Result<Option<Vec<u8>>> {
    let row = sqlx::query("select callback_secret_sealed from trigger_subscriptions where id = $1")
        .bind(id)
        .fetch_optional(pool)
        .await?;
    Ok(row.and_then(|r| r.get::<Option<Vec<u8>>, _>("callback_secret_sealed")))
}

// ─── Sessions ─────────────────────────────────────────────────────────────

#[allow(clippy::too_many_arguments)]
pub async fn create_session(
    pool: &PgPool,
    tenant: Uuid,
    agent_id: Uuid,
    agent_revision_id: Uuid,
    autonomy: &str,
    task: &str,
    repo_source: &Value,
    run_spec: &Value,
    budgets: &Value,
    trigger: Option<&Value>,
) -> sqlx::Result<SessionRow> {
    sqlx::query_as(
        "insert into sessions
           (id, tenant_id, agent_id, agent_revision_id, autonomy, task, repo_source, run_spec, budgets, trigger)
         values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
         returning *",
    )
    .bind(Uuid::now_v7())
    .bind(tenant)
    .bind(agent_id)
    .bind(agent_revision_id)
    .bind(autonomy)
    .bind(task)
    .bind(repo_source)
    .bind(run_spec)
    .bind(budgets)
    .bind(trigger)
    .fetch_one(pool)
    .await
}

pub async fn get_session(pool: &PgPool, id: Uuid) -> sqlx::Result<Option<SessionRow>> {
    sqlx::query_as("select * from sessions where id = $1")
        .bind(id)
        .fetch_optional(pool)
        .await
}

pub async fn list_sessions(
    pool: &PgPool,
    tenant: Uuid,
    limit: i64,
) -> sqlx::Result<Vec<SessionRow>> {
    sqlx::query_as("select * from sessions where tenant_id = $1 order by created_at desc limit $2")
        .bind(tenant)
        .bind(limit)
        .fetch_all(pool)
        .await
}

pub async fn sessions_in_status(pool: &PgPool, statuses: &[&str]) -> sqlx::Result<Vec<SessionRow>> {
    let list: Vec<String> = statuses.iter().map(|s| s.to_string()).collect();
    sqlx::query_as("select * from sessions where status = any($1)")
        .bind(&list)
        .fetch_all(pool)
        .await
}

/// Sessions stuck before launch. The orchestrator moves created →
/// provisioning → initializing in seconds (initializing: minutes at worst
/// for a big repo copy), so a stale row means the control plane died
/// mid-launch and nothing owns the session anymore.
pub async fn stale_nonstarted_sessions(
    pool: &PgPool,
    max_age_mins: i32,
) -> sqlx::Result<Vec<SessionRow>> {
    sqlx::query_as(
        "select * from sessions
         where status = any($1) and updated_at < now() - make_interval(mins => $2)",
    )
    .bind(vec![
        "created".to_string(),
        "provisioning".to_string(),
        "initializing".to_string(),
    ])
    .bind(max_age_mins)
    .fetch_all(pool)
    .await
}

/// The single status writer. Validates the transition inside a transaction;
/// returns Ok(None) if the transition is not legal (caller decides whether
/// that is an error or a benign race).
pub async fn transition_session(
    pool: &PgPool,
    id: Uuid,
    next: SessionStatus,
    reason: Option<&str>,
) -> sqlx::Result<Option<(SessionStatus, SessionRow)>> {
    let mut tx = pool.begin().await?;
    let row: Option<(String,)> =
        sqlx::query_as("select status from sessions where id = $1 for update")
            .bind(id)
            .fetch_optional(&mut *tx)
            .await?;
    let Some((current,)) = row else {
        return Ok(None);
    };
    let current = SessionStatus::parse(&current).unwrap_or(SessionStatus::Failed);
    if !current.can_transition_to(next) {
        tx.rollback().await.ok();
        return Ok(None);
    }
    let updated: SessionRow = sqlx::query_as(
        "update sessions set
            status = $2,
            status_reason = $3,
            updated_at = now(),
            started_at = case when $2 = 'running'
                              then coalesce(started_at, now()) else started_at end,
            finished_at = case when $2 in ('completed','failed','cancelled','budget_exceeded')
                               then now() else finished_at end
         where id = $1 returning *",
    )
    .bind(id)
    .bind(next.as_str())
    .bind(reason)
    .fetch_one(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(Some((current, updated)))
}

pub async fn set_sandbox_handle(pool: &PgPool, id: Uuid, handle: &Value) -> sqlx::Result<()> {
    sqlx::query("update sessions set sandbox_handle = $2, updated_at = now() where id = $1")
        .bind(id)
        .bind(handle)
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn set_base_commit(pool: &PgPool, id: Uuid, commit: &str) -> sqlx::Result<()> {
    sqlx::query("update sessions set base_commit = $2, updated_at = now() where id = $1")
        .bind(id)
        .bind(commit)
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn set_result_summary(pool: &PgPool, id: Uuid, summary: &str) -> sqlx::Result<()> {
    sqlx::query("update sessions set result_summary = $2, updated_at = now() where id = $1")
        .bind(id)
        .bind(summary)
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn heartbeat(pool: &PgPool, id: Uuid) -> sqlx::Result<()> {
    sqlx::query("update sessions set last_heartbeat_at = now(), updated_at = now() where id = $1")
        .bind(id)
        .execute(pool)
        .await?;
    Ok(())
}

// ─── Events (append-only; Redacted enforced at the type level) ────────────

pub async fn append_event(pool: &PgPool, event: Redacted<EventEnvelope>) -> sqlx::Result<i64> {
    let env = event.into_inner();
    let payload = serde_json::to_value(&env.body).unwrap_or(Value::Null);
    let type_name = env.body.type_name();
    let row = sqlx::query("select append_event($1, $2, $3, $4, $5, $6) as seq")
        .bind(env.session_id)
        .bind(env.event_id)
        .bind(env.actor.as_str())
        .bind(&type_name)
        .bind(&payload)
        .bind(env.occurred_at)
        .fetch_one(pool)
        .await?;
    Ok(row.get::<i64, _>("seq"))
}

pub async fn events_after(
    pool: &PgPool,
    session: Uuid,
    after_seq: i64,
    limit: i64,
) -> sqlx::Result<Vec<EventRow>> {
    sqlx::query_as(
        "select event_id, session_id, seq, actor, type, payload, occurred_at
         from events where session_id = $1 and seq > $2 order by seq limit $3",
    )
    .bind(session)
    .bind(after_seq)
    .bind(limit)
    .fetch_all(pool)
    .await
}

// ─── Approvals ────────────────────────────────────────────────────────────

/// Idempotent by (session_id, tool_call_id): a runner retry after a socket
/// drop re-attaches to the same row instead of duplicating it.
#[allow(clippy::too_many_arguments)]
pub async fn upsert_pending_approval(
    pool: &PgPool,
    session: Uuid,
    tool_call_id: &str,
    tool: &str,
    summary: &str,
    input_digest: Option<&str>,
    risk: Option<&str>,
    scope: &str,
    scope_key: &str,
    ttl_secs: i64,
) -> sqlx::Result<(ApprovalRow, bool)> {
    let inserted: Option<ApprovalRow> = sqlx::query_as(
        "insert into approvals
           (id, session_id, tool_call_id, tool, summary, input_digest, risk, scope, scope_key, expires_at)
         values ($1,$2,$3,$4,$5,$6,$7,$8,$9, now() + make_interval(secs => $10))
         on conflict (session_id, tool_call_id) do nothing
         returning id, session_id, tool_call_id, tool, summary, risk, scope, scope_key, status,
                   requested_at, expires_at, decided_at, decided_by",
    )
    .bind(Uuid::now_v7())
    .bind(session)
    .bind(tool_call_id)
    .bind(tool)
    .bind(summary)
    .bind(input_digest)
    .bind(risk)
    .bind(scope)
    .bind(scope_key)
    .bind(ttl_secs as f64)
    .fetch_optional(pool)
    .await?;
    if let Some(row) = inserted {
        return Ok((row, true));
    }
    let existing: ApprovalRow = sqlx::query_as(
        "select id, session_id, tool_call_id, tool, summary, risk, scope, scope_key, status,
                requested_at, expires_at, decided_at, decided_by
         from approvals where session_id = $1 and tool_call_id = $2",
    )
    .bind(session)
    .bind(tool_call_id)
    .fetch_one(pool)
    .await?;
    Ok((existing, false))
}

pub async fn decide_approval(
    pool: &PgPool,
    id: Uuid,
    status: &str,
    decided_by: &str,
) -> sqlx::Result<Option<ApprovalRow>> {
    sqlx::query_as(
        "update approvals set status = $2, decided_at = now(), decided_by = $3
         where id = $1 and status = 'pending'
         returning id, session_id, tool_call_id, tool, summary, risk, scope, scope_key, status,
                   requested_at, expires_at, decided_at, decided_by",
    )
    .bind(id)
    .bind(status)
    .bind(decided_by)
    .fetch_optional(pool)
    .await
}

pub async fn get_approval(pool: &PgPool, id: Uuid) -> sqlx::Result<Option<ApprovalRow>> {
    sqlx::query_as(
        "select id, session_id, tool_call_id, tool, summary, risk, scope, scope_key, status,
                requested_at, expires_at, decided_at, decided_by
         from approvals where id = $1",
    )
    .bind(id)
    .fetch_optional(pool)
    .await
}

pub async fn pending_approvals(pool: &PgPool) -> sqlx::Result<Vec<ApprovalRow>> {
    sqlx::query_as(
        "select id, session_id, tool_call_id, tool, summary, risk, scope, scope_key, status,
                requested_at, expires_at, decided_at, decided_by
         from approvals where status = 'pending' order by requested_at",
    )
    .fetch_all(pool)
    .await
}

pub async fn session_approvals(pool: &PgPool, session: Uuid) -> sqlx::Result<Vec<ApprovalRow>> {
    sqlx::query_as(
        "select id, session_id, tool_call_id, tool, summary, risk, scope, scope_key, status,
                requested_at, expires_at, decided_at, decided_by
         from approvals where session_id = $1 order by requested_at desc",
    )
    .bind(session)
    .fetch_all(pool)
    .await
}

/// Has this session already granted `approved_session` for this scope key?
pub async fn has_session_grant(
    pool: &PgPool,
    session: Uuid,
    scope_key: &str,
) -> sqlx::Result<bool> {
    let row = sqlx::query(
        "select exists(
           select 1 from approvals
           where session_id = $1 and scope_key = $2 and status = 'approved_session'
         ) as granted",
    )
    .bind(session)
    .bind(scope_key)
    .fetch_one(pool)
    .await?;
    Ok(row.get::<bool, _>("granted"))
}

pub async fn expire_stale_approvals(pool: &PgPool) -> sqlx::Result<Vec<ApprovalRow>> {
    sqlx::query_as(
        "update approvals set status = 'expired', decided_at = now(), decided_by = 'timeout'
         where status = 'pending' and expires_at < now()
         returning id, session_id, tool_call_id, tool, summary, risk, scope, scope_key, status,
                   requested_at, expires_at, decided_at, decided_by",
    )
    .fetch_all(pool)
    .await
}

// ─── Artifacts ────────────────────────────────────────────────────────────

pub async fn add_artifact(
    pool: &PgPool,
    session: Uuid,
    kind: &str,
    name: &str,
    content: &str,
    content_type: &str,
) -> sqlx::Result<ArtifactRow> {
    sqlx::query_as(
        "insert into artifacts (id, session_id, kind, name, content, content_type)
         values ($1,$2,$3,$4,$5,$6) returning *",
    )
    .bind(Uuid::now_v7())
    .bind(session)
    .bind(kind)
    .bind(name)
    .bind(content)
    .bind(content_type)
    .fetch_one(pool)
    .await
}

pub async fn list_artifacts(pool: &PgPool, session: Uuid) -> sqlx::Result<Vec<ArtifactRow>> {
    sqlx::query_as("select * from artifacts where session_id = $1 order by created_at")
        .bind(session)
        .fetch_all(pool)
        .await
}

pub async fn get_artifact(pool: &PgPool, id: Uuid) -> sqlx::Result<Option<ArtifactRow>> {
    sqlx::query_as("select * from artifacts where id = $1")
        .bind(id)
        .fetch_optional(pool)
        .await
}

// ─── Usage ────────────────────────────────────────────────────────────────

#[allow(clippy::too_many_arguments)]
pub async fn add_usage(
    pool: &PgPool,
    session: Uuid,
    model: &str,
    input_tokens: i64,
    output_tokens: i64,
    cache_read: i64,
    cache_write: i64,
    cost_usd: Option<f64>,
    source: &str,
    external_id: Option<&str>,
) -> sqlx::Result<bool> {
    let res = sqlx::query(
        "insert into usage_entries
           (id, session_id, model, input_tokens, output_tokens, cache_read_tokens,
            cache_write_tokens, cost_usd, source, external_id)
         values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
         on conflict (external_id) where external_id is not null do nothing",
    )
    .bind(Uuid::now_v7())
    .bind(session)
    .bind(model)
    .bind(input_tokens)
    .bind(output_tokens)
    .bind(cache_read)
    .bind(cache_write)
    .bind(cost_usd)
    .bind(source)
    .bind(external_id)
    .execute(pool)
    .await?;
    Ok(res.rows_affected() > 0)
}

pub async fn usage_totals(pool: &PgPool, session: Uuid) -> sqlx::Result<UsageTotals> {
    sqlx::query_as(
        "select coalesce(sum(input_tokens),0)::bigint as input_tokens,
                coalesce(sum(output_tokens),0)::bigint as output_tokens,
                coalesce(sum(cache_read_tokens),0)::bigint as cache_read_tokens,
                coalesce(sum(cache_write_tokens),0)::bigint as cache_write_tokens,
                coalesce(sum(cost_usd),0)::float8 as cost_usd,
                count(*)::bigint as requests
         from usage_entries where session_id = $1",
    )
    .bind(session)
    .fetch_one(pool)
    .await
}

pub async fn tool_call_count(pool: &PgPool, session: Uuid) -> sqlx::Result<i64> {
    let row = sqlx::query(
        "select count(*)::bigint as n from events
         where session_id = $1 and type = 'tool.requested'",
    )
    .bind(session)
    .fetch_one(pool)
    .await?;
    Ok(row.get::<i64, _>("n"))
}

// ─── Tokens ───────────────────────────────────────────────────────────────

pub async fn create_session_token(
    pool: &PgPool,
    tenant: Uuid,
    session: Uuid,
    token_plain: &str,
    ttl_secs: i64,
) -> sqlx::Result<()> {
    sqlx::query(
        "insert into api_tokens (id, tenant_id, kind, session_id, token_sha256, expires_at)
         values ($1, $2, 'session', $3, $4, now() + make_interval(secs => $5))",
    )
    .bind(Uuid::now_v7())
    .bind(tenant)
    .bind(session)
    .bind(sha256_hex(token_plain))
    .bind(ttl_secs as f64)
    .execute(pool)
    .await?;
    Ok(())
}

/// Returns the session id a valid (unexpired, unrevoked) token belongs to.
pub async fn session_for_token(pool: &PgPool, token_plain: &str) -> sqlx::Result<Option<Uuid>> {
    let row = sqlx::query(
        "select session_id from api_tokens
         where kind = 'session' and token_sha256 = $1
           and revoked_at is null
           and (expires_at is null or expires_at > now())",
    )
    .bind(sha256_hex(token_plain))
    .fetch_optional(pool)
    .await?;
    Ok(row.and_then(|r| r.get::<Option<Uuid>, _>("session_id")))
}

pub async fn extend_session_token(
    pool: &PgPool,
    token_plain: &str,
    ttl_secs: i64,
) -> sqlx::Result<bool> {
    let res = sqlx::query(
        "update api_tokens set expires_at = now() + make_interval(secs => $2)
         where kind = 'session' and token_sha256 = $1 and revoked_at is null",
    )
    .bind(sha256_hex(token_plain))
    .bind(ttl_secs as f64)
    .execute(pool)
    .await?;
    Ok(res.rows_affected() > 0)
}

// ─── Trigger invocations (Idempotency-Key) ────────────────────────────────

#[derive(Debug)]
pub enum InvocationClaim {
    /// We own this key — create the run, then `bind_invocation`.
    Claimed { invocation_id: Uuid },
    /// This key already produced a run — return it (after digest check).
    Replay {
        session_id: Uuid,
        request_digest: String,
    },
    /// Another request holds the key mid-creation — caller should 409.
    InFlight,
}

/// Claim an idempotency key. Exactly one concurrent caller wins the insert;
/// a claim whose creation crashed (bound to no session) becomes re-claimable
/// after 60s so a dangling row can't wedge the key forever.
pub async fn claim_invocation(
    pool: &PgPool,
    subscription: Uuid,
    idempotency_key: &str,
    request_digest: &str,
) -> sqlx::Result<InvocationClaim> {
    let inserted = sqlx::query(
        "insert into trigger_invocations (id, subscription_id, idempotency_key, request_digest)
         values ($1, $2, $3, $4)
         on conflict (subscription_id, idempotency_key) do nothing
         returning id",
    )
    .bind(Uuid::now_v7())
    .bind(subscription)
    .bind(idempotency_key)
    .bind(request_digest)
    .fetch_optional(pool)
    .await?;
    if let Some(row) = inserted {
        return Ok(InvocationClaim::Claimed {
            invocation_id: row.get("id"),
        });
    }
    let existing = sqlx::query(
        "select id, session_id, request_digest, created_at from trigger_invocations
         where subscription_id = $1 and idempotency_key = $2",
    )
    .bind(subscription)
    .bind(idempotency_key)
    .fetch_one(pool)
    .await?;
    if let Some(session_id) = existing.get::<Option<Uuid>, _>("session_id") {
        return Ok(InvocationClaim::Replay {
            session_id,
            request_digest: existing.get("request_digest"),
        });
    }
    // Unbound claim: take it over only once it is stale (crashed creator).
    let takeover = sqlx::query(
        "update trigger_invocations
            set created_at = now(), request_digest = $3
          where subscription_id = $1 and idempotency_key = $2
            and session_id is null and created_at < now() - interval '60 seconds'
          returning id",
    )
    .bind(subscription)
    .bind(idempotency_key)
    .bind(request_digest)
    .fetch_optional(pool)
    .await?;
    Ok(match takeover {
        Some(row) => InvocationClaim::Claimed {
            invocation_id: row.get("id"),
        },
        None => InvocationClaim::InFlight,
    })
}

pub async fn bind_invocation(pool: &PgPool, invocation: Uuid, session: Uuid) -> sqlx::Result<()> {
    sqlx::query("update trigger_invocations set session_id = $2 where id = $1")
        .bind(invocation)
        .bind(session)
        .execute(pool)
        .await?;
    Ok(())
}

/// Free a claim whose run creation failed, so an immediate retry can re-try.
pub async fn release_invocation(pool: &PgPool, invocation: Uuid) -> sqlx::Result<()> {
    sqlx::query("delete from trigger_invocations where id = $1 and session_id is null")
        .bind(invocation)
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn list_subscription_sessions(
    pool: &PgPool,
    subscription: Uuid,
    limit: i64,
) -> sqlx::Result<Vec<SessionRow>> {
    sqlx::query_as(
        "select s.* from sessions s
         join trigger_invocations i on i.session_id = s.id
         where i.subscription_id = $1
         order by s.created_at desc limit $2",
    )
    .bind(subscription)
    .bind(limit)
    .fetch_all(pool)
    .await
}

/// Scopes the trigger-token polling endpoint to runs this subscription made.
pub async fn subscription_owns_session(
    pool: &PgPool,
    subscription: Uuid,
    session: Uuid,
) -> sqlx::Result<bool> {
    let row = sqlx::query(
        "select exists(
           select 1 from trigger_invocations
           where subscription_id = $1 and session_id = $2
         ) as owned",
    )
    .bind(subscription)
    .bind(session)
    .fetch_one(pool)
    .await?;
    Ok(row.get::<bool, _>("owned"))
}

// ─── Result deliveries ────────────────────────────────────────────────────

#[derive(Debug, Clone, sqlx::FromRow, serde::Serialize)]
pub struct ResultDeliveryRow {
    pub id: Uuid,
    pub session_id: Uuid,
    pub subscription_id: Option<Uuid>,
    pub destination: Value,
    pub status: String,
    pub attempts: i32,
    pub next_attempt_at: DateTime<Utc>,
    pub last_error: Option<String>,
    pub payload_digest: Option<String>,
    pub delivered_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

pub async fn enqueue_result_delivery(
    pool: &PgPool,
    session: Uuid,
    subscription: Option<Uuid>,
    destination: &Value,
) -> sqlx::Result<ResultDeliveryRow> {
    sqlx::query_as(
        "insert into result_deliveries (id, session_id, subscription_id, destination)
         values ($1, $2, $3, $4) returning *",
    )
    .bind(Uuid::now_v7())
    .bind(session)
    .bind(subscription)
    .bind(destination)
    .fetch_one(pool)
    .await
}

/// Due work for the (single, sequential) delivery worker. No row locking:
/// there is one worker task per server and attempts are awaited one at a
/// time, so a row can never be attempted twice concurrently. Delivery is
/// at-least-once by design — receivers dedup on the delivery id.
pub async fn due_result_deliveries(
    pool: &PgPool,
    limit: i64,
) -> sqlx::Result<Vec<ResultDeliveryRow>> {
    sqlx::query_as(
        "select * from result_deliveries
         where status = 'pending' and next_attempt_at <= now()
         order by next_attempt_at limit $1",
    )
    .bind(limit)
    .fetch_all(pool)
    .await
}

/// Record one attempt. ok → delivered; failure → attempts+1 and either
/// rescheduled (`retry_in_secs`) or terminally 'failed' at `max_attempts`.
pub async fn mark_delivery_attempt(
    pool: &PgPool,
    id: Uuid,
    ok: bool,
    error: Option<&str>,
    payload_digest: Option<&str>,
    retry_in_secs: i64,
    max_attempts: i32,
) -> sqlx::Result<Option<ResultDeliveryRow>> {
    sqlx::query_as(
        "update result_deliveries set
            attempts = attempts + 1,
            status = case when $2 then 'delivered'
                          when attempts + 1 >= $6 then 'failed'
                          else 'pending' end,
            delivered_at = case when $2 then now() else delivered_at end,
            last_error = $3,
            payload_digest = coalesce($4, payload_digest),
            next_attempt_at = now() + make_interval(secs => $5),
            updated_at = now()
         where id = $1 returning *",
    )
    .bind(id)
    .bind(ok)
    .bind(error)
    .bind(payload_digest)
    .bind(retry_in_secs as f64)
    .bind(max_attempts)
    .fetch_optional(pool)
    .await
}

pub async fn list_session_deliveries(
    pool: &PgPool,
    session: Uuid,
) -> sqlx::Result<Vec<ResultDeliveryRow>> {
    sqlx::query_as("select * from result_deliveries where session_id = $1 order by created_at")
        .bind(session)
        .fetch_all(pool)
        .await
}

pub async fn list_subscription_deliveries(
    pool: &PgPool,
    subscription: Uuid,
    limit: i64,
) -> sqlx::Result<Vec<ResultDeliveryRow>> {
    sqlx::query_as(
        "select * from result_deliveries where subscription_id = $1
         order by created_at desc limit $2",
    )
    .bind(subscription)
    .bind(limit)
    .fetch_all(pool)
    .await
}

pub async fn create_trigger_token(
    pool: &PgPool,
    tenant: Uuid,
    subscription: Uuid,
    token_plain: &str,
) -> sqlx::Result<()> {
    sqlx::query(
        "insert into api_tokens (id, tenant_id, kind, subscription_id, token_sha256)
         values ($1, $2, 'trigger', $3, $4)",
    )
    .bind(Uuid::now_v7())
    .bind(tenant)
    .bind(subscription)
    .bind(sha256_hex(token_plain))
    .execute(pool)
    .await?;
    Ok(())
}

/// Resolves a scoped trigger token to its subscription. This is the entire
/// authority of the token — it can never satisfy Admin or SessionAuth.
pub async fn subscription_for_token(
    pool: &PgPool,
    token_plain: &str,
) -> sqlx::Result<Option<Uuid>> {
    let row = sqlx::query(
        "select subscription_id from api_tokens
         where kind = 'trigger' and token_sha256 = $1
           and revoked_at is null
           and (expires_at is null or expires_at > now())",
    )
    .bind(sha256_hex(token_plain))
    .fetch_optional(pool)
    .await?;
    Ok(row.and_then(|r| r.get::<Option<Uuid>, _>("subscription_id")))
}

/// Rotation support: kill every live token for the subscription.
pub async fn revoke_trigger_tokens(pool: &PgPool, subscription: Uuid) -> sqlx::Result<u64> {
    let res = sqlx::query(
        "update api_tokens set revoked_at = now()
         where kind = 'trigger' and subscription_id = $1 and revoked_at is null",
    )
    .bind(subscription)
    .execute(pool)
    .await?;
    Ok(res.rows_affected())
}

// ─── LISTEN/NOTIFY wakeup hub ─────────────────────────────────────────────

/// Spawns the notify listener with a reconnect loop. Payloads are
/// (session_id, seq). Delivery is best-effort by design — every consumer
/// polls the seq catch-up query as the source of truth.
pub fn spawn_listener(database_url: String) -> tokio::sync::broadcast::Sender<(Uuid, i64)> {
    let (tx, _) = tokio::sync::broadcast::channel::<(Uuid, i64)>(1024);
    let tx2 = tx.clone();
    tokio::spawn(async move {
        loop {
            match PgListener::connect(&database_url).await {
                Ok(mut listener) => {
                    if listener.listen("fluidbox_events").await.is_err() {
                        tokio::time::sleep(std::time::Duration::from_secs(3)).await;
                        continue;
                    }
                    tracing::info!("pg listener connected");
                    loop {
                        match listener.recv().await {
                            Ok(n) => {
                                if let Some((sid, seq)) = n.payload().split_once(':') {
                                    if let (Ok(sid), Ok(seq)) =
                                        (Uuid::parse_str(sid), seq.parse::<i64>())
                                    {
                                        let _ = tx2.send((sid, seq));
                                    }
                                }
                            }
                            Err(e) => {
                                tracing::warn!("pg listener dropped: {e}; reconnecting");
                                break;
                            }
                        }
                    }
                }
                Err(e) => {
                    tracing::warn!("pg listener connect failed: {e}; retrying");
                }
            }
            tokio::time::sleep(std::time::Duration::from_secs(3)).await;
        }
    });
    tx
}

// ─── Integration test (runs only when DATABASE_URL is set) ───────────────

#[cfg(test)]
mod tests {
    use super::*;
    use fluidbox_core::event::{Actor, EventBody, EventEnvelope, Redactor};

    #[tokio::test]
    async fn append_event_assigns_gapless_seq_and_notifies() {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("skipping: DATABASE_URL not set");
            return;
        };
        let pool = connect(&url).await.expect("connect");
        let tenant = ensure_default_tenant(&pool).await.unwrap();

        let policy = upsert_policy(
            &pool,
            tenant,
            "test-seq",
            "name: test-seq",
            &serde_json::json!({"name": "test-seq"}),
        )
        .await
        .unwrap();
        let agent = create_agent(&pool, tenant, "test-seq-agent", None)
            .await
            .unwrap();
        let rev = append_agent_revision(
            &pool,
            agent.id,
            "claude-agent-sdk",
            "img:test",
            "claude-haiku-4-5",
            None,
            policy.id,
            &serde_json::json!({}),
            None,
        )
        .await
        .unwrap();
        let session = create_session(
            &pool,
            tenant,
            agent.id,
            rev.id,
            "supervised",
            "t",
            &serde_json::json!({"kind":"none"}),
            &serde_json::json!({}),
            &serde_json::json!({}),
            None,
        )
        .await
        .unwrap();

        let mut listener = PgListener::connect(&url).await.unwrap();
        listener.listen("fluidbox_events").await.unwrap();

        let redactor = Redactor::default();
        let mut seqs = Vec::new();
        for i in 0..3 {
            let env = EventEnvelope::new(
                session.id,
                Actor::System,
                EventBody::AgentMessage {
                    role: "assistant".into(),
                    text: format!("m{i}"),
                },
            );
            seqs.push(append_event(&pool, redactor.scrub(env)).await.unwrap());
        }
        assert_eq!(seqs, vec![1, 2, 3]);

        let n = tokio::time::timeout(std::time::Duration::from_secs(5), listener.recv())
            .await
            .expect("notify within 5s")
            .expect("notify ok");
        assert!(n.payload().starts_with(&session.id.to_string()));

        let events = events_after(&pool, session.id, 0, 10).await.unwrap();
        assert_eq!(events.len(), 3);
        assert_eq!(events[0].r#type, "agent.message");
    }

    #[tokio::test]
    async fn stale_nonstarted_sweep_finds_only_old_prelaunch_sessions() {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("skipping: DATABASE_URL not set");
            return;
        };
        let pool = connect(&url).await.expect("connect");
        let tenant = ensure_default_tenant(&pool).await.unwrap();
        let policy = upsert_policy(
            &pool,
            tenant,
            "test-stale",
            "name: test-stale",
            &serde_json::json!({"name": "test-stale"}),
        )
        .await
        .unwrap();
        let agent = create_agent(&pool, tenant, "test-stale-agent", None)
            .await
            .unwrap();
        let rev = append_agent_revision(
            &pool,
            agent.id,
            "claude-agent-sdk",
            "img:test",
            "claude-haiku-4-5",
            None,
            policy.id,
            &serde_json::json!({}),
            None,
        )
        .await
        .unwrap();
        let repo = serde_json::json!({"kind":"none"});
        let empty = serde_json::json!({});
        let fresh = create_session(
            &pool,
            tenant,
            agent.id,
            rev.id,
            "supervised",
            "stale-test fresh",
            &repo,
            &empty,
            &empty,
            None,
        )
        .await
        .unwrap();
        let stale = create_session(
            &pool,
            tenant,
            agent.id,
            rev.id,
            "supervised",
            "stale-test old",
            &repo,
            &empty,
            &empty,
            None,
        )
        .await
        .unwrap();
        sqlx::query("update sessions set updated_at = now() - interval '20 minutes' where id = $1")
            .bind(stale.id)
            .execute(&pool)
            .await
            .unwrap();

        let ids: Vec<Uuid> = stale_nonstarted_sessions(&pool, 15)
            .await
            .unwrap()
            .iter()
            .map(|s| s.id)
            .collect();
        assert!(ids.contains(&stale.id), "old created session must be swept");
        assert!(!ids.contains(&fresh.id), "fresh session must not be swept");

        // Terminal sessions are never swept even when old.
        use fluidbox_core::state::SessionStatus;
        transition_session(&pool, stale.id, SessionStatus::Failed, Some("test"))
            .await
            .unwrap();
        sqlx::query("update sessions set updated_at = now() - interval '20 minutes' where id = $1")
            .bind(stale.id)
            .execute(&pool)
            .await
            .unwrap();
        let ids: Vec<Uuid> = stale_nonstarted_sessions(&pool, 15)
            .await
            .unwrap()
            .iter()
            .map(|s| s.id)
            .collect();
        assert!(
            !ids.contains(&stale.id),
            "terminal session must not be swept"
        );

        for id in [fresh.id, stale.id] {
            sqlx::query("delete from sessions where id = $1")
                .bind(id)
                .execute(&pool)
                .await
                .unwrap();
        }
    }

    #[tokio::test]
    async fn connection_lifecycle_and_credential_isolation() {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("skipping: DATABASE_URL not set");
            return;
        };
        let pool = connect(&url).await.expect("connect");
        let tenant = ensure_default_tenant(&pool).await.unwrap();

        let sealed = b"nonce||ciphertext-not-a-real-secret".to_vec();
        let conn = create_connection(
            &pool,
            tenant,
            "github",
            "test-account-42",
            "test-connection",
            &sealed,
            &serde_json::json!(["repo"]),
            &serde_json::json!({}),
            &serde_json::json!({"test": true}),
        )
        .await
        .unwrap();

        // The row type/serialization can never leak the credential.
        let as_json = serde_json::to_value(&conn).unwrap();
        assert!(as_json.get("credential_sealed").is_none());
        assert!(!serde_json::to_string(&as_json)
            .unwrap()
            .contains("ciphertext-not-a-real-secret"));

        // Active connection yields the sealed bytes.
        let got = connection_credential_sealed(&pool, conn.id)
            .await
            .unwrap()
            .expect("active connection has credential");
        assert_eq!(got, sealed);

        // Revocation is terminal for credential access.
        let revoked = revoke_connection(&pool, conn.id).await.unwrap().unwrap();
        assert_eq!(revoked.status, "revoked");
        assert!(connection_credential_sealed(&pool, conn.id)
            .await
            .unwrap()
            .is_none());
        // Idempotent second revoke: no row to update.
        assert!(revoke_connection(&pool, conn.id).await.unwrap().is_none());

        sqlx::query("delete from integration_connections where id = $1")
            .bind(conn.id)
            .execute(&pool)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn trigger_subscription_lifecycle_token_and_secret_isolation() {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("skipping: DATABASE_URL not set");
            return;
        };
        let pool = connect(&url).await.expect("connect");
        let tenant = ensure_default_tenant(&pool).await.unwrap();
        let policy = upsert_policy(
            &pool,
            tenant,
            "test-trig",
            "name: test-trig",
            &serde_json::json!({"name": "test-trig"}),
        )
        .await
        .unwrap();
        let agent = create_agent(&pool, tenant, "test-trig-agent", None)
            .await
            .unwrap();
        let _rev = append_agent_revision(
            &pool,
            agent.id,
            "claude-agent-sdk",
            "img:test",
            "claude-haiku-4-5",
            None,
            policy.id,
            &serde_json::json!({}),
            None,
        )
        .await
        .unwrap();

        let sealed = b"nonce||not-a-real-secret".to_vec();
        let sub = create_trigger_subscription(
            &pool,
            tenant,
            agent.id,
            "test-sub",
            "api",
            None,
            Some("Investigate {{ticket}}"),
            false,
            false,
            None,
            None,
            None,
            &serde_json::json!([{"kind": "signed_webhook", "url": "http://127.0.0.1:1/cb"}]),
            Some(&sealed),
        )
        .await
        .unwrap();
        assert!(sub.enabled);
        assert!(!sub.allow_task_override);

        // Row serialization can never leak the sealed secret.
        let as_json = serde_json::to_value(&sub).unwrap();
        assert!(as_json.get("callback_secret_sealed").is_none());

        // The single secret reader returns the sealed bytes.
        let got = subscription_callback_secret_sealed(&pool, sub.id)
            .await
            .unwrap();
        assert_eq!(got, Some(sealed));

        // Trigger tokens: hashed at rest, resolvable, revocable.
        create_trigger_token(&pool, tenant, sub.id, "fbx_trig_testtoken123")
            .await
            .unwrap();
        assert_eq!(
            subscription_for_token(&pool, "fbx_trig_testtoken123")
                .await
                .unwrap(),
            Some(sub.id)
        );
        assert_eq!(
            subscription_for_token(&pool, "fbx_trig_wrong")
                .await
                .unwrap(),
            None
        );
        let revoked = revoke_trigger_tokens(&pool, sub.id).await.unwrap();
        assert_eq!(revoked, 1);
        assert_eq!(
            subscription_for_token(&pool, "fbx_trig_testtoken123")
                .await
                .unwrap(),
            None
        );

        // Enable toggle.
        let off = set_trigger_subscription_enabled(&pool, sub.id, false)
            .await
            .unwrap()
            .unwrap();
        assert!(!off.enabled);

        sqlx::query("delete from trigger_subscriptions where id = $1")
            .bind(sub.id)
            .execute(&pool)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn invocation_claims_are_idempotent_by_key() {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("skipping: DATABASE_URL not set");
            return;
        };
        let pool = connect(&url).await.expect("connect");
        let tenant = ensure_default_tenant(&pool).await.unwrap();
        let policy = upsert_policy(
            &pool,
            tenant,
            "test-idem",
            "name: test-idem",
            &serde_json::json!({"name": "test-idem"}),
        )
        .await
        .unwrap();
        let agent = create_agent(&pool, tenant, "test-idem-agent", None)
            .await
            .unwrap();
        let rev = append_agent_revision(
            &pool,
            agent.id,
            "claude-agent-sdk",
            "img:test",
            "claude-haiku-4-5",
            None,
            policy.id,
            &serde_json::json!({}),
            None,
        )
        .await
        .unwrap();
        let sub = create_trigger_subscription(
            &pool,
            tenant,
            agent.id,
            "test-idem-sub",
            "api",
            None,
            Some("t"),
            false,
            false,
            None,
            None,
            None,
            &serde_json::json!([]),
            None,
        )
        .await
        .unwrap();

        // First claim wins.
        let c1 = claim_invocation(&pool, sub.id, "key-1", "digest-a")
            .await
            .unwrap();
        let InvocationClaim::Claimed { invocation_id } = c1 else {
            panic!("wanted Claimed, got {c1:?}")
        };

        // Same key while unbound → InFlight (a concurrent retry must wait).
        assert!(matches!(
            claim_invocation(&pool, sub.id, "key-1", "digest-a")
                .await
                .unwrap(),
            InvocationClaim::InFlight
        ));

        // Bind to a real session, then the same key replays that session.
        let session = create_session(
            &pool,
            tenant,
            agent.id,
            rev.id,
            "supervised",
            "t",
            &serde_json::json!({"kind":"scratch"}),
            &serde_json::json!({}),
            &serde_json::json!({}),
            Some(&serde_json::json!({"kind":"api"})),
        )
        .await
        .unwrap();
        assert_eq!(session.trigger, Some(serde_json::json!({"kind":"api"})));
        bind_invocation(&pool, invocation_id, session.id)
            .await
            .unwrap();
        let c3 = claim_invocation(&pool, sub.id, "key-1", "digest-a")
            .await
            .unwrap();
        match c3 {
            InvocationClaim::Replay {
                session_id,
                request_digest,
            } => {
                assert_eq!(session_id, session.id);
                assert_eq!(request_digest, "digest-a");
            }
            other => panic!("wanted Replay, got {other:?}"),
        }

        // A released (failed-creation) claim frees the key immediately.
        let c4 = claim_invocation(&pool, sub.id, "key-2", "digest-b")
            .await
            .unwrap();
        let InvocationClaim::Claimed {
            invocation_id: inv2,
        } = c4
        else {
            panic!()
        };
        release_invocation(&pool, inv2).await.unwrap();
        assert!(matches!(
            claim_invocation(&pool, sub.id, "key-2", "digest-b")
                .await
                .unwrap(),
            InvocationClaim::Claimed { .. }
        ));

        assert!(subscription_owns_session(&pool, sub.id, session.id)
            .await
            .unwrap());
        let listed = list_subscription_sessions(&pool, sub.id, 10).await.unwrap();
        assert!(listed.iter().any(|s| s.id == session.id));

        sqlx::query("delete from sessions where id = $1")
            .bind(session.id)
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("delete from trigger_subscriptions where id = $1")
            .bind(sub.id)
            .execute(&pool)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn result_delivery_attempt_state_machine() {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("skipping: DATABASE_URL not set");
            return;
        };
        let pool = connect(&url).await.expect("connect");
        let tenant = ensure_default_tenant(&pool).await.unwrap();
        let policy = upsert_policy(
            &pool,
            tenant,
            "test-del",
            "name: test-del",
            &serde_json::json!({"name": "test-del"}),
        )
        .await
        .unwrap();
        let agent = create_agent(&pool, tenant, "test-del-agent", None)
            .await
            .unwrap();
        let rev = append_agent_revision(
            &pool,
            agent.id,
            "claude-agent-sdk",
            "img:test",
            "claude-haiku-4-5",
            None,
            policy.id,
            &serde_json::json!({}),
            None,
        )
        .await
        .unwrap();
        let session = create_session(
            &pool,
            tenant,
            agent.id,
            rev.id,
            "supervised",
            "t",
            &serde_json::json!({"kind":"scratch"}),
            &serde_json::json!({}),
            &serde_json::json!({}),
            None,
        )
        .await
        .unwrap();

        let dest = serde_json::json!({"kind": "signed_webhook", "url": "http://127.0.0.1:1/cb"});
        let d = enqueue_result_delivery(&pool, session.id, None, &dest)
            .await
            .unwrap();
        assert_eq!(d.status, "pending");
        assert_eq!(d.attempts, 0);

        // Due immediately.
        let due = due_result_deliveries(&pool, 10).await.unwrap();
        assert!(due.iter().any(|x| x.id == d.id));

        // Failure → still pending, attempts=1, pushed into the future (not due).
        let after =
            mark_delivery_attempt(&pool, d.id, false, Some("connection refused"), None, 30, 3)
                .await
                .unwrap()
                .unwrap();
        assert_eq!((after.status.as_str(), after.attempts), ("pending", 1));
        assert!(!due_result_deliveries(&pool, 50)
            .await
            .unwrap()
            .iter()
            .any(|x| x.id == d.id));

        // Exhausting attempts → failed, terminal for the delivery only.
        mark_delivery_attempt(&pool, d.id, false, Some("refused"), None, 30, 3)
            .await
            .unwrap();
        let last = mark_delivery_attempt(&pool, d.id, false, Some("refused"), None, 30, 3)
            .await
            .unwrap()
            .unwrap();
        assert_eq!((last.status.as_str(), last.attempts), ("failed", 3));

        // Success path on a second delivery.
        let d2 = enqueue_result_delivery(&pool, session.id, None, &dest)
            .await
            .unwrap();
        let okd = mark_delivery_attempt(&pool, d2.id, true, None, Some("sha256:x"), 0, 3)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(okd.status, "delivered");
        assert!(okd.delivered_at.is_some());
        assert_eq!(okd.payload_digest.as_deref(), Some("sha256:x"));

        let listed = list_session_deliveries(&pool, session.id).await.unwrap();
        assert_eq!(listed.len(), 2);

        sqlx::query("delete from sessions where id = $1")
            .bind(session.id)
            .execute(&pool)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn revision_default_workspace_roundtrips() {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("skipping: DATABASE_URL not set");
            return;
        };
        let pool = connect(&url).await.expect("connect");
        let tenant = ensure_default_tenant(&pool).await.unwrap();
        let policy = upsert_policy(
            &pool,
            tenant,
            "test-ws",
            "name: test-ws",
            &serde_json::json!({"name": "test-ws"}),
        )
        .await
        .unwrap();
        let agent = create_agent(&pool, tenant, "test-ws-agent", None)
            .await
            .unwrap();

        let ws = serde_json::json!({
            "kind": "git_repository",
            "clone_url": "https://github.com/o/r.git",
            "ref": "main"
        });
        let rev = append_agent_revision(
            &pool,
            agent.id,
            "claude-agent-sdk",
            "img:test",
            "claude-haiku-4-5",
            None,
            policy.id,
            &serde_json::json!({}),
            Some(&ws),
        )
        .await
        .unwrap();
        assert_eq!(rev.default_workspace, Some(ws));

        // A revision without one stays None.
        let rev2 = append_agent_revision(
            &pool,
            agent.id,
            "claude-agent-sdk",
            "img:test",
            "claude-haiku-4-5",
            None,
            policy.id,
            &serde_json::json!({}),
            None,
        )
        .await
        .unwrap();
        assert!(rev2.default_workspace.is_none());

        sqlx::query("delete from agent_revisions where agent_id = $1")
            .bind(agent.id)
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("delete from agents where id = $1")
            .bind(agent.id)
            .execute(&pool)
            .await
            .unwrap();
    }
}
