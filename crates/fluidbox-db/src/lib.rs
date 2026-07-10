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
    pub created_at: DateTime<Utc>,
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
) -> sqlx::Result<AgentRevisionRow> {
    sqlx::query_as(
        "insert into agent_revisions
           (id, agent_id, rev, harness, runner_image, model, system_prompt, policy_id, budgets)
         values ($1, $2,
           coalesce((select max(rev) from agent_revisions where agent_id = $2), 0) + 1,
           $3, $4, $5, $6, $7, $8)
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
) -> sqlx::Result<SessionRow> {
    sqlx::query_as(
        "insert into sessions
           (id, tenant_id, agent_id, agent_revision_id, autonomy, task, repo_source, run_spec, budgets)
         values ($1,$2,$3,$4,$5,$6,$7,$8,$9)
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
}
