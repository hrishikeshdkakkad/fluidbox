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

pub mod identity;
pub mod seed;
pub mod system_worker;

/// A verified tenant context. Constructible ONLY via [`TenantScope::assume`],
/// which a caller may invoke only when it holds — or has just resolved — a
/// verified tenant identity: an authenticated principal's own tenant, or a
/// `tenant_id` read back from a DB row. The non-principal constructions are a
/// closed, documented set (design doc
/// `docs/plans/2026-07-17-idp-agnostic-identity-design.md`): (a) verified-
/// credential resolution — the two credential-like exceptions, keyed purely on
/// a secret digest (session/PAT token sha256; the pending-switch confirmation-
/// cookie hash); (b) DB-resolved worker rows (the `system_worker` cross-tenant
/// scans, each row carrying its own `tenant_id`); (c) design-mandated pre-auth
/// surfaces that expose no tenant-owned resource — slug → org routing for
/// login-flow creation only, and the operator org-CRUD endpoints; (d) the boot
/// seed. Every identity repository takes it right after the executor and
/// carries its id into a `tenant_id = $n` predicate, so tenant isolation is a
/// signature requirement, not a remember-to-filter convention.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TenantScope(Uuid);

impl TenantScope {
    /// Assert a verified tenant context. See the type docs for the documented
    /// set of constructions permitted to do so — do NOT call this with a
    /// tenant id the browser supplied.
    pub fn assume(tenant_id: Uuid) -> Self {
        Self(tenant_id)
    }

    pub fn tenant_id(&self) -> Uuid {
        self.0
    }
}

/// Who owns a connection (design :274-296). `Organization` connections are
/// visible to every member; `User` connections are one member's personal
/// custody. github_app connections are ALWAYS `Organization`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionOwner {
    Organization,
    User(Uuid),
}

impl ConnectionOwner {
    /// (owner_type, owner_user_id) as stamped into the row.
    fn parts(&self) -> (&'static str, Option<Uuid>) {
        match self {
            ConnectionOwner::Organization => ("organization", None),
            ConnectionOwner::User(id) => ("user", Some(*id)),
        }
    }
}

/// The visibility lens for a connection listing (design :274-296): `All` sees
/// every connection in the tenant (operator / admin); `User` sees org-owned
/// connections plus only its OWN personal connections.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionViewer {
    All,
    User(Uuid),
}

impl ConnectionViewer {
    /// The user id whose personal rows are visible, or None for `All` — bound
    /// into the `$n is null or owner_type='organization' or owner_user_id=$n`
    /// predicate.
    fn user_id(&self) -> Option<Uuid> {
        match self {
            ConnectionViewer::All => None,
            ConnectionViewer::User(id) => Some(*id),
        }
    }
}

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
    /// The EFFECTIVE policy: base yaml ++ `managed_overrides`. This — not
    /// `managed_overrides` — is what `run_service` freezes into a RunSpec, so
    /// every write to the overrides column must republish this.
    pub parsed: Value,
    /// UI-owned per-tool decisions (`Vec<fluidbox_core::policy::ToolOverride>`),
    /// kept out of the git-owned `yaml_source`. See migration 0010.
    pub managed_overrides: Value,
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
    /// Brokered connection requirements (design :349-389): a validated
    /// `Vec<ConnectionRequirement>` jsonb (slot / connector / tools / mode).
    /// Append-only with the revision; validated app-side, never an FK
    /// (agent_revisions has no tenant column). Defaults to `[]`.
    pub connection_requirements: Value,
    pub created_at: DateTime<Utc>,
}

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

/// Deliberately has NO credential fields: every query selects the explicit
/// `CONNECTION_COLS` list, so the sealed credential / client secret can
/// never ride along into an API response or log.
/// `connection_credential_sealed` / `connection_client_secret_sealed` are
/// the only readers. `oauth` carries NON-secret custody state (endpoints,
/// client identity, scopes, error note).
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
    pub auth_kind: String,
    pub oauth: Option<Value>,
    /// Typed custody linkage for seamless github_app connections: the pem +
    /// webhook secret live on the registration. NULL = legacy per-connection
    /// custody. Resolution fails closed — never falls back across kinds.
    pub registration_id: Option<Uuid>,
    /// Ownership (design :274-296): `organization` (visible to every member) or
    /// `user` (one member's personal custody); `owner_user_id` is set iff
    /// `owner_type='user'`. `created_by_user_id` records who connected it (null
    /// for system/admin-created rows). `authorization_generation` bumps on every
    /// re-consent/rotation so stale run bindings fail closed.
    pub owner_type: String,
    pub owner_user_id: Option<Uuid>,
    pub created_by_user_id: Option<Uuid>,
    pub authorization_generation: i32,
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
    /// Who invoked this run (design "tenant/user audit fields"): the invocation
    /// class, and the authenticated user id when one exists (None for
    /// operator-token / trigger / schedule / webhook). Drives run visibility.
    pub invoked_by_kind: Option<String>,
    pub invoked_by_user_id: Option<Uuid>,
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
    pub input_digest: Option<String>,
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
    // Migration 0012 made `slug` NOT NULL; the boot tenant owns slug 'default'.
    // On a live DB the migration backfilled it already — this keeps a fresh DB
    // and any hand-edited row converged.
    let row = sqlx::query(
        "insert into tenants (id, name, slug) values ($1, 'default', 'default')
         on conflict (name) do update set slug = excluded.slug
         returning id",
    )
    .bind(id)
    .fetch_one(pool)
    .await?;
    Ok(row.get("id"))
}

// ─── Policies ─────────────────────────────────────────────────────────────

/// Upsert a policy's AUTHORED yaml. Existing `managed_overrides` are preserved
/// and merged back into `parsed` — without this, the next `just policy-sync`
/// would silently drop every decision made in the Governance page.
///
/// Storage primitive: it merges, it does not judge. A caller that changes the
/// base rules under an existing override must `Policy::validate()` the merged
/// result BEFORE calling (the API layer does), because an override targeting a
/// rule that just grew `paths`/`shell` is invalid and cannot be caught here —
/// `fluidbox-db` has no error type to refuse with.
pub async fn upsert_policy(
    pool: &PgPool,
    scope: TenantScope,
    name: &str,
    yaml_source: &str,
    parsed: &Value,
) -> sqlx::Result<PolicyRow> {
    sqlx::query_as(
        "insert into policies (id, tenant_id, name, yaml_source, parsed)
         values ($1, $2, $3, $4, $5)
         on conflict (tenant_id, name) do update
           set yaml_source = excluded.yaml_source,
               parsed = jsonb_set(
                 excluded.parsed, '{managed_overrides}', policies.managed_overrides, true
               ),
               version = policies.version + 1,
               updated_at = now()
         returning *",
    )
    .bind(Uuid::now_v7())
    .bind(scope.tenant_id())
    .bind(name)
    .bind(yaml_source)
    .bind(parsed)
    .fetch_one(pool)
    .await
}

/// Upsert ONE exact-name override, replacing any existing decision for that
/// tool. Bumps `version` and republishes `parsed`.
pub async fn set_policy_override(
    pool: &PgPool,
    scope: TenantScope,
    name: &str,
    tool: &str,
    action: fluidbox_core::policy::RuleAction,
) -> sqlx::Result<PolicyRow> {
    let entry = serde_json::json!([{ "tool": tool, "action": action }]);
    write_policy_overrides(pool, scope, name, tool, &entry).await
}

/// Remove ONE override; the tool falls back to whatever the base rules say.
/// Bumps `version` and republishes `parsed`.
pub async fn clear_policy_override(
    pool: &PgPool,
    scope: TenantScope,
    name: &str,
    tool: &str,
) -> sqlx::Result<PolicyRow> {
    write_policy_overrides(pool, scope, name, tool, &serde_json::json!([])).await
}

/// Drop every override for `tool`, then append `append` (a jsonb ARRAY — one
/// entry to set, empty to clear). Set and clear are the same write: filter out
/// the tool's old decision, optionally add the new one.
///
/// ONE statement, because `parsed` and `managed_overrides` disagreeing — even
/// between two round-trips — means a run evaluating a policy that no longer
/// exists. `run_service` reads `parsed`; an override written only to the column
/// would look saved in the UI and never fire.
async fn write_policy_overrides(
    pool: &PgPool,
    scope: TenantScope,
    name: &str,
    tool: &str,
    append: &Value,
) -> sqlx::Result<PolicyRow> {
    sqlx::query_as(
        "with target as (
           select id,
                  coalesce(
                    (select jsonb_agg(e)
                       from jsonb_array_elements(managed_overrides) e
                      where e->>'tool' <> $3),
                    '[]'::jsonb
                  ) || $4::jsonb as overrides
             from policies
            where tenant_id = $1 and name = $2
         )
         update policies p
            set managed_overrides = t.overrides,
                parsed = jsonb_set(p.parsed, '{managed_overrides}', t.overrides, true),
                version = p.version + 1,
                updated_at = now()
           from target t
          where p.id = t.id
         returning p.*",
    )
    .bind(scope.tenant_id())
    .bind(name)
    .bind(tool)
    .bind(append)
    .fetch_one(pool)
    .await
}

/// Bootstrap a policy from a seed file only if it does not already exist.
/// Returns the existing or newly-inserted row — so UI edits (which bump the
/// version) are never clobbered by a later boot re-reading the disk YAML.
pub async fn seed_policy_if_absent(
    pool: &PgPool,
    scope: TenantScope,
    name: &str,
    yaml_source: &str,
    parsed: &Value,
) -> sqlx::Result<(PolicyRow, bool)> {
    if let Some(existing) = get_policy_by_name(pool, scope, name).await? {
        return Ok((existing, false));
    }
    let row = sqlx::query_as(
        "insert into policies (id, tenant_id, name, yaml_source, parsed)
         values ($1, $2, $3, $4, $5)
         on conflict (tenant_id, name) do update set name = excluded.name
         returning *",
    )
    .bind(Uuid::now_v7())
    .bind(scope.tenant_id())
    .bind(name)
    .bind(yaml_source)
    .bind(parsed)
    .fetch_one(pool)
    .await?;
    Ok((row, true))
}

pub async fn list_policies(pool: &PgPool, scope: TenantScope) -> sqlx::Result<Vec<PolicyRow>> {
    sqlx::query_as("select * from policies where tenant_id = $1 order by name")
        .bind(scope.tenant_id())
        .fetch_all(pool)
        .await
}

pub async fn get_policy(
    pool: &PgPool,
    scope: TenantScope,
    id: Uuid,
) -> sqlx::Result<Option<PolicyRow>> {
    sqlx::query_as("select * from policies where id = $1 and tenant_id = $2")
        .bind(id)
        .bind(scope.tenant_id())
        .fetch_optional(pool)
        .await
}

pub async fn get_policy_by_name(
    pool: &PgPool,
    scope: TenantScope,
    name: &str,
) -> sqlx::Result<Option<PolicyRow>> {
    sqlx::query_as("select * from policies where tenant_id = $1 and name = $2")
        .bind(scope.tenant_id())
        .bind(name)
        .fetch_optional(pool)
        .await
}

/// Agents whose LATEST revision uses this policy — the blast radius an override
/// header must state. An older revision pointing here does not count: only the
/// latest revision governs future runs, so only it is at stake in an edit.
pub async fn policy_agents_using(
    pool: &PgPool,
    scope: TenantScope,
    policy_id: Uuid,
) -> sqlx::Result<i64> {
    sqlx::query_scalar(
        "select count(*) from agents a
          where a.tenant_id = $1
            and (
              select r.policy_id from agent_revisions r
               where r.agent_id = a.id
               order by r.rev desc
               limit 1
            ) = $2",
    )
    .bind(scope.tenant_id())
    .bind(policy_id)
    .fetch_one(pool)
    .await
}

/// The union of `mcp__<server>__<tool>` names from the capability bundles pinned
/// on the LATEST revision of every agent using this policy. This is what makes a
/// connected server's photographed tools appear in the matrix without anyone
/// typing them. Sorted and deduplicated: two agents may pin the same bundle.
///
/// Reads the pins' bundle ids rather than resolving `name`/`version` — the pin is
/// exact by construction (§17 #7), so the id IS the photograph the frozen RunSpec
/// will carry.
pub async fn policy_mcp_tools(
    pool: &PgPool,
    scope: TenantScope,
    policy_id: Uuid,
) -> sqlx::Result<Vec<String>> {
    let pins: Vec<Value> = sqlx::query_scalar(
        "select r.capability_bundles from agents a
           join lateral (
             select * from agent_revisions r2
              where r2.agent_id = a.id order by r2.rev desc limit 1
           ) r on true
          where a.tenant_id = $1 and r.policy_id = $2",
    )
    .bind(scope.tenant_id())
    .bind(policy_id)
    .fetch_all(pool)
    .await?;

    let mut ids: Vec<Uuid> = Vec::new();
    for p in &pins {
        let Some(arr) = p.as_array() else { continue };
        for r in arr {
            if let Some(id) = r
                .get("id")
                .and_then(|v| v.as_str())
                .and_then(|s| s.parse().ok())
            {
                ids.push(id);
            }
        }
    }
    ids.sort_unstable();
    ids.dedup();
    if ids.is_empty() {
        return Ok(vec![]);
    }

    // Tenant-scoped: a pin can never reach across a tenant boundary.
    let defs: Vec<Value> = sqlx::query_scalar(
        "select definition from capability_bundles where tenant_id = $1 and id = any($2)",
    )
    .bind(scope.tenant_id())
    .bind(&ids)
    .fetch_all(pool)
    .await?;

    let mut out: Vec<String> = Vec::new();
    for def in &defs {
        let Some(servers) = def.get("servers").and_then(|v| v.as_array()) else {
            continue;
        };
        for s in servers {
            let Some(server) = s.get("name").and_then(|v| v.as_str()) else {
                continue;
            };
            let Some(tools) = s.get("tools").and_then(|v| v.as_array()) else {
                continue;
            };
            for t in tools {
                if let Some(tool) = t.get("name").and_then(|v| v.as_str()) {
                    out.push(format!("mcp__{server}__{tool}"));
                }
            }
        }
    }
    out.sort_unstable();
    out.dedup();
    Ok(out)
}

// ─── Agents & revisions ───────────────────────────────────────────────────

pub async fn create_agent(
    pool: &PgPool,
    scope: TenantScope,
    name: &str,
    description: Option<&str>,
) -> sqlx::Result<AgentRow> {
    sqlx::query_as(
        "insert into agents (id, tenant_id, name, description) values ($1,$2,$3,$4)
         on conflict (tenant_id, name) do update set description = excluded.description
         returning *",
    )
    .bind(Uuid::now_v7())
    .bind(scope.tenant_id())
    .bind(name)
    .bind(description)
    .fetch_one(pool)
    .await
}

pub async fn list_agents(pool: &PgPool, scope: TenantScope) -> sqlx::Result<Vec<AgentRow>> {
    sqlx::query_as("select * from agents where tenant_id = $1 order by name")
        .bind(scope.tenant_id())
        .fetch_all(pool)
        .await
}

pub async fn get_agent(
    pool: &PgPool,
    scope: TenantScope,
    id: Uuid,
) -> sqlx::Result<Option<AgentRow>> {
    sqlx::query_as("select * from agents where id = $1 and tenant_id = $2")
        .bind(id)
        .bind(scope.tenant_id())
        .fetch_optional(pool)
        .await
}

pub async fn get_agent_by_name(
    pool: &PgPool,
    scope: TenantScope,
    name: &str,
) -> sqlx::Result<Option<AgentRow>> {
    sqlx::query_as("select * from agents where tenant_id = $1 and name = $2")
        .bind(scope.tenant_id())
        .bind(name)
        .fetch_optional(pool)
        .await
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
) -> sqlx::Result<AgentRevisionRow> {
    // Revisions carry no tenant column of their own; the tenant boundary is the
    // parent agent — the insert only lands when the agent AND the referenced
    // policy both belong to the scope (a cross-tenant policy_id is proven
    // impossible in SQL, not just Rust-side). Zero rows → RowNotFound (the
    // existing contract for a not-in-scope agent), which callers already map to
    // a 404. `connection_requirements` is validated app-side (Task 2) before it
    // reaches here.
    sqlx::query_as(
        "insert into agent_revisions
           (id, agent_id, rev, harness, runner_image, model, system_prompt, policy_id, budgets,
            default_workspace, capability_bundles, connection_requirements)
         select $1, $2,
           coalesce((select max(rev) from agent_revisions where agent_id = $2), 0) + 1,
           $3, $4, $5, $6, $7, $8, $9, $10, $11
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
    .bind(scope.tenant_id())
    .fetch_one(pool)
    .await
}

pub async fn latest_revision(
    pool: &PgPool,
    scope: TenantScope,
    agent_id: Uuid,
) -> sqlx::Result<Option<AgentRevisionRow>> {
    sqlx::query_as(
        "select r.* from agent_revisions r
         join agents a on a.id = r.agent_id
         where r.agent_id = $1 and a.tenant_id = $2
         order by r.rev desc limit 1",
    )
    .bind(agent_id)
    .bind(scope.tenant_id())
    .fetch_optional(pool)
    .await
}

pub async fn list_revisions(
    pool: &PgPool,
    scope: TenantScope,
    agent_id: Uuid,
) -> sqlx::Result<Vec<AgentRevisionRow>> {
    sqlx::query_as(
        "select r.* from agent_revisions r
         join agents a on a.id = r.agent_id
         where r.agent_id = $1 and a.tenant_id = $2
         order by r.rev desc",
    )
    .bind(agent_id)
    .bind(scope.tenant_id())
    .fetch_all(pool)
    .await
}

pub async fn get_revision(
    pool: &PgPool,
    scope: TenantScope,
    id: Uuid,
) -> sqlx::Result<Option<AgentRevisionRow>> {
    sqlx::query_as(
        "select r.* from agent_revisions r
         join agents a on a.id = r.agent_id
         where r.id = $1 and a.tenant_id = $2",
    )
    .bind(id)
    .bind(scope.tenant_id())
    .fetch_optional(pool)
    .await
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
    sqlx::query_as(
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
    .fetch_one(pool)
    .await
}

pub async fn list_capability_bundles(
    pool: &PgPool,
    scope: TenantScope,
) -> sqlx::Result<Vec<CapabilityBundleRow>> {
    sqlx::query_as(
        "select * from capability_bundles where tenant_id = $1
         order by name, version desc",
    )
    .bind(scope.tenant_id())
    .fetch_all(pool)
    .await
}

pub async fn get_capability_bundle(
    pool: &PgPool,
    scope: TenantScope,
    id: Uuid,
) -> sqlx::Result<Option<CapabilityBundleRow>> {
    sqlx::query_as("select * from capability_bundles where id = $1 and tenant_id = $2")
        .bind(id)
        .bind(scope.tenant_id())
        .fetch_optional(pool)
        .await
}

pub async fn latest_capability_bundle(
    pool: &PgPool,
    scope: TenantScope,
    name: &str,
) -> sqlx::Result<Option<CapabilityBundleRow>> {
    sqlx::query_as(
        "select * from capability_bundles where tenant_id = $1 and name = $2
         order by version desc limit 1",
    )
    .bind(scope.tenant_id())
    .bind(name)
    .fetch_optional(pool)
    .await
}

pub async fn get_capability_bundle_version(
    pool: &PgPool,
    scope: TenantScope,
    name: &str,
    version: i32,
) -> sqlx::Result<Option<CapabilityBundleRow>> {
    sqlx::query_as(
        "select * from capability_bundles
         where tenant_id = $1 and name = $2 and version = $3",
    )
    .bind(scope.tenant_id())
    .bind(name)
    .bind(version)
    .fetch_optional(pool)
    .await
}

// ─── Integration connections ──────────────────────────────────────────────

/// Every connection query selects this explicit column list (never `*`) so
/// the sealed credential / client secret can't ride along into a row.
const CONNECTION_COLS: &str = "id, tenant_id, provider, external_account_id, display_name, \
     granted_scopes, resource_selection, status, metadata, auth_kind, oauth, \
     registration_id, owner_type, owner_user_id, created_by_user_id, \
     authorization_generation, created_at, updated_at";

/// Auth flavor of a new connection. `static` seals the pasted secret now and
/// starts `active`; `oauth` starts `pending` with NO credential — the
/// callback exchange activates it with the sealed rotating refresh token.
pub struct ConnectionAuth<'a> {
    pub auth_kind: &'a str, // static | oauth
    pub status: &'a str,    // active | pending | suspended
    pub oauth: Option<&'a Value>,
    pub client_secret_sealed: Option<&'a [u8]>,
    /// Set only by the seamless github_app flows (custody on the
    /// registration); legacy/manual connections leave it NULL.
    pub registration_id: Option<Uuid>,
}

impl ConnectionAuth<'static> {
    pub fn static_active() -> Self {
        Self {
            auth_kind: "static",
            status: "active",
            oauth: None,
            client_secret_sealed: None,
            registration_id: None,
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub async fn create_connection(
    pool: &PgPool,
    scope: TenantScope,
    provider: &str,
    external_account_id: &str,
    display_name: &str,
    credential_sealed: Option<&[u8]>,
    granted_scopes: &Value,
    resource_selection: &Value,
    metadata: &Value,
    webhook_secret_sealed: Option<&[u8]>,
    auth: ConnectionAuth<'_>,
    owner: ConnectionOwner,
    created_by_user_id: Option<Uuid>,
) -> sqlx::Result<IntegrationConnectionRow> {
    // owner_type/owner_user_id are stamped from `owner`; authorization_generation
    // starts at 1 (the column default) and bumps only on re-consent/rotation.
    let (owner_type, owner_user_id) = owner.parts();
    sqlx::query_as(sqlx::AssertSqlSafe(format!(
        "insert into integration_connections
           (id, tenant_id, provider, external_account_id, display_name, credential_sealed,
            granted_scopes, resource_selection, metadata, webhook_secret_sealed,
            auth_kind, status, oauth, client_secret_sealed, registration_id,
            owner_type, owner_user_id, created_by_user_id)
         values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18)
         returning {CONNECTION_COLS}"
    )))
    .bind(Uuid::now_v7())
    .bind(scope.tenant_id())
    .bind(provider)
    .bind(external_account_id)
    .bind(display_name)
    .bind(credential_sealed)
    .bind(granted_scopes)
    .bind(resource_selection)
    .bind(metadata)
    .bind(webhook_secret_sealed)
    .bind(auth.auth_kind)
    .bind(auth.status)
    .bind(auth.oauth)
    .bind(auth.client_secret_sealed)
    .bind(auth.registration_id)
    .bind(owner_type)
    .bind(owner_user_id)
    .bind(created_by_user_id)
    .fetch_one(pool)
    .await
}

pub async fn list_connections(
    pool: &PgPool,
    scope: TenantScope,
) -> sqlx::Result<Vec<IntegrationConnectionRow>> {
    sqlx::query_as(sqlx::AssertSqlSafe(format!(
        "select {CONNECTION_COLS} from integration_connections
         where tenant_id = $1 order by created_at desc"
    )))
    .bind(scope.tenant_id())
    .fetch_all(pool)
    .await
}

pub async fn get_connection(
    pool: &PgPool,
    scope: TenantScope,
    id: Uuid,
) -> sqlx::Result<Option<IntegrationConnectionRow>> {
    sqlx::query_as(sqlx::AssertSqlSafe(format!(
        "select {CONNECTION_COLS} from integration_connections where id = $1 and tenant_id = $2"
    )))
    .bind(id)
    .bind(scope.tenant_id())
    .fetch_optional(pool)
    .await
}

pub async fn revoke_connection(
    pool: &PgPool,
    scope: TenantScope,
    id: Uuid,
) -> sqlx::Result<Option<IntegrationConnectionRow>> {
    sqlx::query_as(sqlx::AssertSqlSafe(format!(
        "update integration_connections set status = 'revoked', updated_at = now()
         where id = $1 and status <> 'revoked' and tenant_id = $2
         returning {CONNECTION_COLS}"
    )))
    .bind(id)
    .bind(scope.tenant_id())
    .fetch_optional(pool)
    .await
}

/// List connections through a visibility lens (design :274-296): `All` returns
/// every connection in the tenant; `User(id)` returns org-owned connections
/// plus only that user's personal connections. `list_connections` stays the
/// unfiltered internal/worker reader.
pub async fn list_connections_visible(
    pool: &PgPool,
    scope: TenantScope,
    viewer: ConnectionViewer,
) -> sqlx::Result<Vec<IntegrationConnectionRow>> {
    sqlx::query_as(sqlx::AssertSqlSafe(format!(
        "select {CONNECTION_COLS} from integration_connections
         where tenant_id = $1
           and ($2::uuid is null or owner_type = 'organization' or owner_user_id = $2)
         order by created_at desc"
    )))
    .bind(scope.tenant_id())
    .bind(viewer.user_id())
    .fetch_all(pool)
    .await
}

/// Read one connection through the same visibility lens as
/// [`list_connections_visible`] — returns None for another user's personal row.
pub async fn get_connection_visible(
    pool: &PgPool,
    scope: TenantScope,
    id: Uuid,
    viewer: ConnectionViewer,
) -> sqlx::Result<Option<IntegrationConnectionRow>> {
    sqlx::query_as(sqlx::AssertSqlSafe(format!(
        "select {CONNECTION_COLS} from integration_connections
         where id = $1 and tenant_id = $2
           and ($3::uuid is null or owner_type = 'organization' or owner_user_id = $3)"
    )))
    .bind(id)
    .bind(scope.tenant_id())
    .bind(viewer.user_id())
    .fetch_optional(pool)
    .await
}

/// Bump a connection's authorization generation (design :296) — called on every
/// re-consent/rotation so any run binding that froze the older generation fails
/// closed at the broker recheck. Returns the new generation, or None if the
/// connection is not in scope.
pub async fn bump_connection_generation(
    pool: &PgPool,
    scope: TenantScope,
    id: Uuid,
) -> sqlx::Result<Option<i32>> {
    let row = sqlx::query(
        "update integration_connections
         set authorization_generation = authorization_generation + 1, updated_at = now()
         where id = $1 and tenant_id = $2
         returning authorization_generation",
    )
    .bind(id)
    .bind(scope.tenant_id())
    .fetch_optional(pool)
    .await?;
    Ok(row.map(|r| r.get::<i32, _>("authorization_generation")))
}

/// Persist non-secret OAuth custody state (discovered endpoints, client
/// identity, pending bundle) before the connection is activated.
pub async fn update_connection_oauth(
    pool: &PgPool,
    scope: TenantScope,
    id: Uuid,
    oauth: &Value,
) -> sqlx::Result<()> {
    sqlx::query(
        "update integration_connections set oauth = $2, updated_at = now()
         where id = $1 and status <> 'revoked' and tenant_id = $3",
    )
    .bind(id)
    .bind(oauth)
    .bind(scope.tenant_id())
    .execute(pool)
    .await
    .map(|_| ())
}

/// The callback exchange completing: seal the rotating refresh token into
/// `credential_sealed` (the SAME custody column static bearers use) and
/// flip the connection live. Works from pending (first connect) and error
/// (reconnect after invalid_grant) alike.
pub async fn activate_connection_oauth(
    pool: &PgPool,
    scope: TenantScope,
    id: Uuid,
    sealed_refresh: &[u8],
    oauth: &Value,
    granted_scopes: &Value,
) -> sqlx::Result<Option<IntegrationConnectionRow>> {
    sqlx::query_as(sqlx::AssertSqlSafe(format!(
        "update integration_connections
         set credential_sealed = $2, oauth = $3, granted_scopes = $4,
             status = 'active', updated_at = now()
         where id = $1 and status <> 'revoked' and auth_kind = 'oauth' and tenant_id = $5
         returning {CONNECTION_COLS}"
    )))
    .bind(id)
    .bind(sealed_refresh)
    .bind(oauth)
    .bind(granted_scopes)
    .bind(scope.tenant_id())
    .fetch_optional(pool)
    .await
}

/// Refresh-token rotation: one atomic overwrite (OAuth 2.1 MUST — old token
/// is gone the moment the new one lands). Active connections only; returns
/// false when the row was revoked/errored underneath the caller.
pub async fn rotate_connection_refresh(
    pool: &PgPool,
    scope: TenantScope,
    id: Uuid,
    sealed_new: &[u8],
) -> sqlx::Result<bool> {
    let r = sqlx::query(
        "update integration_connections set credential_sealed = $2, updated_at = now()
         where id = $1 and status = 'active' and auth_kind = 'oauth' and tenant_id = $3",
    )
    .bind(id)
    .bind(sealed_new)
    .bind(scope.tenant_id())
    .execute(pool)
    .await?;
    Ok(r.rows_affected() == 1)
}

/// `invalid_grant`-class failure: the refresh token is dead, the connection
/// needs human re-consent. Everything downstream fails closed off the
/// status: `connection_credential_sealed` stops returning, run creation
/// refuses, the broker surfaces "reconnect".
pub async fn mark_connection_error(
    pool: &PgPool,
    scope: TenantScope,
    id: Uuid,
    note: &str,
) -> sqlx::Result<()> {
    sqlx::query(
        "update integration_connections
         set status = 'error', updated_at = now(),
             oauth = jsonb_set(coalesce(oauth, '{}'::jsonb), '{error}', to_jsonb($2::text))
         where id = $1 and status = 'active' and tenant_id = $3",
    )
    .bind(id)
    .bind(note)
    .bind(scope.tenant_id())
    .execute(pool)
    .await
    .map(|_| ())
}

/// Store a (DCR-minted) client secret after connection creation. Sealed by
/// the caller; readable only via `connection_client_secret_sealed`.
pub async fn set_connection_client_secret(
    pool: &PgPool,
    scope: TenantScope,
    id: Uuid,
    sealed: &[u8],
) -> sqlx::Result<()> {
    sqlx::query(
        "update integration_connections set client_secret_sealed = $2, updated_at = now()
         where id = $1 and status <> 'revoked' and tenant_id = $3",
    )
    .bind(id)
    .bind(sealed)
    .bind(scope.tenant_id())
    .execute(pool)
    .await
    .map(|_| ())
}

/// The only reader of the sealed client secret (confidential OAuth clients).
/// Client identity outlives token state — the dance needs it while the row
/// is still pending (first exchange) or errored (reconnect) — so any
/// non-revoked status qualifies.
pub async fn connection_client_secret_sealed(
    pool: &PgPool,
    scope: TenantScope,
    id: Uuid,
) -> sqlx::Result<Option<Vec<u8>>> {
    let row = sqlx::query(
        "select client_secret_sealed from integration_connections
         where id = $1 and status <> 'revoked' and tenant_id = $2",
    )
    .bind(id)
    .bind(scope.tenant_id())
    .fetch_optional(pool)
    .await?;
    Ok(row.and_then(|r| r.get::<Option<Vec<u8>>, _>("client_secret_sealed")))
}

// ─── Connector catalog ────────────────────────────────────────────────────

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
/// transaction. The `exists` guard proves the connection is in scope — a
/// cross-tenant connection_id yields RowNotFound (the composite FK is the
/// backstop).
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
                       where c.id = $3 and c.tenant_id = $2)
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
    sqlx::query_as(
        "select * from connection_tool_snapshots
         where tenant_id = $1 and connection_id = $2
         order by snapshot_version desc limit 1",
    )
    .bind(scope.tenant_id())
    .bind(connection_id)
    .fetch_optional(pool)
    .await
}

/// Every snapshot for a connection, newest first.
pub async fn list_connection_tool_snapshots(
    pool: &PgPool,
    scope: TenantScope,
    connection_id: Uuid,
) -> sqlx::Result<Vec<ConnectionToolSnapshotRow>> {
    sqlx::query_as(
        "select * from connection_tool_snapshots
         where tenant_id = $1 and connection_id = $2
         order by snapshot_version desc",
    )
    .bind(scope.tenant_id())
    .bind(connection_id)
    .fetch_all(pool)
    .await
}

/// One specific snapshot version for a connection (the pin a run froze).
pub async fn get_connection_tool_snapshot(
    pool: &PgPool,
    scope: TenantScope,
    connection_id: Uuid,
    version: i32,
) -> sqlx::Result<Option<ConnectionToolSnapshotRow>> {
    sqlx::query_as(
        "select * from connection_tool_snapshots
         where tenant_id = $1 and connection_id = $2 and snapshot_version = $3",
    )
    .bind(scope.tenant_id())
    .bind(connection_id)
    .bind(version)
    .fetch_optional(pool)
    .await
}

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
    sqlx::query_as(
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
    .fetch_all(pool)
    .await
}

/// Resolve one slug for a tenant: the tenant's custom row first, else the
/// global row; disabled rows excluded (design :262-266).
pub async fn get_catalog_by_slug(
    pool: &PgPool,
    scope: TenantScope,
    slug: &str,
) -> sqlx::Result<Option<ConnectorCatalogRow>> {
    sqlx::query_as(
        "select * from connector_catalog
         where slug = $1 and disabled_at is null and (tenant_id = $2 or tenant_id is null)
         order by (tenant_id is not null) desc
         limit 1",
    )
    .bind(slug)
    .bind(scope.tenant_id())
    .fetch_optional(pool)
    .await
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
    // tier AND provenance are forced 'custom': verified/community are curation
    // judgements the API cannot self-award, and a 'custom' provenance keeps a
    // user's BYO entry distinguishable from both the fluidbox seed and an
    // import (the generated import upsert only ever refreshes rows whose
    // provenance.source is an import source — 'mcp-registry' or 'open-connector'
    // — so it can never clobber this custom row; see the importer). The
    // `not exists (global)` guard fails closed on a global-slug collision — a
    // tenant can never mask a curated slug with a divergent definition.
    sqlx::query_as(
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
    .fetch_optional(pool)
    .await
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
    let r = sqlx::query("delete from connector_catalog where slug = $1 and tenant_id = $2")
        .bind(slug)
        .bind(scope.tenant_id())
        .execute(pool)
        .await?;
    Ok(r.rows_affected())
}

/// The only reader of the sealed credential. Returns None unless the
/// connection exists AND is active — a revoked connection can never again
/// produce a credential.
pub async fn connection_credential_sealed(
    pool: &PgPool,
    scope: TenantScope,
    id: Uuid,
) -> sqlx::Result<Option<Vec<u8>>> {
    let row = sqlx::query(
        "select credential_sealed from integration_connections
         where id = $1 and status = 'active' and tenant_id = $2",
    )
    .bind(id)
    .bind(scope.tenant_id())
    .fetch_optional(pool)
    .await?;
    Ok(row.map(|r| r.get::<Vec<u8>, _>("credential_sealed")))
}

/// The only reader of the sealed webhook secret (verified on every ingress
/// request). Active connections only — a revoked connection stops receiving.
pub async fn connection_webhook_secret_sealed(
    pool: &PgPool,
    scope: TenantScope,
    id: Uuid,
) -> sqlx::Result<Option<Vec<u8>>> {
    let row = sqlx::query(
        "select webhook_secret_sealed from integration_connections
         where id = $1 and status = 'active' and tenant_id = $2",
    )
    .bind(id)
    .bind(scope.tenant_id())
    .fetch_optional(pool)
    .await?;
    Ok(row.and_then(|r| r.get::<Option<Vec<u8>>, _>("webhook_secret_sealed")))
}

// ─── GitHub App registrations & flows (Phase 5.6) ─────────────────────────

/// The App identity created via GitHub's manifest flow. Secrets (pem,
/// webhook secret, client secret) are NEVER selected by row queries — the
/// explicit column list below cannot leak them; the dedicated active-only
/// readers are the only accessors.
#[derive(Debug, Clone, sqlx::FromRow, serde::Serialize)]
pub struct GithubAppRegistrationRow {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub status: String, // pending | active | revoked
    pub target_kind: String,
    pub target_org: Option<String>,
    pub app_id: Option<String>,
    pub slug: Option<String>,
    pub name: Option<String>,
    pub client_id: Option<String>,
    pub html_url: Option<String>,
    pub owner_login: Option<String>,
    /// False = degraded: GitHub returned no webhook secret at conversion —
    /// fetch/publish work, event ingress cannot authenticate.
    pub has_webhook_secret: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

const GH_REG_COLS: &str = "id, tenant_id, status, target_kind, target_org, app_id, slug, \
     name, client_id, html_url, owner_login, \
     (webhook_secret_sealed is not null) as has_webhook_secret, created_at, updated_at";

pub async fn create_github_app_registration(
    pool: &PgPool,
    scope: TenantScope,
    target_kind: &str,
    target_org: Option<&str>,
) -> sqlx::Result<GithubAppRegistrationRow> {
    sqlx::query_as(sqlx::AssertSqlSafe(format!(
        "insert into github_app_registrations (id, tenant_id, target_kind, target_org)
         values ($1, $2, $3, $4)
         returning {GH_REG_COLS}"
    )))
    .bind(Uuid::now_v7())
    .bind(scope.tenant_id())
    .bind(target_kind)
    .bind(target_org)
    .fetch_one(pool)
    .await
}

pub async fn list_github_app_registrations(
    pool: &PgPool,
    scope: TenantScope,
) -> sqlx::Result<Vec<GithubAppRegistrationRow>> {
    sqlx::query_as(sqlx::AssertSqlSafe(format!(
        "select {GH_REG_COLS} from github_app_registrations
         where tenant_id = $1 order by created_at desc"
    )))
    .bind(scope.tenant_id())
    .fetch_all(pool)
    .await
}

pub async fn get_github_app_registration(
    pool: &PgPool,
    scope: TenantScope,
    id: Uuid,
) -> sqlx::Result<Option<GithubAppRegistrationRow>> {
    sqlx::query_as(sqlx::AssertSqlSafe(format!(
        "select {GH_REG_COLS} from github_app_registrations where id = $1 and tenant_id = $2"
    )))
    .bind(id)
    .bind(scope.tenant_id())
    .fetch_optional(pool)
    .await
}

/// The manifest conversion landing: exactly ONE conversion may complete a
/// registration (`where status = 'pending'`); a racing second conversion
/// affects zero rows and its result is discarded by the caller.
#[allow(clippy::too_many_arguments)]
pub async fn activate_github_app_registration(
    pool: &PgPool,
    scope: TenantScope,
    id: Uuid,
    app_id: &str,
    slug: &str,
    name: &str,
    client_id: Option<&str>,
    html_url: &str,
    owner_login: Option<&str>,
    pem_sealed: &[u8],
    webhook_secret_sealed: Option<&[u8]>,
    client_secret_sealed: Option<&[u8]>,
) -> sqlx::Result<Option<GithubAppRegistrationRow>> {
    sqlx::query_as(sqlx::AssertSqlSafe(format!(
        "update github_app_registrations
         set app_id = $2, slug = $3, name = $4, client_id = $5, html_url = $6,
             owner_login = $7, pem_sealed = $8, webhook_secret_sealed = $9,
             client_secret_sealed = $10, status = 'active', updated_at = now()
         where id = $1 and status = 'pending' and tenant_id = $11
         returning {GH_REG_COLS}"
    )))
    .bind(id)
    .bind(app_id)
    .bind(slug)
    .bind(name)
    .bind(client_id)
    .bind(html_url)
    .bind(owner_login)
    .bind(pem_sealed)
    .bind(webhook_secret_sealed)
    .bind(client_secret_sealed)
    .bind(scope.tenant_id())
    .fetch_optional(pool)
    .await
}

/// Revoke a registration AND its child connections in one transaction;
/// returns the affected connection ids so the caller can evict cached
/// installation tokens. Registrations are revoked, never deleted (the FK is
/// RESTRICT on purpose).
pub async fn revoke_github_app_registration(
    pool: &PgPool,
    scope: TenantScope,
    id: Uuid,
) -> sqlx::Result<Option<Vec<Uuid>>> {
    let mut tx = pool.begin().await?;
    let reg = sqlx::query(
        "update github_app_registrations set status = 'revoked', updated_at = now()
         where id = $1 and status <> 'revoked' and tenant_id = $2",
    )
    .bind(id)
    .bind(scope.tenant_id())
    .execute(&mut *tx)
    .await?;
    if reg.rows_affected() == 0 {
        tx.rollback().await?;
        return Ok(None);
    }
    // Scope the child cascade to the registration's own tenant too — the
    // composite FK already makes a cross-tenant child impossible, but the
    // predicate keeps the statement self-scoped (never a bare-id UPDATE).
    let rows = sqlx::query(
        "update integration_connections set status = 'revoked', updated_at = now()
         where registration_id = $1 and status <> 'revoked' and tenant_id = $2
         returning id",
    )
    .bind(id)
    .bind(scope.tenant_id())
    .fetch_all(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(Some(rows.iter().map(|r| r.get::<Uuid, _>("id")).collect()))
}

/// Active-only reader for the App signing key (same discipline as
/// `connection_credential_sealed`): a revoked registration can never again
/// produce a JWT.
pub async fn github_app_registration_pem_sealed(
    pool: &PgPool,
    scope: TenantScope,
    id: Uuid,
) -> sqlx::Result<Option<Vec<u8>>> {
    let row = sqlx::query(
        "select pem_sealed from github_app_registrations
         where id = $1 and status = 'active' and tenant_id = $2",
    )
    .bind(id)
    .bind(scope.tenant_id())
    .fetch_optional(pool)
    .await?;
    Ok(row.and_then(|r| r.get::<Option<Vec<u8>>, _>("pem_sealed")))
}

/// Active-only reader for the app-level webhook secret (verified on every
/// app-level ingress request).
pub async fn github_app_registration_webhook_secret_sealed(
    pool: &PgPool,
    scope: TenantScope,
    id: Uuid,
) -> sqlx::Result<Option<Vec<u8>>> {
    let row = sqlx::query(
        "select webhook_secret_sealed from github_app_registrations
         where id = $1 and status = 'active' and tenant_id = $2",
    )
    .bind(id)
    .bind(scope.tenant_id())
    .fetch_optional(pool)
    .await?;
    Ok(row.and_then(|r| r.get::<Option<Vec<u8>>, _>("webhook_secret_sealed")))
}

/// Mint a one-time flow (admin intent). Opportunistically sweeps expired
/// unconsumed flows immediately, and consumed ones after a 7-day audit
/// window, so abandoned dances never accumulate.
pub async fn create_github_app_flow(
    pool: &PgPool,
    registration_id: Uuid,
    purpose: &str,
    ttl_secs: i64,
) -> sqlx::Result<Uuid> {
    sqlx::query(
        "delete from github_app_flows
         where (consumed_at is null and expires_at < now())
            or expires_at < now() - interval '7 days'",
    )
    .execute(pool)
    .await?;
    let id = Uuid::now_v7();
    sqlx::query(
        "insert into github_app_flows (id, registration_id, purpose, expires_at)
         values ($1, $2, $3, now() + make_interval(secs => $4::double precision))",
    )
    .bind(id)
    .bind(registration_id)
    .bind(purpose)
    .bind(ttl_secs as f64)
    .execute(pool)
    .await?;
    Ok(id)
}

/// The go page's one-time claim: binds a fresh browser cookie hash to the
/// flow. Exactly one browser can ever be bound.
pub async fn claim_github_app_bootstrap(
    pool: &PgPool,
    flow_id: Uuid,
    purpose: &str,
    browser_hash: &str,
) -> sqlx::Result<Option<Uuid>> {
    let row = sqlx::query(
        "update github_app_flows
         set bootstrap_consumed_at = now(), browser_hash = $3
         where id = $1 and purpose = $2 and bootstrap_consumed_at is null
           and expires_at > now()
         returning registration_id",
    )
    .bind(flow_id)
    .bind(purpose)
    .bind(browser_hash)
    .fetch_optional(pool)
    .await?;
    Ok(row.map(|r| r.get::<Uuid, _>("registration_id")))
}

/// The callback/setup one-time claim. The browser-cookie hash sits INSIDE
/// the predicate: an attacker holding a leaked state parameter but not the
/// initiating browser's cookie cannot complete OR burn the flow.
pub async fn claim_github_app_flow(
    pool: &PgPool,
    flow_id: Uuid,
    purpose: &str,
    registration_id: Uuid,
    browser_hash: &str,
) -> sqlx::Result<bool> {
    let r = sqlx::query(
        "update github_app_flows
         set consumed_at = now()
         where id = $1 and purpose = $2 and registration_id = $3
           and consumed_at is null and bootstrap_consumed_at is not null
           and browser_hash = $4 and expires_at > now()",
    )
    .bind(flow_id)
    .bind(purpose)
    .bind(registration_id)
    .bind(browser_hash)
    .execute(pool)
    .await?;
    Ok(r.rows_affected() == 1)
}

/// Insert a seamless installation connection ONLY if the installation has
/// never had a row of ANY status — the check rides inside the statement, so
/// an insert can never land just after a concurrent revoke (F‑6: revoked
/// rows revive only via approve, never via a fresh import racing in).
/// Returns None when any row (live or revoked) already exists; the caller
/// loops back through its existing-row path.
#[allow(clippy::too_many_arguments)]
pub async fn create_github_app_connection_if_absent(
    pool: &PgPool,
    scope: TenantScope,
    installation_id: &str,
    display_name: &str,
    metadata: &Value,
    status: &str,
    registration_id: Uuid,
) -> sqlx::Result<Option<IntegrationConnectionRow>> {
    sqlx::query_as(sqlx::AssertSqlSafe(format!(
        // github_app connections are ALWAYS organization-owned (system custody
        // via the registration) — owner_type is stamped explicitly, never a
        // per-user personal connection.
        "insert into integration_connections
           (id, tenant_id, provider, external_account_id, display_name, credential_sealed,
            granted_scopes, resource_selection, metadata, webhook_secret_sealed,
            auth_kind, status, oauth, client_secret_sealed, registration_id, owner_type)
         select $1, $2, 'github_app', $3, $4, null, '[]'::jsonb, '{{}}'::jsonb, $5, null,
                'static', $6, null, null, $7, 'organization'
         where not exists (
             select 1 from integration_connections
             where tenant_id = $2 and provider = 'github_app' and external_account_id = $3
         )
         returning {CONNECTION_COLS}"
    )))
    .bind(Uuid::now_v7())
    .bind(scope.tenant_id())
    .bind(installation_id)
    .bind(display_name)
    .bind(metadata)
    .bind(status)
    .bind(registration_id)
    .fetch_optional(pool)
    .await
}

/// The single live connection row for a GitHub installation, preferring a
/// live row but surfacing a revoked one (callers refuse or route revival
/// through the explicit approve path — never a second row).
pub async fn get_github_app_connection_by_installation(
    pool: &PgPool,
    scope: TenantScope,
    installation_id: &str,
) -> sqlx::Result<Option<IntegrationConnectionRow>> {
    sqlx::query_as(sqlx::AssertSqlSafe(format!(
        "select {CONNECTION_COLS} from integration_connections
         where tenant_id = $1 and provider = 'github_app' and external_account_id = $2
         order by (status <> 'revoked') desc, created_at desc
         limit 1"
    )))
    .bind(scope.tenant_id())
    .bind(installation_id)
    .fetch_optional(pool)
    .await
}

/// Guarded status transition: only fires when the current status is one of
/// `allowed_from`. Returns the fresh row on success.
pub async fn set_connection_status(
    pool: &PgPool,
    scope: TenantScope,
    id: Uuid,
    status: &str,
    allowed_from: &[&str],
) -> sqlx::Result<Option<IntegrationConnectionRow>> {
    let from: Vec<String> = allowed_from.iter().map(|s| s.to_string()).collect();
    sqlx::query_as(sqlx::AssertSqlSafe(format!(
        "update integration_connections set status = $2, updated_at = now()
         where id = $1 and status = any($3) and tenant_id = $4
         returning {CONNECTION_COLS}"
    )))
    .bind(id)
    .bind(status)
    .bind(&from)
    .bind(scope.tenant_id())
    .fetch_optional(pool)
    .await
}

/// Refresh the display metadata a setup/sync re-verification produced.
pub async fn refresh_connection_metadata(
    pool: &PgPool,
    scope: TenantScope,
    id: Uuid,
    display_name: &str,
    metadata: &Value,
) -> sqlx::Result<()> {
    sqlx::query(
        "update integration_connections
         set display_name = $2, metadata = $3, updated_at = now()
         where id = $1 and status <> 'revoked' and tenant_id = $4",
    )
    .bind(id)
    .bind(display_name)
    .bind(metadata)
    .bind(scope.tenant_id())
    .execute(pool)
    .await
    .map(|_| ())
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
    pub concurrency_policy: String,
    pub budget_override: Option<Value>,
    pub workspace_override: Option<Value>,
    pub result_destinations: Value,
    /// Event subscriptions only (trigger_kind = 'event'); NULL otherwise.
    pub connection_id: Option<Uuid>,
    pub resource_selector: Option<Value>,
    pub event_filter: Option<Value>,
    pub event_publish: Option<Value>,
    /// Capability keep-list (bundle names; §3.5 narrowing). NULL = keep all
    /// bundles the resolved revision attaches; intersection is remove-only.
    pub capability_bundles: Option<Value>,
    /// Generation of the subscription's callback-secret authority (invariant 7,
    /// design :428-431): bumps on secret rotation so a `subscription_secret`
    /// binding freezing an older generation fails closed.
    pub authority_generation: i32,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

const SUBSCRIPTION_COLS: &str = "id, tenant_id, agent_id, name, trigger_kind, pinned_revision_id, \
     enabled, task_template, allow_task_override, allow_workspace_override, autonomy, \
     concurrency_policy, budget_override, workspace_override, result_destinations, \
     connection_id, resource_selector, event_filter, event_publish, capability_bundles, \
     authority_generation, created_at, updated_at";

#[allow(clippy::too_many_arguments)]
pub async fn create_trigger_subscription(
    pool: &PgPool,
    scope: TenantScope,
    agent_id: Uuid,
    name: &str,
    trigger_kind: &str,
    pinned_revision_id: Option<Uuid>,
    task_template: Option<&str>,
    allow_task_override: bool,
    allow_workspace_override: bool,
    autonomy: Option<&str>,
    concurrency_policy: &str,
    budget_override: Option<&Value>,
    workspace_override: Option<&Value>,
    result_destinations: &Value,
    callback_secret_sealed: Option<&[u8]>,
    connection_id: Option<Uuid>,
    resource_selector: Option<&Value>,
    event_filter: Option<&Value>,
    event_publish: Option<&Value>,
    capability_bundles: Option<&Value>,
) -> sqlx::Result<TriggerSubscriptionRow> {
    // Prove every referenced parent belongs to this tenant IN SQL (the handler
    // pre-validates too, but this is the relational backstop): the agent is
    // in-scope; a Some pinned_revision is a revision of THAT agent; a Some
    // connection is in-scope. A miss yields zero rows → fetch_one RowNotFound,
    // the same shape a not-in-scope agent already produced for other writes.
    sqlx::query_as(sqlx::AssertSqlSafe(format!(
        "insert into trigger_subscriptions
           (id, tenant_id, agent_id, name, trigger_kind, pinned_revision_id, task_template,
            allow_task_override, allow_workspace_override, autonomy, concurrency_policy,
            budget_override, workspace_override, result_destinations, callback_secret_sealed,
            connection_id, resource_selector, event_filter, event_publish, capability_bundles)
         select $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20
         where exists (select 1 from agents a where a.id = $3 and a.tenant_id = $2)
           and ($6::uuid is null or exists (
                 select 1 from agent_revisions r where r.id = $6 and r.agent_id = $3))
           and ($16::uuid is null or exists (
                 select 1 from integration_connections c where c.id = $16 and c.tenant_id = $2))
         returning {SUBSCRIPTION_COLS}"
    )))
    .bind(Uuid::now_v7())
    .bind(scope.tenant_id())
    .bind(agent_id)
    .bind(name)
    .bind(trigger_kind)
    .bind(pinned_revision_id)
    .bind(task_template)
    .bind(allow_task_override)
    .bind(allow_workspace_override)
    .bind(autonomy)
    .bind(concurrency_policy)
    .bind(budget_override)
    .bind(workspace_override)
    .bind(result_destinations)
    .bind(callback_secret_sealed)
    .bind(connection_id)
    .bind(resource_selector)
    .bind(event_filter)
    .bind(event_publish)
    .bind(capability_bundles)
    .fetch_one(pool)
    .await
}

/// Enabled event subscriptions listening on a connection — the matcher's
/// candidate set.
pub async fn list_event_subscriptions(
    pool: &PgPool,
    scope: TenantScope,
    connection: Uuid,
) -> sqlx::Result<Vec<TriggerSubscriptionRow>> {
    sqlx::query_as(sqlx::AssertSqlSafe(format!(
        "select {SUBSCRIPTION_COLS} from trigger_subscriptions
         where connection_id = $1 and trigger_kind = 'event' and enabled and tenant_id = $2
         order by created_at"
    )))
    .bind(connection)
    .bind(scope.tenant_id())
    .fetch_all(pool)
    .await
}

pub async fn list_trigger_subscriptions(
    pool: &PgPool,
    scope: TenantScope,
) -> sqlx::Result<Vec<TriggerSubscriptionRow>> {
    sqlx::query_as(sqlx::AssertSqlSafe(format!(
        "select {SUBSCRIPTION_COLS} from trigger_subscriptions
         where tenant_id = $1 order by created_at desc"
    )))
    .bind(scope.tenant_id())
    .fetch_all(pool)
    .await
}

pub async fn get_trigger_subscription(
    pool: &PgPool,
    scope: TenantScope,
    id: Uuid,
) -> sqlx::Result<Option<TriggerSubscriptionRow>> {
    sqlx::query_as(sqlx::AssertSqlSafe(format!(
        "select {SUBSCRIPTION_COLS} from trigger_subscriptions where id = $1 and tenant_id = $2"
    )))
    .bind(id)
    .bind(scope.tenant_id())
    .fetch_optional(pool)
    .await
}

pub async fn set_trigger_subscription_enabled(
    pool: &PgPool,
    scope: TenantScope,
    id: Uuid,
    enabled: bool,
) -> sqlx::Result<Option<TriggerSubscriptionRow>> {
    sqlx::query_as(sqlx::AssertSqlSafe(format!(
        "update trigger_subscriptions set enabled = $2, updated_at = now()
         where id = $1 and tenant_id = $3 returning {SUBSCRIPTION_COLS}"
    )))
    .bind(id)
    .bind(enabled)
    .bind(scope.tenant_id())
    .fetch_optional(pool)
    .await
}

/// The only reader of the sealed callback secret. Deliveries for in-flight
/// runs must still sign after a disable, so this does not require `enabled`.
pub async fn subscription_callback_secret_sealed(
    pool: &PgPool,
    scope: TenantScope,
    id: Uuid,
) -> sqlx::Result<Option<Vec<u8>>> {
    let row = sqlx::query(
        "select callback_secret_sealed from trigger_subscriptions
         where id = $1 and tenant_id = $2",
    )
    .bind(id)
    .bind(scope.tenant_id())
    .fetch_optional(pool)
    .await?;
    Ok(row.and_then(|r| r.get::<Option<Vec<u8>>, _>("callback_secret_sealed")))
}

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
    sqlx::query_as("select * from run_resource_bindings where id = $1 and tenant_id = $2")
        .bind(id)
        .bind(scope.tenant_id())
        .fetch_optional(pool)
        .await
}

/// Every binding a run resolved, ordered by slot for stable display.
pub async fn session_resource_bindings(
    pool: &PgPool,
    scope: TenantScope,
    session_id: Uuid,
) -> sqlx::Result<Vec<RunResourceBindingRow>> {
    sqlx::query_as(
        "select * from run_resource_bindings
         where session_id = $1 and tenant_id = $2
         order by slot_kind, requirement_slot",
    )
    .bind(session_id)
    .bind(scope.tenant_id())
    .fetch_all(pool)
    .await
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
    sqlx::query_as(
        "select * from run_resource_bindings
         where session_id = $1 and tenant_id = $2 and slot_kind = $3 and requirement_slot = $4",
    )
    .bind(session_id)
    .bind(scope.tenant_id())
    .bind(slot_kind)
    .bind(slot)
    .fetch_optional(pool)
    .await
}

// ─── Sessions ─────────────────────────────────────────────────────────────

#[allow(clippy::too_many_arguments)]
pub async fn create_session(
    pool: &PgPool,
    scope: TenantScope,
    agent_id: Uuid,
    agent_revision_id: Uuid,
    autonomy: &str,
    trust_tier: &str,
    task: &str,
    repo_source: &Value,
    run_spec: &Value,
    budgets: &Value,
    trigger: Option<&Value>,
    invoked_by_kind: Option<&str>,
    invoked_by_user_id: Option<Uuid>,
    bind_invocation: Option<Uuid>,
    bind_dispatch: Option<Uuid>,
    bindings: &[NewRunResourceBinding],
) -> sqlx::Result<SessionRow> {
    let mut tx = pool.begin().await?;
    // Prove the agent AND the pinned revision both belong to this tenant in SQL
    // (the run builder resolves them under scope first; this is the relational
    // backstop). A miss yields zero rows → fetch_one RowNotFound, surfaced via
    // `?` like any other create failure.
    let row: SessionRow = sqlx::query_as(
        "insert into sessions
           (id, tenant_id, agent_id, agent_revision_id, autonomy, trust_tier, task, repo_source, run_spec, budgets, trigger, invoked_by_kind, invoked_by_user_id)
         select $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13
         where exists (select 1 from agents a where a.id = $3 and a.tenant_id = $2)
           and exists (select 1 from agent_revisions r where r.id = $4 and r.agent_id = $3)
         returning *",
    )
    .bind(Uuid::now_v7())
    .bind(scope.tenant_id())
    .bind(agent_id)
    .bind(agent_revision_id)
    .bind(autonomy)
    .bind(trust_tier)
    .bind(task)
    .bind(repo_source)
    .bind(run_spec)
    .bind(budgets)
    .bind(trigger)
    .bind(invoked_by_kind)
    .bind(invoked_by_user_id)
    .fetch_one(&mut *tx)
    .await?;
    // Resolved run resource bindings are written INSIDE this transaction — a run
    // and the frozen record of what it resolved commit together, or not at all
    // (design :391-463; invariant 21). The composite FK refuses a binding whose
    // (tenant, session) does not match this session's.
    if !bindings.is_empty() {
        insert_run_resource_bindings(&mut tx, scope, row.id, bindings).await?;
    }
    // Atomic claim bind: the run and its idempotency claim commit together,
    // so a crash can never orphan a created run from its claim (which would
    // let the stale-claim takeover duplicate it).
    if let Some(invocation) = bind_invocation {
        // EXISTS-scoped through the owning subscription so the claim can only
        // bind an invocation in this session's tenant (matches the predicate
        // style in `mark_invocation_skipped`).
        sqlx::query(
            "update trigger_invocations set session_id = $2
             where id = $1
               and exists (select 1 from trigger_subscriptions sub
                           where sub.id = trigger_invocations.subscription_id
                             and sub.tenant_id = $3)",
        )
        .bind(invocation)
        .bind(row.id)
        .bind(scope.tenant_id())
        .execute(&mut *tx)
        .await?;
    }
    // Same discipline for the event fan-out claim (level-2 dedup): the
    // dispatch row and the session commit together.
    if let Some(dispatch) = bind_dispatch {
        // EXISTS-scoped through the owning delivery → connection so the claim
        // can only bind a dispatch in this session's tenant (matches the
        // predicate style in `list_delivery_dispatches`).
        sqlx::query(
            "update trigger_dispatches set session_id = $2
             where id = $1
               and exists (select 1 from trigger_deliveries d
                           join integration_connections c on c.id = d.connection_id
                           where d.id = trigger_dispatches.delivery_id
                             and c.tenant_id = $3)",
        )
        .bind(dispatch)
        .bind(row.id)
        .bind(scope.tenant_id())
        .execute(&mut *tx)
        .await?;
    }
    tx.commit().await?;
    Ok(row)
}

pub async fn get_session(
    pool: &PgPool,
    scope: TenantScope,
    id: Uuid,
) -> sqlx::Result<Option<SessionRow>> {
    sqlx::query_as("select * from sessions where id = $1 and tenant_id = $2")
        .bind(id)
        .bind(scope.tenant_id())
        .fetch_optional(pool)
        .await
}

/// List a tenant's sessions, newest first. `invoked_by` narrows to a single
/// user's runs (the run-visibility rule for a plain member); `None` returns
/// every session in the tenant (operator / `runs.read_all` holders).
pub async fn list_sessions(
    pool: &PgPool,
    scope: TenantScope,
    invoked_by: Option<Uuid>,
    limit: i64,
) -> sqlx::Result<Vec<SessionRow>> {
    sqlx::query_as(
        "select * from sessions
         where tenant_id = $1 and ($2::uuid is null or invoked_by_user_id = $2)
         order by created_at desc limit $3",
    )
    .bind(scope.tenant_id())
    .bind(invoked_by)
    .bind(limit)
    .fetch_all(pool)
    .await
}

/// The single status writer. Validates the transition inside a transaction;
/// returns Ok(None) if the transition is not legal (caller decides whether
/// that is an error or a benign race).
pub async fn transition_session(
    pool: &PgPool,
    scope: TenantScope,
    id: Uuid,
    next: SessionStatus,
    reason: Option<&str>,
) -> sqlx::Result<Option<(SessionStatus, SessionRow)>> {
    let mut tx = pool.begin().await?;
    let row: Option<(String,)> =
        sqlx::query_as("select status from sessions where id = $1 and tenant_id = $2 for update")
            .bind(id)
            .bind(scope.tenant_id())
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
         where id = $1 and tenant_id = $4 returning *",
    )
    .bind(id)
    .bind(next.as_str())
    .bind(reason)
    .bind(scope.tenant_id())
    .fetch_one(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(Some((current, updated)))
}

/// Attach the sandbox handle — REFUSED (returns false) unless the session is
/// still in an ACTIVE (pre-wind-down) state AND no finalization intent
/// exists: the intent is the single source of truth for ownership, and it
/// commits BEFORE the wind-down transition — a status-only fence would let a
/// launch attach a live sandbox inside that gap. The caller must terminate
/// the sandbox on refusal.
///
/// Deliberately a lock-then-check-then-update TRANSACTION, not one UPDATE:
/// a single statement's `not exists` subquery keeps the command snapshot
/// even after blocking on `begin_finalization`'s session row lock (Postgres
/// re-checks only the target tuple on unblock), so it could attach past a
/// just-committed intent. Taking the same row lock first and reading the
/// intent in a SECOND statement gets a fresh snapshot that must see it.
pub async fn set_sandbox_handle(
    pool: &PgPool,
    scope: TenantScope,
    id: Uuid,
    handle: &Value,
) -> sqlx::Result<bool> {
    use fluidbox_core::state::SessionStatus;
    let mut tx = pool.begin().await?;
    let locked: Option<(String,)> =
        sqlx::query_as("select status from sessions where id = $1 and tenant_id = $2 for update")
            .bind(id)
            .bind(scope.tenant_id())
            .fetch_optional(&mut *tx)
            .await?;
    let Some((status,)) = locked else {
        return Ok(false);
    };
    let active = SessionStatus::parse(&status).is_some_and(|s| s.accepts_work());
    if !active {
        return Ok(false);
    }
    // EXISTS-scoped through the owning session so the intent probe stays inside
    // this tenant (belt-and-braces: the row above is already locked and
    // tenant-checked; `session_finalizations` has no tenant column of its own).
    let (intent_exists,): (bool,) = sqlx::query_as(
        "select exists(
             select 1 from session_finalizations f
             where f.session_id = $1
               and exists (select 1 from sessions s
                           where s.id = f.session_id and s.tenant_id = $2))",
    )
    .bind(id)
    .bind(scope.tenant_id())
    .fetch_one(&mut *tx)
    .await?;
    if intent_exists {
        return Ok(false);
    }
    sqlx::query(
        "update sessions set sandbox_handle = $2, updated_at = now()
         where id = $1 and tenant_id = $3",
    )
    .bind(id)
    .bind(handle)
    .bind(scope.tenant_id())
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(true)
}

/// Adopt a DISCOVERED sandbox handle into a session atomically: only while no
/// handle is stored AND the session is still in an active (pre-wind-down)
/// status. The predicate is in the UPDATE itself, so the reconciler racing
/// `run()`'s own `set_sandbox_handle`, a concurrent cancel, or a terminal
/// transition can never overwrite a real handle or resurrect a closed
/// session. Returns whether the adoption landed.
pub async fn adopt_sandbox_handle(
    pool: &PgPool,
    scope: TenantScope,
    id: Uuid,
    handle: &Value,
) -> sqlx::Result<bool> {
    let res = sqlx::query(
        "update sessions set sandbox_handle = $2, updated_at = now()
         where id = $1 and tenant_id = $3 and sandbox_handle is null
           and status in ('created','provisioning','initializing','running','awaiting_approval')",
    )
    .bind(id)
    .bind(handle)
    .bind(scope.tenant_id())
    .execute(pool)
    .await?;
    Ok(res.rows_affected() > 0)
}

pub async fn set_base_commit(
    pool: &PgPool,
    scope: TenantScope,
    id: Uuid,
    commit: &str,
) -> sqlx::Result<()> {
    sqlx::query(
        "update sessions set base_commit = $2, updated_at = now()
         where id = $1 and tenant_id = $3",
    )
    .bind(id)
    .bind(commit)
    .bind(scope.tenant_id())
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn set_result_summary(
    pool: &PgPool,
    scope: TenantScope,
    id: Uuid,
    summary: &str,
) -> sqlx::Result<()> {
    sqlx::query(
        "update sessions set result_summary = $2, updated_at = now()
         where id = $1 and tenant_id = $3",
    )
    .bind(id)
    .bind(summary)
    .bind(scope.tenant_id())
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn heartbeat(pool: &PgPool, scope: TenantScope, id: Uuid) -> sqlx::Result<()> {
    sqlx::query(
        "update sessions set last_heartbeat_at = now(), updated_at = now()
         where id = $1 and tenant_id = $2",
    )
    .bind(id)
    .bind(scope.tenant_id())
    .execute(pool)
    .await?;
    Ok(())
}

// ─── Durable finalization intent (K8s design 2026-07-15, migration 0011) ──

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct FinalizationRow {
    pub session_id: Uuid,
    pub outcome: String,
    pub summary: Option<String>,
    pub reason: Option<String>,
    pub needs_quiesce: bool,
    pub quiesce_deadline: Option<DateTime<Utc>>,
    pub claimed_at: Option<DateTime<Utc>>,
    pub attempts: i32,
    pub created_at: DateTime<Utc>,
}

/// The outcome of persisting a finalization intent.
#[derive(Debug)]
pub enum BeginFinalization {
    /// The intent is durably persisted (by this call or a previous one).
    /// `row` is the AUTHORITATIVE intent — a loser of the insert race
    /// receives the winner's row and must derive every wind-down decision
    /// (target state, quiesce, deadline) from it, never from its own
    /// arguments. `session_status` is the status observed under the lock.
    Persisted {
        row: FinalizationRow,
        created: bool,
        session_status: String,
    },
    /// The session is already terminal — no intent may be (re)created.
    AlreadyTerminal,
    /// The session does not exist.
    Missing,
}

/// Persist the intent to finalize a session (idempotent), in ONE transaction
/// that locks the session row: the terminal check, the quiesce computation,
/// and the insert all see the same snapshot, so a late caller can never
/// recreate an intent after terminalization, and `needs_quiesce`/deadline
/// always match the state they were derived from. Holding the session lock
/// also fences the conflict→select read: terminalization (and the intent
/// delete that follows it) updates the sessions row, so it cannot slip
/// between our conflict and our read of the winning row. The first writer
/// wins the outcome; a racing second caller receives the winner's row with
/// `created: false` and defers to it.
#[allow(clippy::too_many_arguments)]
pub async fn begin_finalization(
    pool: &PgPool,
    scope: TenantScope,
    session: Uuid,
    outcome: &str,
    summary: Option<&str>,
    reason: Option<&str>,
    want_quiesce: bool,
    quiesce_deadline_secs: i64,
) -> sqlx::Result<BeginFinalization> {
    use fluidbox_core::state::SessionStatus;
    let mut tx = pool.begin().await?;
    let locked: Option<(String, Option<Value>)> = sqlx::query_as(
        "select status, sandbox_handle from sessions where id = $1 and tenant_id = $2 for update",
    )
    .bind(session)
    .bind(scope.tenant_id())
    .fetch_optional(&mut *tx)
    .await?;
    let Some((status, handle)) = locked else {
        return Ok(BeginFinalization::Missing);
    };
    if SessionStatus::parse(&status).is_some_and(|s| s.is_terminal()) {
        return Ok(BeginFinalization::AlreadyTerminal);
    }
    // Quiesce only makes sense while a runner is live to receive the
    // heartbeat signal — computed from the LOCKED snapshot, not the caller's
    // (possibly stale) read.
    let quiesce = want_quiesce
        && matches!(status.as_str(), "running" | "awaiting_approval")
        && handle.is_some();
    let deadline = quiesce.then(|| Utc::now() + chrono::Duration::seconds(quiesce_deadline_secs));
    let inserted: Option<FinalizationRow> = sqlx::query_as(
        "insert into session_finalizations
           (session_id, outcome, summary, reason, needs_quiesce, quiesce_deadline)
         values ($1,$2,$3,$4,$5,$6)
         on conflict (session_id) do nothing
         returning *",
    )
    .bind(session)
    .bind(outcome)
    .bind(summary)
    .bind(reason)
    .bind(quiesce)
    .bind(deadline)
    .fetch_optional(&mut *tx)
    .await?;
    let (row, created) = match inserted {
        Some(r) => (r, true),
        None => (
            sqlx::query_as("select * from session_finalizations where session_id = $1")
                .bind(session)
                .fetch_one(&mut *tx)
                .await?,
            false,
        ),
    };
    tx.commit().await?;
    Ok(BeginFinalization::Persisted {
        row,
        created,
        session_status: status,
    })
}

pub async fn get_finalization(
    pool: &PgPool,
    scope: TenantScope,
    session: Uuid,
) -> sqlx::Result<Option<FinalizationRow>> {
    sqlx::query_as(
        "select * from session_finalizations
         where session_id = $1
           and exists (select 1 from sessions s where s.id = $1 and s.tenant_id = $2)",
    )
    .bind(session)
    .bind(scope.tenant_id())
    .fetch_optional(pool)
    .await
}

/// Claim a finalization for driving: succeeds when the row is unclaimed OR its
/// claim went stale (the previous driver crashed). Bumps `attempts` and stamps
/// `claimed_at`. A concurrent driver that loses the CAS gets None and backs
/// off — the finalizing→terminal transition is the ultimate single-winner
/// gate regardless, so a double-claim can never double-finalize.
pub async fn claim_finalization(
    pool: &PgPool,
    scope: TenantScope,
    session: Uuid,
    stale_secs: i64,
) -> sqlx::Result<Option<FinalizationRow>> {
    sqlx::query_as(
        "update session_finalizations
            set claimed_at = now(), attempts = attempts + 1
          where session_id = $1
            and (claimed_at is null or claimed_at < now() - make_interval(secs => $2))
            and exists (select 1 from sessions s where s.id = $1 and s.tenant_id = $3)
          returning *",
    )
    .bind(session)
    .bind(stale_secs as f64)
    .bind(scope.tenant_id())
    .fetch_optional(pool)
    .await
}

/// Release a driver's claim early — for DELIBERATE deferrals (e.g. the
/// provisioning settle window), so the finalize worker retries at its own
/// cadence instead of waiting out the stale-claim threshold.
pub async fn release_finalization_claim(
    pool: &PgPool,
    scope: TenantScope,
    session: Uuid,
) -> sqlx::Result<()> {
    sqlx::query(
        "update session_finalizations set claimed_at = null
         where session_id = $1
           and exists (select 1 from sessions s where s.id = $1 and s.tenant_id = $2)",
    )
    .bind(session)
    .bind(scope.tenant_id())
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn delete_finalization(
    pool: &PgPool,
    scope: TenantScope,
    session: Uuid,
) -> sqlx::Result<()> {
    sqlx::query(
        "delete from session_finalizations
         where session_id = $1
           and exists (select 1 from sessions s where s.id = $1 and s.tenant_id = $2)",
    )
    .bind(session)
    .bind(scope.tenant_id())
    .execute(pool)
    .await?;
    Ok(())
}

// ─── Cross-replica OAuth refresh serialization (K8s design 2026-07-15) ─────

/// Stable 64-bit advisory-lock key from a connection id. Postgres advisory
/// locks are keyed on `bigint`; we fold the uuid's leading 8 bytes.
pub fn oauth_lock_key(connection_id: Uuid) -> i64 {
    let b = connection_id.as_bytes();
    i64::from_be_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]])
}

/// Take a transaction-scoped Postgres advisory lock keyed on a connection id,
/// on `tx`. Serializes OAuth refresh-token rotation ACROSS control-plane
/// replicas (a second replica can no longer double-rotate a refresh token
/// into `invalid_grant`) — replacing reliance on the in-process mutex. The
/// lock releases automatically when `tx` is committed or dropped, so the
/// caller holds `tx` across the refresh HTTP round-trip and the rotation
/// write, then commits.
pub async fn acquire_oauth_lock(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    connection_id: Uuid,
) -> sqlx::Result<()> {
    sqlx::query("select pg_advisory_xact_lock($1)")
        .bind(oauth_lock_key(connection_id))
        .execute(&mut **tx)
        .await?;
    Ok(())
}

/// Idempotent artifact write: a crash-retry during finalization must not
/// accumulate duplicate diff rows. Replaces any existing (session, kind, name).
/// The stored diff artifact's content, if any — the finalizer's evidence
/// guard: a re-driven finalization must never overwrite a collected diff
/// with an `artifact_missing` marker (missing → collected upgrades are fine).
pub async fn diff_artifact_content(
    pool: &PgPool,
    scope: TenantScope,
    session: Uuid,
) -> sqlx::Result<Option<String>> {
    let row: Option<(String,)> = sqlx::query_as(
        "select content from artifacts
         where session_id = $1 and kind = 'diff'
           and exists (select 1 from sessions s where s.id = $1 and s.tenant_id = $2)
         limit 1",
    )
    .bind(session)
    .bind(scope.tenant_id())
    .fetch_optional(pool)
    .await?;
    Ok(row.map(|(c,)| c))
}

pub async fn upsert_artifact(
    pool: &PgPool,
    scope: TenantScope,
    session: Uuid,
    kind: &str,
    name: &str,
    content: &str,
    content_type: &str,
) -> sqlx::Result<ArtifactRow> {
    let mut tx = pool.begin().await?;
    sqlx::query(
        "delete from artifacts
         where session_id = $1 and kind = $2 and name = $3
           and exists (select 1 from sessions s where s.id = $1 and s.tenant_id = $4)",
    )
    .bind(session)
    .bind(kind)
    .bind(name)
    .bind(scope.tenant_id())
    .execute(&mut *tx)
    .await?;
    let row: ArtifactRow = sqlx::query_as(
        "insert into artifacts (id, session_id, kind, name, content, content_type)
         select $1,$2,$3,$4,$5,$6
         where exists (select 1 from sessions s where s.id = $2 and s.tenant_id = $7)
         returning *",
    )
    .bind(Uuid::now_v7())
    .bind(session)
    .bind(kind)
    .bind(name)
    .bind(content)
    .bind(content_type)
    .bind(scope.tenant_id())
    .fetch_one(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(row)
}

// ─── Events (append-only; Redacted enforced at the type level) ────────────

pub async fn append_event(
    pool: &PgPool,
    scope: TenantScope,
    event: Redacted<EventEnvelope>,
) -> sqlx::Result<i64> {
    let env = event.into_inner();
    let payload = serde_json::to_value(&env.body).unwrap_or(Value::Null);
    let type_name = env.body.type_name();
    // Gate the append on the session belonging to the caller's tenant. The
    // `where exists(...)` guards the target list, so the side-effecting
    // `append_event(...)` function is NOT invoked on a scope miss (no seq bump,
    // no NOTIFY) — zero rows → RowNotFound, which the ledger helper logs.
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
    .fetch_optional(pool)
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
    sqlx::query_as(
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
    .fetch_all(pool)
    .await
}

// ─── Approvals & tool-call intents ────────────────────────────────────────
//
// Phase 6 gate hardening: the approvals table doubles as the INTENT registry.
// Every gate decision registers one row per (session_id, tool_call_id) —
// status 'intent' at registration, then either 'auto_allowed'/'auto_denied'
// (gate-decided) or the human approval lifecycle ('pending' → decided) when
// the verdict requires one. The row's (tool, input_digest) is the digest
// binding: a reused id must match it. tool_call_count counts these rows —
// unique persistent intents, never runner-posted events.

/// The full approvals column list as a literal, so every query below stays
/// a compile-time-audited static string (sqlx 0.9 SqlSafeStr).
macro_rules! approval_cols {
    () => {
        "id, session_id, tool_call_id, tool, summary, input_digest, risk, \
         scope, scope_key, status, requested_at, expires_at, decided_at, decided_by"
    };
}
// Re-exported by path so the `system_worker` module's approval scans share the
// same compile-time column literal.
pub(crate) use approval_cols;

/// Register a tool-call intent, idempotent by (session_id, tool_call_id).
/// Returns (row, inserted). When `inserted` is false the caller MUST compare
/// the row's (tool, input_digest) against the incoming call — a mismatch is
/// a protocol violation, never a re-attach.
pub async fn register_tool_intent(
    pool: &PgPool,
    scope: TenantScope,
    session: Uuid,
    tool_call_id: &str,
    tool: &str,
    summary: &str,
    input_digest: &str,
) -> sqlx::Result<(ApprovalRow, bool)> {
    let inserted: Option<ApprovalRow> = sqlx::query_as(concat!(
        "insert into approvals
           (id, session_id, tool_call_id, tool, summary, input_digest, scope, scope_key,
            status, expires_at)
         select $1,$2,$3,$4,$5,$6,'once',$4,'intent', now()
         where exists (select 1 from sessions s where s.id = $2 and s.tenant_id = $7)
         on conflict (session_id, tool_call_id) do nothing
         returning ",
        approval_cols!()
    ))
    .bind(Uuid::now_v7())
    .bind(session)
    .bind(tool_call_id)
    .bind(tool)
    .bind(summary)
    .bind(input_digest)
    .bind(scope.tenant_id())
    .fetch_optional(pool)
    .await?;
    if let Some(row) = inserted {
        return Ok((row, true));
    }
    let existing: ApprovalRow = sqlx::query_as(concat!(
        "select ",
        approval_cols!(),
        " from approvals
         where session_id = $1 and tool_call_id = $2
           and exists (select 1 from sessions s where s.id = $1 and s.tenant_id = $3)"
    ))
    .bind(session)
    .bind(tool_call_id)
    .bind(scope.tenant_id())
    .fetch_one(pool)
    .await?;
    Ok((existing, false))
}

/// Promote a registered intent into a pending human approval (the
/// RequireApproval path). Returns None when the row is no longer 'intent'
/// (a concurrent handler already promoted or the verdict landed) — the
/// caller re-reads and acts on the current status.
pub async fn promote_intent_to_pending(
    pool: &PgPool,
    scope: TenantScope,
    id: Uuid,
    risk: Option<&str>,
    approval_scope: &str,
    scope_key: &str,
    ttl_secs: i64,
) -> sqlx::Result<Option<ApprovalRow>> {
    sqlx::query_as(concat!(
        "update approvals
            set status = 'pending', risk = $2, scope = $3, scope_key = $4,
                expires_at = now() + make_interval(secs => $5)
          where id = $1 and status = 'intent'
            and exists (select 1 from sessions s
                        where s.id = approvals.session_id and s.tenant_id = $6)
          returning ",
        approval_cols!()
    ))
    .bind(id)
    .bind(risk)
    .bind(approval_scope)
    .bind(scope_key)
    .bind(ttl_secs as f64)
    .bind(scope.tenant_id())
    .fetch_optional(pool)
    .await
}

/// Record the gate's own verdict on an intent ('auto_allowed'/'auto_denied').
/// A compare-and-set guarded on status='intent': returns true iff THIS call
/// won the transition. A loser (another concurrent handler for the same
/// tool_call_id already moved the row, or a human decision landed) gets
/// false and must adopt the durable outcome instead of its locally-computed
/// verdict — that is what keeps one intent to one decision under races.
pub async fn record_intent_verdict(
    pool: &PgPool,
    scope: TenantScope,
    id: Uuid,
    status: &str,
) -> sqlx::Result<bool> {
    let res = sqlx::query(
        "update approvals set status = $2, decided_at = now(), decided_by = 'gate'
         where id = $1 and status = 'intent'
           and exists (select 1 from sessions s
                       where s.id = approvals.session_id and s.tenant_id = $3)",
    )
    .bind(id)
    .bind(status)
    .bind(scope.tenant_id())
    .execute(pool)
    .await?;
    Ok(res.rows_affected() > 0)
}

pub async fn decide_approval(
    pool: &PgPool,
    scope: TenantScope,
    id: Uuid,
    status: &str,
    decided_by: &str,
) -> sqlx::Result<Option<ApprovalRow>> {
    sqlx::query_as(concat!(
        "update approvals set status = $2, decided_at = now(), decided_by = $3
         where id = $1 and status = 'pending'
           and exists (select 1 from sessions s
                       where s.id = approvals.session_id and s.tenant_id = $4)
         returning ",
        approval_cols!()
    ))
    .bind(id)
    .bind(status)
    .bind(decided_by)
    .bind(scope.tenant_id())
    .fetch_optional(pool)
    .await
}

pub async fn get_approval(
    pool: &PgPool,
    scope: TenantScope,
    id: Uuid,
) -> sqlx::Result<Option<ApprovalRow>> {
    sqlx::query_as(concat!(
        "select ",
        approval_cols!(),
        " from approvals
         where id = $1
           and exists (select 1 from sessions s
                       where s.id = approvals.session_id and s.tenant_id = $2)"
    ))
    .bind(id)
    .bind(scope.tenant_id())
    .fetch_optional(pool)
    .await
}

/// Human-lifecycle rows only: intent bookkeeping ('intent'/'auto_*') is the
/// gate's, not the approvals API's.
pub async fn session_approvals(
    pool: &PgPool,
    scope: TenantScope,
    session: Uuid,
) -> sqlx::Result<Vec<ApprovalRow>> {
    sqlx::query_as(concat!(
        "select ",
        approval_cols!(),
        " from approvals
         where session_id = $1 and status not in ('intent','auto_allowed','auto_denied')
           and exists (select 1 from sessions s where s.id = $1 and s.tenant_id = $2)
         order by requested_at desc"
    ))
    .bind(session)
    .bind(scope.tenant_id())
    .fetch_all(pool)
    .await
}

/// The tenant-scoped approvals inbox (the org approval queue). The
/// cross-tenant expiry sweep runs off [`system_worker::expire_stale_approvals`];
/// this one is what a request handler shows an approver, and it never crosses a
/// tenant boundary.
pub async fn pending_approvals(
    pool: &PgPool,
    scope: TenantScope,
) -> sqlx::Result<Vec<ApprovalRow>> {
    sqlx::query_as(concat!(
        "select ",
        approval_cols!(),
        " from approvals
         where status = 'pending'
           and exists (select 1 from sessions s
                       where s.id = approvals.session_id and s.tenant_id = $1)
         order by requested_at"
    ))
    .bind(scope.tenant_id())
    .fetch_all(pool)
    .await
}

/// Has this session already granted `approved_session` for this scope key?
pub async fn has_session_grant(
    pool: &PgPool,
    scope: TenantScope,
    session: Uuid,
    scope_key: &str,
) -> sqlx::Result<bool> {
    let row = sqlx::query(
        "select exists(
           select 1 from approvals
           where session_id = $1 and scope_key = $2 and status = 'approved_session'
             and exists (select 1 from sessions s where s.id = $1 and s.tenant_id = $3)
         ) as granted",
    )
    .bind(session)
    .bind(scope_key)
    .bind(scope.tenant_id())
    .fetch_one(pool)
    .await?;
    Ok(row.get::<bool, _>("granted"))
}

// ─── Artifacts ────────────────────────────────────────────────────────────

pub async fn add_artifact(
    pool: &PgPool,
    scope: TenantScope,
    session: Uuid,
    kind: &str,
    name: &str,
    content: &str,
    content_type: &str,
) -> sqlx::Result<ArtifactRow> {
    sqlx::query_as(
        "insert into artifacts (id, session_id, kind, name, content, content_type)
         select $1,$2,$3,$4,$5,$6
         where exists (select 1 from sessions s where s.id = $2 and s.tenant_id = $7)
         returning *",
    )
    .bind(Uuid::now_v7())
    .bind(session)
    .bind(kind)
    .bind(name)
    .bind(content)
    .bind(content_type)
    .bind(scope.tenant_id())
    .fetch_one(pool)
    .await
}

pub async fn list_artifacts(
    pool: &PgPool,
    scope: TenantScope,
    session: Uuid,
) -> sqlx::Result<Vec<ArtifactRow>> {
    sqlx::query_as(
        "select * from artifacts
         where session_id = $1
           and exists (select 1 from sessions s where s.id = $1 and s.tenant_id = $2)
         order by created_at",
    )
    .bind(session)
    .bind(scope.tenant_id())
    .fetch_all(pool)
    .await
}

pub async fn get_artifact(
    pool: &PgPool,
    scope: TenantScope,
    id: Uuid,
) -> sqlx::Result<Option<ArtifactRow>> {
    sqlx::query_as(
        "select * from artifacts a
         where a.id = $1
           and exists (select 1 from sessions s where s.id = a.session_id and s.tenant_id = $2)",
    )
    .bind(id)
    .bind(scope.tenant_id())
    .fetch_optional(pool)
    .await
}

// ─── Usage ────────────────────────────────────────────────────────────────

#[allow(clippy::too_many_arguments)]
pub async fn add_usage(
    pool: &PgPool,
    scope: TenantScope,
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
         select $1,$2,$3,$4,$5,$6,$7,$8,$9,$10
         where exists (select 1 from sessions s where s.id = $2 and s.tenant_id = $11)
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
    .bind(scope.tenant_id())
    .execute(pool)
    .await?;
    Ok(res.rows_affected() > 0)
}

pub async fn usage_totals(
    pool: &PgPool,
    scope: TenantScope,
    session: Uuid,
) -> sqlx::Result<UsageTotals> {
    sqlx::query_as(
        "select coalesce(sum(input_tokens),0)::bigint as input_tokens,
                coalesce(sum(output_tokens),0)::bigint as output_tokens,
                coalesce(sum(cache_read_tokens),0)::bigint as cache_read_tokens,
                coalesce(sum(cache_write_tokens),0)::bigint as cache_write_tokens,
                coalesce(sum(cost_usd),0)::float8 as cost_usd,
                count(*)::bigint as requests
         from usage_entries
         where session_id = $1
           and exists (select 1 from sessions s where s.id = $1 and s.tenant_id = $2)",
    )
    .bind(session)
    .bind(scope.tenant_id())
    .fetch_one(pool)
    .await
}

/// Unique persistent tool-call INTENTS (one approvals row per tool_call_id)
/// — the budget's counting unit. Never derived from runner-posted events:
/// budget parity does not trust runner cooperation.
pub async fn tool_call_count(
    pool: &PgPool,
    scope: TenantScope,
    session: Uuid,
) -> sqlx::Result<i64> {
    let row = sqlx::query(
        "select count(*)::bigint as n from approvals
         where session_id = $1
           and exists (select 1 from sessions s where s.id = $1 and s.tenant_id = $2)",
    )
    .bind(session)
    .bind(scope.tenant_id())
    .fetch_one(pool)
    .await?;
    Ok(row.get::<i64, _>("n"))
}

// ─── Tokens ───────────────────────────────────────────────────────────────

pub async fn create_session_token(
    pool: &PgPool,
    scope: TenantScope,
    session: Uuid,
    token_plain: &str,
    ttl_secs: i64,
) -> sqlx::Result<()> {
    sqlx::query(
        "insert into api_tokens (id, tenant_id, kind, session_id, token_sha256, expires_at)
         values ($1, $2, 'session', $3, $4, now() + make_interval(secs => $5))",
    )
    .bind(Uuid::now_v7())
    .bind(scope.tenant_id())
    .bind(session)
    .bind(sha256_hex(token_plain))
    .bind(ttl_secs as f64)
    .execute(pool)
    .await?;
    Ok(())
}

/// What resolving a session token yields: the session it belongs to AND its
/// owning tenant. The tenant rides the credential so the caller (auth
/// extractor / facade / `/result`) can build a `TenantScope` without a second
/// query — the "bootstrap exception" pattern (token resolution keys purely on
/// the sha256, then hands back a verified tenant).
#[derive(Debug, Clone, Copy)]
pub struct SessionTokenAuth {
    pub session_id: Uuid,
    pub tenant_id: Uuid,
}

/// Resolve a session token to its session IGNORING revoked_at/expiry — used
/// ONLY by /result to acknowledge an already-terminal session whose token was
/// revoked on the terminal transition (so a lost-response retry acks cleanly).
/// Every other endpoint uses the strict `session_for_token`. A completely
/// bogus token still returns None; a real token resolves to its own session,
/// and the caller gates the ack on that session being terminal.
pub async fn session_for_token_incl_revoked(
    pool: &PgPool,
    token_plain: &str,
) -> sqlx::Result<Option<SessionTokenAuth>> {
    let row = sqlx::query(
        "select session_id, tenant_id from api_tokens
         where kind = 'session' and token_sha256 = $1",
    )
    .bind(sha256_hex(token_plain))
    .fetch_optional(pool)
    .await?;
    Ok(row.and_then(|r| {
        r.get::<Option<Uuid>, _>("session_id")
            .map(|session_id| SessionTokenAuth {
                session_id,
                tenant_id: r.get::<Uuid, _>("tenant_id"),
            })
    }))
}

/// Returns the session (and its tenant) a valid (unexpired, unrevoked) token
/// belongs to.
pub async fn session_for_token(
    pool: &PgPool,
    token_plain: &str,
) -> sqlx::Result<Option<SessionTokenAuth>> {
    let row = sqlx::query(
        "select session_id, tenant_id from api_tokens
         where kind = 'session' and token_sha256 = $1
           and revoked_at is null
           and (expires_at is null or expires_at > now())",
    )
    .bind(sha256_hex(token_plain))
    .fetch_optional(pool)
    .await?;
    Ok(row.and_then(|r| {
        r.get::<Option<Uuid>, _>("session_id")
            .map(|session_id| SessionTokenAuth {
                session_id,
                tenant_id: r.get::<Uuid, _>("tenant_id"),
            })
    }))
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

/// Revoke every live session token for a session — called when the session
/// enters a terminal state so a still-running or wedged runner can no longer
/// authenticate to the facade or internal gateway (defense in depth beyond
/// the facade's own terminal-session refusal).
pub async fn revoke_session_tokens(
    pool: &PgPool,
    scope: TenantScope,
    session: Uuid,
) -> sqlx::Result<u64> {
    let res = sqlx::query(
        "update api_tokens set revoked_at = now()
         where kind = 'session' and session_id = $1 and revoked_at is null
           and exists (select 1 from sessions s where s.id = $1 and s.tenant_id = $2)",
    )
    .bind(session)
    .bind(scope.tenant_id())
    .execute(pool)
    .await?;
    Ok(res.rows_affected())
}

// ─── Trigger invocations (Idempotency-Key) ────────────────────────────────

#[derive(Debug)]
pub enum InvocationClaim {
    /// We own this key — create the run, binding this claim atomically via
    /// create_session's bind_invocation param.
    Claimed { invocation_id: Uuid },
    /// This key already produced a run — return it (after digest check).
    Replay {
        session_id: Uuid,
        request_digest: String,
    },
    /// This key's firing was skipped (overlap | missed | error: …) — a
    /// terminal outcome; replays of the key return it forever.
    Skipped { reason: String },
    /// Another request holds the key mid-creation — caller should 409.
    InFlight,
}

/// Claim an idempotency key. Exactly one concurrent caller wins the insert;
/// a claim whose creation crashed (bound to no session) becomes re-claimable
/// after 60s so a dangling row can't wedge the key forever.
pub async fn claim_invocation(
    pool: &PgPool,
    scope: TenantScope,
    subscription: Uuid,
    idempotency_key: &str,
    request_digest: &str,
) -> sqlx::Result<InvocationClaim> {
    let inserted = sqlx::query(
        "insert into trigger_invocations (id, subscription_id, idempotency_key, request_digest)
         select $1, $2, $3, $4
         where exists (select 1 from trigger_subscriptions where id = $2 and tenant_id = $5)
         on conflict (subscription_id, idempotency_key) do nothing
         returning id",
    )
    .bind(Uuid::now_v7())
    .bind(subscription)
    .bind(idempotency_key)
    .bind(request_digest)
    .bind(scope.tenant_id())
    .fetch_optional(pool)
    .await?;
    if let Some(row) = inserted {
        return Ok(InvocationClaim::Claimed {
            invocation_id: row.get("id"),
        });
    }
    let existing = sqlx::query(
        "select id, session_id, request_digest, skip_reason, created_at from trigger_invocations
         where subscription_id = $1 and idempotency_key = $2
           and exists (select 1 from trigger_subscriptions where id = $1 and tenant_id = $3)",
    )
    .bind(subscription)
    .bind(idempotency_key)
    .bind(scope.tenant_id())
    .fetch_one(pool)
    .await?;
    if let Some(session_id) = existing.get::<Option<Uuid>, _>("session_id") {
        return Ok(InvocationClaim::Replay {
            session_id,
            request_digest: existing.get("request_digest"),
        });
    }
    if let Some(reason) = existing.get::<Option<String>, _>("skip_reason") {
        return Ok(InvocationClaim::Skipped { reason });
    }
    // Unbound claim: take it over only once it is stale (crashed creator).
    // Skipped rows are terminal — never stealable.
    let takeover = sqlx::query(
        "update trigger_invocations
            set created_at = now(), request_digest = $3
          where subscription_id = $1 and idempotency_key = $2
            and session_id is null and skip_reason is null
            and created_at < now() - interval '60 seconds'
            and exists (select 1 from trigger_subscriptions where id = $1 and tenant_id = $4)
          returning id",
    )
    .bind(subscription)
    .bind(idempotency_key)
    .bind(request_digest)
    .bind(scope.tenant_id())
    .fetch_optional(pool)
    .await?;
    Ok(match takeover {
        Some(row) => InvocationClaim::Claimed {
            invocation_id: row.get("id"),
        },
        None => InvocationClaim::InFlight,
    })
}

/// A skipped firing is the terminal state of its claim row: visibly
/// recorded, never re-claimable. Guarded on session_id so a bound run can
/// never be relabelled a skip.
pub async fn mark_invocation_skipped(
    pool: &PgPool,
    scope: TenantScope,
    invocation: Uuid,
    reason: &str,
) -> sqlx::Result<()> {
    sqlx::query(
        "update trigger_invocations set skip_reason = $2
         where id = $1 and session_id is null
           and exists (select 1 from trigger_subscriptions sub
                       where sub.id = trigger_invocations.subscription_id
                         and sub.tenant_id = $3)",
    )
    .bind(invocation)
    .bind(reason)
    .bind(scope.tenant_id())
    .execute(pool)
    .await?;
    Ok(())
}

#[derive(Debug, Clone, sqlx::FromRow, serde::Serialize)]
pub struct TriggerInvocationRow {
    pub id: Uuid,
    pub subscription_id: Uuid,
    pub idempotency_key: String,
    pub session_id: Option<Uuid>,
    pub skip_reason: Option<String>,
    pub created_at: DateTime<Utc>,
}

pub async fn list_subscription_invocations(
    pool: &PgPool,
    scope: TenantScope,
    subscription: Uuid,
    limit: i64,
) -> sqlx::Result<Vec<TriggerInvocationRow>> {
    sqlx::query_as(
        "select id, subscription_id, idempotency_key, session_id, skip_reason, created_at
         from trigger_invocations where subscription_id = $1
           and exists (select 1 from trigger_subscriptions where id = $1 and tenant_id = $3)
         order by created_at desc limit $2",
    )
    .bind(subscription)
    .bind(limit)
    .bind(scope.tenant_id())
    .fetch_all(pool)
    .await
}

/// Non-terminal runs of a subscription — the concurrency-policy input.
pub async fn active_subscription_sessions(
    pool: &PgPool,
    scope: TenantScope,
    subscription: Uuid,
) -> sqlx::Result<Vec<SessionRow>> {
    sqlx::query_as(
        "select s.* from sessions s
         join trigger_invocations i on i.session_id = s.id
         where i.subscription_id = $1 and s.tenant_id = $2
           and s.status not in ('completed','failed','cancelled','budget_exceeded')
         order by s.created_at",
    )
    .bind(subscription)
    .bind(scope.tenant_id())
    .fetch_all(pool)
    .await
}

/// Free a claim whose run creation failed, so an immediate retry can re-try.
pub async fn release_invocation(
    pool: &PgPool,
    scope: TenantScope,
    invocation: Uuid,
) -> sqlx::Result<()> {
    sqlx::query(
        "delete from trigger_invocations where id = $1 and session_id is null
           and exists (select 1 from trigger_subscriptions sub
                       where sub.id = trigger_invocations.subscription_id
                         and sub.tenant_id = $2)",
    )
    .bind(invocation)
    .bind(scope.tenant_id())
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn list_subscription_sessions(
    pool: &PgPool,
    scope: TenantScope,
    subscription: Uuid,
    limit: i64,
) -> sqlx::Result<Vec<SessionRow>> {
    sqlx::query_as(
        "select s.* from sessions s
         join trigger_invocations i on i.session_id = s.id
         where i.subscription_id = $1 and s.tenant_id = $3
         order by s.created_at desc limit $2",
    )
    .bind(subscription)
    .bind(limit)
    .bind(scope.tenant_id())
    .fetch_all(pool)
    .await
}

/// Scopes the trigger-token polling endpoint to runs this subscription made.
pub async fn subscription_owns_session(
    pool: &PgPool,
    scope: TenantScope,
    subscription: Uuid,
    session: Uuid,
) -> sqlx::Result<bool> {
    let row = sqlx::query(
        "select exists(
           select 1 from trigger_invocations ti
           join trigger_subscriptions sub on sub.id = ti.subscription_id
           where ti.subscription_id = $1 and ti.session_id = $2 and sub.tenant_id = $3
         ) as owned",
    )
    .bind(subscription)
    .bind(session)
    .bind(scope.tenant_id())
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

/// True if a delivery row exists for this session AND destination — the
/// per-destination idempotency check both enqueue paths (the terminal
/// transition and the claim-serialized reconciler) run before inserting:
/// a crash after destination A but before destination B is healed by
/// enqueueing exactly B, never duplicating A, and "some rows exist" is
/// never mistaken for "all destinations enqueued".
pub async fn result_delivery_exists_for(
    pool: &PgPool,
    scope: TenantScope,
    session: Uuid,
    destination: &Value,
) -> sqlx::Result<bool> {
    let (exists,): (bool,) = sqlx::query_as(
        "select exists(select 1 from result_deliveries
           where session_id = $1 and destination = $2
             and exists (select 1 from sessions s where s.id = $1 and s.tenant_id = $3))",
    )
    .bind(session)
    .bind(destination)
    .bind(scope.tenant_id())
    .fetch_one(pool)
    .await?;
    Ok(exists)
}

/// True if the session already has a `run.result` ledger event — the
/// reconciler's exactly-once guard (emit-if-missing under the finalize
/// claim, which serializes drivers).
pub async fn has_run_result_event(
    pool: &PgPool,
    scope: TenantScope,
    session: Uuid,
) -> sqlx::Result<bool> {
    let (exists,): (bool,) = sqlx::query_as(
        "select exists(select 1 from events where session_id = $1 and type = 'run.result'
           and exists (select 1 from sessions s where s.id = $1 and s.tenant_id = $2))",
    )
    .bind(session)
    .bind(scope.tenant_id())
    .fetch_one(pool)
    .await?;
    Ok(exists)
}

pub async fn enqueue_result_delivery(
    pool: &PgPool,
    scope: TenantScope,
    session: Uuid,
    subscription: Option<Uuid>,
    destination: &Value,
) -> sqlx::Result<ResultDeliveryRow> {
    // The session must be in scope AND — when a subscription is named — it must
    // belong to the SAME tenant (a cross-tenant subscription is proven
    // impossible here, not just Rust-side). A miss → fetch_one RowNotFound, the
    // existing not-in-scope-session shape.
    sqlx::query_as(
        "insert into result_deliveries (id, session_id, subscription_id, destination)
         select $1, $2, $3, $4
         where exists (select 1 from sessions s where s.id = $2 and s.tenant_id = $5)
           and ($3::uuid is null or exists (
                 select 1 from trigger_subscriptions sub where sub.id = $3 and sub.tenant_id = $5))
         returning *",
    )
    .bind(Uuid::now_v7())
    .bind(session)
    .bind(subscription)
    .bind(destination)
    .bind(scope.tenant_id())
    .fetch_one(pool)
    .await
}

/// Record one attempt. ok → delivered; failure → attempts+1 and either
/// rescheduled (`retry_in_secs`) or terminally 'failed' at `max_attempts`.
#[allow(clippy::too_many_arguments)]
pub async fn mark_delivery_attempt(
    pool: &PgPool,
    scope: TenantScope,
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
         where id = $1
           and exists (select 1 from sessions s
                       where s.id = result_deliveries.session_id and s.tenant_id = $7)
         returning *",
    )
    .bind(id)
    .bind(ok)
    .bind(error)
    .bind(payload_digest)
    .bind(retry_in_secs as f64)
    .bind(max_attempts)
    .bind(scope.tenant_id())
    .fetch_optional(pool)
    .await
}

pub async fn list_session_deliveries(
    pool: &PgPool,
    scope: TenantScope,
    session: Uuid,
) -> sqlx::Result<Vec<ResultDeliveryRow>> {
    sqlx::query_as(
        "select * from result_deliveries where session_id = $1
           and exists (select 1 from sessions s where s.id = $1 and s.tenant_id = $2)
         order by created_at",
    )
    .bind(session)
    .bind(scope.tenant_id())
    .fetch_all(pool)
    .await
}

pub async fn list_subscription_deliveries(
    pool: &PgPool,
    scope: TenantScope,
    subscription: Uuid,
    limit: i64,
) -> sqlx::Result<Vec<ResultDeliveryRow>> {
    sqlx::query_as(
        "select * from result_deliveries where subscription_id = $1
           and exists (select 1 from trigger_subscriptions sub
                       where sub.id = $1 and sub.tenant_id = $3)
         order by created_at desc limit $2",
    )
    .bind(subscription)
    .bind(limit)
    .bind(scope.tenant_id())
    .fetch_all(pool)
    .await
}

// ─── Schedules (Phase 3: the clock on a subscription) ────────────────────

#[derive(Debug, Clone, sqlx::FromRow, serde::Serialize)]
pub struct ScheduleRow {
    pub id: Uuid,
    pub subscription_id: Uuid,
    pub cron: String,
    pub timezone: String,
    pub next_fire_at: Option<DateTime<Utc>>,
    pub missed_run_policy: String,
    pub last_fired_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

pub async fn create_schedule(
    pool: &PgPool,
    scope: TenantScope,
    subscription: Uuid,
    cron: &str,
    timezone: &str,
    next_fire_at: DateTime<Utc>,
    missed_run_policy: &str,
) -> sqlx::Result<ScheduleRow> {
    sqlx::query_as(
        "insert into schedules (id, subscription_id, cron, timezone, next_fire_at, missed_run_policy)
         select $1, $2, $3, $4, $5, $6
         where exists (select 1 from trigger_subscriptions where id = $2 and tenant_id = $7)
         returning *",
    )
    .bind(Uuid::now_v7())
    .bind(subscription)
    .bind(cron)
    .bind(timezone)
    .bind(next_fire_at)
    .bind(missed_run_policy)
    .bind(scope.tenant_id())
    .fetch_one(pool)
    .await
}

pub async fn schedule_for_subscription(
    pool: &PgPool,
    scope: TenantScope,
    subscription: Uuid,
) -> sqlx::Result<Option<ScheduleRow>> {
    sqlx::query_as(
        "select * from schedules where subscription_id = $1
           and exists (select 1 from trigger_subscriptions sub
                       where sub.id = $1 and sub.tenant_id = $2)",
    )
    .bind(subscription)
    .bind(scope.tenant_id())
    .fetch_optional(pool)
    .await
}

pub async fn schedules_for_tenant(
    pool: &PgPool,
    scope: TenantScope,
) -> sqlx::Result<Vec<ScheduleRow>> {
    sqlx::query_as(
        "select sc.* from schedules sc
         join trigger_subscriptions sub on sub.id = sc.subscription_id
         where sub.tenant_id = $1",
    )
    .bind(scope.tenant_id())
    .fetch_all(pool)
    .await
}

/// CAS advance: only moves the clock if next_fire_at is still the fire time
/// this worker processed — two workers can never double-advance past an
/// unhandled fire time.
pub async fn advance_schedule(
    pool: &PgPool,
    scope: TenantScope,
    id: Uuid,
    from: DateTime<Utc>,
    to: Option<DateTime<Utc>>,
    fired_at: Option<DateTime<Utc>>,
) -> sqlx::Result<bool> {
    let res = sqlx::query(
        "update schedules set
            next_fire_at = $2,
            last_fired_at = coalesce($3, last_fired_at),
            updated_at = now()
         where id = $1 and next_fire_at = $4
           and exists (select 1 from trigger_subscriptions sub
                       where sub.id = schedules.subscription_id and sub.tenant_id = $5)",
    )
    .bind(id)
    .bind(to)
    .bind(fired_at)
    .bind(from)
    .bind(scope.tenant_id())
    .execute(pool)
    .await?;
    Ok(res.rows_affected() > 0)
}

pub async fn create_trigger_token(
    pool: &PgPool,
    scope: TenantScope,
    subscription: Uuid,
    token_plain: &str,
) -> sqlx::Result<()> {
    sqlx::query(
        "insert into api_tokens (id, tenant_id, kind, subscription_id, token_sha256)
         values ($1, $2, 'trigger', $3, $4)",
    )
    .bind(Uuid::now_v7())
    .bind(scope.tenant_id())
    .bind(subscription)
    .bind(sha256_hex(token_plain))
    .execute(pool)
    .await?;
    Ok(())
}

/// What resolving a trigger token yields: the subscription it may invoke AND
/// its owning tenant (the "bootstrap exception" pattern — keys on the sha256,
/// hands back a verified tenant).
#[derive(Debug, Clone, Copy)]
pub struct TriggerTokenAuth {
    pub subscription_id: Uuid,
    pub tenant_id: Uuid,
}

/// Resolves a scoped trigger token to its subscription (and tenant). This is
/// the entire authority of the token — it can never satisfy Admin or
/// SessionAuth.
pub async fn subscription_for_token(
    pool: &PgPool,
    token_plain: &str,
) -> sqlx::Result<Option<TriggerTokenAuth>> {
    let row = sqlx::query(
        "select subscription_id, tenant_id from api_tokens
         where kind = 'trigger' and token_sha256 = $1
           and revoked_at is null
           and (expires_at is null or expires_at > now())",
    )
    .bind(sha256_hex(token_plain))
    .fetch_optional(pool)
    .await?;
    Ok(row.and_then(|r| {
        r.get::<Option<Uuid>, _>("subscription_id")
            .map(|subscription_id| TriggerTokenAuth {
                subscription_id,
                tenant_id: r.get::<Uuid, _>("tenant_id"),
            })
    }))
}

/// Rotation support: kill every live token for the subscription.
pub async fn revoke_trigger_tokens(
    pool: &PgPool,
    scope: TenantScope,
    subscription: Uuid,
) -> sqlx::Result<u64> {
    let res = sqlx::query(
        "update api_tokens set revoked_at = now()
         where kind = 'trigger' and subscription_id = $1 and revoked_at is null
           and exists (select 1 from trigger_subscriptions sub
                       where sub.id = $1 and sub.tenant_id = $2)",
    )
    .bind(subscription)
    .bind(scope.tenant_id())
    .execute(pool)
    .await?;
    Ok(res.rows_affected())
}

// ─── LISTEN/NOTIFY wakeup hub ─────────────────────────────────────────────

/// Spawns the notify listener with a reconnect loop. Payloads are
/// (session_id, seq). Delivery is best-effort by design — every consumer
/// polls the seq catch-up query as the source of truth.
// ─── Event deliveries & dispatches (design §6.4) ──────────────────────────

#[derive(Debug, Clone, sqlx::FromRow, serde::Serialize)]
pub struct TriggerDeliveryRow {
    pub id: Uuid,
    pub connection_id: Uuid,
    pub external_event_id: String,
    pub event_type: String,
    pub payload: Value,
    pub payload_digest: String,
    pub occurred_at: Option<DateTime<Utc>>,
    pub received_at: DateTime<Utc>,
}

#[derive(Debug, Clone, sqlx::FromRow, serde::Serialize)]
pub struct TriggerDispatchRow {
    pub id: Uuid,
    pub delivery_id: Uuid,
    pub subscription_id: Uuid,
    pub session_id: Option<Uuid>,
    pub status: String,
    pub skip_reason: Option<String>,
    pub created_at: DateTime<Utc>,
}

/// Level-1 dedup: store the delivery once; a retry returns the stored row
/// with `fresh = false` and the caller re-walks dispatch (which is itself
/// idempotent) — so a retry can only ever HEAL a partial fan-out.
#[allow(clippy::too_many_arguments)]
pub async fn insert_trigger_delivery(
    pool: &PgPool,
    scope: TenantScope,
    connection: Uuid,
    external_event_id: &str,
    event_type: &str,
    payload: &Value,
    payload_digest: &str,
    occurred_at: Option<DateTime<Utc>>,
) -> sqlx::Result<(TriggerDeliveryRow, bool)> {
    let inserted: Option<TriggerDeliveryRow> = sqlx::query_as(
        "insert into trigger_deliveries
           (id, connection_id, external_event_id, event_type, payload, payload_digest, occurred_at)
         select $1,$2,$3,$4,$5,$6,$7
         where exists (select 1 from integration_connections c where c.id = $2 and c.tenant_id = $8)
         on conflict (connection_id, external_event_id) do nothing
         returning *",
    )
    .bind(Uuid::now_v7())
    .bind(connection)
    .bind(external_event_id)
    .bind(event_type)
    .bind(payload)
    .bind(payload_digest)
    .bind(occurred_at)
    .bind(scope.tenant_id())
    .fetch_optional(pool)
    .await?;
    if let Some(row) = inserted {
        return Ok((row, true));
    }
    let existing = sqlx::query_as(
        "select * from trigger_deliveries where connection_id = $1 and external_event_id = $2
           and exists (select 1 from integration_connections c where c.id = $1 and c.tenant_id = $3)",
    )
    .bind(connection)
    .bind(external_event_id)
    .bind(scope.tenant_id())
    .fetch_one(pool)
    .await?;
    Ok((existing, false))
}

/// Level-2 dedup: claim the (delivery, subscription) slot. `None` means the
/// slot already produced its outcome (a bound run, a recorded skip/error, or
/// a fresh in-flight creation) — the caller fires nothing. Like
/// `claim_invocation`, an unbound `created` claim older than 60s is
/// stealable (crashed creator); skipped/errored rows are terminal.
pub async fn claim_trigger_dispatch(
    pool: &PgPool,
    scope: TenantScope,
    delivery: Uuid,
    subscription: Uuid,
) -> sqlx::Result<Option<TriggerDispatchRow>> {
    // Both the subscription AND the delivery's connection must sit in this
    // tenant (the delivery→connection→tenant join is the same proof
    // `list_delivery_dispatches` uses). A miss → zero rows → None, the existing
    // no-claim shape.
    let inserted: Option<TriggerDispatchRow> = sqlx::query_as(
        "insert into trigger_dispatches (id, delivery_id, subscription_id)
         select $1,$2,$3
         where exists (select 1 from trigger_subscriptions sub
                       where sub.id = $3 and sub.tenant_id = $4)
           and exists (select 1 from trigger_deliveries d
                       join integration_connections c on c.id = d.connection_id
                       where d.id = $2 and c.tenant_id = $4)
         on conflict (delivery_id, subscription_id) do nothing
         returning *",
    )
    .bind(Uuid::now_v7())
    .bind(delivery)
    .bind(subscription)
    .bind(scope.tenant_id())
    .fetch_optional(pool)
    .await?;
    if inserted.is_some() {
        return Ok(inserted);
    }
    sqlx::query_as(
        "update trigger_dispatches
            set created_at = now()
          where delivery_id = $1 and subscription_id = $2
            and session_id is null and status = 'created'
            and created_at < now() - interval '60 seconds'
            and exists (select 1 from trigger_subscriptions sub
                        where sub.id = $2 and sub.tenant_id = $3)
            and exists (select 1 from trigger_deliveries d
                        join integration_connections c on c.id = d.connection_id
                        where d.id = $1 and c.tenant_id = $3)
          returning *",
    )
    .bind(delivery)
    .bind(subscription)
    .bind(scope.tenant_id())
    .fetch_optional(pool)
    .await
}

/// Terminal bookkeeping for a claimed-but-not-run dispatch (skipped |
/// error). Guarded on session_id so a bound run can never be relabelled.
pub async fn mark_dispatch_outcome(
    pool: &PgPool,
    scope: TenantScope,
    dispatch: Uuid,
    status: &str,
    skip_reason: Option<&str>,
) -> sqlx::Result<()> {
    sqlx::query(
        "update trigger_dispatches set status = $2, skip_reason = $3
         where id = $1 and session_id is null
           and exists (select 1 from trigger_subscriptions sub
                       where sub.id = trigger_dispatches.subscription_id and sub.tenant_id = $4)",
    )
    .bind(dispatch)
    .bind(status)
    .bind(skip_reason)
    .bind(scope.tenant_id())
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn list_delivery_dispatches(
    pool: &PgPool,
    scope: TenantScope,
    delivery: Uuid,
) -> sqlx::Result<Vec<TriggerDispatchRow>> {
    sqlx::query_as(
        "select * from trigger_dispatches where delivery_id = $1
           and exists (select 1 from trigger_deliveries d
                       join integration_connections c on c.id = d.connection_id
                       where d.id = $1 and c.tenant_id = $2)
         order by created_at",
    )
    .bind(delivery)
    .bind(scope.tenant_id())
    .fetch_all(pool)
    .await
}

pub async fn list_connection_deliveries(
    pool: &PgPool,
    scope: TenantScope,
    connection: Uuid,
    limit: i64,
) -> sqlx::Result<Vec<TriggerDeliveryRow>> {
    sqlx::query_as(
        "select * from trigger_deliveries where connection_id = $1
           and exists (select 1 from integration_connections c where c.id = $1 and c.tenant_id = $3)
         order by received_at desc limit $2",
    )
    .bind(connection)
    .bind(limit)
    .bind(scope.tenant_id())
    .fetch_all(pool)
    .await
}

// ─── External results (§17 #3: stable update-in-place identity) ───────────

#[derive(Debug, Clone, sqlx::FromRow, serde::Serialize)]
pub struct ExternalResultRow {
    pub id: Uuid,
    pub subscription_id: Uuid,
    pub kind: String,
    pub resource_key: String,
    pub external_id: String,
    pub external_url: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

pub async fn get_external_result(
    pool: &PgPool,
    scope: TenantScope,
    subscription: Uuid,
    kind: &str,
    resource_key: &str,
) -> sqlx::Result<Option<ExternalResultRow>> {
    sqlx::query_as(
        "select * from external_results
         where subscription_id = $1 and kind = $2 and resource_key = $3
           and exists (select 1 from trigger_subscriptions sub
                       where sub.id = $1 and sub.tenant_id = $4)",
    )
    .bind(subscription)
    .bind(kind)
    .bind(resource_key)
    .bind(scope.tenant_id())
    .fetch_optional(pool)
    .await
}

pub async fn upsert_external_result(
    pool: &PgPool,
    scope: TenantScope,
    subscription: Uuid,
    kind: &str,
    resource_key: &str,
    external_id: &str,
    external_url: Option<&str>,
) -> sqlx::Result<ExternalResultRow> {
    sqlx::query_as(
        "insert into external_results
           (id, subscription_id, kind, resource_key, external_id, external_url)
         select $1,$2,$3,$4,$5,$6
         where exists (select 1 from trigger_subscriptions sub
                       where sub.id = $2 and sub.tenant_id = $7)
         on conflict (subscription_id, kind, resource_key)
           do update set external_id = excluded.external_id,
                         external_url = excluded.external_url,
                         updated_at = now()
         returning *",
    )
    .bind(Uuid::now_v7())
    .bind(subscription)
    .bind(kind)
    .bind(resource_key)
    .bind(external_id)
    .bind(external_url)
    .bind(scope.tenant_id())
    .fetch_one(pool)
    .await
}

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

    /// The durable-finalizer DB contract (PR #47 fix batch 2 — H3/H5):
    /// single-winner intent under the session row lock, quiesce computed from
    /// the LOCKED snapshot, losers receive the winner's row, recovery sees
    /// intents on ACTIVE sessions, and a terminal session fences both intent
    /// re-creation and late sandbox-handle attachment.
    #[tokio::test]
    async fn finalization_intent_is_transactional_and_single_winner() {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("skipping: DATABASE_URL not set");
            return;
        };
        let pool = connect(&url).await.expect("connect");
        let tenant = ensure_default_tenant(&pool).await.unwrap();
        let scope = TenantScope::assume(tenant);
        let policy = upsert_policy(
            &pool,
            scope,
            "test-finalize",
            "name: test-finalize",
            &serde_json::json!({"name": "test-finalize"}),
        )
        .await
        .unwrap();
        let agent = create_agent(&pool, scope, "test-finalize-agent", None)
            .await
            .unwrap();
        let rev = append_agent_revision(
            &pool,
            scope,
            agent.id,
            "claude-agent-sdk",
            "img:test",
            "claude-haiku-4-5",
            None,
            policy.id,
            &serde_json::json!({}),
            None,
            &serde_json::json!([]),
            &serde_json::json!([]),
        )
        .await
        .unwrap();
        let repo = serde_json::json!({"kind":"none"});
        let empty = serde_json::json!({});
        let mk = |title: &'static str| {
            create_session(
                &pool,
                scope,
                agent.id,
                rev.id,
                "supervised",
                "trusted",
                title,
                &repo,
                &empty,
                &empty,
                None,
                None,
                None,
                None,
                None,
                &[],
            )
        };
        let racer = mk("finalize-test race").await.unwrap();
        let fenced = mk("finalize-test fence").await.unwrap();

        use fluidbox_core::state::SessionStatus;
        // Advance the race session to running with a handle so the locked
        // snapshot computes a REAL quiesce for want_quiesce callers.
        for st in [
            SessionStatus::Provisioning,
            SessionStatus::Initializing,
            SessionStatus::Running,
        ] {
            transition_session(&pool, scope, racer.id, st, None)
                .await
                .unwrap();
        }
        let attached_active = set_sandbox_handle(
            &pool,
            scope,
            racer.id,
            &serde_json::json!({"external_id":"t","uid":"u"}),
        )
        .await
        .unwrap();

        // Genuinely concurrent: two connections race the insert under the
        // row lock — a cancel (wants quiesce) against a /result (does not).
        let (a, b) = tokio::join!(
            begin_finalization(
                &pool,
                scope,
                racer.id,
                "cancelled",
                None,
                Some("race"),
                true,
                30
            ),
            begin_finalization(
                &pool,
                scope,
                racer.id,
                "completed",
                Some("done"),
                None,
                false,
                30
            ),
        );
        let unpack = |r: sqlx::Result<BeginFinalization>| match r.unwrap() {
            BeginFinalization::Persisted {
                row,
                created,
                session_status,
            } => (row, created, session_status),
            other => panic!("expected Persisted, got {other:?}"),
        };
        let (row_a, created_a, status_a) = unpack(a);
        let (row_b, created_b, status_b) = unpack(b);

        // Recovery must see the intent while the session is still ACTIVE
        // (the crash-between-persist-and-transition window).
        let pending_while_active = system_worker::pending_finalizations(&pool).await.unwrap();

        // Claim semantics: one holder at a time; an early release (the
        // deliberate settle-defer path) re-opens it immediately, without
        // waiting out the stale threshold.
        let claim1 = claim_finalization(&pool, scope, racer.id, 420)
            .await
            .unwrap();
        let claim_held = claim_finalization(&pool, scope, racer.id, 420)
            .await
            .unwrap();
        release_finalization_claim(&pool, scope, racer.id)
            .await
            .unwrap();
        let claim_after_release = claim_finalization(&pool, scope, racer.id, 420)
            .await
            .unwrap();

        // Fence session: persist an intent, terminalize legally, release the
        // intent, then try to re-create it and to attach a handle late.
        let first_fence = begin_finalization(
            &pool,
            scope,
            fenced.id,
            "failed",
            None,
            Some("t"),
            false,
            30,
        )
        .await
        .unwrap();
        // The gap that matters: intent committed, wind-down transition NOT
        // yet applied — the session status still accepts work, but the
        // intent alone must fence a late attach.
        let attached_intent_gap = set_sandbox_handle(
            &pool,
            scope,
            fenced.id,
            &serde_json::json!({"external_id":"tg","uid":"ug"}),
        )
        .await
        .unwrap();
        transition_session(&pool, scope, fenced.id, SessionStatus::Finalizing, None)
            .await
            .unwrap();
        // Wind-down owns the session: a provisioning race may no longer
        // attach a handle.
        let attached_winddown = set_sandbox_handle(
            &pool,
            scope,
            fenced.id,
            &serde_json::json!({"external_id":"tw","uid":"uw"}),
        )
        .await
        .unwrap();
        transition_session(&pool, scope, fenced.id, SessionStatus::Failed, None)
            .await
            .unwrap();
        // Terminal + intent = cleanup still owed: recovery must see it.
        let pending_while_terminal = system_worker::pending_finalizations(&pool).await.unwrap();
        delete_finalization(&pool, scope, fenced.id).await.unwrap();
        let pending_after_release = system_worker::pending_finalizations(&pool).await.unwrap();
        let post_terminal =
            begin_finalization(&pool, scope, fenced.id, "cancelled", None, None, true, 30)
                .await
                .unwrap();
        let attached_terminal = set_sandbox_handle(
            &pool,
            scope,
            fenced.id,
            &serde_json::json!({"external_id":"t2","uid":"u2"}),
        )
        .await
        .unwrap();
        let missing = begin_finalization(
            &pool,
            scope,
            Uuid::now_v7(),
            "failed",
            None,
            None,
            false,
            30,
        )
        .await
        .unwrap();

        // Fixtures out BEFORE the assertions (session delete cascades to the
        // surviving intent).
        for id in [racer.id, fenced.id] {
            sqlx::query("delete from sessions where id = $1")
                .bind(id)
                .execute(&pool)
                .await
                .unwrap();
        }

        assert!(attached_active, "handle attach must succeed while active");
        assert!(
            created_a ^ created_b,
            "exactly one racer creates the intent (created_a={created_a}, created_b={created_b})"
        );
        assert_eq!(
            row_a.outcome, row_b.outcome,
            "both racers must hold the WINNER's row"
        );
        assert_eq!(row_a.needs_quiesce, row_b.needs_quiesce);
        let winner_is_cancel = row_a.outcome == "cancelled";
        assert_eq!(
            row_a.needs_quiesce, winner_is_cancel,
            "quiesce comes from the winning intent, derived from the locked snapshot"
        );
        assert_eq!(
            row_a.quiesce_deadline.is_some(),
            winner_is_cancel,
            "deadline exists iff the winner wanted quiesce"
        );
        assert_eq!(status_a, "running");
        assert_eq!(status_b, "running");
        assert!(
            pending_while_active.contains(&racer.id),
            "recovery must scan intents on ACTIVE sessions"
        );
        assert!(claim1.is_some(), "first claim must succeed");
        assert!(
            claim_held.is_none(),
            "a held claim must not be re-claimable"
        );
        assert!(
            claim_after_release.is_some(),
            "an early-released claim must be immediately re-claimable"
        );
        assert!(matches!(
            first_fence,
            BeginFinalization::Persisted { created: true, .. }
        ));
        assert!(
            !attached_intent_gap,
            "a committed intent must fence attach BEFORE the wind-down transition lands"
        );
        assert!(
            !attached_winddown,
            "a winding-down session must refuse a late sandbox handle"
        );
        assert!(
            pending_while_terminal.contains(&fenced.id),
            "recovery must see intents on TERMINAL sessions (cleanup owed)"
        );
        assert!(
            !pending_after_release.contains(&fenced.id),
            "a released intent leaves the recovery worklist"
        );
        assert!(
            matches!(post_terminal, BeginFinalization::AlreadyTerminal),
            "a terminal session must fence intent re-creation"
        );
        assert!(
            !attached_terminal,
            "a terminal session must refuse a late sandbox handle"
        );
        assert!(matches!(missing, BeginFinalization::Missing));
    }

    #[tokio::test]
    async fn append_event_assigns_gapless_seq_and_notifies() {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("skipping: DATABASE_URL not set");
            return;
        };
        let pool = connect(&url).await.expect("connect");
        let tenant = ensure_default_tenant(&pool).await.unwrap();
        let scope = TenantScope::assume(tenant);

        let policy = upsert_policy(
            &pool,
            scope,
            "test-seq",
            "name: test-seq",
            &serde_json::json!({"name": "test-seq"}),
        )
        .await
        .unwrap();
        let agent = create_agent(&pool, scope, "test-seq-agent", None)
            .await
            .unwrap();
        let rev = append_agent_revision(
            &pool,
            scope,
            agent.id,
            "claude-agent-sdk",
            "img:test",
            "claude-haiku-4-5",
            None,
            policy.id,
            &serde_json::json!({}),
            None,
            &serde_json::json!([]),
            &serde_json::json!([]),
        )
        .await
        .unwrap();
        let session = create_session(
            &pool,
            scope,
            agent.id,
            rev.id,
            "supervised",
            "trusted",
            "t",
            &serde_json::json!({"kind":"none"}),
            &serde_json::json!({}),
            &serde_json::json!({}),
            None,
            None,
            None,
            None,
            None,
            &[],
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
            seqs.push(
                append_event(&pool, scope, redactor.scrub(env))
                    .await
                    .unwrap(),
            );
        }
        assert_eq!(seqs, vec![1, 2, 3]);

        let n = tokio::time::timeout(std::time::Duration::from_secs(5), listener.recv())
            .await
            .expect("notify within 5s")
            .expect("notify ok");
        assert!(n.payload().starts_with(&session.id.to_string()));

        let events = events_after(&pool, scope, session.id, 0, 10).await.unwrap();
        assert_eq!(events.len(), 3);
        assert_eq!(events[0].r#type, "agent.message");
    }

    #[tokio::test]
    async fn session_token_revoke_is_terminal_and_extend_cannot_resurrect() {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("skipping: DATABASE_URL not set");
            return;
        };
        let pool = connect(&url).await.expect("connect");
        let tenant = ensure_default_tenant(&pool).await.unwrap();
        let scope = TenantScope::assume(tenant);
        let policy = upsert_policy(
            &pool,
            scope,
            "test-token",
            "name: test-token",
            &serde_json::json!({"name": "test-token"}),
        )
        .await
        .unwrap();
        let agent = create_agent(&pool, scope, "test-token-agent", None)
            .await
            .unwrap();
        let rev = append_agent_revision(
            &pool,
            scope,
            agent.id,
            "codex",
            "img:test",
            "gpt-5.4-mini",
            None,
            policy.id,
            &serde_json::json!({}),
            None,
            &serde_json::json!([]),
            &serde_json::json!([]),
        )
        .await
        .unwrap();
        let session = create_session(
            &pool,
            scope,
            agent.id,
            rev.id,
            "autonomous",
            "trusted",
            "t",
            &serde_json::json!({"kind":"none"}),
            &serde_json::json!({}),
            &serde_json::json!({}),
            None,
            None,
            None,
            None,
            None,
            &[],
        )
        .await
        .unwrap();

        let token = format!("fbx_sess_{}", Uuid::now_v7().simple());
        create_session_token(&pool, scope, session.id, &token, 3600)
            .await
            .unwrap();
        assert_eq!(
            session_for_token(&pool, &token)
                .await
                .unwrap()
                .map(|a| a.session_id),
            Some(session.id)
        );
        // A live token extends.
        assert!(extend_session_token(&pool, &token, 3600).await.unwrap());

        // Terminal transition revokes it — the runner can no longer auth.
        assert_eq!(
            revoke_session_tokens(&pool, scope, session.id)
                .await
                .unwrap(),
            1
        );
        assert_eq!(
            session_for_token(&pool, &token)
                .await
                .unwrap()
                .map(|a| a.session_id),
            None
        );
        // And a renew can never resurrect a revoked token.
        assert!(!extend_session_token(&pool, &token, 3600).await.unwrap());
        // Revoking again is a no-op (idempotent).
        assert_eq!(
            revoke_session_tokens(&pool, scope, session.id)
                .await
                .unwrap(),
            0
        );
    }

    #[tokio::test]
    async fn intent_registry_digest_binding_and_lifecycle() {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("skipping: DATABASE_URL not set");
            return;
        };
        let pool = connect(&url).await.expect("connect");
        let tenant = ensure_default_tenant(&pool).await.unwrap();
        let scope = TenantScope::assume(tenant);
        let policy = upsert_policy(
            &pool,
            scope,
            "test-intent",
            "name: test-intent",
            &serde_json::json!({"name": "test-intent"}),
        )
        .await
        .unwrap();
        let agent = create_agent(&pool, scope, "test-intent-agent", None)
            .await
            .unwrap();
        let rev = append_agent_revision(
            &pool,
            scope,
            agent.id,
            "codex",
            "img:test",
            "gpt-5.4-mini",
            None,
            policy.id,
            &serde_json::json!({}),
            None,
            &serde_json::json!([]),
            &serde_json::json!([]),
        )
        .await
        .unwrap();
        let session = create_session(
            &pool,
            scope,
            agent.id,
            rev.id,
            "supervised",
            "trusted",
            "t",
            &serde_json::json!({"kind":"none"}),
            &serde_json::json!({}),
            &serde_json::json!({}),
            None,
            None,
            None,
            None,
            None,
            &[],
        )
        .await
        .unwrap();

        // Registration is idempotent by (session, tool_call_id).
        let (row, inserted) =
            register_tool_intent(&pool, scope, session.id, "tc1", "Bash", "cat x", "digest-a")
                .await
                .unwrap();
        assert!(inserted);
        assert_eq!(row.status, "intent");
        assert_eq!(row.input_digest.as_deref(), Some("digest-a"));
        let (again, inserted2) =
            register_tool_intent(&pool, scope, session.id, "tc1", "Bash", "cat x", "digest-a")
                .await
                .unwrap();
        assert!(!inserted2);
        assert_eq!(again.id, row.id);
        // The caller compares digests — the registry hands back the stored
        // binding even on a mismatched retry.
        let (mismatch, inserted3) =
            register_tool_intent(&pool, scope, session.id, "tc1", "Bash", "cat y", "digest-B")
                .await
                .unwrap();
        assert!(!inserted3);
        assert_eq!(mismatch.input_digest.as_deref(), Some("digest-a"));

        // Gate verdicts stick, and the CAS reports who won.
        assert!(record_intent_verdict(&pool, scope, row.id, "auto_allowed")
            .await
            .unwrap());
        assert!(
            !record_intent_verdict(&pool, scope, row.id, "auto_denied")
                .await
                .unwrap(),
            "second verdict loses the CAS — the first stands"
        );
        let cur = get_approval(&pool, scope, row.id).await.unwrap().unwrap();
        assert_eq!(cur.status, "auto_allowed");
        // A decided intent can no longer be promoted into an approval.
        assert!(
            promote_intent_to_pending(&pool, scope, row.id, None, "once", "Bash", 600)
                .await
                .unwrap()
                .is_none()
        );

        // The approval lifecycle rides the SAME row when promotion wins.
        let (row2, _) = register_tool_intent(
            &pool, scope, session.id, "tc2", "Bash", "git push", "digest-c",
        )
        .await
        .unwrap();
        let promoted =
            promote_intent_to_pending(&pool, scope, row2.id, Some("high"), "once", "Bash", 600)
                .await
                .unwrap()
                .expect("first promotion wins");
        assert_eq!(promoted.status, "pending");
        assert!(promoted.expires_at > chrono::Utc::now());
        assert!(
            promote_intent_to_pending(&pool, scope, row2.id, Some("high"), "once", "Bash", 600)
                .await
                .unwrap()
                .is_none(),
            "second promotion is a no-op"
        );
        let decided = decide_approval(&pool, scope, row2.id, "approved_once", "tester")
            .await
            .unwrap()
            .expect("pending row decides");
        assert_eq!(decided.status, "approved_once");
        assert!(
            !record_intent_verdict(&pool, scope, row2.id, "auto_denied")
                .await
                .unwrap(),
            "a human decision is never overwritten by a gate verdict"
        );
        let cur2 = get_approval(&pool, scope, row2.id).await.unwrap().unwrap();
        assert_eq!(cur2.status, "approved_once");

        // The budget counts unique intents; the approvals API hides gate
        // bookkeeping but keeps the human lifecycle.
        assert_eq!(tool_call_count(&pool, scope, session.id).await.unwrap(), 2);
        let visible = session_approvals(&pool, scope, session.id).await.unwrap();
        assert_eq!(visible.len(), 1);
        assert_eq!(visible[0].tool_call_id, "tc2");
    }

    #[tokio::test]
    async fn stale_nonstarted_sweep_finds_only_old_prelaunch_sessions() {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("skipping: DATABASE_URL not set");
            return;
        };
        let pool = connect(&url).await.expect("connect");
        let tenant = ensure_default_tenant(&pool).await.unwrap();
        let scope = TenantScope::assume(tenant);
        let policy = upsert_policy(
            &pool,
            scope,
            "test-stale",
            "name: test-stale",
            &serde_json::json!({"name": "test-stale"}),
        )
        .await
        .unwrap();
        let agent = create_agent(&pool, scope, "test-stale-agent", None)
            .await
            .unwrap();
        let rev = append_agent_revision(
            &pool,
            scope,
            agent.id,
            "claude-agent-sdk",
            "img:test",
            "claude-haiku-4-5",
            None,
            policy.id,
            &serde_json::json!({}),
            None,
            &serde_json::json!([]),
            &serde_json::json!([]),
        )
        .await
        .unwrap();
        let repo = serde_json::json!({"kind":"none"});
        let empty = serde_json::json!({});
        let fresh = create_session(
            &pool,
            scope,
            agent.id,
            rev.id,
            "supervised",
            "trusted",
            "stale-test fresh",
            &repo,
            &empty,
            &empty,
            None,
            None,
            None,
            None,
            None,
            &[],
        )
        .await
        .unwrap();
        let stale = create_session(
            &pool,
            scope,
            agent.id,
            rev.id,
            "supervised",
            "trusted",
            "stale-test old",
            &repo,
            &empty,
            &empty,
            None,
            None,
            None,
            None,
            None,
            &[],
        )
        .await
        .unwrap();
        // The sweep keys off created_at (heartbeat-proof; M5) — backdate that.
        let backdate =
            "update sessions set created_at = now() - interval '20 minutes' where id = $1";
        sqlx::query(backdate)
            .bind(stale.id)
            .execute(&pool)
            .await
            .unwrap();

        let sweep_created: Vec<Uuid> = system_worker::stale_nonstarted_sessions(&pool, 15)
            .await
            .unwrap()
            .iter()
            .map(|s| s.id)
            .collect();

        // The wind-down machine owns terminal entry: the pre-epic direct
        // created→failed edge must be REFUSED (Ok(None)), and terminalization
        // goes through finalizing. Neither a winding-down nor a terminal
        // session may be swept, however old.
        use fluidbox_core::state::SessionStatus;
        let direct_terminal =
            transition_session(&pool, scope, stale.id, SessionStatus::Failed, Some("test"))
                .await
                .unwrap();
        let to_finalizing = transition_session(
            &pool,
            scope,
            stale.id,
            SessionStatus::Finalizing,
            Some("test"),
        )
        .await
        .unwrap();
        sqlx::query(backdate)
            .bind(stale.id)
            .execute(&pool)
            .await
            .unwrap();
        let sweep_finalizing: Vec<Uuid> = system_worker::stale_nonstarted_sessions(&pool, 15)
            .await
            .unwrap()
            .iter()
            .map(|s| s.id)
            .collect();
        let to_failed =
            transition_session(&pool, scope, stale.id, SessionStatus::Failed, Some("test"))
                .await
                .unwrap();
        sqlx::query(backdate)
            .bind(stale.id)
            .execute(&pool)
            .await
            .unwrap();
        let sweep_terminal: Vec<Uuid> = system_worker::stale_nonstarted_sessions(&pool, 15)
            .await
            .unwrap()
            .iter()
            .map(|s| s.id)
            .collect();

        // Fixtures out BEFORE the assertions — a failed assertion must not
        // leak sessions into the shared tenant.
        for id in [fresh.id, stale.id] {
            sqlx::query("delete from sessions where id = $1")
                .bind(id)
                .execute(&pool)
                .await
                .unwrap();
        }

        assert!(
            sweep_created.contains(&stale.id),
            "old created session must be swept"
        );
        assert!(
            !sweep_created.contains(&fresh.id),
            "fresh session must not be swept"
        );
        assert!(
            direct_terminal.is_none(),
            "created→failed must be refused (no active→terminal edge)"
        );
        assert!(
            to_finalizing.is_some(),
            "created→finalizing must be legal (crash recovery finalizes from anywhere)"
        );
        assert!(
            !sweep_finalizing.contains(&stale.id),
            "winding-down session must not be swept"
        );
        assert!(to_failed.is_some(), "finalizing→failed must be legal");
        assert!(
            !sweep_terminal.contains(&stale.id),
            "terminal session must not be swept"
        );
    }

    #[tokio::test]
    async fn adopt_sandbox_handle_is_guarded() {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("skipping: DATABASE_URL not set");
            return;
        };
        let pool = connect(&url).await.expect("connect");
        let tenant = ensure_default_tenant(&pool).await.unwrap();
        let scope = TenantScope::assume(tenant);
        let policy = upsert_policy(
            &pool,
            scope,
            "test-adopt",
            "name: test-adopt",
            &serde_json::json!({"name": "test-adopt"}),
        )
        .await
        .unwrap();
        let agent = create_agent(&pool, scope, "test-adopt-agent", None)
            .await
            .unwrap();
        let rev = append_agent_revision(
            &pool,
            scope,
            agent.id,
            "claude-agent-sdk",
            "img:test",
            "claude-haiku-4-5",
            None,
            policy.id,
            &serde_json::json!({}),
            None,
            &serde_json::json!([]),
            &serde_json::json!([]),
        )
        .await
        .unwrap();
        let repo = serde_json::json!({"kind":"none"});
        let empty = serde_json::json!({});
        let s = create_session(
            &pool,
            scope,
            agent.id,
            rev.id,
            "supervised",
            "trusted",
            "adopt-test",
            &repo,
            &empty,
            &empty,
            None,
            None,
            None,
            None,
            None,
            &[],
        )
        .await
        .unwrap();
        let discovered =
            serde_json::json!({"runtime":"kubernetes","external_id":"pod-x","attrs":{"uid":"u1"}});
        let real =
            serde_json::json!({"runtime":"kubernetes","external_id":"pod-x","attrs":{"uid":"u2"}});

        // Active + handle-less → adoption lands.
        let adopted = adopt_sandbox_handle(&pool, scope, s.id, &discovered)
            .await
            .unwrap();
        // A stored handle is never overwritten (run() won the race).
        set_sandbox_handle(&pool, scope, s.id, &real).await.unwrap();
        let overwrote = adopt_sandbox_handle(&pool, scope, s.id, &discovered)
            .await
            .unwrap();
        let kept: (Value,) = sqlx::query_as("select sandbox_handle from sessions where id = $1")
            .bind(s.id)
            .fetch_one(&pool)
            .await
            .unwrap();
        // A winding-down session never re-acquires a handle.
        sqlx::query(
            "update sessions set sandbox_handle = null, status = 'finalizing' where id = $1",
        )
        .bind(s.id)
        .execute(&pool)
        .await
        .unwrap();
        let resurrected = adopt_sandbox_handle(&pool, scope, s.id, &discovered)
            .await
            .unwrap();

        // Fixtures out BEFORE the assertions.
        sqlx::query("delete from sessions where id = $1")
            .bind(s.id)
            .execute(&pool)
            .await
            .unwrap();

        assert!(adopted, "active handle-less session must adopt");
        assert!(!overwrote, "a stored handle must never be overwritten");
        assert_eq!(kept.0["attrs"]["uid"], "u2", "run()'s handle must survive");
        assert!(!resurrected, "a winding-down session must not adopt");
    }

    #[tokio::test]
    async fn connection_lifecycle_and_credential_isolation() {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("skipping: DATABASE_URL not set");
            return;
        };
        let pool = connect(&url).await.expect("connect");
        let tenant = ensure_default_tenant(&pool).await.unwrap();
        let scope = TenantScope::assume(tenant);

        let sealed = b"nonce||ciphertext-not-a-real-secret".to_vec();
        let conn = create_connection(
            &pool,
            scope,
            "github",
            "test-account-42",
            "test-connection",
            Some(&sealed),
            &serde_json::json!(["repo"]),
            &serde_json::json!({}),
            &serde_json::json!({"test": true}),
            None,
            ConnectionAuth::static_active(),
            ConnectionOwner::Organization,
            None,
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
        let got = connection_credential_sealed(&pool, scope, conn.id)
            .await
            .unwrap()
            .expect("active connection has credential");
        assert_eq!(got, sealed);

        // Revocation is terminal for credential access.
        let revoked = revoke_connection(&pool, scope, conn.id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(revoked.status, "revoked");
        assert!(connection_credential_sealed(&pool, scope, conn.id)
            .await
            .unwrap()
            .is_none());
        // Idempotent second revoke: no row to update.
        assert!(revoke_connection(&pool, scope, conn.id)
            .await
            .unwrap()
            .is_none());

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
        let scope = TenantScope::assume(tenant);
        let policy = upsert_policy(
            &pool,
            scope,
            "test-trig",
            "name: test-trig",
            &serde_json::json!({"name": "test-trig"}),
        )
        .await
        .unwrap();
        let agent = create_agent(&pool, scope, "test-trig-agent", None)
            .await
            .unwrap();
        let _rev = append_agent_revision(
            &pool,
            scope,
            agent.id,
            "claude-agent-sdk",
            "img:test",
            "claude-haiku-4-5",
            None,
            policy.id,
            &serde_json::json!({}),
            None,
            &serde_json::json!([]),
            &serde_json::json!([]),
        )
        .await
        .unwrap();

        let sealed = b"nonce||not-a-real-secret".to_vec();
        let sub = create_trigger_subscription(
            &pool,
            scope,
            agent.id,
            "test-sub",
            "api",
            None,
            Some("Investigate {{ticket}}"),
            false,
            false,
            None,
            "allow",
            None,
            None,
            &serde_json::json!([{"kind": "signed_webhook", "url": "http://127.0.0.1:1/cb"}]),
            Some(&sealed),
            None,
            None,
            None,
            None,
            None,
        )
        .await
        .unwrap();
        assert!(sub.enabled);
        assert!(!sub.allow_task_override);

        // Row serialization can never leak the sealed secret.
        let as_json = serde_json::to_value(&sub).unwrap();
        assert!(as_json.get("callback_secret_sealed").is_none());

        // The single secret reader returns the sealed bytes.
        let got = subscription_callback_secret_sealed(&pool, scope, sub.id)
            .await
            .unwrap();
        assert_eq!(got, Some(sealed));

        // Trigger tokens: hashed at rest, resolvable, revocable.
        create_trigger_token(&pool, scope, sub.id, "fbx_trig_testtoken123")
            .await
            .unwrap();
        assert_eq!(
            subscription_for_token(&pool, "fbx_trig_testtoken123")
                .await
                .unwrap()
                .map(|a| a.subscription_id),
            Some(sub.id)
        );
        assert_eq!(
            subscription_for_token(&pool, "fbx_trig_wrong")
                .await
                .unwrap()
                .map(|a| a.subscription_id),
            None
        );
        let revoked = revoke_trigger_tokens(&pool, scope, sub.id).await.unwrap();
        assert_eq!(revoked, 1);
        assert_eq!(
            subscription_for_token(&pool, "fbx_trig_testtoken123")
                .await
                .unwrap()
                .map(|a| a.subscription_id),
            None
        );

        // Enable toggle.
        let off = set_trigger_subscription_enabled(&pool, scope, sub.id, false)
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
        let scope = TenantScope::assume(tenant);
        let policy = upsert_policy(
            &pool,
            scope,
            "test-idem",
            "name: test-idem",
            &serde_json::json!({"name": "test-idem"}),
        )
        .await
        .unwrap();
        let agent = create_agent(&pool, scope, "test-idem-agent", None)
            .await
            .unwrap();
        let rev = append_agent_revision(
            &pool,
            scope,
            agent.id,
            "claude-agent-sdk",
            "img:test",
            "claude-haiku-4-5",
            None,
            policy.id,
            &serde_json::json!({}),
            None,
            &serde_json::json!([]),
            &serde_json::json!([]),
        )
        .await
        .unwrap();
        let sub = create_trigger_subscription(
            &pool,
            scope,
            agent.id,
            "test-idem-sub",
            "api",
            None,
            Some("t"),
            false,
            false,
            None,
            "allow",
            None,
            None,
            &serde_json::json!([]),
            None,
            None,
            None,
            None,
            None,
            None,
        )
        .await
        .unwrap();

        // First claim wins.
        let c1 = claim_invocation(&pool, scope, sub.id, "key-1", "digest-a")
            .await
            .unwrap();
        let InvocationClaim::Claimed { invocation_id } = c1 else {
            panic!("wanted Claimed, got {c1:?}")
        };

        // Same key while unbound → InFlight (a concurrent retry must wait).
        assert!(matches!(
            claim_invocation(&pool, scope, sub.id, "key-1", "digest-a")
                .await
                .unwrap(),
            InvocationClaim::InFlight
        ));

        // Bind atomically with session creation (same transaction), then
        // the same key replays that session.
        let session = create_session(
            &pool,
            scope,
            agent.id,
            rev.id,
            "supervised",
            "trusted",
            "t",
            &serde_json::json!({"kind":"scratch"}),
            &serde_json::json!({}),
            &serde_json::json!({}),
            Some(&serde_json::json!({"kind":"api"})),
            None,
            None,
            Some(invocation_id),
            None,
            &[],
        )
        .await
        .unwrap();
        assert_eq!(session.trigger, Some(serde_json::json!({"kind":"api"})));
        let c3 = claim_invocation(&pool, scope, sub.id, "key-1", "digest-a")
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
        let c4 = claim_invocation(&pool, scope, sub.id, "key-2", "digest-b")
            .await
            .unwrap();
        let InvocationClaim::Claimed {
            invocation_id: inv2,
        } = c4
        else {
            panic!()
        };
        release_invocation(&pool, scope, inv2).await.unwrap();
        assert!(matches!(
            claim_invocation(&pool, scope, sub.id, "key-2", "digest-b")
                .await
                .unwrap(),
            InvocationClaim::Claimed { .. }
        ));

        assert!(subscription_owns_session(&pool, scope, sub.id, session.id)
            .await
            .unwrap());
        let listed = list_subscription_sessions(&pool, scope, sub.id, 10)
            .await
            .unwrap();
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
    async fn schedule_lifecycle_and_skip_claims() {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("skipping: DATABASE_URL not set");
            return;
        };
        let pool = connect(&url).await.expect("connect");
        let tenant = ensure_default_tenant(&pool).await.unwrap();
        let scope = TenantScope::assume(tenant);
        let agent = create_agent(&pool, scope, "test-sched-agent", None)
            .await
            .unwrap();
        let sub = create_trigger_subscription(
            &pool,
            scope,
            agent.id,
            &format!("test-sched-{}", Uuid::now_v7()),
            "schedule",
            None,
            Some("maintenance sweep"),
            false,
            false,
            None,
            "skip_if_running",
            None,
            None,
            &serde_json::json!([]),
            None,
            None,
            None,
            None,
            None,
            None,
        )
        .await
        .unwrap();
        assert_eq!(sub.concurrency_policy, "skip_if_running");

        // Overdue schedule → due; disabled subscription → not due.
        let past = Utc::now() - chrono::Duration::seconds(1);
        let sched = create_schedule(&pool, scope, sub.id, "*/5 * * * * *", "UTC", past, "skip")
            .await
            .unwrap();
        assert!(system_worker::due_schedules(&pool, 50)
            .await
            .unwrap()
            .iter()
            .any(|s| s.id == sched.id));
        set_trigger_subscription_enabled(&pool, scope, sub.id, false)
            .await
            .unwrap();
        assert!(!system_worker::due_schedules(&pool, 50)
            .await
            .unwrap()
            .iter()
            .any(|s| s.id == sched.id));
        set_trigger_subscription_enabled(&pool, scope, sub.id, true)
            .await
            .unwrap();

        // Deterministic fire key: claim once, mark skipped, replay the skip.
        let key = "sched:2026-07-10T00:00:00Z";
        let claim = claim_invocation(&pool, scope, sub.id, key, "d1")
            .await
            .unwrap();
        let InvocationClaim::Claimed { invocation_id } = claim else {
            panic!("expected Claimed, got {claim:?}");
        };
        mark_invocation_skipped(&pool, scope, invocation_id, "missed")
            .await
            .unwrap();
        let again = claim_invocation(&pool, scope, sub.id, key, "d1")
            .await
            .unwrap();
        let InvocationClaim::Skipped { reason } = again else {
            panic!("expected Skipped, got {again:?}");
        };
        assert_eq!(reason, "missed");
        let inv = list_subscription_invocations(&pool, scope, sub.id, 10)
            .await
            .unwrap();
        assert_eq!(inv.len(), 1);
        assert_eq!(inv[0].skip_reason.as_deref(), Some("missed"));
        assert!(inv[0].session_id.is_none());

        // CAS advance: succeeds from the processed fire time, then refuses.
        // (`stored` is read back so both sides carry Postgres µs precision.)
        use chrono::SubsecRound;
        let stored = schedule_for_subscription(&pool, scope, sub.id)
            .await
            .unwrap()
            .unwrap()
            .next_fire_at
            .unwrap();
        let future = (Utc::now() + chrono::Duration::seconds(60)).trunc_subsecs(6);
        assert!(
            advance_schedule(&pool, scope, sched.id, stored, Some(future), None)
                .await
                .unwrap()
        );
        assert!(
            !advance_schedule(&pool, scope, sched.id, stored, Some(future), None)
                .await
                .unwrap()
        );
        let row = schedule_for_subscription(&pool, scope, sub.id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(row.next_fire_at, Some(future));
        assert!(row.last_fired_at.is_none()); // skips never touch last_fired_at
        assert!(!system_worker::due_schedules(&pool, 50)
            .await
            .unwrap()
            .iter()
            .any(|s| s.id == sched.id));

        // Cleanup (cascades schedules + invocations).
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
        let scope = TenantScope::assume(tenant);
        let policy = upsert_policy(
            &pool,
            scope,
            "test-del",
            "name: test-del",
            &serde_json::json!({"name": "test-del"}),
        )
        .await
        .unwrap();
        let agent = create_agent(&pool, scope, "test-del-agent", None)
            .await
            .unwrap();
        let rev = append_agent_revision(
            &pool,
            scope,
            agent.id,
            "claude-agent-sdk",
            "img:test",
            "claude-haiku-4-5",
            None,
            policy.id,
            &serde_json::json!({}),
            None,
            &serde_json::json!([]),
            &serde_json::json!([]),
        )
        .await
        .unwrap();
        let session = create_session(
            &pool,
            scope,
            agent.id,
            rev.id,
            "supervised",
            "trusted",
            "t",
            &serde_json::json!({"kind":"scratch"}),
            &serde_json::json!({}),
            &serde_json::json!({}),
            None,
            None,
            None,
            None,
            None,
            &[],
        )
        .await
        .unwrap();

        let dest = serde_json::json!({"kind": "signed_webhook", "url": "http://127.0.0.1:1/cb"});
        let d = enqueue_result_delivery(&pool, scope, session.id, None, &dest)
            .await
            .unwrap();
        assert_eq!(d.status, "pending");
        assert_eq!(d.attempts, 0);

        // Due immediately.
        let due = system_worker::due_result_deliveries(&pool, 10)
            .await
            .unwrap();
        assert!(due.iter().any(|x| x.id == d.id));

        // Failure → still pending, attempts=1, pushed into the future (not due).
        let after = mark_delivery_attempt(
            &pool,
            scope,
            d.id,
            false,
            Some("connection refused"),
            None,
            30,
            3,
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!((after.status.as_str(), after.attempts), ("pending", 1));
        assert!(!system_worker::due_result_deliveries(&pool, 50)
            .await
            .unwrap()
            .iter()
            .any(|x| x.id == d.id));

        // Exhausting attempts → failed, terminal for the delivery only.
        mark_delivery_attempt(&pool, scope, d.id, false, Some("refused"), None, 30, 3)
            .await
            .unwrap();
        let last = mark_delivery_attempt(&pool, scope, d.id, false, Some("refused"), None, 30, 3)
            .await
            .unwrap()
            .unwrap();
        assert_eq!((last.status.as_str(), last.attempts), ("failed", 3));

        // Success path on a second delivery.
        let d2 = enqueue_result_delivery(&pool, scope, session.id, None, &dest)
            .await
            .unwrap();
        let okd = mark_delivery_attempt(&pool, scope, d2.id, true, None, Some("sha256:x"), 0, 3)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(okd.status, "delivered");
        assert!(okd.delivered_at.is_some());
        assert_eq!(okd.payload_digest.as_deref(), Some("sha256:x"));

        let listed = list_session_deliveries(&pool, scope, session.id)
            .await
            .unwrap();
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
        let scope = TenantScope::assume(tenant);
        let policy = upsert_policy(
            &pool,
            scope,
            "test-ws",
            "name: test-ws",
            &serde_json::json!({"name": "test-ws"}),
        )
        .await
        .unwrap();
        let agent = create_agent(&pool, scope, "test-ws-agent", None)
            .await
            .unwrap();

        let ws = serde_json::json!({
            "kind": "git_repository",
            "clone_url": "https://github.com/o/r.git",
            "ref": "main"
        });
        let rev = append_agent_revision(
            &pool,
            scope,
            agent.id,
            "claude-agent-sdk",
            "img:test",
            "claude-haiku-4-5",
            None,
            policy.id,
            &serde_json::json!({}),
            Some(&ws),
            &serde_json::json!([]),
            &serde_json::json!([]),
        )
        .await
        .unwrap();
        assert_eq!(rev.default_workspace, Some(ws));

        // A revision without one stays None.
        let rev2 = append_agent_revision(
            &pool,
            scope,
            agent.id,
            "claude-agent-sdk",
            "img:test",
            "claude-haiku-4-5",
            None,
            policy.id,
            &serde_json::json!({}),
            None,
            &serde_json::json!([]),
            &serde_json::json!([]),
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

    #[tokio::test]
    async fn capability_bundles_are_append_only_and_refs_roundtrip() {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("skipping: DATABASE_URL not set");
            return;
        };
        let pool = connect(&url).await.expect("connect");
        let tenant = ensure_default_tenant(&pool).await.unwrap();
        let scope = TenantScope::assume(tenant);
        let name = format!("test-bundle-{}", Uuid::now_v7());

        let def_v1 = serde_json::json!({"servers": [{
            "class": "sandbox", "name": "ws", "command": "node",
            "args": ["/opt/x.mjs"],
            "tools": [{"name": "count", "description": "d", "input_schema": {"type": "object"}}]
        }]});
        let v1 = create_capability_bundle(&pool, scope, &name, Some("first"), &def_v1, "sha256:a")
            .await
            .unwrap();
        assert_eq!(v1.version, 1);

        // Publishing again appends version 2 — the v1 row never mutates.
        let v2 = create_capability_bundle(&pool, scope, &name, None, &def_v1, "sha256:b")
            .await
            .unwrap();
        assert_eq!(v2.version, 2);
        assert_ne!(v1.id, v2.id);
        let v1_again = get_capability_bundle(&pool, scope, v1.id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(v1_again.definition_digest, "sha256:a");
        assert_eq!(
            latest_capability_bundle(&pool, scope, &name)
                .await
                .unwrap()
                .unwrap()
                .id,
            v2.id
        );
        assert_eq!(
            get_capability_bundle_version(&pool, scope, &name, 1)
                .await
                .unwrap()
                .unwrap()
                .id,
            v1.id
        );

        // Revision pins (§17 #7) + subscription keep-list roundtrip as jsonb.
        let policy = upsert_policy(
            &pool,
            scope,
            "test-cap",
            "name: test-cap",
            &serde_json::json!({"name": "test-cap"}),
        )
        .await
        .unwrap();
        let agent = create_agent(&pool, scope, "test-cap-agent", None)
            .await
            .unwrap();
        let pins = serde_json::json!([{"id": v1.id, "name": name, "version": 1}]);
        let rev = append_agent_revision(
            &pool,
            scope,
            agent.id,
            "claude-agent-sdk",
            "img:test",
            "claude-haiku-4-5",
            None,
            policy.id,
            &serde_json::json!({}),
            None,
            &pins,
            &serde_json::json!([]),
        )
        .await
        .unwrap();
        assert_eq!(rev.capability_bundles, pins);

        let keep = serde_json::json!([name]);
        let sub = create_trigger_subscription(
            &pool,
            scope,
            agent.id,
            &format!("test-cap-sub-{}", Uuid::now_v7()),
            "api",
            None,
            Some("t"),
            false,
            false,
            None,
            "allow",
            None,
            None,
            &serde_json::json!([]),
            None,
            None,
            None,
            None,
            None,
            Some(&keep),
        )
        .await
        .unwrap();
        assert_eq!(sub.capability_bundles, Some(keep));

        sqlx::query("delete from trigger_subscriptions where id = $1")
            .bind(sub.id)
            .execute(&pool)
            .await
            .unwrap();
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
        sqlx::query("delete from capability_bundles where tenant_id = $1 and name = $2")
            .bind(tenant)
            .bind(&name)
            .execute(&pool)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn connector_catalog_seeded_and_custom_entries_forced_custom_tier() {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("skipping: DATABASE_URL not set");
            return;
        };
        let pool = connect(&url).await.expect("connect");
        // The curated seeds are GLOBAL (tenant_id null); any valid scope sees
        // them via the tenant-or-global reader.
        let tenant = ensure_default_tenant(&pool).await.unwrap();
        let scope = TenantScope::assume(tenant);

        // Migration 0007 seeds the curated set (API-only settle: the
        // migration IS the seed; no file, no boot sync).
        let rows = list_catalog(&pool, scope).await.unwrap();
        assert!(rows.len() >= 7, "expected ≥7 seeded entries");
        let notion = get_catalog_by_slug(&pool, scope, "notion")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(notion.auth_mode, "oauth");
        assert_eq!(notion.tier, "verified");
        assert!(notion.tenant_id.is_none(), "curated seeds are global");
        let sentry = get_catalog_by_slug(&pool, scope, "sentry")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(sentry.auth_hints["header_name"], "Sentry-Bearer");
        assert_eq!(sentry.auth_hints["scheme"], "");
        let ws = get_catalog_by_slug(&pool, scope, "workspace-info")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(ws.transport, "stdio");
        assert!(ws.sandbox_launch.is_some());
        // Slack seed is explicitly deferred to the Phase-7 vertical.
        assert!(get_catalog_by_slug(&pool, scope, "slack")
            .await
            .unwrap()
            .is_none());
        // Verified entries sort ahead of custom ones.
        assert_eq!(rows[0].tier, "verified");

        let slug = format!("test-cat-{}", Uuid::now_v7().simple());
        let row = create_catalog_entry(
            &pool,
            scope,
            &slug,
            "Test entry",
            None,
            Some("test"),
            &serde_json::json!(["test"]),
            Some("https://mcp.example.test/mcp"),
            "streamable_http",
            "api_key",
            &serde_json::json!({}),
            &serde_json::json!([]),
            &serde_json::json!([]),
            &serde_json::json!([]),
            None,
        )
        .await
        .unwrap()
        .expect("custom entry lands");
        assert_eq!(row.tier, "custom", "API entries can't self-award tiers");
        assert_eq!(
            row.provenance["source"], "custom",
            "API entries carry a 'custom' provenance, distinct from seed + import"
        );
        assert_eq!(
            row.tenant_id,
            Some(tenant),
            "custom entries are tenant-scoped"
        );
        // The curated seed rows keep the fluidbox provenance the 0009 backfill
        // gave them — the import upsert predicate keys off exactly this, so an
        // import can never clobber a hand-curated verified entry.
        let gh = get_catalog_by_slug(&pool, scope, "github")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(gh.provenance["source"], "fluidbox");
        // Same-tenant slug re-insert conflicts (the per-tenant unique index).
        assert!(create_catalog_entry(
            &pool,
            scope,
            &slug,
            "dup",
            None,
            None,
            &serde_json::json!([]),
            None,
            "streamable_http",
            "none",
            &serde_json::json!({}),
            &serde_json::json!([]),
            &serde_json::json!([]),
            &serde_json::json!([]),
            None,
        )
        .await
        .is_err());

        sqlx::query("delete from connector_catalog where slug = $1")
            .bind(&slug)
            .execute(&pool)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn oauth_connection_lifecycle_pending_activate_rotate_error() {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("skipping: DATABASE_URL not set");
            return;
        };
        let pool = connect(&url).await.expect("connect");
        let tenant = ensure_default_tenant(&pool).await.unwrap();
        let scope = TenantScope::assume(tenant);

        // Pending OAuth connection: no credential yet.
        let conn = create_connection(
            &pool,
            scope,
            "mcp_http",
            "mcp.example.test",
            "oauth-lifecycle-test",
            None,
            &serde_json::json!([]),
            &serde_json::json!({}),
            &serde_json::json!({"base_url": "https://mcp.example.test"}),
            None,
            ConnectionAuth {
                auth_kind: "oauth",
                status: "pending",
                oauth: Some(&serde_json::json!({"resource": "https://mcp.example.test"})),
                client_secret_sealed: Some(b"sealed-client-secret"),
                registration_id: None,
            },
            ConnectionOwner::Organization,
            None,
        )
        .await
        .unwrap();
        assert_eq!(conn.auth_kind, "oauth");
        assert_eq!(conn.status, "pending");
        // Pending = no credential, and the active-only reader refuses.
        assert!(connection_credential_sealed(&pool, scope, conn.id)
            .await
            .unwrap()
            .is_none());
        // …but client identity IS readable while pending (the dance needs it).
        assert_eq!(
            connection_client_secret_sealed(&pool, scope, conn.id)
                .await
                .unwrap()
                .as_deref(),
            Some(b"sealed-client-secret".as_slice())
        );
        // Rotation refuses non-active rows.
        assert!(!rotate_connection_refresh(&pool, scope, conn.id, b"rt1")
            .await
            .unwrap());

        // Callback exchange: seal refresh + activate.
        let row = activate_connection_oauth(
            &pool,
            scope,
            conn.id,
            b"sealed-rt-1",
            &serde_json::json!({"resource": "https://mcp.example.test", "client_id": "c1"}),
            &serde_json::json!(["read"]),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(row.status, "active");
        assert_eq!(
            connection_credential_sealed(&pool, scope, conn.id)
                .await
                .unwrap()
                .as_deref(),
            Some(b"sealed-rt-1".as_slice())
        );

        // Rotation is one atomic overwrite; the old bytes are gone.
        assert!(
            rotate_connection_refresh(&pool, scope, conn.id, b"sealed-rt-2")
                .await
                .unwrap()
        );
        assert_eq!(
            connection_credential_sealed(&pool, scope, conn.id)
                .await
                .unwrap()
                .as_deref(),
            Some(b"sealed-rt-2".as_slice())
        );

        // invalid_grant ⇒ error: the credential reader fails closed; the
        // error note lands in oauth jsonb for the dashboard.
        mark_connection_error(&pool, scope, conn.id, "invalid_grant: reconnect required")
            .await
            .unwrap();
        let row = get_connection(&pool, scope, conn.id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(row.status, "error");
        assert!(row.oauth.unwrap()["error"]
            .as_str()
            .unwrap()
            .contains("invalid_grant"));
        assert!(connection_credential_sealed(&pool, scope, conn.id)
            .await
            .unwrap()
            .is_none());

        // Reconnect path: activation works FROM error too.
        let row = activate_connection_oauth(
            &pool,
            scope,
            conn.id,
            b"sealed-rt-3",
            &serde_json::json!({"resource": "https://mcp.example.test"}),
            &serde_json::json!([]),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(row.status, "active");

        sqlx::query("delete from integration_connections where id = $1")
            .bind(conn.id)
            .execute(&pool)
            .await
            .unwrap();
    }

    /// `just policy-sync` force-pushes the AUTHORED yaml. It must not take the
    /// Governance page's per-tool decisions with it — and `parsed` (what
    /// `run_service` actually evaluates) must carry them on every write.
    #[tokio::test]
    async fn upsert_preserves_managed_overrides() {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("skipping: DATABASE_URL not set");
            return;
        };
        let pool = connect(&url).await.expect("connect");
        let tenant = ensure_default_tenant(&pool).await.unwrap();
        let scope = TenantScope::assume(tenant);
        let yaml = "name: ov-test\ntools: []\n";
        let policy = fluidbox_core::policy::Policy::parse_yaml(yaml).unwrap();
        let parsed = serde_json::to_value(&policy).unwrap();
        upsert_policy(&pool, scope, "ov-test", yaml, &parsed)
            .await
            .unwrap();
        // Reset any override left behind by a previous (or crashed) run.
        clear_policy_override(&pool, scope, "ov-test", "mcp__x__y")
            .await
            .unwrap();

        set_policy_override(
            &pool,
            scope,
            "ov-test",
            "mcp__x__y",
            fluidbox_core::policy::RuleAction::Allow,
        )
        .await
        .unwrap();

        // A policy-sync re-push of the SAME yaml must not drop the override.
        let row = upsert_policy(&pool, scope, "ov-test", yaml, &parsed)
            .await
            .unwrap();
        let overrides: Vec<fluidbox_core::policy::ToolOverride> =
            serde_json::from_value(row.managed_overrides.clone()).unwrap();
        assert_eq!(overrides.len(), 1, "policy-sync dropped the override");
        assert_eq!(overrides[0].tool, "mcp__x__y");

        // …and `parsed` must carry it, because run_service evaluates from `parsed`.
        let effective: fluidbox_core::policy::Policy =
            serde_json::from_value(row.parsed.clone()).unwrap();
        assert_eq!(effective.managed_overrides.len(), 1);
        assert_eq!(
            effective.managed_overrides[0].action,
            fluidbox_core::policy::RuleAction::Allow
        );

        // Re-setting the SAME tool replaces, never duplicates.
        let row = set_policy_override(
            &pool,
            scope,
            "ov-test",
            "mcp__x__y",
            fluidbox_core::policy::RuleAction::Deny,
        )
        .await
        .unwrap();
        let effective: fluidbox_core::policy::Policy =
            serde_json::from_value(row.parsed.clone()).unwrap();
        assert_eq!(effective.managed_overrides.len(), 1);
        assert_eq!(
            effective.managed_overrides[0].action,
            fluidbox_core::policy::RuleAction::Deny
        );

        clear_policy_override(&pool, scope, "ov-test", "mcp__x__y")
            .await
            .unwrap();
        let row = get_policy_by_name(&pool, scope, "ov-test")
            .await
            .unwrap()
            .unwrap();
        let effective: fluidbox_core::policy::Policy =
            serde_json::from_value(row.parsed.clone()).unwrap();
        assert!(effective.managed_overrides.is_empty());
        let overrides: Vec<fluidbox_core::policy::ToolOverride> =
            serde_json::from_value(row.managed_overrides.clone()).unwrap();
        assert!(overrides.is_empty());
    }

    /// Only the LATEST revision governs future runs, so only it may count toward a
    /// policy's blast radius. Uses fresh policy names, so the shared default tenant's
    /// other agents cannot perturb the counts.
    #[tokio::test]
    async fn policy_agents_using_counts_only_latest_revisions() {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("skipping: DATABASE_URL not set");
            return;
        };
        let pool = connect(&url).await.expect("connect");
        let tenant = ensure_default_tenant(&pool).await.unwrap();
        let scope = TenantScope::assume(tenant);

        let mk = |name: &str| format!("name: {name}\ntools: []\n");
        let (ya, yb) = (mk("pau-a"), mk("pau-b"));
        let pa = upsert_policy(
            &pool,
            scope,
            "pau-a",
            &ya,
            &serde_json::to_value(fluidbox_core::policy::Policy::parse_yaml(&ya).unwrap()).unwrap(),
        )
        .await
        .unwrap();
        let pb = upsert_policy(
            &pool,
            scope,
            "pau-b",
            &yb,
            &serde_json::to_value(fluidbox_core::policy::Policy::parse_yaml(&yb).unwrap()).unwrap(),
        )
        .await
        .unwrap();

        let agent = create_agent(&pool, scope, "pau-agent", None).await.unwrap();
        let budgets = serde_json::json!({});
        let pins = serde_json::json!([]);
        let reqs = serde_json::json!([]);
        let rev = |policy_id| {
            append_agent_revision(
                &pool,
                scope,
                agent.id,
                "claude-agent-sdk",
                "img",
                "claude-haiku-4-5",
                None,
                policy_id,
                &budgets,
                None,
                &pins,
                &reqs,
            )
        };

        rev(pa.id).await.unwrap();
        assert_eq!(policy_agents_using(&pool, scope, pa.id).await.unwrap(), 1);
        assert_eq!(policy_agents_using(&pool, scope, pb.id).await.unwrap(), 0);

        // Append a revision moving the agent to policy B: A drops to 0, B goes to 1.
        rev(pb.id).await.unwrap();
        assert_eq!(policy_agents_using(&pool, scope, pa.id).await.unwrap(), 0);
        assert_eq!(policy_agents_using(&pool, scope, pb.id).await.unwrap(), 1);
    }

    /// The matrix's MCP rows come from what the agents on this policy can actually
    /// call: the union of the photographed tools in the bundles pinned on their
    /// LATEST revisions — sorted, and deduplicated across agents sharing a bundle.
    #[tokio::test]
    async fn policy_mcp_tools_unions_pinned_bundle_tools() {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("skipping: DATABASE_URL not set");
            return;
        };
        let pool = connect(&url).await.expect("connect");
        let tenant = ensure_default_tenant(&pool).await.unwrap();
        let scope = TenantScope::assume(tenant);

        let yaml = "name: pmt-policy\ntools: []\n";
        let policy = upsert_policy(
            &pool,
            scope,
            "pmt-policy",
            yaml,
            &serde_json::to_value(fluidbox_core::policy::Policy::parse_yaml(yaml).unwrap())
                .unwrap(),
        )
        .await
        .unwrap();

        // Tools are declared out of alphabetical order: the union must sort them.
        let bundle_name = format!("pmt-bundle-{}", Uuid::now_v7());
        let def = serde_json::json!({"servers": [{
            "class": "brokered", "name": "beta",
            "tools": [
                {"name": "zeta", "description": "d", "input_schema": {"type": "object"}},
                {"name": "alpha", "description": "d", "input_schema": {"type": "object"}}
            ]
        }]});
        let bundle = create_capability_bundle(&pool, scope, &bundle_name, None, &def, "sha256:pmt")
            .await
            .unwrap();
        let pins = serde_json::json!([
            { "id": bundle.id, "name": bundle.name, "version": bundle.version }
        ]);

        // Two agents share the bundle: the union deduplicates across them.
        let budgets = serde_json::json!({});
        for name in ["pmt-agent-a", "pmt-agent-b"] {
            let agent = create_agent(&pool, scope, name, None).await.unwrap();
            append_agent_revision(
                &pool,
                scope,
                agent.id,
                "claude-agent-sdk",
                "img",
                "claude-haiku-4-5",
                None,
                policy.id,
                &budgets,
                None,
                &pins,
                &serde_json::json!([]),
            )
            .await
            .unwrap();
        }

        assert_eq!(
            policy_mcp_tools(&pool, scope, policy.id).await.unwrap(),
            vec![
                "mcp__beta__alpha".to_string(),
                "mcp__beta__zeta".to_string()
            ]
        );

        // A policy nobody's latest revision points at contributes no tools.
        let empty_yaml = "name: pmt-empty\ntools: []\n";
        let empty = upsert_policy(
            &pool,
            scope,
            "pmt-empty",
            empty_yaml,
            &serde_json::to_value(fluidbox_core::policy::Policy::parse_yaml(empty_yaml).unwrap())
                .unwrap(),
        )
        .await
        .unwrap();
        assert!(policy_mcp_tools(&pool, scope, empty.id)
            .await
            .unwrap()
            .is_empty());
    }

    /// Cross-tenant isolation (wave A): a session and its child rows created
    /// under tenant B are invisible to tenant A's scope. The tenant predicate
    /// now lives in SQL, so a cross-tenant id misses at the database — never
    /// via a Rust-side filter. Throwaway orgs; cleanup is children-first
    /// (tenant FKs are NO ACTION).
    #[tokio::test]
    async fn tenant_scope_isolates_sessions_and_children() {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("skipping: DATABASE_URL not set");
            return;
        };
        let pool = connect(&url).await.expect("connect");

        let slug_a = format!("t-{}", Uuid::now_v7().simple());
        let slug_b = format!("t-{}", Uuid::now_v7().simple());
        let org_a = identity::create_org(&pool, &slug_a, None).await.unwrap();
        let org_b = identity::create_org(&pool, &slug_b, None).await.unwrap();
        let scope_a = TenantScope::assume(org_a.id);
        let scope_b = TenantScope::assume(org_b.id);

        // A full session fixture under B.
        let policy = upsert_policy(
            &pool,
            scope_b,
            "xt-policy",
            "name: xt",
            &serde_json::json!({"name":"xt"}),
        )
        .await
        .unwrap();
        let agent = create_agent(&pool, scope_b, "xt-agent", None)
            .await
            .unwrap();
        let rev = append_agent_revision(
            &pool,
            scope_b,
            agent.id,
            "claude-agent-sdk",
            "img:test",
            "claude-haiku-4-5",
            None,
            policy.id,
            &serde_json::json!({}),
            None,
            &serde_json::json!([]),
            &serde_json::json!([]),
        )
        .await
        .unwrap();
        let session = create_session(
            &pool,
            scope_b,
            agent.id,
            rev.id,
            "supervised",
            "trusted",
            "xt",
            &serde_json::json!({"kind":"none"}),
            &serde_json::json!({}),
            &serde_json::json!({}),
            None,
            None,
            None,
            None,
            None,
            &[],
        )
        .await
        .unwrap();

        // Child rows under B's scope: an event, an artifact, usage, and a
        // human-visible (pending) approval.
        let redactor = Redactor::default();
        append_event(
            &pool,
            scope_b,
            redactor.scrub(EventEnvelope::new(
                session.id,
                Actor::System,
                EventBody::AgentMessage {
                    role: "assistant".into(),
                    text: "hi".into(),
                },
            )),
        )
        .await
        .unwrap();
        add_artifact(
            &pool,
            scope_b,
            session.id,
            "diff",
            "changes.patch",
            "x",
            "text/plain",
        )
        .await
        .unwrap();
        add_usage(
            &pool,
            scope_b,
            session.id,
            "m",
            1,
            1,
            0,
            0,
            Some(0.0),
            "test",
            None,
        )
        .await
        .unwrap();
        let (intent, _) = register_tool_intent(&pool, scope_b, session.id, "tc1", "Bash", "s", "d")
            .await
            .unwrap();
        promote_intent_to_pending(&pool, scope_b, intent.id, None, "once", "Bash", 600)
            .await
            .unwrap();

        // Negative — tenant A sees NONE of B's rows.
        let get_a = get_session(&pool, scope_a, session.id).await.unwrap();
        let events_a = events_after(&pool, scope_a, session.id, 0, 10)
            .await
            .unwrap();
        let approvals_a = session_approvals(&pool, scope_a, session.id).await.unwrap();
        let artifacts_a = list_artifacts(&pool, scope_a, session.id).await.unwrap();
        let usage_a = usage_totals(&pool, scope_a, session.id).await.unwrap();
        // Positive control — tenant B still reads its own session, approval, AND
        // every child family (events/artifacts/usage) under its OWNING scope, so
        // the negatives below prove a tenant boundary, not a globally-broken read.
        let get_b = get_session(&pool, scope_b, session.id).await.unwrap();
        let approvals_b = session_approvals(&pool, scope_b, session.id).await.unwrap();
        let events_b = events_after(&pool, scope_b, session.id, 0, 10)
            .await
            .unwrap();
        let artifacts_b = list_artifacts(&pool, scope_b, session.id).await.unwrap();
        let usage_b = usage_totals(&pool, scope_b, session.id).await.unwrap();

        // Cleanup, children-first, both orgs — BEFORE the assertions so a
        // failure never leaks throwaway fixtures.
        for stmt in [
            "delete from events where session_id in (select id from sessions where tenant_id = $1)",
            "delete from artifacts where session_id in (select id from sessions where tenant_id = $1)",
            "delete from approvals where session_id in (select id from sessions where tenant_id = $1)",
            "delete from usage_entries where session_id in (select id from sessions where tenant_id = $1)",
            "delete from api_tokens where session_id in (select id from sessions where tenant_id = $1)",
            "delete from session_finalizations where session_id in (select id from sessions where tenant_id = $1)",
            "delete from sessions where tenant_id = $1",
            "delete from agent_revisions where agent_id in (select id from agents where tenant_id = $1)",
            "delete from agents where tenant_id = $1",
            "delete from policies where tenant_id = $1",
        ] {
            sqlx::query(stmt)
                .bind(org_b.id)
                .execute(&pool)
                .await
                .unwrap();
        }
        for id in [org_a.id, org_b.id] {
            sqlx::query("delete from tenants where id = $1")
                .bind(id)
                .execute(&pool)
                .await
                .unwrap();
        }

        assert!(get_a.is_none(), "tenant A must not read B's session");
        assert!(events_a.is_empty(), "tenant A must see none of B's events");
        assert!(
            approvals_a.is_empty(),
            "tenant A must see none of B's approvals"
        );
        assert!(
            artifacts_a.is_empty(),
            "tenant A must see none of B's artifacts"
        );
        assert_eq!(
            usage_a.requests, 0,
            "tenant A totals zero usage for B's session"
        );
        assert!(get_b.is_some(), "tenant B still reads its own session");
        assert_eq!(
            approvals_b.len(),
            1,
            "tenant B sees its own pending approval"
        );
        assert_eq!(events_b.len(), 1, "tenant B reads its own event");
        assert_eq!(artifacts_b.len(), 1, "tenant B reads its own artifact");
        assert_eq!(usage_b.requests, 1, "tenant B totals its own usage");
    }

    /// Cross-tenant isolation for AGENTS: an agent created under B is invisible
    /// to A's scope at the database. Throwaway orgs; cleanup children-first
    /// BEFORE the asserts so a failure never leaks fixtures.
    #[tokio::test]
    async fn tenant_scope_isolates_agents() {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("skipping: DATABASE_URL not set");
            return;
        };
        let pool = connect(&url).await.expect("connect");
        let org_a = identity::create_org(&pool, &format!("t-{}", Uuid::now_v7().simple()), None)
            .await
            .unwrap();
        let org_b = identity::create_org(&pool, &format!("t-{}", Uuid::now_v7().simple()), None)
            .await
            .unwrap();
        let scope_a = TenantScope::assume(org_a.id);
        let scope_b = TenantScope::assume(org_b.id);

        let agent = create_agent(&pool, scope_b, "xt-agent", None)
            .await
            .unwrap();

        let read_a = get_agent(&pool, scope_a, agent.id).await.unwrap();
        let read_b = get_agent(&pool, scope_b, agent.id).await.unwrap();

        // Cleanup BEFORE the assertions, both orgs (tenant FKs are NO ACTION).
        sqlx::query("delete from agents where tenant_id = $1")
            .bind(org_b.id)
            .execute(&pool)
            .await
            .unwrap();
        for id in [org_a.id, org_b.id] {
            sqlx::query("delete from tenants where id = $1")
                .bind(id)
                .execute(&pool)
                .await
                .unwrap();
        }

        assert!(read_a.is_none(), "tenant A must not read B's agent");
        assert!(read_b.is_some(), "tenant B reads its own agent");
    }

    /// Cross-tenant isolation for POLICIES.
    #[tokio::test]
    async fn tenant_scope_isolates_policies() {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("skipping: DATABASE_URL not set");
            return;
        };
        let pool = connect(&url).await.expect("connect");
        let org_a = identity::create_org(&pool, &format!("t-{}", Uuid::now_v7().simple()), None)
            .await
            .unwrap();
        let org_b = identity::create_org(&pool, &format!("t-{}", Uuid::now_v7().simple()), None)
            .await
            .unwrap();
        let scope_a = TenantScope::assume(org_a.id);
        let scope_b = TenantScope::assume(org_b.id);

        let policy = upsert_policy(
            &pool,
            scope_b,
            "xt-policy",
            "name: xt",
            &serde_json::json!({"name":"xt"}),
        )
        .await
        .unwrap();

        let read_a = get_policy(&pool, scope_a, policy.id).await.unwrap();
        let read_b = get_policy(&pool, scope_b, policy.id).await.unwrap();

        sqlx::query("delete from policies where tenant_id = $1")
            .bind(org_b.id)
            .execute(&pool)
            .await
            .unwrap();
        for id in [org_a.id, org_b.id] {
            sqlx::query("delete from tenants where id = $1")
                .bind(id)
                .execute(&pool)
                .await
                .unwrap();
        }

        assert!(read_a.is_none(), "tenant A must not read B's policy");
        assert!(read_b.is_some(), "tenant B reads its own policy");
    }

    /// Cross-tenant isolation for CONNECTIONS: neither the row nor the sealed
    /// credential is reachable across the tenant boundary.
    #[tokio::test]
    async fn tenant_scope_isolates_connections() {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("skipping: DATABASE_URL not set");
            return;
        };
        let pool = connect(&url).await.expect("connect");
        let org_a = identity::create_org(&pool, &format!("t-{}", Uuid::now_v7().simple()), None)
            .await
            .unwrap();
        let org_b = identity::create_org(&pool, &format!("t-{}", Uuid::now_v7().simple()), None)
            .await
            .unwrap();
        let scope_a = TenantScope::assume(org_a.id);
        let scope_b = TenantScope::assume(org_b.id);

        let conn = create_connection(
            &pool,
            scope_b,
            "mcp_http",
            "acct",
            "disp",
            Some(&[1, 2, 3]),
            &serde_json::json!([]),
            &serde_json::json!({}),
            &serde_json::json!({"base_url":"https://x"}),
            None,
            ConnectionAuth::static_active(),
            ConnectionOwner::Organization,
            None,
        )
        .await
        .unwrap();

        let get_a = get_connection(&pool, scope_a, conn.id).await.unwrap();
        let cred_a = connection_credential_sealed(&pool, scope_a, conn.id)
            .await
            .unwrap();
        let get_b = get_connection(&pool, scope_b, conn.id).await.unwrap();
        let cred_b = connection_credential_sealed(&pool, scope_b, conn.id)
            .await
            .unwrap();

        sqlx::query("delete from integration_connections where tenant_id = $1")
            .bind(org_b.id)
            .execute(&pool)
            .await
            .unwrap();
        for id in [org_a.id, org_b.id] {
            sqlx::query("delete from tenants where id = $1")
                .bind(id)
                .execute(&pool)
                .await
                .unwrap();
        }

        assert!(get_a.is_none(), "tenant A must not read B's connection");
        assert!(
            cred_a.is_none(),
            "tenant A must not read B's sealed credential"
        );
        assert!(get_b.is_some(), "tenant B reads its own connection");
        assert!(cred_b.is_some(), "tenant B reads its own sealed credential");
    }

    /// Cross-tenant isolation for TRIGGER SUBSCRIPTIONS.
    #[tokio::test]
    async fn tenant_scope_isolates_subscriptions() {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("skipping: DATABASE_URL not set");
            return;
        };
        let pool = connect(&url).await.expect("connect");
        let org_a = identity::create_org(&pool, &format!("t-{}", Uuid::now_v7().simple()), None)
            .await
            .unwrap();
        let org_b = identity::create_org(&pool, &format!("t-{}", Uuid::now_v7().simple()), None)
            .await
            .unwrap();
        let scope_a = TenantScope::assume(org_a.id);
        let scope_b = TenantScope::assume(org_b.id);

        let agent = create_agent(&pool, scope_b, "xt-agent", None)
            .await
            .unwrap();
        let sub = create_trigger_subscription(
            &pool,
            scope_b,
            agent.id,
            "xt-sub",
            "api",
            None,
            Some("do {{x}}"),
            true,
            false,
            None,
            "allow",
            None,
            None,
            &serde_json::json!([]),
            None,
            None,
            None,
            None,
            None,
            None,
        )
        .await
        .unwrap();

        let read_a = get_trigger_subscription(&pool, scope_a, sub.id)
            .await
            .unwrap();
        let read_b = get_trigger_subscription(&pool, scope_b, sub.id)
            .await
            .unwrap();

        // Children-first: subscriptions before agents.
        for stmt in [
            "delete from trigger_subscriptions where tenant_id = $1",
            "delete from agents where tenant_id = $1",
        ] {
            sqlx::query(stmt)
                .bind(org_b.id)
                .execute(&pool)
                .await
                .unwrap();
        }
        for id in [org_a.id, org_b.id] {
            sqlx::query("delete from tenants where id = $1")
                .bind(id)
                .execute(&pool)
                .await
                .unwrap();
        }

        assert!(read_a.is_none(), "tenant A must not read B's subscription");
        assert!(read_b.is_some(), "tenant B reads its own subscription");
    }

    /// Cross-tenant isolation for SCHEDULES (looked up via their subscription).
    #[tokio::test]
    async fn tenant_scope_isolates_schedules() {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("skipping: DATABASE_URL not set");
            return;
        };
        let pool = connect(&url).await.expect("connect");
        let org_a = identity::create_org(&pool, &format!("t-{}", Uuid::now_v7().simple()), None)
            .await
            .unwrap();
        let org_b = identity::create_org(&pool, &format!("t-{}", Uuid::now_v7().simple()), None)
            .await
            .unwrap();
        let scope_a = TenantScope::assume(org_a.id);
        let scope_b = TenantScope::assume(org_b.id);

        let agent = create_agent(&pool, scope_b, "xt-agent", None)
            .await
            .unwrap();
        let sub = create_trigger_subscription(
            &pool,
            scope_b,
            agent.id,
            "xt-sub",
            "schedule",
            None,
            Some("do {{x}}"),
            true,
            false,
            None,
            "allow",
            None,
            None,
            &serde_json::json!([]),
            None,
            None,
            None,
            None,
            None,
            None,
        )
        .await
        .unwrap();
        create_schedule(
            &pool,
            scope_b,
            sub.id,
            "*/5 * * * * *",
            "UTC",
            chrono::Utc::now(),
            "skip",
        )
        .await
        .unwrap();

        let read_a = schedule_for_subscription(&pool, scope_a, sub.id)
            .await
            .unwrap();
        let read_b = schedule_for_subscription(&pool, scope_b, sub.id)
            .await
            .unwrap();

        // Children-first: schedules (via subscription) → subscriptions → agents.
        for stmt in [
            "delete from schedules where subscription_id in (select id from trigger_subscriptions where tenant_id = $1)",
            "delete from trigger_subscriptions where tenant_id = $1",
            "delete from agents where tenant_id = $1",
        ] {
            sqlx::query(stmt).bind(org_b.id).execute(&pool).await.unwrap();
        }
        for id in [org_a.id, org_b.id] {
            sqlx::query("delete from tenants where id = $1")
                .bind(id)
                .execute(&pool)
                .await
                .unwrap();
        }

        assert!(read_a.is_none(), "tenant A must not read B's schedule");
        assert!(read_b.is_some(), "tenant B reads its own schedule");
    }

    /// Cross-tenant isolation for EXTERNAL RESULTS (§17 #3 stable identity).
    #[tokio::test]
    async fn tenant_scope_isolates_external_results() {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("skipping: DATABASE_URL not set");
            return;
        };
        let pool = connect(&url).await.expect("connect");
        let org_a = identity::create_org(&pool, &format!("t-{}", Uuid::now_v7().simple()), None)
            .await
            .unwrap();
        let org_b = identity::create_org(&pool, &format!("t-{}", Uuid::now_v7().simple()), None)
            .await
            .unwrap();
        let scope_a = TenantScope::assume(org_a.id);
        let scope_b = TenantScope::assume(org_b.id);

        let agent = create_agent(&pool, scope_b, "xt-agent", None)
            .await
            .unwrap();
        let sub = create_trigger_subscription(
            &pool,
            scope_b,
            agent.id,
            "xt-sub",
            "api",
            None,
            Some("do {{x}}"),
            true,
            false,
            None,
            "allow",
            None,
            None,
            &serde_json::json!([]),
            None,
            None,
            None,
            None,
            None,
            None,
        )
        .await
        .unwrap();
        upsert_external_result(
            &pool,
            scope_b,
            sub.id,
            "github_pr_comment",
            "acme/x#1",
            "999",
            Some("https://u"),
        )
        .await
        .unwrap();

        let read_a = get_external_result(&pool, scope_a, sub.id, "github_pr_comment", "acme/x#1")
            .await
            .unwrap();
        let read_b = get_external_result(&pool, scope_b, sub.id, "github_pr_comment", "acme/x#1")
            .await
            .unwrap();

        // Children-first: external_results (via subscription) → subscriptions → agents.
        for stmt in [
            "delete from external_results where subscription_id in (select id from trigger_subscriptions where tenant_id = $1)",
            "delete from trigger_subscriptions where tenant_id = $1",
            "delete from agents where tenant_id = $1",
        ] {
            sqlx::query(stmt).bind(org_b.id).execute(&pool).await.unwrap();
        }
        for id in [org_a.id, org_b.id] {
            sqlx::query("delete from tenants where id = $1")
                .bind(id)
                .execute(&pool)
                .await
                .unwrap();
        }

        assert!(
            read_a.is_none(),
            "tenant A must not read B's external result"
        );
        assert!(read_b.is_some(), "tenant B reads its own external result");
    }

    // ─── Phase C (#31): ownership, snapshots, bindings, catalog scoping ──────

    /// Seed a user + active membership under `scope` (each with its own staged
    /// idp config, so callers need not thread one). Returns the user id — the
    /// FK target for a connection's `owner_user_id`/`created_by_user_id`.
    async fn seed_member(pool: &PgPool, scope: TenantScope, subject: &str) -> Uuid {
        let cfg_id = Uuid::now_v7();
        sqlx::query(
            "insert into org_idp_configs
               (id, tenant_id, generation, issuer, client_id, claim_mappings, status)
             values ($1, $2,
                     coalesce((select max(generation) from org_idp_configs where tenant_id = $2), 0) + 1,
                     $3, 'client-test', '{}'::jsonb, 'staged')",
        )
        .bind(cfg_id)
        .bind(scope.tenant_id())
        .bind(format!("https://idp.test/{subject}"))
        .execute(pool)
        .await
        .unwrap();
        let user_id = Uuid::now_v7();
        sqlx::query(
            "insert into users
               (id, tenant_id, idp_config_id, subject, email, email_normalized, email_verified, status)
             values ($1, $2, $3, $4, $5, $5, true, 'active')",
        )
        .bind(user_id)
        .bind(scope.tenant_id())
        .bind(cfg_id)
        .bind(subject)
        .bind(format!("{subject}@example.com"))
        .execute(pool)
        .await
        .unwrap();
        sqlx::query(
            "insert into org_memberships (id, tenant_id, user_id, roles, status)
             values ($1, $2, $3, '{member}', 'active')",
        )
        .bind(Uuid::now_v7())
        .bind(scope.tenant_id())
        .bind(user_id)
        .execute(pool)
        .await
        .unwrap();
        user_id
    }

    async fn cleanup_orgs(pool: &PgPool, stmts: &[&'static str], tenants: &[Uuid]) {
        for id in tenants {
            for &stmt in stmts {
                sqlx::query(stmt).bind(id).execute(pool).await.unwrap();
            }
            sqlx::query("delete from tenants where id = $1")
                .bind(id)
                .execute(pool)
                .await
                .unwrap();
        }
    }

    /// Owner-shape CHECK, ownership visibility lens, and generation bump.
    #[tokio::test]
    async fn phase_c_connection_ownership_and_visibility() {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("skipping: DATABASE_URL not set");
            return;
        };
        let pool = connect(&url).await.expect("connect");
        let slug = format!("t-{}", Uuid::now_v7().simple());
        let org = identity::create_org(&pool, &slug, None).await.unwrap();
        let scope = TenantScope::assume(org.id);
        let alice = seed_member(&pool, scope, "alice").await;
        let bob = seed_member(&pool, scope, "bob").await;

        // owner-shape CHECK: owner_type='user' with a NULL owner_user_id is
        // rejected by the DB (a half-populated owner is fail-closed).
        let bad_owner = sqlx::query(
            "insert into integration_connections
               (id, tenant_id, provider, external_account_id, display_name, owner_type)
             values ($1, $2, 'mcp_http', 'x', 'bad', 'user')",
        )
        .bind(Uuid::now_v7())
        .bind(org.id)
        .execute(&pool)
        .await;

        let org_conn = create_connection(
            &pool,
            scope,
            "mcp_http",
            "acct-org",
            "Org conn",
            None,
            &serde_json::json!([]),
            &serde_json::json!({}),
            &serde_json::json!({}),
            None,
            ConnectionAuth::static_active(),
            ConnectionOwner::Organization,
            None,
        )
        .await
        .unwrap();
        let alice_conn = create_connection(
            &pool,
            scope,
            "mcp_http",
            "acct-alice",
            "Alice personal",
            None,
            &serde_json::json!([]),
            &serde_json::json!({}),
            &serde_json::json!({}),
            None,
            ConnectionAuth::static_active(),
            ConnectionOwner::User(alice),
            Some(alice),
        )
        .await
        .unwrap();

        // bob's lens sees the org connection but NOT alice's personal one.
        let bob_list = list_connections_visible(&pool, scope, ConnectionViewer::User(bob))
            .await
            .unwrap();
        let all_list = list_connections_visible(&pool, scope, ConnectionViewer::All)
            .await
            .unwrap();
        let bob_sees_alice =
            get_connection_visible(&pool, scope, alice_conn.id, ConnectionViewer::User(bob))
                .await
                .unwrap();
        let alice_sees_alice =
            get_connection_visible(&pool, scope, alice_conn.id, ConnectionViewer::User(alice))
                .await
                .unwrap();
        let bumped = bump_connection_generation(&pool, scope, org_conn.id)
            .await
            .unwrap();

        cleanup_orgs(
            &pool,
            &[
                "delete from integration_connections where tenant_id = $1",
                "delete from org_memberships where tenant_id = $1",
                "delete from users where tenant_id = $1",
                "delete from org_idp_configs where tenant_id = $1",
            ],
            &[org.id],
        )
        .await;

        assert!(
            bad_owner.is_err(),
            "user owner without owner_user_id rejected"
        );
        assert_eq!(org_conn.owner_type, "organization");
        assert_eq!(org_conn.authorization_generation, 1);
        assert_eq!(alice_conn.owner_type, "user");
        assert_eq!(alice_conn.owner_user_id, Some(alice));
        let bob_ids: Vec<Uuid> = bob_list.iter().map(|c| c.id).collect();
        assert!(
            bob_ids.contains(&org_conn.id),
            "bob sees the org connection"
        );
        assert!(
            !bob_ids.contains(&alice_conn.id),
            "bob must not see alice's personal connection"
        );
        assert_eq!(all_list.len(), 2, "All lens sees both connections");
        assert!(
            bob_sees_alice.is_none(),
            "bob cannot read alice's personal row"
        );
        assert!(alice_sees_alice.is_some(), "alice reads her own connection");
        assert_eq!(bumped, Some(2), "generation bumps 1 → 2");
    }

    /// Snapshots auto-increment per connection, are append-only, and are
    /// tenant-scoped.
    #[tokio::test]
    async fn phase_c_tool_snapshots_versioned_and_scoped() {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("skipping: DATABASE_URL not set");
            return;
        };
        let pool = connect(&url).await.expect("connect");
        let slug_a = format!("t-{}", Uuid::now_v7().simple());
        let slug_b = format!("t-{}", Uuid::now_v7().simple());
        let org_a = identity::create_org(&pool, &slug_a, None).await.unwrap();
        let org_b = identity::create_org(&pool, &slug_b, None).await.unwrap();
        let scope_a = TenantScope::assume(org_a.id);
        let scope_b = TenantScope::assume(org_b.id);

        let conn = create_connection(
            &pool,
            scope_a,
            "mcp_http",
            "acct-snap",
            "Snap conn",
            None,
            &serde_json::json!([]),
            &serde_json::json!({}),
            &serde_json::json!({}),
            None,
            ConnectionAuth::static_active(),
            ConnectionOwner::Organization,
            None,
        )
        .await
        .unwrap();

        let s1 = insert_connection_tool_snapshot(
            &pool,
            scope_a,
            conn.id,
            1,
            "2025-06-18",
            &serde_json::json!([{"name": "t1"}]),
            "digest-1",
        )
        .await
        .unwrap();
        let s2 = insert_connection_tool_snapshot(
            &pool,
            scope_a,
            conn.id,
            1,
            "2025-06-18",
            &serde_json::json!([{"name": "t2"}]),
            "digest-2",
        )
        .await
        .unwrap();
        let latest = latest_connection_tool_snapshot(&pool, scope_a, conn.id)
            .await
            .unwrap();
        let listed = list_connection_tool_snapshots(&pool, scope_a, conn.id)
            .await
            .unwrap();
        let v1 = get_connection_tool_snapshot(&pool, scope_a, conn.id, 1)
            .await
            .unwrap();
        // Append-only: a duplicate (tenant, connection, version) is rejected.
        let dup = sqlx::query(
            "insert into connection_tool_snapshots
               (id, tenant_id, connection_id, snapshot_version, authorization_generation,
                protocol_version, tools_json, tools_digest)
             values ($1, $2, $3, 2, 1, 'p', '[]'::jsonb, 'd')",
        )
        .bind(Uuid::now_v7())
        .bind(org_a.id)
        .bind(conn.id)
        .execute(&pool)
        .await;
        // Cross-tenant: B cannot read A's snapshots.
        let latest_b = latest_connection_tool_snapshot(&pool, scope_b, conn.id)
            .await
            .unwrap();
        let get_b = get_connection_tool_snapshot(&pool, scope_b, conn.id, 1)
            .await
            .unwrap();

        cleanup_orgs(
            &pool,
            &[
                "delete from connection_tool_snapshots where tenant_id = $1",
                "delete from integration_connections where tenant_id = $1",
            ],
            &[org_a.id, org_b.id],
        )
        .await;

        assert_eq!(s1.snapshot_version, 1, "first snapshot is version 1");
        assert_eq!(
            s2.snapshot_version, 2,
            "version auto-increments per connection"
        );
        assert_eq!(latest.unwrap().snapshot_version, 2);
        assert_eq!(listed.len(), 2, "list returns every version, newest first");
        assert_eq!(listed[0].snapshot_version, 2);
        assert_eq!(v1.unwrap().tools_digest, "digest-1");
        assert!(
            dup.is_err(),
            "duplicate (tenant, connection, version) rejected"
        );
        assert!(latest_b.is_none(), "B cannot read A's snapshot (latest)");
        assert!(get_b.is_none(), "B cannot read A's snapshot (by version)");
    }

    /// A snapshot taken after a re-consent records the BUMPED authorization
    /// generation (design :294-296, :306) — the pin a run binding froze under
    /// the older generation stays distinguishable, so the broker recheck can
    /// fail it closed. (The live-MCP photograph itself is CI-e2e territory; this
    /// exercises the generation stamping the photograph relies on.)
    #[tokio::test]
    async fn phase_c_snapshot_records_bumped_generation() {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("skipping: DATABASE_URL not set");
            return;
        };
        let pool = connect(&url).await.expect("connect");
        let slug = format!("t-{}", Uuid::now_v7().simple());
        let org = identity::create_org(&pool, &slug, None).await.unwrap();
        let scope = TenantScope::assume(org.id);

        let conn = create_connection(
            &pool,
            scope,
            "mcp_http",
            "acct-gen",
            "Gen conn",
            None,
            &serde_json::json!([]),
            &serde_json::json!({}),
            &serde_json::json!({}),
            None,
            ConnectionAuth::static_active(),
            ConnectionOwner::Organization,
            None,
        )
        .await
        .unwrap();

        // First photograph stamps generation 1.
        let s1 = insert_connection_tool_snapshot(
            &pool,
            scope,
            conn.id,
            conn.authorization_generation,
            "2025-06-18",
            &serde_json::json!([{ "name": "t1" }]),
            "digest-1",
        )
        .await
        .unwrap();

        // Re-consent bumps the generation; a fresh photograph stamps the bumped
        // value (read off the connection's CURRENT generation, as the server does).
        let bumped = bump_connection_generation(&pool, scope, conn.id)
            .await
            .unwrap()
            .expect("connection in scope");
        let conn2 = get_connection(&pool, scope, conn.id)
            .await
            .unwrap()
            .unwrap();
        let s2 = insert_connection_tool_snapshot(
            &pool,
            scope,
            conn.id,
            conn2.authorization_generation,
            "2025-06-18",
            &serde_json::json!([{ "name": "t2" }]),
            "digest-2",
        )
        .await
        .unwrap();

        cleanup_orgs(
            &pool,
            &[
                "delete from connection_tool_snapshots where tenant_id = $1",
                "delete from integration_connections where tenant_id = $1",
            ],
            &[org.id],
        )
        .await;

        assert_eq!(s1.authorization_generation, 1, "first snapshot is gen 1");
        assert_eq!(bumped, 2, "bump takes the connection to generation 2");
        assert_eq!(conn2.authorization_generation, 2);
        assert_eq!(
            s2.authorization_generation, 2,
            "snapshot records the BUMPED generation"
        );
        assert_eq!(
            s2.snapshot_version, 2,
            "snapshot version keeps auto-incrementing across a generation bump"
        );
    }

    /// Bindings commit atomically with the session, are tenant-scoped, and the
    /// authority/mcp CHECK constraints reject malformed shapes.
    #[tokio::test]
    async fn phase_c_run_resource_bindings_atomic_and_checks() {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("skipping: DATABASE_URL not set");
            return;
        };
        let pool = connect(&url).await.expect("connect");
        let slug_a = format!("t-{}", Uuid::now_v7().simple());
        let slug_b = format!("t-{}", Uuid::now_v7().simple());
        let org_a = identity::create_org(&pool, &slug_a, None).await.unwrap();
        let org_b = identity::create_org(&pool, &slug_b, None).await.unwrap();
        let scope_a = TenantScope::assume(org_a.id);
        let scope_b = TenantScope::assume(org_b.id);

        let mk_session = |scope: TenantScope, bindings: Vec<NewRunResourceBinding>| {
            let pool = pool.clone();
            async move {
                let policy = upsert_policy(
                    &pool,
                    scope,
                    "rb-policy",
                    "name: rb",
                    &serde_json::json!({"name":"rb"}),
                )
                .await
                .unwrap();
                let agent = create_agent(&pool, scope, "rb-agent", None).await.unwrap();
                let rev = append_agent_revision(
                    &pool,
                    scope,
                    agent.id,
                    "claude-agent-sdk",
                    "img:test",
                    "claude-haiku-4-5",
                    None,
                    policy.id,
                    &serde_json::json!({}),
                    None,
                    &serde_json::json!([]),
                    &serde_json::json!([]),
                )
                .await
                .unwrap();
                create_session(
                    &pool,
                    scope,
                    agent.id,
                    rev.id,
                    "supervised",
                    "trusted",
                    "rb",
                    &serde_json::json!({"kind":"none"}),
                    &serde_json::json!({}),
                    &serde_json::json!({}),
                    None,
                    None,
                    None,
                    None,
                    None,
                    &bindings,
                )
                .await
                .unwrap()
            }
        };

        let conn = create_connection(
            &pool,
            scope_a,
            "mcp_http",
            "acct-rb",
            "RB conn",
            None,
            &serde_json::json!([]),
            &serde_json::json!({}),
            &serde_json::json!({}),
            None,
            ConnectionAuth::static_active(),
            ConnectionOwner::Organization,
            None,
        )
        .await
        .unwrap();
        let snap = insert_connection_tool_snapshot(
            &pool,
            scope_a,
            conn.id,
            conn.authorization_generation,
            "2025-06-18",
            &serde_json::json!([{"name": "t1"}]),
            "digest-1",
        )
        .await
        .unwrap();

        let mcp_binding = NewRunResourceBinding {
            id: Uuid::now_v7(),
            requirement_slot: "primary".into(),
            slot_kind: "mcp".into(),
            authority_kind: "connection".into(),
            connection_id: Some(conn.id),
            subscription_id: None,
            authority_generation: Some(conn.authorization_generation),
            connection_owner_type: Some(conn.owner_type.clone()),
            connection_owner_user_id: conn.owner_user_id,
            snapshot_version: Some(snap.snapshot_version),
            effective_tools_json: Some(serde_json::json!([{"name": "t1"}])),
            effective_tools_digest: Some("digest-1".into()),
            resource_scope: serde_json::json!({}),
            resolved_by_principal_kind: "operator".into(),
            resolved_by_principal_id: None,
            binding_mode: "organization".into(),
        };
        let session = mk_session(scope_a, vec![mcp_binding.clone()]).await;

        // Atomic: the binding is present under A immediately after the session.
        let a_bindings = session_resource_bindings(&pool, scope_a, session.id)
            .await
            .unwrap();
        let by_id = get_run_resource_binding(&pool, scope_a, mcp_binding.id)
            .await
            .unwrap();
        let found = find_session_binding(&pool, scope_a, session.id, "mcp", "primary")
            .await
            .unwrap();
        // Cross-tenant: B cannot read A's binding.
        let b_bindings = session_resource_bindings(&pool, scope_b, session.id)
            .await
            .unwrap();
        let by_id_b = get_run_resource_binding(&pool, scope_b, mcp_binding.id)
            .await
            .unwrap();

        // FK negative: a binding for another tenant's session is refused.
        let session_b = mk_session(scope_b, vec![]).await;
        let none_binding = |slot_kind: &str, authority_kind: &str| NewRunResourceBinding {
            id: Uuid::now_v7(),
            requirement_slot: "x".into(),
            slot_kind: slot_kind.into(),
            authority_kind: authority_kind.into(),
            connection_id: None,
            subscription_id: None,
            authority_generation: None,
            connection_owner_type: None,
            connection_owner_user_id: None,
            snapshot_version: None,
            effective_tools_json: None,
            effective_tools_digest: None,
            resource_scope: serde_json::json!({}),
            resolved_by_principal_kind: "system".into(),
            resolved_by_principal_id: None,
            binding_mode: "organization".into(),
        };
        let fk_bad = insert_run_resource_bindings(
            &mut pool.acquire().await.unwrap(),
            scope_a,
            session_b.id,
            &[none_binding("workspace_fetch", "none")],
        )
        .await;

        // Shape CHECK negatives (each on a valid in-scope session):
        // (a) mcp slot missing the snapshot fields. A FRESH requirement_slot is
        // mandatory: reusing "primary" would collide with mcp_binding on the
        // unique (tenant_id, session_id, slot_kind, requirement_slot) key, so the
        // insert would fail even if the mcp-shape CHECK regressed. With its own
        // slot the ONLY reason it can fail is run_resource_bindings_mcp_shape.
        let mut bad_mcp = mcp_binding.clone();
        bad_mcp.id = Uuid::now_v7();
        bad_mcp.requirement_slot = "shape-a".into();
        bad_mcp.snapshot_version = None;
        bad_mcp.effective_tools_json = None;
        bad_mcp.effective_tools_digest = None;
        let shape_a = insert_run_resource_bindings(
            &mut pool.acquire().await.unwrap(),
            scope_a,
            session.id,
            &[bad_mcp],
        )
        .await;
        // (b) connection authority missing its generation.
        let mut bad_gen = mcp_binding.clone();
        bad_gen.id = Uuid::now_v7();
        bad_gen.requirement_slot = "wf".into();
        bad_gen.slot_kind = "workspace_fetch".into();
        bad_gen.snapshot_version = None;
        bad_gen.effective_tools_json = None;
        bad_gen.effective_tools_digest = None;
        bad_gen.authority_generation = None;
        let shape_b = insert_run_resource_bindings(
            &mut pool.acquire().await.unwrap(),
            scope_a,
            session.id,
            &[bad_gen],
        )
        .await;
        // (c) none authority carrying a connection_id.
        let mut bad_none = none_binding("workspace_fetch", "none");
        bad_none.connection_id = Some(conn.id);
        let shape_c = insert_run_resource_bindings(
            &mut pool.acquire().await.unwrap(),
            scope_a,
            session.id,
            &[bad_none],
        )
        .await;

        cleanup_orgs(
            &pool,
            &[
                "delete from run_resource_bindings where tenant_id = $1",
                "delete from sessions where tenant_id = $1",
                "delete from connection_tool_snapshots where tenant_id = $1",
                "delete from integration_connections where tenant_id = $1",
                "delete from agent_revisions where agent_id in (select id from agents where tenant_id = $1)",
                "delete from agents where tenant_id = $1",
                "delete from policies where tenant_id = $1",
            ],
            &[org_a.id, org_b.id],
        )
        .await;

        assert_eq!(
            a_bindings.len(),
            1,
            "the binding committed with the session"
        );
        assert_eq!(a_bindings[0].id, mcp_binding.id);
        assert_eq!(a_bindings[0].authority_kind, "connection");
        assert!(by_id.is_some(), "binding readable by id in scope");
        assert!(found.is_some(), "binding found by (slot_kind, slot)");
        assert!(b_bindings.is_empty(), "B cannot list A's bindings");
        assert!(by_id_b.is_none(), "B cannot read A's binding by id");
        assert!(
            fk_bad.is_err(),
            "binding for another tenant's session refused"
        );
        assert!(
            shape_a.is_err(),
            "mcp slot without snapshot fields rejected"
        );
        assert!(
            shape_b.is_err(),
            "connection authority without generation rejected"
        );
        assert!(
            shape_c.is_err(),
            "none authority with a connection_id rejected"
        );
    }

    /// Custom catalog entries land tenant-scoped, are invisible to another org,
    /// and cannot mask a global slug.
    #[tokio::test]
    async fn phase_c_catalog_custom_entries_tenant_scoped() {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("skipping: DATABASE_URL not set");
            return;
        };
        let pool = connect(&url).await.expect("connect");
        let slug_a = format!("t-{}", Uuid::now_v7().simple());
        let slug_b = format!("t-{}", Uuid::now_v7().simple());
        let org_a = identity::create_org(&pool, &slug_a, None).await.unwrap();
        let org_b = identity::create_org(&pool, &slug_b, None).await.unwrap();
        let scope_a = TenantScope::assume(org_a.id);
        let scope_b = TenantScope::assume(org_b.id);

        let entry_slug = format!("xt-cat-{}", Uuid::now_v7().simple());
        let created = create_catalog_entry(
            &pool,
            scope_a,
            &entry_slug,
            "Tenant custom",
            None,
            None,
            &serde_json::json!([]),
            Some("https://mcp.example.test/mcp"),
            "streamable_http",
            "none",
            &serde_json::json!({}),
            &serde_json::json!([]),
            &serde_json::json!([]),
            &serde_json::json!([]),
            None,
        )
        .await
        .unwrap();

        let a_sees = get_catalog_by_slug(&pool, scope_a, &entry_slug)
            .await
            .unwrap();
        let b_sees = get_catalog_by_slug(&pool, scope_b, &entry_slug)
            .await
            .unwrap();
        let a_list = list_catalog(&pool, scope_a).await.unwrap();
        let b_list = list_catalog(&pool, scope_b).await.unwrap();
        // A custom slug colliding with a GLOBAL seed ('github') is refused.
        let collision = create_catalog_entry(
            &pool,
            scope_a,
            "github",
            "Shadow",
            None,
            None,
            &serde_json::json!([]),
            Some("https://evil.example.test/mcp"),
            "streamable_http",
            "none",
            &serde_json::json!({}),
            &serde_json::json!([]),
            &serde_json::json!([]),
            &serde_json::json!([]),
            None,
        )
        .await
        .unwrap();

        cleanup_orgs(
            &pool,
            &["delete from connector_catalog where tenant_id = $1"],
            &[org_a.id, org_b.id],
        )
        .await;

        let created = created.expect("custom entry lands");
        assert_eq!(created.tenant_id, Some(org_a.id));
        assert!(a_sees.is_some(), "A sees its own custom entry");
        assert!(b_sees.is_none(), "B cannot see A's custom entry");
        assert!(
            a_list.iter().any(|c| c.slug == entry_slug),
            "A's list includes its custom entry"
        );
        assert!(
            !b_list.iter().any(|c| c.slug == entry_slug),
            "B's list excludes A's custom entry"
        );
        assert!(collision.is_none(), "a global-slug collision is refused");
    }
}
