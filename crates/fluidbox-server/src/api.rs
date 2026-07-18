//! Public `/v1` API (admin token). The dashboard and CLI talk only to this.

use crate::auth::Principal;
use crate::error::{ApiError, ApiResult};
use crate::harness;
use crate::orchestrator;
use crate::rbac;
use crate::state::AppState;
use axum::extract::{Path, Query, State};
use axum::Json;
use fluidbox_core::policy::{Policy, RuleAction, ToolOverride};
use fluidbox_core::spec::{
    Autonomy, Budgets, CheckoutMode, InvocationContext, InvocationKind, WorkspaceSpec,
};
use fluidbox_db::TenantScope;
use serde::Deserialize;
use serde_json::{json, Value};
use uuid::Uuid;

// ─── Workspace input (shared by run creation and agent defaults) ──────────

/// What callers may ask for. Resolved and validated into a frozen
/// `WorkspaceSpec` before anything is stored: connection-bound repositories
/// are checked against the connection (existence, tenant, status, host), so
/// an invocation can narrow authority but never escape it.
#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum WorkspaceInput {
    #[serde(alias = "none")]
    Scratch,
    #[serde(alias = "local_path")]
    LocalCopy { path: String },
    GitRepository {
        #[serde(default)]
        connection_id: Option<Uuid>,
        /// "owner/name" — used with a connection to derive the clone URL.
        #[serde(default)]
        repository: Option<String>,
        #[serde(default)]
        clone_url: Option<String>,
        #[serde(default)]
        r#ref: Option<String>,
        #[serde(default)]
        commit_sha: Option<String>,
        #[serde(default)]
        checkout_mode: Option<CheckoutMode>,
    },
}

/// Same parsed origin (scheme + host + port)? Guards caller-supplied clone
/// URLs against escaping the configured clone base — string prefixes lie
/// (`https://github.com.evil.tld`), parsed origins don't. `file://` bases
/// (the e2e seam) additionally require PATH containment: sharing the file
/// scheme is not "the same place".
pub(crate) fn same_origin(a: &str, b: &str) -> bool {
    match (reqwest::Url::parse(a), reqwest::Url::parse(b)) {
        (Ok(a), Ok(b)) => {
            let origin_ok = a.scheme() == b.scheme()
                && a.host_str() == b.host_str()
                && a.port_or_known_default() == b.port_or_known_default();
            if !origin_ok {
                return false;
            }
            if a.scheme() == "file" {
                let root = b.path().trim_end_matches('/');
                return a.path() == root || a.path().starts_with(&format!("{root}/"));
            }
            true
        }
        _ => false,
    }
}

pub(crate) fn valid_repo_name(repo: &str) -> bool {
    match repo.split_once('/') {
        Some((owner, name)) => {
            let ok = |s: &str| {
                !s.is_empty()
                    && s.chars()
                        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
            };
            ok(owner) && ok(name)
        }
        None => false,
    }
}

pub(crate) async fn resolve_workspace_input(
    state: &AppState,
    scope: TenantScope,
    input: WorkspaceInput,
) -> ApiResult<WorkspaceSpec> {
    Ok(match input {
        WorkspaceInput::Scratch => WorkspaceSpec::Scratch,
        WorkspaceInput::LocalCopy { path } => {
            if path.trim().is_empty() {
                return Err(ApiError::BadRequest("workspace path is empty".into()));
            }
            WorkspaceSpec::LocalCopy { path }
        }
        WorkspaceInput::GitRepository {
            connection_id,
            repository,
            clone_url,
            r#ref,
            commit_sha,
            checkout_mode,
        } => {
            if let Some(sha) = &commit_sha {
                if sha.len() < 7 || sha.len() > 40 || !sha.chars().all(|c| c.is_ascii_hexdigit()) {
                    return Err(ApiError::BadRequest(format!("invalid commit_sha '{sha}'")));
                }
            }
            if let Some(repo) = &repository {
                if !valid_repo_name(repo) {
                    return Err(ApiError::BadRequest(format!(
                        "repository must be 'owner/name' (got '{repo}')"
                    )));
                }
            }
            let clone_url = match connection_id {
                Some(cid) => {
                    let conn = fluidbox_db::get_connection(&state.pool, scope, cid)
                        .await?
                        .ok_or_else(|| ApiError::BadRequest(format!("unknown connection {cid}")))?;
                    if conn.status != "active" {
                        return Err(ApiError::BadRequest(format!(
                            "connection {cid} is {} — reconnect it first",
                            conn.status
                        )));
                    }
                    // Both flavors supply git credentials: a PAT directly,
                    // a github_app via minted installation tokens.
                    if crate::connectors::connector_for(&conn.provider) != Some("github") {
                        return Err(ApiError::BadRequest(format!(
                            "connection provider '{}' does not supply git workspaces",
                            conn.provider
                        )));
                    }
                    let base = state.cfg.github_clone_base.trim_end_matches('/');
                    match clone_url {
                        // A supplied URL may narrow but not escape the
                        // connection's provider (parsed-origin compare, so
                        // the e2e file:// seam and GHES stay honest).
                        Some(url) => {
                            if !same_origin(&url, base) {
                                return Err(ApiError::BadRequest(format!(
                                    "clone_url must be on {base} for a github connection"
                                )));
                            }
                            url
                        }
                        None => {
                            let repo = repository.as_deref().ok_or_else(|| {
                                ApiError::BadRequest(
                                    "repository (owner/name) or clone_url is required".into(),
                                )
                            })?;
                            // No `.git` suffix — matches the event-derived
                            // clone URLs (git accepts both on GitHub, and
                            // file:// fixture roots only serve this form).
                            format!("{base}/{repo}")
                        }
                    }
                }
                None => match clone_url {
                    // Unauthenticated clone (public repo, or file:// in dev —
                    // this API is admin-token-gated, same trust as LocalCopy).
                    Some(url) => url,
                    None => match &repository {
                        Some(repo) => format!("https://github.com/{repo}.git"),
                        None => {
                            return Err(ApiError::BadRequest(
                                "clone_url or connection_id+repository is required".into(),
                            ))
                        }
                    },
                },
            };
            WorkspaceSpec::GitRepository {
                connection_id,
                repository,
                clone_url,
                r#ref,
                commit_sha,
                checkout_mode: checkout_mode.unwrap_or_default(),
            }
        }
    })
}

/// A revision default of Scratch means "no default" — store nothing.
async fn default_workspace_value(
    state: &AppState,
    scope: TenantScope,
    input: Option<WorkspaceInput>,
) -> ApiResult<Option<Value>> {
    match input {
        None => Ok(None),
        Some(input) => match resolve_workspace_input(state, scope, input).await? {
            WorkspaceSpec::Scratch => Ok(None),
            spec => Ok(Some(serde_json::to_value(&spec)?)),
        },
    }
}

// ─── Capability attachment (§17 #7: pin-only) ─────────────────────────────

/// Resolve `"name"` / `"name@version"` refs into exact pins. A bare name
/// pins the newest version AT ATTACH TIME — nothing floats afterwards;
/// upgrading a bundle means appending a new agent revision. Server-alias
/// collisions across the attached set are refused here so the run-time
/// intersection can never materialize a shadowed tool.
pub(crate) async fn resolve_bundle_pins(
    state: &AppState,
    scope: TenantScope,
    specs: &[String],
) -> ApiResult<Value> {
    use fluidbox_core::capability::{
        server_collision, BundleRef, CapabilityBundleDef, FrozenBundle,
    };
    let mut refs: Vec<BundleRef> = Vec::with_capacity(specs.len());
    let mut frozen: Vec<FrozenBundle> = Vec::with_capacity(specs.len());
    for spec in specs {
        let spec = spec.trim();
        let (name, version) = match spec.split_once('@') {
            Some((n, v)) => (
                n.trim(),
                Some(v.trim().parse::<i32>().map_err(|_| {
                    ApiError::BadRequest(format!("bad bundle version in '{spec}'"))
                })?),
            ),
            None => (spec, None),
        };
        if refs.iter().any(|r| r.name == name) {
            return Err(ApiError::BadRequest(format!(
                "bundle '{name}' is attached more than once"
            )));
        }
        let row = match version {
            Some(v) => {
                fluidbox_db::get_capability_bundle_version(&state.pool, scope, name, v).await?
            }
            None => fluidbox_db::latest_capability_bundle(&state.pool, scope, name).await?,
        }
        .ok_or_else(|| ApiError::BadRequest(format!("unknown capability bundle '{spec}'")))?;
        let def: CapabilityBundleDef = serde_json::from_value(row.definition.clone())
            .map_err(|e| ApiError::Internal(format!("bad stored bundle definition: {e}")))?;
        refs.push(BundleRef {
            id: row.id,
            name: row.name.clone(),
            version: row.version,
        });
        frozen.push(FrozenBundle {
            id: row.id,
            name: row.name,
            version: row.version,
            definition_digest: row.definition_digest,
            servers: def.servers,
        });
    }
    if let Some(name) = server_collision(&frozen) {
        return Err(ApiError::BadRequest(format!(
            "capability server name '{name}' appears in more than one attached bundle"
        )));
    }
    Ok(serde_json::to_value(&refs)?)
}

// ─── Health ───────────────────────────────────────────────────────────────

pub async fn health() -> Json<Value> {
    Json(json!({ "status": "ok" }))
}

pub async fn health_ready(State(state): State<AppState>) -> ApiResult<Json<Value>> {
    sqlx::query("select 1").execute(&state.pool).await?;
    let provider_ok = state.provider.healthcheck().await.is_ok();
    Ok(Json(json!({
        "status": "ready",
        "db": true,
        "provider": state.provider.runtime_name(),
        "provider_ok": provider_ok,
    })))
}

// ─── Agents & revisions ───────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct CreateAgent {
    pub name: String,
    pub description: Option<String>,
    pub harness: Option<String>,
    pub model: Option<String>,
    pub system_prompt: Option<String>,
    pub policy: Option<String>,       // policy name
    pub runner_image: Option<String>, // defaults to configured sandbox image
    pub budgets: Option<Budgets>,
    #[serde(default)]
    pub default_workspace: Option<WorkspaceInput>,
    /// Capability bundles to attach: "name" (pins the newest version now)
    /// or "name@version" (§17 #7 pin-only).
    #[serde(default)]
    pub capability_bundles: Option<Vec<String>>,
}

/// Validate a harness id and return its (runner image, model) defaults.
/// Unknown ids are a 422 — refused before anything persists.
fn harness_defaults<'a>(
    harness_id: &str,
    cfg: &'a crate::config::Config,
) -> Result<(&'a str, &'a str), ApiError> {
    match (
        harness::default_runner_image(harness_id, cfg),
        harness::default_model(harness_id, cfg),
    ) {
        (Some(image), Some(model)) => Ok((image, model)),
        _ => Err(ApiError::UnprocessableEntity(format!(
            "unknown harness '{harness_id}' (known: {})",
            harness::KNOWN.join(", ")
        ))),
    }
}

/// Reject an EXPLICIT model that doesn't belong to the harness — a clean 422
/// before anything persists, instead of a murky failure at the first model
/// call. Inherited/default models are trusted (a shipped default is always a
/// member of its list, pinned by a harness unit test).
fn validate_model(harness_id: &str, model: &str) -> Result<(), ApiError> {
    if harness::model_belongs(harness_id, model) {
        return Ok(());
    }
    let valid: Vec<&str> = harness::models(harness_id).iter().map(|m| m.id).collect();
    Err(ApiError::UnprocessableEntity(format!(
        "model '{model}' is not valid for harness '{harness_id}' (valid: {})",
        valid.join(", ")
    )))
}

/// `GET /v1/harnesses` — the supported harness + model catalog. The SINGLE
/// source of truth for the dashboard's harness/model pickers (the frontend no
/// longer hardcodes model lists).
pub async fn list_harnesses(
    _principal: Principal,
    State(state): State<AppState>,
) -> ApiResult<Json<Value>> {
    let harnesses: Vec<Value> = harness::KNOWN
        .iter()
        .map(|&id| {
            json!({
                "id": id,
                "display_name": harness::display_name(id),
                "hint": harness::hint(id),
                "available": true,
                "default_model": harness::default_model(id, &state.cfg),
                "models": harness::models(id)
                    .iter()
                    .map(|m| json!({
                        "id": m.id,
                        "display_name": m.display_name,
                        "hint": m.hint,
                    }))
                    .collect::<Vec<_>>(),
            })
        })
        .collect();
    Ok(Json(json!({ "harnesses": harnesses })))
}

/// add_revision inheritance for image/model: explicit wins; on a harness
/// SWITCH the previous harness's value is not inherited — it re-defaults to
/// the new harness's default (a claude image/model on a codex revision is
/// never a sane inheritance).
fn inherit_unless_switched<'a>(
    explicit: Option<&'a str>,
    previous: Option<&'a str>,
    harness_changed: bool,
    default: &'a str,
) -> &'a str {
    match (explicit, harness_changed) {
        (Some(e), _) => e,
        (None, true) => default,
        (None, false) => previous.unwrap_or(default),
    }
}

pub async fn create_agent(
    principal: Principal,
    State(state): State<AppState>,
    Json(req): Json<CreateAgent>,
) -> ApiResult<Json<Value>> {
    if !rbac::can_mutate_resources(&principal) {
        return Err(ApiError::Forbidden(
            "creating agents requires admin or owner".into(),
        ));
    }
    // Validate the harness BEFORE the agent row exists — a 422 here must not
    // leave a revision-less agent behind.
    let harness_id = req.harness.as_deref().unwrap_or(harness::CLAUDE_AGENT_SDK);
    let (default_image, default_model) = harness_defaults(harness_id, &state.cfg)?;
    if let Some(m) = req.model.as_deref() {
        validate_model(harness_id, m)?;
    }

    let scope = principal.scope();
    let agent =
        fluidbox_db::create_agent(&state.pool, scope, &req.name, req.description.as_deref())
            .await?;

    // Create an initial revision so the agent is immediately runnable.
    let policy_name = req.policy.as_deref().unwrap_or("default");
    let policy = fluidbox_db::get_policy_by_name(&state.pool, scope, policy_name)
        .await?
        .ok_or_else(|| ApiError::BadRequest(format!("unknown policy '{policy_name}'")))?;
    let budgets = req.budgets.unwrap_or_default();
    let default_workspace = default_workspace_value(&state, scope, req.default_workspace).await?;
    let capability_pins = match &req.capability_bundles {
        Some(specs) => resolve_bundle_pins(&state, scope, specs).await?,
        None => json!([]),
    };
    let rev = fluidbox_db::append_agent_revision(
        &state.pool,
        scope,
        agent.id,
        harness_id,
        req.runner_image.as_deref().unwrap_or(default_image),
        req.model.as_deref().unwrap_or(default_model),
        req.system_prompt.as_deref(),
        policy.id,
        &serde_json::to_value(&budgets)?,
        default_workspace.as_ref(),
        &capability_pins,
        // Task 5 wires the request field; empty requirements for now.
        &json!([]),
    )
    .await?;

    Ok(Json(json!({ "agent": agent, "revision": rev })))
}

pub async fn list_agents(
    principal: Principal,
    State(state): State<AppState>,
) -> ApiResult<Json<Value>> {
    let scope = principal.scope();
    let agents = fluidbox_db::list_agents(&state.pool, scope).await?;
    Ok(Json(json!({ "agents": agents })))
}

pub async fn get_agent(
    principal: Principal,
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<Value>> {
    let scope = principal.scope();
    let agent = fluidbox_db::get_agent(&state.pool, scope, id)
        .await?
        .ok_or(ApiError::NotFound)?;
    let revisions = fluidbox_db::list_revisions(&state.pool, scope, id).await?;
    Ok(Json(json!({ "agent": agent, "revisions": revisions })))
}

#[derive(Deserialize)]
pub struct AddRevision {
    pub harness: Option<String>,
    pub model: Option<String>,
    pub system_prompt: Option<String>,
    pub policy: Option<String>,
    pub runner_image: Option<String>,
    pub budgets: Option<Budgets>,
    /// Omitted → inherit from the latest revision. An explicit
    /// `{"kind":"scratch"}` clears the default.
    #[serde(default)]
    pub default_workspace: Option<WorkspaceInput>,
    /// Omitted → inherit the latest revision's pins. An explicit `[]`
    /// clears them; entries re-resolve ("name" pins the newest version NOW
    /// — this is how a bundle upgrade lands: append a revision, §17 #7).
    #[serde(default)]
    pub capability_bundles: Option<Vec<String>>,
}

pub async fn add_revision(
    principal: Principal,
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    Json(req): Json<AddRevision>,
) -> ApiResult<Json<Value>> {
    if !rbac::can_mutate_resources(&principal) {
        return Err(ApiError::Forbidden(
            "editing agents requires admin or owner".into(),
        ));
    }
    let scope = principal.scope();
    let agent = fluidbox_db::get_agent(&state.pool, scope, id)
        .await?
        .ok_or(ApiError::NotFound)?;
    let latest = fluidbox_db::latest_revision(&state.pool, scope, id).await?;
    // Inherit from the latest revision unless overridden.
    let harness_id = req
        .harness
        .as_deref()
        .or(latest.as_ref().map(|r| r.harness.as_str()))
        .unwrap_or(harness::CLAUDE_AGENT_SDK);
    let (default_image, default_model) = harness_defaults(harness_id, &state.cfg)?;
    if let Some(m) = req.model.as_deref() {
        validate_model(harness_id, m)?;
    }
    let harness_changed = latest
        .as_ref()
        .map(|r| r.harness != harness_id)
        .unwrap_or(false);
    let policy_name = req.policy.clone();
    let policy_id = match policy_name {
        Some(name) => {
            fluidbox_db::get_policy_by_name(&state.pool, scope, &name)
                .await?
                .ok_or_else(|| ApiError::BadRequest(format!("unknown policy '{name}'")))?
                .id
        }
        None => latest.as_ref().map(|r| r.policy_id).ok_or_else(|| {
            ApiError::BadRequest("policy is required for the first revision".into())
        })?,
    };
    let budgets = req
        .budgets
        .map(|b| serde_json::to_value(b).unwrap())
        .or_else(|| latest.as_ref().map(|r| r.budgets.clone()))
        .unwrap_or_else(|| serde_json::to_value(Budgets::default()).unwrap());
    // Omitted → inherit; explicit scratch → cleared (stored as NULL).
    let default_workspace = match req.default_workspace {
        Some(input) => default_workspace_value(&state, scope, Some(input)).await?,
        None => latest.as_ref().and_then(|r| r.default_workspace.clone()),
    };
    // Omitted → inherit the previous pins verbatim; explicit list (incl.
    // []) re-resolves — the §17 #7 upgrade path.
    let capability_pins = match &req.capability_bundles {
        Some(specs) => resolve_bundle_pins(&state, scope, specs).await?,
        None => latest
            .as_ref()
            .map(|r| r.capability_bundles.clone())
            .unwrap_or_else(|| json!([])),
    };

    let rev = fluidbox_db::append_agent_revision(
        &state.pool,
        scope,
        agent.id,
        harness_id,
        inherit_unless_switched(
            req.runner_image.as_deref(),
            latest.as_ref().map(|r| r.runner_image.as_str()),
            harness_changed,
            default_image,
        ),
        inherit_unless_switched(
            req.model.as_deref(),
            latest.as_ref().map(|r| r.model.as_str()),
            harness_changed,
            default_model,
        ),
        req.system_prompt
            .as_deref()
            .or(latest.as_ref().and_then(|r| r.system_prompt.as_deref())),
        policy_id,
        &budgets,
        default_workspace.as_ref(),
        &capability_pins,
        // Task 5 wires the request field; empty requirements for now.
        &json!([]),
    )
    .await?;
    Ok(Json(json!({ "revision": rev })))
}

// ─── Policies ─────────────────────────────────────────────────────────────

pub async fn list_policies(
    principal: Principal,
    State(state): State<AppState>,
) -> ApiResult<Json<Value>> {
    let scope = principal.scope();
    let rows = fluidbox_db::list_policies(&state.pool, scope).await?;
    let mut out = Vec::with_capacity(rows.len());
    for row in rows {
        let policy: Policy = serde_json::from_value(row.parsed.clone())
            .map_err(|e| ApiError::Internal(format!("bad stored policy: {e}")))?;
        let agents_using = fluidbox_db::policy_agents_using(&state.pool, scope, row.id).await?;
        out.push(json!({
            "id": row.id,
            "name": row.name,
            "version": row.version,
            "updated_at": row.updated_at,
            "autonomy_summary": policy.autonomy_summary(),
            "agents_using": agents_using,
        }));
    }
    Ok(Json(json!({ "policies": out })))
}

/// The Governance page's detail payload. The dashboard renders this verbatim —
/// it never parses YAML and never resolves policy semantics.
pub async fn get_policy(
    principal: Principal,
    State(state): State<AppState>,
    Path(name): Path<String>,
) -> ApiResult<Json<Value>> {
    let scope = principal.scope();
    let row = fluidbox_db::get_policy_by_name(&state.pool, scope, &name)
        .await?
        .ok_or(ApiError::NotFound)?;
    let policy: Policy = serde_json::from_value(row.parsed.clone())
        .map_err(|e| ApiError::Internal(format!("bad stored policy: {e}")))?;

    let mut names: Vec<String> = fluidbox_core::tools::CANONICAL
        .iter()
        .map(|t| t.name.to_string())
        .collect();
    names.extend(fluidbox_db::policy_mcp_tools(&state.pool, scope, row.id).await?);

    let matrix: Vec<Value> = policy
        .tool_matrix(&names)
        .into_iter()
        .map(|(tool, status)| {
            let group = fluidbox_core::tools::CANONICAL
                .iter()
                .find(|t| t.name == tool)
                .map(|t| serde_json::to_value(t.group).unwrap_or(Value::Null))
                .unwrap_or(Value::Null);
            let server = tool
                .strip_prefix("mcp__")
                .and_then(|r| r.split_once("__"))
                .map(|(s, _)| s.to_string());
            json!({
                "tool": tool,
                "group": group,
                "server": server,
                "overridable": status.is_overridable(),
                "status": status,
            })
        })
        .collect();

    Ok(Json(json!({
        "policy": {
            "id": row.id,
            "name": row.name,
            "version": row.version,
            "updated_at": row.updated_at,
        },
        "agents_using": fluidbox_db::policy_agents_using(&state.pool, scope, row.id).await?,
        "autonomy_summary": policy.autonomy_summary(),
        "defaults": policy.defaults,
        "budgets": policy.budgets,
        "approvals": policy.approvals,
        "egress": policy.egress,
        "matrix": matrix,
    })))
}

#[derive(Deserialize)]
pub struct UpsertPolicy {
    pub name: String,
    pub yaml: String,
}

pub async fn upsert_policy(
    principal: Principal,
    State(state): State<AppState>,
    Json(req): Json<UpsertPolicy>,
) -> ApiResult<Json<Value>> {
    if !rbac::can_mutate_resources(&principal) {
        return Err(ApiError::Forbidden(
            "editing policies requires admin or owner".into(),
        ));
    }
    let mut policy = Policy::parse_yaml(&req.yaml).map_err(ApiError::UnprocessableEntity)?;
    if policy.name != req.name {
        return Err(ApiError::BadRequest(
            "policy name must match yaml `name`".into(),
        ));
    }
    // The authored yaml is never the policy that RUNS: the overrides live in
    // their own column and are re-merged into every republished `parsed`. So
    // validate the merged result, not the yaml — otherwise `shell.deny_regex`
    // added to a rule that already carries an override would be silently dead
    // (overrides are consulted BEFORE the rules) while the page still shows it.
    //
    // Assign, never append: `managed_overrides` is `#[serde(default)]`, so yaml
    // could author one, and the column — the only sanctioned writer, `[]` for a
    // policy that does not exist yet — is the truth `parsed` must agree with.
    let scope = principal.scope();
    let existing = fluidbox_db::get_policy_by_name(&state.pool, scope, &req.name).await?;
    policy.managed_overrides = match &existing {
        Some(row) => serde_json::from_value(row.managed_overrides.clone())
            .map_err(|e| ApiError::Internal(format!("bad stored overrides: {e}")))?,
        None => Vec::new(),
    };
    policy.validate().map_err(ApiError::UnprocessableEntity)?;

    let parsed = serde_json::to_value(&policy)?;
    let row = fluidbox_db::upsert_policy(&state.pool, scope, &req.name, &req.yaml, &parsed).await?;
    Ok(Json(json!({ "policy": row })))
}

#[derive(Deserialize)]
pub struct ValidatePolicy {
    pub yaml: String,
}

pub async fn validate_policy(
    _principal: Principal,
    Json(req): Json<ValidatePolicy>,
) -> ApiResult<Json<Value>> {
    match Policy::parse_yaml(&req.yaml) {
        Ok(p) => Ok(Json(json!({ "valid": true, "name": p.name }))),
        Err(e) => Err(ApiError::UnprocessableEntity(e)),
    }
}

#[derive(Deserialize)]
pub struct SetOverride {
    pub action: RuleAction,
}

/// The override write raced a policy delete: the pre-check found the row, the
/// write did not. A vanished policy is a 404, not a 500.
fn policy_gone(e: sqlx::Error) -> ApiError {
    match e {
        sqlx::Error::RowNotFound => ApiError::NotFound,
        other => ApiError::Db(other),
    }
}

/// The server enforces what the UI renders — never the UI alone. A conditional
/// rule's verdict depends on the path touched or the command run, so a flat
/// action cannot express it and flattening it would delete the rule's
/// paths.deny / shell constraints.
pub async fn put_policy_override(
    principal: Principal,
    State(state): State<AppState>,
    Path((name, tool)): Path<(String, String)>,
    Json(req): Json<SetOverride>,
) -> ApiResult<Json<Value>> {
    if !rbac::can_mutate_resources(&principal) {
        return Err(ApiError::Forbidden(
            "editing policies requires admin or owner".into(),
        ));
    }
    let scope = principal.scope();
    let row = fluidbox_db::get_policy_by_name(&state.pool, scope, &name)
        .await?
        .ok_or(ApiError::NotFound)?;
    let mut policy: Policy = serde_json::from_value(row.parsed.clone())
        .map_err(|e| ApiError::Internal(format!("bad stored policy: {e}")))?;

    // Exact names only — a wildcard override would be an un-reviewable blanket
    // rule authored by a click.
    if !fluidbox_core::tools::is_canonical(&tool) && !fluidbox_core::tools::is_mcp(&tool) {
        return Err(ApiError::BadRequest(format!(
            "'{tool}' is not a known tool — overrides take exact canonical or mcp__* names"
        )));
    }
    // `mcp__*` is a NAMESPACE, not a roster: the name shape alone proves
    // nothing exists. A blanket `mcp__*` rule (the seed has one) resolves any
    // invented name to an overridable row, so without this the override lands
    // in the column for a tool that no bundle photographed — consulted FIRST by
    // every future evaluation, yet rendered by no page (the matrix lists only
    // canonical + currently-attached tools). Attach that bundle later and the
    // tool arrives pre-decided, invisible, never re-decided. So a write must
    // pass the same roster the matrix is drawn from.
    if fluidbox_core::tools::is_mcp(&tool)
        && !fluidbox_db::policy_mcp_tools(&state.pool, scope, row.id)
            .await?
            .iter()
            .any(|t| t == &tool)
    {
        return Err(ApiError::BadRequest(format!(
            "'{tool}' is not among the MCP tools this policy's agents can call — attach a \
             capability bundle providing it before setting a permission for it"
        )));
    }
    let status = policy
        .tool_matrix(std::slice::from_ref(&tool))
        .pop()
        .map(|(_, s)| s)
        .ok_or_else(|| ApiError::Internal("tool_matrix returned no row".into()))?;
    if !status.is_overridable() {
        return Err(ApiError::BadRequest(format!(
            "'{tool}' is governed by a conditional rule (paths/shell); its verdict depends on \
             the path touched or command run, so it cannot be set to a single action"
        )));
    }

    // Fail-closed backstop. The checks above give a precise 400 for the one
    // click a human makes; `validate()` is the invariant the ENGINE keeps, so
    // run it against the merged policy that would actually be persisted —
    // nothing reaches the column that `validate()` would refuse on the sync
    // path. Replace, never append: one decision per tool.
    policy.managed_overrides.retain(|o| o.tool != tool);
    policy.managed_overrides.push(ToolOverride {
        tool: tool.clone(),
        action: req.action,
    });
    policy.validate().map_err(ApiError::BadRequest)?;

    let row = fluidbox_db::set_policy_override(&state.pool, scope, &name, &tool, req.action)
        .await
        .map_err(policy_gone)?;
    Ok(Json(
        json!({ "policy": { "name": row.name, "version": row.version } }),
    ))
}

pub async fn delete_policy_override(
    principal: Principal,
    State(state): State<AppState>,
    Path((name, tool)): Path<(String, String)>,
) -> ApiResult<Json<Value>> {
    if !rbac::can_mutate_resources(&principal) {
        return Err(ApiError::Forbidden(
            "editing policies requires admin or owner".into(),
        ));
    }
    let scope = principal.scope();
    fluidbox_db::get_policy_by_name(&state.pool, scope, &name)
        .await?
        .ok_or(ApiError::NotFound)?;
    // Clearing only ever REMOVES an override, so the merged policy it leaves
    // behind is a subset of one that already validated — nothing to re-check.
    let row = fluidbox_db::clear_policy_override(&state.pool, scope, &name, &tool)
        .await
        .map_err(policy_gone)?;
    Ok(Json(
        json!({ "policy": { "name": row.name, "version": row.version } }),
    ))
}

// ─── Sessions ─────────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct CreateSession {
    /// Agent name or id.
    pub agent: String,
    pub task: String,
    /// Explicit invocation workspace. Omitted → the agent revision's default
    /// workspace → scratch.
    #[serde(default)]
    pub workspace: Option<WorkspaceInput>,
    /// Deprecated alias for `workspace` (M1 callers).
    #[serde(default)]
    pub repo: Option<WorkspaceInput>,
    #[serde(default)]
    pub autonomous: bool,
    /// Optional per-run budget tightening.
    #[serde(default)]
    pub budgets: Option<Budgets>,
    /// Optional per-run capability narrowing: a keep-list of bundle names
    /// intersected with the revision's attachments (remove-only, §3.5).
    #[serde(default)]
    pub capabilities: Option<Vec<String>>,
}

pub async fn create_session(
    principal: Principal,
    State(state): State<AppState>,
    Json(req): Json<CreateSession>,
) -> ApiResult<Json<Value>> {
    // Any authenticated principal may create a run; visibility of the created
    // run is governed by `invoked_by_user_id` (stamped below).
    let scope = principal.scope();
    let explicit_input = match (req.workspace, req.repo) {
        (Some(_), Some(_)) => {
            return Err(ApiError::BadRequest(
                "provide either `workspace` or legacy `repo`, not both".into(),
            ))
        }
        (w, r) => w.or(r),
    };
    let explicit = match explicit_input {
        Some(input) => Some(resolve_workspace_input(&state, scope, input).await?),
        None => None,
    };
    let autonomy = if req.autonomous {
        Autonomy::Autonomous
    } else {
        Autonomy::Supervised
    };
    let created = crate::run_service::create_run(
        &state,
        scope,
        crate::run_service::CreateRun {
            agent: req.agent,
            revision: crate::run_service::RevisionSelector::Latest,
            task: req.task,
            explicit_workspace: explicit,
            autonomy,
            trust_tier: fluidbox_core::spec::TrustTier::Trusted,
            budget_override: req.budgets,
            capability_selection: req.capabilities,
            invocation: InvocationContext {
                kind: InvocationKind::Manual,
                subscription_id: None,
                actor: Some(principal.decided_by()),
                attributes: Value::Null,
                received_at: Some(chrono::Utc::now()),
                ..Default::default()
            },
            invoked_by_user_id: principal.user_id(),
            result_destinations: vec![],
            bound_invocation: None,
            bound_dispatch: None,
        },
    )
    .await?;
    let session = match created {
        crate::run_service::RunCreation::Created(s) => *s,
        // Manual runs carry no subscription — both unreachable, but honest.
        crate::run_service::RunCreation::SkippedOverlap { running_session_id } => {
            return Err(ApiError::Conflict(format!(
                "skipped: run {running_session_id} is still active (concurrency_policy=skip_if_running)"
            )))
        }
        crate::run_service::RunCreation::ReplaceUnpersisted { running_session_id } => {
            return Err(ApiError::ServiceUnavailable(format!(
                "could not persist cancellation of running session {running_session_id} for replace; retry"
            )))
        }
    };
    Ok(Json(json!({ "session": session })))
}

#[derive(Deserialize)]
pub struct ListQuery {
    #[serde(default = "default_limit")]
    pub limit: i64,
}
fn default_limit() -> i64 {
    50
}

pub async fn list_sessions(
    principal: Principal,
    State(state): State<AppState>,
    Query(q): Query<ListQuery>,
) -> ApiResult<Json<Value>> {
    let scope = principal.scope();
    // A plain member sees only runs it invoked; operator / runs.read_all
    // holders see every run in the tenant. The filter is applied in SQL.
    let invoked_by = if rbac::can_read_all_runs(&principal) {
        None
    } else {
        Some(principal.user_id().unwrap_or_else(Uuid::nil))
    };
    let sessions = fluidbox_db::list_sessions(&state.pool, scope, invoked_by, q.limit).await?;
    Ok(Json(json!({ "sessions": sessions })))
}

pub async fn get_session(
    principal: Principal,
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<Value>> {
    let scope = principal.scope();
    let session = fluidbox_db::get_session(&state.pool, scope, id)
        .await?
        .ok_or(ApiError::NotFound)?;
    rbac::ensure_run_visible(&principal, &session)?;
    let totals = fluidbox_db::usage_totals(&state.pool, scope, id).await?;
    Ok(Json(json!({ "session": session, "usage": totals })))
}

pub async fn cancel_session(
    principal: Principal,
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<Value>> {
    use orchestrator::FinalizeStart;
    // Prove tenant ownership + run visibility before cancelling.
    let session = fluidbox_db::get_session(&state.pool, principal.scope(), id)
        .await?
        .ok_or(ApiError::NotFound)?;
    rbac::ensure_run_visible(&principal, &session)?;
    // The session was just loaded under principal.scope() (ownership proven);
    // thread that scope so the finalizer does not re-resolve the tenant.
    match orchestrator::cancel(&state, principal.scope(), id, "cancelled by user").await {
        FinalizeStart::Persisted { created } => Ok(Json(json!({ "cancelled": created }))),
        FinalizeStart::AlreadyTerminal | FinalizeStart::Missing => {
            Ok(Json(json!({ "cancelled": false })))
        }
        // The intent did not persist — a 200 here would tell the user the
        // run is being cancelled when nothing durable says so.
        FinalizeStart::DbError => Err(ApiError::ServiceUnavailable(
            "cancellation not persisted; retry".into(),
        )),
    }
}

#[derive(Deserialize)]
pub struct EventsQuery {
    #[serde(default)]
    pub after: i64,
    #[serde(default = "default_event_limit")]
    pub limit: i64,
}
fn default_event_limit() -> i64 {
    500
}

pub async fn get_events(
    principal: Principal,
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    Query(q): Query<EventsQuery>,
) -> ApiResult<Json<Value>> {
    let scope = principal.scope();
    let session = fluidbox_db::get_session(&state.pool, scope, id)
        .await?
        .ok_or(ApiError::NotFound)?;
    rbac::ensure_run_visible(&principal, &session)?;
    let events = fluidbox_db::events_after(&state.pool, scope, id, q.after, q.limit).await?;
    Ok(Json(json!({ "events": events })))
}

// ─── Approvals ────────────────────────────────────────────────────────────

pub async fn approvals_inbox(
    principal: Principal,
    State(state): State<AppState>,
) -> ApiResult<Json<Value>> {
    // The org approval queue: only run.read_all holders (operator /
    // approver / admin / owner) see it; a plain member reads its own runs'
    // approvals through the per-session list.
    if !rbac::can_read_all_runs(&principal) {
        return Err(ApiError::Forbidden(
            "the approvals inbox requires approver, admin, or owner".into(),
        ));
    }
    let approvals = fluidbox_db::pending_approvals(&state.pool, principal.scope()).await?;
    Ok(Json(json!({ "approvals": approvals })))
}

pub async fn session_approvals(
    principal: Principal,
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<Value>> {
    let scope = principal.scope();
    let session = fluidbox_db::get_session(&state.pool, scope, id)
        .await?
        .ok_or(ApiError::NotFound)?;
    rbac::ensure_run_visible(&principal, &session)?;
    let approvals = fluidbox_db::session_approvals(&state.pool, scope, id).await?;
    Ok(Json(json!({ "approvals": approvals })))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Decision {
    /// approved_once | approved_session | denied
    pub decision: String,
}

pub async fn decide_approval(
    principal: Principal,
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    Json(req): Json<Decision>,
) -> ApiResult<Json<Value>> {
    let status = match req.decision.as_str() {
        "approved_once" | "approve" | "allow" => "approved_once",
        "approved_session" => "approved_session",
        "denied" | "deny" => "denied",
        other => return Err(ApiError::BadRequest(format!("unknown decision '{other}'"))),
    };
    let scope = principal.scope();
    // Authorization (parent design lines 564-583): decide_org holders may
    // decide any visible approval; a plain member may decide only approvals on
    // a run it invoked (`approval.decide_own`). In Phase B every brokered call
    // carries org authority, so decide_org is the org path.
    let approval = fluidbox_db::get_approval(&state.pool, scope, id)
        .await?
        .ok_or(ApiError::NotFound)?;
    if !rbac::can_decide_org(&principal) {
        let session = fluidbox_db::get_session(&state.pool, scope, approval.session_id)
            .await?
            .ok_or(ApiError::NotFound)?;
        // `approval.decide_own` covers only credentialless calls on a run the
        // member invoked; brokered (`mcp__*`) calls are org authority and need
        // decide_org (parent design lines 564-579).
        if !rbac::can_decide_own(&principal, session.invoked_by_user_id, &approval.tool) {
            return Err(ApiError::Forbidden(
                "deciding this approval requires approver, admin, or owner".into(),
            ));
        }
    }
    // `decided_by` is DERIVED from the authenticated principal — never
    // request-supplied (parent design line 581).
    let decided_by = principal.decided_by();
    let row = fluidbox_db::decide_approval(&state.pool, scope, id, status, &decided_by)
        .await?
        .ok_or_else(|| ApiError::Conflict("approval is not pending".into()))?;
    // Wake the blocked permission handler.
    state.approvals.wake(id).await;
    Ok(Json(json!({ "approval": row })))
}

// ─── Result deliveries ────────────────────────────────────────────────────

pub async fn session_deliveries(
    principal: Principal,
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<Value>> {
    let scope = principal.scope();
    let session = fluidbox_db::get_session(&state.pool, scope, id)
        .await?
        .ok_or(ApiError::NotFound)?;
    rbac::ensure_run_visible(&principal, &session)?;
    let deliveries = fluidbox_db::list_session_deliveries(&state.pool, scope, id).await?;
    Ok(Json(json!({ "deliveries": deliveries })))
}

// ─── Artifacts & cost ─────────────────────────────────────────────────────

pub async fn list_artifacts(
    principal: Principal,
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<Value>> {
    let scope = principal.scope();
    let session = fluidbox_db::get_session(&state.pool, scope, id)
        .await?
        .ok_or(ApiError::NotFound)?;
    rbac::ensure_run_visible(&principal, &session)?;
    let artifacts = fluidbox_db::list_artifacts(&state.pool, scope, id).await?;
    Ok(Json(json!({ "artifacts": artifacts })))
}

pub async fn get_artifact(
    principal: Principal,
    State(state): State<AppState>,
    Path((sid, aid)): Path<(Uuid, Uuid)>,
) -> ApiResult<Json<Value>> {
    let scope = principal.scope();
    let session = fluidbox_db::get_session(&state.pool, scope, sid)
        .await?
        .ok_or(ApiError::NotFound)?;
    rbac::ensure_run_visible(&principal, &session)?;
    let artifact = fluidbox_db::get_artifact(&state.pool, scope, aid)
        .await?
        .ok_or(ApiError::NotFound)?;
    // Scope the artifact to the visible run: a same-tenant artifact from an
    // INVISIBLE run must never be readable through a visible run's id.
    if artifact.session_id != sid {
        return Err(ApiError::NotFound);
    }
    Ok(Json(json!({ "artifact": artifact })))
}

pub async fn get_cost(
    principal: Principal,
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<Value>> {
    let scope = principal.scope();
    let session = fluidbox_db::get_session(&state.pool, scope, id)
        .await?
        .ok_or(ApiError::NotFound)?;
    rbac::ensure_run_visible(&principal, &session)?;
    let totals = fluidbox_db::usage_totals(&state.pool, scope, id).await?;
    let tool_calls = fluidbox_db::tool_call_count(&state.pool, scope, id).await?;
    Ok(Json(json!({ "usage": totals, "tool_calls": tool_calls })))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn same_origin_compares_parsed_origins_not_prefixes() {
        assert!(same_origin(
            "https://github.com/acme/site",
            "https://github.com"
        ));
        // Default ports are equal to elided ones.
        assert!(same_origin(
            "https://github.com:443/x",
            "https://github.com"
        ));
        // Prefix tricks that string checks would wave through.
        assert!(!same_origin(
            "https://github.com.evil.tld/acme/site",
            "https://github.com"
        ));
        assert!(!same_origin("http://github.com/x", "https://github.com"));
        assert!(!same_origin(
            "https://github.com:8443/x",
            "https://github.com"
        ));
        // The e2e file:// clone seam requires PATH containment, not merely
        // a shared scheme.
        assert!(same_origin("file:///tmp/fix/acme/site", "file:///tmp/fix"));
        assert!(same_origin("file:///tmp/fix", "file:///tmp/fix/"));
        assert!(!same_origin("file:///tmp/other/repo", "file:///tmp/fix"));
        assert!(!same_origin("file:///tmp/fixother", "file:///tmp/fix"));
        assert!(!same_origin("file:///tmp/fix", "https://github.com"));
        assert!(!same_origin("not a url", "https://github.com"));
    }

    #[test]
    fn revision_inheritance_re_defaults_on_harness_switch() {
        // Same harness: previous value inherits.
        assert_eq!(
            inherit_unless_switched(None, Some("img:prev"), false, "img:default"),
            "img:prev"
        );
        // Harness switched: the previous harness's value must NOT leak —
        // fall to the new harness's default.
        assert_eq!(
            inherit_unless_switched(None, Some("img:prev"), true, "img:default"),
            "img:default"
        );
        // Explicit always wins, switch or not.
        assert_eq!(
            inherit_unless_switched(Some("img:mine"), Some("img:prev"), true, "img:default"),
            "img:mine"
        );
        assert_eq!(
            inherit_unless_switched(Some("img:mine"), Some("img:prev"), false, "img:default"),
            "img:mine"
        );
        // First revision (no previous): default.
        assert_eq!(
            inherit_unless_switched(None, None, false, "img:default"),
            "img:default"
        );
    }
}
