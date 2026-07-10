//! Public `/v1` API (admin token). The dashboard and CLI talk only to this.

use crate::auth::Admin;
use crate::error::{ApiError, ApiResult};
use crate::orchestrator;
use crate::state::AppState;
use axum::extract::{Path, Query, State};
use axum::Json;
use fluidbox_core::policy::Policy;
use fluidbox_core::spec::{Autonomy, Budgets, CheckoutMode, RunSpec, TrustTier, WorkspaceSpec};
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

fn valid_repo_name(repo: &str) -> bool {
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

async fn resolve_workspace_input(
    state: &AppState,
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
                    let conn = fluidbox_db::get_connection(&state.pool, cid)
                        .await?
                        .filter(|c| c.tenant_id == state.tenant_id)
                        .ok_or_else(|| ApiError::BadRequest(format!("unknown connection {cid}")))?;
                    if conn.status != "active" {
                        return Err(ApiError::BadRequest(format!(
                            "connection {cid} is {} — reconnect it first",
                            conn.status
                        )));
                    }
                    if conn.provider != "github" {
                        return Err(ApiError::BadRequest(format!(
                            "connection provider '{}' does not supply git workspaces",
                            conn.provider
                        )));
                    }
                    match clone_url {
                        // A supplied URL may narrow but not escape the
                        // connection's provider.
                        Some(url) => {
                            if !url.starts_with("https://github.com/") {
                                return Err(ApiError::BadRequest(
                                    "clone_url must be on https://github.com/ for a github connection".into(),
                                ));
                            }
                            url
                        }
                        None => {
                            let repo = repository.as_deref().ok_or_else(|| {
                                ApiError::BadRequest(
                                    "repository (owner/name) or clone_url is required".into(),
                                )
                            })?;
                            format!("https://github.com/{repo}.git")
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
    input: Option<WorkspaceInput>,
) -> ApiResult<Option<Value>> {
    match input {
        None => Ok(None),
        Some(input) => match resolve_workspace_input(state, input).await? {
            WorkspaceSpec::Scratch => Ok(None),
            spec => Ok(Some(serde_json::to_value(&spec)?)),
        },
    }
}

// ─── Health ───────────────────────────────────────────────────────────────

pub async fn health() -> Json<Value> {
    Json(json!({ "status": "ok" }))
}

pub async fn health_ready(State(state): State<AppState>) -> ApiResult<Json<Value>> {
    sqlx::query("select 1").execute(&state.pool).await?;
    let docker_ok = state.provider.ping().await.is_ok();
    Ok(Json(
        json!({ "status": "ready", "db": true, "docker": docker_ok }),
    ))
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
}

pub async fn create_agent(
    _: Admin,
    State(state): State<AppState>,
    Json(req): Json<CreateAgent>,
) -> ApiResult<Json<Value>> {
    let agent = fluidbox_db::create_agent(
        &state.pool,
        state.tenant_id,
        &req.name,
        req.description.as_deref(),
    )
    .await?;

    // Create an initial revision so the agent is immediately runnable.
    let policy_name = req.policy.as_deref().unwrap_or("default");
    let policy = fluidbox_db::get_policy_by_name(&state.pool, state.tenant_id, policy_name)
        .await?
        .ok_or_else(|| ApiError::BadRequest(format!("unknown policy '{policy_name}'")))?;
    let budgets = req.budgets.unwrap_or_default();
    let default_workspace = default_workspace_value(&state, req.default_workspace).await?;
    let rev = fluidbox_db::append_agent_revision(
        &state.pool,
        agent.id,
        req.harness.as_deref().unwrap_or("claude-agent-sdk"),
        req.runner_image
            .as_deref()
            .unwrap_or(&state.cfg.sandbox_image),
        req.model.as_deref().unwrap_or(&state.cfg.default_model),
        req.system_prompt.as_deref(),
        policy.id,
        &serde_json::to_value(&budgets)?,
        default_workspace.as_ref(),
    )
    .await?;

    Ok(Json(json!({ "agent": agent, "revision": rev })))
}

pub async fn list_agents(_: Admin, State(state): State<AppState>) -> ApiResult<Json<Value>> {
    let agents = fluidbox_db::list_agents(&state.pool, state.tenant_id).await?;
    Ok(Json(json!({ "agents": agents })))
}

pub async fn get_agent(
    _: Admin,
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<Value>> {
    let agent = fluidbox_db::get_agent(&state.pool, id)
        .await?
        .ok_or(ApiError::NotFound)?;
    let revisions = fluidbox_db::list_revisions(&state.pool, id).await?;
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
}

pub async fn add_revision(
    _: Admin,
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    Json(req): Json<AddRevision>,
) -> ApiResult<Json<Value>> {
    let agent = fluidbox_db::get_agent(&state.pool, id)
        .await?
        .ok_or(ApiError::NotFound)?;
    let latest = fluidbox_db::latest_revision(&state.pool, id).await?;
    // Inherit from the latest revision unless overridden.
    let policy_name = req.policy.clone();
    let policy_id = match policy_name {
        Some(name) => {
            fluidbox_db::get_policy_by_name(&state.pool, state.tenant_id, &name)
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
        Some(input) => default_workspace_value(&state, Some(input)).await?,
        None => latest.as_ref().and_then(|r| r.default_workspace.clone()),
    };

    let rev = fluidbox_db::append_agent_revision(
        &state.pool,
        agent.id,
        req.harness
            .as_deref()
            .or(latest.as_ref().map(|r| r.harness.as_str()))
            .unwrap_or("claude-agent-sdk"),
        req.runner_image
            .as_deref()
            .or(latest.as_ref().map(|r| r.runner_image.as_str()))
            .unwrap_or(&state.cfg.sandbox_image),
        req.model
            .as_deref()
            .or(latest.as_ref().map(|r| r.model.as_str()))
            .unwrap_or(&state.cfg.default_model),
        req.system_prompt
            .as_deref()
            .or(latest.as_ref().and_then(|r| r.system_prompt.as_deref())),
        policy_id,
        &budgets,
        default_workspace.as_ref(),
    )
    .await?;
    Ok(Json(json!({ "revision": rev })))
}

// ─── Policies ─────────────────────────────────────────────────────────────

pub async fn list_policies(_: Admin, State(state): State<AppState>) -> ApiResult<Json<Value>> {
    let policies = fluidbox_db::list_policies(&state.pool, state.tenant_id).await?;
    Ok(Json(json!({ "policies": policies })))
}

#[derive(Deserialize)]
pub struct UpsertPolicy {
    pub name: String,
    pub yaml: String,
}

pub async fn upsert_policy(
    _: Admin,
    State(state): State<AppState>,
    Json(req): Json<UpsertPolicy>,
) -> ApiResult<Json<Value>> {
    let policy = Policy::parse_yaml(&req.yaml).map_err(ApiError::UnprocessableEntity)?;
    if policy.name != req.name {
        return Err(ApiError::BadRequest(
            "policy name must match yaml `name`".into(),
        ));
    }
    let parsed = serde_json::to_value(&policy)?;
    let row =
        fluidbox_db::upsert_policy(&state.pool, state.tenant_id, &req.name, &req.yaml, &parsed)
            .await?;
    Ok(Json(json!({ "policy": row })))
}

#[derive(Deserialize)]
pub struct ValidatePolicy {
    pub yaml: String,
}

pub async fn validate_policy(_: Admin, Json(req): Json<ValidatePolicy>) -> ApiResult<Json<Value>> {
    match Policy::parse_yaml(&req.yaml) {
        Ok(p) => Ok(Json(json!({ "valid": true, "name": p.name }))),
        Err(e) => Err(ApiError::UnprocessableEntity(e)),
    }
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
}

pub async fn create_session(
    _: Admin,
    State(state): State<AppState>,
    Json(req): Json<CreateSession>,
) -> ApiResult<Json<Value>> {
    // Resolve agent by id or name.
    let agent = match Uuid::parse_str(&req.agent) {
        Ok(id) => fluidbox_db::get_agent(&state.pool, id).await?,
        Err(_) => fluidbox_db::get_agent_by_name(&state.pool, state.tenant_id, &req.agent).await?,
    }
    .ok_or_else(|| ApiError::BadRequest(format!("unknown agent '{}'", req.agent)))?;

    let rev = fluidbox_db::latest_revision(&state.pool, agent.id)
        .await?
        .ok_or_else(|| ApiError::BadRequest("agent has no revisions".into()))?;
    let policy_row = fluidbox_db::get_policy(&state.pool, rev.policy_id)
        .await?
        .ok_or_else(|| ApiError::Internal("revision policy missing".into()))?;
    let policy: Policy = serde_json::from_value(policy_row.parsed.clone())
        .map_err(|e| ApiError::Internal(format!("bad stored policy: {e}")))?;

    let autonomy = if req.autonomous {
        Autonomy::Autonomous
    } else {
        Autonomy::Supervised
    };

    // Autonomy permission gate: a policy may forbid autonomous runs.
    if autonomy == Autonomy::Autonomous && !policy.autonomy.permitted {
        return Err(ApiError::BadRequest(
            "policy does not permit autonomous runs".into(),
        ));
    }

    let agent_budgets: Budgets = serde_json::from_value(rev.budgets.clone()).unwrap_or_default();
    // The policy's budgets are a ceiling: revision defaults and per-run
    // requests may only tighten below them, never widen past them.
    let ceiling = agent_budgets.tightened_by(&policy.budgets);
    let effective_budgets = match &req.budgets {
        Some(b) => ceiling.tightened_by(b),
        None => ceiling,
    };

    // Workspace resolution (design §3.3): explicit invocation workspace
    // > agent revision default > scratch. Validation happens on the explicit
    // input; the stored default was validated when the revision was created.
    let explicit_input = match (req.workspace, req.repo) {
        (Some(_), Some(_)) => {
            return Err(ApiError::BadRequest(
                "provide either `workspace` or legacy `repo`, not both".into(),
            ))
        }
        (w, r) => w.or(r),
    };
    let explicit = match explicit_input {
        Some(input) => Some(resolve_workspace_input(&state, input).await?),
        None => None,
    };
    let revision_default: Option<WorkspaceSpec> = rev
        .default_workspace
        .as_ref()
        .map(|v| serde_json::from_value(v.clone()))
        .transpose()
        .map_err(|e| ApiError::Internal(format!("bad stored default workspace: {e}")))?;
    let workspace = WorkspaceSpec::resolve(explicit, revision_default);

    // A connection-backed workspace must still be usable at run time (the
    // connection may have been revoked since the default was stored).
    if let WorkspaceSpec::GitRepository {
        connection_id: Some(cid),
        ..
    } = &workspace
    {
        let active = fluidbox_db::get_connection(&state.pool, *cid)
            .await?
            .filter(|c| c.tenant_id == state.tenant_id)
            .map(|c| c.status == "active")
            .unwrap_or(false);
        if !active {
            return Err(ApiError::BadRequest(format!(
                "workspace connection {cid} is not active — reconnect it or override the workspace"
            )));
        }
    }

    let run_spec = RunSpec {
        agent_id: agent.id,
        agent_revision_id: rev.id,
        agent_name: agent.name.clone(),
        harness: rev.harness.clone(),
        runner_image: rev.runner_image.clone(),
        model: rev.model.clone(),
        system_prompt: rev.system_prompt.clone(),
        task: req.task.clone(),
        workspace: workspace.clone(),
        autonomy,
        trust_tier: TrustTier::Trusted,
        budgets: effective_budgets.clone(),
        policy_id: policy_row.id,
        policy_version: policy_row.version,
        policy_snapshot: policy,
    };

    let session = fluidbox_db::create_session(
        &state.pool,
        state.tenant_id,
        agent.id,
        rev.id,
        autonomy.as_str(),
        &req.task,
        &serde_json::to_value(&workspace)?,
        &serde_json::to_value(&run_spec)?,
        &serde_json::to_value(&effective_budgets)?,
    )
    .await?;

    crate::ledger::record(
        &state,
        session.id,
        fluidbox_core::event::Actor::System,
        fluidbox_core::event::EventBody::SessionCreated {
            task: req.task.clone(),
            agent: agent.name.clone(),
            autonomy: autonomy.as_str().into(),
        },
    )
    .await;

    // Kick off the run.
    orchestrator::spawn_run(state.clone(), session.id);

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
    _: Admin,
    State(state): State<AppState>,
    Query(q): Query<ListQuery>,
) -> ApiResult<Json<Value>> {
    let sessions = fluidbox_db::list_sessions(&state.pool, state.tenant_id, q.limit).await?;
    Ok(Json(json!({ "sessions": sessions })))
}

pub async fn get_session(
    _: Admin,
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<Value>> {
    let session = fluidbox_db::get_session(&state.pool, id)
        .await?
        .ok_or(ApiError::NotFound)?;
    let totals = fluidbox_db::usage_totals(&state.pool, id).await?;
    Ok(Json(json!({ "session": session, "usage": totals })))
}

pub async fn cancel_session(
    _: Admin,
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<Value>> {
    let ok = orchestrator::cancel(&state, id).await;
    Ok(Json(json!({ "cancelled": ok })))
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
    _: Admin,
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    Query(q): Query<EventsQuery>,
) -> ApiResult<Json<Value>> {
    let events = fluidbox_db::events_after(&state.pool, id, q.after, q.limit).await?;
    Ok(Json(json!({ "events": events })))
}

// ─── Approvals ────────────────────────────────────────────────────────────

pub async fn approvals_inbox(_: Admin, State(state): State<AppState>) -> ApiResult<Json<Value>> {
    let approvals = fluidbox_db::pending_approvals(&state.pool).await?;
    Ok(Json(json!({ "approvals": approvals })))
}

pub async fn session_approvals(
    _: Admin,
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<Value>> {
    let approvals = fluidbox_db::session_approvals(&state.pool, id).await?;
    Ok(Json(json!({ "approvals": approvals })))
}

#[derive(Deserialize)]
pub struct Decision {
    /// approved_once | approved_session | denied
    pub decision: String,
    #[serde(default)]
    pub decided_by: Option<String>,
}

pub async fn decide_approval(
    _: Admin,
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
    let decided_by = req.decided_by.unwrap_or_else(|| "operator".into());
    let row = fluidbox_db::decide_approval(&state.pool, id, status, &decided_by)
        .await?
        .ok_or_else(|| ApiError::Conflict("approval is not pending".into()))?;
    // Wake the blocked permission handler.
    state.approvals.wake(id).await;
    Ok(Json(json!({ "approval": row })))
}

// ─── Artifacts & cost ─────────────────────────────────────────────────────

pub async fn list_artifacts(
    _: Admin,
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<Value>> {
    let artifacts = fluidbox_db::list_artifacts(&state.pool, id).await?;
    Ok(Json(json!({ "artifacts": artifacts })))
}

pub async fn get_artifact(
    _: Admin,
    State(state): State<AppState>,
    Path((_sid, aid)): Path<(Uuid, Uuid)>,
) -> ApiResult<Json<Value>> {
    let artifact = fluidbox_db::get_artifact(&state.pool, aid)
        .await?
        .ok_or(ApiError::NotFound)?;
    Ok(Json(json!({ "artifact": artifact })))
}

pub async fn get_cost(
    _: Admin,
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<Value>> {
    let totals = fluidbox_db::usage_totals(&state.pool, id).await?;
    let tool_calls = fluidbox_db::tool_call_count(&state.pool, id).await?;
    Ok(Json(json!({ "usage": totals, "tool_calls": tool_calls })))
}
