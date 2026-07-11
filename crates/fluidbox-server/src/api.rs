//! Public `/v1` API (admin token). The dashboard and CLI talk only to this.

use crate::auth::Admin;
use crate::error::{ApiError, ApiResult};
use crate::orchestrator;
use crate::state::AppState;
use axum::extract::{Path, Query, State};
use axum::Json;
use fluidbox_core::policy::Policy;
use fluidbox_core::spec::{
    Autonomy, Budgets, CheckoutMode, InvocationContext, InvocationKind, WorkspaceSpec,
};
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

// ─── Capability attachment (§17 #7: pin-only) ─────────────────────────────

/// Resolve `"name"` / `"name@version"` refs into exact pins. A bare name
/// pins the newest version AT ATTACH TIME — nothing floats afterwards;
/// upgrading a bundle means appending a new agent revision. Server-alias
/// collisions across the attached set are refused here so the run-time
/// intersection can never materialize a shadowed tool.
pub(crate) async fn resolve_bundle_pins(state: &AppState, specs: &[String]) -> ApiResult<Value> {
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
                fluidbox_db::get_capability_bundle_version(&state.pool, state.tenant_id, name, v)
                    .await?
            }
            None => {
                fluidbox_db::latest_capability_bundle(&state.pool, state.tenant_id, name).await?
            }
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
    /// Capability bundles to attach: "name" (pins the newest version now)
    /// or "name@version" (§17 #7 pin-only).
    #[serde(default)]
    pub capability_bundles: Option<Vec<String>>,
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
    let capability_pins = match &req.capability_bundles {
        Some(specs) => resolve_bundle_pins(&state, specs).await?,
        None => json!([]),
    };
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
        &capability_pins,
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
    /// Omitted → inherit the latest revision's pins. An explicit `[]`
    /// clears them; entries re-resolve ("name" pins the newest version NOW
    /// — this is how a bundle upgrade lands: append a revision, §17 #7).
    #[serde(default)]
    pub capability_bundles: Option<Vec<String>>,
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
    // Omitted → inherit the previous pins verbatim; explicit list (incl.
    // []) re-resolves — the §17 #7 upgrade path.
    let capability_pins = match &req.capability_bundles {
        Some(specs) => resolve_bundle_pins(&state, specs).await?,
        None => latest
            .as_ref()
            .map(|r| r.capability_bundles.clone())
            .unwrap_or_else(|| json!([])),
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
        &capability_pins,
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
    /// Optional per-run capability narrowing: a keep-list of bundle names
    /// intersected with the revision's attachments (remove-only, §3.5).
    #[serde(default)]
    pub capabilities: Option<Vec<String>>,
}

pub async fn create_session(
    _: Admin,
    State(state): State<AppState>,
    Json(req): Json<CreateSession>,
) -> ApiResult<Json<Value>> {
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
    let autonomy = if req.autonomous {
        Autonomy::Autonomous
    } else {
        Autonomy::Supervised
    };
    let created = crate::run_service::create_run(
        &state,
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
                actor: Some("operator".into()),
                attributes: Value::Null,
                received_at: Some(chrono::Utc::now()),
                ..Default::default()
            },
            result_destinations: vec![],
            bound_invocation: None,
            bound_dispatch: None,
        },
    )
    .await?;
    let session = match created {
        crate::run_service::RunCreation::Created(s) => *s,
        // Manual runs carry no subscription — unreachable, but honest.
        crate::run_service::RunCreation::SkippedOverlap { running_session_id } => {
            return Err(ApiError::Conflict(format!(
                "skipped: run {running_session_id} is still active (concurrency_policy=skip_if_running)"
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
    let ok = orchestrator::cancel(&state, id, "cancelled by user").await;
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

// ─── Result deliveries ────────────────────────────────────────────────────

pub async fn session_deliveries(
    _: Admin,
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<Value>> {
    let deliveries = fluidbox_db::list_session_deliveries(&state.pool, id).await?;
    Ok(Json(json!({ "deliveries": deliveries })))
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
}
