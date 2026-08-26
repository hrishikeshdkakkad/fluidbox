//! Public `/v1` API (admin token). The dashboard and CLI talk only to this.

use crate::auth::Principal;
use crate::error::{ApiError, ApiResult};
use crate::harness;
use crate::orchestrator;
use crate::rbac;
use crate::state::AppState;
use axum::extract::{Path, Query, State};
use axum::Json;
use fluidbox_core::capability::{validate_requirements, ConnectionRequirement};
use fluidbox_core::policy::Policy;
use fluidbox_core::spec::{
    Autonomy, Budgets, CheckoutMode, InvocationContext, InvocationKind, WorkspaceSpec,
};
use fluidbox_db::{ConnectionViewer, TenantScope};
use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::HashMap;
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

/// Whether the caller may name a HOST FILESYSTEM PATH as a workspace
/// (`WorkspaceInput::LocalCopy`). `LocalCopy` copies an arbitrary control-plane
/// path into the run's `/workspace`, so it is host-filesystem read access with
/// no root, no canonicalization and no tenant meaning — `/var/run/secrets/…`,
/// another tenant's materialized workspace, the data dir, anything the server
/// process can read.
///
/// It is therefore OPERATOR-ONLY. That matches the local/single-admin model it
/// was built for (`FLUIDBOX_REQUIRE_SSO` off ⇒ the admin token IS the operator,
/// so the CLI/e2e are unaffected), and closes it under multi-user, where
/// `POST /v1/sessions` accepts ANY authenticated principal — a plain member or a
/// PAT could otherwise exfiltrate host files into an agent. Stale comments
/// elsewhere in this file called the workspace API "admin-token-gated"; it has
/// not been since Phase B, and this enum is now the enforcement.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LocalPathAuthority {
    /// The principal is an Operator (admin token).
    Operator,
    /// Anyone else — a `LocalCopy` input is refused.
    Denied,
}

impl LocalPathAuthority {
    pub(crate) fn of(principal: &Principal) -> Self {
        match principal {
            Principal::Operator { .. } => LocalPathAuthority::Operator,
            Principal::User(_) => LocalPathAuthority::Denied,
        }
    }
}

pub(crate) async fn resolve_workspace_input(
    state: &AppState,
    scope: TenantScope,
    viewer: ConnectionViewer,
    local: LocalPathAuthority,
    input: WorkspaceInput,
) -> ApiResult<WorkspaceSpec> {
    Ok(match input {
        WorkspaceInput::Scratch => WorkspaceSpec::Scratch,
        WorkspaceInput::LocalCopy { path } => {
            if local != LocalPathAuthority::Operator {
                return Err(ApiError::Forbidden(
                    "a local_copy workspace names a control-plane host path and is \
                     restricted to the operator (admin token)"
                        .into(),
                ));
            }
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
                    // Visibility-filtered read (invariant 21): a user naming
                    // another user's personal connection resolves to None here —
                    // the SAME "unknown connection" as a truly missing id, so
                    // existence is not leaked. The credentialed AUTHORITY (owner,
                    // generation, membership) is frozen by binding resolution in
                    // create_run and rechecked by every consumer (Task 6).
                    let conn = fluidbox_db::get_connection_visible(&state.pool, scope, cid, viewer)
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
                    // Unauthenticated clone (public repo, or file:// in dev).
                    // NOTE: this API is NOT admin-token-gated — any authenticated
                    // principal reaches it (see `LocalPathAuthority`); an
                    // unauthenticated clone URL is still admitted because it
                    // carries no credential and goes through the egress policy.
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
                // Resolved by create_run's binding service (Task 5), never from
                // user input (invariant 21).
                binding_id: None,
                repository,
                clone_url,
                r#ref,
                commit_sha,
                checkout_mode: checkout_mode.unwrap_or_default(),
            }
        }
    })
}

/// A revision default of Scratch means "no default" — store nothing. Revision
/// defaults are set by an admin/owner mutation, so the operator lens (`All`)
/// applies; the per-run authority is re-resolved with the invoker's lens.
async fn default_workspace_value(
    state: &AppState,
    scope: TenantScope,
    local: LocalPathAuthority,
    input: Option<WorkspaceInput>,
) -> ApiResult<Option<Value>> {
    match input {
        None => Ok(None),
        Some(input) => {
            match resolve_workspace_input(state, scope, ConnectionViewer::All, local, input).await?
            {
                WorkspaceSpec::Scratch => Ok(None),
                spec => Ok(Some(serde_json::to_value(&spec)?)),
            }
        }
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
    /// Brokered connection requirements the agent declares (design §"Agent
    /// connection requirement"): what it needs, never whose credential. Stored
    /// (validated) on the initial revision; resolved per-run into bindings.
    #[serde(default)]
    pub connection_requirements: Option<Vec<ConnectionRequirement>>,
    /// The sandbox network the agent DECLARES it needs. Policy caps it and a
    /// per-run override may only narrow it; omitted means offline.
    #[serde(default)]
    pub network: Option<fluidbox_core::network::NetworkRequest>,
}

/// Validate a revision's declared network request into stored jsonb. Validation
/// happens HERE, at authoring, so a target that could never be lowered to a
/// datapath rule is a 422 on the agent — not a refusal on every run that agent
/// ever attempts.
fn network_json(req: Option<&fluidbox_core::network::NetworkRequest>) -> ApiResult<Option<Value>> {
    match req {
        Some(r) => {
            r.validate().map_err(|e| {
                ApiError::UnprocessableEntity(format!("invalid network declaration: {e}"))
            })?;
            Ok(Some(serde_json::to_value(r)?))
        }
        None => Ok(None),
    }
}

/// Validate a revision's declared connection requirements into stored jsonb
/// (or `[]`). A malformed list is a 422 before anything persists.
fn requirements_json(reqs: Option<&Vec<ConnectionRequirement>>) -> ApiResult<Value> {
    match reqs {
        Some(reqs) => {
            validate_requirements(reqs).map_err(|e| {
                ApiError::UnprocessableEntity(format!("invalid connection requirements: {e}"))
            })?;
            Ok(serde_json::to_value(reqs)?)
        }
        None => Ok(json!([])),
    }
}

/// Validate a harness id and return its (runner image, model) defaults.
/// Unknown ids are a 422 — refused before anything persists.
fn harness_defaults<'a>(
    harness_id: &str,
    cfg: &'a crate::config::Config,
) -> Result<(&'a str, &'a str), ApiError> {
    if !harness::is_known(harness_id) {
        return Err(ApiError::UnprocessableEntity(format!(
            "unknown harness '{harness_id}' (known: {})",
            harness::KNOWN.join(", ")
        )));
    }
    // The inherited default must be one the deployment SERVES: an agent
    // created without an explicit model must not inherit a default the tenant
    // key will 403 at its first model call.
    match (
        harness::default_runner_image(harness_id, cfg),
        harness::servable_default_model(harness_id, cfg),
    ) {
        (Some(image), Some(model)) => Ok((image, model)),
        _ => {
            let known: Vec<&str> = harness::models(harness_id).iter().map(|m| m.id).collect();
            Err(ApiError::UnprocessableEntity(format!(
                "harness '{harness_id}' has no model this deployment serves (its models: {}); \
                 widen llm.tenant.models and rotate the tenant key to enable it",
                known.join(", ")
            )))
        }
    }
}

/// Reject an EXPLICIT model that doesn't belong to the harness — a clean 422
/// before anything persists, instead of a murky failure at the first model
/// call. Inherited/default models are trusted (a shipped default is always a
/// member of its list, pinned by a harness unit test).
fn validate_model(
    cfg: &crate::config::Config,
    harness_id: &str,
    model: &str,
) -> Result<(), ApiError> {
    if !harness::model_belongs(harness_id, model) {
        let valid: Vec<&str> = harness::models(harness_id).iter().map(|m| m.id).collect();
        return Err(ApiError::UnprocessableEntity(format!(
            "model '{model}' is not valid for harness '{harness_id}' (valid: {})",
            valid.join(", ")
        )));
    }
    // Valid for the harness, but can THIS deployment serve it? In tenant key
    // mode the answer is the allowlist the tenant's LiteLLM key was minted
    // with; refusing here is a 422 before anything persists, instead of a 403
    // at the first model call of an already-provisioned run.
    if !harness::is_servable(cfg, model) {
        let served: Vec<&str> = harness::servable_models(harness_id, cfg)
            .iter()
            .map(|m| m.id)
            .collect();
        return Err(ApiError::UnprocessableEntity(format!(
            "model '{model}' is valid for harness '{harness_id}' but this deployment's LLM \
             gateway does not serve it (served: {}); widen llm.tenant.models and rotate \
             the tenant key to enable it",
            if served.is_empty() {
                "none".to_string()
            } else {
                served.join(", ")
            }
        )));
    }
    Ok(())
}

/// The deployment's RESOLVED network posture, asked of the provider rather
/// than read from config — config says what was requested, the provider says
/// what is true.
fn harnesses_network_block(enforcer: &dyn fluidbox_core::traits::NetworkPolicyProvider) -> Value {
    json!({
        "enforcer": enforcer.enforcer_name(),
        "supports_egress_grants": enforcer.supports_egress_grants(),
    })
}

/// `GET /v1/harnesses` — the supported harness + model catalog. The SINGLE
/// source of truth for the dashboard's harness/model pickers (the frontend no
/// longer hardcodes model lists).
pub async fn list_harnesses(
    _principal: Principal,
    State(state): State<AppState>,
) -> ApiResult<Json<Value>> {
    // What the facade can SERVE, not what the harness knows: in tenant key
    // mode the per-tenant LiteLLM key carries a model allowlist, and a model
    // outside it is a 403 at the first model call — after the sandbox was
    // provisioned. The catalog is where that gets caught instead. A harness
    // with no servable model is reported unavailable, and the dashboard hides
    // it rather than offering a run that cannot start.
    let harnesses: Vec<Value> = harness::KNOWN
        .iter()
        .map(|&id| {
            let models = harness::servable_models(id, &state.cfg);
            json!({
                "id": id,
                "display_name": harness::display_name(id),
                "hint": harness::hint(id),
                "available": !models.is_empty(),
                "default_model": harness::servable_default_model(id, &state.cfg),
                "models": models
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
    Ok(Json(json!({
        "harnesses": harnesses,
        "network": harnesses_network_block(state.provider.network_enforcer()),
    })))
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
        validate_model(&state.cfg, harness_id, m)?;
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
    let default_workspace = default_workspace_value(
        &state,
        scope,
        LocalPathAuthority::of(&principal),
        req.default_workspace,
    )
    .await?;
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
        &requirements_json(req.connection_requirements.as_ref())?,
        network_json(req.network.as_ref())?.as_ref(),
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
    /// Omitted → inherit the latest revision's requirements. An explicit `[]`
    /// clears them; a list is validated + stored (append-only, like the pins).
    #[serde(default)]
    pub connection_requirements: Option<Vec<ConnectionRequirement>>,
    /// Omitted → inherit the latest revision's declaration; an explicit
    /// `{"mode":"offline"}` clears it. Append-only, like the pins.
    #[serde(default)]
    pub network: Option<fluidbox_core::network::NetworkRequest>,
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
        validate_model(&state.cfg, harness_id, m)?;
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
        Some(input) => {
            default_workspace_value(
                &state,
                scope,
                LocalPathAuthority::of(&principal),
                Some(input),
            )
            .await?
        }
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
    // Omitted → inherit the previous requirements verbatim; explicit list (incl.
    // []) is validated + re-stored (append-only on the revision).
    let requirements = match &req.connection_requirements {
        Some(_) => requirements_json(req.connection_requirements.as_ref())?,
        None => latest
            .as_ref()
            .map(|r| r.connection_requirements.clone())
            .unwrap_or_else(|| json!([])),
    };
    // Same inheritance rule as the pins: omitted keeps what the previous
    // revision declared, so appending a revision for an unrelated reason never
    // silently drops the agent's network declaration.
    let network = match &req.network {
        Some(_) => network_json(req.network.as_ref())?,
        None => latest.as_ref().and_then(|r| r.network.clone()),
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
        &requirements,
        network.as_ref(),
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
        // `version` is the LATEST version number (design §4.6: unchanged wire
        // shape, new source of truth). A version-less policy is a bug state;
        // surfacing `version: 0` with no summary beats hiding the row.
        let autonomy_summary = match &row.latest_content {
            Some(content) => {
                let policy: Policy = serde_json::from_value(content.clone())
                    .map_err(|e| ApiError::Internal(format!("bad stored policy: {e}")))?;
                serde_json::to_value(policy.autonomy_summary())?
            }
            None => Value::Null,
        };
        let agents_using = fluidbox_db::policy_agents_using(&state.pool, scope, row.id).await?;
        out.push(json!({
            "id": row.id,
            "name": row.name,
            "version": row.latest_version,
            "updated_at": row.updated_at,
            "autonomy_summary": autonomy_summary,
            "agents_using": agents_using,
        }));
    }
    Ok(Json(json!({ "policies": out })))
}

/// Resolve a policy's LATEST version or fail closed — a policy with zero
/// versions is a bug, not a state (design §4.2), and every read/append path
/// says so the same way.
async fn require_latest_version(
    state: &AppState,
    scope: TenantScope,
    row: &fluidbox_db::PolicyRow,
) -> ApiResult<fluidbox_db::PolicyVersionRow> {
    fluidbox_db::latest_policy_version(&state.pool, scope, row.id)
        .await?
        .ok_or_else(|| ApiError::Internal(format!("policy '{}' has no versions", row.name)))
}

/// The Governance page's detail payload. The dashboard renders this verbatim —
/// it never parses YAML and never resolves policy semantics. `content` is the
/// editor's input (the latest version's canonical document); `versions` is the
/// history metadata (content fetched per version via the versions route).
pub async fn get_policy(
    principal: Principal,
    State(state): State<AppState>,
    Path(name): Path<String>,
) -> ApiResult<Json<Value>> {
    let scope = principal.scope();
    let row = fluidbox_db::get_policy_by_name(&state.pool, scope, &name)
        .await?
        .ok_or(ApiError::NotFound)?;
    let latest = require_latest_version(&state, scope, &row).await?;
    let policy: Policy = serde_json::from_value(latest.content.clone())
        .map_err(|e| ApiError::Internal(format!("bad stored policy: {e}")))?;

    let mut names: Vec<String> = fluidbox_core::tools::CANONICAL
        .iter()
        .map(|t| t.name.to_string())
        .collect();
    names.extend(fluidbox_db::policy_mcp_tools(&state.pool, scope, row.id).await?);
    let matrix = matrix_payload(&policy, &names);

    let versions: Vec<Value> = fluidbox_db::list_policy_versions(&state.pool, scope, row.id)
        .await?
        .into_iter()
        .map(version_meta)
        .collect();

    Ok(Json(json!({
        "policy": {
            "id": row.id,
            "name": row.name,
            "version": latest.version,
            "updated_at": row.updated_at,
        },
        "content": latest.content,
        "versions": versions,
        "agents_using": fluidbox_db::policy_agents_using(&state.pool, scope, row.id).await?,
        "autonomy_summary": policy.autonomy_summary(),
        "defaults": policy.defaults,
        "budgets": policy.budgets,
        "approvals": policy.approvals,
        "egress": policy.egress,
        "matrix": matrix,
    })))
}

/// The resolved permission matrix rows, exactly as the dashboard renders them
/// — shared by the detail payload and the draft preview so the two can never
/// disagree about how a verdict is presented.
fn matrix_payload(policy: &Policy, names: &[String]) -> Vec<Value> {
    policy
        .tool_matrix(names)
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
                "status": status,
            })
        })
        .collect()
}

/// One version's metadata — never its content (the versions route serves that).
fn version_meta(v: fluidbox_db::PolicyVersionRow) -> Value {
    json!({
        "version": v.version,
        "author": v.author,
        "author_user_id": v.author_user_id,
        "summary": v.summary,
        "created_at": v.created_at,
    })
}

/// `GET /v1/policies/{name}/versions/{version}` — one immutable version, for
/// diff, revert preview, and export. `yaml` is the stored source when the
/// version arrived as YAML, else generated from the canonical content.
pub async fn get_policy_version(
    principal: Principal,
    State(state): State<AppState>,
    Path((name, version)): Path<(String, i32)>,
) -> ApiResult<Json<Value>> {
    let scope = principal.scope();
    let row = fluidbox_db::get_policy_by_name(&state.pool, scope, &name)
        .await?
        .ok_or(ApiError::NotFound)?;
    let v = fluidbox_db::get_policy_version(&state.pool, scope, row.id, version)
        .await?
        .ok_or(ApiError::NotFound)?;
    let yaml = match &v.yaml_source {
        Some(y) => y.clone(),
        None => {
            let policy: Policy = serde_json::from_value(v.content.clone())
                .map_err(|e| ApiError::Internal(format!("bad stored policy: {e}")))?;
            serde_yaml::to_string(&policy)
                .map_err(|e| ApiError::Internal(format!("yaml export failed: {e}")))?
        }
    };
    Ok(Json(json!({
        "policy": { "id": row.id, "name": row.name },
        "version": version_meta(v.clone()),
        "content": v.content,
        "yaml": yaml,
    })))
}

#[derive(Deserialize)]
pub struct UpsertPolicy {
    pub name: String,
    pub yaml: String,
}

/// `POST /v1/policies` — the YAML IMPORT path (design §4.5): the wire shape
/// `scripts/policy-sync.sh` used to POST, kept because the e2e depends on it.
/// It now APPENDS a version (author 'api') rather than force-overwriting —
/// which is exactly why the sync script could retire.
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
    // Strict: a typo'd key in an imported yaml must refuse, never silently
    // weaken the policy it describes (the same posture as publish).
    let policy = Policy::parse_yaml_strict(&req.yaml).map_err(ApiError::UnprocessableEntity)?;
    if policy.name != req.name {
        return Err(ApiError::BadRequest(
            "policy name must match yaml `name`".into(),
        ));
    }
    reject_reserved_name(&req.name)?;
    let scope = principal.scope();
    let parsed = serde_json::to_value(&policy)?;
    let (row, version, appended) = fluidbox_db::import_policy_yaml(
        &state.pool,
        scope,
        &req.name,
        &req.yaml,
        &parsed,
        principal.user_id(),
    )
    .await?;
    Ok(Json(json!({ "policy": {
        "id": row.id,
        "name": row.name,
        "version": version.version,
        "updated_at": row.updated_at,
    }, "appended": appended })))
}

#[derive(Deserialize)]
pub struct ValidatePolicy {
    pub yaml: String,
}

pub async fn validate_policy(
    _principal: Principal,
    Json(req): Json<ValidatePolicy>,
) -> ApiResult<Json<Value>> {
    match Policy::parse_yaml_strict(&req.yaml) {
        Ok(p) => Ok(Json(json!({ "valid": true, "name": p.name }))),
        Err(e) => Err(ApiError::UnprocessableEntity(e)),
    }
}

#[derive(Deserialize)]
pub struct PublishPolicy {
    /// The whole draft, as structure. The server validates; the browser never
    /// resolves a verdict (design §4.4).
    pub content: Value,
    /// The review beat (design §3): what changed and why. Required, non-blank.
    pub summary: String,
    /// The head version this draft was loaded from — optimistic concurrency.
    /// A publish over a moved head is a 409, never a silent overwrite of the
    /// other editor's intent; a post-commit retry of one's own publish lands
    /// on the same 409, which is what makes the write safe to retry.
    pub base_version: i32,
}

/// Map an optimistic append to its response or its 409.
fn appended_or_conflict(
    out: fluidbox_db::AppendPolicyVersion,
    base_version: i32,
) -> Result<fluidbox_db::PolicyVersionRow, ApiError> {
    match out {
        fluidbox_db::AppendPolicyVersion::Appended(v) => Ok(v),
        fluidbox_db::AppendPolicyVersion::Stale { head } => Err(ApiError::Conflict(format!(
            "the policy moved to v{head} since this draft loaded v{base_version} — reload, \
             re-apply your edit, and publish again"
        ))),
    }
}

/// The publish/revert summary is the review beat — bound it, and refuse blank.
fn validate_summary(summary: &str) -> Result<(), ApiError> {
    let trimmed = summary.trim();
    if trimmed.is_empty() {
        return Err(ApiError::BadRequest(
            "a publish needs a non-empty summary — say what changed and why".into(),
        ));
    }
    if trimmed.len() > 500 {
        return Err(ApiError::BadRequest(
            "summary is limited to 500 characters".into(),
        ));
    }
    Ok(())
}

/// `POST /v1/policies/{name}/publish` — mint ONE immutable version from a
/// draft. The draft parses STRICTLY (`Policy::parse_strict`: an unknown field
/// at any level is a 422, never a silently-dropped key publishing a weaker
/// policy than its author reviewed), and the stored content is the
/// re-serialized canonical struct.
pub async fn publish_policy(
    principal: Principal,
    State(state): State<AppState>,
    Path(name): Path<String>,
    Json(req): Json<PublishPolicy>,
) -> ApiResult<Json<Value>> {
    if !rbac::can_mutate_resources(&principal) {
        return Err(ApiError::Forbidden(
            "editing policies requires admin or owner".into(),
        ));
    }
    validate_summary(&req.summary)?;
    let scope = principal.scope();
    let row = fluidbox_db::get_policy_by_name(&state.pool, scope, &name)
        .await?
        .ok_or(ApiError::NotFound)?;
    let policy = Policy::parse_strict(req.content)
        .map_err(|e| ApiError::UnprocessableEntity(format!("bad policy content: {e}")))?;
    if policy.name != name {
        return Err(ApiError::BadRequest(
            "policy content `name` must match the path".into(),
        ));
    }
    let content = serde_json::to_value(&policy)?;
    let version = appended_or_conflict(
        fluidbox_db::append_policy_version(
            &state.pool,
            scope,
            row.id,
            Some(req.base_version),
            fluidbox_db::NewPolicyVersion {
                content: &content,
                yaml_source: None,
                summary: Some(req.summary.trim()),
                author: "ui",
                author_user_id: principal.user_id(),
            },
        )
        .await?,
        req.base_version,
    )?;
    Ok(Json(json!({ "policy": {
        "id": row.id,
        "name": row.name,
        "version": version.version,
    }})))
}

#[derive(Deserialize)]
pub struct RevertPolicy {
    pub version: i32,
    /// Same optimistic guard as publish: the head the reverter was looking at.
    pub base_version: i32,
}

/// `POST /v1/policies/{name}/revert` — publish an OLD version's content
/// forward as a NEW version. History is never mutated: the reverted-over
/// versions stay readable (design §3, "revert publishes forward").
pub async fn revert_policy(
    principal: Principal,
    State(state): State<AppState>,
    Path(name): Path<String>,
    Json(req): Json<RevertPolicy>,
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
    let target = fluidbox_db::get_policy_version(&state.pool, scope, row.id, req.version)
        .await?
        .ok_or(ApiError::NotFound)?;
    let summary = format!("revert to v{}", target.version);
    let version = appended_or_conflict(
        fluidbox_db::append_policy_version(
            &state.pool,
            scope,
            row.id,
            Some(req.base_version),
            fluidbox_db::NewPolicyVersion {
                content: &target.content,
                yaml_source: target.yaml_source.as_deref(),
                summary: Some(&summary),
                author: "ui",
                author_user_id: principal.user_id(),
            },
        )
        .await?,
        req.base_version,
    )?;
    Ok(Json(json!({ "policy": {
        "id": row.id,
        "name": row.name,
        "version": version.version,
    }})))
}

#[derive(Deserialize)]
pub struct PreviewPolicy {
    pub content: Value,
    /// Resolving an EXISTING policy's name folds its agents' mcp__* roster
    /// into the matrix names; a brand-new draft previews canonical tools only.
    #[serde(default)]
    pub name: Option<String>,
}

/// `POST /v1/policies/preview` — validate a draft and resolve its matrix +
/// autonomy summary SERVER-SIDE. This is what keeps the editor presentation-
/// only while a draft diverges from the stored policy: the browser posts
/// structure, the policy engine answers, nothing is derived in TypeScript.
pub async fn preview_policy(
    principal: Principal,
    State(state): State<AppState>,
    Json(req): Json<PreviewPolicy>,
) -> ApiResult<Json<Value>> {
    let scope = principal.scope();
    let policy = Policy::parse_strict(req.content)
        .map_err(|e| ApiError::UnprocessableEntity(format!("bad policy content: {e}")))?;
    let mut names: Vec<String> = fluidbox_core::tools::CANONICAL
        .iter()
        .map(|t| t.name.to_string())
        .collect();
    if let Some(name) = &req.name {
        if let Some(row) = fluidbox_db::get_policy_by_name(&state.pool, scope, name).await? {
            names.extend(fluidbox_db::policy_mcp_tools(&state.pool, scope, row.id).await?);
        }
    }
    Ok(Json(json!({
        "content": serde_json::to_value(&policy)?,
        "autonomy_summary": policy.autonomy_summary(),
        "defaults": policy.defaults,
        "budgets": policy.budgets,
        "approvals": policy.approvals,
        "egress": policy.egress,
        "matrix": matrix_payload(&policy, &names),
    })))
}

#[derive(Deserialize)]
pub struct ClonePolicy {
    /// The NEW policy's name.
    pub name: String,
    /// Clone source (a policy name). Omitted = start blank: an empty rule set
    /// under the fail-safe defaults (everything asks a human).
    #[serde(default)]
    pub from: Option<String>,
    /// Pin the exact source version (the one the dialog displayed). Omitted =
    /// the source's latest at execution time.
    #[serde(default)]
    pub from_version: Option<i32>,
}

/// NEW policy names travel in URL paths and dashboard links, so creation
/// constrains them to a routable set. Existing stored names are untouched —
/// this gates the clone/create path only (the YAML import path keeps its
/// legacy latitude, documented).
fn validate_policy_name(name: &str) -> Result<(), ApiError> {
    let ok = !name.is_empty()
        && name.len() <= 64
        && !name.starts_with('.')
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'));
    if !ok {
        return Err(ApiError::BadRequest(
            "policy names are 1-64 characters of a-z A-Z 0-9 . _ - and do not start with '.'"
                .into(),
        ));
    }
    reject_reserved_name(name)
}

/// The static `/v1/policies/*` routes shadow `/{name}` in axum, so a policy
/// carrying one of their names would be unreachable by its own URL. Refused on
/// EVERY creating path (clone AND the yaml import).
///
/// The list lives in `fluidbox-core` because the boot seed enforces it too and
/// the two crates cannot see each other; `policy_routes_are_all_reserved`
/// below pins it against the router's actual static segments.
fn reject_reserved_name(name: &str) -> Result<(), ApiError> {
    if fluidbox_core::policy::is_reserved_policy_name(name) {
        return Err(ApiError::BadRequest(format!(
            "'{name}' is reserved by the policies API — pick another name"
        )));
    }
    Ok(())
}

/// `POST /v1/policies/clone` — create a new policy (identity + version 1 in
/// one transaction) by cloning a parent's content or starting blank (design
/// §4.4 "New policy").
pub async fn clone_policy(
    principal: Principal,
    State(state): State<AppState>,
    Json(req): Json<ClonePolicy>,
) -> ApiResult<Json<Value>> {
    if !rbac::can_mutate_resources(&principal) {
        return Err(ApiError::Forbidden(
            "creating policies requires admin or owner".into(),
        ));
    }
    validate_policy_name(&req.name)?;
    if req.from.is_none() && req.from_version.is_some() {
        return Err(ApiError::BadRequest(
            "`from_version` needs `from` — a blank policy has no source version".into(),
        ));
    }
    let scope = principal.scope();
    let (policy, summary) = match &req.from {
        Some(source) => {
            let source_row = fluidbox_db::get_policy_by_name(&state.pool, scope, source)
                .await?
                .ok_or_else(|| ApiError::BadRequest(format!("unknown source policy '{source}'")))?;
            let source_version = match req.from_version {
                Some(n) => fluidbox_db::get_policy_version(&state.pool, scope, source_row.id, n)
                    .await?
                    .ok_or_else(|| {
                        ApiError::BadRequest(format!("source policy '{source}' has no v{n}"))
                    })?,
                None => require_latest_version(&state, scope, &source_row).await?,
            };
            let mut policy: Policy = serde_json::from_value(source_version.content.clone())
                .map_err(|e| ApiError::Internal(format!("bad stored policy: {e}")))?;
            policy.name = req.name.clone();
            (
                policy,
                format!("cloned from '{}' v{}", source, source_version.version),
            )
        }
        None => (
            Policy {
                name: req.name.clone(),
                defaults: Default::default(),
                egress: Default::default(),
                // Fail-safe: a blank policy caps sandbox network at `offline`.
                network: Default::default(),
                budgets: Default::default(),
                approvals: Default::default(),
                autonomy: Default::default(),
                tools: Vec::new(),
            },
            "created blank".to_string(),
        ),
    };
    policy.validate().map_err(ApiError::UnprocessableEntity)?;
    let content = serde_json::to_value(&policy)?;
    let (row, version) = fluidbox_db::create_policy(
        &state.pool,
        scope,
        &req.name,
        fluidbox_db::NewPolicyVersion {
            content: &content,
            yaml_source: None,
            summary: Some(&summary),
            author: "ui",
            author_user_id: principal.user_id(),
        },
    )
    .await
    .map_err(|e| match &e {
        // ONLY the name constraint maps to 409 — a different unique violation
        // here would be a bug worth its 500, not a user-facing conflict.
        sqlx::Error::Database(db)
            if db.code().as_deref() == Some("23505")
                && db.constraint() == Some("policies_tenant_id_name_key") =>
        {
            ApiError::Conflict(format!("a policy named '{}' already exists", req.name))
        }
        _ => ApiError::Db(e),
    })?;
    Ok(Json(json!({ "policy": {
        "id": row.id,
        "name": row.name,
        "version": version.version,
    }})))
}

/// `DELETE /v1/policies/{name}` — remove a policy identity and, through the
/// composite FK's cascade, its whole version history.
///
/// The counterpart to `clone`: without it the only way to create a policy is
/// also the only way to accumulate them forever, and a test suite that mints
/// one per run has nowhere to put it back.
///
/// Refuses (409) while ANY agent revision names it — every revision, not just
/// the latest, because revisions are immutable and a historical one must keep
/// resolving its policy. RUNS are never at stake: a RunSpec froze the whole
/// policy document, so no run needs the row to survive.
pub async fn delete_policy(
    principal: Principal,
    State(state): State<AppState>,
    Path(name): Path<String>,
) -> ApiResult<Json<Value>> {
    if !rbac::can_mutate_resources(&principal) {
        return Err(ApiError::Forbidden(
            "deleting policies requires admin or owner".into(),
        ));
    }
    let scope = principal.scope();
    let row = fluidbox_db::get_policy_by_name(&state.pool, scope, &name)
        .await?
        .ok_or(ApiError::NotFound)?;
    // `None` = the FK refused rather than our count. Same refusal, without
    // claiming a count we did not measure. See the arm below for when that can
    // actually happen (short answer: not today).
    let in_use = |revisions: Option<i64>| {
        let named = match revisions {
            Some(n) => format!("{n} agent revision{}", if n == 1 { "" } else { "s" }),
            None => "an agent revision created while this delete was in flight".to_string(),
        };
        ApiError::Conflict(format!(
            "'{name}' is still named by {named} — including historical revisions, which stay \
             immutable. Point those agents at another policy and delete the agents that no \
             longer need this one."
        ))
    };
    match fluidbox_db::delete_policy(&state.pool, scope, row.id).await {
        Ok(fluidbox_db::DeletePolicy::Deleted) => Ok(Json(
            json!({ "deleted": { "id": row.id, "name": row.name } }),
        )),
        Ok(fluidbox_db::DeletePolicy::InUse { revisions }) => Err(in_use(Some(revisions))),
        // UNREACHABLE TODAY, and kept deliberately.
        //
        // The obvious story — "a revision landed between the count and the
        // delete" — is not actually possible: `delete_policy` takes the parent
        // row `FOR UPDATE`, and inserting an `agent_revision` takes `FOR KEY
        // SHARE` on that same row to satisfy the FK. Those conflict, so the two
        // serialize: a revision already in flight makes our lock wait and is
        // then counted, and a revision starting after our lock waits for us and
        // fails. There is no window between the count and the delete.
        //
        // The arm stays because it is the FK — not the count — that actually
        // guarantees the invariant. If the lock ordering above is ever relaxed
        // (a `FOR NO KEY UPDATE`, a count moved outside the transaction), this
        // degrades the outcome to the correct 409 instead of a 500. Only THIS
        // constraint: any other 23503 here is a bug that deserves its 500.
        Err(sqlx::Error::Database(db))
            if db.code().as_deref() == Some("23503")
                && db.constraint() == Some("agent_revisions_policy_id_fkey") =>
        {
            Err(in_use(None))
        }
        // The row vanished between the name lookup above and the delete (a
        // concurrent delete won). 404 is the honest answer, and it is the same
        // one a second DELETE of the same name gets — so a client retrying is
        // never told something different about the same end state.
        Ok(fluidbox_db::DeletePolicy::NotFound) => Err(ApiError::NotFound),
        Err(e) => Err(ApiError::Db(e)),
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
    /// The sanctioned explicit binding override (design "Explicit binding"):
    /// requirement slot → connection id. Binding resolution verifies each
    /// entry (tenant, caller may use it, connector match, snapshot).
    #[serde(default)]
    pub bindings: Option<HashMap<String, Uuid>>,
    /// Optional per-run network narrowing, intersected with the revision's
    /// declaration (remove-only, like `capabilities`): a smaller mode, a subset
    /// of the declared targets, a shorter lifetime. A target the revision never
    /// declared is DROPPED — this can never introduce reach.
    #[serde(default)]
    pub network: Option<fluidbox_core::network::NetworkRequest>,
}

pub async fn create_session(
    principal: Principal,
    State(state): State<AppState>,
    Json(req): Json<CreateSession>,
) -> ApiResult<Json<Value>> {
    // Any authenticated principal may create a run; visibility of the created
    // run is governed by `invoked_by_user_id` (stamped below).
    let scope = principal.scope();
    // The invoker's visibility lens: a user sees org connections + only its own
    // personal ones; the operator sees all. A user-supplied workspace connection
    // resolves through this lens (invariant 21), so naming another user's
    // personal connection reads as "unknown".
    let viewer = rbac::connection_viewer(&principal);
    let explicit_input = match (req.workspace, req.repo) {
        (Some(_), Some(_)) => {
            return Err(ApiError::BadRequest(
                "provide either `workspace` or legacy `repo`, not both".into(),
            ))
        }
        (w, r) => w.or(r),
    };
    let explicit = match explicit_input {
        Some(input) => Some(
            resolve_workspace_input(
                &state,
                scope,
                viewer,
                LocalPathAuthority::of(&principal),
                input,
            )
            .await?,
        ),
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
            // Re-derived so the revision-default FALLBACK is held to the same
            // operator-only local_copy rule as the explicit input above.
            local_path_authority: LocalPathAuthority::of(&principal),
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
            // A manual/UI run's principal is the user (or operator), never a
            // trigger token.
            invoking_token_id: None,
            explicit_bindings: req.bindings.unwrap_or_default(),
            result_destinations: vec![],
            bound_invocation: None,
            bound_dispatch: None,
            network_override: req.network.clone(),
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
    fluidbox_obs::span::record_subject_run(&session.id.to_string());
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
    fluidbox_obs::span::record_subject_run(&id.to_string());
    let scope = principal.scope();
    let session = fluidbox_db::get_session(&state.pool, scope, id)
        .await?
        .ok_or(ApiError::NotFound)?;
    rbac::ensure_run_visible(&principal, &session)?;
    let totals = fluidbox_db::usage_totals(&state.pool, scope, id).await?;
    // "Why is my run not running yet" — the per-run half of the queue's
    // observability story (design 2026-08-23 §13). Attached ONLY while the run
    // is actually queued: on any other status the number would be stale the
    // instant it was read, and a field that is sometimes meaningful and
    // sometimes not is worse than an absent one.
    //
    // `queued_at` needs nothing here — it is a `SessionRow` column and already
    // serializes with the row.
    if session.status == fluidbox_core::state::SessionStatus::Queued.as_str() {
        let position = fluidbox_db::queued_position(&state.pool, scope, session.created_at).await?;
        return Ok(Json(json!({
            "session": session,
            "usage": totals,
            "queue_position": position,
        })));
    }
    Ok(Json(json!({ "session": session, "usage": totals })))
}

pub async fn cancel_session(
    principal: Principal,
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<Value>> {
    use orchestrator::FinalizeStart;
    fluidbox_obs::span::record_subject_run(&id.to_string());
    // Prove tenant ownership, then CANCELLATION authority — a mutation, so
    // deliberately stricter than run visibility (`runs.read_all` lets an
    // approver judge approvals, not control every tenant run).
    let session = fluidbox_db::get_session(&state.pool, principal.scope(), id)
        .await?
        .ok_or(ApiError::NotFound)?;
    rbac::authorize_run_cancellation(&principal, &session)?;
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
    fluidbox_obs::span::record_subject_run(&id.to_string());
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
    fluidbox_obs::span::record_subject_run(&id.to_string());
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
    let approval = fluidbox_db::get_approval(&state.pool, scope, id)
        .await?
        .ok_or(ApiError::NotFound)?;
    fluidbox_obs::span::record_subject_run(&approval.session_id.to_string());
    let session = fluidbox_db::get_session(&state.pool, scope, approval.session_id)
        .await?
        .ok_or(ApiError::NotFound)?;

    // Authorization (parent design lines 562-583). Phase C ends Phase B's "every
    // brokered call is org authority" premise: an mcp tool resolves to its slot's
    // run resource binding, and a personal (user-owned) connection is decidable
    // ONLY by its owner (on a run they invoked) — no role, admin/owner/operator
    // included. A non-mcp built-in tool is credentialless; an mcp tool with no
    // binding is a LEGACY brokered call that keeps Phase B's org authority.
    let slot =
        fluidbox_core::capability::parse_mcp_tool(&approval.tool).map(|(s, _)| s.to_string());
    let run_spec: Option<fluidbox_core::spec::RunSpec> =
        serde_json::from_value(session.run_spec.clone()).ok();
    // A Phase C run declares a BrokeredSurface per bound mcp slot in its RunSpec.
    let surface = match (&slot, &run_spec) {
        (Some(s), Some(rs)) => rs.find_brokered_surface(s).cloned(),
        _ => None,
    };
    let binding = match &slot {
        Some(s) => {
            fluidbox_db::find_session_binding(&state.pool, scope, session.id, "mcp", s).await?
        }
        None => None,
    };
    // R1.4(b): when the RunSpec has a BrokeredSurface for this slot, its binding
    // MUST exist and match — a missing/mismatched row is an integrity error, NOT
    // a fall-through to org authority. The legacy Organization fallback below
    // applies ONLY when there is no surface (a pre-Phase-C embedded FrozenBundle
    // brokered server).
    if let Some(surface) = &surface {
        let ok = binding.as_ref().is_some_and(|b| b.id == surface.binding_id);
        if !ok {
            return Err(ApiError::Conflict(
                "this approval's brokered surface has no matching run resource binding — refusing to classify its authority".into(),
            ));
        }
    }
    let authority = match &binding {
        Some(b) => {
            let facts = rbac::ApprovalBindingFacts::from_binding(b);
            // R1.4(c): an mcp binding is always a connection authority — cross-check
            // the LIVE connection owner (one scoped read) and prefer the stricter of
            // frozen-vs-live, so a stale/mislabeled org binding can never let a
            // non-owner decide under what is really a personal connection.
            match b.connection_id {
                Some(cid) => {
                    // Tenant known (the approval's scope) → scoped_tx so the RLS
                    // GUC rides the executor-generic read.
                    let mut conn_tx = fluidbox_db::scoped_tx(&state.pool, scope).await?;
                    let found = fluidbox_db::get_connection(&mut *conn_tx, scope, cid).await?;
                    conn_tx.commit().await?;
                    match found {
                        Some(conn) => rbac::reconcile_connection_authority(
                            &facts,
                            &conn.owner_type,
                            conn.owner_user_id,
                        ),
                        None => {
                            return Err(ApiError::Conflict(
                                "this approval's connection no longer exists — cannot classify its authority".into(),
                            ))
                        }
                    }
                }
                None => rbac::classify_approval_authority(&approval.tool, Some(&facts)),
            }
        }
        None => rbac::classify_approval_authority(&approval.tool, None),
    };
    // Enforced identically on approve AND deny (symmetric, v1).
    if let Err(refusal) = rbac::authorize_approval_decision(
        &authority,
        session.invoked_by_user_id,
        principal.user_id(),
        rbac::can_decide_org(&principal),
    ) {
        return Err(approval_refusal_error(&state, scope, refusal, binding.as_ref()).await);
    }

    // `decided_by` is DERIVED from the authenticated principal — never
    // request-supplied (parent design line 581).
    let decided_by = principal.decided_by();
    // Phase E (#33; Gap 13): the DECISION transaction is the ledger emitter. The
    // canonical `approval.decided` + `tool.decision` pair commits atomically with
    // this compare-and-set and `pg_notify`s every replica's waiters — so a decided
    // approval produces exactly ONE pair no matter how many `/permission` handlers
    // are re-attached to the row, and a waiter on ANOTHER replica wakes
    // immediately instead of riding its ≤2 s poll floor.
    let events = crate::internal::approval_decision_events(
        &state,
        session.id,
        id,
        &approval.tool_call_id,
        &approval.tool,
        status,
        &decided_by,
    );
    let row = fluidbox_db::decide_approval_tx(&state.pool, scope, id, status, &decided_by, events)
        .await?
        .ok_or_else(|| ApiError::Conflict("approval is not pending".into()))?;
    // Wake this replica's blocked permission handler without waiting for the
    // NOTIFY round trip (other replicas ride the channel).
    state.approvals.wake(id).await;
    Ok(Json(json!({ "approval": row })))
}

/// Turn an approval-authorization refusal into an `ApiError::Forbidden`. The
/// personal-connection case names WHOSE connection would execute (design
/// :576-579) using the connection's display name — never a secret; the org /
/// credentialless cases keep Phase B's message verbatim.
async fn approval_refusal_error(
    state: &AppState,
    scope: TenantScope,
    refusal: rbac::ApprovalRefusal,
    binding: Option<&fluidbox_db::RunResourceBindingRow>,
) -> ApiError {
    match refusal {
        rbac::ApprovalRefusal::PersonalConnection { owner_user_id } => {
            let label = personal_connection_label(state, scope, binding, owner_user_id).await;
            ApiError::Forbidden(format!(
                "this approval executes under {label}, a personal connection — only its owner, who invoked the run, may decide it"
            ))
        }
        // Both non-personal refusals keep Phase B's exact message.
        rbac::ApprovalRefusal::NeedsOrg | rbac::ApprovalRefusal::NeedsOwnOrOrg => {
            ApiError::Forbidden("deciding this approval requires approver, admin, or owner".into())
        }
    }
}

/// A safe, human label for the personal connection an approval would execute
/// under: the connection's display name when readable (not a secret), else a
/// generic phrase naming the owner id. Never leaks a credential.
async fn personal_connection_label(
    state: &AppState,
    scope: TenantScope,
    binding: Option<&fluidbox_db::RunResourceBindingRow>,
    owner_user_id: Uuid,
) -> String {
    if let Some(cid) = binding.and_then(|b| b.connection_id) {
        // Tenant known (the approval's scope) → scoped_tx so the RLS GUC rides the
        // executor-generic read; a tx/read failure just falls through to the
        // generic label.
        if let Ok(mut conn_tx) = fluidbox_db::scoped_tx(&state.pool, scope).await {
            let found = fluidbox_db::get_connection(&mut *conn_tx, scope, cid).await;
            let _ = conn_tx.commit().await;
            if let Ok(Some(conn)) = found {
                return format!("connection '{}'", conn.display_name);
            }
        }
    }
    format!("another user's personal connection (owner {owner_user_id})")
}

// ─── Result deliveries ────────────────────────────────────────────────────

pub async fn session_deliveries(
    principal: Principal,
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<Value>> {
    fluidbox_obs::span::record_subject_run(&id.to_string());
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
    fluidbox_obs::span::record_subject_run(&id.to_string());
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
    fluidbox_obs::span::record_subject_run(&sid.to_string());
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
    fluidbox_obs::span::record_subject_run(&id.to_string());
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
    fn harnesses_payload_reports_the_resolved_enforcer_not_the_config() {
        // The value must come from the PROVIDER. Echoing config is the bug that
        // let FLUIDBOX_NETWORK_ENFORCER=cilium sit on a cluster with no enforcer.
        let body = harnesses_network_block(&fluidbox_core::traits::NoNetworkEnforcer);
        assert_eq!(body["supports_egress_grants"], serde_json::json!(false));
        assert_eq!(body["enforcer"], serde_json::json!("none"));
    }

    #[test]
    fn harnesses_payload_reports_a_live_egress_capable_enforcer() {
        // The NoNetworkEnforcer case alone passes even if the block hardcodes
        // "none"/false. A fake that answers "cilium"/true proves BOTH fields are
        // delegated to the argument, not baked in.
        struct FakeCiliumEnforcer;

        #[async_trait::async_trait]
        impl fluidbox_core::traits::NetworkPolicyProvider for FakeCiliumEnforcer {
            async fn prepare(
                &self,
                _granted: &fluidbox_core::traits::GrantedNetwork,
            ) -> Result<(), fluidbox_core::traits::NetworkPolicyError> {
                Ok(())
            }
            async fn verify(
                &self,
                _granted: &fluidbox_core::traits::GrantedNetwork,
            ) -> Result<(), fluidbox_core::traits::NetworkPolicyError> {
                Ok(())
            }
            async fn revoke(
                &self,
                _granted: &fluidbox_core::traits::GrantedNetwork,
            ) -> Result<(), fluidbox_core::traits::NetworkPolicyError> {
                Ok(())
            }
            fn enforcer_name(&self) -> &'static str {
                "cilium"
            }
            fn supports_egress_grants(&self) -> bool {
                true
            }
        }

        let body = harnesses_network_block(&FakeCiliumEnforcer);
        assert_eq!(body["enforcer"], serde_json::json!("cilium"));
        assert_eq!(body["supports_egress_grants"], serde_json::json!(true));
    }

    /// `LocalCopy` is host-filesystem read access with no root and no tenant
    /// meaning, and `POST /v1/sessions` admits ANY authenticated principal — so
    /// the authority must be derived from the principal CLASS, not from a
    /// comment about the admin token.
    #[test]
    fn local_copy_authority_is_operator_only() {
        let scope = TenantScope::assume(Uuid::new_v4());
        assert_eq!(
            LocalPathAuthority::of(&Principal::Operator { scope }),
            LocalPathAuthority::Operator
        );
        // Every non-operator principal — member, admin, owner, PAT alike; the
        // roles live inside UserPrincipal and none of them opens this door.
        for roles in [
            vec![],
            vec!["member".to_string()],
            vec!["owner".to_string()],
        ] {
            let user = Principal::User(crate::auth::UserPrincipal {
                tenant_id: scope.tenant_id(),
                user_id: Uuid::new_v4(),
                membership_id: Uuid::new_v4(),
                roles,
                auth: crate::auth::AuthContext::Pat {
                    token_id: Uuid::new_v4(),
                },
            });
            assert_eq!(
                LocalPathAuthority::of(&user),
                LocalPathAuthority::Denied,
                "a non-operator principal must not reach a host path"
            );
        }
    }

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

    /// The reserved-name list and the ROUTER must not drift. axum matches a
    /// static segment before `/{name}`, so a policy named after any static
    /// `/policies/*` segment would be unreachable by its own URL — and a wrong
    /// constant here is invisible to every other test (the same failure mode
    /// CLAUDE.md flags for the audience mapping, so it gets the same treatment:
    /// read the router's source and compare).
    ///
    /// Reads `main.rs` rather than the built `Router` because axum exposes no
    /// way to enumerate registered paths.
    #[test]
    fn policy_routes_are_all_reserved() {
        let main_rs = include_str!("main.rs");
        let mut segments: Vec<&str> = Vec::new();
        for line in main_rs.lines() {
            // `.route("/policies/<seg>...` — the FIRST segment after
            // `/policies/` is the only one that can shadow `/{name}`.
            let Some(rest) = line.split("\"/policies/").nth(1) else {
                continue;
            };
            let Some(path) = rest.split('"').next() else {
                continue;
            };
            let seg = path.split('/').next().unwrap_or_default();
            // `{name}` IS the capture this test exists to protect.
            if seg.is_empty() || seg.starts_with('{') {
                continue;
            }
            segments.push(seg);
        }
        assert!(
            !segments.is_empty(),
            "found no static /policies/* routes in main.rs — the scraper broke, \
             which would make this test vacuously green"
        );
        // The scraper understands `.route("/policies/…")` and nothing else. If
        // the policy routes are ever moved under a nested Router, every path
        // above becomes invisible and this test goes quietly vacuous — so make
        // that a loud failure instead of a silent one.
        assert!(
            !main_rs.contains(".nest(\"/policies"),
            "policy routes are now NESTED; this test only scrapes `.route(\"/policies/…\")` \
             and would no longer see them. Teach the scraper the new shape before trusting it."
        );
        for seg in &segments {
            assert!(
                fluidbox_core::policy::is_reserved_policy_name(seg),
                "route /policies/{seg} shadows /{{name}}, but '{seg}' is absent from \
                 fluidbox_core::policy::RESERVED_POLICY_NAMES — a policy named '{seg}' \
                 would be unreachable by its own URL. Add it there."
            );
        }
        // …and nothing is reserved that no longer needs to be (a stale entry
        // silently forbids a name users could otherwise have).
        for name in fluidbox_core::policy::RESERVED_POLICY_NAMES {
            assert!(
                segments.contains(name),
                "'{name}' is reserved but no /policies/{name} route exists — drop it \
                 from RESERVED_POLICY_NAMES rather than forbidding a usable name."
            );
        }
    }
}
