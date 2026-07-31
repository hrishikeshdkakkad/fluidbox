//! Recipes: the catalog surface + the deploy engine (design
//! docs/plans/2026-07-31-enterprise-recipes-design.md).
//!
//! A deploy VALIDATES (schema → semantic widgets → render → per-object
//! checks mirroring the manual creation handlers) before it writes anything,
//! then stamps policy + agents + subscriptions (+schedules +tokens) + the
//! instance in ONE transaction — a mid-stamp failure leaves nothing behind.
//! Everything stamped is an ordinary object created through the shared
//! `fluidbox-db` creators; runs go through `run_service::create_run` AFTER the
//! stamp commits. There is no recipe-specific execution or permission path.
//!
//! Authority: browsing is open to any principal; deploy/instance lifecycle
//! rides `rbac::can_deploy_recipes` (admin/owner/operator — the union of the
//! two authorities a stamp exercises); custom recipe authoring rides
//! `rbac::can_mutate_resources`.

use crate::auth::Principal;
use crate::error::{ApiError, ApiResult};
use crate::rbac;
use crate::run_service::{self, CreateRun, RevisionSelector, RunCreation};
use crate::state::AppState;
use crate::triggers::{
    contract_urls, random_hex_token, render_task_template, schedule_context, SECRET_PREFIX,
    TOKEN_PREFIX,
};
use crate::{api, harness};
use axum::extract::{Path, State};
use axum::Json;
use fluidbox_core::capability::ConnectionRequirement;
use fluidbox_core::policy::Policy;
use fluidbox_core::recipe::{
    self, ParamSpec, ParamWidget, RecipeDefinition, RenderCtx, RenderedRecipe,
};
use fluidbox_core::schedule::{ConcurrencyPolicy, CronSchedule, MissedRunPolicy};
use fluidbox_core::schema_guard;
use fluidbox_core::spec::{
    Autonomy, Budgets, InvocationContext, InvocationKind, ResultDestination, TrustTier,
    WorkspaceSpec,
};
use fluidbox_db::recipes as db;
use fluidbox_db::TenantScope;
use serde::Deserialize;
use serde_json::{json, Map, Value};
use std::collections::{BTreeSet, HashMap};
use uuid::Uuid;

/// Slugs the route space owns: `/v1/recipes/instances` must never be shadowed
/// by a recipe named "instances".
const RESERVED_SLUGS: &[&str] = &["instances"];

fn valid_recipe_slug(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 64
        && s.chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
        && !RESERVED_SLUGS.contains(&s)
}

/// Instance names flow into stamped object names ("{name} · security") and a
/// slugified policy name, so they are bounded tighter than a free-text field.
fn validate_instance_name(name: &str) -> Result<&str, ApiError> {
    let name = name.trim();
    if name.is_empty() {
        return Err(ApiError::BadRequest("name is required".into()));
    }
    if name.len() > 48 {
        return Err(ApiError::BadRequest(
            "name must be at most 48 characters".into(),
        ));
    }
    Ok(name)
}

/// "Acme PR review" → "acme-pr-review" for the stamped policy's name (policy
/// names are constrained to `[A-Za-z0-9._-]`).
fn slugify(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    let mut dash = true; // suppress leading dash
    for c in name.chars() {
        if c.is_ascii_alphanumeric() {
            out.push(c.to_ascii_lowercase());
            dash = false;
        } else if !dash {
            out.push('-');
            dash = true;
        }
    }
    while out.ends_with('-') {
        out.pop();
    }
    if out.is_empty() {
        "instance".to_string()
    } else {
        out
    }
}

// ─── Catalog ──────────────────────────────────────────────────────────────

/// Card-level facets derived from a version's definition + schema: what the
/// browser needs to render an honest card without shipping the blobs.
fn facets_of(def: &RecipeDefinition, specs: &[ParamSpec]) -> Value {
    let mut kinds: Vec<&str> = def
        .subscriptions
        .iter()
        .map(|s| s.kind.as_str())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    if def.first_run.is_some() {
        kinds.push("instant");
    }
    let connectors: Vec<Value> = specs
        .iter()
        .filter_map(|p| match &p.widget {
            ParamWidget::Connection { provider, mcp } => Some(json!({
                "param": p.name,
                "title": p.title,
                "provider": provider,
                "mcp": mcp,
                "required": p.required,
            })),
            _ => None,
        })
        .collect();
    // Honest ceiling: one triggering event may start EVERY agent (the fan-out
    // panel), so the per-event ceiling is the sum of per-agent cost caps.
    let cost: f64 = def
        .agents
        .iter()
        .map(|a| {
            a.budgets
                .as_ref()
                .and_then(|b| b.get("max_cost_usd"))
                .and_then(Value::as_f64)
                .unwrap_or_else(|| Budgets::default().max_cost_usd.unwrap_or(0.0))
        })
        .sum();
    json!({
        "agent_count": def.agents.len(),
        "multi_agent": def.agents.len() > 1,
        "trigger_kinds": kinds,
        "connectors": connectors,
        "cost_ceiling_usd": (cost * 100.0).round() / 100.0,
        "instant_run": def.first_run.is_some(),
        "success_criteria": def.success_criteria,
    })
}

/// The "what gets created" manifest for detail + deploy-plan surfaces.
fn manifest_of(def: &RecipeDefinition) -> Value {
    json!({
        "policy": def.policy.is_some(),
        "agents": def.agents.iter().map(|a| json!({
            "slot": a.slot,
            "harness": a.harness,
        })).collect::<Vec<_>>(),
        "subscriptions": def.subscriptions.iter().map(|s| json!({
            "slot": s.slot,
            "agent_slot": s.agent_slot,
            "kind": s.kind,
        })).collect::<Vec<_>>(),
        "first_run": def.first_run.is_some(),
    })
}

/// Human-auditable summary of the recipe's embedded policy for the
/// pre-deploy permissions panel. Renders the SERVER's parse of the rules —
/// the dashboard never re-derives verdicts.
fn policy_summary(def: &RecipeDefinition) -> ApiResult<Value> {
    let Some(p) = &def.policy else {
        return Ok(json!({ "embedded": false,
            "note": "agents deploy under the organization's default policy" }));
    };
    let policy = Policy::parse_strict(p.content.clone())
        .map_err(|e| ApiError::Internal(format!("stored recipe policy invalid: {e}")))?;
    let rules: Vec<Value> = policy
        .tools
        .iter()
        .map(|r| {
            json!({
                "tools": r.r#match,
                "action": r.action,
                "constrained": r.paths.is_some() || r.shell.is_some(),
            })
        })
        .collect();
    Ok(json!({
        "embedded": true,
        "default_action": policy.defaults.tool_action,
        "autonomy_permitted": policy.autonomy.permitted,
        "on_approval_rule": policy.autonomy.on_approval_rule,
        "budgets": policy.budgets,
        "rules": rules,
    }))
}

pub async fn list(principal: Principal, State(state): State<AppState>) -> ApiResult<Json<Value>> {
    let scope = principal.scope();
    let rows = db::list_recipes(&state.pool, scope).await?;
    let mut out = Vec::with_capacity(rows.len());
    for r in rows {
        // The catalog is small (curated + a tenant's customs); a per-row
        // latest-version read keeps the list query blob-free.
        let Some(v) = db::get_recipe_version(&state.pool, scope, r.id, r.latest_version).await?
        else {
            continue; // version-less identity: a bug state; hide rather than 500
        };
        let (def, specs) = parse_stored(&v)?;
        out.push(json!({
            "id": r.id,
            "slug": r.slug,
            "name": r.name,
            "tagline": r.tagline,
            "category": r.category,
            "tags": r.tags,
            "tier": r.tier,
            "icon": r.icon,
            "custom": r.tenant_id.is_some(),
            "latest_version": r.latest_version,
            "facets": facets_of(&def, &specs),
            "updated_at": r.updated_at,
        }));
    }
    Ok(Json(json!({ "recipes": out })))
}

pub async fn get(
    principal: Principal,
    State(state): State<AppState>,
    Path(slug): Path<String>,
) -> ApiResult<Json<Value>> {
    let scope = principal.scope();
    let (recipe, version) = db::get_recipe_by_slug(&state.pool, scope, &slug)
        .await?
        .ok_or(ApiError::NotFound)?;
    let (def, specs) = parse_stored(&version)?;
    let versions = db::list_recipe_versions(&state.pool, scope, recipe.id).await?;
    Ok(Json(json!({
        "recipe": recipe,
        "version": {
            "version": version.version,
            "definition": version.definition,
            "params_schema": version.params_schema,
            "changelog": version.changelog,
            "created_at": version.created_at,
        },
        "params": specs,
        "facets": facets_of(&def, &specs),
        "manifest": manifest_of(&def),
        "policy_summary": policy_summary(&def)?,
        "summary_md": def.summary_md,
        "versions": versions,
    })))
}

/// Parse + re-validate a stored version's blobs. Stored state failing here is
/// an Internal (seeds are covered by a fluidbox-db test; custom rows were
/// validated at create) — never a user-attributable 4xx.
fn parse_stored(v: &db::RecipeVersionRow) -> ApiResult<(RecipeDefinition, Vec<ParamSpec>)> {
    let def = RecipeDefinition::parse(&v.definition)
        .map_err(|e| ApiError::Internal(format!("stored recipe definition invalid: {e}")))?;
    schema_guard::guard_schema(&v.params_schema)
        .map_err(|e| ApiError::Internal(format!("stored recipe params_schema invalid: {e}")))?;
    let specs = recipe::param_specs(&v.params_schema)
        .map_err(|e| ApiError::Internal(format!("stored recipe params_schema invalid: {e}")))?;
    Ok((def, specs))
}

// ─── Custom recipe authoring ──────────────────────────────────────────────

#[derive(Deserialize)]
pub struct CreateCustomRecipe {
    pub slug: String,
    pub name: String,
    #[serde(default)]
    pub tagline: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub category: Option<String>,
    #[serde(default)]
    pub tags: Option<Vec<String>>,
    #[serde(default)]
    pub icon: Option<String>,
    pub definition: Value,
    pub params_schema: Value,
    #[serde(default)]
    pub changelog: Option<String>,
}

/// Shared authoring validation: strict definition parse, guarded schema,
/// renderable widgets, and every `$param:`/`{{recipe.*}}` reference declared.
fn validate_authored(definition: &Value, params_schema: &Value) -> ApiResult<()> {
    RecipeDefinition::parse(definition)
        .map_err(|e| ApiError::UnprocessableEntity(format!("invalid definition: {e}")))?;
    schema_guard::guard_schema(params_schema)
        .map_err(|e| ApiError::UnprocessableEntity(format!("invalid params_schema: {e}")))?;
    let specs = recipe::param_specs(params_schema)
        .map_err(|e| ApiError::UnprocessableEntity(format!("invalid params_schema: {e}")))?;
    let declared: BTreeSet<&str> = specs.iter().map(|s| s.name.as_str()).collect();
    for referenced in recipe::referenced_params(definition) {
        if !declared.contains(referenced.as_str()) {
            return Err(ApiError::UnprocessableEntity(format!(
                "definition references parameter '{referenced}' but params_schema does not declare it"
            )));
        }
    }
    Ok(())
}

pub async fn create_custom(
    principal: Principal,
    State(state): State<AppState>,
    Json(req): Json<CreateCustomRecipe>,
) -> ApiResult<Json<Value>> {
    if !rbac::can_mutate_resources(&principal) {
        return Err(ApiError::Forbidden(
            "creating recipes requires admin or owner".into(),
        ));
    }
    let slug = req.slug.trim();
    if !valid_recipe_slug(slug) {
        return Err(ApiError::BadRequest(
            "slug must be 1-64 chars of [a-z0-9-] and not a reserved name".into(),
        ));
    }
    if req.name.trim().is_empty() {
        return Err(ApiError::BadRequest("name is required".into()));
    }
    validate_authored(&req.definition, &req.params_schema)?;
    let tags = json!(req.tags.unwrap_or_default());
    let created = db::create_custom_recipe(
        &state.pool,
        principal.scope(),
        slug,
        req.name.trim(),
        req.tagline.trim(),
        req.description.trim(),
        req.category.as_deref().unwrap_or("general"),
        &tags,
        req.icon.as_deref().unwrap_or("custom"),
        &req.definition,
        &req.params_schema,
        req.changelog.as_deref(),
    )
    .await
    .map_err(|e| match &e {
        sqlx::Error::Database(db) if db.is_unique_violation() => {
            ApiError::Conflict(format!("a recipe with slug '{slug}' already exists"))
        }
        _ => ApiError::Db(e),
    })?;
    let Some((recipe_row, version)) = created else {
        return Err(ApiError::Conflict(format!(
            "'{slug}' is an official recipe slug — pick a different slug"
        )));
    };
    Ok(Json(json!({ "recipe": recipe_row, "version": version })))
}

#[derive(Deserialize)]
pub struct AppendVersion {
    pub definition: Value,
    pub params_schema: Value,
    #[serde(default)]
    pub changelog: Option<String>,
}

pub async fn append_version(
    principal: Principal,
    State(state): State<AppState>,
    Path(slug): Path<String>,
    Json(req): Json<AppendVersion>,
) -> ApiResult<Json<Value>> {
    if !rbac::can_mutate_resources(&principal) {
        return Err(ApiError::Forbidden(
            "versioning recipes requires admin or owner".into(),
        ));
    }
    let scope = principal.scope();
    let (recipe_row, _) = db::get_recipe_by_slug(&state.pool, scope, &slug)
        .await?
        .ok_or(ApiError::NotFound)?;
    if recipe_row.tenant_id.is_none() {
        return Err(ApiError::Forbidden(
            "official recipes are versioned by fluidbox releases — clone into a custom recipe to modify".into(),
        ));
    }
    validate_authored(&req.definition, &req.params_schema)?;
    let version = db::append_custom_recipe_version(
        &state.pool,
        scope,
        recipe_row.id,
        &req.definition,
        &req.params_schema,
        req.changelog.as_deref(),
    )
    .await?
    .ok_or(ApiError::NotFound)?;
    Ok(Json(json!({ "version": version })))
}

// ─── Deploy engine ────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct DeployBody {
    pub name: String,
    #[serde(default)]
    pub params: Map<String, Value>,
    #[serde(default)]
    pub dry_run: bool,
}

/// Everything a stamp needs, fully validated and rendered — assembled BEFORE
/// any write. Also serializable as the dry-run plan.
struct Prepared {
    effective_params: Map<String, Value>,
    params_digest: String,
    policy: Option<(String, Value)>,
    agents: Vec<PreparedAgent>,
    subscriptions: Vec<PreparedSubscription>,
    first_run: Option<PreparedFirstRun>,
    plan: Value,
}

struct PreparedAgent {
    slot: String,
    name: String,
    harness: String,
    runner_image: String,
    model: String,
    system_prompt: Option<String>,
    budgets: Value,
    capability_pins: Value,
    requirements: Value,
    default_workspace: Option<Value>,
}

struct PreparedSubscription {
    slot: String,
    agent_slot: String,
    kind: String,
    name: String,
    task_template: Option<String>,
    autonomous: bool,
    concurrency: String,
    connection_id: Option<Uuid>,
    resource_selector: Option<Value>,
    event_filter: Option<Value>,
    event_publish: Option<Value>,
    destinations: Value,
    callback_secret: Option<(String, crate::seal::Sealed)>,
    schedule: Option<(String, String, String, chrono::DateTime<chrono::Utc>)>,
    allow_task_override: bool,
    allow_workspace_override: bool,
    budget_override: Option<Value>,
    capability_keep: Option<Value>,
    workspace: Option<Value>,
}

struct PreparedFirstRun {
    agent_slot: String,
    task: String,
    autonomous: bool,
}

/// Widget-level semantic validation + reference resolution. Returns the
/// RENDER params (reference params expanded into objects) alongside the raw
/// effective params that get stored on the instance.
async fn resolve_params(
    state: &AppState,
    scope: TenantScope,
    specs: &[ParamSpec],
    effective: &Map<String, Value>,
) -> ApiResult<Map<String, Value>> {
    let mut render = effective.clone();
    for spec in specs {
        let Some(value) = effective.get(&spec.name) else {
            continue; // absent optional — schema validation already vetted requireds
        };
        match &spec.widget {
            ParamWidget::Connection { provider, mcp } => {
                let cid = value
                    .as_str()
                    .and_then(|s| Uuid::parse_str(s).ok())
                    .ok_or_else(|| {
                        ApiError::UnprocessableEntity(format!(
                            "param '{}': must be a connection id",
                            spec.name
                        ))
                    })?;
                let mut tx = fluidbox_db::scoped_tx(&state.pool, scope).await?;
                let conn = fluidbox_db::get_connection(&mut *tx, scope, cid).await?;
                tx.commit().await?;
                let conn = conn.ok_or_else(|| {
                    ApiError::UnprocessableEntity(format!(
                        "param '{}': unknown connection {cid}",
                        spec.name
                    ))
                })?;
                if conn.status != "active" {
                    return Err(ApiError::UnprocessableEntity(format!(
                        "param '{}': connection '{}' is {} — reconnect it first",
                        spec.name, conn.display_name, conn.status
                    )));
                }
                if let Some(p) = provider {
                    // "github" means either connection shape that speaks the
                    // github provider (manual PAT or seamless App).
                    let ok = match p.as_str() {
                        "github" => conn.provider == "github" || conn.provider == "github_app",
                        other => conn.provider == other,
                    };
                    if !ok {
                        return Err(ApiError::UnprocessableEntity(format!(
                            "param '{}': connection '{}' is a {} connection, not {p}",
                            spec.name, conn.display_name, conn.provider
                        )));
                    }
                }
                if *mcp && conn.provider != "mcp_http" {
                    return Err(ApiError::UnprocessableEntity(format!(
                        "param '{}': connection '{}' is not an MCP server connection",
                        spec.name, conn.display_name
                    )));
                }
                // The SAME url precedence binding resolution matches on
                // (endpoint_url — the concrete server — else base_url), so a
                // requirement rendered from this object resolves back to this
                // connection and no other.
                let base_url = conn
                    .metadata
                    .get("endpoint_url")
                    .and_then(Value::as_str)
                    .or_else(|| conn.metadata.get("base_url").and_then(Value::as_str))
                    .unwrap_or_default();
                render.insert(
                    spec.name.clone(),
                    json!({
                        "id": cid.to_string(),
                        "provider": conn.provider,
                        "display_name": conn.display_name,
                        "base_url": base_url,
                    }),
                );
            }
            ParamWidget::ConnectionTools { connection_param } => {
                let tools: Vec<String> = value
                    .as_array()
                    .map(|a| {
                        a.iter()
                            .filter_map(Value::as_str)
                            .map(str::to_string)
                            .collect()
                    })
                    .unwrap_or_default();
                let Some(conn_id) = effective
                    .get(connection_param)
                    .and_then(Value::as_str)
                    .and_then(|s| Uuid::parse_str(s).ok())
                else {
                    return Err(ApiError::UnprocessableEntity(format!(
                        "param '{}': set '{}' first",
                        spec.name, connection_param
                    )));
                };
                // Early, deploy-time mirror of the run-time snapshot-subset
                // check: fail here with a pick-list-shaped error rather than
                // at first fire.
                let snapshot =
                    fluidbox_db::latest_connection_tool_snapshot(&state.pool, scope, conn_id)
                        .await?
                        .ok_or_else(|| {
                            ApiError::UnprocessableEntity(format!(
                                "param '{}': the connection has no tool snapshot — refresh its tools",
                                spec.name
                            ))
                        })?;
                let available: BTreeSet<&str> = snapshot
                    .tools_json
                    .as_array()
                    .map(|a| {
                        a.iter()
                            .filter_map(|t| t.get("name").and_then(Value::as_str))
                            .collect()
                    })
                    .unwrap_or_default();
                let missing: Vec<&str> = tools
                    .iter()
                    .map(String::as_str)
                    .filter(|t| !available.contains(t))
                    .collect();
                if !missing.is_empty() {
                    return Err(ApiError::UnprocessableEntity(format!(
                        "param '{}': the connection's snapshot has no tool(s): {}",
                        spec.name,
                        missing.join(", ")
                    )));
                }
            }
            ParamWidget::Repositories => {
                for r in value.as_array().into_iter().flatten() {
                    let Some(r) = r.as_str() else { continue };
                    if !api::valid_repo_name(r) {
                        return Err(ApiError::UnprocessableEntity(format!(
                            "param '{}': repository must be 'owner/name' (got '{r}')",
                            spec.name
                        )));
                    }
                }
            }
            ParamWidget::Cron => {
                let cron = value.as_str().unwrap_or_default();
                CronSchedule::parse(cron, "UTC").map_err(|e| {
                    ApiError::UnprocessableEntity(format!("param '{}': {e}", spec.name))
                })?;
            }
            ParamWidget::Timezone => {
                // Validated through the same seam schedules use — an unknown
                // IANA name fails CronSchedule::parse, so the error text and
                // acceptance set can never drift from the scheduler's.
                let tz = value.as_str().unwrap_or_default();
                CronSchedule::parse("0 0 * * *", tz).map_err(|e| {
                    ApiError::UnprocessableEntity(format!("param '{}': {e}", spec.name))
                })?;
            }
            ParamWidget::Model { harness: h } => {
                let m = value.as_str().unwrap_or_default();
                if !harness::model_belongs(h, m) {
                    return Err(ApiError::UnprocessableEntity(format!(
                        "param '{}': model '{m}' is not valid for harness '{h}'",
                        spec.name
                    )));
                }
            }
            ParamWidget::Url => {
                let url = value.as_str().unwrap_or_default();
                if !(url.starts_with("http://") || url.starts_with("https://")) {
                    return Err(ApiError::UnprocessableEntity(format!(
                        "param '{}': must be an http(s) URL",
                        spec.name
                    )));
                }
                crate::egress::admit_url(url, &state.egress_policy).map_err(|e| {
                    ApiError::UnprocessableEntity(format!("param '{}': rejected: {e}", spec.name))
                })?;
            }
            // Structural widgets — the JSON-Schema validation already covered
            // shape; text-y content needs no semantic pass.
            ParamWidget::Text
            | ParamWidget::Textarea
            | ParamWidget::Number
            | ParamWidget::Boolean
            | ParamWidget::Select
            | ParamWidget::StringList
            | ParamWidget::Events => {}
        }
    }
    Ok(render)
}

/// The full validate → resolve → render → per-object-check pipeline. Reused
/// verbatim by deploy and upgrade (upgrade renders the NEW version with the
/// merged params).
async fn prepare(
    state: &AppState,
    principal: &Principal,
    version: &db::RecipeVersionRow,
    instance_name: &str,
    raw_params: &Map<String, Value>,
) -> ApiResult<Prepared> {
    let scope = principal.scope();
    let (def, specs) = parse_stored(version)?;

    // 1) Structural validation against the frozen schema (defaults applied).
    let effective = recipe::apply_defaults(&version.params_schema, raw_params);
    recipe::validate_params(&version.params_schema, &effective).map_err(|pointers| {
        ApiError::UnprocessableEntity(format!("invalid params: {}", pointers.join("; ")))
    })?;

    // 2) Semantic widget validation + reference resolution.
    let render_params = resolve_params(state, scope, &specs, &effective).await?;

    // 3) Render the definition.
    let rendered = recipe::render_definition(
        &def,
        &RenderCtx {
            params: &render_params,
            instance_name,
        },
    )
    .map_err(ApiError::UnprocessableEntity)?;

    // 4) Per-object checks, mirroring the manual creation handlers.
    let prepared = prepare_objects(state, principal, instance_name, &def, rendered).await?;

    let params_digest = fluidbox_db::sha256_hex(
        &serde_json::to_string(&Value::Object(effective.clone())).expect("params serialize"),
    );
    Ok(Prepared {
        effective_params: effective,
        params_digest,
        plan: prepared.plan.clone(),
        ..prepared
    })
}

async fn prepare_objects(
    state: &AppState,
    principal: &Principal,
    instance_name: &str,
    def: &RecipeDefinition,
    rendered: RenderedRecipe,
) -> ApiResult<Prepared> {
    let scope = principal.scope();

    // Policy: inject the stamped name into the content so the governance page
    // shows a self-describing document.
    let policy = match rendered.policy_content {
        None => None,
        Some(mut content) => {
            let policy_name = format!("{}-policy", slugify(instance_name));
            if let Some(obj) = content.as_object_mut() {
                obj.insert("name".into(), json!(policy_name));
            }
            Policy::parse_strict(content.clone())
                .map_err(|e| ApiError::Internal(format!("recipe policy failed to render: {e}")))?;
            Some((policy_name, content))
        }
    };

    let mut agents = Vec::with_capacity(rendered.agents.len());
    for a in rendered.agents {
        let (default_image, default_model) = match (
            harness::default_runner_image(&a.harness, &state.cfg),
            harness::default_model(&a.harness, &state.cfg),
        ) {
            (Some(i), Some(m)) => (i.to_string(), m.to_string()),
            _ => {
                return Err(ApiError::UnprocessableEntity(format!(
                    "agents[{}]: unknown harness '{}' (known: {})",
                    a.slot,
                    a.harness,
                    harness::KNOWN.join(", ")
                )))
            }
        };
        let model = match a.model {
            Some(m) => {
                if !harness::model_belongs(&a.harness, &m) {
                    return Err(ApiError::UnprocessableEntity(format!(
                        "agents[{}]: model '{m}' is not valid for harness '{}'",
                        a.slot, a.harness
                    )));
                }
                m
            }
            None => default_model,
        };
        let budgets: Budgets = match &a.budgets {
            Some(v) => serde_json::from_value(v.clone()).map_err(|e| {
                ApiError::UnprocessableEntity(format!("agents[{}].budgets: {e}", a.slot))
            })?,
            None => Budgets::default(),
        };
        let requirements: Vec<ConnectionRequirement> =
            serde_json::from_value(a.connection_requirements.clone()).map_err(|e| {
                ApiError::UnprocessableEntity(format!(
                    "agents[{}].connection_requirements: {e}",
                    a.slot
                ))
            })?;
        fluidbox_core::capability::validate_requirements(&requirements).map_err(|e| {
            ApiError::UnprocessableEntity(format!(
                "agents[{}].connection_requirements: {e}",
                a.slot
            ))
        })?;
        let capability_pins = if a.capability_bundles.is_empty() {
            json!([])
        } else {
            api::resolve_bundle_pins(state, scope, &a.capability_bundles).await?
        };
        let default_workspace = match a.workspace {
            None => None,
            Some(w) => Some(resolve_workspace(state, principal, &a.slot, w).await?),
        };
        agents.push(PreparedAgent {
            slot: a.slot,
            name: a.name,
            harness: a.harness,
            runner_image: default_image,
            model,
            system_prompt: a.system_prompt,
            budgets: serde_json::to_value(&budgets)?,
            capability_pins,
            requirements: serde_json::to_value(&requirements)?,
            default_workspace,
        });
    }

    let mut subscriptions = Vec::with_capacity(rendered.subscriptions.len());
    for s in rendered.subscriptions {
        let template = s.task_template.as_deref().map(str::trim).filter(|t| !t.is_empty());
        if template.is_none() && !s.allow_task_override {
            return Err(ApiError::UnprocessableEntity(format!(
                "subscriptions[{}]: provide a task_template or set allow_task_override",
                s.slot
            )));
        }
        if ConcurrencyPolicy::parse(&s.concurrency_policy).is_none() {
            return Err(ApiError::UnprocessableEntity(format!(
                "subscriptions[{}]: concurrency_policy must be allow | skip_if_running | replace",
                s.slot
            )));
        }
        // Event wiring: mirror the trigger-create checks so recipe deploys
        // refuse the same dead config the manual path refuses.
        let (connection_id, resource_selector, event_filter, event_publish) = match s.kind.as_str()
        {
            "event" => {
                let cid = s
                    .connection_id
                    .as_deref()
                    .and_then(|c| Uuid::parse_str(c).ok())
                    .ok_or_else(|| {
                        ApiError::UnprocessableEntity(format!(
                            "subscriptions[{}]: connection must resolve to a connection id",
                            s.slot
                        ))
                    })?;
                let mut tx = fluidbox_db::scoped_tx(&state.pool, scope).await?;
                let conn = fluidbox_db::get_connection(&mut *tx, scope, cid).await?;
                tx.commit().await?;
                let conn = conn.ok_or_else(|| {
                    ApiError::UnprocessableEntity(format!(
                        "subscriptions[{}]: unknown connection {cid}",
                        s.slot
                    ))
                })?;
                if conn.status != "active" {
                    return Err(ApiError::UnprocessableEntity(format!(
                        "subscriptions[{}]: connection is {} — reconnect it first",
                        s.slot, conn.status
                    )));
                }
                let connector =
                    crate::connectors::connector_for(&conn.provider).ok_or_else(|| {
                        ApiError::UnprocessableEntity(format!(
                            "subscriptions[{}]: provider '{}' has no event connector",
                            s.slot, conn.provider
                        ))
                    })?;
                let can_receive = match conn.registration_id {
                    Some(rid) => fluidbox_db::github_app_registration_webhook_secret_sealed(
                        &state.pool,
                        scope,
                        rid,
                    )
                    .await?
                    .is_some(),
                    None => {
                        fluidbox_db::connection_webhook_secret_sealed(&state.pool, scope, cid)
                            .await?
                            .is_some()
                    }
                };
                if !can_receive {
                    return Err(ApiError::UnprocessableEntity(format!(
                        "subscriptions[{}]: this connection cannot receive events (no webhook secret) — connect a github_app",
                        s.slot
                    )));
                }
                let supported = crate::connectors::supported_events(connector);
                let events: Vec<String> = match &s.events {
                    None => crate::connectors::default_events(connector),
                    Some(list) if list.is_empty() => {
                        return Err(ApiError::UnprocessableEntity(format!(
                            "subscriptions[{}]: events must not be empty",
                            s.slot
                        )))
                    }
                    Some(list) => {
                        for e in list {
                            if !supported.contains(&e.as_str()) {
                                return Err(ApiError::UnprocessableEntity(format!(
                                    "subscriptions[{}]: unsupported event '{e}' (supported: {})",
                                    s.slot,
                                    supported.join(", ")
                                )));
                            }
                        }
                        list.clone()
                    }
                };
                let modes = crate::connectors::publish_modes(connector);
                let publish: Vec<String> = match &s.publish {
                    None => vec!["pr_comment".to_string()],
                    Some(list) => {
                        for m in list {
                            if !modes.contains(&m.as_str()) {
                                return Err(ApiError::UnprocessableEntity(format!(
                                    "subscriptions[{}]: unsupported publish mode '{m}' (supported: {})",
                                    s.slot,
                                    modes.join(", ")
                                )));
                            }
                        }
                        list.clone()
                    }
                };
                if s.repositories.is_empty() {
                    return Err(ApiError::UnprocessableEntity(format!(
                        "subscriptions[{}]: event subscriptions need at least one repository",
                        s.slot
                    )));
                }
                for r in &s.repositories {
                    if !api::valid_repo_name(r) {
                        return Err(ApiError::UnprocessableEntity(format!(
                            "subscriptions[{}]: repository must be 'owner/name' (got '{r}')",
                            s.slot
                        )));
                    }
                }
                let tpl = template.ok_or_else(|| {
                    ApiError::UnprocessableEntity(format!(
                        "subscriptions[{}]: an event subscription needs a task_template",
                        s.slot
                    ))
                })?;
                render_task_template(tpl, &crate::connectors::sample_context(connector)).map_err(
                    |e| {
                        ApiError::UnprocessableEntity(format!(
                            "subscriptions[{}]: task_template must render from the event context: {e}",
                            s.slot
                        ))
                    },
                )?;
                (
                    Some(cid),
                    Some(json!({ "repositories": s.repositories })),
                    Some(json!({ "events": events })),
                    Some(json!(publish)),
                )
            }
            _ => (None, None, None, None),
        };
        let schedule = match (&s.kind[..], &s.schedule) {
            ("schedule", Some(sc)) => {
                let cron = CronSchedule::parse(&sc.cron, &sc.timezone).map_err(|e| {
                    ApiError::UnprocessableEntity(format!("subscriptions[{}]: {e}", s.slot))
                })?;
                if MissedRunPolicy::parse(&sc.missed_run_policy).is_none() {
                    return Err(ApiError::UnprocessableEntity(format!(
                        "subscriptions[{}]: missed_run_policy must be skip | catch_up",
                        s.slot
                    )));
                }
                let tpl = template.ok_or_else(|| {
                    ApiError::UnprocessableEntity(format!(
                        "subscriptions[{}]: a schedule needs a task_template",
                        s.slot
                    ))
                })?;
                render_task_template(tpl, &schedule_context("2026-01-01T00:00:00Z")).map_err(
                    |e| {
                        ApiError::UnprocessableEntity(format!(
                            "subscriptions[{}]: task_template must render from the schedule context: {e}",
                            s.slot
                        ))
                    },
                )?;
                let first = cron.next_fire_after(chrono::Utc::now()).ok_or_else(|| {
                    ApiError::UnprocessableEntity(format!(
                        "subscriptions[{}]: cron expression never fires in the future",
                        s.slot
                    ))
                })?;
                Some((
                    sc.cron.trim().to_string(),
                    sc.timezone.clone(),
                    sc.missed_run_policy.clone(),
                    first,
                ))
            }
            _ => None,
        };
        let (destinations, callback_secret) = match &s.callback_url {
            None => (json!([]), None),
            Some(url) => {
                if !(url.starts_with("http://") || url.starts_with("https://")) {
                    return Err(ApiError::UnprocessableEntity(format!(
                        "subscriptions[{}]: callback_url must be http(s)",
                        s.slot
                    )));
                }
                crate::egress::admit_url(url, &state.egress_policy).map_err(|e| {
                    ApiError::UnprocessableEntity(format!(
                        "subscriptions[{}]: callback_url rejected: {e}",
                        s.slot
                    ))
                })?;
                let sealer = state.sealer.as_ref().ok_or_else(|| {
                    ApiError::BadRequest(
                        "signed callbacks are disabled: set FLUIDBOX_CREDENTIAL_KEY on the server"
                            .into(),
                    )
                })?;
                let secret = random_hex_token(SECRET_PREFIX);
                let sealed = sealer
                    .seal(
                        &secret,
                        crate::seal::SealCtx::new(
                            scope.tenant_id(),
                            crate::seal::SealFamily::SubscriptionCallbackSecret,
                        ),
                    )
                    .await?;
                let dests = serde_json::to_value(vec![ResultDestination::SignedWebhook {
                    url: url.clone(),
                    binding_id: None,
                }])?;
                (dests, Some((secret, sealed)))
            }
        };
        let workspace = match s.workspace {
            None => None,
            Some(w) => Some(resolve_workspace(state, principal, &s.slot, w).await?),
        };
        let budget_override = match &s.budgets {
            None => None,
            Some(v) => {
                let b: Budgets = serde_json::from_value(v.clone()).map_err(|e| {
                    ApiError::UnprocessableEntity(format!(
                        "subscriptions[{}].budgets: {e}",
                        s.slot
                    ))
                })?;
                Some(serde_json::to_value(&b)?)
            }
        };
        // Keep-list entries must name bundles the agent actually attaches —
        // the trigger-create dead-config rule.
        let capability_keep = match &s.capabilities {
            None => None,
            Some(keep) => {
                let agent = agents.iter().find(|a| a.slot == s.agent_slot).ok_or_else(|| {
                    ApiError::Internal("subscription references unknown agent slot".into())
                })?;
                let pins: Vec<fluidbox_core::capability::BundleRef> =
                    serde_json::from_value(agent.capability_pins.clone())
                        .map_err(|e| ApiError::Internal(format!("bad rendered pins: {e}")))?;
                for name in keep {
                    if !pins.iter().any(|p| &p.name == name) {
                        return Err(ApiError::UnprocessableEntity(format!(
                            "subscriptions[{}]: keep-list names '{name}' but agent '{}' attaches no such bundle",
                            s.slot, s.agent_slot
                        )));
                    }
                }
                Some(json!(keep))
            }
        };
        subscriptions.push(PreparedSubscription {
            slot: s.slot,
            agent_slot: s.agent_slot,
            kind: s.kind,
            name: s.name,
            task_template: template.map(str::to_string),
            autonomous: s.autonomous,
            concurrency: s.concurrency_policy,
            connection_id,
            resource_selector,
            event_filter,
            event_publish,
            destinations,
            callback_secret,
            schedule,
            allow_task_override: s.allow_task_override,
            allow_workspace_override: s.allow_workspace_override,
            budget_override,
            capability_keep,
            workspace,
        });
    }

    let first_run = rendered.first_run.map(|fr| PreparedFirstRun {
        agent_slot: fr.agent_slot,
        task: fr.task,
        autonomous: fr.autonomous,
    });

    // The dry-run plan: what WOULD be created, plus the governance summary —
    // the Terraform-plan step the wizard shows before the real deploy.
    let plan = json!({
        "instance": { "name": instance_name },
        "policy": policy.as_ref().map(|(name, _)| json!({ "name": name })),
        "agents": agents.iter().map(|a| json!({
            "slot": a.slot, "name": a.name, "harness": a.harness, "model": a.model,
            "budgets": a.budgets,
        })).collect::<Vec<_>>(),
        "subscriptions": subscriptions.iter().map(|s| json!({
            "slot": s.slot, "name": s.name, "kind": s.kind,
            "agent_slot": s.agent_slot,
            "events": s.event_filter, "repositories": s.resource_selector,
            "publish": s.event_publish,
            "schedule": s.schedule.as_ref().map(|(c, tz, m, first)| json!({
                "cron": c, "timezone": tz, "missed_run_policy": m, "first_fire_at": first })),
            "signed_webhook": s.callback_secret.is_some(),
            "autonomous": s.autonomous,
        })).collect::<Vec<_>>(),
        "first_run": first_run.as_ref().map(|f| json!({ "agent_slot": f.agent_slot })),
        "cost_ceiling_usd": agents.iter().filter_map(|a|
            a.budgets.get("max_cost_usd").and_then(Value::as_f64)).sum::<f64>(),
        "policy_summary": policy_summary(def)?,
    });

    Ok(Prepared {
        effective_params: Map::new(), // filled by prepare()
        params_digest: String::new(), // filled by prepare()
        policy,
        agents,
        subscriptions,
        first_run,
        plan,
    })
}

async fn resolve_workspace(
    state: &AppState,
    principal: &Principal,
    slot: &str,
    rendered: Value,
) -> ApiResult<Value> {
    let input: api::WorkspaceInput = serde_json::from_value(rendered).map_err(|e| {
        ApiError::UnprocessableEntity(format!("[{slot}].workspace does not parse: {e}"))
    })?;
    let spec = api::resolve_workspace_input(
        state,
        principal.scope(),
        fluidbox_db::ConnectionViewer::All,
        api::LocalPathAuthority::of(principal),
        input,
    )
    .await?;
    match spec {
        WorkspaceSpec::Scratch => Ok(json!(null)),
        spec => Ok(serde_json::to_value(&spec)?),
    }
}

pub async fn deploy(
    principal: Principal,
    State(state): State<AppState>,
    Path(slug): Path<String>,
    Json(body): Json<DeployBody>,
) -> ApiResult<(axum::http::StatusCode, Json<Value>)> {
    if !rbac::can_deploy_recipes(&principal) {
        return Err(ApiError::Forbidden(
            "deploying recipes requires admin or owner".into(),
        ));
    }
    let scope = principal.scope();
    let name = validate_instance_name(&body.name)?;
    let (recipe_row, version) = db::get_recipe_by_slug(&state.pool, scope, &slug)
        .await?
        .ok_or(ApiError::NotFound)?;
    let prepared = prepare(&state, &principal, &version, name, &body.params).await?;

    if body.dry_run {
        return Ok((axum::http::StatusCode::OK, Json(json!({ "plan": prepared.plan }))));
    }

    // Resolve the fallback policy id BEFORE the stamp so the transaction does
    // only writes.
    let fallback_policy = match prepared.policy {
        Some(_) => None,
        None => Some(
            fluidbox_db::get_policy_by_name(&state.pool, scope, "default")
                .await?
                .ok_or_else(|| {
                    ApiError::Internal("the 'default' policy is missing from this tenant".into())
                })?,
        ),
    };

    // ── THE ATOMIC STAMP ──
    let mut tx = fluidbox_db::scoped_tx(&state.pool, scope).await?;
    let stamp: Result<_, ApiError> = async {
        let policy_id = match &prepared.policy {
            Some((pname, content)) => {
                let (row, _) = fluidbox_db::create_policy_tx(
                    &mut tx,
                    scope.tenant_id(),
                    pname,
                    fluidbox_db::NewPolicyVersion {
                        content,
                        yaml_source: None,
                        summary: Some("stamped by recipe deploy"),
                        author: "api",
                        author_user_id: principal.user_id(),
                    },
                )
                .await?;
                row.id
            }
            None => fallback_policy.as_ref().expect("resolved above").id,
        };
        let mut agent_ids: HashMap<String, Uuid> = HashMap::new();
        let mut objects: Vec<Value> = Vec::new();
        if prepared.policy.is_some() {
            objects.push(json!({ "kind": "policy", "id": policy_id, "slot": "policy" }));
        }
        for a in &prepared.agents {
            let agent: fluidbox_db::AgentRow = sqlx::query_as(
                "insert into agents (id, tenant_id, name, description)
                 values ($1, $2, $3, $4) returning *",
            )
            .bind(Uuid::now_v7())
            .bind(scope.tenant_id())
            .bind(&a.name)
            .bind(format!("recipe: {} · {}", recipe_row.slug, a.slot))
            .fetch_one(&mut *tx)
            .await?;
            fluidbox_db::append_agent_revision_tx(
                &mut tx,
                scope.tenant_id(),
                agent.id,
                &a.harness,
                &a.runner_image,
                &a.model,
                a.system_prompt.as_deref(),
                policy_id,
                &a.budgets,
                a.default_workspace.as_ref().filter(|w| !w.is_null()),
                &a.capability_pins,
                &a.requirements,
            )
            .await?;
            agent_ids.insert(a.slot.clone(), agent.id);
            objects.push(json!({ "kind": "agent", "id": agent.id, "slot": a.slot, "name": a.name }));
        }
        let mut secrets_tokens: Map<String, Value> = Map::new();
        let mut secrets_callbacks: Map<String, Value> = Map::new();
        let mut sub_rows: Vec<(String, fluidbox_db::TriggerSubscriptionRow)> = Vec::new();
        for s in &prepared.subscriptions {
            let agent_id = *agent_ids
                .get(&s.agent_slot)
                .ok_or_else(|| ApiError::Internal("agent slot vanished".into()))?;
            let sealed_owned = s.callback_secret.as_ref().map(|(_, sealed)| crate::seal::Sealed {
                bytes: sealed.bytes.clone(),
                key_version: sealed.key_version,
            });
            let (cb_bytes, cb_kv) = crate::seal::Sealed::split(&sealed_owned);
            let sub = fluidbox_db::create_trigger_subscription_tx(
                &mut tx,
                scope.tenant_id(),
                agent_id,
                &s.name,
                &s.kind,
                None,
                s.task_template.as_deref(),
                s.allow_task_override,
                s.allow_workspace_override,
                s.autonomous.then_some("autonomous"),
                &s.concurrency,
                s.budget_override.as_ref(),
                s.workspace.as_ref().filter(|w| !w.is_null()),
                &s.destinations,
                cb_bytes,
                cb_kv,
                s.connection_id,
                s.resource_selector.as_ref(),
                s.event_filter.as_ref(),
                s.event_publish.as_ref(),
                s.capability_keep.as_ref(),
            )
            .await?;
            let token = random_hex_token(TOKEN_PREFIX);
            fluidbox_db::create_trigger_token_tx(&mut tx, scope.tenant_id(), sub.id, &token)
                .await?;
            secrets_tokens.insert(s.slot.clone(), json!(token));
            if let Some((secret, _)) = &s.callback_secret {
                secrets_callbacks.insert(s.slot.clone(), json!(secret));
            }
            if let Some((cron, tz, missed, first)) = &s.schedule {
                fluidbox_db::create_schedule_tx(
                    &mut tx,
                    scope.tenant_id(),
                    sub.id,
                    cron,
                    tz,
                    *first,
                    missed,
                )
                .await?;
            }
            objects.push(json!({ "kind": "subscription", "id": sub.id, "slot": s.slot,
                                 "name": s.name, "trigger_kind": s.kind }));
            sub_rows.push((s.slot.clone(), sub));
        }
        let instance = db::create_recipe_instance_tx(
            &mut tx,
            scope.tenant_id(),
            recipe_row.id,
            &recipe_row.slug,
            version.version,
            name,
            &Value::Object(prepared.effective_params.clone()),
            &prepared.params_digest,
            principal.user_id(),
        )
        .await?;
        for o in &objects {
            db::insert_instance_object_tx(
                &mut tx,
                scope.tenant_id(),
                instance.id,
                o["kind"].as_str().unwrap_or(""),
                o["id"]
                    .as_str()
                    .and_then(|s| Uuid::parse_str(s).ok())
                    .unwrap_or_default(),
                o["slot"].as_str().unwrap_or(""),
            )
            .await?;
        }
        Ok((instance, objects, secrets_tokens, secrets_callbacks, sub_rows))
    }
    .await;

    let (instance, objects, tokens, callbacks, sub_rows) = match stamp {
        Ok(v) => {
            tx.commit().await?;
            v
        }
        Err(e) => {
            // Rollback is implicit on drop, but be explicit: nothing survives
            // a failed stamp.
            let _ = tx.rollback().await;
            return Err(match e {
                ApiError::Db(db_err) => match &db_err {
                    sqlx::Error::Database(d) if d.is_unique_violation() => ApiError::Conflict(
                        format!(
                            "a deployment named '{name}' (or an object it would create) already exists — pick a different name"
                        ),
                    ),
                    _ => ApiError::Db(db_err),
                },
                other => other,
            });
        }
    };

    tracing::info!(
        instance = %instance.id, recipe = %recipe_row.slug, version = version.version,
        objects = objects.len(), "recipe deployed"
    );

    // First run — AFTER the commit; a failure reports on the response and the
    // instance page, never unwinds the deploy.
    let first_run = match &prepared.first_run {
        None => None,
        Some(fr) => {
            let agent_obj = objects.iter().find(|o| {
                o["kind"] == json!("agent") && o["slot"] == json!(fr.agent_slot.as_str())
            });
            match agent_obj.and_then(|o| o["id"].as_str()) {
                None => Some(json!({ "error": "first-run agent slot missing" })),
                Some(agent_id) => Some(
                    start_instance_run(
                        &state,
                        &principal,
                        &instance,
                        agent_id,
                        &fr.task,
                        fr.autonomous,
                    )
                    .await,
                ),
            }
        }
    };

    // Per-subscription contract URLs (api-kind deployments are driven by
    // external callers; the invoke/poll contract belongs in the response).
    let contracts: Vec<Value> = sub_rows
        .iter()
        .map(|(slot, sub)| {
            let mut m = contract_urls(&state.cfg.public_url, sub.id, None);
            m.insert("slot".into(), json!(slot));
            m.insert("subscription_id".into(), json!(sub.id));
            Value::Object(m)
        })
        .collect();

    Ok((
        axum::http::StatusCode::CREATED,
        Json(json!({
            "instance": instance,
            "objects": objects,
            "plan": prepared.plan,
            "secrets": {
                "note": "shown once — store them now",
                "trigger_tokens": tokens,
                "callback_secrets": callbacks,
            },
            "contracts": contracts,
            "first_run": first_run,
        })),
    ))
}

/// Start a run for an instance through the ONE funnel. Returns a JSON blob
/// (session id or error) — callers surface it, they never fail on it.
async fn start_instance_run(
    state: &AppState,
    principal: &Principal,
    instance: &db::RecipeInstanceRow,
    agent_id: &str,
    task: &str,
    autonomous: bool,
) -> Value {
    let scope = principal.scope();
    let req = CreateRun {
        agent: agent_id.to_string(),
        revision: RevisionSelector::Latest,
        task: task.to_string(),
        explicit_workspace: None,
        local_path_authority: api::LocalPathAuthority::of(principal),
        autonomy: if autonomous {
            Autonomy::Autonomous
        } else {
            Autonomy::Supervised
        },
        trust_tier: TrustTier::Trusted,
        budget_override: None,
        capability_selection: None,
        invocation: InvocationContext {
            kind: InvocationKind::Manual,
            actor: Some(format!("recipe:{}", instance.recipe_slug)),
            attributes: json!({ "recipe_instance": instance.id }),
            received_at: Some(chrono::Utc::now()),
            ..InvocationContext::default()
        },
        invoked_by_user_id: principal.user_id(),
        invoking_token_id: None,
        explicit_bindings: HashMap::new(),
        result_destinations: vec![],
        bound_invocation: None,
        bound_dispatch: None,
    };
    match run_service::create_run(state, scope, req).await {
        Ok(RunCreation::Created(session)) => {
            if let Err(e) =
                db::record_instance_session(&state.pool, scope, instance.id, session.id, "run")
                    .await
            {
                tracing::warn!(error = %e, "recipe run link not recorded");
            }
            json!({ "session_id": session.id })
        }
        Ok(RunCreation::SkippedOverlap { running_session_id }) => {
            json!({ "error": "another run of this deployment is still active",
                    "running_session_id": running_session_id })
        }
        Ok(RunCreation::ReplaceUnpersisted { .. }) => {
            json!({ "error": "could not persist the replacement — retry" })
        }
        Err(e) => json!({ "error": e.to_string() }),
    }
}

// ─── Instances ────────────────────────────────────────────────────────────

pub async fn list_instances(
    principal: Principal,
    State(state): State<AppState>,
) -> ApiResult<Json<Value>> {
    let scope = principal.scope();
    let instances = db::list_recipe_instances(&state.pool, scope).await?;
    // Latest version per recipe id, for the update_available flag.
    let latest: HashMap<Uuid, i32> = db::list_recipes(&state.pool, scope)
        .await?
        .into_iter()
        .map(|r| (r.id, r.latest_version))
        .collect();
    let out: Vec<Value> = instances
        .into_iter()
        .map(|i| {
            let newest = latest.get(&i.recipe_id).copied().unwrap_or(i.recipe_version);
            json!({
                "instance": i,
                "latest_version": newest,
                "update_available": newest > i.recipe_version,
            })
        })
        .collect();
    Ok(Json(json!({ "instances": out })))
}

pub async fn get_instance(
    principal: Principal,
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<Value>> {
    let scope = principal.scope();
    let instance = db::get_recipe_instance(&state.pool, scope, id)
        .await?
        .ok_or(ApiError::NotFound)?;
    let objects = db::instance_objects_detailed(&state.pool, scope, id).await?;
    // Recent runs: subscription-borrowed sessions + directly linked
    // (first-run / run-now) sessions, merged newest-first.
    let mut session_ids: Vec<Uuid> = Vec::new();
    let mut sessions: Vec<fluidbox_db::SessionRow> = Vec::new();
    for o in &objects {
        match o.kind.as_str() {
            "subscription" => {
                sessions.extend(
                    fluidbox_db::list_subscription_sessions(&state.pool, scope, o.object_id, 10)
                        .await?,
                );
            }
            "session" => session_ids.push(o.object_id),
            _ => {}
        }
    }
    sessions.extend(db::sessions_by_ids(&state.pool, scope, &session_ids).await?);
    sessions.sort_by_key(|s| std::cmp::Reverse(s.created_at));
    sessions.dedup_by_key(|s| s.id);
    sessions.truncate(25);
    let latest = db::get_recipe_by_slug(&state.pool, scope, &instance.recipe_slug)
        .await?
        .map(|(_, v)| v.version)
        .unwrap_or(instance.recipe_version);
    let contracts: Vec<Value> = objects
        .iter()
        .filter(|o| o.kind == "subscription")
        .map(|o| {
            let mut m = contract_urls(&state.cfg.public_url, o.object_id, None);
            m.insert("slot".into(), json!(o.slot));
            m.insert("subscription_id".into(), json!(o.object_id));
            Value::Object(m)
        })
        .collect();
    Ok(Json(json!({
        "instance": instance,
        "objects": objects,
        "sessions": sessions,
        "latest_version": latest,
        "update_available": latest > instance.recipe_version,
        "contracts": contracts,
    })))
}

async fn flip_instance(
    principal: &Principal,
    state: &AppState,
    id: Uuid,
    status: &str,
    enable_subs: bool,
) -> ApiResult<db::RecipeInstanceRow> {
    if !rbac::can_deploy_recipes(principal) {
        return Err(ApiError::Forbidden(
            "managing recipe deployments requires admin or owner".into(),
        ));
    }
    let scope = principal.scope();
    let objects = db::instance_objects(&state.pool, scope, id).await?;
    let mut tx = fluidbox_db::scoped_tx(&state.pool, scope).await?;
    let instance = db::set_instance_status_tx(&mut tx, scope.tenant_id(), id, status)
        .await?
        .ok_or(ApiError::NotFound)?;
    for o in objects.iter().filter(|o| o.kind == "subscription") {
        fluidbox_db::set_trigger_subscription_enabled_tx(
            &mut tx,
            scope.tenant_id(),
            o.object_id,
            enable_subs,
        )
        .await?;
    }
    tx.commit().await?;
    tracing::info!(instance = %id, status, "recipe instance status changed");
    Ok(instance)
}

pub async fn pause_instance(
    principal: Principal,
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<Value>> {
    let instance = flip_instance(&principal, &state, id, "paused", false).await?;
    Ok(Json(json!({ "instance": instance })))
}

pub async fn resume_instance(
    principal: Principal,
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<Value>> {
    let instance = flip_instance(&principal, &state, id, "active", true).await?;
    Ok(Json(json!({ "instance": instance })))
}

pub async fn delete_instance(
    principal: Principal,
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<Value>> {
    // Soft delete: subscriptions disabled, status recorded; stamped agents /
    // policies / runs REMAIN (append-only history other objects reference).
    let instance = flip_instance(&principal, &state, id, "deleted", false).await?;
    Ok(Json(json!({
        "instance": instance,
        "note": "subscriptions disabled; agents, policies, and run history remain"
    })))
}

pub async fn run_instance(
    principal: Principal,
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> ApiResult<(axum::http::StatusCode, Json<Value>)> {
    if !rbac::can_deploy_recipes(&principal) {
        return Err(ApiError::Forbidden(
            "running a recipe deployment requires admin or owner".into(),
        ));
    }
    let scope = principal.scope();
    let instance = db::get_recipe_instance(&state.pool, scope, id)
        .await?
        .ok_or(ApiError::NotFound)?;
    if instance.status != "active" {
        return Err(ApiError::Conflict(format!(
            "deployment is {} — resume it first",
            instance.status
        )));
    }
    // Render the INSTANCE's pinned version with its saved params — never the
    // latest (upgrade is explicit).
    let version =
        db::get_recipe_version(&state.pool, scope, instance.recipe_id, instance.recipe_version)
            .await?
            .ok_or_else(|| ApiError::Internal("instance version row missing".into()))?;
    let (def, specs) = parse_stored(&version)?;
    let Some(fr) = &def.first_run else {
        return Err(ApiError::BadRequest(
            "this deployment runs via its triggers (schedule/event/API) — it has no on-demand run"
                .into(),
        ));
    };
    let raw = instance.params.as_object().cloned().unwrap_or_default();
    let render_params = resolve_params(&state, scope, &specs, &raw).await?;
    let rendered = recipe::render_definition(
        &def,
        &RenderCtx {
            params: &render_params,
            instance_name: &instance.name,
        },
    )
    .map_err(|e| ApiError::UnprocessableEntity(format!("saved params no longer render: {e}")))?;
    let task = rendered
        .first_run
        .as_ref()
        .map(|f| f.task.clone())
        .unwrap_or_default();
    let objects = db::instance_objects(&state.pool, scope, id).await?;
    let agent = objects
        .iter()
        .find(|o| o.kind == "agent" && o.slot == fr.agent_slot)
        .ok_or_else(|| ApiError::Internal("first-run agent object missing".into()))?;
    let result = start_instance_run(
        &state,
        &principal,
        &instance,
        &agent.object_id.to_string(),
        &task,
        rendered.first_run.map(|f| f.autonomous).unwrap_or(false),
    )
    .await;
    if result.get("session_id").is_some() {
        Ok((axum::http::StatusCode::CREATED, Json(result)))
    } else {
        Err(ApiError::Conflict(
            result["error"].as_str().unwrap_or("run not started").to_string(),
        ))
    }
}

// ─── Upgrade ──────────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct UpgradeBody {
    #[serde(default)]
    pub params: Map<String, Value>,
    #[serde(default)]
    pub dry_run: bool,
}

/// Upgrade an instance to the recipe's latest version: agent revision
/// appends, a policy version append, and subscription/schedule
/// mutable-surface updates, applied in one transaction. STRUCTURAL changes
/// (added/removed slots; kind/connection/events/publish/destination changes)
/// are refused with a 422 naming the difference — redeploy as a new instance
/// for those (design §7: detached instances, explicit manual upgrade, never a
/// re-render).
pub async fn upgrade_instance(
    principal: Principal,
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    Json(body): Json<UpgradeBody>,
) -> ApiResult<Json<Value>> {
    if !rbac::can_deploy_recipes(&principal) {
        return Err(ApiError::Forbidden(
            "upgrading recipe deployments requires admin or owner".into(),
        ));
    }
    let scope = principal.scope();
    let instance = db::get_recipe_instance(&state.pool, scope, id)
        .await?
        .ok_or(ApiError::NotFound)?;
    if instance.status == "deleted" {
        return Err(ApiError::Conflict("deployment is deleted".into()));
    }
    let (_recipe_row, latest) = db::get_recipe_by_slug(&state.pool, scope, &instance.recipe_slug)
        .await?
        .ok_or_else(|| ApiError::Conflict("the recipe behind this deployment is gone".into()))?;
    if latest.version <= instance.recipe_version {
        return Err(ApiError::Conflict(format!(
            "already at the latest version (v{})",
            instance.recipe_version
        )));
    }
    // Merge: saved params, overlaid by any caller-supplied updates (new
    // required params arrive here).
    let mut merged = instance.params.as_object().cloned().unwrap_or_default();
    for (k, v) in &body.params {
        merged.insert(k.clone(), v.clone());
    }
    let prepared = prepare(&state, &principal, &latest, &instance.name, &merged).await?;

    let objects = db::instance_objects(&state.pool, scope, id).await?;
    let by_slot = |kind: &str| -> HashMap<String, Uuid> {
        objects
            .iter()
            .filter(|o| o.kind == kind)
            .map(|o| (o.slot.clone(), o.object_id))
            .collect()
    };
    let stamped_agents = by_slot("agent");
    let stamped_subs = by_slot("subscription");
    let stamped_policy = objects.iter().find(|o| o.kind == "policy").map(|o| o.object_id);

    // Structural guard: slot sets must match exactly.
    let new_agents: BTreeSet<&str> = prepared.agents.iter().map(|a| a.slot.as_str()).collect();
    let old_agents: BTreeSet<&str> = stamped_agents.keys().map(String::as_str).collect();
    if new_agents != old_agents {
        return Err(ApiError::UnprocessableEntity(format!(
            "structural change: agent slots differ (deployed: {:?}, new: {:?}) — deploy the new version as a fresh instance",
            old_agents, new_agents
        )));
    }
    let new_subs: BTreeSet<&str> = prepared
        .subscriptions
        .iter()
        .map(|s| s.slot.as_str())
        .collect();
    let old_subs: BTreeSet<&str> = stamped_subs.keys().map(String::as_str).collect();
    if new_subs != old_subs {
        return Err(ApiError::UnprocessableEntity(format!(
            "structural change: subscription slots differ (deployed: {:?}, new: {:?}) — deploy the new version as a fresh instance",
            old_subs, new_subs
        )));
    }
    if prepared.policy.is_some() != stamped_policy.is_some() {
        return Err(ApiError::UnprocessableEntity(
            "structural change: the new version adds or removes the embedded policy — redeploy".into(),
        ));
    }

    // Per-subscription structural guard + change set.
    let mut sub_changes: Vec<Value> = Vec::new();
    let mut sub_updates: Vec<(Uuid, &PreparedSubscription, bool)> = Vec::new();
    for s in &prepared.subscriptions {
        let sub_id = stamped_subs[&s.slot];
        let current = fluidbox_db::get_trigger_subscription(&state.pool, scope, sub_id)
            .await?
            .ok_or_else(|| ApiError::Internal("stamped subscription missing".into()))?;
        let structural_diff = |what: &str| {
            ApiError::UnprocessableEntity(format!(
                "structural change on subscription '{}': {what} differs — deploy the new version as a fresh instance",
                s.slot
            ))
        };
        if current.trigger_kind != s.kind {
            return Err(structural_diff("trigger kind"));
        }
        if current.connection_id != s.connection_id {
            return Err(structural_diff("connection"));
        }
        if current.event_filter != s.event_filter {
            return Err(structural_diff("events"));
        }
        if current.event_publish != s.event_publish {
            return Err(structural_diff("publish modes"));
        }
        if current.resource_selector != s.resource_selector {
            return Err(structural_diff("repositories"));
        }
        if (current.result_destinations != json!([])) != s.callback_secret.is_some()
            && !(current.result_destinations == json!([]) && s.callback_secret.is_none())
        {
            return Err(structural_diff("signed webhook destination"));
        }
        let mutable_changed = current.name != s.name
            || current.task_template.as_deref() != s.task_template.as_deref()
            || current.allow_task_override != s.allow_task_override
            || current.allow_workspace_override != s.allow_workspace_override
            || current.concurrency_policy != s.concurrency;
        let cadence_changed = match (&s.schedule, s.kind.as_str()) {
            (Some((cron, tz, missed, _)), "schedule") => {
                let sched = fluidbox_db::schedule_for_subscription(&state.pool, scope, sub_id)
                    .await?
                    .ok_or_else(|| ApiError::Internal("stamped schedule missing".into()))?;
                sched.cron != *cron
                    || sched.timezone != *tz
                    || sched.missed_run_policy != *missed
            }
            _ => false,
        };
        if mutable_changed || cadence_changed {
            sub_changes.push(json!({ "slot": s.slot, "updated": true }));
            sub_updates.push((sub_id, s, cadence_changed));
        }
    }

    // Agent change set: compare rendered vs current latest revision.
    let mut agent_updates: Vec<(&PreparedAgent, Uuid)> = Vec::new();
    for a in &prepared.agents {
        let agent_id = stamped_agents[&a.slot];
        let current = fluidbox_db::latest_revision(&state.pool, scope, agent_id)
            .await?
            .ok_or_else(|| ApiError::Internal("stamped agent has no revision".into()))?;
        let changed = current.harness != a.harness
            || current.model != a.model
            || current.system_prompt.as_deref() != a.system_prompt.as_deref()
            || current.budgets != a.budgets
            || current.capability_bundles != a.capability_pins
            || current.connection_requirements != a.requirements
            || current.default_workspace.as_ref()
                != a.default_workspace.as_ref().filter(|w| !w.is_null());
        if changed {
            agent_updates.push((a, agent_id));
        }
    }

    // Policy change: compare latest stamped version's content to the rendered.
    let policy_update = match (&prepared.policy, stamped_policy) {
        (Some((_, content)), Some(pid)) => {
            let head = fluidbox_db::latest_policy_version(&state.pool, scope, pid).await?;
            match head {
                Some(v) if &v.content == content => None,
                _ => Some((pid, content.clone())),
            }
        }
        _ => None,
    };

    let plan = json!({
        "from_version": instance.recipe_version,
        "to_version": latest.version,
        "agents_updated": agent_updates.iter().map(|(a, _)| a.slot.clone()).collect::<Vec<_>>(),
        "subscriptions_updated": sub_changes,
        "policy_updated": policy_update.is_some(),
    });
    if body.dry_run {
        return Ok(Json(json!({ "plan": plan })));
    }

    let mut tx = fluidbox_db::scoped_tx(&state.pool, scope).await?;
    for (a, agent_id) in &agent_updates {
        // The policy id on the NEW revision: the stamped policy when the
        // recipe embeds one, else the revision keeps its current policy.
        let policy_id = match stamped_policy {
            Some(pid) => pid,
            None => {
                fluidbox_db::latest_revision(&state.pool, scope, *agent_id)
                    .await?
                    .ok_or_else(|| ApiError::Internal("revision vanished".into()))?
                    .policy_id
            }
        };
        fluidbox_db::append_agent_revision_tx(
            &mut tx,
            scope.tenant_id(),
            *agent_id,
            &a.harness,
            &a.runner_image,
            &a.model,
            a.system_prompt.as_deref(),
            policy_id,
            &a.budgets,
            a.default_workspace.as_ref().filter(|w| !w.is_null()),
            &a.capability_pins,
            &a.requirements,
        )
        .await?;
    }
    if let Some((pid, content)) = &policy_update {
        fluidbox_db::append_policy_version_tx(
            &mut tx,
            scope.tenant_id(),
            *pid,
            None,
            fluidbox_db::NewPolicyVersion {
                content,
                yaml_source: None,
                summary: Some("recipe upgrade"),
                author: "api",
                author_user_id: principal.user_id(),
            },
        )
        .await?;
    }
    for (sub_id, s, cadence_changed) in &sub_updates {
        db::update_subscription_recipe_tx(
            &mut tx,
            scope.tenant_id(),
            *sub_id,
            &s.name,
            s.task_template.as_deref(),
            s.allow_task_override,
            s.allow_workspace_override,
            &s.concurrency,
        )
        .await?;
        if let Some((cron, tz, missed, first)) = &s.schedule {
            db::update_schedule_cadence_tx(
                &mut tx,
                scope.tenant_id(),
                *sub_id,
                cron,
                tz,
                missed,
                cadence_changed.then_some(*first),
            )
            .await?;
        }
    }
    let updated = db::bump_instance_version_tx(
        &mut tx,
        scope.tenant_id(),
        id,
        latest.version,
        &Value::Object(prepared.effective_params.clone()),
        &prepared.params_digest,
    )
    .await?
    .ok_or(ApiError::NotFound)?;
    tx.commit().await?;
    tracing::info!(instance = %id, from = instance.recipe_version, to = latest.version,
                   "recipe instance upgraded");
    Ok(Json(json!({ "instance": updated, "plan": plan })))
}
