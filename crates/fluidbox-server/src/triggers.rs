//! API trigger subscriptions & scoped invocation (design doc §3.5/§6.1).
//! A trigger borrows an agent: it can start only the runs its subscription
//! allows and nothing else. §17 #6 (settled): caller task/workspace
//! overrides are opt-in per subscription, default OFF.

use crate::auth::{Admin, TriggerAuth};
use crate::error::{ApiError, ApiResult};
use crate::state::AppState;
use axum::extract::{Path, State};
use axum::http::HeaderMap;
use axum::Json;
use fluidbox_core::schedule::{ConcurrencyPolicy, CronSchedule, MissedRunPolicy};
use fluidbox_core::spec::{
    Autonomy, Budgets, InvocationContext, InvocationKind, ResultDestination, WorkspaceSpec,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use uuid::Uuid;

/// The only workspace fields an external caller may send: pick a repository
/// / ref / commit within the subscription's authority. Deliberately NO
/// `connection_id`, `clone_url`, or local path — those would widen it.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct InvokeWorkspace {
    #[serde(default)]
    pub repository: Option<String>,
    #[serde(default)]
    pub r#ref: Option<String>,
    #[serde(default)]
    pub commit_sha: Option<String>,
}

/// `{{key}}` substitution from the invocation context. Strict: an unknown
/// key or unclosed brace is an error — a silently-empty hole in an agent
/// task is worse than a 400.
pub fn render_task_template(
    template: &str,
    ctx: &BTreeMap<String, String>,
) -> Result<String, String> {
    let mut out = String::with_capacity(template.len());
    let mut rest = template;
    while let Some(i) = rest.find("{{") {
        out.push_str(&rest[..i]);
        let after = &rest[i + 2..];
        let Some(j) = after.find("}}") else {
            return Err("task_template has an unclosed '{{'".into());
        };
        let key = after[..j].trim();
        match ctx.get(key) {
            Some(v) => out.push_str(v),
            None => {
                return Err(format!(
                    "task_template references '{{{{{key}}}}}' but the invocation context has no '{key}'"
                ))
            }
        }
        rest = &after[j + 2..];
    }
    out.push_str(rest);
    Ok(out)
}

/// The template context a schedule firing renders with. Kept deliberately
/// small: schedules have no external caller, so `fire_time` (RFC3339 UTC)
/// is the only variable input.
pub fn schedule_context(fire_time: &str) -> BTreeMap<String, String> {
    BTreeMap::from([("fire_time".to_string(), fire_time.to_string())])
}

/// Subscription-stored run parameters shared by every borrow path (API
/// invoke and schedule firing).
pub struct SubRunParams {
    pub autonomy: Autonomy,
    pub budget_override: Option<Budgets>,
    pub result_destinations: Vec<ResultDestination>,
    /// The subscription's workspace override, if any.
    pub workspace: Option<WorkspaceSpec>,
}

pub fn sub_run_params(sub: &fluidbox_db::TriggerSubscriptionRow) -> ApiResult<SubRunParams> {
    let autonomy = match sub.autonomy.as_deref() {
        Some("autonomous") => Autonomy::Autonomous,
        _ => Autonomy::Supervised,
    };
    let budget_override: Option<Budgets> = sub
        .budget_override
        .as_ref()
        .map(|v| serde_json::from_value(v.clone()))
        .transpose()
        .map_err(|e| ApiError::Internal(format!("bad stored budget override: {e}")))?;
    let result_destinations: Vec<ResultDestination> =
        serde_json::from_value(sub.result_destinations.clone())
            .map_err(|e| ApiError::Internal(format!("bad stored destinations: {e}")))?;
    let workspace: Option<WorkspaceSpec> = sub
        .workspace_override
        .as_ref()
        .map(|v| serde_json::from_value(v.clone()))
        .transpose()
        .map_err(|e| ApiError::Internal(format!("bad stored subscription workspace: {e}")))?;
    Ok(SubRunParams {
        autonomy,
        budget_override,
        result_destinations,
        workspace,
    })
}

/// Narrow a git workspace within the subscription's authority: swap the
/// repository (github + same connection only) and/or pin ref/commit. The
/// base comes from the subscription or the agent revision — never from the
/// caller — so the result can only ever be a subset of configured authority.
pub fn narrow_workspace(
    base: &WorkspaceSpec,
    req: &InvokeWorkspace,
) -> Result<WorkspaceSpec, String> {
    let WorkspaceSpec::GitRepository {
        connection_id,
        repository,
        clone_url,
        r#ref,
        commit_sha,
        checkout_mode,
    } = base
    else {
        return Err(
            "this subscription's workspace is not a git repository — nothing to narrow".into(),
        );
    };
    if let Some(sha) = &req.commit_sha {
        if sha.len() < 7 || sha.len() > 40 || !sha.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(format!("invalid commit_sha '{sha}'"));
        }
    }
    let (repository, clone_url) = match &req.repository {
        None => (repository.clone(), clone_url.clone()),
        Some(repo) => {
            if !crate::api::valid_repo_name(repo) {
                return Err(format!("repository must be 'owner/name' (got '{repo}')"));
            }
            // A repo swap is only meaningful inside a github-backed base;
            // retargeting an arbitrary clone_url would escape it.
            if connection_id.is_none() && !clone_url.starts_with("https://github.com/") {
                return Err("cannot retarget a non-github workspace".into());
            }
            (Some(repo.clone()), format!("https://github.com/{repo}.git"))
        }
    };
    Ok(WorkspaceSpec::GitRepository {
        connection_id: *connection_id,
        repository,
        clone_url,
        r#ref: req.r#ref.clone().or_else(|| r#ref.clone()),
        commit_sha: req.commit_sha.clone().or_else(|| commit_sha.clone()),
        checkout_mode: *checkout_mode,
    })
}

/// Canonical request digest for Idempotency-Key reuse detection. BTreeMap
/// gives key-order independence; same semantic body → same digest.
pub fn canonical_digest(
    task: &Option<String>,
    context: &BTreeMap<String, String>,
    workspace: &Option<InvokeWorkspace>,
) -> String {
    #[derive(Serialize)]
    struct Canonical<'a> {
        task: &'a Option<String>,
        context: &'a BTreeMap<String, String>,
        workspace: &'a Option<InvokeWorkspace>,
    }
    fluidbox_db::sha256_hex(
        &serde_json::to_string(&Canonical {
            task,
            context,
            workspace,
        })
        .expect("canonical body serializes"),
    )
}

// ─── Admin: subscription management ───────────────────────────────────────

const TOKEN_PREFIX: &str = "fbx_trig_";
const SECRET_PREFIX: &str = "fbx_whsec_";

fn random_hex_token(prefix: &str) -> String {
    // 2 × v4 uuid = 256 bits of entropy, no extra deps (same trick as
    // orchestrator::uuid_token).
    format!(
        "{prefix}{}{}",
        Uuid::new_v4().simple(),
        Uuid::new_v4().simple()
    )
}

#[derive(Deserialize)]
pub struct CreateTrigger {
    /// Agent id or name.
    pub agent: String,
    pub name: String,
    #[serde(default)]
    pub task_template: Option<String>,
    #[serde(default)]
    pub allow_task_override: bool,
    #[serde(default)]
    pub allow_workspace_override: bool,
    #[serde(default)]
    pub autonomous: bool,
    #[serde(default)]
    pub budgets: Option<Budgets>,
    /// Subscription-level workspace (validated like any workspace input).
    #[serde(default)]
    pub workspace: Option<crate::api::WorkspaceInput>,
    /// Pre-registered signed-webhook destination (design §6.1: destinations
    /// are approved at subscription time, never invented by the caller).
    #[serde(default)]
    pub callback_url: Option<String>,
    /// Pin the run to a specific revision id; omitted = always latest.
    #[serde(default)]
    pub pinned_revision_id: Option<Uuid>,
    /// allow (default) | skip_if_running | replace — enforced for ALL
    /// invocations of this subscription (§17 #5).
    #[serde(default)]
    pub concurrency_policy: Option<String>,
    /// Attach a clock: the subscription becomes trigger_kind='schedule'.
    #[serde(default)]
    pub schedule: Option<ScheduleInput>,
}

#[derive(Deserialize)]
pub struct ScheduleInput {
    pub cron: String,
    /// IANA name; defaults to UTC. Explicit so next-fire is DST-correct.
    #[serde(default)]
    pub timezone: Option<String>,
    /// skip (default) | catch_up (§17 #5).
    #[serde(default)]
    pub missed_run_policy: Option<String>,
}

pub async fn create(
    _: Admin,
    State(state): State<AppState>,
    Json(req): Json<CreateTrigger>,
) -> ApiResult<Json<Value>> {
    let name = req.name.trim();
    if name.is_empty() {
        return Err(ApiError::BadRequest("name is required".into()));
    }
    let agent = match Uuid::parse_str(&req.agent) {
        Ok(id) => fluidbox_db::get_agent(&state.pool, id).await?,
        Err(_) => fluidbox_db::get_agent_by_name(&state.pool, state.tenant_id, &req.agent).await?,
    }
    .filter(|a| a.tenant_id == state.tenant_id)
    .ok_or_else(|| ApiError::BadRequest(format!("unknown agent '{}'", req.agent)))?;
    if let Some(rid) = req.pinned_revision_id {
        fluidbox_db::get_revision(&state.pool, rid)
            .await?
            .filter(|r| r.agent_id == agent.id)
            .ok_or_else(|| {
                ApiError::BadRequest(format!("revision {rid} does not belong to this agent"))
            })?;
    }
    // A subscription that can never produce a task is dead config.
    let template = req
        .task_template
        .as_deref()
        .map(str::trim)
        .filter(|t| !t.is_empty());
    if template.is_none() && !req.allow_task_override {
        return Err(ApiError::BadRequest(
            "provide a task_template or set allow_task_override".into(),
        ));
    }
    let concurrency = req.concurrency_policy.as_deref().unwrap_or("allow");
    if ConcurrencyPolicy::parse(concurrency).is_none() {
        return Err(ApiError::BadRequest(
            "concurrency_policy must be allow | skip_if_running | replace".into(),
        ));
    }
    // A schedule fires with no caller: the cron/timezone must parse, the
    // template must exist and render from the schedule context alone, and
    // there must actually be a future firing.
    let schedule_cfg = match &req.schedule {
        None => None,
        Some(s) => {
            let tz = s.timezone.as_deref().unwrap_or("UTC");
            let cron = CronSchedule::parse(&s.cron, tz).map_err(ApiError::BadRequest)?;
            let missed = s.missed_run_policy.as_deref().unwrap_or("skip");
            if MissedRunPolicy::parse(missed).is_none() {
                return Err(ApiError::BadRequest(
                    "missed_run_policy must be skip | catch_up".into(),
                ));
            }
            let tpl = template.ok_or_else(|| {
                ApiError::BadRequest("a schedule needs a task_template (there is no caller)".into())
            })?;
            render_task_template(tpl, &schedule_context("2026-01-01T00:00:00Z")).map_err(|e| {
                ApiError::BadRequest(format!(
                    "task_template must render from the schedule context ({{{{fire_time}}}}): {e}"
                ))
            })?;
            let first = cron.next_fire_after(chrono::Utc::now()).ok_or_else(|| {
                ApiError::BadRequest("cron expression never fires in the future".into())
            })?;
            Some((
                s.cron.trim().to_string(),
                tz.to_string(),
                missed.to_string(),
                first,
            ))
        }
    };
    let trigger_kind = if schedule_cfg.is_some() {
        "schedule"
    } else {
        "api"
    };
    let workspace_value = match req.workspace {
        None => None,
        Some(input) => match crate::api::resolve_workspace_input(&state, input).await? {
            WorkspaceSpec::Scratch => None,
            spec => Some(serde_json::to_value(&spec)?),
        },
    };

    // Signed-webhook destination: generate + seal the HMAC secret now;
    // the plaintext is returned exactly once, in this response.
    let (destinations, secret_plain, secret_sealed) = match &req.callback_url {
        None => (json!([]), None, None),
        Some(url) => {
            if !(url.starts_with("http://") || url.starts_with("https://")) {
                return Err(ApiError::BadRequest("callback_url must be http(s)".into()));
            }
            let sealer = state.sealer.as_ref().ok_or_else(|| {
                ApiError::BadRequest(
                    "signed callbacks are disabled: set FLUIDBOX_CREDENTIAL_KEY on the server"
                        .into(),
                )
            })?;
            let secret = random_hex_token(SECRET_PREFIX);
            let sealed = sealer.seal(&secret);
            let dests =
                serde_json::to_value(vec![ResultDestination::SignedWebhook { url: url.clone() }])?;
            (dests, Some(secret), Some(sealed))
        }
    };

    let sub = fluidbox_db::create_trigger_subscription(
        &state.pool,
        state.tenant_id,
        agent.id,
        name,
        trigger_kind,
        req.pinned_revision_id,
        template,
        req.allow_task_override,
        req.allow_workspace_override,
        req.autonomous.then_some("autonomous"),
        concurrency,
        req.budgets
            .as_ref()
            .map(serde_json::to_value)
            .transpose()?
            .as_ref(),
        workspace_value.as_ref(),
        &destinations,
        secret_sealed.as_deref(),
        None,
        None,
        None,
        None,
    )
    .await
    .map_err(|e| match &e {
        sqlx::Error::Database(db) if db.is_unique_violation() => {
            ApiError::Conflict(format!("a trigger named '{name}' already exists"))
        }
        _ => ApiError::Db(e),
    })?;

    let token = random_hex_token(TOKEN_PREFIX);
    fluidbox_db::create_trigger_token(&state.pool, state.tenant_id, sub.id, &token).await?;

    let schedule_row = match schedule_cfg {
        None => None,
        Some((cron, tz, missed, first)) => Some(
            fluidbox_db::create_schedule(&state.pool, sub.id, &cron, &tz, first, &missed).await?,
        ),
    };

    // token + callback_secret appear ONLY here, once, at creation.
    Ok(Json(json!({
        "subscription": sub,
        "schedule": schedule_row,
        "token": token,
        "callback_secret": secret_plain,
    })))
}

pub async fn list(_: Admin, State(state): State<AppState>) -> ApiResult<Json<Value>> {
    let subscriptions =
        fluidbox_db::list_trigger_subscriptions(&state.pool, state.tenant_id).await?;
    let schedules = fluidbox_db::schedules_for_tenant(&state.pool, state.tenant_id).await?;
    Ok(Json(
        json!({ "subscriptions": subscriptions, "schedules": schedules }),
    ))
}

pub async fn get(
    _: Admin,
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<Value>> {
    let sub = fluidbox_db::get_trigger_subscription(&state.pool, id)
        .await?
        .filter(|s| s.tenant_id == state.tenant_id)
        .ok_or(ApiError::NotFound)?;
    let sessions = fluidbox_db::list_subscription_sessions(&state.pool, id, 20).await?;
    let deliveries = fluidbox_db::list_subscription_deliveries(&state.pool, id, 20).await?;
    let schedule = fluidbox_db::schedule_for_subscription(&state.pool, id).await?;
    let invocations = fluidbox_db::list_subscription_invocations(&state.pool, id, 30).await?;
    Ok(Json(json!({
        "subscription": sub, "schedule": schedule, "sessions": sessions,
        "deliveries": deliveries, "invocations": invocations
    })))
}

async fn set_enabled(state: &AppState, id: Uuid, enabled: bool) -> ApiResult<Json<Value>> {
    let sub = fluidbox_db::get_trigger_subscription(&state.pool, id)
        .await?
        .filter(|s| s.tenant_id == state.tenant_id)
        .ok_or(ApiError::NotFound)?;
    let row = fluidbox_db::set_trigger_subscription_enabled(&state.pool, sub.id, enabled)
        .await?
        .ok_or(ApiError::NotFound)?;
    Ok(Json(json!({ "subscription": row })))
}

pub async fn enable(
    _: Admin,
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<Value>> {
    set_enabled(&state, id, true).await
}

pub async fn disable(
    _: Admin,
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<Value>> {
    set_enabled(&state, id, false).await
}

/// Rotation: every live token dies, one new token is minted and returned once.
pub async fn rotate_token(
    _: Admin,
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<Value>> {
    let sub = fluidbox_db::get_trigger_subscription(&state.pool, id)
        .await?
        .filter(|s| s.tenant_id == state.tenant_id)
        .ok_or(ApiError::NotFound)?;
    let revoked = fluidbox_db::revoke_trigger_tokens(&state.pool, sub.id).await?;
    let token = random_hex_token(TOKEN_PREFIX);
    fluidbox_db::create_trigger_token(&state.pool, state.tenant_id, sub.id, &token).await?;
    Ok(Json(json!({ "token": token, "revoked": revoked })))
}

// ─── Scoped: invoke & poll ────────────────────────────────────────────────

const MAX_TASK_CHARS: usize = 16_384;
const MAX_CONTEXT_BYTES: usize = 8_192;
const MAX_IDEMPOTENCY_KEY_CHARS: usize = 200;

#[derive(Deserialize)]
pub struct InvokeBody {
    #[serde(default)]
    pub task: Option<String>,
    #[serde(default)]
    pub context: Option<serde_json::Map<String, Value>>,
    #[serde(default)]
    pub workspace: Option<InvokeWorkspace>,
}

/// Flatten the caller's context object into strings; nested values are
/// rejected — context is template input and audit data, not a payload bus.
fn flatten_context(
    raw: Option<serde_json::Map<String, Value>>,
) -> Result<BTreeMap<String, String>, ApiError> {
    let Some(map) = raw else {
        return Ok(BTreeMap::new());
    };
    let mut out = BTreeMap::new();
    for (k, v) in map {
        let s = match v {
            Value::String(s) => s,
            Value::Number(n) => n.to_string(),
            Value::Bool(b) => b.to_string(),
            _ => {
                return Err(ApiError::BadRequest(format!(
                    "context.{k} must be a string, number, or bool"
                )))
            }
        };
        out.insert(k, s);
    }
    let size: usize = out.iter().map(|(k, v)| k.len() + v.len()).sum();
    if size > MAX_CONTEXT_BYTES {
        return Err(ApiError::BadRequest(format!(
            "context too large ({size} bytes > {MAX_CONTEXT_BYTES})"
        )));
    }
    Ok(out)
}

pub async fn invoke(
    auth: TriggerAuth,
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    headers: HeaderMap,
    Json(body): Json<InvokeBody>,
) -> ApiResult<Json<Value>> {
    // The token IS the authority; the path must match it.
    if auth.subscription_id != id {
        return Err(ApiError::Unauthorized);
    }
    let sub = fluidbox_db::get_trigger_subscription(&state.pool, id)
        .await?
        .filter(|s| s.tenant_id == state.tenant_id)
        .ok_or(ApiError::NotFound)?;
    if !sub.enabled {
        return Err(ApiError::Conflict(
            "trigger subscription is disabled".into(),
        ));
    }

    // §17 #6: overrides are opt-in per subscription, default off.
    if body.task.is_some() && !sub.allow_task_override {
        return Err(ApiError::BadRequest(
            "this subscription does not allow task override".into(),
        ));
    }
    if body.workspace.is_some() && !sub.allow_workspace_override {
        return Err(ApiError::BadRequest(
            "this subscription does not allow workspace override".into(),
        ));
    }
    if body
        .task
        .as_deref()
        .map(|t| t.chars().count() > MAX_TASK_CHARS)
        .unwrap_or(false)
    {
        return Err(ApiError::BadRequest(format!(
            "task too large (> {MAX_TASK_CHARS} chars)"
        )));
    }
    let context = flatten_context(body.context.clone())?;

    // Effective task: allowed caller task, else the rendered template.
    let task = match body
        .task
        .as_deref()
        .map(str::trim)
        .filter(|t| !t.is_empty())
    {
        Some(t) => t.to_string(),
        None => {
            let template = sub.task_template.as_deref().ok_or_else(|| {
                ApiError::BadRequest(
                    "no task: subscription has no task_template and no caller task was allowed/provided"
                        .into(),
                )
            })?;
            render_task_template(template, &context).map_err(ApiError::BadRequest)?
        }
    };

    let SubRunParams {
        autonomy,
        budget_override,
        result_destinations: destinations,
        workspace: sub_workspace,
    } = sub_run_params(&sub)?;

    // Effective workspace: subscription override > (narrowed by caller when
    // allowed). When neither exists, create_run falls through to the agent
    // revision default and then scratch — same precedence as every run.
    let explicit_workspace = match &body.workspace {
        None => sub_workspace,
        Some(nw) => {
            // Narrowing base: subscription workspace, else the revision default.
            let base = match sub_workspace {
                Some(ws) => ws,
                None => {
                    let rev = match sub.pinned_revision_id {
                        Some(rid) => fluidbox_db::get_revision(&state.pool, rid).await?,
                        None => fluidbox_db::latest_revision(&state.pool, sub.agent_id).await?,
                    }
                    .ok_or_else(|| ApiError::BadRequest("agent has no revisions".into()))?;
                    rev.default_workspace
                        .as_ref()
                        .map(|v| serde_json::from_value(v.clone()))
                        .transpose()
                        .map_err(|e| {
                            ApiError::Internal(format!("bad stored default workspace: {e}"))
                        })?
                        .ok_or_else(|| {
                            ApiError::BadRequest(
                                "workspace override needs a git workspace on the subscription or agent revision"
                                    .into(),
                            )
                        })?
                }
            };
            Some(narrow_workspace(&base, nw).map_err(ApiError::BadRequest)?)
        }
    };

    // Idempotency: caller key dedups; absent key → unique auto key (the
    // invocation row is still written so every invoke is auditable).
    let provided_key = headers
        .get("idempotency-key")
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|k| !k.is_empty())
        .map(str::to_string);
    if provided_key
        .as_deref()
        .map(|k| k.chars().count() > MAX_IDEMPOTENCY_KEY_CHARS)
        .unwrap_or(false)
    {
        return Err(ApiError::BadRequest("Idempotency-Key too long".into()));
    }
    let digest = canonical_digest(&body.task, &context, &body.workspace);
    let key = provided_key
        .clone()
        .unwrap_or_else(|| format!("auto-{}", Uuid::now_v7()));

    let claim = fluidbox_db::claim_invocation(&state.pool, sub.id, &key, &digest).await?;
    let invocation_id = match claim {
        fluidbox_db::InvocationClaim::Replay {
            session_id,
            request_digest,
        } => {
            if request_digest != digest {
                return Err(ApiError::UnprocessableEntity(
                    "Idempotency-Key was already used with a different request body".into(),
                ));
            }
            let session = fluidbox_db::get_session(&state.pool, session_id)
                .await?
                .ok_or(ApiError::NotFound)?;
            return Ok(Json(json!({
                "session_id": session.id,
                "status": session.status,
                "replay": true,
                "poll_url": format!("/v1/triggers/{}/runs/{}", sub.id, session.id),
            })));
        }
        fluidbox_db::InvocationClaim::Skipped { reason } => {
            return Err(ApiError::Conflict(format!(
                "this Idempotency-Key was skipped ({reason}) — use a new key to retry"
            )))
        }
        fluidbox_db::InvocationClaim::InFlight => {
            return Err(ApiError::Conflict(
                "an invocation with this Idempotency-Key is being created — retry shortly".into(),
            ))
        }
        fluidbox_db::InvocationClaim::Claimed { invocation_id } => invocation_id,
    };

    let invocation = InvocationContext {
        kind: InvocationKind::Api,
        subscription_id: Some(sub.id),
        actor: Some(format!("trigger:{}", sub.name)),
        attributes: json!({
            "context": context,
            "idempotency_key": provided_key,
        }),
        received_at: Some(chrono::Utc::now()),
        ..Default::default()
    };

    let created = crate::run_service::create_run(
        &state,
        crate::run_service::CreateRun {
            agent: sub.agent_id.to_string(),
            revision: match sub.pinned_revision_id {
                Some(rid) => crate::run_service::RevisionSelector::Pinned(rid),
                None => crate::run_service::RevisionSelector::Latest,
            },
            task,
            explicit_workspace,
            autonomy,
            budget_override,
            invocation,
            result_destinations: destinations,
            bound_invocation: Some(invocation_id),
        },
    )
    .await;

    match created {
        Ok(crate::run_service::RunCreation::Created(session)) => Ok(Json(json!({
            "session_id": session.id,
            "status": session.status,
            "replay": false,
            "poll_url": format!("/v1/triggers/{}/runs/{}", sub.id, session.id),
        }))),
        Ok(crate::run_service::RunCreation::SkippedOverlap { running_session_id }) => {
            // The skip is the terminal outcome of this key — recorded, not
            // retried; the caller uses a new key once the run finishes.
            fluidbox_db::mark_invocation_skipped(&state.pool, invocation_id, "overlap")
                .await
                .ok();
            Err(ApiError::Conflict(format!(
                "skipped: run {running_session_id} from this subscription is still active (concurrency_policy=skip_if_running)"
            )))
        }
        Err(e) => {
            // Free the key so the caller's retry isn't wedged behind a failure.
            fluidbox_db::release_invocation(&state.pool, invocation_id)
                .await
                .ok();
            Err(e)
        }
    }
}

/// Scoped polling: a trigger token can read exactly the runs it created.
pub async fn poll_run(
    auth: TriggerAuth,
    State(state): State<AppState>,
    Path((id, sid)): Path<(Uuid, Uuid)>,
) -> ApiResult<Json<Value>> {
    if auth.subscription_id != id {
        return Err(ApiError::Unauthorized);
    }
    if !fluidbox_db::subscription_owns_session(&state.pool, id, sid).await? {
        return Err(ApiError::NotFound);
    }
    let session = fluidbox_db::get_session(&state.pool, sid)
        .await?
        .ok_or(ApiError::NotFound)?;
    let payload = crate::deliveries::result_payload(&state, &session, None, None).await?;
    Ok(Json(payload))
}

#[cfg(test)]
mod tests {
    use super::*;
    use fluidbox_core::spec::{CheckoutMode, WorkspaceSpec};
    use std::collections::BTreeMap;
    use uuid::Uuid;

    fn ctx(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn template_renders_context_keys() {
        let out = render_task_template(
            "Investigate {{ticket}} ({{ severity }})",
            &ctx(&[("ticket", "INC-42"), ("severity", "high")]),
        )
        .unwrap();
        assert_eq!(out, "Investigate INC-42 (high)");
        // No placeholders → template passes through untouched.
        assert_eq!(render_task_template("static", &ctx(&[])).unwrap(), "static");
    }

    #[test]
    fn template_rejects_missing_keys_and_unclosed_braces() {
        // Missing key must 400, not silently leave a hole in the prompt.
        assert!(render_task_template("do {{thing}}", &ctx(&[])).is_err());
        assert!(render_task_template("do {{thing", &ctx(&[("thing", "x")])).is_err());
    }

    fn git_base(connection: bool) -> WorkspaceSpec {
        WorkspaceSpec::GitRepository {
            connection_id: connection.then(Uuid::now_v7),
            repository: Some("acme/base".into()),
            clone_url: "https://github.com/acme/base.git".into(),
            r#ref: Some("main".into()),
            commit_sha: None,
            checkout_mode: CheckoutMode::WritableCopy,
        }
    }

    #[test]
    fn narrowing_swaps_ref_and_commit_within_base() {
        let out = narrow_workspace(
            &git_base(true),
            &InvokeWorkspace {
                repository: None,
                r#ref: Some("feature".into()),
                commit_sha: Some("a".repeat(40)),
            },
        )
        .unwrap();
        let WorkspaceSpec::GitRepository {
            r#ref,
            commit_sha,
            clone_url,
            connection_id,
            ..
        } = out
        else {
            panic!()
        };
        assert_eq!(r#ref.as_deref(), Some("feature"));
        assert_eq!(commit_sha.as_deref(), Some(&"a".repeat(40)[..]));
        assert_eq!(clone_url, "https://github.com/acme/base.git"); // repo unchanged
        assert!(connection_id.is_some()); // same connection — never a new one
    }

    #[test]
    fn narrowing_repository_swap_stays_on_github_and_same_connection() {
        let out = narrow_workspace(
            &git_base(true),
            &InvokeWorkspace {
                repository: Some("acme/other".into()),
                r#ref: None,
                commit_sha: None,
            },
        )
        .unwrap();
        let WorkspaceSpec::GitRepository {
            repository,
            clone_url,
            r#ref,
            ..
        } = out
        else {
            panic!()
        };
        assert_eq!(repository.as_deref(), Some("acme/other"));
        assert_eq!(clone_url, "https://github.com/acme/other.git");
        assert_eq!(r#ref.as_deref(), Some("main")); // base ref inherited
    }

    #[test]
    fn narrowing_rejects_escapes() {
        // repository swap on a non-github base (file:// fixture) → refused.
        let file_base = WorkspaceSpec::GitRepository {
            connection_id: None,
            repository: None,
            clone_url: "file:///tmp/fixture".into(),
            r#ref: None,
            commit_sha: None,
            checkout_mode: CheckoutMode::WritableCopy,
        };
        assert!(narrow_workspace(
            &file_base,
            &InvokeWorkspace {
                repository: Some("a/b".into()),
                r#ref: None,
                commit_sha: None
            }
        )
        .is_err());
        // …but ref-only narrowing of that base is fine.
        assert!(narrow_workspace(
            &file_base,
            &InvokeWorkspace {
                repository: None,
                r#ref: Some("feature".into()),
                commit_sha: None
            }
        )
        .is_ok());
        // Scratch/local bases cannot be narrowed into a git workspace.
        assert!(narrow_workspace(
            &WorkspaceSpec::Scratch,
            &InvokeWorkspace {
                repository: None,
                r#ref: Some("x".into()),
                commit_sha: None
            }
        )
        .is_err());
        // Malformed inputs.
        assert!(narrow_workspace(
            &git_base(true),
            &InvokeWorkspace {
                repository: Some("no-slash".into()),
                r#ref: None,
                commit_sha: None
            }
        )
        .is_err());
        assert!(narrow_workspace(
            &git_base(true),
            &InvokeWorkspace {
                repository: None,
                r#ref: None,
                commit_sha: Some("zz".into())
            }
        )
        .is_err());
    }

    #[test]
    fn schedule_context_renders_fire_time_only() {
        let ctx = schedule_context("2026-07-10T00:00:00Z");
        assert_eq!(
            render_task_template("sweep at {{fire_time}}", &ctx).unwrap(),
            "sweep at 2026-07-10T00:00:00Z"
        );
        // A schedule template referencing caller keys is dead config.
        assert!(render_task_template("do {{ticket}}", &ctx).is_err());
    }

    #[test]
    fn canonical_digest_is_order_independent_and_body_sensitive() {
        let a = canonical_digest(&Some("t".into()), &ctx(&[("a", "1"), ("b", "2")]), &None);
        let b = canonical_digest(&Some("t".into()), &ctx(&[("b", "2"), ("a", "1")]), &None);
        assert_eq!(a, b); // BTreeMap canonicalizes key order
        let c = canonical_digest(&Some("t2".into()), &ctx(&[("a", "1"), ("b", "2")]), &None);
        assert_ne!(a, c);
    }
}
