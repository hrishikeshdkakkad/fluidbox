//! API trigger subscriptions & scoped invocation (design doc §3.5/§6.1).
//! A trigger borrows an agent: it can start only the runs its subscription
//! allows and nothing else. §17 #6 (settled): caller task/workspace
//! overrides are opt-in per subscription, default OFF.

use crate::auth::{Principal, TriggerAuth};
use crate::error::{ApiError, ApiResult};
use crate::rbac;
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
        ..
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
            // A local path is not a provider namespace: swapping repos on a
            // file:// base would be wider LOCAL filesystem authority, not a
            // narrowing (§17 #6 allows swaps inside a github/connection
            // base only).
            if clone_url.starts_with("file://") {
                return Err("cannot retarget a file:// workspace".into());
            }
            // A swap must stay inside the base's own root: derive it by
            // stripping the base's repository suffix from its clone URL —
            // works identically for github.com and GHES, and makes leaving
            // the root structurally impossible.
            let base_repo = repository
                .as_deref()
                .ok_or("cannot retarget this workspace — its base has no repository identity")?;
            let stripped = clone_url.strip_suffix(".git").unwrap_or(clone_url);
            let root = stripped
                .strip_suffix(base_repo)
                .and_then(|r| r.strip_suffix('/'))
                .ok_or(
                    "cannot retarget this workspace — its clone URL does not embed the repository",
                )?;
            let dot_git = if clone_url.ends_with(".git") {
                ".git"
            } else {
                ""
            };
            (Some(repo.clone()), format!("{root}/{repo}{dot_git}"))
        }
    };
    Ok(WorkspaceSpec::GitRepository {
        connection_id: *connection_id,
        // A narrowed workspace starts unbound; create_run resolves its
        // workspace_fetch binding (Task 5), never narrow-time.
        binding_id: None,
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
    /// Listen on a connection's events: the subscription becomes
    /// trigger_kind='event' (mutually exclusive with `schedule`).
    #[serde(default)]
    pub connection: Option<String>,
    /// Resource selector: only these repositories match. Empty/omitted =
    /// every repository the connection can see.
    #[serde(default)]
    pub repositories: Option<Vec<String>>,
    /// Event filter. Omitted = the connector's defaults (§17 #2: opened +
    /// reopened; synchronize is an explicit opt-in — it fires per push).
    #[serde(default)]
    pub events: Option<Vec<String>>,
    /// Provider publish modes ("pr_comment", "check"). Omitted =
    /// ["pr_comment"]; an explicit [] publishes to the dashboard/webhook only.
    #[serde(default)]
    pub publish: Option<Vec<String>>,
    /// Capability keep-list (§3.5): bundle NAMES this subscription's runs
    /// keep, intersected with the revision's attachments — remove-only.
    /// Omitted = keep all; an explicit [] strips every capability.
    #[serde(default)]
    pub capabilities: Option<Vec<String>>,
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
    principal: Principal,
    State(state): State<AppState>,
    Json(req): Json<CreateTrigger>,
) -> ApiResult<Json<Value>> {
    if !rbac::can_manage_subscriptions(&principal) {
        return Err(ApiError::Forbidden(
            "managing trigger subscriptions requires admin or owner".into(),
        ));
    }
    let scope = principal.scope();
    let name = req.name.trim();
    if name.is_empty() {
        return Err(ApiError::BadRequest("name is required".into()));
    }
    let agent = match Uuid::parse_str(&req.agent) {
        Ok(id) => fluidbox_db::get_agent(&state.pool, scope, id).await?,
        Err(_) => fluidbox_db::get_agent_by_name(&state.pool, scope, &req.agent).await?,
    }
    .ok_or_else(|| ApiError::BadRequest(format!("unknown agent '{}'", req.agent)))?;
    if let Some(rid) = req.pinned_revision_id {
        fluidbox_db::get_revision(&state.pool, scope, rid)
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
    // Capability keep-list: naming a bundle the target revision doesn't
    // attach is dead config — refused at create (the intersection at run
    // time could only ever ignore it). An explicit [] is a deliberate
    // strip-everything and passes.
    let capability_keep: Option<Value> = match &req.capabilities {
        None => None,
        Some(keep) => {
            let rev = match req.pinned_revision_id {
                Some(rid) => fluidbox_db::get_revision(&state.pool, scope, rid).await?,
                None => fluidbox_db::latest_revision(&state.pool, scope, agent.id).await?,
            }
            .ok_or_else(|| ApiError::BadRequest("agent has no revisions".into()))?;
            let pins: Vec<fluidbox_core::capability::BundleRef> =
                serde_json::from_value(rev.capability_bundles.clone())
                    .map_err(|e| ApiError::Internal(format!("bad stored capability pins: {e}")))?;
            for name in keep {
                if !pins.iter().any(|p| &p.name == name) {
                    return Err(ApiError::BadRequest(format!(
                        "capability keep-list names '{name}' but the agent revision attaches no such bundle (attached: {})",
                        if pins.is_empty() {
                            "none".to_string()
                        } else {
                            pins.iter()
                                .map(|p| p.name.as_str())
                                .collect::<Vec<_>>()
                                .join(", ")
                        }
                    )));
                }
            }
            Some(json!(keep))
        }
    };
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
    // Event subscription config (design §6.3): validated against the
    // connection's connector so dead config is refused at create time.
    let event_cfg = match &req.connection {
        None => {
            if req.repositories.is_some() || req.events.is_some() || req.publish.is_some() {
                return Err(ApiError::BadRequest(
                    "repositories/events/publish require a connection".into(),
                ));
            }
            None
        }
        Some(conn_str) => {
            if req.schedule.is_some() {
                return Err(ApiError::BadRequest(
                    "a subscription is either scheduled or event-driven, not both".into(),
                ));
            }
            let cid = Uuid::parse_str(conn_str.trim())
                .map_err(|_| ApiError::BadRequest("connection must be a connection id".into()))?;
            // Tenant-scoped (not owner-scoped) by design: a subscription CONSUMES
            // a connection, and the design routes that authority through run
            // resource bindings (invariant 21, Task 5) + the broker
            // owner-membership recheck (Task 6), not Task 4's connection-object
            // viewer. Subscription create is admin/owner-gated already. See
            // task-4-report "Deferred / flagged".
            let conn = fluidbox_db::get_connection(&state.pool, scope, cid)
                .await?
                .ok_or_else(|| ApiError::BadRequest(format!("unknown connection {cid}")))?;
            if conn.status != "active" {
                return Err(ApiError::BadRequest(format!(
                    "connection is {} — reconnect it first",
                    conn.status
                )));
            }
            let connector = crate::connectors::connector_for(&conn.provider).ok_or_else(|| {
                ApiError::BadRequest(format!(
                    "provider '{}' has no event connector",
                    conn.provider
                ))
            })?;
            // Legacy rows carry their own webhook secret; seamless rows
            // receive events on their REGISTRATION's app-level ingress.
            let can_receive = match conn.registration_id {
                Some(rid) => fluidbox_db::github_app_registration_webhook_secret_sealed(
                    &state.pool,
                    scope,
                    rid,
                )
                .await?
                .is_some(),
                None => fluidbox_db::connection_webhook_secret_sealed(&state.pool, scope, cid)
                    .await?
                    .is_some(),
            };
            if !can_receive {
                return Err(ApiError::BadRequest(
                    "this connection cannot receive events (no webhook secret) — connect a github_app".into(),
                ));
            }
            // §17 #2: defaults from the connector; anything explicit must be
            // a supported event.
            let supported = crate::connectors::supported_events(connector);
            let events: Vec<String> = match &req.events {
                None => crate::connectors::default_events(connector),
                Some(list) if list.is_empty() => {
                    return Err(ApiError::BadRequest("events must not be empty".into()))
                }
                Some(list) => {
                    for e in list {
                        if !supported.contains(&e.as_str()) {
                            return Err(ApiError::BadRequest(format!(
                                "unsupported event '{e}' (supported: {})",
                                supported.join(", ")
                            )));
                        }
                    }
                    list.clone()
                }
            };
            let modes = crate::connectors::publish_modes(connector);
            let publish: Vec<String> = match &req.publish {
                None => vec!["pr_comment".to_string()],
                Some(list) => {
                    for m in list {
                        if !modes.contains(&m.as_str()) {
                            return Err(ApiError::BadRequest(format!(
                                "unsupported publish mode '{m}' (supported: {})",
                                modes.join(", ")
                            )));
                        }
                    }
                    list.clone()
                }
            };
            let repositories: Vec<String> = req.repositories.clone().unwrap_or_default();
            for r in &repositories {
                if !crate::api::valid_repo_name(r) {
                    return Err(ApiError::BadRequest(format!(
                        "repository must be 'owner/name' (got '{r}')"
                    )));
                }
            }
            // An event fires with no caller: the template must exist and
            // render from the event context alone.
            let tpl = template.ok_or_else(|| {
                ApiError::BadRequest("an event subscription needs a task_template".into())
            })?;
            render_task_template(tpl, &crate::connectors::sample_context(connector)).map_err(
                |e| {
                    ApiError::BadRequest(format!(
                        "task_template must render from the event context ({}): {e}",
                        crate::connectors::sample_context(connector)
                            .keys()
                            .map(|k| format!("{{{{{k}}}}}"))
                            .collect::<Vec<_>>()
                            .join(" ")
                    ))
                },
            )?;
            Some((
                cid,
                connector,
                repositories,
                events,
                publish,
                conn.registration_id,
            ))
        }
    };

    let trigger_kind = if schedule_cfg.is_some() {
        "schedule"
    } else if event_cfg.is_some() {
        "event"
    } else {
        "api"
    };
    let workspace_value = match req.workspace {
        None => None,
        // Subscription config is an admin/owner mutation → operator lens; the
        // per-run authority is re-resolved server-side at fire time.
        Some(input) => match crate::api::resolve_workspace_input(
            &state,
            scope,
            fluidbox_db::ConnectionViewer::All,
            input,
        )
        .await?
        {
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
            (dests, Some(secret), Some(sealed))
        }
    };

    let (connection_id, resource_selector, event_filter, event_publish, ingress_path) =
        match &event_cfg {
            None => (None, None, None, None, None),
            Some((cid, connector, repos, events, publish, registration_id)) => (
                Some(*cid),
                Some(json!({ "repositories": repos })),
                Some(json!({ "events": events })),
                Some(json!(publish)),
                // Seamless connections receive events on their
                // registration's app-level ingress, not a per-connection
                // path.
                Some(match registration_id {
                    Some(rid) => format!("/v1/ingress/{connector}/app/{rid}"),
                    None => format!("/v1/ingress/{connector}/{cid}"),
                }),
            ),
        };

    let (cb_bytes, cb_kv) = crate::seal::Sealed::split(&secret_sealed);
    let sub = fluidbox_db::create_trigger_subscription(
        &state.pool,
        scope,
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
        cb_bytes,
        cb_kv,
        connection_id,
        resource_selector.as_ref(),
        event_filter.as_ref(),
        event_publish.as_ref(),
        capability_keep.as_ref(),
    )
    .await
    .map_err(|e| match &e {
        sqlx::Error::Database(db) if db.is_unique_violation() => {
            ApiError::Conflict(format!("a trigger named '{name}' already exists"))
        }
        _ => ApiError::Db(e),
    })?;

    let token = random_hex_token(TOKEN_PREFIX);
    fluidbox_db::create_trigger_token(&state.pool, scope, sub.id, &token).await?;

    let schedule_row = match schedule_cfg {
        None => None,
        Some((cron, tz, missed, first)) => Some(
            fluidbox_db::create_schedule(&state.pool, scope, sub.id, &cron, &tz, first, &missed)
                .await?,
        ),
    };

    // token + callback_secret appear ONLY here, once, at creation.
    //
    // The absolute URLs are built server-side from FLUIDBOX_PUBLIC_URL: the
    // control plane is the only party that knows its own browser/caller-facing
    // address (the dashboard reaches it through a same-origin proxy, so it
    // cannot derive it), and an integration contract with a placeholder host is
    // not a contract. Trailing slashes are trimmed so joins never double up.
    let base = state.cfg.public_url.trim_end_matches('/');
    Ok(Json(json!({
        "subscription": sub,
        "schedule": schedule_row,
        "token": token,
        "callback_secret": secret_plain,
        "ingress_path": ingress_path,
        "base_url": base,
        "invoke_url": format!("{base}/v1/triggers/{}/invoke", sub.id),
        "poll_url_template": format!("{base}/v1/triggers/{}/runs/{{session_id}}", sub.id),
        "ingress_url": ingress_path
            .as_ref()
            .map(|path| format!("{base}{path}")),
    })))
}

pub async fn list(principal: Principal, State(state): State<AppState>) -> ApiResult<Json<Value>> {
    if !rbac::can_manage_subscriptions(&principal) {
        return Err(ApiError::Forbidden(
            "viewing trigger subscriptions requires admin or owner".into(),
        ));
    }
    let scope = principal.scope();
    let subscriptions = fluidbox_db::list_trigger_subscriptions(&state.pool, scope).await?;
    let schedules = fluidbox_db::schedules_for_tenant(&state.pool, scope).await?;
    Ok(Json(
        json!({ "subscriptions": subscriptions, "schedules": schedules }),
    ))
}

pub async fn get(
    principal: Principal,
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<Value>> {
    if !rbac::can_manage_subscriptions(&principal) {
        return Err(ApiError::Forbidden(
            "viewing a trigger subscription requires admin or owner".into(),
        ));
    }
    let scope = principal.scope();
    let sub = fluidbox_db::get_trigger_subscription(&state.pool, scope, id)
        .await?
        .ok_or(ApiError::NotFound)?;
    let sessions = fluidbox_db::list_subscription_sessions(&state.pool, scope, id, 20).await?;
    let deliveries = fluidbox_db::list_subscription_deliveries(&state.pool, scope, id, 20).await?;
    let schedule = fluidbox_db::schedule_for_subscription(&state.pool, scope, id).await?;
    let invocations =
        fluidbox_db::list_subscription_invocations(&state.pool, scope, id, 30).await?;
    Ok(Json(json!({
        "subscription": sub, "schedule": schedule, "sessions": sessions,
        "deliveries": deliveries, "invocations": invocations
    })))
}

async fn set_enabled(
    state: &AppState,
    scope: fluidbox_db::TenantScope,
    id: Uuid,
    enabled: bool,
) -> ApiResult<Json<Value>> {
    let sub = fluidbox_db::get_trigger_subscription(&state.pool, scope, id)
        .await?
        .ok_or(ApiError::NotFound)?;
    let row = fluidbox_db::set_trigger_subscription_enabled(&state.pool, scope, sub.id, enabled)
        .await?
        .ok_or(ApiError::NotFound)?;
    Ok(Json(json!({ "subscription": row })))
}

pub async fn enable(
    principal: Principal,
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<Value>> {
    if !rbac::can_manage_subscriptions(&principal) {
        return Err(ApiError::Forbidden(
            "managing trigger subscriptions requires admin or owner".into(),
        ));
    }
    set_enabled(&state, principal.scope(), id, true).await
}

pub async fn disable(
    principal: Principal,
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<Value>> {
    if !rbac::can_manage_subscriptions(&principal) {
        return Err(ApiError::Forbidden(
            "managing trigger subscriptions requires admin or owner".into(),
        ));
    }
    set_enabled(&state, principal.scope(), id, false).await
}

/// Rotation: every live token dies, one new token is minted and returned once.
pub async fn rotate_token(
    principal: Principal,
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<Value>> {
    if !rbac::can_manage_subscriptions(&principal) {
        return Err(ApiError::Forbidden(
            "managing trigger subscriptions requires admin or owner".into(),
        ));
    }
    let scope = principal.scope();
    let sub = fluidbox_db::get_trigger_subscription(&state.pool, scope, id)
        .await?
        .ok_or(ApiError::NotFound)?;
    let revoked = fluidbox_db::revoke_trigger_tokens(&state.pool, scope, sub.id).await?;
    let token = random_hex_token(TOKEN_PREFIX);
    fluidbox_db::create_trigger_token(&state.pool, scope, sub.id, &token).await?;
    // A rotated token needs the same contract as a freshly-created one — the
    // caller has to re-wire an integration either way, and the dashboard cannot
    // derive these URLs itself.
    let base = state.cfg.public_url.trim_end_matches('/');
    Ok(Json(json!({
        "token": token,
        "revoked": revoked,
        "base_url": base,
        "invoke_url": format!("{base}/v1/triggers/{}/invoke", sub.id),
        "poll_url_template": format!("{base}/v1/triggers/{}/runs/{{session_id}}", sub.id),
    })))
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
    // The token's tenant is the whole authority — every DB call scopes to it.
    let scope = auth.scope;
    let sub = fluidbox_db::get_trigger_subscription(&state.pool, scope, id)
        .await?
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
                        Some(rid) => fluidbox_db::get_revision(&state.pool, scope, rid).await?,
                        None => {
                            fluidbox_db::latest_revision(&state.pool, scope, sub.agent_id).await?
                        }
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

    let claim = fluidbox_db::claim_invocation(&state.pool, scope, sub.id, &key, &digest).await?;
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
            let session = fluidbox_db::get_session(&state.pool, scope, session_id)
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
        scope,
        crate::run_service::CreateRun {
            agent: sub.agent_id.to_string(),
            revision: match sub.pinned_revision_id {
                Some(rid) => crate::run_service::RevisionSelector::Pinned(rid),
                None => crate::run_service::RevisionSelector::Latest,
            },
            task,
            explicit_workspace,
            autonomy,
            trust_tier: fluidbox_core::spec::TrustTier::Trusted,
            budget_override,
            // The subscription's stored keep-list applies inside create_run;
            // callers cannot send one (narrowing config lives on the
            // subscription, like every other override).
            capability_selection: None,
            invocation,
            // A trigger-token invoke is not a directly-authenticated user.
            invoked_by_user_id: None,
            // Freeze the exact invoking token as the run's `trigger` principal
            // (E1) so the binding recheck fails closed on token revocation.
            invoking_token_id: Some(auth.token_id),
            // Invoke overrides only narrow — a trigger never introduces a new
            // connection (design/trap); the subscription derives its authority.
            explicit_bindings: std::collections::HashMap::new(),
            result_destinations: destinations,
            bound_invocation: Some(invocation_id),
            bound_dispatch: None,
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
            fluidbox_db::mark_invocation_skipped(&state.pool, scope, invocation_id, "overlap")
                .await
                .ok();
            Err(ApiError::Conflict(format!(
                "skipped: run {running_session_id} from this subscription is still active (concurrency_policy=skip_if_running)"
            )))
        }
        Ok(crate::run_service::RunCreation::ReplaceUnpersisted { running_session_id }) => {
            // Transient, NOT terminal: free the key so the caller's retry
            // isn't wedged behind a 409 that lies about skip_if_running.
            fluidbox_db::release_invocation(&state.pool, scope, invocation_id)
                .await
                .ok();
            Err(ApiError::ServiceUnavailable(format!(
                "could not persist cancellation of running session {running_session_id} for replace; retry"
            )))
        }
        Err(e) => {
            // Free the key so the caller's retry isn't wedged behind a failure.
            fluidbox_db::release_invocation(&state.pool, scope, invocation_id)
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
    let scope = auth.scope;
    if !fluidbox_db::subscription_owns_session(&state.pool, scope, id, sid).await? {
        return Err(ApiError::NotFound);
    }
    let session = fluidbox_db::get_session(&state.pool, scope, sid)
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
            binding_id: None,
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
            binding_id: None,
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
        // A file base WITH a repository identity (event-derived e2e shape)
        // is refused too — local paths are not a provider namespace.
        let file_repo_base = WorkspaceSpec::GitRepository {
            connection_id: Some(Uuid::now_v7()),
            binding_id: None,
            repository: Some("acme/base".into()),
            clone_url: "file:///tmp/fixture/acme/base".into(),
            r#ref: None,
            commit_sha: None,
            checkout_mode: CheckoutMode::WritableCopy,
        };
        assert!(narrow_workspace(
            &file_repo_base,
            &InvokeWorkspace {
                repository: Some("acme/other".into()),
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
