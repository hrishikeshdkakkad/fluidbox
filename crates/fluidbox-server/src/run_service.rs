//! The one internal run-creation service (design doc §4). Every entry point
//! — manual UI/CLI (`POST /v1/sessions`), API triggers, and later schedules
//! and events — converges here. It resolves and freezes: the immutable
//! agent revision, the effective workspace, autonomy, tightened budgets,
//! the invocation context, and the result destinations. An invocation may
//! narrow the agent's authority; nothing here can widen it.

use crate::error::{ApiError, ApiResult};
use crate::orchestrator;
use crate::state::AppState;
use fluidbox_core::capability::{
    narrow_bundles, server_collision, BundleRef, CapabilityBundleDef, CapabilityServer,
    FrozenBundle,
};
use fluidbox_core::policy::Policy;
use fluidbox_core::schedule::ConcurrencyPolicy;
use fluidbox_core::spec::{
    Autonomy, Budgets, InvocationContext, InvocationKind, ResultDestination, RunSpec, TrustTier,
    WorkspaceSpec,
};
use fluidbox_db::TenantScope;
use uuid::Uuid;

pub enum RevisionSelector {
    /// The agent's current (latest) revision — what manual runs use today.
    Latest,
    /// A subscription-pinned revision; must belong to the agent.
    Pinned(Uuid),
}

pub struct CreateRun {
    /// Agent id or name.
    pub agent: String,
    pub revision: RevisionSelector,
    pub task: String,
    /// Validated workspace the invocation supplies explicitly (precedence:
    /// event-derived/explicit > revision default > scratch). Callers
    /// validate their own inputs (admin API: resolve_workspace_input;
    /// triggers: narrowing; events: connector normalization).
    pub explicit_workspace: Option<WorkspaceSpec>,
    pub autonomy: Autonomy,
    /// Frozen into the RunSpec and enforced at the permission gate. Fork /
    /// untrusted event sources arrive pre-downgraded to ReadOnly (§7.3);
    /// nothing downstream can widen it back.
    pub trust_tier: TrustTier,
    pub budget_override: Option<Budgets>,
    /// Per-run capability keep-list (§3.5 narrowing, bundle names). None =
    /// keep everything the revision attaches (after the subscription's own
    /// keep-list). Removal-only by construction — an intersection can never
    /// add a bundle the revision lacks.
    pub capability_selection: Option<Vec<String>>,
    pub invocation: InvocationContext,
    /// The authenticated user who initiated this run, when one exists (admin/UI
    /// path once identity lands). None for operator-token, trigger, schedule,
    /// and webhook invocations. Stamped onto `sessions.invoked_by_user_id`.
    pub invoked_by_user_id: Option<Uuid>,
    pub result_destinations: Vec<ResultDestination>,
    /// Idempotency claim bound atomically with session creation (same DB
    /// transaction) — a crash can never leave a created run unclaimed, so a
    /// stale-claim takeover can never duplicate it. None for manual runs.
    pub bound_invocation: Option<Uuid>,
    /// Event fan-out claim (trigger_dispatches), bound in the same
    /// transaction — same crash-safety argument as bound_invocation.
    pub bound_dispatch: Option<Uuid>,
}

pub enum RunCreation {
    Created(Box<fluidbox_db::SessionRow>),
    /// concurrency_policy = skip_if_running and another run of this
    /// subscription is still active. Nothing was created; the caller
    /// records the skip visibly (claim row → skip_reason, or 409).
    SkippedOverlap {
        running_session_id: Uuid,
    },
    /// concurrency_policy = replace, but the old run's cancellation intent
    /// could not be durably persisted (transient DB failure survived the
    /// inline retries). Nothing was created and nothing is terminal about
    /// this: API invokes release their idempotency claim and 503 (caller
    /// retries); schedules/events record a visible skip (their next firing
    /// retries naturally).
    ReplaceUnpersisted {
        running_session_id: Uuid,
    },
}

pub async fn create_run(
    state: &AppState,
    scope: TenantScope,
    req: CreateRun,
) -> ApiResult<RunCreation> {
    // Netpol run-gate (Kubernetes): refuse to admit a run until the CNI is
    // proven to enforce NetworkPolicy. Fails closed — a non-enforcing cluster
    // never runs an agent with unverified sandbox isolation.
    if state.cfg.require_enforced_netpol
        && !state
            .netpol_verified
            .load(std::sync::atomic::Ordering::SeqCst)
    {
        return Err(ApiError::ServiceUnavailable(
            "sandbox network isolation is not yet verified on this cluster — \
             runs are blocked until the NetworkPolicy enforcement probe passes"
                .into(),
        ));
    }

    // Resolve agent by id or name — SQL-scoped to the caller's tenant.
    let agent = match Uuid::parse_str(&req.agent) {
        Ok(id) => fluidbox_db::get_agent(&state.pool, scope, id).await?,
        Err(_) => fluidbox_db::get_agent_by_name(&state.pool, scope, &req.agent).await?,
    }
    .ok_or_else(|| ApiError::BadRequest(format!("unknown agent '{}'", req.agent)))?;

    let rev = match req.revision {
        RevisionSelector::Latest => fluidbox_db::latest_revision(&state.pool, scope, agent.id)
            .await?
            .ok_or_else(|| ApiError::BadRequest("agent has no revisions".into()))?,
        RevisionSelector::Pinned(id) => fluidbox_db::get_revision(&state.pool, scope, id)
            .await?
            .filter(|r| r.agent_id == agent.id)
            .ok_or_else(|| {
                ApiError::BadRequest(format!(
                    "revision {id} does not belong to agent '{}'",
                    agent.name
                ))
            })?,
    };
    // Fail closed at zero spend: a RunSpec only ever freezes a harness the
    // registry knows. Rows predating harness validation (or edited out of
    // band) refuse here rather than launching an image with no contract.
    if !crate::harness::is_known(&rev.harness) {
        return Err(ApiError::UnprocessableEntity(format!(
            "revision harness '{}' is not a known harness ({})",
            rev.harness,
            crate::harness::KNOWN.join(", ")
        )));
    }

    let policy_row = fluidbox_db::get_policy(&state.pool, scope, rev.policy_id)
        .await?
        .ok_or_else(|| ApiError::Internal("revision policy missing".into()))?;
    let policy: Policy = serde_json::from_value(policy_row.parsed.clone())
        .map_err(|e| ApiError::Internal(format!("bad stored policy: {e}")))?;

    // Autonomy permission gate: a policy may forbid autonomous runs.
    if req.autonomy == Autonomy::Autonomous && !policy.autonomy.permitted {
        return Err(ApiError::BadRequest(
            "policy does not permit autonomous runs".into(),
        ));
    }

    // The subscription (when the invocation carries one) governs both the
    // §17 #5 concurrency policy and the §3.5 capability keep-list below.
    let subscription = match req.invocation.subscription_id {
        Some(sub_id) => Some(
            fluidbox_db::get_trigger_subscription(&state.pool, scope, sub_id)
                .await?
                .ok_or_else(|| {
                    ApiError::Internal("invocation references a missing subscription".into())
                })?,
        ),
        None => None,
    };

    // §17 #5 (settled 2026-07-10): the subscription's concurrency policy
    // governs EVERY invocation that carries one — API invokes and schedule
    // firings alike. Manual runs carry no subscription and are never gated.
    if let Some(sub) = &subscription {
        let concurrency = ConcurrencyPolicy::parse(&sub.concurrency_policy).ok_or_else(|| {
            ApiError::Internal(format!(
                "bad stored concurrency_policy '{}'",
                sub.concurrency_policy
            ))
        })?;
        if concurrency != ConcurrencyPolicy::Allow {
            let active =
                fluidbox_db::active_subscription_sessions(&state.pool, scope, sub.id).await?;
            match concurrency {
                ConcurrencyPolicy::SkipIfRunning => {
                    if let Some(s) = active.first() {
                        return Ok(RunCreation::SkippedOverlap {
                            running_session_id: s.id,
                        });
                    }
                }
                ConcurrencyPolicy::Replace => {
                    for s in &active {
                        // The replacement must not proceed unless the old
                        // run's cancellation durably persisted: a healthy old
                        // run with no wall-clock budget would otherwise
                        // coexist with its replacement indefinitely. Retry
                        // the transient case inline; if it still will not
                        // persist, record a SKIP — the vocabulary schedulers
                        // and event dispatch already handle — rather than an
                        // error they would treat as a permanently lost
                        // firing.
                        let mut persisted = false;
                        for _ in 0..3u32 {
                            match orchestrator::cancel(
                                state,
                                scope,
                                s.id,
                                "replaced by a newer invocation of this subscription",
                            )
                            .await
                            {
                                orchestrator::FinalizeStart::DbError => {
                                    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                                }
                                _ => {
                                    persisted = true;
                                    break;
                                }
                            }
                        }
                        if !persisted {
                            tracing::warn!(
                                "replace: cancel intent for {} not persisted after retries",
                                s.id
                            );
                            return Ok(RunCreation::ReplaceUnpersisted {
                                running_session_id: s.id,
                            });
                        }
                    }
                }
                ConcurrencyPolicy::Allow => unreachable!(),
            }
        }
    }

    let agent_budgets: Budgets = serde_json::from_value(rev.budgets.clone()).unwrap_or_default();
    // The policy's budgets are a ceiling: revision defaults and per-run
    // requests may only tighten below them, never widen past them.
    let ceiling = agent_budgets.tightened_by(&policy.budgets);
    let effective_budgets = match &req.budget_override {
        Some(b) => ceiling.tightened_by(b),
        None => ceiling,
    };

    // Workspace precedence (design §3.3): explicit > revision default > scratch.
    let revision_default: Option<WorkspaceSpec> = rev
        .default_workspace
        .as_ref()
        .map(|v| serde_json::from_value(v.clone()))
        .transpose()
        .map_err(|e| ApiError::Internal(format!("bad stored default workspace: {e}")))?;
    let workspace = WorkspaceSpec::resolve(req.explicit_workspace, revision_default);

    // A connection-backed workspace must still be usable at run time (the
    // connection may have been revoked since the default was stored).
    if let WorkspaceSpec::GitRepository {
        connection_id: Some(cid),
        ..
    } = &workspace
    {
        let active = fluidbox_db::get_connection(&state.pool, scope, *cid)
            .await?
            .map(|c| c.status == "active")
            .unwrap_or(false);
        if !active {
            return Err(ApiError::BadRequest(format!(
                "workspace connection {cid} is not active — reconnect it or override the workspace"
            )));
        }
    }

    // Effective capabilities (design §4): revision pins ∩ subscription
    // keep-list ∩ per-run keep-list ∩ trust tier — frozen with full schema
    // snapshots. Narrowing removes, never adds.
    let capabilities = frozen_capabilities(
        state,
        scope,
        &rev,
        subscription.as_ref(),
        req.capability_selection.as_deref(),
        req.trust_tier,
    )
    .await?;

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
        autonomy: req.autonomy,
        trust_tier: req.trust_tier,
        budgets: effective_budgets.clone(),
        policy_id: policy_row.id,
        policy_version: policy_row.version,
        policy_snapshot: policy,
        invocation: req.invocation.clone(),
        result_destinations: req.result_destinations.clone(),
        capabilities,
    };

    // 512 KiB serialized runner-env ceiling (design 2026-07-15): env injection
    // is the v1 config channel and a Kubernetes Secret caps ~1 MiB. Reject a
    // bloated run at creation with a clear 422 + per-component diagnostics,
    // rather than an opaque kubelet/daemon failure at launch. The estimate
    // uses placeholder identity (tiny, bounded); `run()` re-checks for real.
    let est_env = orchestrator::build_runner_env(
        &run_spec,
        &state.cfg.public_control_url,
        Uuid::nil(),
        "fbx_sess_00000000000000000000000000000000",
    );
    let env_bytes = orchestrator::serialized_env_len(&est_env);
    if env_bytes > crate::config::MAX_RUNNER_ENV_BYTES {
        return Err(ApiError::UnprocessableEntity(format!(
            "runner environment is {env_bytes} bytes, over the {} byte ceiling — \
             shorten the task/system prompt or narrow capabilities ({})",
            crate::config::MAX_RUNNER_ENV_BYTES,
            orchestrator::env_size_breakdown(&est_env),
        )));
    }

    // Who invoked this run (design "tenant/user audit fields"), derived from the
    // invocation kind create_run already computes: a directly-authenticated
    // principal on the admin/UI path is a "user" when their id is known, else an
    // "operator" (today's shared admin token / no-identity path); a trigger-token
    // invoke is a "trigger"; a schedule tick is a "schedule"; a connector webhook
    // is a "webhook". `invoked_by_user_id` is None until identity plumbs it in.
    let invoked_by_kind = match req.invocation.kind {
        InvocationKind::Manual => {
            if req.invoked_by_user_id.is_some() {
                "user"
            } else {
                "operator"
            }
        }
        InvocationKind::Api => "trigger",
        InvocationKind::Schedule => "schedule",
        InvocationKind::Event => "webhook",
    };

    let session = fluidbox_db::create_session(
        &state.pool,
        scope,
        agent.id,
        rev.id,
        req.autonomy.as_str(),
        run_spec.trust_tier.as_str(),
        &req.task,
        &serde_json::to_value(&workspace)?,
        &serde_json::to_value(&run_spec)?,
        &serde_json::to_value(&effective_budgets)?,
        Some(&serde_json::to_value(&req.invocation)?),
        Some(invoked_by_kind),
        req.invoked_by_user_id,
        req.bound_invocation,
        req.bound_dispatch,
    )
    .await?;

    crate::ledger::record(
        state,
        scope,
        session.id,
        fluidbox_core::event::Actor::System,
        fluidbox_core::event::EventBody::SessionCreated {
            task: req.task.clone(),
            agent: agent.name.clone(),
            autonomy: req.autonomy.as_str().into(),
        },
    )
    .await;

    // Timeline visibility for the frozen capability set (the RunSpec is the
    // authoritative copy).
    if !run_spec.capabilities.is_empty() {
        crate::ledger::record(
            state,
            scope,
            session.id,
            fluidbox_core::event::Actor::System,
            fluidbox_core::event::EventBody::CapabilitiesFrozen {
                bundles: run_spec
                    .capabilities
                    .iter()
                    .map(|b| format!("{}@{}", b.name, b.version))
                    .collect(),
                tools: run_spec
                    .capabilities
                    .iter()
                    .flat_map(|b| &b.servers)
                    .map(|s| s.tools().len() as u64)
                    .sum(),
            },
        )
        .await;
    }

    // Kick off the run.
    orchestrator::spawn_run(state.clone(), session.id);

    Ok(RunCreation::Created(Box::new(session)))
}

/// Resolve the run's frozen capability set (design §3.6/§8). The revision's
/// §17 #7 pins load the exact registered bundle versions — snapshots and
/// all — then the subscription's and the invocation's keep-lists intersect
/// them (remove-only), the trust tier gets its say, and fail-closed checks
/// run BEFORE any model spend.
async fn frozen_capabilities(
    state: &AppState,
    scope: TenantScope,
    rev: &fluidbox_db::AgentRevisionRow,
    subscription: Option<&fluidbox_db::TriggerSubscriptionRow>,
    manual_keep: Option<&[String]>,
    trust_tier: TrustTier,
) -> ApiResult<Vec<FrozenBundle>> {
    // Fork / untrusted event sources run with ZERO MCP surface (§7.3): the
    // read-only gate would deny every mcp__* call anyway; stripping here
    // means hostile repo content never even meets a capability server.
    if trust_tier == TrustTier::ReadOnly {
        return Ok(vec![]);
    }
    let refs: Vec<BundleRef> = serde_json::from_value(rev.capability_bundles.clone())
        .map_err(|e| ApiError::Internal(format!("bad stored capability pins: {e}")))?;
    let mut bundles = Vec::with_capacity(refs.len());
    for r in refs {
        let row = fluidbox_db::get_capability_bundle(&state.pool, scope, r.id)
            .await?
            .filter(|b| b.name == r.name && b.version == r.version)
            .ok_or_else(|| {
                ApiError::Internal(format!(
                    "pinned capability bundle {}@{} is missing",
                    r.name, r.version
                ))
            })?;
        let def: CapabilityBundleDef = serde_json::from_value(row.definition.clone())
            .map_err(|e| ApiError::Internal(format!("bad stored bundle definition: {e}")))?;
        bundles.push(FrozenBundle {
            id: row.id,
            name: row.name,
            version: row.version,
            definition_digest: row.definition_digest,
            servers: def.servers,
        });
    }
    if let Some(sub) = subscription {
        if let Some(v) = &sub.capability_bundles {
            let keep: Vec<String> = serde_json::from_value(v.clone()).map_err(|e| {
                ApiError::Internal(format!("bad stored subscription capability keep-list: {e}"))
            })?;
            bundles = narrow_bundles(bundles, Some(&keep));
        }
    }
    if manual_keep.is_some() {
        bundles = narrow_bundles(bundles, manual_keep);
    }
    // Shadowing defense: one alias, one server, across the whole frozen set.
    if let Some(name) = server_collision(&bundles) {
        return Err(ApiError::BadRequest(format!(
            "capability server name '{name}' appears in more than one attached bundle — narrow the set or re-bundle"
        )));
    }
    // A brokered server's connection must still be usable at run time (it
    // may have been revoked since the bundle was registered) — fail closed
    // during creation, before any model spend.
    for bundle in &bundles {
        for server in &bundle.servers {
            if let CapabilityServer::Brokered {
                name,
                connection_id: Some(cid),
                ..
            } = server
            {
                let active = fluidbox_db::get_connection(&state.pool, scope, *cid)
                    .await?
                    .map(|c| c.status == "active")
                    .unwrap_or(false);
                if !active {
                    return Err(ApiError::BadRequest(format!(
                        "capability server '{name}' (bundle {}@{}) uses connection {cid} which is not active — reconnect it or narrow the capabilities",
                        bundle.name, bundle.version
                    )));
                }
            }
        }
    }
    Ok(bundles)
}
