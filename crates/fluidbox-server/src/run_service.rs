//! The one internal run-creation service (design doc §4). Every entry point
//! — manual UI/CLI (`POST /v1/sessions`), API triggers, and later schedules
//! and events — converges here. It resolves and freezes: the immutable
//! agent revision, the effective workspace, autonomy, tightened budgets,
//! the invocation context, and the result destinations. An invocation may
//! narrow the agent's authority; nothing here can widen it.

use crate::error::{ApiError, ApiResult};
use crate::orchestrator;
use crate::state::AppState;
use fluidbox_core::policy::Policy;
use fluidbox_core::spec::{
    Autonomy, Budgets, InvocationContext, ResultDestination, RunSpec, TrustTier, WorkspaceSpec,
};
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
    /// explicit > revision default > scratch). Callers validate their own
    /// inputs (admin API: resolve_workspace_input; triggers: narrowing).
    pub explicit_workspace: Option<WorkspaceSpec>,
    pub autonomy: Autonomy,
    pub budget_override: Option<Budgets>,
    pub invocation: InvocationContext,
    pub result_destinations: Vec<ResultDestination>,
}

pub async fn create_run(state: &AppState, req: CreateRun) -> ApiResult<fluidbox_db::SessionRow> {
    // Resolve agent by id or name.
    let agent = match Uuid::parse_str(&req.agent) {
        Ok(id) => fluidbox_db::get_agent(&state.pool, id).await?,
        Err(_) => fluidbox_db::get_agent_by_name(&state.pool, state.tenant_id, &req.agent).await?,
    }
    .filter(|a| a.tenant_id == state.tenant_id)
    .ok_or_else(|| ApiError::BadRequest(format!("unknown agent '{}'", req.agent)))?;

    let rev = match req.revision {
        RevisionSelector::Latest => fluidbox_db::latest_revision(&state.pool, agent.id)
            .await?
            .ok_or_else(|| ApiError::BadRequest("agent has no revisions".into()))?,
        RevisionSelector::Pinned(id) => fluidbox_db::get_revision(&state.pool, id)
            .await?
            .filter(|r| r.agent_id == agent.id)
            .ok_or_else(|| {
                ApiError::BadRequest(format!(
                    "revision {id} does not belong to agent '{}'",
                    agent.name
                ))
            })?,
    };
    let policy_row = fluidbox_db::get_policy(&state.pool, rev.policy_id)
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
        autonomy: req.autonomy,
        trust_tier: TrustTier::Trusted,
        budgets: effective_budgets.clone(),
        policy_id: policy_row.id,
        policy_version: policy_row.version,
        policy_snapshot: policy,
        invocation: req.invocation.clone(),
        result_destinations: req.result_destinations.clone(),
    };

    let session = fluidbox_db::create_session(
        &state.pool,
        state.tenant_id,
        agent.id,
        rev.id,
        req.autonomy.as_str(),
        &req.task,
        &serde_json::to_value(&workspace)?,
        &serde_json::to_value(&run_spec)?,
        &serde_json::to_value(&effective_budgets)?,
        Some(&serde_json::to_value(&req.invocation)?),
        None,
    )
    .await?;

    crate::ledger::record(
        state,
        session.id,
        fluidbox_core::event::Actor::System,
        fluidbox_core::event::EventBody::SessionCreated {
            task: req.task.clone(),
            agent: agent.name.clone(),
            autonomy: req.autonomy.as_str().into(),
        },
    )
    .await;

    // Kick off the run.
    orchestrator::spawn_run(state.clone(), session.id);

    Ok(session)
}
