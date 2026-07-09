//! Session lifecycle driver. The server is the single status writer; the
//! runner only reports events/heartbeats/result. This module owns the
//! transitions, the sandbox, workspace init, budget enforcement, and reaping.

use crate::ledger;
use crate::state::AppState;
use fluidbox_core::event::{Actor, EventBody};
use fluidbox_core::spec::{RepoSource, RunSpec};
use fluidbox_core::state::SessionStatus;
use fluidbox_core::traits::{ExecutionProvider, NetworkMode, SandboxHandle, SandboxSpec};
use fluidbox_db::SessionRow;
use std::path::PathBuf;
use uuid::Uuid;

const SESSION_TOKEN_TTL_SECS: i64 = 3 * 3600;

/// Spawn the full run of a freshly-created session in the background.
pub fn spawn_run(state: AppState, session_id: Uuid) {
    tokio::spawn(async move {
        if let Err(e) = run(state.clone(), session_id).await {
            tracing::error!("run {session_id} failed: {e}");
            fail(&state, session_id, &format!("{e}")).await;
        }
    });
}

async fn transition(state: &AppState, id: Uuid, next: SessionStatus, reason: Option<&str>) -> bool {
    match fluidbox_db::transition_session(&state.pool, id, next, reason).await {
        Ok(Some((from, _))) => {
            ledger::record(
                state,
                id,
                Actor::System,
                EventBody::StatusChanged {
                    from: from.as_str().into(),
                    to: next.as_str().into(),
                    reason: reason.map(|s| s.to_string()),
                },
            )
            .await;
            true
        }
        Ok(None) => false,
        Err(e) => {
            tracing::error!("transition {id}->{next:?} failed: {e}");
            false
        }
    }
}

pub async fn fail(state: &AppState, id: Uuid, reason: &str) {
    ledger::record(state, id, Actor::System, EventBody::RunError { message: reason.into() }).await;
    transition(state, id, SessionStatus::Failed, Some(reason)).await;
    reap(state, id).await;
}

async fn run(state: AppState, session_id: Uuid) -> anyhow::Result<()> {
    let session = fluidbox_db::get_session(&state.pool, session_id)
        .await?
        .ok_or_else(|| anyhow::anyhow!("session vanished"))?;
    let run_spec: RunSpec = serde_json::from_value(session.run_spec.clone())?;

    // created → provisioning
    if !transition(&state, session_id, SessionStatus::Provisioning, None).await {
        anyhow::bail!("could not enter provisioning");
    }

    // Mint the session token the sandbox authenticates with.
    let session_token = format!("fbx_sess_{}", uuid_token());
    fluidbox_db::create_session_token(
        &state.pool,
        state.tenant_id,
        session_id,
        &session_token,
        SESSION_TOKEN_TTL_SECS,
    )
    .await?;

    // provisioning → initializing (workspace materialization, control-plane
    // side, BEFORE the agent starts — a bad repo fails here at zero model spend)
    transition(&state, session_id, SessionStatus::Initializing, None).await;
    let workspace_dir = materialize_workspace(&state, session_id, &run_spec).await?;

    // Launch the sandbox.
    let control_url = state.cfg.public_control_url.clone();
    let env = vec![
        ("FLUIDBOX_CONTROL_URL".into(), control_url.clone()),
        ("FLUIDBOX_SESSION_ID".into(), session_id.to_string()),
        ("FLUIDBOX_SESSION_TOKEN".into(), session_token.clone()),
        ("FLUIDBOX_TASK".into(), run_spec.task.clone()),
        ("FLUIDBOX_AUTONOMY".into(), run_spec.autonomy.as_str().into()),
        ("FLUIDBOX_MODEL".into(), run_spec.model.clone()),
        ("FLUIDBOX_WORKSPACE".into(), "/workspace".into()),
        (
            "ANTHROPIC_BASE_URL".into(),
            format!("{}/internal/llm", control_url.trim_end_matches('/')),
        ),
        // The fake key IS the session token; the facade swaps in the real one.
        ("ANTHROPIC_API_KEY".into(), session_token.clone()),
        ("ANTHROPIC_MODEL".into(), run_spec.model.clone()),
    ];
    let mut env = env;
    if let Some(sp) = &run_spec.system_prompt {
        env.push(("FLUIDBOX_SYSTEM_PROMPT".into(), sp.clone()));
    }

    let sandbox_spec = SandboxSpec {
        session_id,
        image: run_spec.runner_image.clone(),
        env,
        workspace_host_dir: workspace_dir.as_ref().map(|p| p.display().to_string()),
        network: NetworkMode::HostDev,
    };

    let handle = state.provider.provision(&sandbox_spec).await?;
    fluidbox_db::set_sandbox_handle(&state.pool, session_id, &serde_json::to_value(&handle)?).await?;

    // initializing → running (traffic is now expected)
    transition(&state, session_id, SessionStatus::Running, None).await;
    fluidbox_db::heartbeat(&state.pool, session_id).await.ok();

    // The run now proceeds via the internal gateway (permission/events/
    // heartbeat/result). The watchdog + budget sweeper + result handler drive
    // it to a terminal state. We just record the launch.
    ledger::record(
        &state,
        session_id,
        Actor::System,
        EventBody::AgentMessage {
            role: "system".into(),
            text: format!("sandbox launched ({})", handle.external_id.chars().take(12).collect::<String>()),
        },
    )
    .await;

    Ok(())
}

async fn materialize_workspace(
    state: &AppState,
    session_id: Uuid,
    run_spec: &RunSpec,
) -> anyhow::Result<Option<PathBuf>> {
    match &run_spec.repo {
        RepoSource::LocalPath { path } => {
            let ws = fluidbox_provider::workspace::materialize_local(
                &state.cfg.data_dir,
                session_id,
                std::path::Path::new(path),
            )?;
            if let Some(bc) = &ws.base_commit {
                fluidbox_db::set_base_commit(&state.pool, session_id, bc).await.ok();
            }
            ledger::record(
                state,
                session_id,
                Actor::System,
                EventBody::WorkspaceInitialized {
                    base_commit: ws.base_commit.clone(),
                    files: Some(ws.file_count),
                },
            )
            .await;
            Ok(Some(ws.host_dir))
        }
        RepoSource::GitUrl { .. } => {
            // Deferred: MVP tests use LocalPath / None. Cloning a git URL is
            // control-plane-side too, but not needed for M1 acceptance.
            anyhow::bail!("git-url repos are not enabled in M1");
        }
        RepoSource::None => {
            // A scratch workspace so the agent still has somewhere to write.
            let dir = state.cfg.data_dir.join("workspaces").join(session_id.to_string()).join("repo");
            std::fs::create_dir_all(&dir)?;
            let ws = fluidbox_provider::workspace::materialize_local(
                &state.cfg.data_dir,
                session_id,
                &dir,
            )?;
            if let Some(bc) = &ws.base_commit {
                fluidbox_db::set_base_commit(&state.pool, session_id, bc).await.ok();
            }
            ledger::record(
                state,
                session_id,
                Actor::System,
                EventBody::WorkspaceInitialized { base_commit: ws.base_commit.clone(), files: Some(0) },
            )
            .await;
            Ok(Some(ws.host_dir))
        }
    }
}

/// Called by the internal /result handler: finalize a run, capture the diff,
/// then reap the sandbox.
pub async fn finalize(state: &AppState, session: &SessionRow, outcome: &str, summary: Option<&str>) {
    let id = session.id;
    // Capture the diff artifact from the materialized workspace.
    let ws_dir = state
        .cfg
        .data_dir
        .join("workspaces")
        .join(id.to_string())
        .join("repo");
    if ws_dir.exists() {
        match fluidbox_provider::workspace::capture_diff(&ws_dir, session.base_commit.as_deref()) {
            Ok(diff) if !diff.trim().is_empty() => {
                fluidbox_db::add_artifact(&state.pool, id, "diff", "changes.patch", &diff, "text/x-diff")
                    .await
                    .ok();
            }
            Ok(_) => {
                fluidbox_db::add_artifact(&state.pool, id, "diff", "changes.patch", "(no changes)", "text/plain")
                    .await
                    .ok();
            }
            Err(e) => tracing::warn!("diff capture failed for {id}: {e}"),
        }
    }

    if let Some(s) = summary {
        fluidbox_db::set_result_summary(&state.pool, id, s).await.ok();
        fluidbox_db::add_artifact(&state.pool, id, "summary", "summary.md", s, "text/markdown")
            .await
            .ok();
    }

    let terminal = match outcome {
        "completed" => SessionStatus::Completed,
        "cancelled" => SessionStatus::Cancelled,
        "budget_exceeded" => SessionStatus::BudgetExceeded,
        _ => SessionStatus::Failed,
    };
    ledger::record(
        state,
        id,
        Actor::Harness,
        EventBody::RunResult { outcome: outcome.into(), summary: summary.map(|s| s.to_string()) },
    )
    .await;
    transition(state, id, terminal, summary).await;
    reap(state, id).await;
}

/// Tear down the sandbox for a session (idempotent).
pub async fn reap(state: &AppState, id: Uuid) {
    if let Ok(Some(session)) = fluidbox_db::get_session(&state.pool, id).await {
        if let Some(handle_json) = session.sandbox_handle {
            if let Ok(handle) = serde_json::from_value::<SandboxHandle>(handle_json) {
                if let Err(e) = state.provider.terminate(&handle).await {
                    tracing::warn!("reap {id}: {e}");
                }
            }
        }
    }
}

/// Cancel a session (admin action).
pub async fn cancel(state: &AppState, id: Uuid) -> bool {
    if let Ok(Some(s)) = fluidbox_db::get_session(&state.pool, id).await {
        if s.status_enum().is_terminal() {
            return false;
        }
    }
    let ok = transition(state, id, SessionStatus::Cancelled, Some("cancelled by user")).await;
    if ok {
        reap(state, id).await;
    }
    ok
}

fn uuid_token() -> String {
    // 32 hex chars of entropy from a v4 uuid (no extra deps).
    Uuid::new_v4().simple().to_string()
}
