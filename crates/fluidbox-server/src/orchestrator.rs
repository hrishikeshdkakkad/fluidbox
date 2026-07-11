//! Session lifecycle driver. The server is the single status writer; the
//! runner only reports events/heartbeats/result. This module owns the
//! transitions, the sandbox, workspace init, budget enforcement, and reaping.

use crate::ledger;
use crate::state::AppState;
use fluidbox_core::event::{Actor, EventBody};
use fluidbox_core::spec::{RunSpec, WorkspaceSpec};
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
            if next.is_terminal() {
                // Publication is decoupled: enqueue rows; the delivery worker
                // owns retries. This is the ONLY enqueue point — every exit
                // path (finalize/fail/cancel/sweeps) funnels through here,
                // and the state machine makes terminal entry exactly-once.
                crate::deliveries::enqueue_for_session(state, id).await;
            }
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
    ledger::record(
        state,
        id,
        Actor::System,
        EventBody::RunError {
            message: reason.into(),
        },
    )
    .await;
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
        (
            "FLUIDBOX_AUTONOMY".into(),
            run_spec.autonomy.as_str().into(),
        ),
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
    if !run_spec.capabilities.is_empty() {
        env.push((
            "FLUIDBOX_CAPABILITIES".into(),
            runner_capability_manifest(&run_spec.capabilities).to_string(),
        ));
    }

    let sandbox_spec = SandboxSpec {
        session_id,
        image: run_spec.runner_image.clone(),
        env,
        workspace_host_dir: workspace_dir.as_ref().map(|p| p.display().to_string()),
        network: NetworkMode::HostDev,
    };

    let handle = state.provider.provision(&sandbox_spec).await?;
    fluidbox_db::set_sandbox_handle(&state.pool, session_id, &serde_json::to_value(&handle)?)
        .await?;

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
            text: format!(
                "sandbox launched ({})",
                handle.external_id.chars().take(12).collect::<String>()
            ),
        },
    )
    .await;

    Ok(())
}

/// The sandbox-facing slice of the frozen capability set. The runner needs:
/// sandbox servers' launch specs (command/args), and brokered servers'
/// frozen tool snapshots (to advertise them via the broker shim). Broker
/// internals — URLs, connection ids — stay out of the sandbox: it holds an
/// intent channel, not a map of the control plane's upstreams.
fn runner_capability_manifest(
    capabilities: &[fluidbox_core::capability::FrozenBundle],
) -> serde_json::Value {
    use fluidbox_core::capability::CapabilityServer;
    let servers: Vec<serde_json::Value> = capabilities
        .iter()
        .flat_map(|b| &b.servers)
        .map(|s| match s {
            CapabilityServer::Sandbox {
                name,
                command,
                args,
                ..
            } => serde_json::json!({
                "class": "sandbox", "name": name, "command": command, "args": args,
            }),
            CapabilityServer::Brokered { name, tools, .. } => serde_json::json!({
                "class": "brokered", "name": name,
                "tools": tools.iter().map(|t| serde_json::json!({
                    "name": t.name,
                    "description": t.description,
                    "input_schema": t.input_schema,
                })).collect::<Vec<_>>(),
            }),
        })
        .collect();
    serde_json::json!({ "servers": servers })
}

async fn materialize_workspace(
    state: &AppState,
    session_id: Uuid,
    run_spec: &RunSpec,
) -> anyhow::Result<Option<PathBuf>> {
    let data_dir = state.cfg.data_dir.clone();
    let (ws, repo, r#ref) = match &run_spec.workspace {
        WorkspaceSpec::LocalCopy { path } => {
            let src = PathBuf::from(path);
            let ws = tokio::task::spawn_blocking(move || {
                fluidbox_provider::workspace::materialize_local(&data_dir, session_id, &src)
            })
            .await??;
            (ws, None, None)
        }
        WorkspaceSpec::GitRepository {
            connection_id,
            clone_url,
            r#ref,
            commit_sha,
            ..
        } => {
            // The credential is unsealed here, used for the fetch, and
            // dropped — it never reaches the RunSpec, sandbox env, ledger,
            // or artifacts.
            let auth_header = match connection_id {
                Some(cid) => Some(connection_auth_header(state, *cid).await?),
                None => None,
            };
            let (url, rf, sha) = (clone_url.clone(), r#ref.clone(), commit_sha.clone());
            let ws = tokio::task::spawn_blocking(move || {
                fluidbox_provider::workspace::materialize_git(
                    &data_dir,
                    session_id,
                    &url,
                    rf.as_deref(),
                    sha.as_deref(),
                    auth_header.as_deref(),
                )
            })
            .await??;
            (ws, Some(clone_url.clone()), r#ref.clone())
        }
        WorkspaceSpec::Scratch => {
            // A scratch workspace so the agent still has somewhere to write.
            let dir = data_dir
                .join("workspaces")
                .join(session_id.to_string())
                .join("repo");
            std::fs::create_dir_all(&dir)?;
            let ws = tokio::task::spawn_blocking(move || {
                fluidbox_provider::workspace::materialize_local(&data_dir, session_id, &dir)
            })
            .await??;
            (ws, None, None)
        }
    };

    if let Some(bc) = &ws.base_commit {
        fluidbox_db::set_base_commit(&state.pool, session_id, bc)
            .await
            .ok();
    }
    ledger::record(
        state,
        session_id,
        Actor::System,
        EventBody::WorkspaceInitialized {
            base_commit: ws.base_commit.clone(),
            files: Some(ws.file_count),
            repo,
            r#ref,
        },
    )
    .await;
    Ok(Some(ws.host_dir))
}

/// Resolve a connection into an `Authorization` header value for git fetch
/// via the provider's connector (PAT, or a minted App installation token).
/// Fails closed: missing/revoked connection or missing key stops the run
/// during `initializing` — before any model spend.
async fn connection_auth_header(state: &AppState, connection_id: Uuid) -> anyhow::Result<String> {
    let conn = fluidbox_db::get_connection(&state.pool, connection_id)
        .await?
        .ok_or_else(|| anyhow::anyhow!("connection {connection_id} not found"))?;
    crate::connectors::fetch_auth_header(state, &conn).await
}

/// Capture the diff artifact from the materialized workspace, then remove
/// the per-session workspace dir (idempotent; kept when the capture failed
/// or FLUIDBOX_KEEP_WORKSPACES is set, so there's something to debug).
async fn capture_diff_and_cleanup(state: &AppState, session: &SessionRow) {
    let id = session.id;
    let ws_dir = state
        .cfg
        .data_dir
        .join("workspaces")
        .join(id.to_string())
        .join("repo");
    let mut captured = true;
    if ws_dir.exists() {
        match fluidbox_provider::workspace::capture_diff(&ws_dir, session.base_commit.as_deref()) {
            Ok(diff) if !diff.trim().is_empty() => {
                fluidbox_db::add_artifact(
                    &state.pool,
                    id,
                    "diff",
                    "changes.patch",
                    &diff,
                    "text/x-diff",
                )
                .await
                .ok();
            }
            Ok(_) => {
                fluidbox_db::add_artifact(
                    &state.pool,
                    id,
                    "diff",
                    "changes.patch",
                    "(no changes)",
                    "text/plain",
                )
                .await
                .ok();
            }
            Err(e) => {
                captured = false;
                tracing::warn!("diff capture failed for {id}: {e}");
            }
        }
    }
    if captured && !state.cfg.keep_workspaces {
        if let Err(e) = fluidbox_provider::workspace::cleanup_workspace(&state.cfg.data_dir, id) {
            tracing::warn!("workspace cleanup failed for {id}: {e}");
        }
    }
}

/// Called by the internal /result handler: finalize a run, capture the diff,
/// then reap the sandbox.
pub async fn finalize(
    state: &AppState,
    session: &SessionRow,
    outcome: &str,
    summary: Option<&str>,
) {
    let id = session.id;
    capture_diff_and_cleanup(state, session).await;

    if let Some(s) = summary {
        fluidbox_db::set_result_summary(&state.pool, id, s)
            .await
            .ok();
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
        EventBody::RunResult {
            outcome: outcome.into(),
            summary: summary.map(|s| s.to_string()),
        },
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

/// Cancel a session (admin action, or a `replace` concurrency policy).
/// Captures whatever the agent produced so far as the diff artifact, then
/// tears everything down.
pub async fn cancel(state: &AppState, id: Uuid, reason: &str) -> bool {
    let Ok(Some(session)) = fluidbox_db::get_session(&state.pool, id).await else {
        return false;
    };
    if session.status_enum().is_terminal() {
        return false;
    }
    let ok = transition(state, id, SessionStatus::Cancelled, Some(reason)).await;
    if ok {
        reap(state, id).await;
        capture_diff_and_cleanup(state, &session).await;
    }
    ok
}

fn uuid_token() -> String {
    // 32 hex chars of entropy from a v4 uuid (no extra deps).
    Uuid::new_v4().simple().to_string()
}
