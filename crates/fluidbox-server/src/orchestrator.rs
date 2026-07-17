//! Session lifecycle driver. The server is the single status writer; the
//! runner only reports events/heartbeats/result. This module owns the
//! transitions, the sandbox, workspace init, budget enforcement, and the
//! durable terminal finalizer.
//!
//! **Durable finalizer (K8s design 2026-07-15, Phase 0).** Every terminal
//! path — result, cancel, fail, watchdog, budget — funnels through
//! `begin_finalize` → a persisted `session_finalizations` intent + a
//! `cancelling`/`finalizing` state → `drive_finalization`, which collects the
//! diff artifact BEFORE the terminal transition. Because delivery enqueue
//! rides terminal entry (in `transition`), collection can never race the
//! artifact. The intent is persisted before `/result` ACKs, and a
//! restart-recoverable worker re-drives any interrupted finalization, so a
//! crash mid-finalize strands nothing.

use crate::ledger;
use crate::state::AppState;
use fluidbox_core::event::{Actor, EventBody};
use fluidbox_core::spec::{RunSpec, WorkspaceSpec};
use fluidbox_core::state::SessionStatus;
use fluidbox_core::traits::{CollectContext, CollectedArtifacts, SandboxHandle, SandboxSpec};
use fluidbox_db::SessionRow;
use std::path::PathBuf;
use std::time::Duration;
use uuid::Uuid;

const SESSION_TOKEN_TTL_SECS: i64 = 3 * 3600;

/// Cancellation quiesce deadline: three 10 s heartbeat opportunities + jitter
/// (settled Q5; 20 s rejected as only two opportunities). Past it, a racing
/// worktree is never collected — the diff is recorded `artifact_missing`.
const QUIESCE_DEADLINE_SECS: i64 = 30;

/// A finalization claim older than this is re-drivable (the previous driver
/// crashed). Comfortably above the collection + quiesce budget below.
const FINALIZE_CLAIM_STALE_SECS: i64 = 180;

/// Terminal artifact collection is bounded: a hostile or huge worktree can
/// waste the cap, never wedge `finalizing`.
const COLLECT_TIMEOUT: Duration = Duration::from_secs(120);

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
                // Defense-in-depth: kill the session's tokens the moment it
                // goes terminal so a still-running or leaked token can't reach
                // the facade/gateway. The PRIMARY guard is each endpoint's own
                // terminal/wind-down check.
                if let Err(e) = fluidbox_db::revoke_session_tokens(&state.pool, id).await {
                    tracing::warn!("revoke_session_tokens {id} failed: {e}");
                }
                // Publication is decoupled: enqueue rows; the delivery worker
                // owns retries. This is the ONLY enqueue point — every exit
                // path funnels through here — and it fires on terminal entry,
                // which is now reachable ONLY from `finalizing`, so the diff
                // artifact is already stored when delivery is enqueued.
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

/// Terminal completion (runner `/result`, wall-clock budget, tool-call
/// budget). Collects the diff before terminalizing; no quiesce (the runner
/// already stopped, or is being stopped without needing a clean worktree
/// beyond what it left).
pub async fn finalize(
    state: &AppState,
    session: &SessionRow,
    outcome: &str,
    summary: Option<&str>,
) {
    begin_finalize(state, session.id, outcome, summary, summary, false).await;
}

/// Terminal failure. Same durable path — a failed run now STILL collects
/// whatever the agent produced (fixes live defect #1: `fail()` used to reap
/// with no diff).
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
    begin_finalize(state, id, "failed", None, Some(reason), false).await;
}

/// Cancel a session (admin action, or a `replace` concurrency policy). Rides
/// the durable finalizer WITH quiesce: the runner is asked (via its heartbeat
/// response) to stop and NOT post `/result`, we wait up to 30 s for a clean
/// worktree, then collect. Returns true if cancellation was initiated (the
/// terminal `cancelled` lands asynchronously after collection).
pub async fn cancel(state: &AppState, id: Uuid, reason: &str) -> bool {
    let Ok(Some(session)) = fluidbox_db::get_session(&state.pool, id).await else {
        return false;
    };
    let st = session.status_enum();
    if st.is_terminal() || st.is_winding_down() {
        return false;
    }
    begin_finalize(state, id, "cancelled", None, Some(reason), true).await
}

/// Persist the terminal intent, enter the matching wind-down state, and kick
/// the driver. Idempotent: a racing second caller (e.g. `/result` and the
/// wall-clock sweeper) sees the intent already recorded and defers.
async fn begin_finalize(
    state: &AppState,
    id: Uuid,
    outcome: &str,
    summary: Option<&str>,
    reason: Option<&str>,
    want_quiesce: bool,
) -> bool {
    let Ok(Some(session)) = fluidbox_db::get_session(&state.pool, id).await else {
        return false;
    };
    let st = session.status_enum();
    if st.is_terminal() {
        return false;
    }

    // Quiesce only makes sense while a runner is actually live to receive the
    // heartbeat signal; otherwise go straight to collection.
    let quiesce = want_quiesce
        && matches!(st, SessionStatus::Running | SessionStatus::AwaitingApproval)
        && session.sandbox_handle.is_some();
    let (winddown, deadline) = if quiesce {
        (
            SessionStatus::Cancelling,
            Some(chrono::Utc::now() + chrono::Duration::seconds(QUIESCE_DEADLINE_SECS)),
        )
    } else {
        (SessionStatus::Finalizing, None)
    };

    // Persist intent BEFORE any ACK / state change (the /result-lossiness fix).
    // A DB error here must NOT leave the session winding down without a durable
    // intent — the recovery worker joins on `session_finalizations`, so an
    // intent-less `finalizing` session would strand forever. Fail closed:
    // don't transition; the caller/watchdog can retry.
    let created = match fluidbox_db::begin_finalization(
        &state.pool,
        id,
        outcome,
        summary,
        reason,
        quiesce,
        deadline,
    )
    .await
    {
        Ok(c) => c,
        Err(e) => {
            tracing::error!("begin_finalization {id} failed, not winding down: {e}");
            return false;
        }
    };

    // If the session is already winding down (a retry, or the other of a
    // /result+cancel race), don't re-transition — just make sure a driver runs.
    if !st.is_winding_down() {
        transition(state, id, winddown, reason).await;
    }

    if quiesce && created {
        ledger::record(
            state,
            id,
            Actor::System,
            EventBody::QuiesceRequested {
                deadline_secs: QUIESCE_DEADLINE_SECS as u64,
            },
        )
        .await;
    }

    let state2 = state.clone();
    tokio::spawn(async move {
        drive_finalization(&state2, id).await;
    });
    true
}

/// Drive one session's finalization to a terminal state. Claim-guarded (so
/// only one driver acts at a time) and idempotent (the `finalizing→terminal`
/// transition is the single-winner gate). Safe to call repeatedly — the
/// recovery worker calls it for any interrupted finalization.
pub async fn drive_finalization(state: &AppState, id: Uuid) {
    let claimed = fluidbox_db::claim_finalization(&state.pool, id, FINALIZE_CLAIM_STALE_SECS).await;
    let intent = match claimed {
        Ok(Some(i)) => i,
        Ok(None) => return, // another driver owns it, or no intent — nothing to do
        Err(e) => {
            tracing::warn!("claim_finalization {id} failed: {e}");
            return;
        }
    };

    let Ok(Some(session)) = fluidbox_db::get_session(&state.pool, id).await else {
        fluidbox_db::delete_finalization(&state.pool, id).await.ok();
        return;
    };
    if session.status_enum().is_terminal() {
        fluidbox_db::delete_finalization(&state.pool, id).await.ok();
        return;
    }

    // Cancelling → wait for the runner to quiesce (or the deadline), then
    // enter the collection phase.
    let mut skip_collection = false;
    if session.status_enum() == SessionStatus::Cancelling {
        let timed_out = await_quiesce(state, &session, intent.quiesce_deadline).await;
        if timed_out {
            skip_collection = true; // never collect a racing worktree
        }
        transition(
            state,
            id,
            SessionStatus::Finalizing,
            intent.reason.as_deref(),
        )
        .await;
    }

    collect_and_terminalize(state, id, &intent, skip_collection).await;
}

/// Block until the runner's sandbox is no longer live (clean quiesce) or the
/// deadline passes. Returns true on timeout.
async fn await_quiesce(
    state: &AppState,
    session: &SessionRow,
    deadline: Option<chrono::DateTime<chrono::Utc>>,
) -> bool {
    let deadline = deadline.unwrap_or_else(chrono::Utc::now);
    let handle: Option<SandboxHandle> = session
        .sandbox_handle
        .clone()
        .and_then(|j| serde_json::from_value(j).ok());
    let Some(handle) = handle else {
        return false; // no sandbox to wait on
    };
    loop {
        if chrono::Utc::now() >= deadline {
            return true;
        }
        match state.provider.state(&handle).await {
            Ok(st) if !st.is_live() => return false, // runner exited
            _ => {}
        }
        tokio::time::sleep(Duration::from_millis(750)).await;
    }
}

/// Collect the diff (unless skipped), store the artifact or an explicit
/// `artifact_missing`, then make the single terminal transition, reap, and
/// clear the intent.
async fn collect_and_terminalize(
    state: &AppState,
    id: Uuid,
    intent: &fluidbox_db::FinalizationRow,
    skip_collection: bool,
) {
    let Ok(Some(session)) = fluidbox_db::get_session(&state.pool, id).await else {
        return;
    };

    // A diff is only "expected" once the session had a workspace/sandbox — a
    // pre-launch failure records no artifact_missing noise.
    let expected_diff = session.started_at.is_some()
        || session.base_commit.is_some()
        || session.sandbox_handle.is_some();

    if skip_collection {
        record_missing(state, id, "quiesce_timeout").await;
    } else {
        let handle: Option<SandboxHandle> = session
            .sandbox_handle
            .clone()
            .and_then(|j| serde_json::from_value(j).ok());
        let ctx = CollectContext {
            session_id: id,
            base_commit: session.base_commit.clone(),
        };
        let collected = tokio::time::timeout(
            COLLECT_TIMEOUT,
            state.provider.collect_artifacts(handle.as_ref(), &ctx),
        )
        .await;
        match collected {
            Ok(Ok(CollectedArtifacts::Collected(arts))) => {
                store_collected(state, id, arts).await;
            }
            Ok(Ok(CollectedArtifacts::Missing { reason })) => {
                if expected_diff {
                    record_missing(state, id, &reason).await;
                }
            }
            Ok(Err(e)) => {
                if expected_diff {
                    record_missing(state, id, &format!("collector error: {e}")).await;
                }
            }
            Err(_) => {
                if expected_diff {
                    record_missing(state, id, "collection_timeout").await;
                }
            }
        }
    }

    // Summary artifact (unchanged shape).
    if let Some(s) = intent.summary.as_deref() {
        fluidbox_db::set_result_summary(&state.pool, id, s)
            .await
            .ok();
        fluidbox_db::upsert_artifact(&state.pool, id, "summary", "summary.md", s, "text/markdown")
            .await
            .ok();
    }

    ledger::record(
        state,
        id,
        Actor::Harness,
        EventBody::RunResult {
            outcome: intent.outcome.clone(),
            summary: intent.summary.clone(),
        },
    )
    .await;

    let terminal = match intent.outcome.as_str() {
        "completed" => SessionStatus::Completed,
        "cancelled" => SessionStatus::Cancelled,
        "budget_exceeded" => SessionStatus::BudgetExceeded,
        _ => SessionStatus::Failed,
    };
    // The single-winner gate: delivery enqueue rides this transition.
    transition(state, id, terminal, intent.reason.as_deref()).await;

    reap(state, id).await;
    if !state.cfg.keep_workspaces {
        if let Err(e) = fluidbox_workspace::cleanup_workspace(&state.cfg.data_dir, id) {
            tracing::warn!("workspace cleanup failed for {id}: {e}");
        }
        delete_archive(&state.cfg.data_dir, id);
    }
    fluidbox_db::delete_finalization(&state.pool, id).await.ok();
}

async fn store_collected(
    state: &AppState,
    id: Uuid,
    arts: Vec<fluidbox_core::traits::CollectedArtifact>,
) {
    for a in arts {
        // A clean worktree is a real (empty) result, not a missing diff — the
        // artifact contract keeps a diff row on every collected run.
        let (content, content_type): (String, String) =
            if a.kind == "diff" && a.content.trim().is_empty() {
                ("(no changes)".into(), "text/plain".into())
            } else {
                (a.content.clone(), a.content_type.clone())
            };
        fluidbox_db::upsert_artifact(&state.pool, id, &a.kind, &a.name, &content, &content_type)
            .await
            .ok();
        ledger::record(
            state,
            id,
            Actor::System,
            EventBody::ArtifactCollected {
                kind: a.kind,
                name: a.name,
                bytes: a.bytes,
                sha256: a.sha256,
                truncated: a.truncated,
            },
        )
        .await;
    }
}

async fn record_missing(state: &AppState, id: Uuid, reason: &str) {
    fluidbox_db::upsert_artifact(
        &state.pool,
        id,
        "diff",
        "changes.patch",
        &format!("(diff unavailable: {reason})"),
        "text/plain",
    )
    .await
    .ok();
    ledger::record(
        state,
        id,
        Actor::System,
        EventBody::ArtifactMissing {
            kind: "diff".into(),
            reason: reason.into(),
        },
    )
    .await;
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
    let (workspace_dir, base_commit) = materialize_workspace(&state, session_id, &run_spec).await?;

    let control_url = state.cfg.public_control_url.clone();
    let env = build_runner_env(&run_spec, &control_url, session_id, &session_token);

    // 512 KiB serialized runner-env ceiling (env injection is the v1 config
    // channel; a Kubernetes Secret caps ~1 MiB). Fail closed at zero spend.
    let env_bytes = serialized_env_len(&env);
    if env_bytes > crate::config::MAX_RUNNER_ENV_BYTES {
        anyhow::bail!(
            "runner env is {env_bytes} bytes, over the {} byte ceiling ({})",
            crate::config::MAX_RUNNER_ENV_BYTES,
            env_size_breakdown(&env)
        );
    }

    // Archive-transport providers (Kubernetes) pull an immutable, credential-
    // free archive the control plane packs here. Host-dir providers (Docker)
    // bind mount and skip this. Authority stays control-plane-side either way.
    let workspace_archive = if state.provider.workspace_transport()
        == fluidbox_core::traits::WorkspaceTransport::Archive
    {
        match &workspace_dir {
            Some(_) => Some(pack_and_store_archive(&state, session_id, base_commit.clone()).await?),
            None => None,
        }
    } else {
        None
    };

    let sandbox_spec = SandboxSpec {
        session_id,
        image: run_spec.runner_image.clone(),
        env,
        workspace_host_dir: workspace_dir.as_ref().map(|p| p.display().to_string()),
        workspace_archive,
        active_deadline_secs: run_spec.budgets.max_wall_clock_secs,
        network: state.cfg.network_mode,
    };

    let handle = state.provider.provision(&sandbox_spec).await?;
    fluidbox_db::set_sandbox_handle(&state.pool, session_id, &serde_json::to_value(&handle)?)
        .await?;

    // initializing → running (traffic is now expected)
    transition(&state, session_id, SessionStatus::Running, None).await;
    fluidbox_db::heartbeat(&state.pool, session_id).await.ok();

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

/// Assemble the runner env. The generic FLUIDBOX_* block is the harness-neutral
/// runner contract; per-harness extras ride `harness::runner_env`.
pub fn build_runner_env(
    run_spec: &RunSpec,
    control_url: &str,
    session_id: Uuid,
    session_token: &str,
) -> Vec<(String, String)> {
    let mut env = vec![
        ("FLUIDBOX_CONTROL_URL".into(), control_url.to_string()),
        ("FLUIDBOX_SESSION_ID".into(), session_id.to_string()),
        ("FLUIDBOX_SESSION_TOKEN".into(), session_token.to_string()),
        ("FLUIDBOX_TASK".into(), run_spec.task.clone()),
        (
            "FLUIDBOX_AUTONOMY".into(),
            run_spec.autonomy.as_str().into(),
        ),
        ("FLUIDBOX_MODEL".into(), run_spec.model.clone()),
        ("FLUIDBOX_WORKSPACE".into(), "/workspace".into()),
    ];
    env.extend(crate::harness::runner_env(
        &run_spec.harness,
        control_url,
        session_token,
        &run_spec.model,
    ));
    if let Some(sp) = &run_spec.system_prompt {
        env.push(("FLUIDBOX_SYSTEM_PROMPT".into(), sp.clone()));
    }
    if !run_spec.capabilities.is_empty() {
        env.push((
            "FLUIDBOX_CAPABILITIES".into(),
            runner_capability_manifest(&run_spec.capabilities).to_string(),
        ));
    }
    env
}

/// Serialized size the provider must transport (env-var form: `K=V\0`).
pub fn serialized_env_len(env: &[(String, String)]) -> usize {
    env.iter().map(|(k, v)| k.len() + v.len() + 2).sum()
}

/// The on-disk archive path for a session (PVC-backed in Kubernetes; survives
/// a `Recreate` upgrade so init can still pull after a control-plane restart).
pub fn archive_path(data_dir: &std::path::Path, session_id: Uuid) -> PathBuf {
    data_dir
        .join("archives")
        .join(format!("{session_id}.tar.gz"))
}

/// Pack the materialized workspace into an immutable archive, store it, and
/// return the descriptor the init container verifies. The archive URL is on
/// the INTERNAL listener (the pod reaches it with the session token it already
/// holds — nothing new becomes reachable).
async fn pack_and_store_archive(
    state: &AppState,
    session_id: Uuid,
    base_commit: Option<String>,
) -> anyhow::Result<fluidbox_core::traits::WorkspaceArchive> {
    let data_dir = state.cfg.data_dir.clone();
    let max_bytes = state.cfg.max_archive_bytes;
    let dest = archive_path(&data_dir, session_id);
    // Streamed to disk (GzEncoder<File>) — the archive never lives in RAM,
    // and the size cap fails the run HERE, before any sandbox or model spend.
    let packed = tokio::task::spawn_blocking(move || {
        let root = fluidbox_workspace::session_workspace_root(&data_dir, session_id);
        if let Some(parent) = dest.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let packed = fluidbox_workspace::pack_workspace_to_file(&root, &dest, max_bytes)?;
        Ok::<_, anyhow::Error>(packed)
    })
    .await??;

    // The pod pulls from the internal control URL (the same base the runner
    // uses for every other internal call).
    let url = format!(
        "{}/internal/sessions/{}/workspace",
        state.cfg.public_control_url.trim_end_matches('/'),
        session_id
    );
    Ok(fluidbox_core::traits::WorkspaceArchive {
        url,
        sha256: packed.sha256,
        len: packed.len,
        base_commit,
    })
}

/// Delete a session's stored archive (idempotent). Called eagerly on the
/// first runner heartbeat (init consumed it) and again at finalize; the
/// periodic TTL sweep (`workers::archive_ttl_sweep`) is the backstop for the
/// crash windows in between.
pub fn delete_archive(data_dir: &std::path::Path, session_id: Uuid) {
    let _ = std::fs::remove_file(archive_path(data_dir, session_id));
}

/// Remove every stored archive whose mtime is older than `ttl`. The archive
/// is single-use transport (the init container pulls it once) — anything this
/// old is a leak: a pre-launch crash, or a crash after the terminal
/// transition but before `delete_archive`. Returns how many were removed.
pub fn sweep_stale_archives(data_dir: &std::path::Path, ttl: std::time::Duration) -> usize {
    let dir = data_dir.join("archives");
    let Ok(entries) = std::fs::read_dir(&dir) else {
        return 0; // No archives ever stored (e.g. the Docker provider).
    };
    let now = std::time::SystemTime::now();
    let mut removed = 0;
    for entry in entries.flatten() {
        let path = entry.path();
        let Ok(meta) = entry.metadata() else { continue };
        if !meta.is_file() {
            continue;
        }
        let Ok(mtime) = meta.modified() else { continue };
        let stale = now
            .duration_since(mtime)
            .map(|age| age >= ttl)
            .unwrap_or(false);
        if stale && std::fs::remove_file(&path).is_ok() {
            tracing::info!("archive TTL sweep removed {}", path.display());
            removed += 1;
        }
    }
    removed
}

pub fn env_size_breakdown(env: &[(String, String)]) -> String {
    let mut parts: Vec<(usize, &str)> = env
        .iter()
        .map(|(k, v)| (k.len() + v.len(), k.as_str()))
        .collect();
    parts.sort_by_key(|&(n, _)| std::cmp::Reverse(n)); // largest first
    parts
        .iter()
        .take(4)
        .map(|(n, k)| format!("{k}={n}B"))
        .collect::<Vec<_>>()
        .join(", ")
}

/// The sandbox-facing slice of the frozen capability set. The runner needs:
/// sandbox servers' launch specs (command/args), and brokered servers'
/// frozen tool snapshots (to advertise them via the broker shim). Broker
/// internals — URLs, connection ids — stay out of the sandbox.
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
) -> anyhow::Result<(Option<PathBuf>, Option<String>)> {
    let data_dir = state.cfg.data_dir.clone();
    let (ws, repo, r#ref) = match &run_spec.workspace {
        WorkspaceSpec::LocalCopy { path } => {
            let src = PathBuf::from(path);
            let ws = tokio::task::spawn_blocking(move || {
                fluidbox_workspace::materialize_local(&data_dir, session_id, &src)
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
                fluidbox_workspace::materialize_git(
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
                fluidbox_workspace::materialize_local(&data_dir, session_id, &dir)
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
    Ok((Some(ws.host_dir), ws.base_commit))
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

fn uuid_token() -> String {
    // 32 hex chars of entropy from a v4 uuid (no extra deps).
    Uuid::new_v4().simple().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ttl_sweep_removes_only_stale_archives() {
        let tmp = std::env::temp_dir().join(format!("fbx-ttl-{}", uuid::Uuid::now_v7()));
        let archives = tmp.join("archives");
        std::fs::create_dir_all(&archives).unwrap();
        std::fs::write(archives.join("a.tar.gz"), b"x").unwrap();
        std::fs::write(archives.join("b.tar.gz"), b"y").unwrap();

        // A generous TTL keeps fresh archives.
        assert_eq!(
            sweep_stale_archives(&tmp, std::time::Duration::from_secs(3600)),
            0
        );
        assert!(archives.join("a.tar.gz").exists());

        // TTL zero: everything with mtime <= now is stale.
        assert_eq!(sweep_stale_archives(&tmp, std::time::Duration::ZERO), 2);
        assert!(!archives.join("a.tar.gz").exists());
        assert!(!archives.join("b.tar.gz").exists());

        // A missing archives dir (Docker provider) is a quiet no-op.
        assert_eq!(
            sweep_stale_archives(&tmp.join("nope"), std::time::Duration::ZERO),
            0
        );
        std::fs::remove_dir_all(&tmp).ok();
    }
}
