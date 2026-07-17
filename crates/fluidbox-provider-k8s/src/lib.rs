//! fluidbox-provider-k8s — the Kubernetes ExecutionProvider (design
//! 2026-07-15). One bare Pod per run in a dedicated sandbox namespace, via
//! kube-rs. Runner images run UNMODIFIED; the pod pulls a credential-free
//! immutable archive; the diff is collected in-pod against a pristine baseline
//! over `pods/exec`. All Kubernetes knowledge lives in this crate — the server
//! sees only the `ExecutionProvider` trait.
//!
//! Invariants (mirrored from the design):
//! - Pod-first/Secret-second with an ownerReference → Pod, so the token
//!   Secret is GC-reaped and never orphaned; no patch step, no orphan window.
//! - Every mutation is UID-preconditioned: a stale handle can never delete a
//!   Pod that reused the deterministic name.
//! - `state()` inspects the NAMED runner container, not Pod phase (the
//!   collector keeps the Pod Running after the runner exits, by design).
//! - Watches accelerate detection but are never truth; the orchestrator's
//!   periodic list/reconcile is authoritative (same philosophy as SSE
//!   NOTIFY+seq).

use async_trait::async_trait;
use fluidbox_core::traits::{
    CollectContext, CollectedArtifact, CollectedArtifacts, ExecutionProvider, ProviderError,
    SandboxHandle, SandboxSpec, SandboxStatus, WorkspaceTransport,
};
use k8s_openapi::api::core::v1::{Pod, Secret};
use kube::api::{Api, AttachParams, DeleteParams, ListParams, Preconditions, PropagationPolicy};
use kube::core::ObjectMeta;
use kube::{Client, ResourceExt};
use std::time::Duration;
use uuid::Uuid;

pub mod config;
pub mod manifest;
pub mod netpol;

use config::K8sConfig;
use manifest::{
    build_pod, build_secret, object_name, COLLECTOR_CONTAINER, LABEL_MANAGED, LABEL_SESSION,
    RUNNER_CONTAINER,
};
use std::path::{Path, PathBuf};

const RUNTIME: &str = "kubernetes";
/// Diff artifacts are bounded at this many bytes over exec (the collector
/// already caps them; this is the receive-side ceiling).
const MAX_DIFF_BYTES: usize = 16 * 1024 * 1024;
/// How many times a dropped collection stream may resume from its last byte
/// before parse_collected's integrity check decides on what arrived.
const MAX_STREAM_RESUMES: u32 = 4;

pub struct KubernetesProvider {
    pods: Api<Pod>,
    secrets: Api<Secret>,
    cfg: K8sConfig,
    namespace: String,
    /// The control plane's data dir: pre-launch collection (no pod ever
    /// existed) falls back to the locally-materialized workspace here, the
    /// same transport Docker always uses (L9 parity).
    data_dir: PathBuf,
}

impl KubernetesProvider {
    /// Connect using the ambient kube config (in-cluster ServiceAccount, or
    /// `~/.kube/config` for local dev). Fails if no cluster is reachable.
    pub async fn connect(cfg: K8sConfig, data_dir: PathBuf) -> anyhow::Result<Self> {
        let client = Client::try_default().await?;
        Ok(Self::with_client(client, cfg, data_dir))
    }

    pub fn with_client(client: Client, cfg: K8sConfig, data_dir: PathBuf) -> Self {
        let namespace = cfg.namespace.clone();
        Self {
            pods: Api::namespaced(client.clone(), &namespace),
            secrets: Api::namespaced(client, &namespace),
            cfg,
            namespace,
            data_dir,
        }
    }

    fn handle(&self, name: &str, uid: &str) -> SandboxHandle {
        SandboxHandle {
            runtime: RUNTIME.into(),
            external_id: name.into(),
            attrs: serde_json::json!({ "namespace": self.namespace, "uid": uid }),
        }
    }

    fn handle_uid<'a>(&self, handle: &'a SandboxHandle) -> Option<&'a str> {
        handle.attrs.get("uid").and_then(|v| v.as_str())
    }

    /// UID-guarded delete of a Pod: a stale handle never deletes a Pod that
    /// reused the name. Foreground propagation reaps the Secret via its
    /// ownerReference. Idempotent (404 = already gone).
    async fn delete_pod(&self, name: &str, uid: Option<&str>) -> Result<(), ProviderError> {
        // L10: a delete without a UID precondition could remove a same-named
        // pod that is not ours. Handles always carry UIDs today — refuse the
        // unguarded form rather than ever racing a name reuse.
        let Some(uid) = uid else {
            return Err(ProviderError::Other(format!(
                "refusing unguarded delete of pod {name}: no uid precondition"
            )));
        };
        let dp = DeleteParams {
            preconditions: Some(Preconditions {
                uid: Some(uid.to_string()),
                resource_version: None,
            }),
            propagation_policy: Some(PropagationPolicy::Foreground),
            ..Default::default()
        };
        match self.pods.delete(name, &dp).await {
            Ok(_) => Ok(()),
            Err(kube::Error::Api(e)) if e.code == 404 => Ok(()),
            // A 409 precondition mismatch means the Pod is a DIFFERENT object
            // than our handle names — not ours to delete. Treat as success
            // (ours is already gone).
            Err(kube::Error::Api(e)) if e.code == 409 => Ok(()),
            Err(e) => Err(map_err(e)),
        }
    }
}

fn map_err(e: impl std::fmt::Display) -> ProviderError {
    ProviderError::Other(e.to_string())
}

/// Grace for `CreateContainerConfigError`: Pod-first/Secret-second means the
/// kubelet reports it TRANSIENTLY between Pod creation and the Secret landing
/// (~1 s in practice) — by design, not misconfiguration. Only a config error
/// persisting past this pod age is real (M6).
pub const CONFIG_ERROR_GRACE_SECS: i64 = 120;

/// Map a Pod to the structured status of its NAMED runner container (not Pod
/// phase). Init failure surfaces as a terminated runner so the orchestrator
/// fails the run; a still-pulling image is Pending with the reason.
pub fn runner_status(pod: &Pod) -> SandboxStatus {
    // Deletion in progress (reap, eviction, node-loss cleanup): the pod is
    // going away and its container statuses may be stale snapshots from an
    // unreachable kubelet — never report it live (M7).
    if pod.metadata.deletion_timestamp.is_some() {
        return SandboxStatus::Unknown {
            reason: Some("pod deletion in progress".into()),
        };
    }
    let status = match &pod.status {
        Some(s) => s,
        None => return SandboxStatus::Pending { reason: None },
    };

    // Kubelet unreachable (node loss): phase Unknown means every container
    // status below is a stale last-known snapshot — a frozen "running" must
    // not keep the sandbox live forever. Checked BEFORE container statuses
    // for exactly that reason (M7).
    if status.phase.as_deref() == Some("Unknown") {
        return SandboxStatus::Unknown {
            reason: status.reason.clone().or(Some("pod phase Unknown".into())),
        };
    }

    // A waiting reason is fatal if it never self-resolves; the config-error
    // reason is special-cased behind the Secret-window grace (M6).
    let fatal = |reason: Option<&str>| {
        fatal_waiting(reason)
            || (reason == Some("CreateContainerConfigError")
                && pod_older_than(pod, CONFIG_ERROR_GRACE_SECS))
    };

    // An init container that terminated non-zero blocks the runner forever —
    // report it as a terminated sandbox with the init reason.
    if let Some(inits) = &status.init_container_statuses {
        for c in inits {
            if let Some(term) = c.state.as_ref().and_then(|st| st.terminated.as_ref()) {
                if term.exit_code != 0 {
                    return SandboxStatus::Terminated {
                        exit_code: Some(term.exit_code as i64),
                        reason: Some(format!(
                            "init:{}",
                            term.reason.clone().unwrap_or_else(|| "Error".into())
                        )),
                    };
                }
            }
            // Still waiting on an init container (e.g. image pull) → Pending.
            if let Some(w) = c.state.as_ref().and_then(|st| st.waiting.as_ref()) {
                if fatal(w.reason.as_deref()) {
                    return SandboxStatus::Terminated {
                        exit_code: None,
                        reason: Some(format!(
                            "init:{}",
                            w.reason.clone().unwrap_or_else(|| "Waiting".into())
                        )),
                    };
                }
            }
        }
    }

    if let Some(containers) = &status.container_statuses {
        if let Some(runner) = containers.iter().find(|c| c.name == RUNNER_CONTAINER) {
            if let Some(state) = &runner.state {
                if state.running.is_some() {
                    return SandboxStatus::Running;
                }
                if let Some(term) = &state.terminated {
                    return SandboxStatus::Terminated {
                        exit_code: Some(term.exit_code as i64),
                        reason: term.reason.clone(),
                    };
                }
                if let Some(w) = &state.waiting {
                    if fatal(w.reason.as_deref()) {
                        return SandboxStatus::Terminated {
                            exit_code: None,
                            reason: w.reason.clone(),
                        };
                    }
                    return SandboxStatus::Pending {
                        reason: w.reason.clone(),
                    };
                }
            }
        }
    }

    // Overall failure with no container detail (scheduling failure, node loss).
    match status.phase.as_deref() {
        Some("Failed") => SandboxStatus::Terminated {
            exit_code: None,
            reason: status.reason.clone().or(Some("PodFailed".into())),
        },
        Some("Succeeded") => SandboxStatus::Terminated {
            exit_code: Some(0),
            reason: None,
        },
        _ => SandboxStatus::Pending {
            reason: status.reason.clone(),
        },
    }
}

/// Pod age vs `creation_timestamp`. A missing timestamp (only synthetic pods
/// in tests) counts as age zero — grace applies, nothing is killed early.
fn pod_older_than(pod: &Pod, secs: i64) -> bool {
    pod.metadata
        .creation_timestamp
        .as_ref()
        .map(|t| k8s_openapi::jiff::Timestamp::now().as_second() - t.0.as_second() > secs)
        .unwrap_or(false)
}

/// Waiting reasons that will never resolve on their own — a misconfigured
/// image or config, distinct from an in-progress pull (`ContainerCreating`,
/// `PodInitializing`, `ImagePull*` in progress). `CreateContainerConfigError`
/// is deliberately NOT here: Pod-first/Secret-second makes it transient by
/// design, so it is graced in `runner_status` (M6).
fn fatal_waiting(reason: Option<&str>) -> bool {
    matches!(
        reason,
        Some("ImagePullBackOff")
            | Some("ErrImagePull")
            | Some("InvalidImageName")
            | Some("CreateContainerError")
            | Some("RunContainerError")
    )
}

#[async_trait]
impl ExecutionProvider for KubernetesProvider {
    async fn provision(&self, spec: &SandboxSpec) -> Result<SandboxHandle, ProviderError> {
        let name = object_name(spec.session_id);

        // 1. Create the Pod referencing the not-yet-existing Secret. The
        //    kubelet holds container start until the Secret lands.
        let pod: Pod = serde_json::from_value(build_pod(spec, &self.cfg))
            .map_err(|e| ProviderError::Other(format!("bad pod manifest: {e}")))?;
        let created = self
            .pods
            .create(&Default::default(), &pod)
            .await
            .map_err(map_err)?;
        let uid = created
            .metadata
            .uid
            .clone()
            .ok_or_else(|| ProviderError::Other("created pod has no uid".into()))?;

        // 2. Create the immutable Secret with an ownerReference → Pod UID.
        let secret: Secret = serde_json::from_value(build_secret(spec, &uid))
            .map_err(|e| ProviderError::Other(format!("bad secret manifest: {e}")))?;
        if let Err(e) = self.secrets.create(&Default::default(), &secret).await {
            // Secret create failed → clean up the Pod (UID-guarded) so nothing
            // orphans, and surface the error (the orchestrator revokes the
            // token on the failed-run path).
            let _ = self.delete_pod(&name, Some(&uid)).await;
            return Err(map_err(e));
        }

        // 3. Block until workspace-init succeeded and the runner started (or a
        //    failure / deadline). `initializing → running` then matches
        //    reality and the workspace endpoint can't race the state gate.
        let deadline = std::time::Instant::now()
            + Duration::from_secs(self.cfg.init_grace_secs.max(60) as u64);
        loop {
            match self.pods.get_opt(&name).await.map_err(map_err)? {
                Some(pod) => match runner_status(&pod) {
                    SandboxStatus::Running => break,
                    SandboxStatus::Terminated { exit_code, reason } => {
                        let _ = self.delete_pod(&name, Some(&uid)).await;
                        return Err(ProviderError::Other(format!(
                            "sandbox failed to start (exit={exit_code:?} reason={reason:?})"
                        )));
                    }
                    SandboxStatus::Pending { .. } | SandboxStatus::Unknown { .. } => {}
                },
                None => {
                    return Err(ProviderError::Other(
                        "pod vanished during provisioning".into(),
                    ))
                }
            }
            if std::time::Instant::now() > deadline {
                let _ = self.delete_pod(&name, Some(&uid)).await;
                return Err(ProviderError::Other(
                    "sandbox did not start before the provisioning deadline".into(),
                ));
            }
            tokio::time::sleep(Duration::from_millis(1000)).await;
        }

        Ok(self.handle(&name, &uid))
    }

    async fn state(&self, handle: &SandboxHandle) -> Result<SandboxStatus, ProviderError> {
        match self
            .pods
            .get_opt(&handle.external_id)
            .await
            .map_err(map_err)?
        {
            None => Ok(SandboxStatus::Unknown {
                reason: Some("pod not found".into()),
            }),
            Some(pod) => {
                // UID guard: a same-named pod that reused the name is NOT ours.
                if let (Some(want), Some(got)) =
                    (self.handle_uid(handle), pod.metadata.uid.as_deref())
                {
                    if want != got {
                        return Ok(SandboxStatus::Unknown {
                            reason: Some("pod uid mismatch (name reused)".into()),
                        });
                    }
                }
                Ok(runner_status(&pod))
            }
        }
    }

    async fn collect_artifacts(
        &self,
        handle: Option<&SandboxHandle>,
        ctx: &CollectContext,
    ) -> Result<CollectedArtifacts, ProviderError> {
        let Some(handle) = handle else {
            // No handle recorded. Two very different cases hide here (L9,
            // Codex round 2):
            //  (a) the crash window between provision() succeeding and the
            //      handle landing — a pod EXISTS and its worktree is the
            //      run's real output. Collect from it, never from the
            //      control-plane copy (which would record a false
            //      "(no changes)" over real agent work).
            //  (b) the pod NEVER existed (pre-launch failure) — the
            //      control-plane copy IS authoritative; collect it exactly
            //      like the host-dir provider does ("(no changes)", not
            //      artifact_missing noise).
            // Distinguish by looking for the deterministically-named pod.
            let name = object_name(ctx.session_id);
            match self.pods.get_opt(&name).await {
                Ok(Some(pod)) => {
                    // A pod under this session's deterministic name EXISTS.
                    // Label match → it is ours: collect its worktree. Label
                    // missing/mismatched → we cannot prove whose it is, and
                    // the local fallback could contradict its real worktree —
                    // record Missing honestly instead of guessing.
                    if pod.labels().get(LABEL_SESSION).map(String::as_str)
                        == Some(ctx.session_id.to_string().as_str())
                    {
                        return self.collect_via_exec(&name).await;
                    }
                    return Ok(CollectedArtifacts::Missing {
                        reason: format!(
                            "pod {name} exists without this session's label — refusing to guess"
                        ),
                    });
                }
                Ok(None) => {
                    // VERIFIED absence: no pod ever survived to run, so the
                    // control-plane copy is authoritative (Docker parity).
                    let data_dir = self.data_dir.clone();
                    let ctx = ctx.clone();
                    return tokio::task::spawn_blocking(move || {
                        collect_from_workspace(&data_dir, &ctx)
                    })
                    .await
                    .map_err(|e| ProviderError::Other(format!("collection task panicked: {e}")));
                }
                // Cannot tell whether a pod exists — never guess with a
                // local diff that could contradict the pod's real worktree.
                Err(e) => return Err(map_err(e)),
            }
        };
        // L10 defense-in-depth: the pod behind this name must still be OUR
        // object before we exec into it — `state()` UID-guards and maps a
        // mismatched/absent pod to Unknown.
        if let Ok(SandboxStatus::Unknown { reason }) = self.state(handle).await {
            return Ok(CollectedArtifacts::Missing {
                reason: format!(
                    "pod identity unverified before collection: {}",
                    reason.unwrap_or_else(|| "unknown".into())
                ),
            });
        }
        self.collect_via_exec(&handle.external_id).await
    }

    async fn terminate(&self, handle: &SandboxHandle) -> Result<(), ProviderError> {
        self.delete_pod(&handle.external_id, self.handle_uid(handle))
            .await
    }

    async fn list_managed(&self) -> Result<Vec<(Uuid, SandboxHandle)>, ProviderError> {
        let lp = ListParams::default().labels(&format!("{LABEL_MANAGED}=true"));
        let pods = self.pods.list(&lp).await.map_err(map_err)?;
        let mut out = Vec::new();
        for pod in pods {
            // Adoption validation: the session label must parse, the pod must
            // live in OUR namespace, and it must carry a uid.
            let labels = pod.labels();
            let Some(sid) = labels
                .get(LABEL_SESSION)
                .and_then(|s| Uuid::parse_str(s).ok())
            else {
                continue;
            };
            let ns = pod.namespace().unwrap_or_default();
            if ns != self.namespace {
                continue;
            }
            let Some(uid) = pod.metadata.uid.clone() else {
                continue;
            };
            let name = pod.name_any();
            out.push((sid, self.handle(&name, &uid)));
        }
        Ok(out)
    }

    async fn healthcheck(&self) -> Result<(), ProviderError> {
        // A cheap namespaced list proves the apiserver + RBAC are reachable.
        self.pods
            .list(&ListParams::default().limit(1))
            .await
            .map(|_| ())
            .map_err(map_err)
    }

    fn workspace_transport(&self) -> WorkspaceTransport {
        WorkspaceTransport::Archive
    }

    fn runtime_name(&self) -> &'static str {
        RUNTIME
    }
}

impl KubernetesProvider {
    /// The exec collection path: compute the diff in the collector container,
    /// then stream the finished file with resume. Shared by the normal
    /// handle-carrying path and the discovered-pod path (L9).
    async fn collect_via_exec(&self, name: &str) -> Result<CollectedArtifacts, ProviderError> {
        // 1. Compute the diff in the collector container (pristine baseline +
        //    final worktree, scrubbed git), writing it to the collector-only
        //    file. A non-zero exit means that file is untrustworthy → Missing.
        if let Err(e) = self.exec_collect(name, &["workspaced", "diff"]).await {
            return Ok(CollectedArtifacts::Missing {
                reason: format!("collector diff exec failed: {e}"),
            });
        }
        // 2. Stream the finished file, resuming from the byte offset already
        //    received if the exec channel closes before the header's declared
        //    length. parse_collected makes the final integrity call.
        let raw = match self.collect_stream_with_resume(name).await {
            Ok(bytes) => bytes,
            Err(e) => {
                return Ok(CollectedArtifacts::Missing {
                    reason: format!("collector stream exec failed: {e}"),
                })
            }
        };
        Ok(parse_collected(&raw))
    }

    /// Exec a command in the collector container and return its stdout. Used
    /// for `workspaced diff` (side-effecting; stdout ignored) and
    /// `workspaced stream` (the diff bytes).
    ///
    /// The remote exit code is read via `take_status()`: a non-zero exit
    /// (transport OK, but the collector command itself failed) surfaces as an
    /// Err rather than masquerading as an empty diff. stdout and stderr are
    /// drained concurrently so a chatty stderr can't wedge the stdout read by
    /// filling the mux buffer before the process can exit.
    async fn exec_collect(&self, pod: &str, cmd: &[&str]) -> Result<Vec<u8>, ProviderError> {
        use tokio::io::AsyncReadExt;
        let ap = AttachParams::default()
            .container(COLLECTOR_CONTAINER)
            .stdout(true)
            .stderr(true);
        let mut proc = self
            .pods
            .exec(pod, cmd.to_vec(), &ap)
            .await
            .map_err(map_err)?;
        // Take the status future BEFORE draining — join() drops it.
        let status_fut = proc.take_status();
        let stdout = proc.stdout();
        let stderr = proc.stderr();
        let mut stdout_buf = Vec::new();
        let mut stderr_buf = Vec::new();
        {
            // Bounded reads: the collector already caps the diff; this stops a
            // runaway stream from exhausting control-plane memory.
            let read_out = async {
                match stdout {
                    Some(s) => {
                        s.take(MAX_DIFF_BYTES as u64)
                            .read_to_end(&mut stdout_buf)
                            .await
                    }
                    None => Ok(0),
                }
            };
            let read_err = async {
                match stderr {
                    Some(s) => s.take(64 * 1024).read_to_end(&mut stderr_buf).await,
                    None => Ok(0),
                }
            };
            let (ro, re) = tokio::join!(read_out, read_err);
            ro.map_err(|e| ProviderError::Other(format!("exec stdout read: {e}")))?;
            re.map_err(|e| ProviderError::Other(format!("exec stderr read: {e}")))?;
        }
        let status = match status_fut {
            Some(f) => f.await,
            None => None,
        };
        proc.join().await.map_err(map_err)?;
        // k8s exec Status: status="Success" on exit 0, "Failure" otherwise.
        if status.as_ref().and_then(|s| s.status.as_deref()) == Some("Failure") {
            let stderr_head: String = String::from_utf8_lossy(&stderr_buf)
                .trim()
                .chars()
                .take(300)
                .collect();
            return Err(ProviderError::Other(format!(
                "collector exec {cmd:?} exited non-zero{}{stderr_head}",
                if stderr_head.is_empty() { "" } else { ": " },
            )));
        }
        Ok(stdout_buf)
    }

    /// Stream the finished diff file, resuming on a short read. The `pods/exec`
    /// channel can close cleanly mid-file; `workspaced stream --offset N`
    /// re-emits from file byte N, so we append until we hold the header's
    /// declared length or exhaust a bounded retry budget. parse_collected then
    /// verifies the assembled bytes, so a still-short result is a visible
    /// Missing rather than a silently truncated diff.
    async fn collect_stream_with_resume(&self, name: &str) -> Result<Vec<u8>, ProviderError> {
        let mut raw = self.exec_collect(name, &["workspaced", "stream"]).await?;
        let Some((header_len, body_bytes)) = stream_target(&raw) else {
            // A missing marker or unparseable header — nothing to resume.
            return Ok(raw);
        };
        let target = header_len as u64 + body_bytes;
        let mut attempts = 0u32;
        while (raw.len() as u64) < target && attempts < MAX_STREAM_RESUMES {
            attempts += 1;
            let offset = raw.len() as u64; // next file byte we still need
            let more = self
                .exec_collect(
                    name,
                    &["workspaced", "stream", "--offset", &offset.to_string()],
                )
                .await?;
            if more.is_empty() {
                break; // no forward progress; let parse_collected judge the shortfall
            }
            raw.extend_from_slice(&more);
        }
        Ok(raw)
    }
}

/// Parse the collector's `fluidbox-diff v1 …` header + body into a
/// `CollectedArtifacts`. The header distinguishes a real (possibly empty)
/// diff from an explicit missing marker AND carries the byte count + digest
/// of the stored body. The split is on RAW bytes so the body offset is exact,
/// and an `ok` diff is verified against its header: a body of the wrong
/// length (an exec stream that closed early) or the wrong digest (corruption
/// in transit) becomes an explicit Missing, never a silently truncated diff.
fn parse_collected(raw: &[u8]) -> CollectedArtifacts {
    let Some(nl) = raw.iter().position(|&b| b == b'\n') else {
        return CollectedArtifacts::Missing {
            reason: "collector output missing/garbled header".into(),
        };
    };
    let header = String::from_utf8_lossy(&raw[..nl]);
    let body = &raw[nl + 1..];
    if !header.starts_with("fluidbox-diff v1") {
        return CollectedArtifacts::Missing {
            reason: "collector output missing/garbled header".into(),
        };
    }
    let field = |key: &str| {
        header
            .split_whitespace()
            .find_map(|tok| tok.strip_prefix(&format!("{key}=")))
    };
    match field("status") {
        Some("ok") => {
            let Some(expected_bytes) = field("bytes").and_then(|v| v.parse::<u64>().ok()) else {
                return CollectedArtifacts::Missing {
                    reason: "collector header missing a byte count".into(),
                };
            };
            let expected_sha = field("sha256").unwrap_or("").to_string();
            let truncated = field("truncated") == Some("true");

            // Integrity: length first (cheap), then digest. Either mismatch
            // means the stored file and the received stream disagree — fail
            // closed rather than store a partial diff as complete.
            if body.len() as u64 != expected_bytes {
                return CollectedArtifacts::Missing {
                    reason: format!(
                        "collector diff truncated in transit ({} of {expected_bytes} bytes)",
                        body.len()
                    ),
                };
            }
            let got_sha = {
                use sha2::{Digest, Sha256};
                format!("sha256:{}", hex::encode(Sha256::digest(body)))
            };
            if got_sha != expected_sha {
                return CollectedArtifacts::Missing {
                    reason: "collector diff digest mismatch".into(),
                };
            }

            CollectedArtifacts::Collected(vec![CollectedArtifact {
                kind: "diff".into(),
                name: "changes.patch".into(),
                content: String::from_utf8_lossy(body).into_owned(),
                content_type: "text/x-diff".into(),
                truncated,
                sha256: expected_sha,
                bytes: expected_bytes,
            }])
        }
        Some("missing") => CollectedArtifacts::Missing {
            reason: field("reason").unwrap_or("unspecified").replace('_', " "),
        },
        _ => CollectedArtifacts::Missing {
            reason: "collector reported an unknown status".into(),
        },
    }
}

/// From an assembled `fluidbox-diff v1 status=ok bytes=N …\n<body>` prefix,
/// return `(header_len_including_newline, declared_body_bytes)` — the pieces
/// the resume loop needs to know when it has the whole file. `None` for a
/// missing/garbled/non-`ok` header (nothing to resume).
fn stream_target(raw: &[u8]) -> Option<(usize, u64)> {
    let nl = raw.iter().position(|&b| b == b'\n')?;
    let header = std::str::from_utf8(&raw[..nl]).ok()?;
    if !header.starts_with("fluidbox-diff v1") {
        return None;
    }
    let field = |key: &str| {
        header
            .split_whitespace()
            .find_map(|t| t.strip_prefix(&format!("{key}=")))
    };
    if field("status") != Some("ok") {
        return None;
    }
    let bytes = field("bytes")?.parse::<u64>().ok()?;
    Some((nl + 1, bytes))
}

/// Collect from the CONTROL-PLANE copy of the workspace — the same transport
/// (and the same shared collection engine) the Docker provider always uses.
/// Only correct when no pod ever consumed/mutated anything, i.e. the
/// no-handle pre-launch path (L9).
fn collect_from_workspace(data_dir: &Path, ctx: &CollectContext) -> CollectedArtifacts {
    let root = fluidbox_workspace::session_workspace_root(data_dir, ctx.session_id);
    match fluidbox_workspace::collect_diff(
        &root,
        ctx.base_commit.as_deref(),
        &fluidbox_workspace::DiffCaps::default(),
    ) {
        fluidbox_workspace::CollectionOutcome::Diff(d) => {
            CollectedArtifacts::Collected(vec![CollectedArtifact {
                kind: "diff".into(),
                name: "changes.patch".into(),
                content: d.patch,
                content_type: "text/x-diff".into(),
                truncated: d.truncated,
                sha256: d.sha256,
                bytes: d.bytes,
            }])
        }
        fluidbox_workspace::CollectionOutcome::Missing { reason } => {
            CollectedArtifacts::Missing { reason }
        }
    }
}

/// Build a Pod ObjectMeta helper (kept for symmetry / future adoption code).
#[allow(dead_code)]
fn meta(name: &str) -> ObjectMeta {
    ObjectMeta {
        name: Some(name.into()),
        ..Default::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::INIT_CONTAINER;
    use k8s_openapi::api::core::v1::{
        ContainerState, ContainerStateRunning, ContainerStateTerminated, ContainerStateWaiting,
        ContainerStatus, PodStatus,
    };

    fn pod_with(runner: Option<ContainerState>, inits: Vec<ContainerStatus>) -> Pod {
        Pod {
            status: Some(PodStatus {
                container_statuses: runner.map(|st| {
                    vec![ContainerStatus {
                        name: RUNNER_CONTAINER.into(),
                        state: Some(st),
                        ..Default::default()
                    }]
                }),
                init_container_statuses: if inits.is_empty() { None } else { Some(inits) },
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    #[test]
    fn running_runner_is_running() {
        let st = ContainerState {
            running: Some(ContainerStateRunning::default()),
            ..Default::default()
        };
        assert_eq!(
            runner_status(&pod_with(Some(st), vec![])),
            SandboxStatus::Running
        );
    }

    #[test]
    fn terminated_runner_carries_exit_code() {
        let st = ContainerState {
            terminated: Some(ContainerStateTerminated {
                exit_code: 3,
                reason: Some("Error".into()),
                ..Default::default()
            }),
            ..Default::default()
        };
        assert_eq!(
            runner_status(&pod_with(Some(st), vec![])),
            SandboxStatus::Terminated {
                exit_code: Some(3),
                reason: Some("Error".into())
            }
        );
    }

    #[test]
    fn image_pull_backoff_is_fatal_terminated() {
        let st = ContainerState {
            waiting: Some(ContainerStateWaiting {
                reason: Some("ImagePullBackOff".into()),
                ..Default::default()
            }),
            ..Default::default()
        };
        assert!(matches!(
            runner_status(&pod_with(Some(st), vec![])),
            SandboxStatus::Terminated { .. }
        ));
    }

    #[test]
    fn container_creating_is_pending() {
        let st = ContainerState {
            waiting: Some(ContainerStateWaiting {
                reason: Some("ContainerCreating".into()),
                ..Default::default()
            }),
            ..Default::default()
        };
        assert!(matches!(
            runner_status(&pod_with(Some(st), vec![])),
            SandboxStatus::Pending { .. }
        ));
    }

    #[test]
    fn failed_init_container_is_terminated() {
        let init = ContainerStatus {
            name: "workspace-init".into(),
            state: Some(ContainerState {
                terminated: Some(ContainerStateTerminated {
                    exit_code: 1,
                    reason: Some("Error".into()),
                    ..Default::default()
                }),
                ..Default::default()
            }),
            ..Default::default()
        };
        assert!(matches!(
            runner_status(&pod_with(None, vec![init])),
            SandboxStatus::Terminated { .. }
        ));
    }

    #[test]
    fn deleting_pod_maps_to_unknown_even_with_stale_running_status() {
        // Node loss / eviction: deletionTimestamp lands while the (stale)
        // container status still says running — the sandbox must stop
        // reporting live so the watchdog can act (M7).
        let st = ContainerState {
            running: Some(ContainerStateRunning::default()),
            ..Default::default()
        };
        let mut pod = pod_with(Some(st), vec![]);
        pod.metadata.deletion_timestamp =
            Some(k8s_openapi::apimachinery::pkg::apis::meta::v1::Time(
                k8s_openapi::jiff::Timestamp::now(),
            ));
        let status = runner_status(&pod);
        assert!(
            matches!(status, SandboxStatus::Unknown { .. }),
            "deleting pod must be Unknown, got {status:?}"
        );
        assert!(!status.is_live());
    }

    #[test]
    fn phase_unknown_maps_to_unknown_not_pending() {
        // Kubelet unreachable: phase Unknown with no container detail used to
        // fall through to Pending — a live status — forever (M7).
        let mut pod = pod_with(None, vec![]);
        pod.status.as_mut().unwrap().phase = Some("Unknown".into());
        let status = runner_status(&pod);
        assert!(
            matches!(status, SandboxStatus::Unknown { .. }),
            "phase Unknown must map to Unknown, got {status:?}"
        );
    }

    #[test]
    fn phase_unknown_wins_over_a_stale_running_container_status() {
        // Node loss without a deletion timestamp: the apiserver keeps the
        // LAST-REPORTED container statuses (running) while phase flips to
        // Unknown — the stale snapshot must not keep the sandbox "live"
        // forever (M7, Codex round 2).
        let st = ContainerState {
            running: Some(ContainerStateRunning::default()),
            ..Default::default()
        };
        let mut pod = pod_with(Some(st), vec![]);
        pod.status.as_mut().unwrap().phase = Some("Unknown".into());
        let status = runner_status(&pod);
        assert!(
            matches!(status, SandboxStatus::Unknown { .. }),
            "phase Unknown must override stale container statuses, got {status:?}"
        );
        assert!(!status.is_live());
    }

    #[test]
    fn config_error_is_graced_while_fresh_fatal_once_persistent() {
        // Pod-first/Secret-second guarantees a CreateContainerConfigError
        // window before the Secret lands — transient by design (M6). Fresh
        // pod → Pending; persisting past the grace → fatal.
        let waiting = ContainerState {
            waiting: Some(ContainerStateWaiting {
                reason: Some("CreateContainerConfigError".into()),
                ..Default::default()
            }),
            ..Default::default()
        };
        let now = k8s_openapi::jiff::Timestamp::now();
        let mut pod = pod_with(Some(waiting.clone()), vec![]);
        pod.metadata.creation_timestamp =
            Some(k8s_openapi::apimachinery::pkg::apis::meta::v1::Time(now));
        assert!(
            matches!(runner_status(&pod), SandboxStatus::Pending { .. }),
            "config error inside the Secret window must be Pending"
        );

        pod.metadata.creation_timestamp =
            Some(k8s_openapi::apimachinery::pkg::apis::meta::v1::Time(
                k8s_openapi::jiff::Timestamp::from_second(
                    now.as_second() - (CONFIG_ERROR_GRACE_SECS + 60),
                )
                .unwrap(),
            ));
        assert!(
            matches!(runner_status(&pod), SandboxStatus::Terminated { .. }),
            "config error persisting past the grace must be fatal"
        );

        // The same grace applies on the init-container path.
        let init = ContainerStatus {
            name: INIT_CONTAINER.into(),
            state: Some(waiting),
            ..Default::default()
        };
        let mut pod = pod_with(None, vec![init]);
        pod.metadata.creation_timestamp =
            Some(k8s_openapi::apimachinery::pkg::apis::meta::v1::Time(now));
        assert!(matches!(runner_status(&pod), SandboxStatus::Pending { .. }));
    }

    #[test]
    fn no_handle_collects_the_local_workspace_like_docker() {
        // L9: a pre-launch failure with a materialized workspace must yield
        // the same "(no changes)" a Docker run records — the control-plane
        // copy is authoritative (no pod ever existed), not artifact noise.
        let tmp = std::env::temp_dir().join(format!("fbx-k8s-l9-{}", Uuid::now_v7()));
        let src = tmp.join("src");
        std::fs::create_dir_all(&src).unwrap();
        std::fs::write(src.join("a.txt"), "hello\n").unwrap();
        let data_dir = tmp.join("data");
        let session_id = Uuid::now_v7();
        let ws = fluidbox_workspace::materialize_local(&data_dir, session_id, &src).unwrap();

        let ctx = CollectContext {
            session_id,
            base_commit: ws.base_commit.clone(),
        };
        match collect_from_workspace(&data_dir, &ctx) {
            CollectedArtifacts::Collected(arts) => {
                assert_eq!(arts.len(), 1);
                assert_eq!(arts[0].kind, "diff");
                assert!(
                    arts[0].content.is_empty(),
                    "untouched workspace must diff empty, got: {}",
                    arts[0].content
                );
            }
            CollectedArtifacts::Missing { reason } => panic!("unexpected missing: {reason}"),
        }

        // Never-materialized workspace stays Missing (suppressed upstream by
        // expected_diff=false).
        let ctx2 = CollectContext {
            session_id: Uuid::now_v7(),
            base_commit: None,
        };
        assert!(matches!(
            collect_from_workspace(&data_dir, &ctx2),
            CollectedArtifacts::Missing { .. }
        ));
        std::fs::remove_dir_all(&tmp).ok();
    }

    fn diff_sha(body: &[u8]) -> String {
        use sha2::{Digest, Sha256};
        format!("sha256:{}", hex::encode(Sha256::digest(body)))
    }

    fn framed(body: &[u8], truncated: bool) -> Vec<u8> {
        let header = format!(
            "fluidbox-diff v1 status=ok bytes={} sha256={} truncated={}\n",
            body.len(),
            diff_sha(body),
            truncated
        );
        [header.into_bytes(), body.to_vec()].concat()
    }

    #[test]
    fn parse_ok_diff() {
        let body = b"diff --git a/x b/x\n+hi\n";
        match parse_collected(&framed(body, false)) {
            CollectedArtifacts::Collected(a) => {
                assert_eq!(a[0].kind, "diff");
                assert!(a[0].content.contains("diff --git"));
                assert_eq!(a[0].sha256, diff_sha(body));
                assert_eq!(a[0].bytes, body.len() as u64);
                assert!(!a[0].truncated);
            }
            _ => panic!("expected collected"),
        }
    }

    /// M2: a stream that closed early (exec channel dropped) delivers a body
    /// SHORTER than the header advertises. It must surface as Missing, never
    /// be stored as a complete diff.
    #[test]
    fn parse_short_body_is_missing_not_silent() {
        let body = b"diff --git a/x b/x\n+a full line of content\n";
        let header = format!(
            "fluidbox-diff v1 status=ok bytes={} sha256={} truncated=false\n",
            body.len(),
            diff_sha(body)
        );
        // only half the body arrives
        let raw = [header.into_bytes(), body[..body.len() / 2].to_vec()].concat();
        match parse_collected(&raw) {
            CollectedArtifacts::Missing { reason } => {
                assert!(reason.contains("truncated"), "reason: {reason}");
            }
            _ => panic!("a short stream must not parse as a complete diff"),
        }
    }

    /// M2: right length, wrong bytes (corruption in transit) → Missing.
    #[test]
    fn parse_corrupted_body_is_missing() {
        let header = format!(
            "fluidbox-diff v1 status=ok bytes=10 sha256={} truncated=false\n",
            diff_sha(b"BBBBBBBBBB")
        );
        let raw = [header.into_bytes(), b"AAAAAAAAAA".to_vec()].concat();
        match parse_collected(&raw) {
            CollectedArtifacts::Missing { reason } => {
                assert!(reason.contains("digest"), "reason: {reason}");
            }
            _ => panic!("a corrupted body must not parse as a valid diff"),
        }
    }

    /// A body carrying invalid UTF-8 must still verify byte-exactly (the
    /// digest is over raw bytes, not a lossy string).
    #[test]
    fn parse_verifies_non_utf8_body_byte_exactly() {
        let body: &[u8] = &[b'+', 0xff, 0xfe, b'\n'];
        match parse_collected(&framed(body, false)) {
            CollectedArtifacts::Collected(a) => {
                assert_eq!(a[0].bytes, body.len() as u64);
                assert_eq!(a[0].sha256, diff_sha(body));
            }
            _ => panic!("expected collected"),
        }
    }

    /// The resume loop keys off `stream_target`: an `ok` header yields the
    /// byte offset past its newline and the declared body length; a missing
    /// marker, a garbled header, or an `ok` header without a byte count all
    /// yield None (nothing to resume — the byte assembly stops).
    #[test]
    fn stream_target_reads_ok_header_only() {
        let body = b"diff --git a/x b/x\n+hi\n";
        let raw = framed(body, false);
        let nl = raw.iter().position(|&b| b == b'\n').unwrap();
        assert_eq!(stream_target(&raw), Some((nl + 1, body.len() as u64)));
        assert_eq!(
            stream_target(b"fluidbox-diff v1 status=missing reason=x\n"),
            None
        );
        assert_eq!(stream_target(b"garbage with no newline"), None);
        assert_eq!(
            stream_target(b"fluidbox-diff v1 status=ok sha256=x\nbody"),
            None
        );
    }

    #[test]
    fn parse_missing_diff() {
        let raw = b"fluidbox-diff v1 status=missing reason=quiesce_timeout\n";
        match parse_collected(raw) {
            CollectedArtifacts::Missing { reason } => assert_eq!(reason, "quiesce timeout"),
            _ => panic!("expected missing"),
        }
    }

    #[test]
    fn parse_garbled_is_missing() {
        assert!(matches!(
            parse_collected(b"garbage"),
            CollectedArtifacts::Missing { .. }
        ));
    }
}
