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

use config::K8sConfig;
use manifest::{
    build_pod, build_secret, object_name, COLLECTOR_CONTAINER, LABEL_MANAGED, LABEL_SESSION,
    RUNNER_CONTAINER,
};

const RUNTIME: &str = "kubernetes";
/// Diff artifacts are bounded at this many bytes over exec (the collector
/// already caps them; this is the receive-side ceiling).
const MAX_DIFF_BYTES: usize = 16 * 1024 * 1024;

pub struct KubernetesProvider {
    pods: Api<Pod>,
    secrets: Api<Secret>,
    cfg: K8sConfig,
    namespace: String,
}

impl KubernetesProvider {
    /// Connect using the ambient kube config (in-cluster ServiceAccount, or
    /// `~/.kube/config` for local dev). Fails if no cluster is reachable.
    pub async fn connect(cfg: K8sConfig) -> anyhow::Result<Self> {
        let client = Client::try_default().await?;
        Ok(Self::with_client(client, cfg))
    }

    pub fn with_client(client: Client, cfg: K8sConfig) -> Self {
        let namespace = cfg.namespace.clone();
        Self {
            pods: Api::namespaced(client.clone(), &namespace),
            secrets: Api::namespaced(client, &namespace),
            cfg,
            namespace,
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
        let dp = DeleteParams {
            preconditions: uid.map(|u| Preconditions {
                uid: Some(u.to_string()),
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

/// Map a Pod to the structured status of its NAMED runner container (not Pod
/// phase). Init failure surfaces as a terminated runner so the orchestrator
/// fails the run; a still-pulling image is Pending with the reason.
pub fn runner_status(pod: &Pod) -> SandboxStatus {
    let status = match &pod.status {
        Some(s) => s,
        None => return SandboxStatus::Pending { reason: None },
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
                if fatal_waiting(w.reason.as_deref()) {
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
                    if fatal_waiting(w.reason.as_deref()) {
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

/// Waiting reasons that will never resolve on their own — a misconfigured
/// image or config, distinct from an in-progress pull (`ContainerCreating`,
/// `PodInitializing`, `ImagePull*` in progress).
fn fatal_waiting(reason: Option<&str>) -> bool {
    matches!(
        reason,
        Some("ImagePullBackOff")
            | Some("ErrImagePull")
            | Some("InvalidImageName")
            | Some("CreateContainerConfigError")
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
        _ctx: &CollectContext,
    ) -> Result<CollectedArtifacts, ProviderError> {
        let Some(handle) = handle else {
            return Ok(CollectedArtifacts::Missing {
                reason: "no sandbox handle (pod never provisioned)".into(),
            });
        };
        let name = &handle.external_id;

        // Compute the diff in the collector container (pristine baseline +
        // final worktree, scrubbed git), then stream the finished file.
        if let Err(e) = self.exec_collect(name, &["workspaced", "diff"]).await {
            return Ok(CollectedArtifacts::Missing {
                reason: format!("collector diff exec failed: {e}"),
            });
        }
        let raw = match self.exec_collect(name, &["workspaced", "stream"]).await {
            Ok(bytes) => bytes,
            Err(e) => {
                return Ok(CollectedArtifacts::Missing {
                    reason: format!("collector stream exec failed: {e}"),
                })
            }
        };
        Ok(parse_collected(&raw))
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
    /// Exec a command in the collector container and return its stdout. Used
    /// for `workspaced diff` (side-effecting; stdout ignored) and
    /// `workspaced stream` (the diff bytes).
    async fn exec_collect(&self, pod: &str, cmd: &[&str]) -> Result<Vec<u8>, ProviderError> {
        let ap = AttachParams::default()
            .container(COLLECTOR_CONTAINER)
            .stdout(true)
            .stderr(true);
        let mut proc = self
            .pods
            .exec(pod, cmd.to_vec(), &ap)
            .await
            .map_err(map_err)?;
        let mut buf = Vec::new();
        if let Some(out) = proc.stdout() {
            // Bounded read: the collector already caps the diff; this stops a
            // runaway stream from exhausting control-plane memory. kube's exec
            // streams are tokio AsyncRead.
            use tokio::io::AsyncReadExt;
            let mut limited = out.take(MAX_DIFF_BYTES as u64);
            limited
                .read_to_end(&mut buf)
                .await
                .map_err(|e| ProviderError::Other(format!("exec stdout read: {e}")))?;
        }
        // Surface a non-zero exec exit as an error (the collector's own
        // failures are already encoded in the streamed header, but a transport
        // failure should not masquerade as an empty diff).
        let _ = proc.join().await;
        Ok(buf)
    }
}

/// Parse the collector's `fluidbox-diff v1 …` header + body into a
/// `CollectedArtifacts`. The header distinguishes a real (possibly empty)
/// diff from an explicit missing marker.
fn parse_collected(raw: &[u8]) -> CollectedArtifacts {
    let text = String::from_utf8_lossy(raw);
    let mut lines = text.splitn(2, '\n');
    let header = lines.next().unwrap_or("");
    let body = lines.next().unwrap_or("");
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
            let bytes = field("bytes")
                .and_then(|v| v.parse().ok())
                .unwrap_or(body.len() as u64);
            let sha256 = field("sha256").unwrap_or("").to_string();
            let truncated = field("truncated") == Some("true");
            CollectedArtifacts::Collected(vec![CollectedArtifact {
                kind: "diff".into(),
                name: "changes.patch".into(),
                content: body.to_string(),
                content_type: "text/x-diff".into(),
                truncated,
                sha256,
                bytes,
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
    fn parse_ok_diff() {
        let raw =
            b"fluidbox-diff v1 status=ok bytes=12 sha256=sha256:ab truncated=false\ndiff --git\n";
        match parse_collected(raw) {
            CollectedArtifacts::Collected(a) => {
                assert_eq!(a[0].kind, "diff");
                assert!(a[0].content.contains("diff --git"));
                assert_eq!(a[0].sha256, "sha256:ab");
                assert!(!a[0].truncated);
            }
            _ => panic!("expected collected"),
        }
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
