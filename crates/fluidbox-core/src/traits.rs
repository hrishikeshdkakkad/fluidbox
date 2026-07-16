//! Extension seams. Everything replaceable in fluidbox plugs into one of
//! these; the governance plane (policy, approvals, ledger, budgets) does not.

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

/// Serializable descriptor of a live sandbox. Persisted as jsonb — never a
/// live client — so the control plane can reattach after a restart, and so
/// the same shape fits Docker (`container_id`) and Kubernetes
/// (`pod name` + namespace + uid).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxHandle {
    pub runtime: String,
    pub external_id: String,
    #[serde(default)]
    pub attrs: Value,
}

#[derive(Debug, Clone)]
pub struct SandboxSpec {
    pub session_id: Uuid,
    pub image: String,
    pub env: Vec<(String, String)>,
    /// Host workspace directory to mount at /workspace (provider-internal
    /// optimization; archive-based providers pull an immutable archive
    /// instead).
    pub workspace_host_dir: Option<String>,
    pub network: NetworkMode,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum NetworkMode {
    /// Sandbox reaches the control plane via the host gateway; general
    /// egress is constrained by policy, not structure. Local-dev mode.
    #[default]
    HostDev,
    /// Per-session internal bridge; zero external egress. Requires the
    /// control plane to be reachable on that bridge.
    Hardened,
}

impl NetworkMode {
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "host-dev" => Some(Self::HostDev),
            "hardened" => Some(Self::Hardened),
            _ => None,
        }
    }
}

/// Structured sandbox state (trait v2). The `reason` strings are provider
/// vocabulary (ImagePullBackOff, OOMKilled, "no such container"…) — they let
/// the orchestrator ledger a *specific* death instead of a generic one, and
/// are informational, never parsed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SandboxStatus {
    /// Created but not yet running (scheduling, image pull, secret wait…).
    Pending {
        reason: Option<String>,
    },
    Running,
    /// Ran and exited; exit code when the runtime still knows it.
    Terminated {
        exit_code: Option<i64>,
        reason: Option<String>,
    },
    /// The sandbox object no longer exists or its state cannot be
    /// determined (removed container, deleted pod, lost node).
    Unknown {
        reason: Option<String>,
    },
}

impl SandboxStatus {
    /// Still occupying (or about to occupy) compute. A live sandbox's
    /// worktree may be racing — collection must wait for !is_live().
    pub fn is_live(&self) -> bool {
        matches!(self, Self::Pending { .. } | Self::Running)
    }

    pub fn reason(&self) -> Option<&str> {
        match self {
            Self::Pending { reason } | Self::Unknown { reason } => reason.as_deref(),
            Self::Terminated { reason, .. } => reason.as_deref(),
            Self::Running => None,
        }
    }
}

/// What a provider needs, beyond the handle, to collect a session's
/// terminal artifacts.
#[derive(Debug, Clone)]
pub struct CollectContext {
    pub session_id: Uuid,
    pub base_commit: Option<String>,
}

/// One bounded, collected artifact payload. `sha256`/`bytes` describe the
/// stored content (post-truncation when `truncated`).
#[derive(Debug, Clone)]
pub struct CollectedArtifact {
    pub kind: String,
    pub name: String,
    pub content: String,
    pub content_type: String,
    pub truncated: bool,
    pub sha256: String,
    pub bytes: u64,
}

/// Outcome of `collect_artifacts`. `Missing` is EXPLICIT by design: a diff
/// that could not be collected is never silently reported as "(no changes)".
/// `Collected(vec![])` means collection ran and the worktree was clean.
#[derive(Debug)]
pub enum CollectedArtifacts {
    Collected(Vec<CollectedArtifact>),
    Missing { reason: String },
}

/// Where sandboxes physically run. Docker today; Kubernetes lands beside it
/// (dual-provider permanence — Docker is never replaced).
#[async_trait]
pub trait ExecutionProvider: Send + Sync {
    async fn provision(&self, spec: &SandboxSpec) -> Result<SandboxHandle, ProviderError>;
    async fn state(&self, handle: &SandboxHandle) -> Result<SandboxStatus, ProviderError>;
    /// Collect terminal artifacts (the diff) for a session — bounded in time
    /// and size, NEVER executing git against agent-controlled `.git` state.
    /// `handle` is None when the session never got a sandbox; providers with
    /// control-plane-side transports (Docker's host dir) may still collect.
    async fn collect_artifacts(
        &self,
        handle: Option<&SandboxHandle>,
        ctx: &CollectContext,
    ) -> Result<CollectedArtifacts, ProviderError>;
    /// Idempotent, precondition-guarded teardown.
    async fn terminate(&self, handle: &SandboxHandle) -> Result<(), ProviderError>;
    /// Every sandbox this provider manages for fluidbox (boot-time sweep +
    /// reconciliation); returns the session ids found.
    async fn list_managed(&self) -> Result<Vec<(Uuid, SandboxHandle)>, ProviderError>;
    /// Non-fatal readiness probe: is the runtime reachable? Feeds boot
    /// logging and /health/ready — never gates startup.
    async fn healthcheck(&self) -> Result<(), ProviderError>;
    fn runtime_name(&self) -> &'static str;
}

#[derive(Debug, thiserror::Error)]
pub enum ProviderError {
    #[error("provider error: {0}")]
    Other(String),
}

// NOTE: there is deliberately no `Harness` trait. A harness is a runner
// image implementing the HTTP runner contract (permission/events/heartbeat/
// result + env contract + canonical tool vocabulary); the server-side
// remainder (id validation, image/model defaults, env extras) is a plain
// match in `fluidbox-server/src/harness.rs`.
