//! Extension seams. Everything replaceable in fluidbox plugs into one of
//! these; the governance plane (policy, approvals, ledger, budgets) does not.

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

/// Serializable descriptor of a live sandbox. Persisted as jsonb — never a
/// live client — so the control plane can reattach after a restart, and so
/// the same shape fits Docker (`container_id`) and Lambda MicroVMs
/// (`microvm_id` + endpoint + lease).
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
    /// optimization; MicroVM providers push an archive instead).
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SandboxState {
    Running,
    Exited(i64),
    Gone,
}

/// Where sandboxes physically run. Docker in M1; Lambda MicroVMs in M2.
#[async_trait]
pub trait ExecutionProvider: Send + Sync {
    async fn provision(&self, spec: &SandboxSpec) -> Result<SandboxHandle, ProviderError>;
    async fn state(&self, handle: &SandboxHandle) -> Result<SandboxState, ProviderError>;
    async fn terminate(&self, handle: &SandboxHandle) -> Result<(), ProviderError>;
    /// Reap every sandbox this provider ever made for fluidbox (boot-time
    /// orphan sweep); returns the session ids found.
    async fn list_orphans(&self) -> Result<Vec<(Uuid, SandboxHandle)>, ProviderError>;
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
