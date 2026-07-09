//! Extension seams. Everything replaceable in fluidbox plugs into one of
//! these; the governance plane (policy, approvals, ledger, budgets) does not.

use crate::spec::RunSpec;
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

/// Which agent brain runs inside the sandbox. The harness adapter
/// orchestrates (spawns the payload / drives a vendor queue); tool intents
/// always flow back through the control plane's internal API, so this trait
/// stays thin by design.
#[async_trait]
pub trait Harness: Send + Sync {
    /// Environment the runner payload needs, derived from the RunSpec.
    fn runner_env(&self, spec: &RunSpec, session_env: &SessionEnv) -> Vec<(String, String)>;
    fn name(&self) -> &'static str;
}

/// Per-session wiring the control plane injects into any harness.
#[derive(Debug, Clone)]
pub struct SessionEnv {
    pub session_id: Uuid,
    pub session_token: String,
    pub control_url: String,
    pub workspace_dir: String,
}
