use std::path::PathBuf;

/// Docker bind mounts require absolute host paths. Resolve the data dir to an
/// absolute path at startup (creating it first so canonicalize succeeds).
fn absolute(p: &str) -> PathBuf {
    let path = PathBuf::from(p);
    std::fs::create_dir_all(&path).ok();
    std::fs::canonicalize(&path).unwrap_or_else(|_| {
        std::env::current_dir()
            .map(|d| d.join(&path))
            .unwrap_or(path)
    })
}

#[derive(Debug, Clone)]
pub struct Config {
    pub bind: String,
    /// The sandbox-facing internal listener (:8788). Serves ONLY `/internal/*`
    /// (runner contract, workspace archive, LLM facade) — never `/v1`. Route
    /// absence is stronger than bearer auth alone: a sandbox that reaches this
    /// bind is immune to any future `/v1` auth regression (design 2026-07-15,
    /// §"Dual listener"). The public bind still serves both for Docker.
    pub internal_bind: String,
    pub database_url: String,
    pub admin_token: String,
    /// URL sandboxes use to reach this control plane (e.g. host.docker.internal).
    pub public_control_url: String,
    pub data_dir: PathBuf,
    pub sandbox_image: String,
    pub default_model: String,
    /// Runner image for `codex` agents (the second harness).
    pub codex_sandbox_image: String,
    /// Default model for `codex` agents (the haiku-analog cost directive).
    pub default_codex_model: String,
    /// Facade upstream: LiteLLM (default) or api.anthropic.com (fallback).
    pub llm_upstream_url: String,
    /// Key the facade presents to LiteLLM. For the direct-Anthropic fallback
    /// this is the real Anthropic key.
    pub llm_upstream_key: String,
    /// Whether the upstream speaks native Anthropic (fallback) — governs how
    /// the facade authenticates upstream.
    pub llm_upstream_is_anthropic: bool,
    /// 32-byte key (hex/base64) sealing connection credentials at rest.
    /// Optional: without it, integration connections are disabled.
    pub credential_key: Option<String>,
    /// GitHub REST base — overridable for tests/GHE.
    pub github_api_url: String,
    /// Browser-facing GitHub base (manifest form target, install URLs) —
    /// overridable for tests/GHE. Distinct from the API base: github.com
    /// vs api.github.com in production.
    pub github_web_url: String,
    /// Base for repository clone URLs derived from event payloads
    /// (https://github.com in production; a file:// fixture root in e2e).
    pub github_clone_base: String,
    /// Keep per-session workspace dirs after terminal diff capture (debug aid).
    pub keep_workspaces: bool,
    /// Browser/AS-facing base URL of this control plane (no trailing slash).
    /// Feeds the OAuth redirect_uri and the CIMD client_id document — both
    /// are fetched by parties that can't use host.docker.internal.
    pub public_url: String,
    /// Execution backend: `docker` (default) or `kubernetes`. Selects which
    /// `ExecutionProvider` `AppState.provider` holds. Dual-provider permanence
    /// (settled Q17): Docker is never replaced.
    pub provider: String,
    /// Sandbox network mode, config-derived instead of hardcoded
    /// (`host-dev` default; `hardened` = zero external egress). Was pinned to
    /// HostDev at `orchestrator.rs:150`.
    pub network_mode: fluidbox_core::traits::NetworkMode,
    /// Block runs until a probe proves the CNI enforces NetworkPolicy
    /// (Kubernetes only; fails closed). Default true; `false` is dev-only.
    pub require_enforced_netpol: bool,
    /// The probe image used by the boot-time netpol run-gate.
    pub netpol_probe_image: String,
    /// The server's own internal Service (name, namespace) — resolved to a
    /// ClusterIP at boot for the runner's no-DNS control URL under zeroEgress.
    pub internal_service: Option<String>,
    pub internal_service_namespace: Option<String>,
    /// Compressed workspace-archive ceiling: packing streams to disk and a
    /// run whose archive would exceed this fails cleanly at zero model spend.
    pub max_archive_bytes: u64,
    /// TTL for the stored-archive sweep (the leak backstop). The archive is
    /// single-use init transport — anything older than this is a leak.
    pub archive_ttl_secs: u64,
}

/// Serialized runner-env ceiling: env injection is the v1 config channel
/// (authenticated fetch is the designated v1.1 follow-up), and Kubernetes
/// caps a Secret/env at ~1 MiB. 512 KiB leaves headroom and fails a bloated
/// run closed at zero model spend rather than at an opaque kubelet error.
pub const MAX_RUNNER_ENV_BYTES: usize = 512 * 1024;

impl Config {
    pub fn from_env() -> anyhow::Result<Self> {
        let get = |k: &str| std::env::var(k);
        let upstream = get("LLM_UPSTREAM_URL").unwrap_or_else(|_| "http://127.0.0.1:4000".into());
        let is_anthropic = upstream.contains("api.anthropic.com");
        // In fallback mode the facade needs the real Anthropic key; otherwise
        // it authenticates to LiteLLM with the master key.
        let upstream_key = if is_anthropic {
            get("ANTHROPIC_API_KEY").unwrap_or_default()
        } else {
            get("LITELLM_MASTER_KEY").unwrap_or_default()
        };
        Ok(Config {
            bind: get("FLUIDBOX_BIND").unwrap_or_else(|_| "127.0.0.1:8787".into()),
            internal_bind: get("FLUIDBOX_INTERNAL_BIND").unwrap_or_else(|_| "0.0.0.0:8788".into()),
            database_url: get("DATABASE_URL")
                .map_err(|_| anyhow::anyhow!("DATABASE_URL is required"))?,
            admin_token: get("FLUIDBOX_ADMIN_TOKEN")
                .map_err(|_| anyhow::anyhow!("FLUIDBOX_ADMIN_TOKEN is required"))?,
            public_control_url: get("FLUIDBOX_PUBLIC_CONTROL_URL")
                .unwrap_or_else(|_| "http://host.docker.internal:8787".into()),
            data_dir: absolute(&get("FLUIDBOX_DATA_DIR").unwrap_or_else(|_| "./data".into())),
            sandbox_image: get("FLUIDBOX_SANDBOX_IMAGE")
                .unwrap_or_else(|_| "fluidbox-sandbox-runner:dev".into()),
            default_model: get("FLUIDBOX_DEFAULT_MODEL")
                .unwrap_or_else(|_| "claude-haiku-4-5".into()),
            codex_sandbox_image: get("FLUIDBOX_CODEX_SANDBOX_IMAGE")
                .unwrap_or_else(|_| "fluidbox-codex-runner:dev".into()),
            default_codex_model: get("FLUIDBOX_DEFAULT_CODEX_MODEL")
                .unwrap_or_else(|_| "gpt-5.4-mini".into()),
            llm_upstream_url: upstream,
            llm_upstream_key: upstream_key,
            llm_upstream_is_anthropic: is_anthropic,
            credential_key: get("FLUIDBOX_CREDENTIAL_KEY")
                .ok()
                .filter(|k| !k.is_empty()),
            github_api_url: get("FLUIDBOX_GITHUB_API_URL")
                .unwrap_or_else(|_| "https://api.github.com".into()),
            github_web_url: get("FLUIDBOX_GITHUB_WEB_URL")
                .unwrap_or_else(|_| "https://github.com".into())
                .trim_end_matches('/')
                .to_string(),
            github_clone_base: get("FLUIDBOX_GITHUB_CLONE_BASE")
                .unwrap_or_else(|_| "https://github.com".into()),
            keep_workspaces: get("FLUIDBOX_KEEP_WORKSPACES")
                .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
                .unwrap_or(false),
            public_url: get("FLUIDBOX_PUBLIC_URL")
                .unwrap_or_else(|_| "http://127.0.0.1:8787".into())
                .trim_end_matches('/')
                .to_string(),
            provider: get("FLUIDBOX_PROVIDER")
                .unwrap_or_else(|_| "docker".into())
                .to_lowercase(),
            network_mode: get("FLUIDBOX_NETWORK_MODE")
                .ok()
                .and_then(|s| fluidbox_core::traits::NetworkMode::parse(&s.to_lowercase()))
                .unwrap_or_default(),
            require_enforced_netpol: get("FLUIDBOX_REQUIRE_ENFORCED_NETPOL")
                .map(|v| v != "false" && v != "0")
                .unwrap_or(true),
            netpol_probe_image: get("FLUIDBOX_NETPOL_PROBE_IMAGE")
                .unwrap_or_else(|_| "busybox:1.36".into()),
            internal_service: get("FLUIDBOX_INTERNAL_SERVICE")
                .ok()
                .filter(|s| !s.is_empty()),
            internal_service_namespace: get("FLUIDBOX_INTERNAL_SERVICE_NAMESPACE")
                .ok()
                .filter(|s| !s.is_empty()),
            max_archive_bytes: get("FLUIDBOX_MAX_ARCHIVE_BYTES")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(2 * 1024 * 1024 * 1024), // 2 GiB
            archive_ttl_secs: get("FLUIDBOX_ARCHIVE_TTL_SECS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(24 * 3600),
        })
    }
}
