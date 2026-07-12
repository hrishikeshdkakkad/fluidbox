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
}

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
        })
    }
}
