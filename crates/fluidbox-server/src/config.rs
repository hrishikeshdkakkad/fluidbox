use std::path::PathBuf;

/// Docker bind mounts require absolute host paths. Resolve the data dir to an
/// absolute path at startup (creating it first so canonicalize succeeds).
fn absolute(p: &str) -> PathBuf {
    let path = PathBuf::from(p);
    std::fs::create_dir_all(&path).ok();
    std::fs::canonicalize(&path).unwrap_or_else(|_| {
        std::env::current_dir().map(|d| d.join(&path)).unwrap_or(path)
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
    /// Facade upstream: LiteLLM (default) or api.anthropic.com (fallback).
    pub llm_upstream_url: String,
    /// Key the facade presents to LiteLLM. For the direct-Anthropic fallback
    /// this is the real Anthropic key.
    pub llm_upstream_key: String,
    /// Whether the upstream speaks native Anthropic (fallback) — governs how
    /// the facade authenticates upstream.
    pub llm_upstream_is_anthropic: bool,
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
            llm_upstream_url: upstream,
            llm_upstream_key: upstream_key,
            llm_upstream_is_anthropic: is_anthropic,
        })
    }
}
