//! The server-side harness registry.
//!
//! A harness IS a runner image implementing the HTTP runner contract
//! (`/permission`, `/events`, `/heartbeat`, `/result` + the broker shim's
//! `/tools/call`), the `FLUIDBOX_*` env contract, the canonical tool
//! vocabulary, and the canonical event dot-names. Server-side harness
//! knowledge is EXACTLY what lives here: validate an id, pick the default
//! runner image and model, and add per-harness env extras. Deliberately a
//! plain match, not a trait registry — the §17 #8 n<3 discipline; a third
//! harness is one more arm in each function.

use crate::config::Config;

pub const CLAUDE_AGENT_SDK: &str = "claude-agent-sdk";
pub const CODEX: &str = "codex";

/// Every harness id the control plane accepts. Order is display order.
pub const KNOWN: &[&str] = &[CLAUDE_AGENT_SDK, CODEX];

pub fn is_known(harness: &str) -> bool {
    KNOWN.contains(&harness)
}

/// The runner image used when a revision doesn't pin one explicitly.
pub fn default_runner_image<'a>(harness: &str, cfg: &'a Config) -> Option<&'a str> {
    match harness {
        CLAUDE_AGENT_SDK => Some(&cfg.sandbox_image),
        CODEX => Some(&cfg.codex_sandbox_image),
        _ => None,
    }
}

/// The model used when a revision doesn't pin one explicitly.
pub fn default_model<'a>(harness: &str, cfg: &'a Config) -> Option<&'a str> {
    match harness {
        CLAUDE_AGENT_SDK => Some(&cfg.default_model),
        CODEX => Some(&cfg.default_codex_model),
        _ => None,
    }
}

/// Per-harness env extras beyond the generic `FLUIDBOX_*` block.
///
/// claude-agent-sdk: the Anthropic trio — base URL pointed at the LLM facade,
/// the fake API key that IS the session token (the facade swaps identity),
/// and the model. codex: nothing — the codex supervisor materializes its
/// model-provider wiring from the generic block inside the runner image.
/// Unknown harnesses get nothing: no identity material for an id the
/// registry doesn't know (create_run refuses those before launch anyway).
pub fn runner_env(
    harness: &str,
    control_url: &str,
    session_token: &str,
    model: &str,
) -> Vec<(String, String)> {
    match harness {
        CLAUDE_AGENT_SDK => vec![
            (
                "ANTHROPIC_BASE_URL".into(),
                format!("{}/internal/llm", control_url.trim_end_matches('/')),
            ),
            // The fake key IS the session token; the facade swaps in the
            // real one upstream.
            ("ANTHROPIC_API_KEY".into(), session_token.to_string()),
            ("ANTHROPIC_MODEL".into(), model.to_string()),
        ],
        _ => Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_cfg() -> Config {
        Config {
            bind: String::new(),
            database_url: String::new(),
            admin_token: String::new(),
            public_control_url: String::new(),
            data_dir: std::path::PathBuf::new(),
            sandbox_image: "fluidbox-sandbox-runner:dev".into(),
            default_model: "claude-haiku-4-5".into(),
            codex_sandbox_image: "fluidbox-codex-runner:dev".into(),
            default_codex_model: "gpt-5.4-mini".into(),
            llm_upstream_url: String::new(),
            llm_upstream_key: String::new(),
            llm_upstream_is_anthropic: false,
            credential_key: None,
            github_api_url: String::new(),
            github_web_url: String::new(),
            github_clone_base: String::new(),
            keep_workspaces: false,
            public_url: String::new(),
        }
    }

    #[test]
    fn known_ids() {
        assert!(is_known("claude-agent-sdk"));
        assert!(is_known("codex"));
        assert!(!is_known("codex-cli"));
        assert!(!is_known("Claude-Agent-SDK")); // ids are exact, no case folding
        assert!(!is_known(""));
    }

    #[test]
    fn per_harness_defaults() {
        let cfg = test_cfg();
        assert_eq!(
            default_runner_image("claude-agent-sdk", &cfg),
            Some("fluidbox-sandbox-runner:dev")
        );
        assert_eq!(
            default_runner_image("codex", &cfg),
            Some("fluidbox-codex-runner:dev")
        );
        assert_eq!(default_runner_image("nope", &cfg), None);
        assert_eq!(
            default_model("claude-agent-sdk", &cfg),
            Some("claude-haiku-4-5")
        );
        assert_eq!(default_model("codex", &cfg), Some("gpt-5.4-mini"));
        assert_eq!(default_model("nope", &cfg), None);
    }

    #[test]
    fn claude_env_is_the_anthropic_trio() {
        let env = runner_env(
            "claude-agent-sdk",
            "http://host.docker.internal:8787/",
            "fbx_sess_abc",
            "claude-haiku-4-5",
        );
        assert_eq!(
            env,
            vec![
                (
                    "ANTHROPIC_BASE_URL".to_string(),
                    "http://host.docker.internal:8787/internal/llm".to_string()
                ),
                ("ANTHROPIC_API_KEY".to_string(), "fbx_sess_abc".to_string()),
                (
                    "ANTHROPIC_MODEL".to_string(),
                    "claude-haiku-4-5".to_string()
                ),
            ]
        );
    }

    #[test]
    fn codex_and_unknown_get_no_extras() {
        assert!(runner_env("codex", "http://c", "t", "m").is_empty());
        assert!(runner_env("mystery", "http://c", "t", "m").is_empty());
    }
}
