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

/// A model offered for a harness, for the dashboard picker. `id` is what
/// freezes into the RunSpec and what the facade pins at call time.
pub struct HarnessModel {
    pub id: &'static str,
    pub display_name: &'static str,
    pub hint: &'static str,
}

/// Human label for a harness id (KNOWN order = display order).
pub fn display_name(harness: &str) -> &'static str {
    match harness {
        CLAUDE_AGENT_SDK => "Claude Agent SDK",
        CODEX => "Codex",
        _ => "",
    }
}

/// One-line description of a harness for the dashboard picker.
pub fn hint(harness: &str) -> &'static str {
    match harness {
        CLAUDE_AGENT_SDK => "Claude Code in the sandbox — live timeline, gated tools, approvals.",
        CODEX => "OpenAI Codex on the same governed runner contract.",
        _ => "",
    }
}

/// The models fluidbox supports for a harness — the SINGLE server-side source
/// of truth the dashboard reads via `GET /v1/harnesses`, replacing the
/// hardcoded, drift-prone frontend lists. Plain match, like the rest of the
/// registry (a third harness is one more arm).
pub fn models(harness: &str) -> &'static [HarnessModel] {
    match harness {
        CLAUDE_AGENT_SDK => &[
            HarnessModel {
                id: "claude-haiku-4-5",
                display_name: "Claude Haiku 4.5",
                hint: "Fastest and cheapest — the default.",
            },
            HarnessModel {
                id: "claude-sonnet-5",
                display_name: "Claude Sonnet 5",
                hint: "Balanced speed and capability.",
            },
            HarnessModel {
                id: "claude-opus-4-8",
                display_name: "Claude Opus 4.8",
                hint: "Most capable for hard agentic coding.",
            },
        ],
        CODEX => &[
            HarnessModel {
                id: "gpt-5.4-mini",
                display_name: "GPT-5.4 mini",
                hint: "Fastest and cheapest — the default.",
            },
            HarnessModel {
                id: "gpt-5.4",
                display_name: "GPT-5.4",
                hint: "Balanced speed and capability.",
            },
            HarnessModel {
                id: "gpt-5.6-sol",
                display_name: "GPT-5.6 Sol",
                hint: "Most capable.",
            },
        ],
        _ => &[],
    }
}

/// Whether a model id is offered for a harness. The gate that turns a
/// harness/model mismatch into a clean 422 at agent-write time instead of a
/// murky failure at the first model call.
pub fn model_belongs(harness: &str, model: &str) -> bool {
    models(harness).iter().any(|m| m.id == model)
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
            internal_bind: String::new(),
            database_url: String::new(),
            runtime_role: None,
            allow_rls_bypass: false,
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
            llm_key_mode: crate::config::LlmKeyMode::Shared,
            llm_admin_url: String::new(),
            llm_tenant_models: Vec::new(),
            llm_tenant_max_budget: None,
            llm_tenant_budget_duration: None,
            llm_tenant_tpm: None,
            llm_tenant_rpm: None,
            credential_key: None,
            kms_mode: crate::config::KmsMode::Off,
            kms_static_kek: None,
            kms_aws_key_id: None,
            kms_aws_endpoint: None,
            github_api_url: String::new(),
            github_web_url: String::new(),
            github_clone_base: String::new(),
            keep_workspaces: false,
            public_url: String::new(),
            egress_allow_cidrs: Vec::new(),
            egress_proxy: None,
            provider: "docker".into(),
            network_mode: fluidbox_core::traits::NetworkMode::HostDev,
            require_enforced_netpol: false,
            netpol_probe_image: "busybox:1.36".into(),
            internal_service: None,
            internal_service_namespace: None,
            max_archive_bytes: 2 * 1024 * 1024 * 1024,
            archive_ttl_secs: 24 * 3600,
            require_sso: false,
            trust_forwarded_for: false,
            session_idle_secs: 8 * 3600,
            session_absolute_secs: 7 * 24 * 3600,
            oidc_discovery_max_age_secs: 3600,
            oidc_clock_skew_secs: 60,
            session_reauth_secs: 60,
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

    #[test]
    fn config_default_models_belong_to_their_harness() {
        let cfg = test_cfg();
        // The shipped defaults MUST be members of their model list — the
        // /harnesses endpoint reports them as `default_model` and inherited
        // models skip the belongs check on that assumption.
        assert!(model_belongs(CLAUDE_AGENT_SDK, &cfg.default_model));
        assert!(model_belongs(CODEX, &cfg.default_codex_model));
    }

    #[test]
    fn model_belongs_is_per_harness() {
        assert!(model_belongs(CLAUDE_AGENT_SDK, "claude-opus-4-8"));
        assert!(model_belongs(CODEX, "gpt-5.6-sol"));
        // Cross-harness models are rejected — the murky-failure gap.
        assert!(!model_belongs(CLAUDE_AGENT_SDK, "gpt-5.4"));
        assert!(!model_belongs(CODEX, "claude-opus-4-8"));
        assert!(!model_belongs(CLAUDE_AGENT_SDK, "made-up-model"));
        assert!(models("nope").is_empty());
    }
}
