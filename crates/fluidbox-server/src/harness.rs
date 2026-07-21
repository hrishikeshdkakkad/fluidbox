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
/// `llm_token` is the LLM-AUDIENCE credential (Gap 10): it authenticates model
/// egress at the facade and NOTHING else — it cannot post /result, forge
/// /events, or ask the tool gate for a decision. Each harness receives it under
/// the var its agent binary actually reads:
/// - claude-agent-sdk: the Anthropic trio — base URL pointed at the LLM facade,
///   the fake API key (= the llm token; the facade swaps in the real upstream
///   identity), and the model.
/// - codex: `FLUIDBOX_LLM_TOKEN`, which the supervisor wires as the codex
///   model-provider `env_key`. (It used to read `FLUIDBOX_SESSION_TOKEN`; that
///   var is now runner-control ONLY and is deleted from the env before codex
///   spawns.)
///
/// Unknown harnesses get nothing: no identity material for an id the registry
/// doesn't know (create_run refuses those before launch anyway).
///
/// **Runner-image compatibility (Gap 10 decision, plan E11).** The audience
/// split is a COUPLED server+image change: a NEW server pairs new sessions with
/// the CURRENT in-repo runner image (`default_runner_image` resolves from this
/// deployment's config), and an in-flight session that predates the deploy holds
/// a legacy `'all'` token that every route still accepts. The unsupported cell is
/// an OLD image PINNED onto a NEW server — reachable without a bad deploy, since
/// `runner_image` is a per-revision API field that `inherit_unless_switched`
/// carries forward: that image's runner-lib reads only `FLUIDBOX_SESSION_TOKEN`
/// and presents the runner-CONTROL token at the tool gate, earning a 403
/// `wrong_audience`. We deliberately do NOT widen the guards to accept it — that
/// would gut the split and the invariant-19 acceptance bullet.
///
/// What that cell does, precisely: the runner-lib treats a `wrong_audience` body
/// code as a FATAL misconfiguration — it logs a named diagnostic, records it on
/// the run's timeline, and exits non-zero (`EXIT_AUDIENCE_MISMATCH`), so the run
/// aborts at the first tool call and the heartbeat watchdog terminalizes it. The
/// broker and sandbox-gate shims exit the same way. **Honest residual:** that
/// behavior lives in the IMAGE, so it protects images built at or after it. An
/// image built BEFORE it maps any 401/403 to `{decision:"deny"}` and would run
/// to completion with every tool denied while model spend proceeded — the exact
/// wrong-result-that-looks-right this closes going forward, and the reason the
/// runner-lib change and this note ship together.
pub fn runner_env(
    harness: &str,
    control_url: &str,
    llm_token: &str,
    model: &str,
) -> Vec<(String, String)> {
    match harness {
        CLAUDE_AGENT_SDK => vec![
            (
                "ANTHROPIC_BASE_URL".into(),
                format!("{}/internal/llm", control_url.trim_end_matches('/')),
            ),
            // The fake key IS the llm-audience token; the facade swaps in the
            // real one upstream.
            ("ANTHROPIC_API_KEY".into(), llm_token.to_string()),
            ("ANTHROPIC_MODEL".into(), model.to_string()),
        ],
        CODEX => vec![("FLUIDBOX_LLM_TOKEN".into(), llm_token.to_string())],
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
            llm_max_concurrent_reservations: crate::facade::DEFAULT_MAX_CONCURRENT_RESERVATIONS,
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
            egress_rate_tenant_per_min: crate::governor::DEFAULT_TENANT_PER_MIN,
            egress_rate_connection_per_min: crate::governor::DEFAULT_CONNECTION_PER_MIN,
            egress_rate_host_per_min: crate::governor::DEFAULT_HOST_PER_MIN,
            egress_rate_user_per_min: crate::governor::DEFAULT_USER_PER_MIN,
            egress_breaker_threshold: crate::governor::DEFAULT_BREAKER_THRESHOLD,
            egress_breaker_open_secs: crate::governor::DEFAULT_BREAKER_OPEN_SECS,
            // This fixture builds a Config for harness-registry assertions only —
            // no pool, no dials — so the durable tier is off rather than defaulted.
            egress_durable: false,
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
            // Phase F capacity knobs — this fixture never opens a pool or serves a
            // request, so the shipped defaults are simply carried.
            db_pool: fluidbox_db::PoolSettings::default(),
            max_request_body_bytes: crate::config::DEFAULT_MAX_REQUEST_BODY_BYTES,
            // Gap 6: this fixture serves no requests, so the shipped default (off)
            // is carried. NOTE for anyone adding a workload-identity assertion —
            // asserting on THIS value proves nothing about production, which builds
            // its Config in `config.rs::from_env`; test that path instead.
            workload_identity: crate::config::WorkloadIdentityMode::default(),
            // Task 4: this fixture packs no archive, so the shipped default
            // (node-local `fs`, one replica) is carried. Same NOTE as above —
            // asserting on THESE values proves nothing about production, which
            // parses them in `config.rs::parse_archive_store`; test that path.
            archive_store: fluidbox_workspace::ArchiveStoreConfig::Fs,
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
            "fbx_sess_llm",
            "claude-haiku-4-5",
        );
        assert_eq!(
            env,
            vec![
                (
                    "ANTHROPIC_BASE_URL".to_string(),
                    "http://host.docker.internal:8787/internal/llm".to_string()
                ),
                // The fake provider key is the LLM-audience token (Gap 10).
                ("ANTHROPIC_API_KEY".to_string(), "fbx_sess_llm".to_string()),
                (
                    "ANTHROPIC_MODEL".to_string(),
                    "claude-haiku-4-5".to_string()
                ),
            ]
        );
    }

    #[test]
    fn codex_gets_the_llm_token_and_unknown_gets_nothing() {
        // Gap 10: codex's model-provider env_key moved OFF FLUIDBOX_SESSION_TOKEN
        // (now runner-control only) onto its own LLM-audience var.
        assert_eq!(
            runner_env("codex", "http://c", "fbx_sess_llm", "m"),
            vec![("FLUIDBOX_LLM_TOKEN".to_string(), "fbx_sess_llm".to_string())]
        );
        // Neither harness may leak the control token into the agent's env: the
        // only credential either arm emits is the one it was handed.
        assert!(runner_env("mystery", "http://c", "fbx_sess_llm", "m").is_empty());
    }

    #[test]
    fn default_runner_images_are_this_deployment_s_configured_images() {
        // What this pins, exactly: the DEFAULT image for each harness resolves
        // from THIS deployment's config — nothing more. That is the half of the
        // Gap 10 compat story this file owns (an unpinned revision therefore
        // launches the runner image shipped with the running server). It says
        // NOTHING about a PINNED image, whose skew behavior lives in the runner
        // image and is asserted route-by-route by the CI `hardening` job; see
        // `runner_env`'s doc for that cell.
        let mut cfg = test_cfg();
        cfg.sandbox_image = "ghcr.io/fluidbox/sandbox-runner:v9".into();
        cfg.codex_sandbox_image = "ghcr.io/fluidbox/codex-runner:v9".into();
        assert_eq!(
            default_runner_image(CLAUDE_AGENT_SDK, &cfg),
            Some("ghcr.io/fluidbox/sandbox-runner:v9")
        );
        assert_eq!(
            default_runner_image(CODEX, &cfg),
            Some("ghcr.io/fluidbox/codex-runner:v9")
        );
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
