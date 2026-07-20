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

/// Key-wrapping backend for envelope sealing (Phase D, #32). `Off` keeps the
/// legacy single-key `FLUIDBOX_CREDENTIAL_KEY` behavior (seals stay v1,
/// byte-identical); `Static`/`Aws` turn on per-tenant DEKs wrapped by a KEK
/// (`FLUIDBOX_KMS_STATIC_KEK` / AWS KMS), so new seals are v2 envelopes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KmsMode {
    Off,
    Static,
    Aws,
}

impl KmsMode {
    fn parse(s: &str) -> Option<Self> {
        match s.trim().to_lowercase().as_str() {
            "off" | "" => Some(KmsMode::Off),
            "static" => Some(KmsMode::Static),
            "aws" => Some(KmsMode::Aws),
            _ => None,
        }
    }
}

/// How the facade authenticates each upstream model request (Phase D, #32; plan
/// D7). `Shared` presents ONE deployment key (`llm_upstream_key`) on every call —
/// today's behavior, now an explicit choice. `Tenant` selects a per-tenant LiteLLM
/// virtual key from the authenticated session's tenant (minted on demand,
/// `llm_keys.rs`), so the LiteLLM master key never rides a routine model request —
/// it only provisions virtual keys.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LlmKeyMode {
    Shared,
    Tenant,
}

impl LlmKeyMode {
    fn parse(s: &str) -> Option<Self> {
        match s.trim().to_lowercase().as_str() {
            "shared" | "" => Some(LlmKeyMode::Shared),
            "tenant" => Some(LlmKeyMode::Tenant),
            _ => None,
        }
    }
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
    /// Least-privilege Postgres role the app pool SET ROLEs to (Phase D, #32; plan
    /// D8). `None` (default, `FLUIDBOX_RUNTIME_ROLE` unset) = single-role mode: the
    /// owner runs everything, RLS still binds it via FORCE + the tenant GUC. `Some`
    /// opts into the role split — migration 0018 creates `fluidbox_runtime`, and boot
    /// verifies the role exists (and its posture) then `SET ROLE`s via `after_connect`.
    pub runtime_role: Option<String>,
    /// Escape hatch for the multi-user RLS boot gate (`FLUIDBOX_ALLOW_RLS_BYPASS`,
    /// review M2). With `FLUIDBOX_REQUIRE_SSO=1`, boot REFUSES a pool whose effective
    /// role is SUPERUSER/BYPASSRLS, because PostgreSQL then skips every migration-0018
    /// policy and tenant isolation is back to being a `where tenant_id = $n`
    /// convention. Set this to `1` only for local single-user operation on a
    /// superuser database; a hosted deployment must fix the role instead.
    pub allow_rls_bypass: bool,
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
    /// Per-request upstream-auth mode (Phase D, #32; plan D7). `Shared` (default)
    /// presents `llm_upstream_key` on every call; `Tenant` selects a per-tenant
    /// LiteLLM virtual key and confines the master key to provisioning.
    pub llm_key_mode: LlmKeyMode,
    /// LiteLLM ADMIN base URL for virtual-key provisioning (`/key/generate`,
    /// `/key/delete`). Defaults to `llm_upstream_url` — split it out only when the
    /// admin plane lives at a different address (test seam mirrors
    /// `FLUIDBOX_GITHUB_API_URL`). Only read by `llm_keys.rs`.
    pub llm_admin_url: String,
    /// Tenant-mode `/key/generate` knobs — serialized into the mint body ONLY when
    /// set. `models` = the virtual key's model allowlist (CSV → Vec; empty = no
    /// allowlist restriction). All optional; a `None`/empty knob is absent from the
    /// request (LiteLLM applies its own default).
    pub llm_tenant_models: Vec<String>,
    pub llm_tenant_max_budget: Option<f64>,
    pub llm_tenant_budget_duration: Option<String>,
    pub llm_tenant_tpm: Option<i64>,
    pub llm_tenant_rpm: Option<i64>,
    /// 32-byte key (hex/base64) sealing connection credentials at rest.
    /// Optional: without it (and with KMS off), integration connections are
    /// disabled. Once KMS is on and every row is re-sealed, this may be retired
    /// (the D4 boot gate proves zero legacy rows before allowing its absence).
    pub credential_key: Option<String>,
    /// Envelope-sealing key-wrapping backend (Phase D). Default `Off`.
    pub kms_mode: KmsMode,
    /// The 32-byte static KEK (hex/base64) that wraps per-tenant DEKs. Required
    /// iff `kms_mode = Static` (validated in `build_sealer`).
    pub kms_static_kek: Option<String>,
    /// The AWS KMS key id/ARN used to wrap per-tenant DEKs. Required iff
    /// `kms_mode = Aws`.
    pub kms_aws_key_id: Option<String>,
    /// Optional AWS KMS endpoint override (test seam — mirrors
    /// `FLUIDBOX_GITHUB_API_URL`: default = real KMS, override = a local fake).
    pub kms_aws_endpoint: Option<String>,
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
    /// Operator egress allowlist (`FLUIDBOX_EGRESS_ALLOW_CIDRS`, Phase E): CIDR
    /// blocks the shared SSRF predicate treats as public even when they fall in a
    /// private/metadata range — a private LiteLLM/GHES/MCP endpoint the deployment
    /// opts into. Parsed once at boot (a malformed entry fails boot); default empty.
    pub egress_allow_cidrs: Vec<fluidbox_core::netpolicy::IpCidr>,
    /// Optional outbound egress proxy (`FLUIDBOX_EGRESS_PROXY`, Phase E) applied to
    /// BOTH hardened reqwest clients and exported as HTTPS_PROXY on the git fetch
    /// subprocess — route all control-plane→internet dials through one waypoint.
    pub egress_proxy: Option<String>,
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
    /// Confine the operator (admin) token to `/v1/admin/*` (`FLUIDBOX_REQUIRE_SSO`).
    /// With it set, `Principal` refuses the admin token on data-plane routes —
    /// a hosted deployment authorizes only verified user principals there.
    pub require_sso: bool,
    /// Trust client-supplied `X-Forwarded-For` / `X-Real-IP` for the login
    /// rate-limit buckets and audit `source_ip` (`FLUIDBOX_TRUST_FORWARDED_FOR`).
    /// Set this ONLY when fluidbox runs behind a trusted reverse proxy that
    /// strips any client-supplied XFF and sets its own — otherwise any client
    /// spoofs its rate-limit bucket and forges audit source IPs. Default false:
    /// the socket peer address is authoritative.
    pub trust_forwarded_for: bool,
    /// Browser-session sliding idle window (seconds). The idle bump is always
    /// `least(now() + idle, absolute_expires_at)`.
    pub session_idle_secs: i64,
    /// Browser-session hard cap (seconds). Consumed by the login session mint.
    pub session_absolute_secs: i64,
    /// Max age of a cached OIDC discovery document / JWKS before re-fetch.
    pub oidc_discovery_max_age_secs: i64,
    /// Permitted clock skew when validating ID-token time claims.
    pub oidc_clock_skew_secs: i64,
    /// Minimum interval between a browser session's re-authorization checks on
    /// a long-lived stream; clamped to at most 60s (the re-auth bound).
    pub session_reauth_secs: i64,
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
        // D7: the per-request upstream-auth mode is an EXPLICIT choice, not a
        // silent URL-substring outcome. Parse it (invalid → boot error) and refuse
        // boot on an incoherent LLM-key config (the empty-shared-key refusal kills
        // the old silent `unwrap_or_default("")`).
        let llm_key_mode = {
            let raw = get("FLUIDBOX_LLM_KEY_MODE").unwrap_or_default();
            LlmKeyMode::parse(&raw).ok_or_else(|| {
                anyhow::anyhow!("FLUIDBOX_LLM_KEY_MODE='{raw}' is invalid (known: shared, tenant)")
            })?
        };
        validate_llm_key_config(llm_key_mode, is_anthropic, upstream_key.is_empty())
            .map_err(|m| anyhow::anyhow!("{m}"))?;
        // Admin plane for virtual-key provisioning defaults to the data-plane URL.
        let llm_admin_url = get("FLUIDBOX_LLM_ADMIN_URL").unwrap_or_else(|_| upstream.clone());
        let provider = get("FLUIDBOX_PROVIDER")
            .unwrap_or_else(|_| "docker".into())
            .to_lowercase();
        let is_k8s_provider = matches!(provider.as_str(), "kubernetes" | "k8s");
        Ok(Config {
            bind: get("FLUIDBOX_BIND").unwrap_or_else(|_| "127.0.0.1:8787".into()),
            // Only the Kubernetes plane needs a pod-reachable internal bind;
            // Docker single-host dev must not grow a LAN-exposed listener by
            // default (the runner reaches :8787 via host.docker.internal).
            internal_bind: get("FLUIDBOX_INTERNAL_BIND").unwrap_or_else(|_| {
                if is_k8s_provider {
                    "0.0.0.0:8788".into()
                } else {
                    "127.0.0.1:8788".into()
                }
            }),
            database_url: get("DATABASE_URL")
                .map_err(|_| anyhow::anyhow!("DATABASE_URL is required"))?,
            // Validated at parse time (fail closed with a clear boot error) since it
            // is interpolated into `SET ROLE` DDL, never a bind parameter.
            runtime_role: {
                match get("FLUIDBOX_RUNTIME_ROLE").ok().filter(|s| !s.is_empty()) {
                    None => None,
                    Some(role) => {
                        fluidbox_db::validate_runtime_role_name(&role)
                            .map_err(|m| anyhow::anyhow!("{m}"))?;
                        Some(role)
                    }
                }
            },
            allow_rls_bypass: get("FLUIDBOX_ALLOW_RLS_BYPASS")
                .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
                .unwrap_or(false),
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
            llm_key_mode,
            llm_admin_url,
            llm_tenant_models: get("FLUIDBOX_LLM_TENANT_MODELS")
                .ok()
                .map(|s| {
                    s.split(',')
                        .map(|m| m.trim().to_string())
                        .filter(|m| !m.is_empty())
                        .collect()
                })
                .unwrap_or_default(),
            llm_tenant_max_budget: parse_opt_f64(
                "FLUIDBOX_LLM_TENANT_MAX_BUDGET",
                get("FLUIDBOX_LLM_TENANT_MAX_BUDGET").ok(),
            )?,
            llm_tenant_budget_duration: get("FLUIDBOX_LLM_TENANT_BUDGET_DURATION")
                .ok()
                .filter(|s| !s.is_empty()),
            llm_tenant_tpm: parse_opt_i64(
                "FLUIDBOX_LLM_TENANT_TPM",
                get("FLUIDBOX_LLM_TENANT_TPM").ok(),
            )?,
            llm_tenant_rpm: parse_opt_i64(
                "FLUIDBOX_LLM_TENANT_RPM",
                get("FLUIDBOX_LLM_TENANT_RPM").ok(),
            )?,
            credential_key: get("FLUIDBOX_CREDENTIAL_KEY")
                .ok()
                .filter(|k| !k.is_empty()),
            kms_mode: {
                let raw = get("FLUIDBOX_KMS_MODE").unwrap_or_default();
                KmsMode::parse(&raw).ok_or_else(|| {
                    anyhow::anyhow!(
                        "FLUIDBOX_KMS_MODE='{raw}' is invalid (known: off, static, aws)"
                    )
                })?
            },
            kms_static_kek: get("FLUIDBOX_KMS_STATIC_KEK")
                .ok()
                .filter(|k| !k.is_empty()),
            kms_aws_key_id: get("FLUIDBOX_KMS_AWS_KEY_ID")
                .ok()
                .filter(|k| !k.is_empty()),
            kms_aws_endpoint: get("FLUIDBOX_KMS_AWS_ENDPOINT")
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
            egress_allow_cidrs: parse_egress_cidrs(
                "FLUIDBOX_EGRESS_ALLOW_CIDRS",
                get("FLUIDBOX_EGRESS_ALLOW_CIDRS").ok(),
            )?,
            egress_proxy: get("FLUIDBOX_EGRESS_PROXY").ok().filter(|s| !s.is_empty()),
            provider,
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
            max_archive_bytes: parse_u64_env(
                "FLUIDBOX_MAX_ARCHIVE_BYTES",
                get("FLUIDBOX_MAX_ARCHIVE_BYTES").ok(),
                2 * 1024 * 1024 * 1024, // 2 GiB
            )?,
            archive_ttl_secs: parse_u64_env(
                "FLUIDBOX_ARCHIVE_TTL_SECS",
                get("FLUIDBOX_ARCHIVE_TTL_SECS").ok(),
                24 * 3600,
            )?,
            require_sso: get("FLUIDBOX_REQUIRE_SSO")
                .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
                .unwrap_or(false),
            trust_forwarded_for: get("FLUIDBOX_TRUST_FORWARDED_FOR")
                .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
                .unwrap_or(false),
            session_idle_secs: parse_i64_env(
                "FLUIDBOX_SESSION_IDLE_SECS",
                get("FLUIDBOX_SESSION_IDLE_SECS").ok(),
                8 * 3600, // 28800
            )?,
            session_absolute_secs: parse_i64_env(
                "FLUIDBOX_SESSION_ABSOLUTE_SECS",
                get("FLUIDBOX_SESSION_ABSOLUTE_SECS").ok(),
                7 * 24 * 3600, // 604800
            )?,
            oidc_discovery_max_age_secs: parse_i64_env(
                "FLUIDBOX_OIDC_DISCOVERY_MAX_AGE_SECS",
                get("FLUIDBOX_OIDC_DISCOVERY_MAX_AGE_SECS").ok(),
                3600,
            )?,
            oidc_clock_skew_secs: parse_i64_env(
                "FLUIDBOX_OIDC_CLOCK_SKEW_SECS",
                get("FLUIDBOX_OIDC_CLOCK_SKEW_SECS").ok(),
                60,
            )?,
            // Clamp to the ≤60s re-auth bound (design lines 658-664): a larger
            // value would widen the window a revoked session keeps a stream.
            session_reauth_secs: parse_i64_env(
                "FLUIDBOX_SESSION_REAUTH_SECS",
                get("FLUIDBOX_SESSION_REAUTH_SECS").ok(),
                60,
            )?
            .min(60),
        })
    }
}

/// Safety-relevant numeric knobs FAIL BOOT on a malformed value: a typo in an
/// intended lower archive cap must not silently widen it to the default.
fn parse_u64_env(name: &str, raw: Option<String>, default: u64) -> anyhow::Result<u64> {
    match raw.filter(|v| !v.is_empty()) {
        None => Ok(default),
        Some(v) => v
            .parse()
            .map_err(|e| anyhow::anyhow!("{name}='{v}' is not a valid u64: {e}")),
    }
}

/// Same fail-boot-on-malformed discipline for i64 duration knobs.
fn parse_i64_env(name: &str, raw: Option<String>, default: i64) -> anyhow::Result<i64> {
    match raw.filter(|v| !v.is_empty()) {
        None => Ok(default),
        Some(v) => v
            .parse()
            .map_err(|e| anyhow::anyhow!("{name}='{v}' is not a valid i64: {e}")),
    }
}

/// Optional f64 knob (tenant virtual-key budget): absent/empty → `None`; a
/// malformed value FAILS BOOT rather than silently dropping the knob.
fn parse_opt_f64(name: &str, raw: Option<String>) -> anyhow::Result<Option<f64>> {
    match raw.filter(|v| !v.is_empty()) {
        None => Ok(None),
        Some(v) => v
            .parse()
            .map(Some)
            .map_err(|e| anyhow::anyhow!("{name}='{v}' is not a valid f64: {e}")),
    }
}

/// Optional i64 knob (tenant virtual-key tpm/rpm): absent/empty → `None`; a
/// malformed value fails boot.
fn parse_opt_i64(name: &str, raw: Option<String>) -> anyhow::Result<Option<i64>> {
    match raw.filter(|v| !v.is_empty()) {
        None => Ok(None),
        Some(v) => v
            .parse()
            .map(Some)
            .map_err(|e| anyhow::anyhow!("{name}='{v}' is not a valid i64: {e}")),
    }
}

/// Parse the comma-separated egress allowlist (Phase E). Empty/absent → no
/// entries; a malformed CIDR FAILS BOOT naming the variable (an operator typo in
/// an egress escape hatch must never silently widen or narrow the boundary).
fn parse_egress_cidrs(
    name: &str,
    raw: Option<String>,
) -> anyhow::Result<Vec<fluidbox_core::netpolicy::IpCidr>> {
    let Some(raw) = raw.filter(|v| !v.trim().is_empty()) else {
        return Ok(Vec::new());
    };
    raw.split(',')
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .map(|s| {
            s.parse::<fluidbox_core::netpolicy::IpCidr>()
                .map_err(|e| anyhow::anyhow!("{name}: {e}"))
        })
        .collect()
}

/// D7 boot coherence for the LLM-key mode (pure, unit-tested). `Shared` refuses
/// an empty resolved upstream key (kills the silent `unwrap_or_default("")`),
/// naming the variable the operator must set. `Tenant` requires a LiteLLM upstream
/// (direct Anthropic cannot mint virtual keys) AND a non-empty master key (the
/// provisioning credential). Returns the operator-facing boot-error message.
fn validate_llm_key_config(
    mode: LlmKeyMode,
    is_anthropic: bool,
    upstream_key_empty: bool,
) -> Result<(), String> {
    match mode {
        LlmKeyMode::Shared => {
            if upstream_key_empty {
                let var = if is_anthropic {
                    "ANTHROPIC_API_KEY"
                } else {
                    "LITELLM_MASTER_KEY"
                };
                return Err(format!(
                    "FLUIDBOX_LLM_KEY_MODE=shared but the resolved upstream key is empty — set \
                     {var} (the facade presents it on every model request; there is no silent \
                     fallback)"
                ));
            }
        }
        LlmKeyMode::Tenant => {
            if is_anthropic {
                return Err(
                    "FLUIDBOX_LLM_KEY_MODE=tenant requires a LiteLLM upstream (LLM_UPSTREAM_URL), \
                     not direct Anthropic — virtual keys are a LiteLLM feature and direct \
                     Anthropic cannot mint them"
                        .into(),
                );
            }
            if upstream_key_empty {
                return Err(
                    "FLUIDBOX_LLM_KEY_MODE=tenant requires LITELLM_MASTER_KEY (the virtual-key \
                     provisioning credential)"
                        .into(),
                );
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn safety_caps_fail_boot_on_malformed_values() {
        assert_eq!(parse_u64_env("X", None, 7).unwrap(), 7);
        assert_eq!(parse_u64_env("X", Some(String::new()), 7).unwrap(), 7);
        assert_eq!(parse_u64_env("X", Some("42".into()), 7).unwrap(), 42);
        // A typo'd cap must be a boot error, never a silent fallback to the
        // (possibly much wider) default.
        assert!(parse_u64_env("X", Some("2GiB".into()), 7).is_err());
    }

    #[test]
    fn llm_key_mode_parses_known_and_rejects_unknown() {
        assert_eq!(LlmKeyMode::parse("shared"), Some(LlmKeyMode::Shared));
        assert_eq!(LlmKeyMode::parse(""), Some(LlmKeyMode::Shared));
        assert_eq!(LlmKeyMode::parse("TENANT"), Some(LlmKeyMode::Tenant));
        assert_eq!(LlmKeyMode::parse("  tenant "), Some(LlmKeyMode::Tenant));
        // An unknown mode is a boot error, never a silent default.
        assert_eq!(LlmKeyMode::parse("virtual"), None);
        assert_eq!(LlmKeyMode::parse("per-user"), None);
    }

    #[test]
    fn shared_mode_refuses_empty_upstream_key() {
        // Empty key + non-anthropic upstream → name LITELLM_MASTER_KEY.
        let e = validate_llm_key_config(LlmKeyMode::Shared, false, true).unwrap_err();
        assert!(e.contains("LITELLM_MASTER_KEY"), "got: {e}");
        // Empty key + anthropic-direct upstream → name ANTHROPIC_API_KEY.
        let e = validate_llm_key_config(LlmKeyMode::Shared, true, true).unwrap_err();
        assert!(e.contains("ANTHROPIC_API_KEY"), "got: {e}");
        // Non-empty key → OK (today's behavior, now explicit).
        assert!(validate_llm_key_config(LlmKeyMode::Shared, false, false).is_ok());
        assert!(validate_llm_key_config(LlmKeyMode::Shared, true, false).is_ok());
    }

    #[test]
    fn tenant_mode_requires_litellm_and_master_key() {
        // Direct-Anthropic upstream cannot mint virtual keys → refuse.
        let e = validate_llm_key_config(LlmKeyMode::Tenant, true, false).unwrap_err();
        assert!(e.contains("LiteLLM"), "got: {e}");
        // LiteLLM upstream but no master key → refuse naming it.
        let e = validate_llm_key_config(LlmKeyMode::Tenant, false, true).unwrap_err();
        assert!(e.contains("LITELLM_MASTER_KEY"), "got: {e}");
        // LiteLLM upstream + master key present → OK.
        assert!(validate_llm_key_config(LlmKeyMode::Tenant, false, false).is_ok());
    }

    #[test]
    fn egress_cidrs_parse_and_fail_closed() {
        assert!(parse_egress_cidrs("X", None).unwrap().is_empty());
        assert!(parse_egress_cidrs("X", Some("  ".into()))
            .unwrap()
            .is_empty());
        let v = parse_egress_cidrs("X", Some("10.0.0.0/8, 169.254.169.254/32".into())).unwrap();
        assert_eq!(v.len(), 2);
        assert_eq!(v[0].prefix, 8);
        // A malformed entry is a boot error, never a silently dropped rule.
        assert!(parse_egress_cidrs("X", Some("10.0.0.0/8,nonsense".into())).is_err());
        assert!(parse_egress_cidrs("X", Some("10.0.0.0/40".into())).is_err());
    }

    #[test]
    fn tenant_knob_parsing_optional_and_fail_closed() {
        assert_eq!(parse_opt_f64("B", None).unwrap(), None);
        assert_eq!(parse_opt_f64("B", Some(String::new())).unwrap(), None);
        assert_eq!(parse_opt_f64("B", Some("12.5".into())).unwrap(), Some(12.5));
        assert!(parse_opt_f64("B", Some("lots".into())).is_err());
        assert_eq!(parse_opt_i64("R", None).unwrap(), None);
        assert_eq!(parse_opt_i64("R", Some("100".into())).unwrap(), Some(100));
        assert!(parse_opt_i64("R", Some("fast".into())).is_err());
    }
}
