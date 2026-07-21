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
    /// Application connection-pool sizing (`FLUIDBOX_DB_*`, Phase F). The old
    /// hardcoded `max_connections(10)` was the ceiling that made the design's
    /// 300-concurrent-run target arithmetically impossible: pool throughput is
    /// `max_connections / mean query time`, and at 300 runs the per-run pollers
    /// (approval wait ≤2 s, in-flight claim poll 500 ms, one SSE catch-up per
    /// connected browser ≤2 s) alone are hundreds of queries a second. See
    /// [`fluidbox_db::PoolSettings`] for what each field is and why its default is
    /// what it is; every one of them fails boot on a malformed value, and the two
    /// that can wedge the process (a zero ceiling, a floor above the ceiling) fail
    /// boot on a merely NONSENSICAL one.
    pub db_pool: fluidbox_db::PoolSettings,
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
    /// How many LLM budget reservations one session may hold at once (Phase E,
    /// #33; Gap 14) — the finite ceiling design :1118 asks for, NOT a per-session
    /// mutex. Lives here rather than behind a lazy `OnceLock` in `facade.rs` so a
    /// malformed value FAILS BOOT naming the variable (and is therefore visible to
    /// `just doctor`) instead of logging once at the first model request and
    /// tolerating the typo for the life of the process. Must be ≥ 1.
    pub llm_max_concurrent_reservations: i64,
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
    /// Validated at boot (a malformed URL fails boot). NOTE: with a proxy set,
    /// target DNS resolution moves to the PROXY, so the SSRF DNS resolver's
    /// name-filtering no longer applies to proxied requests (`admit_url`'s
    /// literal+scheme checks still do) — the proxy becomes the egress control
    /// point, so point it at an allowlisting forward proxy.
    pub egress_proxy: Option<String>,
    /// Outbound brokered-dial ceilings, per minute, for the in-memory
    /// `EgressGovernor` (`FLUIDBOX_EGRESS_RATE_{TENANT,CONNECTION,HOST}_PER_MIN`,
    /// Phase E). Defaults 120 / 60 / 120. **A value of 0 DISABLES that
    /// dimension** (see `governor::GovernorLimits::from_config` for why zero is
    /// not "block everything"); a malformed value fails boot.
    pub egress_rate_tenant_per_min: u32,
    pub egress_rate_connection_per_min: u32,
    pub egress_rate_host_per_min: u32,
    /// The PER-USER outbound ceiling (`FLUIDBOX_EGRESS_RATE_USER_PER_MIN`, Phase F).
    /// The fourth dimension the design names and Phase E deferred: without it one
    /// member of an org can spread dials across the org's connections and consume
    /// the whole tenant budget. Default 60 — the same number as the per-CONNECTION
    /// ceiling, which is what a single-connection run is already bounded by today,
    /// so the common shape sees no change and the multi-connection fan-out this
    /// dimension exists to catch is the case that starts binding. Enforced ONLY in
    /// the durable tier (the in-memory governor is deliberately unchanged), so it
    /// is inactive when `FLUIDBOX_EGRESS_DURABLE=0`. **0 DISABLES it**; a malformed
    /// value fails boot.
    pub egress_rate_user_per_min: u32,
    /// Cross-replica egress governance (`FLUIDBOX_EGRESS_DURABLE`, Phase F;
    /// migration 0023). Default ON. The in-memory governor is per-replica, so an
    /// N-replica deployment's real ceiling is N × the configured rate and a breaker
    /// opened on one replica does not stop the others; this turns on the Postgres
    /// tier that closes both. It is a SECOND gate, never a replacement — a dial
    /// must pass the local tier AND this one — and it DEGRADES: a DB error admits
    /// on the local verdict alone rather than failing the dial. A malformed value
    /// fails boot.
    pub egress_durable: bool,
    /// Per-connection circuit breaker (`FLUIDBOX_EGRESS_BREAKER_THRESHOLD`,
    /// `FLUIDBOX_EGRESS_BREAKER_OPEN_SECS`, Phase E): consecutive transport/5xx
    /// failures that open it (default 5) and how long it stays open before
    /// admitting one half-open probe (default 60s). Zero on EITHER disables the
    /// breaker; a malformed value fails boot.
    pub egress_breaker_threshold: u32,
    pub egress_breaker_open_secs: u64,
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
    /// Ceiling on a buffered request body, in bytes (`FLUIDBOX_MAX_REQUEST_BODY_BYTES`,
    /// Phase F). Default [`DEFAULT_MAX_REQUEST_BODY_BYTES`] = axum's own implicit
    /// 2 MiB, so shipping this changes NOTHING — the point is that the limit stops
    /// being invisible. It was already being enforced (every body-consuming handler
    /// in this crate extracts `Bytes`/`Json`, which axum bounds by default), it was
    /// simply not a number anyone had chosen, could see, or could move.
    ///
    /// It is a CONCURRENCY knob, not just a validation one: the bound is per
    /// in-flight request, so the deployment's exposure is `limit × concurrent
    /// requests` — at the design's 300-run target the default already reserves
    /// 600 MiB against a chart default of a 1 GiB memory limit. Raise it (the LLM
    /// facade buffers the whole model request, so a long conversation is what
    /// actually hits 2 MiB) only together with `server.resources.limits.memory`.
    ///
    /// Refused below [`MIN_MAX_REQUEST_BODY_BYTES`]: a sub-kilobyte ceiling rejects
    /// every real request on this API, which is the "never block everything" shape
    /// the governor knobs already refuse.
    pub max_request_body_bytes: usize,
}

/// The default buffered-body ceiling — deliberately EQUAL to axum's own implicit
/// default (`axum_core`'s `DEFAULT_LIMIT`, 2 MiB), so making the limit explicit is
/// a byte-for-byte no-op on an existing install. A test asserts the equality by
/// driving a real router, in both directions, so a future axum bump that moves its
/// default is visible here rather than in a 413 nobody expected.
pub const DEFAULT_MAX_REQUEST_BODY_BYTES: usize = 2 * 1024 * 1024;

/// Floor under `FLUIDBOX_MAX_REQUEST_BODY_BYTES`. Nothing this API accepts fits in
/// under a kilobyte — a smaller value is a typo (or a unit mix-up), and honouring it
/// would take the whole write surface down while looking like a deliberate setting.
pub const MIN_MAX_REQUEST_BODY_BYTES: usize = 1024;

/// Serialized runner-env ceiling: env injection is the v1 config channel
/// (authenticated fetch is the designated v1.1 follow-up), and Kubernetes
/// caps a Secret/env at ~1 MiB. 512 KiB leaves headroom and fails a bloated
/// run closed at zero model spend rather than at an opaque kubelet error.
pub const MAX_RUNNER_ENV_BYTES: usize = 512 * 1024;

/// Request timeout on the plain outbound client (`AppStateInner::http`) used for
/// operator-configured seams — GitHub and, load-bearingly, the LLM upstream that
/// the facade forwards to. A long-running model turn must not be cut off.
///
/// NAMED rather than typed inline at the one use site (`main.rs`) because
/// `facade::RESERVATION_TTL_SECS` must comfortably EXCEED it: the expiry sweep
/// converts a still-`reserved` row into a conservative charge, so a TTL shorter
/// than this timeout would over-charge a request that is merely slow — and,
/// because both settle under the same request id, that over-charge would stick.
/// `facade`'s test derives its assertion from this constant, so raising the
/// timeout past the TTL fails there instead of silently breaking the guarantee.
pub const UPSTREAM_HTTP_TIMEOUT_SECS: u64 = 15 * 60;

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
            db_pool: parse_pool_settings(&get)?,
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
            llm_max_concurrent_reservations: parse_positive_i64_env(
                "FLUIDBOX_LLM_MAX_CONCURRENT_RESERVATIONS",
                get("FLUIDBOX_LLM_MAX_CONCURRENT_RESERVATIONS").ok(),
                crate::facade::DEFAULT_MAX_CONCURRENT_RESERVATIONS,
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
            egress_proxy: parse_egress_proxy(
                "FLUIDBOX_EGRESS_PROXY",
                get("FLUIDBOX_EGRESS_PROXY").ok(),
            )?,
            egress_rate_tenant_per_min: parse_u32_env(
                "FLUIDBOX_EGRESS_RATE_TENANT_PER_MIN",
                get("FLUIDBOX_EGRESS_RATE_TENANT_PER_MIN").ok(),
                crate::governor::DEFAULT_TENANT_PER_MIN,
            )?,
            egress_rate_connection_per_min: parse_u32_env(
                "FLUIDBOX_EGRESS_RATE_CONNECTION_PER_MIN",
                get("FLUIDBOX_EGRESS_RATE_CONNECTION_PER_MIN").ok(),
                crate::governor::DEFAULT_CONNECTION_PER_MIN,
            )?,
            egress_rate_host_per_min: parse_u32_env(
                "FLUIDBOX_EGRESS_RATE_HOST_PER_MIN",
                get("FLUIDBOX_EGRESS_RATE_HOST_PER_MIN").ok(),
                crate::governor::DEFAULT_HOST_PER_MIN,
            )?,
            egress_rate_user_per_min: parse_u32_env(
                "FLUIDBOX_EGRESS_RATE_USER_PER_MIN",
                get("FLUIDBOX_EGRESS_RATE_USER_PER_MIN").ok(),
                crate::governor::DEFAULT_USER_PER_MIN,
            )?,
            // Default ON: `DATABASE_URL` is REQUIRED above, so "a database is
            // configured" is always true here and the durable tier ships enabled.
            // That is deliberate — a fix for an N× ceiling that has to be switched
            // on is a fix that ships dark — and it is safe to default because the
            // tier DEGRADES on any DB error (admit on the local verdict, log,
            // count) rather than failing dials closed.
            egress_durable: parse_bool_env(
                "FLUIDBOX_EGRESS_DURABLE",
                get("FLUIDBOX_EGRESS_DURABLE").ok(),
                true,
            )?,
            egress_breaker_threshold: parse_u32_env(
                "FLUIDBOX_EGRESS_BREAKER_THRESHOLD",
                get("FLUIDBOX_EGRESS_BREAKER_THRESHOLD").ok(),
                crate::governor::DEFAULT_BREAKER_THRESHOLD,
            )?,
            egress_breaker_open_secs: parse_u64_env(
                "FLUIDBOX_EGRESS_BREAKER_OPEN_SECS",
                get("FLUIDBOX_EGRESS_BREAKER_OPEN_SECS").ok(),
                crate::governor::DEFAULT_BREAKER_OPEN_SECS,
            )?,
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
            max_request_body_bytes: parse_body_limit(
                "FLUIDBOX_MAX_REQUEST_BODY_BYTES",
                get("FLUIDBOX_MAX_REQUEST_BODY_BYTES").ok(),
            )?,
        })
    }
}

/// Read the five `FLUIDBOX_DB_*` pool knobs (Phase F). Each one is absent-means-
/// default and malformed-means-boot-error, exactly like the egress knobs beside
/// them; the CROSS-field coherence check then runs in [`validate_pool_settings`],
/// which is pure and unit-tested.
fn parse_pool_settings(
    get: &impl Fn(&str) -> Result<String, std::env::VarError>,
) -> anyhow::Result<fluidbox_db::PoolSettings> {
    let d = fluidbox_db::PoolSettings::default();
    let settings = fluidbox_db::PoolSettings {
        max_connections: parse_positive_u32_env(
            "FLUIDBOX_DB_MAX_CONNECTIONS",
            get("FLUIDBOX_DB_MAX_CONNECTIONS").ok(),
            d.max_connections,
        )?,
        // 0 is MEANINGFUL here (open on demand) and is the default, so this one
        // rides the plain u32 parse rather than the positive one.
        min_connections: parse_u32_env(
            "FLUIDBOX_DB_MIN_CONNECTIONS",
            get("FLUIDBOX_DB_MIN_CONNECTIONS").ok(),
            d.min_connections,
        )?,
        acquire_timeout_secs: parse_u64_env(
            "FLUIDBOX_DB_ACQUIRE_TIMEOUT_SECS",
            get("FLUIDBOX_DB_ACQUIRE_TIMEOUT_SECS").ok(),
            d.acquire_timeout_secs,
        )?,
        idle_timeout_secs: parse_u64_env(
            "FLUIDBOX_DB_IDLE_TIMEOUT_SECS",
            get("FLUIDBOX_DB_IDLE_TIMEOUT_SECS").ok(),
            d.idle_timeout_secs,
        )?,
        max_lifetime_secs: parse_u64_env(
            "FLUIDBOX_DB_MAX_LIFETIME_SECS",
            get("FLUIDBOX_DB_MAX_LIFETIME_SECS").ok(),
            d.max_lifetime_secs,
        )?,
    };
    validate_pool_settings(&settings).map_err(|m| anyhow::anyhow!("{m}"))?;
    Ok(settings)
}

/// Cross-field coherence for the pool knobs (pure, unit-tested). Each individual
/// value already parsed; these are the combinations that are individually legal and
/// jointly nonsense, and every one of them would surface as a hang or a stall rather
/// than as an error at the point of use — which is exactly the class that belongs in
/// a boot refusal.
fn validate_pool_settings(s: &fluidbox_db::PoolSettings) -> Result<(), String> {
    if s.min_connections > s.max_connections {
        return Err(format!(
            "FLUIDBOX_DB_MIN_CONNECTIONS={} exceeds FLUIDBOX_DB_MAX_CONNECTIONS={} — the pool \
             would try to keep more connections warm than it is allowed to open",
            s.min_connections, s.max_connections
        ));
    }
    if s.acquire_timeout_secs == 0 {
        return Err(
            "FLUIDBOX_DB_ACQUIRE_TIMEOUT_SECS=0 would fail every acquire that does not find a \
             free connection already waiting — set a positive number of seconds"
                .into(),
        );
    }
    // The pool must not hold an idle connection past the point where the SERVER
    // closes it. Neon suspends an idle compute after NEON_AUTOSUSPEND_SECS and takes
    // its connections down with it; anything at or beyond that guarantees the pool
    // hands out connections that are already gone (sqlx then discovers this one
    // round trip into `test_before_acquire`, on whichever request arrives first
    // after a quiet period).
    if s.idle_timeout_secs >= fluidbox_db::NEON_AUTOSUSPEND_SECS {
        return Err(format!(
            "FLUIDBOX_DB_IDLE_TIMEOUT_SECS={} is at or above Neon's {}s idle-compute autosuspend \
             — the pool must retire an idle connection BEFORE the server does, or the first \
             request after a quiet period pays for discovering a dead one",
            s.idle_timeout_secs,
            fluidbox_db::NEON_AUTOSUSPEND_SECS
        ));
    }
    if s.max_lifetime_secs > 0 && s.max_lifetime_secs <= s.idle_timeout_secs {
        return Err(format!(
            "FLUIDBOX_DB_MAX_LIFETIME_SECS={} is not above FLUIDBOX_DB_IDLE_TIMEOUT_SECS={} — \
             recycling would retire connections faster than idling does, so the pool would churn \
             a fresh TLS handshake on a busy connection while a quiet one lives on",
            s.max_lifetime_secs, s.idle_timeout_secs
        ));
    }
    Ok(())
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

/// Same fail-boot-on-malformed discipline for the u32 governor knobs (Phase E):
/// a typo in an intended egress rate limit must fail boot naming the variable,
/// never silently restore the default ceiling.
fn parse_u32_env(name: &str, raw: Option<String>, default: u32) -> anyhow::Result<u32> {
    match raw.filter(|v| !v.is_empty()) {
        None => Ok(default),
        Some(v) => v
            .parse()
            .map_err(|e| anyhow::anyhow!("{name}='{v}' is not a valid u32: {e}")),
    }
}

/// A u32 knob that must be at least 1 (Phase F) — the `parse_positive_i64_env`
/// shape, for the pool ceiling. `parse_u32_env` accepts 0, and for
/// `FLUIDBOX_DB_MAX_CONNECTIONS` a 0 is not "disabled" like it is for the egress
/// rates: it is a pool that can never open a connection, i.e. a process that boots
/// healthy and then times out every single request 15 seconds at a time.
fn parse_positive_u32_env(name: &str, raw: Option<String>, default: u32) -> anyhow::Result<u32> {
    let v = parse_u32_env(name, raw, default)?;
    if v < 1 {
        anyhow::bail!("{name}='{v}' must be at least 1 (a pool of 0 connections serves nothing)");
    }
    Ok(v)
}

/// Parse `FLUIDBOX_MAX_REQUEST_BODY_BYTES` (Phase F): absent/empty ⇒ the axum-
/// equal default, malformed ⇒ a named boot error, and anything under
/// [`MIN_MAX_REQUEST_BODY_BYTES`] ⇒ a boot refusal rather than an API that 413s
/// every write. Parsed as u64 first so a value above `usize::MAX` on a 32-bit
/// target is a clean error instead of a wrap.
fn parse_body_limit(name: &str, raw: Option<String>) -> anyhow::Result<usize> {
    let v = parse_u64_env(name, raw, DEFAULT_MAX_REQUEST_BODY_BYTES as u64)?;
    let v =
        usize::try_from(v).map_err(|_| anyhow::anyhow!("{name}='{v}' does not fit in usize"))?;
    if v < MIN_MAX_REQUEST_BODY_BYTES {
        anyhow::bail!(
            "{name}='{v}' is below the {MIN_MAX_REQUEST_BODY_BYTES}-byte floor — every request \
             this API accepts is larger than that, so the whole write surface would 413"
        );
    }
    Ok(v)
}

/// Same fail-boot-on-malformed discipline for a BOOLEAN governor knob (Phase F).
///
/// Deliberately stricter than the older `.map(|v| v == "1" || …).unwrap_or(false)`
/// shape used by the non-safety flags above: that one reads `FLUIDBOX_EGRESS_DURABLE=ture`
/// as "off" and silently restores the per-replica ceiling the operator was trying to
/// close. A typo in a control that governs outbound abuse must fail boot naming the
/// variable, exactly like the `FLUIDBOX_EGRESS_RATE_*` numbers beside it.
///
/// Whitespace-only is treated as UNSET (the `parse_egress_cidrs` precedent), not as
/// malformed: a stray space after `FLUIDBOX_EGRESS_DURABLE=` in a `.env` means the
/// operator wrote nothing, and answering that with a boot failure would be a worse
/// trade than answering it with the default — which here is the SAFE value anyway.
fn parse_bool_env(name: &str, raw: Option<String>, default: bool) -> anyhow::Result<bool> {
    match raw.filter(|v| !v.trim().is_empty()) {
        None => Ok(default),
        Some(v) => match v.trim().to_ascii_lowercase().as_str() {
            "1" | "true" | "yes" | "on" => Ok(true),
            "0" | "false" | "no" | "off" => Ok(false),
            _ => Err(anyhow::anyhow!(
                "{name}='{v}' is not a valid boolean (use 1/0, true/false, yes/no, on/off)"
            )),
        },
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

/// An i64 knob that must be at least 1. `parse_i64_env` accepts any integer, but
/// a 0 (or negative) concurrency ceiling admits NOTHING and would wedge every run
/// — so it fails boot naming the variable rather than silently restoring the
/// default, which is the whole reason this knob moved out of `facade.rs`'s
/// `OnceLock` (a log line at the first model request is not a boot signal).
fn parse_positive_i64_env(name: &str, raw: Option<String>, default: i64) -> anyhow::Result<i64> {
    let v = parse_i64_env(name, raw, default)?;
    if v < 1 {
        anyhow::bail!("{name}='{v}' must be at least 1 (0 or negative admits no work at all)");
    }
    Ok(v)
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

/// Validate `FLUIDBOX_EGRESS_PROXY` at BOOT (like `FLUIDBOX_EGRESS_ALLOW_CIDRS`):
/// empty ⇒ `None`; otherwise it must be a proxy URL reqwest accepts — the SAME
/// `Proxy::all` the client builders call — so a malformed value is a named boot
/// error, never a first-dial panic. The pre-validated string flows to
/// `egress::build_*_http`, which then only needs a defensive (unreachable)
/// error-map rather than an `expect`.
fn parse_egress_proxy(name: &str, raw: Option<String>) -> anyhow::Result<Option<String>> {
    let Some(v) = raw.map(|s| s.trim().to_string()).filter(|s| !s.is_empty()) else {
        return Ok(None);
    };
    reqwest::Proxy::all(&v).map_err(|e| anyhow::anyhow!("{name}: {e}"))?;
    Ok(Some(v))
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
    fn governor_knobs_default_and_fail_closed() {
        // Absent/empty ⇒ the documented default …
        assert_eq!(parse_u32_env("G", None, 120).unwrap(), 120);
        assert_eq!(parse_u32_env("G", Some(String::new()), 60).unwrap(), 60);
        // … an explicit value wins, INCLUDING the "disabled" zero …
        assert_eq!(parse_u32_env("G", Some("7".into()), 120).unwrap(), 7);
        assert_eq!(parse_u32_env("G", Some("0".into()), 120).unwrap(), 0);
        // … and a malformed value is a NAMED boot error, never the default (the
        // `FLUIDBOX_EGRESS_ALLOW_CIDRS` precedent: an egress knob typo must not
        // silently widen the ceiling).
        let e = parse_u32_env(
            "FLUIDBOX_EGRESS_RATE_HOST_PER_MIN",
            Some("lots".into()),
            120,
        )
        .unwrap_err()
        .to_string();
        assert!(
            e.contains("FLUIDBOX_EGRESS_RATE_HOST_PER_MIN") && e.contains("lots"),
            "got: {e}"
        );
        assert!(parse_u32_env("G", Some("-1".into()), 120).is_err());
        assert!(parse_u32_env("G", Some("4294967296".into()), 120).is_err());
    }

    /// `FLUIDBOX_EGRESS_DURABLE` (Phase F). The knob that decides whether the
    /// cross-replica tier runs at all, so a typo must be a boot error rather than a
    /// silent return to the per-replica N× ceiling.
    #[test]
    fn the_durable_egress_flag_defaults_on_and_fails_boot_on_a_typo() {
        // Absent/empty ⇒ the shipped default (ON — DATABASE_URL is required, so a
        // database is always configured).
        assert!(parse_bool_env("FLUIDBOX_EGRESS_DURABLE", None, true).unwrap());
        assert!(parse_bool_env("FLUIDBOX_EGRESS_DURABLE", Some("  ".into()), true).unwrap());
        // Every spelling an operator plausibly writes, both ways.
        for on in ["1", "true", "TRUE", " yes ", "on"] {
            assert!(
                parse_bool_env("D", Some(on.into()), false).unwrap(),
                "{on} must read as ON"
            );
        }
        for off in ["0", "false", "False", "no", "off"] {
            assert!(
                !parse_bool_env("D", Some(off.into()), true).unwrap(),
                "{off} must read as OFF"
            );
        }
        // A typo is a NAMED boot error. The old `v == "1" || v == "true"` shape
        // would have read this as "off" and quietly reopened the N× ceiling.
        let e = parse_bool_env("FLUIDBOX_EGRESS_DURABLE", Some("ture".into()), true)
            .unwrap_err()
            .to_string();
        assert!(
            e.contains("FLUIDBOX_EGRESS_DURABLE") && e.contains("ture"),
            "got: {e}"
        );
    }

    /// The LLM concurrency ceiling (Gap 14). Drives the REAL parse — the earlier
    /// facade-side test re-implemented the match in its own body, so relaxing the
    /// production check to accept 0 (a ceiling that wedges every run, the exact
    /// case the test named) still passed it.
    #[test]
    fn llm_reservation_ceiling_defaults_and_fails_boot_on_bad_values() {
        // Absent/empty ⇒ the shipped default (32), which is what the const says.
        assert_eq!(
            parse_positive_i64_env(
                "C",
                None,
                crate::facade::DEFAULT_MAX_CONCURRENT_RESERVATIONS
            )
            .unwrap(),
            32
        );
        assert_eq!(
            parse_positive_i64_env("C", Some(String::new()), 32).unwrap(),
            32
        );
        // An explicit positive value wins.
        assert_eq!(
            parse_positive_i64_env("C", Some("8".into()), 32).unwrap(),
            8
        );
        assert_eq!(
            parse_positive_i64_env("C", Some("1".into()), 32).unwrap(),
            1
        );
        // Junk is a NAMED boot error, never the default.
        let e = parse_positive_i64_env(
            "FLUIDBOX_LLM_MAX_CONCURRENT_RESERVATIONS",
            Some("nope".into()),
            32,
        )
        .unwrap_err()
        .to_string();
        assert!(
            e.contains("FLUIDBOX_LLM_MAX_CONCURRENT_RESERVATIONS") && e.contains("nope"),
            "got: {e}"
        );
        // …and so is a non-positive ceiling: 0 would admit no model request at all.
        let e = parse_positive_i64_env(
            "FLUIDBOX_LLM_MAX_CONCURRENT_RESERVATIONS",
            Some("0".into()),
            32,
        )
        .unwrap_err()
        .to_string();
        assert!(
            e.contains("FLUIDBOX_LLM_MAX_CONCURRENT_RESERVATIONS") && e.contains("at least 1"),
            "got: {e}"
        );
        assert!(parse_positive_i64_env("C", Some("-1".into()), 32).is_err());
    }

    /// The pool ceiling (Phase F). `parse_u32_env` treats 0 as a legitimate
    /// "disabled" for the egress rates; for a connection pool 0 means the process
    /// boots healthy and then times out every request, so it needs the
    /// positive-only shape.
    #[test]
    fn the_pool_ceiling_defaults_and_refuses_a_pool_of_zero() {
        assert_eq!(parse_positive_u32_env("C", None, 25).unwrap(), 25);
        assert_eq!(
            parse_positive_u32_env("C", Some(String::new()), 25).unwrap(),
            25
        );
        assert_eq!(
            parse_positive_u32_env("C", Some("200".into()), 25).unwrap(),
            200
        );
        assert_eq!(
            parse_positive_u32_env("C", Some("1".into()), 25).unwrap(),
            1
        );
        // Zero is the one an operator reaches for meaning "unlimited" and gets the
        // exact opposite of.
        let e = parse_positive_u32_env("FLUIDBOX_DB_MAX_CONNECTIONS", Some("0".into()), 25)
            .unwrap_err()
            .to_string();
        assert!(
            e.contains("FLUIDBOX_DB_MAX_CONNECTIONS") && e.contains("at least 1"),
            "got: {e}"
        );
        // …and a typo is a named boot error, never the default.
        let e = parse_positive_u32_env("FLUIDBOX_DB_MAX_CONNECTIONS", Some("lots".into()), 25)
            .unwrap_err()
            .to_string();
        assert!(
            e.contains("FLUIDBOX_DB_MAX_CONNECTIONS") && e.contains("lots"),
            "got: {e}"
        );
    }

    /// The SHIPPED pool sizing. These are load-bearing numbers rather than sqlx
    /// defaults, so they are asserted here: a silent revert to `PoolOptions::new()`
    /// restores the exact ceiling Phase F exists to remove.
    #[test]
    fn the_shipped_pool_sizing_is_the_documented_one() {
        let d = fluidbox_db::PoolSettings::default();
        // Above sqlx's (and the old hardcode's) 10 — the whole point of the task.
        assert!(
            d.max_connections > 10,
            "the pool ceiling must exceed the sqlx default that was the old hardcode"
        );
        assert_eq!(d.max_connections, 25);
        assert_eq!(d.min_connections, 0);
        // UNCHANGED from the pre-Phase-F hardcode: this is the shed valve, and
        // moving it silently would change how a saturated deployment behaves.
        assert_eq!(d.acquire_timeout_secs, 15);
        // DERIVED, not hardcoded: an idle timeout at or past Neon's autosuspend
        // guarantees the pool serves connections the server has already closed.
        assert!(
            d.idle_timeout_secs < fluidbox_db::NEON_AUTOSUSPEND_SECS,
            "idle timeout {} must stay under Neon's {}s autosuspend",
            d.idle_timeout_secs,
            fluidbox_db::NEON_AUTOSUSPEND_SECS
        );
        assert!(d.max_lifetime_secs > d.idle_timeout_secs);
        // The shipped sizing must itself satisfy the boot gate.
        assert!(validate_pool_settings(&d).is_ok());
    }

    /// Every knob must actually REACH sqlx. `connect_with` migrates before it
    /// builds a pool, so this is the only layer where the mapping is observable
    /// offline — and a knob parsed, validated, logged and then dropped on the floor
    /// is indistinguishable from a working one everywhere else.
    #[test]
    fn every_pool_knob_reaches_sqlx() {
        // Five distinct values, so a copy-paste between fields is visible too.
        let o = fluidbox_db::pool_options(fluidbox_db::PoolSettings {
            max_connections: 41,
            min_connections: 7,
            acquire_timeout_secs: 11,
            idle_timeout_secs: 91,
            max_lifetime_secs: 601,
        });
        assert_eq!(o.get_max_connections(), 41);
        assert_eq!(o.get_min_connections(), 7);
        assert_eq!(o.get_acquire_timeout(), std::time::Duration::from_secs(11));
        assert_eq!(
            o.get_idle_timeout(),
            Some(std::time::Duration::from_secs(91))
        );
        assert_eq!(
            o.get_max_lifetime(),
            Some(std::time::Duration::from_secs(601))
        );
        // Deliberately UNCHANGED from sqlx's default: Neon's scale-to-zero closes
        // connections underneath the pool, so the pre-acquire ping stays on.
        assert!(o.get_test_before_acquire());
    }

    /// Cross-field pool coherence. Every case here is individually legal and
    /// jointly nonsense, and every one of them would surface as a hang, a stall or
    /// a churn rather than as an error at the point of use.
    #[test]
    fn nonsensical_pool_combinations_fail_boot() {
        let d = fluidbox_db::PoolSettings::default();
        // A warm floor above the ceiling.
        let e = validate_pool_settings(&fluidbox_db::PoolSettings {
            min_connections: d.max_connections + 1,
            ..d
        })
        .unwrap_err();
        assert!(
            e.contains("FLUIDBOX_DB_MIN_CONNECTIONS") && e.contains("FLUIDBOX_DB_MAX_CONNECTIONS"),
            "got: {e}"
        );
        // min == max is legal (a fully warm pool), so the check must be strict.
        assert!(validate_pool_settings(&fluidbox_db::PoolSettings {
            min_connections: d.max_connections,
            ..d
        })
        .is_ok());
        // A zero acquire timeout fails every acquire that has to wait at all.
        let e = validate_pool_settings(&fluidbox_db::PoolSettings {
            acquire_timeout_secs: 0,
            ..d
        })
        .unwrap_err();
        assert!(e.contains("FLUIDBOX_DB_ACQUIRE_TIMEOUT_SECS"), "got: {e}");
        // An idle timeout at (not merely past) Neon's autosuspend is already wrong.
        let e = validate_pool_settings(&fluidbox_db::PoolSettings {
            idle_timeout_secs: fluidbox_db::NEON_AUTOSUSPEND_SECS,
            max_lifetime_secs: 3600,
            ..d
        })
        .unwrap_err();
        assert!(
            e.contains("FLUIDBOX_DB_IDLE_TIMEOUT_SECS") && e.contains("autosuspend"),
            "got: {e}"
        );
        assert!(validate_pool_settings(&fluidbox_db::PoolSettings {
            idle_timeout_secs: fluidbox_db::NEON_AUTOSUSPEND_SECS - 1,
            max_lifetime_secs: 3600,
            ..d
        })
        .is_ok());
        // Recycling faster than idling churns busy connections.
        let e = validate_pool_settings(&fluidbox_db::PoolSettings {
            idle_timeout_secs: 200,
            max_lifetime_secs: 200,
            ..d
        })
        .unwrap_err();
        assert!(e.contains("FLUIDBOX_DB_MAX_LIFETIME_SECS"), "got: {e}");
        // 0 = sqlx's "no lifetime cap", which is a choice, not a mistake.
        assert!(validate_pool_settings(&fluidbox_db::PoolSettings {
            max_lifetime_secs: 0,
            ..d
        })
        .is_ok());
    }

    /// The pool knobs end-to-end: the exact variable NAMES, and the fact that
    /// [`validate_pool_settings`] is actually reached. Neither is provable by
    /// calling the validator directly — a typo'd name, or a deleted call, leaves
    /// every other test in this file green while the knob silently does nothing.
    #[test]
    fn the_pool_knobs_are_read_by_name_and_validated() {
        // A `get` that answers exactly one variable, as the environment would.
        let only = |name: &'static str, value: &'static str| {
            move |k: &str| {
                if k == name {
                    Ok(value.to_string())
                } else {
                    Err(std::env::VarError::NotPresent)
                }
            }
        };
        let none = |_: &str| Err(std::env::VarError::NotPresent);

        // Nothing set ⇒ exactly the crate default.
        assert_eq!(
            parse_pool_settings(&none).unwrap(),
            fluidbox_db::PoolSettings::default()
        );
        // Each documented name must MOVE its own field (and only its own).
        let s = parse_pool_settings(&only("FLUIDBOX_DB_MAX_CONNECTIONS", "77")).unwrap();
        assert_eq!(s.max_connections, 77);
        let s = parse_pool_settings(&only("FLUIDBOX_DB_MIN_CONNECTIONS", "3")).unwrap();
        assert_eq!(s.min_connections, 3);
        let s = parse_pool_settings(&only("FLUIDBOX_DB_ACQUIRE_TIMEOUT_SECS", "9")).unwrap();
        assert_eq!(s.acquire_timeout_secs, 9);
        let s = parse_pool_settings(&only("FLUIDBOX_DB_IDLE_TIMEOUT_SECS", "120")).unwrap();
        assert_eq!(s.idle_timeout_secs, 120);
        let s = parse_pool_settings(&only("FLUIDBOX_DB_MAX_LIFETIME_SECS", "3600")).unwrap();
        assert_eq!(s.max_lifetime_secs, 3600);
        // …and the coherence gate must be REACHED from here, not merely exist: a
        // floor above the ceiling is legal for each knob on its own.
        let e = parse_pool_settings(&only("FLUIDBOX_DB_MIN_CONNECTIONS", "9999"))
            .unwrap_err()
            .to_string();
        assert!(e.contains("FLUIDBOX_DB_MIN_CONNECTIONS"), "got: {e}");
        // A per-knob parse failure still fails boot from this entry point.
        assert!(parse_pool_settings(&only("FLUIDBOX_DB_MAX_CONNECTIONS", "0")).is_err());
        assert!(parse_pool_settings(&only("FLUIDBOX_DB_IDLE_TIMEOUT_SECS", "4m")).is_err());
    }

    /// This file's PRODUCTION half — the source guard below counts occurrences, and
    /// a test module that quotes the strings it counts would count itself.
    fn production_src() -> &'static str {
        let src = include_str!("config.rs");
        let end = src
            .find("#[cfg(test)]\nmod tests {")
            .expect("this file has a test module");
        &src[..end]
    }

    /// `from_env` must read the body-limit knob under the name the docs, the boot
    /// error, and the Helm chart all use. There is no way to prove this by calling
    /// the parser — the name is passed IN — and a typo would leave a knob that
    /// parses, validates, and is never set by anybody.
    #[test]
    fn the_body_limit_is_read_from_the_documented_variable() {
        let src = production_src();
        assert_eq!(
            src.matches("\"FLUIDBOX_MAX_REQUEST_BODY_BYTES\"").count(),
            2,
            "from_env passes the same name to the parser that it reads from the env"
        );
        assert!(src.contains("max_request_body_bytes: parse_body_limit("));
    }

    /// The buffered-body ceiling (Phase F). Default equal to axum's implicit one,
    /// malformed ⇒ named boot error, and a floor so the knob cannot be used to take
    /// the whole write surface down while looking deliberate.
    #[test]
    fn the_body_limit_defaults_to_axums_own_and_refuses_a_useless_floor() {
        assert_eq!(
            parse_body_limit("B", None).unwrap(),
            DEFAULT_MAX_REQUEST_BODY_BYTES
        );
        assert_eq!(
            parse_body_limit("B", Some(String::new())).unwrap(),
            DEFAULT_MAX_REQUEST_BODY_BYTES
        );
        // The default IS axum's own 2 MiB, so making the limit explicit is a no-op
        // (the router test in `main.rs` proves that end-to-end over a real socket).
        assert_eq!(DEFAULT_MAX_REQUEST_BODY_BYTES, 2 * 1024 * 1024);
        // An explicit value wins, in both directions.
        assert_eq!(
            parse_body_limit("B", Some("16777216".into())).unwrap(),
            16 * 1024 * 1024
        );
        assert_eq!(
            parse_body_limit("B", Some(MIN_MAX_REQUEST_BODY_BYTES.to_string())).unwrap(),
            MIN_MAX_REQUEST_BODY_BYTES
        );
        // Below the floor ⇒ a named refusal, DERIVED from the constant.
        let e = parse_body_limit(
            "FLUIDBOX_MAX_REQUEST_BODY_BYTES",
            Some((MIN_MAX_REQUEST_BODY_BYTES - 1).to_string()),
        )
        .unwrap_err()
        .to_string();
        assert!(
            e.contains("FLUIDBOX_MAX_REQUEST_BODY_BYTES") && e.contains("floor"),
            "got: {e}"
        );
        // 0 is the value an operator reaches for meaning "no limit".
        assert!(parse_body_limit("B", Some("0".into())).is_err());
        // A typo (a `2MB`-style unit suffix is the likely one) is a boot error.
        let e = parse_body_limit("FLUIDBOX_MAX_REQUEST_BODY_BYTES", Some("2MB".into()))
            .unwrap_err()
            .to_string();
        assert!(
            e.contains("FLUIDBOX_MAX_REQUEST_BODY_BYTES") && e.contains("2MB"),
            "got: {e}"
        );
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
