mod admin_orgs;
mod api;
mod auth;
mod bindings;
mod broker;
mod callback;
mod capabilities;
mod catalog;
mod config;
mod connections;
mod connectors;
mod deliveries;
mod dispatcher;
mod egress;
mod error;
mod events;
mod facade;
mod github_app;
mod governor;
mod harness;
mod internal;
mod kms;
mod ledger;
mod llm_keys;
mod login;
mod mcp_sse;
mod metrics;
mod netgrant;
mod oauth;
mod orchestrator;
mod rbac;
mod recipes;
mod request_log;
mod reseal;
mod run_service;
mod scheduler;
mod seal;
mod snapshots;
mod sse;
mod state;
mod tokens;
mod triggers;
mod workers;

/// This binary's identity in every log record's `service` field. A constant on
/// purpose — see `fluidbox_obs::LogConfig::from_env`.
const SERVICE_NAME: &str = "fluidbox-server";

use axum::routing::{delete, get, patch, post};
use axum::Router;
use fluidbox_core::traits::ExecutionProvider;
use state::{AppStateInner, ApprovalRegistry};
use std::net::SocketAddr;
use std::sync::Arc;

/// Select the execution backend from `FLUIDBOX_PROVIDER` (default `docker`).
/// Dual-provider permanence (settled Q17): Docker and Kubernetes are co-equal
/// backends behind the same trait, selected per deployment.
async fn build_provider(cfg: &config::Config) -> anyhow::Result<Arc<dyn ExecutionProvider>> {
    match cfg.provider.as_str() {
        "docker" => Ok(Arc::new(fluidbox_provider::DockerProvider::connect(
            cfg.data_dir.clone(),
        )?)),
        "kubernetes" | "k8s" => {
            let k8s_cfg = fluidbox_provider_k8s::config::K8sConfig::from_env();
            // Resolve the network enforcer at BOOT so `auto` is a concrete
            // answer before the first run is created, and so an explicit
            // `cilium` on a cluster without it refuses to boot rather than
            // admitting grants nothing can deliver.
            use fluidbox_provider_k8s::NetworkEnforcerMode as Mode;
            let mode = match cfg.network_enforcer {
                config::NetworkEnforcer::None => Mode::None,
                config::NetworkEnforcer::Cilium => Mode::Cilium,
                config::NetworkEnforcer::Auto => Mode::Auto,
            };
            Ok(Arc::new(
                fluidbox_provider_k8s::KubernetesProvider::connect(
                    k8s_cfg,
                    cfg.data_dir.clone(),
                    mode,
                    cfg.netpol_wait_secs,
                )
                .await?,
            ))
        }
        // Test-only (design 2026-08-23 §12), and gated at COMPILE time rather
        // than by a runtime flag: on a release build this arm does not exist,
        // so `FLUIDBOX_PROVIDER=null` falls through to the error below and the
        // binary cannot be talked into provisioning nothing.
        #[cfg(feature = "test-provider")]
        "null" => Ok(Arc::new(fluidbox_provider::NullProvider::from_env())),
        other => anyhow::bail!(
            "FLUIDBOX_PROVIDER='{other}' is not available in this build (known: docker, kubernetes)"
        ),
    }
}

/// Apply the process-wide request bounds to a listener's router (Phase F).
///
/// **What this adds:** nothing, on purpose. Every body-consuming handler in this
/// crate extracts `Bytes` or `Json`, and axum bounds those at 2 MiB by default, so
/// the limit was ALREADY being enforced — it was simply invisible, unnamed and
/// unmovable. `DEFAULT_MAX_REQUEST_BODY_BYTES` is that same 2 MiB, so an existing
/// install sees byte-identical behaviour; what changes is that an operator can now
/// see the number, move it, and be refused at boot for a nonsensical one. The
/// accompanying test drives a real listener in BOTH directions (a smaller limit
/// must reject what axum would accept, a larger one must accept what axum would
/// reject) so the layer is proven to be the thing that binds.
///
/// **What this deliberately does NOT add**, because neither is safe here:
///
/// * a request TIMEOUT layer. Both listeners carry requests that are long-lived by
///   design — `/v1/sessions/{id}/events/stream` (SSE, open for the life of a run),
///   `/internal/llm/*` (the facade forwards a model turn under a
///   [`config::UPSTREAM_HTTP_TIMEOUT_SECS`] = 900 s upstream budget and tees the SSE
///   response back), `/internal/sessions/{id}/permission` (blocks until a human
///   decides or the approval expires — MINUTES), and
///   `/internal/sessions/{id}/tools/call` (blocks on the brokered dispatch, and on
///   `poll_in_flight` for up to 30 s). A global timeout would cut model turns off
///   mid-stream — leaving `llm_reservations` rows to be swept into conservative
///   charges — and would convert a pending approval into a failed tool call.
///
/// * a global CONCURRENCY limit. `tower`'s releases its permit when the handler
///   FUTURE resolves, and on the internal plane the three handlers above resolve
///   only after a human, a model, or an upstream server does something. 300 runs
///   parked in `/permission` would hold 300 permits and starve the `/heartbeat`
///   posts that keep those very runs alive — the watchdog would then reap them.
///   The back-pressure valve that IS in place is `FLUIDBOX_DB_ACQUIRE_TIMEOUT_SECS`
///   (above): a saturated database sheds by failing acquires, not by queueing.
fn bounded(router: Router, max_request_body_bytes: usize) -> Router {
    router.layer(axum::extract::DefaultBodyLimit::max(max_request_body_bytes))
}

/// `FLUIDBOX_MIGRATE_ONLY=1` applies migrations, verifies the RLS posture, and
/// exits 0 without serving.
///
/// This is what gives a deploy pipeline MIGRATION ORDERING. Without it,
/// migrations run at pod boot: a failing migration surfaces as a
/// CrashLoopBackOff *after* the rollout has already started, `helm --atomic`
/// rolls the release back, and the operator is left reading pod logs to learn
/// that the schema — not the image — was the problem. With it, the pipeline
/// runs ONE Job to completion first. It either succeeds, and the rollout
/// proceeds against a schema known to be current, or it fails and promotion
/// stops with the migration error as the visible cause.
///
/// ONLY the exact string "1" enables it. Unset, empty, "true", "yes" and every
/// typo mean SERVE. The asymmetry is deliberate and the failure modes are not
/// symmetric: a missed enable costs one redundant migration pass, while an
/// accidental enable would turn a production rollout into a fleet of pods that
/// exit 0 before binding a port — a "successful" deploy that serves nothing.
fn migrate_only(raw: Option<&str>) -> bool {
    matches!(raw.map(str::trim), Some("1"))
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // A boot failure is one of the most important things this process ever has
    // to say, and until this wrapper existed it was the ONE thing that never
    // became a record: `main` returning `Err` makes the runtime print
    // `Error: …` to stderr as bare text. In a JSON deployment that line is the
    // only unparsable one in the file, it carries no `instance`, and it is
    // invisible to every query an operator would run to find out why a replica
    // never came up. So `run()` holds the real body and this logs its failure
    // through the same path as everything else — then still returns `Err`, so
    // the exit status and the human-readable line are unchanged.
    let r = run().await;
    if let Err(e) = &r {
        tracing::error!(
            error = %e,
            error_kind = fluidbox_obs::field::error_kind::INTERNAL,
            "BOOT FAILED — the control plane did not start"
        );
    }
    r
}

async fn run() -> anyhow::Result<()> {
    let _ = dotenvy::dotenv();
    // kube-rs (rustls 0.23) needs a process-level CryptoProvider; the workspace
    // has multiple rustls backends in-tree, so pick ring explicitly or the
    // Kubernetes client panics on first TLS use. No-op for the Docker path.
    let _ = rustls::crypto::ring::default_provider().install_default();
    // Logging is the FIRST thing built, before configuration is even read: a
    // config error is one of the things most worth logging, and until this line
    // runs every diagnostic is lost. `LogConfig` reads its own environment
    // (RUST_LOG stays authoritative when set) and refuses boot on a malformed
    // value, like every other configuration surface here.
    let log_cfg =
        fluidbox_obs::LogConfig::from_env(SERVICE_NAME).map_err(|e| anyhow::anyhow!(e))?;
    let log = fluidbox_obs::init(&log_cfg).map_err(|e| anyhow::anyhow!(e))?;
    // The logging subsystem's own settings, in the log it governs. An operator
    // debugging "why can I not see X" should not have to reconstruct the
    // effective configuration from a deployment manifest.
    // `instance` and `version` are deliberately absent: the ENVELOPE already
    // carries both on this and every other record, and repeating them here only
    // produced `instance_`/`version_` (the collision rename) plus noise.
    tracing::info!(
        format = log_cfg.format.as_str(),
        filter = %log_cfg.filter,
        throttle_per_sec = log_cfg.throttle_per_sec,
        max_field_bytes = log_cfg.limits.max_field_bytes,
        max_line_bytes = log_cfg.limits.max_line_bytes,
        "logging initialised (values are redacted by shape and by field name; \
         there is no switch to disable that)"
    );
    workers::spawn_log_throttle_reporter(log.clone());

    let cfg = config::Config::from_env()?;
    std::fs::create_dir_all(&cfg.data_dir).ok();

    tracing::info!("connecting to the database");
    // Phase F: the pool is SIZED, not defaulted. The deployment-wide connection
    // count is `replicas × (max_connections + 2)` — the +2 being the two
    // `PgListener` connections below, which live outside the pool — and it is that
    // figure, not this one, that has to fit the Postgres/Neon compute's own ceiling.
    let pool =
        fluidbox_db::connect_with(&cfg.database_url, cfg.runtime_role.as_deref(), cfg.db_pool)
            .await?;
    {
        let p = cfg.db_pool;
        tracing::info!(
            pool_max = p.max_connections,
            pool_min = p.min_connections,
            acquire_timeout_secs = p.acquire_timeout_secs,
            idle_timeout_secs = p.idle_timeout_secs,
            max_lifetime_secs = p.max_lifetime_secs,
            "database pool sized — the DEPLOYMENT total is replicas × (pool_max + 2 listeners), \
             and it is that figure, not this one, that has to fit the database's own ceiling"
        );
    }
    if let Some(role) = &cfg.runtime_role {
        tracing::info!(
            runtime_role = %role,
            rls = "role_split",
            "app pool runs under a non-owner role (posture verified: NOLOGIN, no \
             SUPERUSER/BYPASSRLS, no inherited or foreign memberships)"
        );
    }
    // Review M2: RLS is defence-in-depth ONLY if PostgreSQL actually evaluates the
    // policies. It skips them entirely for a SUPERUSER/BYPASSRLS role — which is
    // exactly what Neon's default credential is — so migration 0018 can be applied,
    // FORCEd, and completely inert. Read the EFFECTIVE role of a pooled connection
    // (after any `after_connect SET ROLE`), and in multi-user mode make it fatal:
    // an unnoticed missing `tenant_id` predicate must be contained, not served.
    match fluidbox_db::pool_role_bypasses_rls(&pool).await? {
        None => tracing::info!(
            rls = "enforced",
            "row-level security is ENFORCED for this pool (its role has neither SUPERUSER nor \
             BYPASSRLS)"
        ),
        Some(user) if cfg.require_sso && !cfg.allow_rls_bypass => anyhow::bail!(
            "REFUSING TO BOOT: FLUIDBOX_REQUIRE_SSO=1 (multi-user) but the database role this pool \
             runs as ('{user}') is SUPERUSER or has BYPASSRLS, so PostgreSQL SKIPS every \
             row-level-security policy from migration 0018 and tenant isolation falls back to the \
             `where tenant_id = $n` convention alone. Fix (either one):\n  \
             1. set FLUIDBOX_RUNTIME_ROLE=fluidbox_runtime — migration 0018 creates that NOLOGIN \
             least-privilege role and every pooled connection SET ROLEs to it; or\n  \
             2. point DATABASE_URL at a role that is neither SUPERUSER nor BYPASSRLS.\n  \
             Verify with: select rolsuper, rolbypassrls from pg_roles where rolname = current_user;\n  \
             For local single-user operation on a superuser database, set \
             FLUIDBOX_ALLOW_RLS_BYPASS=1 to accept this."
        ),
        Some(user) if cfg.require_sso => tracing::warn!(
            db_role = %user,
            rls = "bypassed_opt_in",
            "FLUIDBOX_ALLOW_RLS_BYPASS=1: this pool role bypasses RLS, so migration 0018's \
             policies are INERT and tenant isolation rests on the query predicates alone — \
             acceptable for local single-user operation only"
        ),
        Some(user) => tracing::warn!(
            db_role = %user,
            rls = "skipped",
            "this pool role is SUPERUSER or has BYPASSRLS, so migration 0018's RLS policies are \
             skipped by PostgreSQL (single-user mode, tolerated). Set FLUIDBOX_RUNTIME_ROLE \
             before enabling FLUIDBOX_REQUIRE_SSO=1, or boot will refuse"
        ),
    }

    // Migration-only mode. `connect_with` above has already applied every
    // migration and the block above has verified the RLS posture, so a deploy
    // pipeline's pre-upgrade Job has learned everything it needs. Return HERE,
    // before seeding, to keep the Job's contract narrow: schema and posture
    // only, no application writes.
    if migrate_only(std::env::var("FLUIDBOX_MIGRATE_ONLY").ok().as_deref()) {
        tracing::info!(
            "FLUIDBOX_MIGRATE_ONLY=1: migrations applied and RLS posture verified — exiting 0 without serving"
        );
        return Ok(());
    }

    tracing::info!("seeding the default tenant, agent and policies");
    // The curated seed agent rides the harness registry like any other
    // agent — the harness id and its defaults have exactly one home.
    let seed = fluidbox_db::seed::run(
        &pool,
        std::path::Path::new("policies"),
        harness::CLAUDE_AGENT_SDK,
        harness::default_runner_image(harness::CLAUDE_AGENT_SDK, &cfg)
            .expect("claude-agent-sdk is a known harness"),
        harness::default_model(harness::CLAUDE_AGENT_SDK, &cfg)
            .expect("claude-agent-sdk is a known harness"),
    )
    .await?;

    let mut cfg = cfg;
    // Kubernetes zeroEgress: the runner reaches the control plane by the
    // internal Service's ClusterIP (no DNS). Resolve it at boot and override
    // the control URL, unless one was set explicitly.
    let is_k8s = matches!(cfg.provider.as_str(), "kubernetes" | "k8s");
    if is_k8s && std::env::var("FLUIDBOX_PUBLIC_CONTROL_URL").is_err() {
        if let (Some(svc), Some(ns)) = (&cfg.internal_service, &cfg.internal_service_namespace) {
            match fluidbox_provider_k8s::netpol::resolve_service_clusterip(ns, svc).await {
                Ok(Some(ip)) => {
                    // Port derives from the internal bind (never hardcoded);
                    // IPv6 ClusterIPs need brackets in a URL authority.
                    let port = cfg
                        .internal_bind
                        .rsplit(':')
                        .next()
                        .unwrap_or("8788")
                        .to_string();
                    let host = if ip.contains(':') {
                        format!("[{ip}]")
                    } else {
                        ip
                    };
                    cfg.public_control_url = format!("http://{host}:{port}");
                    tracing::info!(control_url = %cfg.public_control_url, "resolved the internal control URL");
                }
                _ => tracing::warn!(
                    service = %svc,
                    "could not resolve the internal Service ClusterIP; the runner control URL may \
                     need DNS"
                ),
            }
        }
    }

    let provider = build_provider(&cfg).await?;
    if let Err(e) = provider.healthcheck().await {
        tracing::warn!(
            provider = %provider.runtime_name(),
            error = %e,
            error_kind = fluidbox_obs::field::error_kind::PROVIDER,
            "provider health probe failed; sandboxes will not launch until it is reachable"
        );
    } else {
        tracing::info!(provider = %provider.runtime_name(), "execution provider selected");
    }

    // Run admission. Saying this at boot matters for the SAME reason the
    // enforcer line below does, and for one more: the rollout discipline is
    // migrate → roll every replica → enable (design 2026-08-23 §6), and an
    // operator mid-roll needs a way to see which replicas have picked the
    // feature up. Silence means the queue is off and runs spawn directly —
    // byte-identical to before the feature existed.
    match &cfg.queue {
        Some(q) => tracing::info!(
            queueing = true,
            max_concurrent_runs = q.max_concurrent_runs,
            max_depth = q.max_depth,
            max_wait_secs = q.max_wait_secs,
            requeue_max = q.requeue_max,
            "run admission ENABLED. On Kubernetes keep max_concurrent_runs at or below the \
             namespace quota's `pods` tier so the quota stays a backstop"
        ),
        None => tracing::info!(
            queueing = false,
            "run admission off (FLUIDBOX_MAX_CONCURRENT_RUNS unset) — runs launch on creation"
        ),
    }

    // Sandbox network grants. Saying this at boot matters: with no enforcer the
    // deployment is offline-only and every non-offline run is REFUSED, which an
    // operator should learn here rather than from a 422 on their first run.
    // Report the RESOLVED enforcer, which is what actually governs: `auto` has
    // been decided by detection at connect time, and the provider is the thing
    // that knows the answer.
    let enforcer = provider.network_enforcer();
    if enforcer.supports_egress_grants() {
        tracing::info!(
            enforcer = %enforcer.enforcer_name(),
            requested = %cfg.network_enforcer.as_str(),
            "sandbox network grants: enforcer resolved"
        );
    } else {
        tracing::info!(
            enforcer = "none",
            requested = %cfg.network_enforcer.as_str(),
            "sandbox network grants: NO enforcer resolved — runs are offline-only and any wider \
             grant is refused at create time"
        );
    }

    let events_tx = fluidbox_db::spawn_listener(cfg.database_url.clone());
    // Phase E (#33; Gap 13): the second listener. Approval decisions announce
    // themselves on their own channel so EVERY replica's blocked `/permission`
    // waiters wake, not just the one that served the decision request.
    let approvals_tx = fluidbox_db::spawn_approval_listener(cfg.database_url.clone());

    // Phase D (#32): the sealer is legacy-only (KMS off), KMS-envelope (static|aws),
    // or None (KMS off + no legacy key → sealing disabled, today's behavior). The
    // boot/seed tenant keys transit tokens in KMS mode (see Sealer::seal_token).
    let sealer = seal::build_sealer(&cfg, &pool, seed.tenant_id)?;
    // D4 retirement gates: refuse boot when the sealing configuration and the
    // stored custody are incoherent (KMS on with the legacy key retired but v1
    // rows remain unreadable; KMS off with KMS-only v2 rows present).
    // In KMS mode this also CLAIMS the deployment's KEK identity (the seed tenant's
    // DEK row, arbitrated by the database) before we serve, so a second replica
    // holding a different KEK refuses boot instead of quietly taking custody of half
    // the tenants. The sealer is passed in so all of it runs on the LIVE backend +
    // DEK cache: the unwrap the gate performs anyway warms the DEK every transit
    // token uses (singleflight already caps this at one Decrypt per restart).
    seal::check_retirement_gates(&cfg, &pool, sealer.as_ref(), seed.tenant_id).await?;
    match (&sealer, cfg.kms_mode) {
        (None, _) => tracing::warn!(
            sealing = "disabled",
            "credential sealing disabled (no FLUIDBOX_CREDENTIAL_KEY, KMS off) — integration \
             connections are disabled"
        ),
        (Some(_), config::KmsMode::Off) => {
            tracing::info!(
                sealing = "legacy_key",
                "credential sealing: legacy key (FLUIDBOX_KMS_MODE=off)"
            )
        }
        (Some(_), mode) => {
            tracing::info!(sealing = "kms_envelope", kms_mode = ?mode, "credential sealing: KMS envelope")
        }
    }
    // Phase D (#32) LLM upstream-auth mode. In tenant mode the facade selects a
    // per-tenant LiteLLM virtual key and the master key is confined to
    // provisioning; shared mode presents the deployment key on every call.
    match cfg.llm_key_mode {
        config::LlmKeyMode::Shared => tracing::info!(
            llm_key_mode = "shared",
            "LLM upstream auth: one shared deployment key"
        ),
        config::LlmKeyMode::Tenant => tracing::info!(
            llm_key_mode = "tenant",
            admin_url = %fluidbox_obs::url_for_log(&cfg.llm_admin_url),
            "LLM upstream auth: per-tenant virtual keys; the master key is confined to provisioning"
        ),
    }
    if cfg.require_sso && cfg.llm_key_mode == config::LlmKeyMode::Shared {
        tracing::warn!(
            llm_key_mode = "shared",
            require_sso = true,
            "FLUIDBOX_REQUIRE_SSO=1 with FLUIDBOX_LLM_KEY_MODE=shared — the facade will refuse \
             EVERY model request (tenant_llm_keys_required); set FLUIDBOX_LLM_KEY_MODE=tenant for \
             hosted deployments"
        );
    }

    // Phase E shared egress boundary: ONE policy (dev-loopback seam + operator
    // allowlist + proxy) drives BOTH hardened clients and is stored on AppState
    // for the broker/deliveries pre-dial admission and the git-clone derivation.
    let egress_policy = egress::EgressPolicy::from_config(&cfg);
    let identity_http = egress::build_identity_http(&egress_policy);
    let egress_http = egress::build_egress_http(&egress_policy);
    // Phase E (E14) + Phase F (0023): the outbound rate limits + per-connection
    // circuit breakers the broker consults before every dial. Two tiers — a
    // per-replica in-memory tier checked first, then (default on) a durable
    // Postgres tier giving the deployment-wide ceiling. See the `governor` docs.
    let governor = governor::EgressGovernor::from_config(&cfg);
    {
        let l = governor.limits();
        tracing::info!(
            tenant_per_min = l.tenant_per_min,
            connection_per_min = l.connection_per_min,
            host_per_min = l.host_per_min,
            breaker_threshold = l.breaker_threshold,
            breaker_open_secs = l.breaker_open_secs,
            durable_tier = cfg.egress_durable,
            "outbound egress governor configured (0 disables a dimension; host_global stays \
             per-replica even with the durable tier on)"
        );
    }

    let state: state::AppState = Arc::new(AppStateInner {
        netgrant_reverify_failures: Default::default(),
        tenant_id: seed.tenant_id,
        redactor: fluidbox_core::event::Redactor::default(),
        provider,
        approvals: ApprovalRegistry::default(),
        events_tx,
        approvals_tx,
        // Plain client for operator-configured seams (GitHub, LLM) only.
        http: reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(
                config::UPSTREAM_HTTP_TIMEOUT_SECS,
            ))
            .build()?,
        identity_http,
        egress_http,
        egress_policy,
        governor,
        sealer,
        connector_tokens: Default::default(),
        oauth_locks: Default::default(),
        mcp_sessions: Default::default(),
        // Gap 12: compiled frozen-schema validators, cap 256 (Default).
        schema_cache: Default::default(),
        tenant_llm_keys: Default::default(),
        // Docker needs no netpol gate; Kubernetes starts unverified and the
        // worker below flips it once the CNI is proven to enforce policy.
        netpol_verified: std::sync::atomic::AtomicBool::new(!is_k8s),
        // Filled by the gate worker before its first probe; the orchestrator
        // freezes these into every sandbox's per-pod admission gate.
        netpol_targets: std::sync::RwLock::new(None),
        oidc: Default::default(),
        // Phase D (#32) legacy→KMS re-seal: the singleton claim flag + live
        // progress, both in-memory (the job is restart-safe by construction).
        reseal_running: std::sync::atomic::AtomicBool::new(false),
        reseal_status: tokio::sync::Mutex::new(reseal::ResealStatus::default()),
        metrics: metrics::Metrics::default(),
        pool,
        cfg,
    });

    // Boot-time housekeeping + background workers.
    workers::boot_orphan_sweep(state.clone()).await;
    workers::spawn_all(state.clone());
    if is_k8s {
        workers::spawn_netpol_gate(state.clone());
    }
    deliveries::spawn_worker(state.clone());
    scheduler::spawn_worker(state.clone());

    let public = Router::new()
        .route("/health", get(api::health))
        .route("/health/ready", get(api::health_ready))
        .route("/agents", get(api::list_agents).post(api::create_agent))
        .route("/agents/{id}", get(api::get_agent))
        .route("/agents/{id}/revisions", post(api::add_revision))
        .route(
            "/policies",
            get(api::list_policies).post(api::upsert_policy),
        )
        .route("/policies/validate", post(api::validate_policy))
        .route("/policies/preview", post(api::preview_policy))
        .route("/policies/clone", post(api::clone_policy))
        .route(
            "/policies/{name}",
            get(api::get_policy).delete(api::delete_policy),
        )
        .route("/policies/{name}/publish", post(api::publish_policy))
        .route("/policies/{name}/revert", post(api::revert_policy))
        .route(
            "/policies/{name}/versions/{version}",
            get(api::get_policy_version),
        )
        .route("/recipes", get(recipes::list).post(recipes::create_custom))
        .route("/recipes/instances", get(recipes::list_instances))
        .route(
            "/recipes/instances/{id}",
            get(recipes::get_instance).delete(recipes::delete_instance),
        )
        .route(
            "/recipes/instances/{id}/pause",
            post(recipes::pause_instance),
        )
        .route(
            "/recipes/instances/{id}/resume",
            post(recipes::resume_instance),
        )
        .route("/recipes/instances/{id}/run", post(recipes::run_instance))
        .route(
            "/recipes/instances/{id}/upgrade",
            post(recipes::upgrade_instance),
        )
        .route("/recipes/{slug}", get(recipes::get))
        .route("/recipes/{slug}/versions", post(recipes::append_version))
        .route("/recipes/{slug}/deploy", post(recipes::deploy))
        .route(
            "/sessions",
            get(api::list_sessions).post(api::create_session),
        )
        .route("/sessions/{id}", get(api::get_session))
        .route("/sessions/{id}/cancel", post(api::cancel_session))
        .route("/sessions/{id}/events", get(api::get_events))
        .route("/sessions/{id}/events/stream", get(sse::stream))
        .route("/sessions/{id}/approvals", get(api::session_approvals))
        .route("/sessions/{id}/artifacts", get(api::list_artifacts))
        .route("/sessions/{id}/artifacts/{aid}", get(api::get_artifact))
        .route("/sessions/{id}/cost", get(api::get_cost))
        .route("/sessions/{id}/deliveries", get(api::session_deliveries))
        .route("/approvals", get(api::approvals_inbox))
        .route("/approvals/{id}/decision", post(api::decide_approval))
        // Personal access tokens (identity Phase B): machine access without a
        // browser flow. Mint/revoke require a browser session (a PAT can never
        // mint a PAT); listing accepts either context.
        .route("/auth/tokens", get(tokens::list).post(tokens::mint))
        .route("/auth/tokens/{id}", delete(tokens::revoke))
        // The IdP-agnostic OIDC login surface (Phase B, Task 5). The neutral
        // entry page, per-org start, and the one stable callback are
        // unauthenticated by design — the sealed `state` + per-flow cookie ARE
        // the auth (same pattern as oauth/callback + github/app legs). switch
        // and logout authenticate by the browser session cookie (CSRF applies).
        .route("/auth/login", get(login::login_page))
        .route("/auth/login/{slug}/start", get(login::start))
        .route("/auth/callback", get(login::callback))
        .route("/auth/switch/{id}", post(login::switch_confirm))
        .route("/auth/logout", post(login::logout))
        .route("/auth/me", get(login::me))
        // Operator break-glass + IdP lifecycle (Phase B, Task 6). Every route is
        // Admin-token gated — this is exactly the surface the operator retains
        // under FLUIDBOX_REQUIRE_SSO=1 (the `Admin` extractor stays valid there
        // while `Principal` refuses the admin token). Each accepted mutation
        // audits inside its transaction; rejected attempts audit separately.
        .route(
            "/admin/orgs",
            get(admin_orgs::list_orgs).post(admin_orgs::create_org),
        )
        .route(
            "/admin/orgs/{slug}/idp",
            get(admin_orgs::list_idp).post(admin_orgs::create_idp),
        )
        .route("/admin/orgs/{slug}/idp/{id}", patch(admin_orgs::patch_idp))
        .route(
            "/admin/orgs/{slug}/idp/{id}/activate",
            post(admin_orgs::activate_idp),
        )
        .route(
            "/admin/orgs/{slug}/idp/{id}/disable",
            post(admin_orgs::disable_idp),
        )
        .route(
            "/admin/orgs/{slug}/idp/{id}/reactivate",
            post(admin_orgs::reactivate_idp),
        )
        .route(
            "/admin/orgs/{slug}/idp/{id}/migrate",
            post(admin_orgs::migrate_idp),
        )
        .route(
            "/admin/orgs/{slug}/break-glass-owner",
            post(admin_orgs::break_glass_owner),
        )
        .route("/admin/orgs/{slug}/members", get(admin_orgs::list_members))
        .route(
            "/admin/orgs/{slug}/members/{membership_id}/deactivate",
            post(admin_orgs::deactivate_member),
        )
        .route(
            "/admin/orgs/{slug}/members/{membership_id}/roles",
            post(admin_orgs::set_member_roles),
        )
        // Rotate a tenant's LiteLLM virtual key (Phase D, #32): mint a fresh key,
        // swap the sealed row, retire the old at LiteLLM. Operator-only; 404 on an
        // unknown org; never returns the key.
        .route(
            "/admin/orgs/{slug}/llm-key/rotate",
            post(admin_orgs::rotate_llm_key),
        )
        // Legacy→KMS re-seal (Phase D, #32): operator-only. POST starts the
        // background job (409 if already running / KMS off); GET reports live
        // count parity + job progress. The D4 retirement boot gate
        // (seal::check_retirement_gates) reads the same counts.
        .route("/admin/reseal", get(reseal::status).post(reseal::start))
        // Operational metrics (Phase F, #34): admin-gated Prometheus exposition.
        // The optional unauth `FLUIDBOX_METRICS_BIND` listener (below) serves the
        // identical body on its own private port.
        .route("/admin/metrics", get(metrics::admin_metrics))
        .route(
            "/capabilities",
            get(capabilities::list).post(capabilities::create),
        )
        .route("/capabilities/{id}", get(capabilities::get))
        .route(
            "/connections",
            get(connections::list).post(connections::create),
        )
        .route("/connections/{id}/revoke", post(connections::revoke))
        .route("/connections/{id}/approve", post(connections::approve))
        .route("/connections/{id}/repos", get(connections::repos))
        // Connection tool snapshots (Phase C): re-photograph on demand, and read
        // the latest photographed tool surface.
        .route("/connections/{id}/tools", get(snapshots::get_tools))
        .route(
            "/connections/{id}/tools/refresh",
            post(snapshots::refresh_tools),
        )
        .route("/connections/{id}/oauth/start", post(oauth::start))
        // Seamless GitHub connect (Phase 5.6): admin start endpoints mint
        // one-time flows; the go/callback/setup legs are browser-facing
        // (sealed tokens + per-flow cookies ARE the auth); app-level
        // ingress authenticates by webhook HMAC like per-connection
        // ingress. 4-segment ingress path cannot collide with the
        // 3-segment {provider}/{connection_id} route below.
        .route("/github/app", get(github_app::list))
        .route(
            "/github/app/manifest/start",
            post(github_app::manifest_start),
        )
        .route("/github/app/manifest/go", get(github_app::manifest_go))
        .route(
            "/github/app/manifest/callback",
            get(github_app::manifest_callback),
        )
        .route("/github/app/install/go", get(github_app::install_go))
        .route(
            "/github/app/{id}/install/start",
            post(github_app::install_start),
        )
        .route("/github/app/{id}/setup", get(github_app::setup))
        .route("/github/app/{id}/sync", post(github_app::sync))
        .route("/github/app/{id}/revoke", post(github_app::revoke))
        .route(
            "/ingress/github/app/{registration_id}",
            post(github_app::app_ingress),
        )
        // Unauthenticated by design: a browser redirect can't carry the
        // admin token. The go leg's sealed boot token and the callback's
        // one-time flow claim (with the initiating-browser cookie hash inside
        // the predicate) ARE the auth (invariant 20; same pattern as the
        // github/app go/callback legs and webhook-signature ingress).
        .route("/oauth/go", get(oauth::go))
        .route("/oauth/callback", get(oauth::callback))
        .route("/catalog", get(catalog::list).post(catalog::create))
        .route("/catalog/{slug}", get(catalog::get))
        .route("/catalog/{slug}/connect", post(catalog::connect))
        // Bring-your-own MCP: a non-committing probe (paste a URL → detect
        // auth + preview tools) and a one-shot connect (custom catalog entry
        // + connect in one call). Both ride the existing catalog seams.
        .route("/mcp/probe", post(catalog::probe))
        .route("/mcp/servers", post(catalog::add_custom))
        // The supported harness + model catalog (single source of truth for
        // the dashboard pickers).
        .route("/harnesses", get(api::list_harnesses))
        .route(
            "/connections/{id}/deliveries",
            get(events::connection_deliveries),
        )
        // Unauthenticated by design: the webhook signature (verified against
        // the connection's sealed secret) is the authentication.
        .route("/ingress/{provider}/{connection_id}", post(events::ingress))
        .route("/triggers", get(triggers::list).post(triggers::create))
        .route("/triggers/{id}", get(triggers::get).patch(triggers::update))
        .route("/triggers/{id}/enable", post(triggers::enable))
        .route("/triggers/{id}/disable", post(triggers::disable))
        .route("/triggers/{id}/rotate_token", post(triggers::rotate_token))
        .route("/triggers/{id}/invoke", post(triggers::invoke))
        .route("/triggers/{id}/run-now", post(triggers::run_now))
        .route("/triggers/{id}/runs/{sid}", get(triggers::poll_run));

    // The internal plane (runner contract, workspace archive, LLM facade).
    // internal::permission etc. extract SessionAuth themselves; the path {id}
    // is informational (the token binds the session).
    let internal = Router::new()
        .route("/sessions/{id}/permission", post(internal::permission))
        // Brokered tools (design §8.3 class 2): intent in, governed result
        // out; the sealed credential turns server-side.
        .route("/sessions/{id}/tools/call", post(internal::tool_call))
        .route("/sessions/{id}/events", post(internal::events))
        .route("/sessions/{id}/heartbeat", post(internal::heartbeat))
        .route("/sessions/{id}/result", post(internal::result))
        // The immutable workspace archive the Kubernetes init container pulls
        // (session from the bearer token; credential-free, digest-verified).
        .route("/sessions/{id}/workspace", get(internal::workspace_archive))
        .route("/token/renew", post(internal::token_renew))
        .route("/llm-usage", post(callback::litellm_usage))
        // The Agent SDK appends /v1/messages (and possibly count_tokens) to
        // ANTHROPIC_BASE_URL=<control>/internal/llm.
        .route("/llm/{*rest}", post(facade::messages));

    // One canonical record per request, on both planes (`request_log`). This
    // replaces a `TraceLayer` whose `debug_span!` was disabled at the default
    // filter — so it attached no fields to anything — and which emitted no
    // completion record at all: there was no access log, no latency signal, and
    // no way to attribute a slow endpoint. `plane` is baked in per listener
    // because the two have different trust models and different expected
    // traffic, and one filter should separate them.
    let request_log = |plane: &'static str| {
        axum::middleware::from_fn(move |req, next| request_log::layer(plane, req, next))
    };

    // Public listener (:8787) — /v1 + oauth + well-known. /internal rides it
    // ONLY on the single-host Docker path (bearer auth separates the planes
    // there). On Kubernetes the sandbox plane is exclusively the :8788
    // listener: route absence is stronger than bearer auth, and a chart
    // Ingress routing '/' must never expose /internal to the internet (M8).
    let mut public_root = Router::new().nest("/v1", public);
    if !is_k8s {
        public_root = public_root.nest("/internal", internal.clone());
    }
    let public_app = bounded(
        public_root
            // CIMD (spec 2025-11-25): this document's URL IS our OAuth
            // client_id; authorization servers fetch it — public by nature.
            .route("/.well-known/fluidbox-client.json", get(oauth::cimd_doc))
            .layer(request_log(fluidbox_obs::field::plane::PUBLIC))
            // NO CORS layer (Phase B): the dashboard is a same-origin proxy
            // (`/` → web, `/v1` → API, one origin), so cross-origin requests to
            // `/v1` are never legitimate and no `Access-Control-*` grant should
            // exist. The permissive layer removed here (design lines 649-653) was a
            // cookie-auth CSRF footgun; browser writes now carry the
            // `x-fluidbox-csrf` header + an Origin check instead.
            .with_state(state.clone()),
        state.cfg.max_request_body_bytes,
    );

    // Internal listener (:8788) — /internal ONLY, no /v1 route exists. This is
    // the sandbox-facing plane on Kubernetes (the internal Service targets it);
    // route absence means a sandbox cannot reach /v1 at the TCP level.
    let internal_app = bounded(
        Router::new()
            .nest("/internal", internal)
            .layer(request_log(fluidbox_obs::field::plane::INTERNAL))
            .with_state(state.clone()),
        state.cfg.max_request_body_bytes,
    );

    let public_listener = tokio::net::TcpListener::bind(&state.cfg.bind).await?;
    let internal_listener = tokio::net::TcpListener::bind(&state.cfg.internal_bind).await?;

    // Optional UNAUTHENTICATED metrics listener (Phase F, #34). Bound at boot so a
    // bad address fails boot (the established convention), then served on a
    // background task: a metrics-endpoint fault must not take the control plane
    // down, unlike the two planes above whose failure is fatal by design.
    if let Some(metrics_addr) = state.cfg.metrics_bind.clone() {
        let metrics_listener = tokio::net::TcpListener::bind(&metrics_addr).await?;
        let metrics_app = Router::new()
            .route("/metrics", get(metrics::metrics_endpoint))
            .layer(request_log(fluidbox_obs::field::plane::METRICS))
            .with_state(state.clone());
        tracing::warn!(
            bind = %metrics_addr,
            plane = fluidbox_obs::field::plane::METRICS,
            "metrics listener bound UNAUTHENTICATED — FLUIDBOX_METRICS_BIND must reach a private \
             interface only"
        );
        tokio::spawn(async move {
            if let Err(e) = axum::serve(metrics_listener, metrics_app).await {
                tracing::error!(error = %e, plane = fluidbox_obs::field::plane::METRICS, "metrics listener exited");
            }
        });
    }

    tracing::info!(
        bind = %state.cfg.bind,
        plane = fluidbox_obs::field::plane::PUBLIC,
        "listening"
    );
    tracing::info!(
        bind = %state.cfg.internal_bind,
        plane = fluidbox_obs::field::plane::INTERNAL,
        "listening (/internal only)"
    );
    // Gap 6 (Phase F): say which mode is live at boot. A security control whose
    // state can only be learned by reading the deployment's env is a control
    // nobody knows the state of; `off` is the default and is announced as loudly
    // as the other two, so "we turned that on months ago" is checkable.
    tracing::info!(
        workload_identity = %state.cfg.workload_identity.as_str(),
        "workload identity mode on the internal gateway (a security control whose state is \
         otherwise only learnable by reading the deployment's environment)"
    );
    tracing::info!(agent = %seed.default_agent, "default agent seeded");

    // Serve both planes; if either listener falls over, the process exits.
    // `ConnectInfo::<SocketAddr>` is wired on BOTH planes so handlers extract the
    // socket peer uniformly (the internal plane never reads it, but the make
    // service is uniform and harmless) — the public login/audit path relies on it
    // as the authoritative client IP unless a trusted proxy is declared.
    tokio::select! {
        r = axum::serve(
            public_listener,
            public_app.into_make_service_with_connect_info::<SocketAddr>(),
        ) => r?,
        r = axum::serve(
            internal_listener,
            internal_app.into_make_service_with_connect_info::<SocketAddr>(),
        ) => r?,
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Serve ONE body-consuming route on an ephemeral loopback port and report the
    /// status code a `body_len`-byte POST gets back. `limit = None` skips
    /// [`bounded`] entirely, which is what makes the assertions below meaningful:
    /// axum's own implicit 2 MiB default is still in force on that arm, so a test
    /// that only checked "big body ⇒ 413" would pass with the layer deleted.
    async fn post_status(limit: Option<usize>, body_len: usize) -> u16 {
        let app = Router::new().route(
            "/echo",
            post(|body: axum::body::Bytes| async move { body.len().to_string() }),
        );
        let app = match limit {
            Some(n) => bounded(app, n),
            None => app,
        };
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move { axum::serve(listener, app).await });
        let status = reqwest::Client::new()
            .post(format!("http://{addr}/echo"))
            .body(vec![b'x'; body_len])
            .send()
            .await
            .expect("the loopback request completes")
            .status()
            .as_u16();
        server.abort();
        status
    }

    /// The explicit limit must be the one that BINDS, in both directions — the only
    /// way to tell a real layer from a decorative one, because axum silently
    /// enforces 2 MiB on `Bytes`/`Json` whether or not we ask.
    #[tokio::test]
    async fn the_explicit_body_limit_is_the_one_that_binds() {
        // Downward: 8 KiB is comfortably under axum's implicit default, so a 413
        // here can ONLY have come from our layer.
        assert_eq!(post_status(Some(4 * 1024), 8 * 1024).await, 413);
        assert_eq!(post_status(None, 8 * 1024).await, 200);
        // Upward: 3 MiB is over axum's implicit default, so a 200 here can ONLY
        // have come from our layer raising it.
        assert_eq!(
            post_status(Some(4 * 1024 * 1024), 3 * 1024 * 1024).await,
            200
        );
        assert_eq!(post_status(None, 3 * 1024 * 1024).await, 413);
        // …and the SHIPPED default is exactly axum's, so making the limit explicit
        // is a no-op on an existing install rather than a quiet re-tuning.
        let d = config::DEFAULT_MAX_REQUEST_BODY_BYTES;
        assert_eq!(post_status(Some(d), d + 1).await, 413);
        assert_eq!(post_status(None, d + 1).await, 413);
        assert_eq!(post_status(Some(d), d).await, 200);
        assert_eq!(post_status(None, d).await, 200);
    }

    /// A layer that exists but is not wired to a listener bounds nothing. The
    /// `include_str!` guards elsewhere in this crate exist for exactly this shape
    /// of defect — a correct helper nobody calls — and no unit test on `bounded`
    /// itself can catch it.
    /// This file's PRODUCTION half. The source guards below count occurrences, and
    /// a test module that quotes the very strings it is counting would count itself
    /// (it did, on the first run) — so the test half is cut off first.
    fn production_src() -> &'static str {
        let src = include_str!("main.rs");
        let end = src
            .find("#[cfg(test)]\nmod tests {")
            .expect("this file has a test module");
        &src[..end]
    }

    #[test]
    fn both_listeners_are_wired_through_the_bound_helper() {
        let src = production_src();
        assert!(
            src.contains("let public_app = bounded("),
            "the public listener must carry the request bounds"
        );
        assert!(
            src.contains("let internal_app = bounded("),
            "the internal listener must carry the request bounds"
        );
        // Both must take the CONFIGURED value, not a literal: a hardcoded bound
        // here would look identical in review and ignore the env var entirely.
        assert_eq!(
            src.matches("state.cfg.max_request_body_bytes,").count(),
            2,
            "each listener passes the configured limit through"
        );
    }

    /// The metrics surface must stay wired: the admin-gated route on the public
    /// plane, and the optional unauth listener guarded by the config knob. A
    /// dropped route or a listener that ignored `metrics_bind` would look identical
    /// in review, and no handler unit test sees the wiring.
    #[test]
    fn the_metrics_endpoint_and_optional_listener_are_wired() {
        let src = production_src();
        assert!(
            src.contains("get(metrics::admin_metrics)"),
            "the admin-gated metrics route must be wired on the public plane"
        );
        assert!(
            src.contains("if let Some(metrics_addr) = state.cfg.metrics_bind.clone()"),
            "the optional metrics listener must be gated on the configured bind"
        );
        assert!(
            src.contains("get(metrics::metrics_endpoint)"),
            "the optional listener must serve the unauth metrics handler"
        );
        assert!(
            src.contains(".layer(request_log(fluidbox_obs::field::plane::METRICS))"),
            "the optional metrics listener must emit correlated request completions"
        );
    }

    /// Only "1" may enable migrate-only mode.
    ///
    /// The asymmetry is the point: a missed enable costs a redundant migration
    /// pass, an accidental one produces pods that exit 0 without ever binding a
    /// port — which reads as a successful deploy that serves nothing.
    #[test]
    fn migrate_only_accepts_exactly_one() {
        assert!(super::migrate_only(Some("1")));
        assert!(
            super::migrate_only(Some(" 1 ")),
            "surrounding whitespace is trimmed"
        );

        for serve in [
            None,
            Some(""),
            Some("0"),
            Some("true"),
            Some("yes"),
            Some("11"),
            Some("1 1"),
        ] {
            assert!(
                !super::migrate_only(serve),
                "{serve:?} must mean SERVE, not exit-without-serving"
            );
        }
    }

    /// Migrate-only must return BEFORE seeding and before anything binds a
    /// listener, and AFTER the RLS posture check — a Job that skipped the
    /// posture gate would report a healthy schema on a database where tenant
    /// isolation is inert.
    #[test]
    fn migrate_only_returns_after_the_rls_gate_and_before_seeding() {
        let src = production_src();
        let gate = src
            .find("row-level security is ENFORCED")
            .expect("RLS posture check");
        // Anchor on the env READ, not the bare name: "FLUIDBOX_MIGRATE_ONLY"
        // also appears in the helper's doc comment far earlier in the file, and
        // matching that made this assertion compare the wrong two positions.
        let early = src
            .find("std::env::var(\"FLUIDBOX_MIGRATE_ONLY\")")
            .expect("migrate-only early return");
        // Anchor on the seed CALL, not on its log message. main renamed
        // "seeding…" to "seeding the default tenant, agent and policies" in the
        // observability work, and a message-anchored assertion breaks on a
        // rewording that changes no behaviour.
        let seed = src.find("fluidbox_db::seed::run(").expect("seed step");
        assert!(
            gate < early,
            "migrate-only must return AFTER the RLS posture check"
        );
        assert!(early < seed, "migrate-only must return BEFORE seeding");
    }

    /// The pool must be built from the CONFIG, not from the crate default: a
    /// `connect` (rather than `connect_with`) here would leave every
    /// `FLUIDBOX_DB_*` knob parsed, validated, logged — and ignored.
    #[test]
    fn the_pool_is_built_from_the_configured_sizing() {
        let src = production_src();
        assert!(
            src.contains("fluidbox_db::connect_with(") && src.contains("cfg.db_pool)"),
            "boot must size the pool from cfg.db_pool"
        );
        // The mutation this is really here for: dropping back to the two-argument
        // `connect`, which silently takes `PoolSettings::default()` and makes every
        // FLUIDBOX_DB_* knob inert.
        assert!(
            !src.contains("fluidbox_db::connect(&cfg.database_url"),
            "boot must not fall back to the default-sized `connect`"
        );
    }
}
