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
mod egress;
mod error;
mod events;
mod facade;
mod github_app;
mod harness;
mod internal;
mod kms;
mod ledger;
mod llm_keys;
mod login;
mod mcp_sse;
mod oauth;
mod orchestrator;
mod rbac;
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

use axum::routing::{delete, get, patch, post, put};
use axum::Router;
use fluidbox_core::traits::ExecutionProvider;
use state::{AppStateInner, ApprovalRegistry};
use std::net::SocketAddr;
use std::sync::Arc;
use tower_http::trace::TraceLayer;

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
            Ok(Arc::new(
                fluidbox_provider_k8s::KubernetesProvider::connect(k8s_cfg, cfg.data_dir.clone())
                    .await?,
            ))
        }
        other => anyhow::bail!(
            "FLUIDBOX_PROVIDER='{other}' is not available in this build (known: docker, kubernetes)"
        ),
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let _ = dotenvy::dotenv();
    // kube-rs (rustls 0.23) needs a process-level CryptoProvider; the workspace
    // has multiple rustls backends in-tree, so pick ring explicitly or the
    // Kubernetes client panics on first TLS use. No-op for the Docker path.
    let _ = rustls::crypto::ring::default_provider().install_default();
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,fluidbox_server=debug,sqlx=warn".into()),
        )
        .init();

    let cfg = config::Config::from_env()?;
    std::fs::create_dir_all(&cfg.data_dir).ok();

    tracing::info!("connecting to database…");
    let pool = fluidbox_db::connect(&cfg.database_url, cfg.runtime_role.as_deref()).await?;
    if let Some(role) = &cfg.runtime_role {
        tracing::info!(
            "app pool runs under non-owner role '{role}' (RLS role split enabled; posture verified: \
             NOLOGIN, no SUPERUSER/BYPASSRLS, no inherited or foreign memberships)"
        );
    }
    // Review M2: RLS is defence-in-depth ONLY if PostgreSQL actually evaluates the
    // policies. It skips them entirely for a SUPERUSER/BYPASSRLS role — which is
    // exactly what Neon's default credential is — so migration 0018 can be applied,
    // FORCEd, and completely inert. Read the EFFECTIVE role of a pooled connection
    // (after any `after_connect SET ROLE`), and in multi-user mode make it fatal:
    // an unnoticed missing `tenant_id` predicate must be contained, not served.
    match fluidbox_db::pool_role_bypasses_rls(&pool).await? {
        None => tracing::info!("row-level security is ENFORCED for this pool (its role has neither SUPERUSER nor BYPASSRLS)"),
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
            "FLUIDBOX_ALLOW_RLS_BYPASS=1: pool role '{user}' bypasses RLS, so migration 0018's \
             policies are INERT and tenant isolation rests on the query predicates alone — \
             acceptable for local single-user operation only"
        ),
        Some(user) => tracing::warn!(
            "pool role '{user}' is SUPERUSER or has BYPASSRLS, so migration 0018's RLS policies \
             are skipped by PostgreSQL (single-user mode, tolerated). Set FLUIDBOX_RUNTIME_ROLE \
             before enabling FLUIDBOX_REQUIRE_SSO=1, or boot will refuse."
        ),
    }

    tracing::info!("seeding…");
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
                    let host = if ip.contains(':') { format!("[{ip}]") } else { ip };
                    cfg.public_control_url = format!("http://{host}:{port}");
                    tracing::info!("resolved internal control URL: {}", cfg.public_control_url);
                }
                _ => tracing::warn!(
                    "could not resolve internal Service {svc} ClusterIP; runner control URL may need DNS"
                ),
            }
        }
    }

    let provider = build_provider(&cfg).await?;
    if let Err(e) = provider.healthcheck().await {
        tracing::warn!(
            "provider '{}' health probe failed ({e}); sandboxes will not launch until it is reachable",
            provider.runtime_name()
        );
    } else {
        tracing::info!("execution provider: {}", provider.runtime_name());
    }

    let events_tx = fluidbox_db::spawn_listener(cfg.database_url.clone());

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
            "credential sealing disabled (no FLUIDBOX_CREDENTIAL_KEY, KMS off) — integration connections are disabled"
        ),
        (Some(_), config::KmsMode::Off) => {
            tracing::info!("credential sealing: legacy key (FLUIDBOX_KMS_MODE=off)")
        }
        (Some(_), mode) => tracing::info!("credential sealing: KMS envelope ({mode:?})"),
    }
    // Phase D (#32) LLM upstream-auth mode. In tenant mode the facade selects a
    // per-tenant LiteLLM virtual key and the master key is confined to
    // provisioning; shared mode presents the deployment key on every call.
    match cfg.llm_key_mode {
        config::LlmKeyMode::Shared => tracing::info!(
            "LLM upstream auth: shared key (FLUIDBOX_LLM_KEY_MODE=shared)"
        ),
        config::LlmKeyMode::Tenant => tracing::info!(
            "LLM upstream auth: per-tenant virtual keys (FLUIDBOX_LLM_KEY_MODE=tenant); master key confined to provisioning at {}",
            cfg.llm_admin_url
        ),
    }
    if cfg.require_sso && cfg.llm_key_mode == config::LlmKeyMode::Shared {
        tracing::warn!(
            "FLUIDBOX_REQUIRE_SSO=1 with FLUIDBOX_LLM_KEY_MODE=shared — the facade will refuse every model request (tenant_llm_keys_required); set FLUIDBOX_LLM_KEY_MODE=tenant for hosted deployments"
        );
    }

    // Phase E shared egress boundary: ONE policy (dev-loopback seam + operator
    // allowlist + proxy) drives BOTH hardened clients and is stored on AppState
    // for the broker/deliveries pre-dial admission and the git-clone derivation.
    let egress_policy = egress::EgressPolicy::from_config(&cfg);
    let identity_http = egress::build_identity_http(&egress_policy);
    let egress_http = egress::build_egress_http(&egress_policy);

    let state: state::AppState = Arc::new(AppStateInner {
        tenant_id: seed.tenant_id,
        redactor: fluidbox_core::event::Redactor::default(),
        provider,
        approvals: ApprovalRegistry::default(),
        events_tx,
        // Plain client for operator-configured seams (GitHub, LLM) only.
        http: reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(15 * 60))
            .build()?,
        identity_http,
        egress_http,
        egress_policy,
        sealer,
        connector_tokens: Default::default(),
        oauth_locks: Default::default(),
        mcp_sessions: Default::default(),
        tenant_llm_keys: Default::default(),
        // Docker needs no netpol gate; Kubernetes starts unverified and the
        // worker below flips it once the CNI is proven to enforce policy.
        netpol_verified: std::sync::atomic::AtomicBool::new(!is_k8s),
        oidc: Default::default(),
        // Phase D (#32) legacy→KMS re-seal: the singleton claim flag + live
        // progress, both in-memory (the job is restart-safe by construction).
        reseal_running: std::sync::atomic::AtomicBool::new(false),
        reseal_status: tokio::sync::Mutex::new(reseal::ResealStatus::default()),
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
        .route("/policies/{name}", get(api::get_policy))
        .route(
            "/policies/{name}/overrides/{tool}",
            put(api::put_policy_override).delete(api::delete_policy_override),
        )
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
        .route("/triggers/{id}", get(triggers::get))
        .route("/triggers/{id}/enable", post(triggers::enable))
        .route("/triggers/{id}/disable", post(triggers::disable))
        .route("/triggers/{id}/rotate_token", post(triggers::rotate_token))
        .route("/triggers/{id}/invoke", post(triggers::invoke))
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

    let trace_layer = || {
        TraceLayer::new_for_http().make_span_with(|req: &axum::http::Request<axum::body::Body>| {
            // Method + PATH only — never the query string: OAuth
            // `code`/`state` and GitHub flow tokens ride queries.
            tracing::debug_span!("http", method = %req.method(), path = %req.uri().path())
        })
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
    let public_app = public_root
        // CIMD (spec 2025-11-25): this document's URL IS our OAuth
        // client_id; authorization servers fetch it — public by nature.
        .route("/.well-known/fluidbox-client.json", get(oauth::cimd_doc))
        .layer(trace_layer())
        // NO CORS layer (Phase B): the dashboard is a same-origin proxy
        // (`/` → web, `/v1` → API, one origin), so cross-origin requests to
        // `/v1` are never legitimate and no `Access-Control-*` grant should
        // exist. The permissive layer removed here (design lines 649-653) was a
        // cookie-auth CSRF footgun; browser writes now carry the
        // `x-fluidbox-csrf` header + an Origin check instead.
        .with_state(state.clone());

    // Internal listener (:8788) — /internal ONLY, no /v1 route exists. This is
    // the sandbox-facing plane on Kubernetes (the internal Service targets it);
    // route absence means a sandbox cannot reach /v1 at the TCP level.
    let internal_app = Router::new()
        .nest("/internal", internal)
        .layer(trace_layer())
        .with_state(state.clone());

    let public_listener = tokio::net::TcpListener::bind(&state.cfg.bind).await?;
    let internal_listener = tokio::net::TcpListener::bind(&state.cfg.internal_bind).await?;
    tracing::info!("fluidbox public  listening on http://{}", state.cfg.bind);
    tracing::info!(
        "fluidbox internal listening on http://{} (/internal only)",
        state.cfg.internal_bind
    );
    tracing::info!("default agent: {}", seed.default_agent);

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
