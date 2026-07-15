mod api;
mod auth;
mod broker;
mod callback;
mod capabilities;
mod catalog;
mod config;
mod connections;
mod connectors;
mod deliveries;
mod error;
mod events;
mod facade;
mod github_app;
mod harness;
mod internal;
mod ledger;
mod oauth;
mod orchestrator;
mod run_service;
mod scheduler;
mod seal;
mod sse;
mod state;
mod triggers;
mod workers;

use axum::routing::{get, post, put};
use axum::Router;
use state::{AppStateInner, ApprovalRegistry};
use std::sync::Arc;
use tower_http::cors::CorsLayer;
use tower_http::trace::TraceLayer;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let _ = dotenvy::dotenv();
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,fluidbox_server=debug,sqlx=warn".into()),
        )
        .init();

    let cfg = config::Config::from_env()?;
    std::fs::create_dir_all(&cfg.data_dir).ok();

    tracing::info!("connecting to database…");
    let pool = fluidbox_db::connect(&cfg.database_url).await?;

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

    let provider = fluidbox_provider::DockerProvider::connect()?;
    if let Err(e) = provider.ping().await {
        tracing::warn!("docker ping failed ({e}); sandboxes will not launch until docker is up");
    }

    let events_tx = fluidbox_db::spawn_listener(cfg.database_url.clone());

    let sealer = match &cfg.credential_key {
        Some(k) => Some(seal::Sealer::from_key_string(k)?),
        None => {
            tracing::warn!(
                "FLUIDBOX_CREDENTIAL_KEY not set — integration connections are disabled"
            );
            None
        }
    };

    let state: state::AppState = Arc::new(AppStateInner {
        tenant_id: seed.tenant_id,
        redactor: fluidbox_core::event::Redactor::default(),
        provider: Arc::new(provider),
        approvals: ApprovalRegistry::default(),
        events_tx,
        http: reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(15 * 60))
            .build()?,
        sealer,
        connector_tokens: Default::default(),
        oauth_locks: Default::default(),
        pool,
        cfg,
    });

    // Boot-time housekeeping + background workers.
    workers::boot_orphan_sweep(state.clone()).await;
    workers::spawn_all(state.clone());
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
        // admin token — the AEAD-sealed `state` parameter is the auth
        // (same pattern as webhook-signature ingress below).
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

    let internal = Router::new()
        .route("/sessions/{id}/permission", post(internal::permission))
        // Brokered tools (design §8.3 class 2): intent in, governed result
        // out; the sealed credential turns server-side.
        .route("/sessions/{id}/tools/call", post(internal::tool_call))
        .route("/sessions/{id}/events", post(internal::events))
        .route("/sessions/{id}/heartbeat", post(internal::heartbeat))
        .route("/sessions/{id}/result", post(internal::result))
        .route("/token/renew", post(internal::token_renew))
        .route("/llm-usage", post(callback::litellm_usage))
        // The Agent SDK appends /v1/messages (and possibly count_tokens) to
        // ANTHROPIC_BASE_URL=<control>/internal/llm.
        .route("/llm/{*rest}", post(facade::messages));

    // Note: internal::permission etc. extract SessionAuth themselves; the
    // path {id} is informational (the token binds the session).
    let app = Router::new()
        .nest("/v1", public)
        .nest("/internal", internal)
        // CIMD (spec 2025-11-25): this document's URL IS our OAuth
        // client_id; authorization servers fetch it — public by nature.
        .route("/.well-known/fluidbox-client.json", get(oauth::cimd_doc))
        // Method + PATH only — never the query string: OAuth `code`/`state`
        // and the GitHub flow tokens ride queries and must not reach logs.
        .layer(
            TraceLayer::new_for_http().make_span_with(|req: &axum::http::Request<axum::body::Body>| {
                tracing::debug_span!("http", method = %req.method(), path = %req.uri().path())
            }),
        )
        .layer(CorsLayer::permissive())
        .with_state(state.clone());

    let listener = tokio::net::TcpListener::bind(&state.cfg.bind).await?;
    tracing::info!("fluidbox listening on http://{}", state.cfg.bind);
    tracing::info!("default agent: {}", seed.default_agent);
    axum::serve(listener, app).await?;
    Ok(())
}
