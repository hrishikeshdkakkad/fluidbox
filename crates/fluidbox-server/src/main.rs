mod api;
mod auth;
mod callback;
mod config;
mod connections;
mod deliveries;
mod error;
mod facade;
mod internal;
mod ledger;
mod orchestrator;
mod run_service;
mod scheduler;
mod seal;
mod sse;
mod state;
mod triggers;
mod workers;

use axum::routing::{get, post};
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
    let seed = fluidbox_db::seed::run(
        &pool,
        std::path::Path::new("policies"),
        &cfg.sandbox_image,
        &cfg.default_model,
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
            "/connections",
            get(connections::list).post(connections::create),
        )
        .route("/connections/{id}/revoke", post(connections::revoke))
        .route("/connections/{id}/repos", get(connections::repos))
        .route("/triggers", get(triggers::list).post(triggers::create))
        .route("/triggers/{id}", get(triggers::get))
        .route("/triggers/{id}/enable", post(triggers::enable))
        .route("/triggers/{id}/disable", post(triggers::disable))
        .route("/triggers/{id}/rotate_token", post(triggers::rotate_token))
        .route("/triggers/{id}/invoke", post(triggers::invoke))
        .route("/triggers/{id}/runs/{sid}", get(triggers::poll_run));

    let internal = Router::new()
        .route("/sessions/{id}/permission", post(internal::permission))
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
        .layer(TraceLayer::new_for_http())
        .layer(CorsLayer::permissive())
        .with_state(state.clone());

    let listener = tokio::net::TcpListener::bind(&state.cfg.bind).await?;
    tracing::info!("fluidbox listening on http://{}", state.cfg.bind);
    tracing::info!("default agent: {}", seed.default_agent);
    axum::serve(listener, app).await?;
    Ok(())
}
