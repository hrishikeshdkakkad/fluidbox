//! Connector dispatch — the ONE place a provider name maps to a module
//! (design §6.3). Everything above this boundary (ingress router, matcher,
//! dedup, run_service, deliveries) speaks only the provider-neutral types
//! below; everything provider-shaped lives in the connector module.
//!
//! n=1 discipline (§17 #8): plain match dispatch, no trait registry / SDK —
//! adding Slack later means one new module + one arm in each match here.

pub mod github;

use axum::http::HeaderMap;
use chrono::{DateTime, Utc};
use fluidbox_core::spec::{ResultDestination, TrustTier, WorkspaceSpec};
use serde_json::Value;
use std::collections::BTreeMap;
use uuid::Uuid;

/// Outcome of duty #1: the event is authentic and identified.
pub struct VerifiedDelivery {
    /// Provider delivery id — the level-1 dedup key.
    pub external_event_id: String,
    /// Provider event name (pre-normalization), e.g. "pull_request".
    pub event_name: String,
}

pub struct NormalizeCtx {
    pub connection_id: Uuid,
    /// Base for repository clone URLs (e.g. https://github.com, or a
    /// file:// fixture root in the e2e). Clone URLs are ALWAYS derived from
    /// this + the validated resource name, never taken from the payload.
    pub clone_base: String,
}

/// Outcome of duties #2 + #3: the provider event in fluidbox terms.
pub struct NormalizedEvent {
    /// Normalized event type, e.g. "pull_request.opened".
    pub event_type: String,
    /// Resource container the matcher selects on, e.g. "acme/site".
    pub resource: String,
    /// Stable resource identity for result upserts, e.g. "acme/site#42".
    pub resource_key: String,
    /// External author/actor, e.g. "github:octocat".
    pub actor: Option<String>,
    pub occurred_at: Option<DateTime<Utc>>,
    /// Fork/untrusted sources arrive pre-downgraded; subscriptions cannot
    /// override this (design §7.3).
    pub trust_tier: TrustTier,
    /// Event-derived workspace at the exact event commit.
    pub workspace: Option<WorkspaceSpec>,
    /// Task-template context (`{{key}}` inputs).
    pub context: BTreeMap<String, String>,
    /// Publish modes this event supports, instantiated with event data —
    /// the router intersects these with the subscription's `event_publish`.
    pub publishable: BTreeMap<String, ResultDestination>,
    /// Frozen into `InvocationContext.attributes` (audit trail).
    pub attributes: Value,
}

/// Which connector serves a connection of this provider.
pub fn connector_for(provider: &str) -> Option<&'static str> {
    match provider {
        "github" | "github_app" => Some("github"),
        _ => None,
    }
}

pub fn verify(
    connector: &str,
    headers: &HeaderMap,
    body: &[u8],
    secret: &str,
) -> Result<VerifiedDelivery, String> {
    match connector {
        "github" => github::verify(headers, body, secret),
        other => Err(format!("unknown connector '{other}'")),
    }
}

/// Build the normalization context for a connector — the one place its
/// provider-specific config knobs are read, so the ingress router stays
/// provider-ignorant.
pub fn normalize_ctx(
    state: &crate::state::AppState,
    connector: &str,
    connection_id: Uuid,
) -> NormalizeCtx {
    let clone_base = match connector {
        "github" => state.cfg.github_clone_base.clone(),
        _ => String::new(),
    };
    NormalizeCtx {
        connection_id,
        clone_base,
    }
}

/// `Ok(None)` = authentic but not an event fluidbox reacts to (ignored
/// politely at ingress, no delivery row).
pub fn normalize(
    connector: &str,
    event_name: &str,
    payload: &Value,
    ctx: &NormalizeCtx,
) -> Result<Option<NormalizedEvent>, String> {
    match connector {
        "github" => github::normalize(event_name, payload, ctx),
        other => Err(format!("unknown connector '{other}'")),
    }
}

pub fn supported_events(connector: &str) -> &'static [&'static str] {
    match connector {
        "github" => &github::SUPPORTED_EVENTS,
        _ => &[],
    }
}

/// §17 #2: the default filter a new subscription gets when it doesn't pick.
pub fn default_events(connector: &str) -> Vec<String> {
    match connector {
        "github" => github::DEFAULT_EVENTS.iter().map(|s| s.to_string()).collect(),
        _ => vec![],
    }
}

pub fn publish_modes(connector: &str) -> &'static [&'static str] {
    match connector {
        "github" => &github::PUBLISH_MODES,
        _ => &[],
    }
}

/// Representative template context for config-time validation (a template
/// referencing unknown keys is dead config — reject at create).
pub fn sample_context(connector: &str) -> BTreeMap<String, String> {
    match connector {
        "github" => github::sample_context(),
        _ => BTreeMap::new(),
    }
}

/// What a publish produced, for delivery bookkeeping.
pub struct PublishOutcome {
    pub external_url: String,
    pub digest: String,
}

/// Provider-neutral inputs a publisher needs — built by deliveries.rs from
/// the session + frozen RunSpec, no provider types involved.
pub struct PublishContext {
    pub session_id: Uuid,
    pub subscription_id: Option<Uuid>,
    pub subscription_name: String,
    pub agent_name: String,
    pub status: String,
    pub summary: Option<String>,
    pub commit_sha: Option<String>,
}

/// Duty #5: publish a canonical result to a provider destination.
/// SignedWebhook never reaches here (deliveries.rs owns it directly).
pub async fn publish(
    state: &crate::state::AppState,
    dest: &ResultDestination,
    ctx: &PublishContext,
) -> Result<PublishOutcome, String> {
    match dest {
        ResultDestination::SignedWebhook { .. } => {
            Err("signed_webhook is not a connector destination".into())
        }
        ResultDestination::GitHubPrComment { .. } | ResultDestination::GitHubCheck { .. } => {
            github::publish(state, dest, ctx).await
        }
    }
}

/// Resolve a connection into a git-fetch `Authorization` header value.
/// Providers differ (a durable PAT vs a minted installation token); the
/// orchestrator doesn't care.
pub async fn fetch_auth_header(
    state: &crate::state::AppState,
    connection: &fluidbox_db::IntegrationConnectionRow,
) -> anyhow::Result<String> {
    match connector_for(&connection.provider) {
        Some("github") => github::fetch_auth_header(state, connection).await,
        _ => anyhow::bail!(
            "connection provider '{}' does not supply git credentials",
            connection.provider
        ),
    }
}

