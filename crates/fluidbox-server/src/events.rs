//! The connected-service event spine (design §6.3/§6.4): ingress → verify →
//! normalize → dedup → match → create_run, one ordinary run per matching
//! subscription. This file is deliberately provider-ignorant — it speaks
//! only the connector dispatch surface and provider-neutral types; the e2e
//! suite greps it to prove no provider name appears here.
//!
//! Idempotency is two DB-unique claim levels: a delivery row per external
//! event id, a dispatch row per (delivery, subscription). A webhook retry
//! re-walks both and can therefore only HEAL a partial fan-out — never
//! duplicate a run or a comment.

use crate::auth::Admin;
use crate::connectors::{self, NormalizedEvent, VerifiedDelivery};
use crate::error::{ApiError, ApiResult};
use crate::run_service::{self, CreateRun, RevisionSelector, RunCreation};
use crate::state::AppState;
use crate::triggers::{render_task_template, sub_run_params, SubRunParams};
use axum::extract::{Path, State};
use axum::http::HeaderMap;
use axum::Json;
use fluidbox_core::spec::{InvocationContext, InvocationKind};
use serde_json::{json, Value};
use uuid::Uuid;

/// Ingress bodies are bounded (axum's default body limit also applies).
const MAX_BODY_BYTES: usize = 2 * 1024 * 1024;

/// `POST /v1/ingress/{provider}/{connection_id}` — deliberately
/// unauthenticated: the provider cannot send bearer tokens; the webhook
/// signature (verified against the connection's sealed secret) IS the
/// authentication, and nothing is stored before it passes.
pub async fn ingress(
    State(state): State<AppState>,
    Path((provider, connection_id)): Path<(String, Uuid)>,
    headers: HeaderMap,
    body: bytes::Bytes,
) -> ApiResult<Json<Value>> {
    if body.len() > MAX_BODY_BYTES {
        return Err(ApiError::BadRequest("payload too large".into()));
    }
    let conn = fluidbox_db::get_connection(&state.pool, connection_id)
        .await?
        .filter(|c| c.tenant_id == state.tenant_id)
        .ok_or(ApiError::NotFound)?;
    // The path names the connector; the connection's provider must resolve
    // to the same one (a PAT connection has no ingress, wrong path → 404).
    let connector = connectors::connector_for(&conn.provider)
        .filter(|c| *c == provider.as_str())
        .ok_or(ApiError::NotFound)?;
    if conn.status != "active" {
        return Err(ApiError::Conflict("connection is not active".into()));
    }
    let sealer = state.sealer.as_ref().ok_or_else(|| {
        ApiError::BadRequest("event ingress is disabled: set FLUIDBOX_CREDENTIAL_KEY".into())
    })?;
    let sealed = fluidbox_db::connection_webhook_secret_sealed(&state.pool, conn.id)
        .await?
        .ok_or_else(|| {
            ApiError::BadRequest("this connection cannot receive events (no webhook secret)".into())
        })?;
    let secret = sealer
        .open(&sealed)
        .map_err(|e| ApiError::Internal(e.to_string()))?;

    // Duty #1 (connector): authenticity. Reasons are logged, not echoed —
    // and NOTHING is stored for an unverified delivery.
    let verified = match connectors::verify(connector, &headers, &body, &secret) {
        Ok(v) => v,
        Err(reason) => {
            tracing::warn!("ingress {connection_id}: rejected delivery: {reason}");
            return Err(ApiError::Unauthorized);
        }
    };

    let payload: Value = serde_json::from_slice(&body)
        .map_err(|e| ApiError::BadRequest(format!("payload is not json: {e}")))?;

    // The digest covers the exact signed bytes — never a re-serialization.
    let digest = format!(
        "sha256:{}",
        fluidbox_db::sha256_hex(std::str::from_utf8(&body).unwrap_or_default())
    );
    process_delivery(&state, &conn, connector, &verified, &payload, &digest).await
}

/// The provider-ignorant spine after authenticity: normalize → dedup →
/// match → create_run. Shared by the per-connection ingress above and the
/// app-level ingress (which resolves the connection from the verified
/// payload before calling here). `payload_digest` is computed by each
/// caller from the exact signed bytes.
pub(crate) async fn process_delivery(
    state: &AppState,
    conn: &fluidbox_db::IntegrationConnectionRow,
    connector: &'static str,
    verified: &VerifiedDelivery,
    payload: &Value,
    payload_digest: &str,
) -> ApiResult<Json<Value>> {
    // Duties #2+#3 (connector): normalize + event workspace. Events fluidbox
    // doesn't react to are acknowledged without a delivery row.
    let ctx = connectors::normalize_ctx(state, connector, conn.id);
    let normalized = connectors::normalize(connector, &verified.event_name, payload, &ctx)
        .map_err(ApiError::BadRequest)?;
    let Some(event) = normalized else {
        return Ok(Json(json!({ "ignored": verified.event_name })));
    };

    // Level-1 dedup: the same external delivery is stored exactly once.
    let (delivery, fresh) = fluidbox_db::insert_trigger_delivery(
        &state.pool,
        conn.id,
        &verified.external_event_id,
        &event.event_type,
        payload,
        payload_digest,
        event.occurred_at,
    )
    .await?;

    // Match + fan out. Every matched subscription ends as exactly one
    // dispatch row: bound to a run, skipped, or errored.
    let subs = fluidbox_db::list_event_subscriptions(&state.pool, conn.id).await?;
    let mut dispatched = Vec::new();
    let mut skipped = Vec::new();
    for sub in subs.iter().filter(|s| {
        subscription_matches(
            &event.event_type,
            &event.resource,
            s.event_filter.as_ref(),
            s.resource_selector.as_ref(),
        )
    }) {
        let Some(claim) =
            fluidbox_db::claim_trigger_dispatch(&state.pool, delivery.id, sub.id).await?
        else {
            // This (delivery, subscription) already produced its outcome.
            skipped.push(json!({ "subscription_id": sub.id, "reason": "already_dispatched" }));
            continue;
        };
        match dispatch_one(state, connector, sub, &event, verified, claim.id).await {
            Ok(RunCreation::Created(session)) => {
                dispatched.push(json!({ "subscription_id": sub.id, "session_id": session.id }));
            }
            Ok(RunCreation::SkippedOverlap { running_session_id }) => {
                // §17 #5: the subscription's concurrency policy governs
                // event fan-out too; the skip is recorded visibly.
                fluidbox_db::mark_dispatch_outcome(
                    &state.pool,
                    claim.id,
                    "skipped",
                    Some("overlap"),
                )
                .await
                .ok();
                skipped.push(json!({
                    "subscription_id": sub.id,
                    "reason": "overlap",
                    "running_session_id": running_session_id,
                }));
            }
            Err(e) => {
                // Recorded, not retried (scheduler precedent): a config
                // error must not turn provider retries into a run factory.
                let msg = e.to_string();
                fluidbox_db::mark_dispatch_outcome(
                    &state.pool,
                    claim.id,
                    "error",
                    Some(&format!("error: {msg}")),
                )
                .await
                .ok();
                tracing::warn!("dispatch {} for delivery {}: {msg}", sub.id, delivery.id);
                skipped
                    .push(json!({ "subscription_id": sub.id, "reason": format!("error: {msg}") }));
            }
        }
    }

    Ok(Json(json!({
        "delivery_id": delivery.id,
        "event_type": event.event_type,
        "duplicate": !fresh,
        "dispatched": dispatched,
        "skipped": skipped,
    })))
}

/// One matched subscription → one ordinary run through the single
/// create_run funnel, carrying the event workspace (exact commit), the
/// pre-downgraded trust tier, and event-derived result destinations.
async fn dispatch_one(
    state: &AppState,
    provider: &str,
    sub: &fluidbox_db::TriggerSubscriptionRow,
    event: &NormalizedEvent,
    verified: &VerifiedDelivery,
    dispatch_id: Uuid,
) -> ApiResult<RunCreation> {
    let template = sub
        .task_template
        .as_deref()
        .ok_or_else(|| ApiError::Internal("event subscription has no task_template".into()))?;
    let task = render_task_template(template, &event.context).map_err(ApiError::BadRequest)?;
    let SubRunParams {
        autonomy,
        budget_override,
        result_destinations: mut destinations,
        workspace: _,
    } = sub_run_params(sub)?;
    // Configured publish modes ∩ what this event can carry (§17 #3 identity
    // lives on the instantiated destination).
    if let Some(modes) = sub.event_publish.as_ref().and_then(|v| v.as_array()) {
        for mode in modes.iter().filter_map(|v| v.as_str()) {
            if let Some(dest) = event.publishable.get(mode) {
                destinations.push(dest.clone());
            }
        }
    }
    run_service::create_run(
        state,
        CreateRun {
            agent: sub.agent_id.to_string(),
            revision: match sub.pinned_revision_id {
                Some(rid) => RevisionSelector::Pinned(rid),
                None => RevisionSelector::Latest,
            },
            task,
            // Event-derived workspace outranks everything (§3.3): the event
            // IS the work; a subscription override cannot retarget it.
            explicit_workspace: event.workspace.clone(),
            autonomy,
            trust_tier: event.trust_tier,
            budget_override,
            // The subscription's own capability keep-list applies inside
            // create_run; the event adds no further narrowing (fork PRs are
            // stripped there via the trust tier).
            capability_selection: None,
            invocation: InvocationContext {
                kind: InvocationKind::Event,
                subscription_id: Some(sub.id),
                actor: event.actor.clone(),
                attributes: event.attributes.clone(),
                received_at: Some(chrono::Utc::now()),
                provider: Some(provider.to_string()),
                external_event_id: Some(verified.external_event_id.clone()),
                event_type: Some(event.event_type.clone()),
                resource: Some(event.resource_key.clone()),
                occurred_at: event.occurred_at,
            },
            result_destinations: destinations,
            bound_invocation: None,
            bound_dispatch: Some(dispatch_id),
        },
    )
    .await
}

/// Pure matcher: event filter (fail closed — a sub without one matches
/// nothing) then resource selector (empty/absent = every resource).
fn subscription_matches(
    event_type: &str,
    resource: &str,
    event_filter: Option<&Value>,
    resource_selector: Option<&Value>,
) -> bool {
    let type_ok = event_filter
        .and_then(|f| f.get("events"))
        .and_then(|e| e.as_array())
        .map(|list| {
            list.iter()
                .filter_map(|v| v.as_str())
                .any(|e| e == event_type)
        })
        .unwrap_or(false);
    if !type_ok {
        return false;
    }
    match resource_selector
        .and_then(|s| s.get("repositories"))
        .and_then(|r| r.as_array())
    {
        None => true,
        Some(list) if list.is_empty() => true,
        Some(list) => list
            .iter()
            .filter_map(|v| v.as_str())
            .any(|r| r.eq_ignore_ascii_case(resource)),
    }
}

/// `GET /v1/connections/{id}/deliveries` (admin): recent deliveries with
/// their per-subscription dispatch outcomes. Payloads stay out of the
/// listing (the digest identifies them; the row keeps the full body).
pub async fn connection_deliveries(
    _: Admin,
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<Value>> {
    let conn = fluidbox_db::get_connection(&state.pool, id)
        .await?
        .filter(|c| c.tenant_id == state.tenant_id)
        .ok_or(ApiError::NotFound)?;
    let deliveries = fluidbox_db::list_connection_deliveries(&state.pool, conn.id, 30).await?;
    let mut out = Vec::with_capacity(deliveries.len());
    for d in deliveries {
        let dispatches = fluidbox_db::list_delivery_dispatches(&state.pool, d.id).await?;
        out.push(json!({
            "id": d.id,
            "external_event_id": d.external_event_id,
            "event_type": d.event_type,
            "payload_digest": d.payload_digest,
            "occurred_at": d.occurred_at,
            "received_at": d.received_at,
            "dispatches": dispatches,
        }));
    }
    Ok(Json(json!({ "deliveries": out })))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matcher_requires_an_event_filter_and_honors_it() {
        let filter = json!({"events": ["pull_request.opened", "pull_request.reopened"]});
        assert!(subscription_matches(
            "pull_request.opened",
            "acme/site",
            Some(&filter),
            None
        ));
        assert!(subscription_matches(
            "pull_request.reopened",
            "acme/site",
            Some(&filter),
            None
        ));
        // Not in the filter (synchronize is opt-in, §17 #2).
        assert!(!subscription_matches(
            "pull_request.synchronize",
            "acme/site",
            Some(&filter),
            None
        ));
        // Fail closed: no filter / malformed filter matches nothing.
        assert!(!subscription_matches(
            "pull_request.opened",
            "acme/site",
            None,
            None
        ));
        assert!(!subscription_matches(
            "pull_request.opened",
            "acme/site",
            Some(&json!({})),
            None
        ));
    }

    #[test]
    fn matcher_resource_selector_narrows_and_empty_means_all() {
        let filter = json!({"events": ["pull_request.opened"]});
        let only_site = json!({"repositories": ["acme/site"]});
        assert!(subscription_matches(
            "pull_request.opened",
            "acme/site",
            Some(&filter),
            Some(&only_site)
        ));
        // Case-insensitive resource compare (provider names are).
        assert!(subscription_matches(
            "pull_request.opened",
            "Acme/Site",
            Some(&filter),
            Some(&only_site)
        ));
        assert!(!subscription_matches(
            "pull_request.opened",
            "acme/other",
            Some(&filter),
            Some(&only_site)
        ));
        // Empty/absent selector = every resource the connection sees.
        assert!(subscription_matches(
            "pull_request.opened",
            "acme/anything",
            Some(&filter),
            Some(&json!({"repositories": []})),
        ));
        assert!(subscription_matches(
            "pull_request.opened",
            "acme/anything",
            Some(&filter),
            Some(&json!({})),
        ));
    }
}
