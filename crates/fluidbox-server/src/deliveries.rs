//! Result payload + signed webhook delivery (design doc §9). Publication is
//! asynchronous and independently retryable — a completed run stays
//! completed even when its callback destination is down forever.

use crate::error::ApiResult;
use crate::state::AppState;
use fluidbox_core::event::{Actor, EventBody};
use fluidbox_core::spec::{ResultDestination, RunSpec};
use fluidbox_db::{SessionRow, TenantScope};
use serde_json::{json, Value};
use std::time::Duration;
use uuid::Uuid;

/// attempts→wait: 5s, 30s, 2m, 10m, 30m, then 1h forever (attempt n is the
/// n-th failure; MAX_ATTEMPTS bounds the total).
const BACKOFF_SECS: [i64; 6] = [5, 30, 120, 600, 1800, 3600];
pub const MAX_ATTEMPTS: i32 = 6;
const DELIVERY_TIMEOUT: Duration = Duration::from_secs(10);

pub fn backoff_secs(attempt: i32) -> i64 {
    BACKOFF_SECS
        .get((attempt.max(1) - 1) as usize)
        .copied()
        .unwrap_or(3600)
}

/// `v1=<hex hmac-sha256(secret, "{timestamp}.{body}")>` — receivers verify
/// by recomputing over the exact raw body bytes.
pub fn sign_payload(secret: &str, timestamp: i64, body: &str) -> String {
    use hmac::digest::KeyInit;
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    let mut mac =
        Hmac::<Sha256>::new_from_slice(secret.as_bytes()).expect("hmac accepts any key length");
    mac.update(timestamp.to_string().as_bytes());
    mac.update(b".");
    mac.update(body.as_bytes());
    format!("v1={}", hex::encode(mac.finalize().into_bytes()))
}

/// Called by the orchestrator on every transition into a terminal state.
/// Failures here are logged, never propagated — result publication must not
/// touch the run lifecycle (design §9).
/// Enqueue one delivery row per RunSpec destination, idempotently: each
/// destination is check-then-insert (there is no unique key on the table),
/// so a crash after destination A but before B is healed by enqueueing
/// exactly B. Callers are never concurrent for one session — the terminal
/// transition is single-winner and the reconciler runs under the finalize
/// claim. Returns true iff EVERY destination now has a row: partial success
/// must not be mistaken for complete reconciliation.
pub async fn enqueue_for_session(state: &AppState, session_id: Uuid) -> bool {
    // Reconciler path: a bare session id arrives from the terminal transition;
    // load cross-tenant, then the result-delivery calls (Task 3, UUID-only)
    // key off the row.
    let Ok(Some(session)) = fluidbox_db::system_worker::get_session(&state.pool, session_id).await
    else {
        return false;
    };
    let scope = TenantScope::assume(session.tenant_id);
    let Ok(run_spec) = serde_json::from_value::<RunSpec>(session.run_spec.clone()) else {
        return false;
    };
    let mut all_present = true;
    for dest in &run_spec.result_destinations {
        let dest_json = match serde_json::to_value(dest) {
            Ok(v) => v,
            Err(_) => {
                all_present = false;
                continue;
            }
        };
        match fluidbox_db::result_delivery_exists_for(&state.pool, scope, session_id, &dest_json)
            .await
        {
            Ok(true) => continue,
            Ok(false) => {}
            Err(e) => {
                tracing::error!("delivery existence check for {session_id} failed: {e}");
                all_present = false;
                continue;
            }
        }
        match fluidbox_db::enqueue_result_delivery(
            &state.pool,
            scope,
            session_id,
            run_spec.invocation.subscription_id,
            &dest_json,
        )
        .await
        {
            Ok(d) => tracing::info!("enqueued result delivery {} for {session_id}", d.id),
            Err(e) => {
                tracing::error!("enqueue delivery for {session_id} failed: {e}");
                all_present = false;
            }
        }
    }
    all_present
}

/// The delivery worker: single sequential loop (no locking needed — see
/// due_result_deliveries). At-least-once semantics; receivers dedup on
/// x-fluidbox-delivery.
pub fn spawn_worker(state: AppState) {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(3));
        loop {
            tick.tick().await;
            let due = match fluidbox_db::system_worker::due_result_deliveries(&state.pool, 10).await
            {
                Ok(d) => d,
                Err(e) => {
                    tracing::warn!("delivery poll failed: {e}");
                    continue;
                }
            };
            for d in due {
                attempt(&state, &d).await;
            }
        }
    });
}

async fn attempt(state: &AppState, d: &fluidbox_db::ResultDeliveryRow) {
    // The delivery row carries only a session id; resolve the owning tenant
    // (cross-tenant worker load) so the scoped calls below key off the right
    // tenant. A vanished session (never happens — sessions are retained) leaves
    // the row for the next tick rather than mutating cross-tenant state.
    let Ok(Some(session)) =
        fluidbox_db::system_worker::get_session(&state.pool, d.session_id).await
    else {
        tracing::warn!(
            "delivery {}: session {} not found; skipping",
            d.id,
            d.session_id
        );
        return;
    };
    let scope = TenantScope::assume(session.tenant_id);
    let outcome = try_deliver(state, d, &session).await;
    let (ok, err, digest, external_url) = match &outcome {
        Ok((digest, external_url)) => (true, None, Some(digest.as_str()), external_url.clone()),
        Err(e) => (false, Some(e.as_str()), None, None),
    };
    let next_attempt = d.attempts + 1;
    let updated = fluidbox_db::mark_delivery_attempt(
        &state.pool,
        scope,
        d.id,
        ok,
        err,
        digest,
        backoff_secs(next_attempt),
        MAX_ATTEMPTS,
    )
    .await;
    let Ok(Some(row)) = updated else { return };
    // Timeline visibility: record delivered / terminally-failed (not every
    // intermediate retry — that's the deliveries table's job). Provider
    // publishes surface the created comment/check URL.
    let url = external_url.unwrap_or_else(|| destination_label(&row.destination));
    match row.status.as_str() {
        "delivered" => {
            crate::ledger::record(
                state,
                row.session_id,
                Actor::System,
                EventBody::CallbackDelivered {
                    delivery_id: row.id,
                    url,
                    attempt: row.attempts,
                },
            )
            .await;
        }
        "failed" => {
            crate::ledger::record(
                state,
                row.session_id,
                Actor::System,
                EventBody::CallbackFailed {
                    delivery_id: row.id,
                    url,
                    attempts: row.attempts,
                    error: row.last_error.clone().unwrap_or_default(),
                },
            )
            .await;
        }
        _ => {}
    }
}

/// Human-readable destination identity for ledger events: the webhook URL,
/// or `kind:repository` for provider destinations (which have no url).
fn destination_label(dest: &Value) -> String {
    if let Some(u) = dest.get("url").and_then(|u| u.as_str()) {
        return u.to_string();
    }
    let kind = dest.get("kind").and_then(|k| k.as_str()).unwrap_or("?");
    match dest.get("repository").and_then(|r| r.as_str()) {
        Some(repo) => format!("{kind}:{repo}"),
        None => kind.to_string(),
    }
}

/// One delivery attempt. Returns (payload digest, external url if the
/// destination created one). The destination decides the wire: signed
/// webhooks are handled here; provider destinations route through the
/// connector publisher.
async fn try_deliver(
    state: &AppState,
    d: &fluidbox_db::ResultDeliveryRow,
    session: &SessionRow,
) -> Result<(String, Option<String>), String> {
    let dest: ResultDestination = serde_json::from_value(d.destination.clone())
        .map_err(|e| format!("bad destination: {e}"))?;
    match &dest {
        ResultDestination::SignedWebhook { url } => {
            let digest = deliver_signed_webhook(state, d, session, url).await?;
            Ok((digest, None))
        }
        _ => {
            let ctx = publish_context(state, d, session).await?;
            let outcome = crate::connectors::publish(state, &dest, &ctx).await?;
            Ok((
                outcome.digest,
                Some(outcome.external_url).filter(|u| !u.is_empty()),
            ))
        }
    }
}

/// Provider-neutral publish inputs from the session + frozen RunSpec.
async fn publish_context(
    state: &AppState,
    d: &fluidbox_db::ResultDeliveryRow,
    session: &SessionRow,
) -> Result<crate::connectors::PublishContext, String> {
    let run_spec: Option<RunSpec> = serde_json::from_value(session.run_spec.clone()).ok();
    let scope = TenantScope::assume(session.tenant_id);
    let subscription_name = match d.subscription_id {
        Some(sid) => fluidbox_db::get_trigger_subscription(&state.pool, scope, sid)
            .await
            .map_err(|e| format!("subscription lookup failed: {e}"))?
            .map(|s| s.name)
            .unwrap_or_else(|| "unknown".into()),
        None => "unknown".into(),
    };
    let commit_sha = run_spec.as_ref().and_then(|r| match &r.workspace {
        fluidbox_core::spec::WorkspaceSpec::GitRepository { commit_sha, .. } => commit_sha.clone(),
        _ => None,
    });
    Ok(crate::connectors::PublishContext {
        scope: TenantScope::assume(session.tenant_id),
        session_id: session.id,
        subscription_id: d.subscription_id,
        subscription_name,
        agent_name: run_spec
            .as_ref()
            .map(|r| r.agent_name.clone())
            .unwrap_or_else(|| "agent".into()),
        status: session.status.clone(),
        summary: session.result_summary.clone(),
        commit_sha,
    })
}

async fn deliver_signed_webhook(
    state: &AppState,
    d: &fluidbox_db::ResultDeliveryRow,
    session: &SessionRow,
    url: &str,
) -> Result<String, String> {
    let sub_id = d
        .subscription_id
        .ok_or("delivery has no subscription (cannot resolve signing secret)")?;
    let scope = TenantScope::assume(session.tenant_id);
    let sealed = fluidbox_db::subscription_callback_secret_sealed(&state.pool, scope, sub_id)
        .await
        .map_err(|e| format!("secret lookup failed: {e}"))?
        .ok_or("subscription has no callback secret")?;
    let sealer = state
        .sealer
        .as_ref()
        .ok_or("FLUIDBOX_CREDENTIAL_KEY not configured")?;
    let secret = sealer.open(&sealed).map_err(|e| e.to_string())?;

    let payload = result_payload(state, session, Some(d.id), Some(d.attempts + 1))
        .await
        .map_err(|e| format!("payload build failed: {e}"))?;
    let body = payload.to_string();
    let digest = format!("sha256:{}", fluidbox_db::sha256_hex(&body));
    let ts = chrono::Utc::now().timestamp();
    let sig = sign_payload(&secret, ts, &body);

    let res = state
        .http
        .post(url)
        .timeout(DELIVERY_TIMEOUT)
        .header("content-type", "application/json")
        .header("x-fluidbox-event", "run.finished")
        .header("x-fluidbox-delivery", d.id.to_string())
        .header("x-fluidbox-timestamp", ts.to_string())
        .header("x-fluidbox-signature", sig)
        .body(body)
        .send()
        .await
        // reqwest errors carry the URL, never headers/body — safe to store.
        .map_err(|e| format!("request failed: {e}"))?;
    if res.status().is_success() {
        Ok(digest)
    } else {
        Err(format!("destination returned {}", res.status()))
    }
}

/// The canonical run result (design §9): status, summary, artifacts, usage/
/// cost, timestamps, invocation reference. Shared by the signed callback and
/// the scoped polling endpoint so external services see one shape.
pub async fn result_payload(
    state: &AppState,
    session: &SessionRow,
    delivery_id: Option<Uuid>,
    attempt: Option<i32>,
) -> ApiResult<Value> {
    let scope = TenantScope::assume(session.tenant_id);
    let usage = fluidbox_db::usage_totals(&state.pool, scope, session.id).await?;
    let tool_calls = fluidbox_db::tool_call_count(&state.pool, scope, session.id).await?;
    let artifacts = fluidbox_db::list_artifacts(&state.pool, scope, session.id).await?;
    let run_spec: Option<RunSpec> = serde_json::from_value(session.run_spec.clone()).ok();
    Ok(json!({
        "event": "run.finished",
        "delivery_id": delivery_id,
        "attempt": attempt,
        "run": {
            "id": session.id,
            "status": session.status,
            "status_reason": session.status_reason,
            "agent_id": session.agent_id,
            "agent_revision_id": session.agent_revision_id,
            "agent_name": run_spec.as_ref().map(|r| r.agent_name.clone()),
            "task": session.task,
            "summary": session.result_summary,
            "invocation": session.trigger,
            "created_at": session.created_at,
            "started_at": session.started_at,
            "finished_at": session.finished_at,
        },
        "usage": {
            "input_tokens": usage.input_tokens,
            "output_tokens": usage.output_tokens,
            "cache_read_tokens": usage.cache_read_tokens,
            "cache_write_tokens": usage.cache_write_tokens,
            "cost_usd": usage.cost_usd,
            "requests": usage.requests,
            "tool_calls": tool_calls,
        },
        "artifacts": artifacts.iter().map(|a| json!({
            "id": a.id, "kind": a.kind, "name": a.name,
            "content_type": a.content_type, "content": a.content,
        })).collect::<Vec<_>>(),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signature_is_stable_and_verifiable() {
        // Pinned vector — the e2e receiver recomputes this with
        // `printf '%s.%s' ts body | openssl dgst -sha256 -hmac secret`.
        let sig = sign_payload("fbx_whsec_test", 1_752_000_000, r#"{"a":1}"#);
        // Exact vector cross-checked against
        //   printf '%s.%s' 1752000000 '{"a":1}' | openssl dgst -sha256 -hmac fbx_whsec_test
        assert_eq!(
            sig,
            "v1=b519ceca5a07a724c2e3aef9decbc4420a5cd7f303bfdf1a28a8c2b63625aa72"
        );
        assert_eq!(
            sig,
            sign_payload("fbx_whsec_test", 1_752_000_000, r#"{"a":1}"#)
        );
        assert_ne!(
            sig,
            sign_payload("fbx_whsec_test", 1_752_000_001, r#"{"a":1}"#)
        );
        assert_ne!(sig, sign_payload("other", 1_752_000_000, r#"{"a":1}"#));
    }

    #[test]
    fn backoff_grows_then_caps() {
        assert_eq!(backoff_secs(1), 5);
        assert_eq!(backoff_secs(2), 30);
        assert_eq!(backoff_secs(6), 3600);
        assert_eq!(backoff_secs(99), 3600);
    }
}
