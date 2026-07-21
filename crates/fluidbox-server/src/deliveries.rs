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

/// How long a claimed delivery row stays off other replicas' scans, measured from
/// the moment ITS OWN attempt starts — `attempt` re-stamps the claim per row
/// (`extend_delivery_claim`) rather than relying on the batch-wide stamp.
///
/// THE ARITHMETIC, EXPLICITLY (review I2). The first cut sized this at 120 s
/// against "one attempt", which was wrong twice over: attempts run SEQUENTIALLY
/// over a batch of `CLAIM_BATCH` = 10 (so the last row's batch-stamped claim had to
/// survive nine other attempts first), and one GitHub publish alone can exceed
/// 120 s — `GITHUB_TIMEOUT` 15 s × (1 installation-token mint + up to
/// `RECONCILE_MAX_PAGES` = 10 reconcile pages + a PATCH that 404s then a POST) =
/// **195 s**. That last number is the sharpest edge: the marker-reconcile
/// pagination Task 6 added to STOP double-posting is itself what pushes a publish
/// past a 120 s claim, re-creating duplicate comments by another route.
///
/// Both halves of the fix are needed. Re-stamping turns the bound from
/// `batch × worst-case-per-row` into `worst-case-per-row`; this constant then has
/// to clear that single-row worst case with margin for DB round trips and a Neon
/// cold start — 195 s + 105 s = **300 s**. It is DERIVED, not typed in, so a
/// raised timeout or page cap moves it automatically; the test additionally pins
/// today's numbers, so such a change fails there and gets re-justified rather than
/// silently parking rows for longer. The cost of the larger TTL is that a CRASHED
/// replica's rows stay parked for up to 300 s before another replica may take
/// them — a delay measured against a backoff schedule that already starts at 5 s
/// and reaches 1 h, and far cheaper than a duplicate external side effect.
const DELIVERY_CLAIM_TTL_SECS: i64 = worst_case_attempt_secs() + CLAIM_TTL_HEADROOM_SECS;

/// Slack over the pure-HTTP worst case for the DB round trips inside one attempt
/// (session + binding + subscription reads, the sealed-secret open, the recorded
/// attempt) and for a Neon cold start ahead of any of them.
const CLAIM_TTL_HEADROOM_SECS: i64 = 105;

/// Rows claimed per tick. Kept at 10: with the per-row re-stamp the batch size no
/// longer multiplies into the TTL, so this is purely a throughput/fairness knob.
const CLAIM_BATCH: i64 = 10;

/// Worst-case wall clock ONE delivery attempt can occupy, derived from the
/// timeouts that actually bound it — the GitHub publish path (its own module owns
/// that arithmetic) or a signed webhook (`DELIVERY_TIMEOUT`).
const fn worst_case_attempt_secs() -> i64 {
    let publish = crate::connectors::github::worst_case_publish_secs();
    let webhook = DELIVERY_TIMEOUT.as_secs() as i64;
    if publish > webhook {
        publish
    } else {
        webhook
    }
}

/// The delivery worker: one loop per replica, each taking a CLAIMED, DISJOINT
/// slice of the due rows (Phase E, #33; Gap 13).
///
/// Before this it was an explicitly single-process sequential loop with no row
/// claim, so two replicas polled the SAME due rows and both attempted them.
/// `claim_due_deliveries` stamps `claimed_by`/`claimed_until` under
/// `for update skip locked` in one transaction, and `mark_delivery_attempt` is
/// guarded on that owner — so concurrent attempts are fenced and a crashed
/// replica's claims expire back into the pool.
///
/// Delivery stays AT-LEAST-ONCE across crashes by design (the external call
/// precedes the durable record; there is no distributed transaction to be had):
/// webhook receivers dedup on `x-fluidbox-delivery`, and the GitHub comment
/// create path closes its own crash window by reconcile-before-create against a
/// deterministic per-subscription marker.
///
/// The batch is claimed at once but attempted SEQUENTIALLY, so each row re-stamps
/// its own claim just before its attempt (review I2) — see
/// [`DELIVERY_CLAIM_TTL_SECS`] for why a batch-wide stamp cannot be sized
/// correctly.
pub fn spawn_worker(state: AppState) {
    tokio::spawn(async move {
        let owner = crate::orchestrator::replica_id();
        let mut tick = tokio::time::interval(Duration::from_secs(3));
        loop {
            tick.tick().await;
            let due = match fluidbox_db::system_worker::claim_due_deliveries(
                &state.pool,
                owner,
                CLAIM_BATCH,
                DELIVERY_CLAIM_TTL_SECS,
            )
            .await
            {
                Ok(d) => d,
                Err(e) => {
                    tracing::warn!("delivery claim poll failed: {e}");
                    continue;
                }
            };
            for d in due {
                attempt(&state, &d, owner).await;
            }
        }
    });
}

async fn attempt(state: &AppState, d: &fluidbox_db::ResultDeliveryRow, owner: Uuid) {
    // The delivery row carries only a session id; resolve the owning tenant
    // (cross-tenant worker load) so the scoped calls below key off the right
    // tenant. A vanished session (never happens — sessions are retained) leaves
    // the row alone rather than mutating cross-tenant state; it returns to the
    // pool when the claim stamped by the poll lapses.
    let Ok(Some(session)) =
        fluidbox_db::system_worker::get_session(&state.pool, d.session_id).await
    else {
        tracing::warn!(
            "delivery {}: session {} not found; skipping (the row stays claimed \
             until its TTL lapses)",
            d.id,
            d.session_id
        );
        return;
    };
    let scope = TenantScope::assume(session.tenant_id);
    // RE-STAMP THE CLAIM PER ROW, BEFORE the side effect (review I2). The batch
    // stamp is already minutes old for a late row; this restarts the TTL clock at
    // THIS attempt so `DELIVERY_CLAIM_TTL_SECS` only has to cover one of them. It
    // is a strict owner CAS, so a row another replica has taken is SKIPPED HERE —
    // before `try_deliver` — which is the only place a lost claim can be handled
    // without either duplicating the external call or stomping the new owner.
    match fluidbox_db::extend_delivery_claim(
        &state.pool,
        scope,
        d.id,
        owner,
        DELIVERY_CLAIM_TTL_SECS,
    )
    .await
    {
        Ok(true) => {}
        Ok(false) => {
            // Not an error and not a spin: the row now belongs to another replica
            // (or is no longer pending), and our own claim scan skips rows whose
            // `claimed_until` is in the future and `claimed_by` is not us, so this
            // replica will not re-pick it until that claim lapses.
            tracing::warn!(
                "delivery {}: claim lost before the attempt (owner {owner} no longer \
                 holds it); skipping — its current owner will deliver it",
                d.id
            );
            return;
        }
        Err(e) => {
            tracing::warn!("delivery {}: claim re-stamp failed: {e}; skipping", d.id);
            return;
        }
    }
    let outcome = try_deliver(state, d, &session).await;
    let (ok, err, digest, external_url) = match &outcome {
        Ok((digest, external_url)) => (true, None, Some(digest.as_str()), external_url.clone()),
        Err(e) => (false, Some(e.as_str()), None, None),
    };
    let next_attempt = d.attempts + 1;
    // Guarded on OUR claim: a replica whose claim expired and was stolen
    // mid-attempt records nothing (`None`) rather than stomping the new owner's
    // attempt counter and backoff.
    let updated = fluidbox_db::mark_delivery_attempt(
        &state.pool,
        scope,
        d.id,
        owner,
        ok,
        err,
        digest,
        backoff_secs(next_attempt),
        MAX_ATTEMPTS,
    )
    .await;
    let row = match updated {
        Ok(Some(row)) => row,
        // OBSERVABLE, because this branch drops the BACKOFF, not just the attempt
        // record (review I2): nothing was written, so `attempts` and
        // `next_attempt_at` are unchanged and the row is due again the moment its
        // new owner's claim lapses. The external side effect above ALREADY
        // happened, so whoever records the attempt records ours as if it were
        // theirs — at-least-once, as documented. Silence here is what made the
        // 120 s-TTL overrun invisible; it must never be silent again.
        Ok(None) => {
            tracing::warn!(
                "delivery {}: claim lost DURING the attempt (it outran the {}s claim \
                 TTL); the attempt and its backoff were NOT recorded — the current \
                 owner's attempt will record instead. delivered={}",
                d.id,
                DELIVERY_CLAIM_TTL_SECS,
                ok
            );
            return;
        }
        Err(e) => {
            tracing::error!("delivery {}: recording the attempt failed: {e}", d.id);
            return;
        }
    };
    // Timeline visibility: record delivered / terminally-failed (not every
    // intermediate retry — that's the deliveries table's job). Provider
    // publishes surface the created comment/check URL.
    let url = external_url.unwrap_or_else(|| destination_label(&row.destination));
    match row.status.as_str() {
        "delivered" => {
            crate::ledger::record(
                state,
                scope,
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
                scope,
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
        ResultDestination::SignedWebhook { url, binding_id } => {
            let digest = deliver_signed_webhook(state, d, session, &dest, url, *binding_id).await?;
            Ok((digest, None))
        }
        _ => {
            // Phase C: a GitHub publish destination carries a `result_publish`
            // binding — recheck it (status + generation + owner membership) BEFORE
            // the connector mints an installation token. A revoked/reauthorized
            // authority fails the attempt visibly and retries per the existing
            // backoff until attempts exhaust (design "fails visibly"). Legacy
            // destinations (no binding_id) skip the recheck, unchanged.
            recheck_publish_binding(state, &dest, session).await?;
            let ctx = publish_context(state, d, session).await?;
            let outcome = crate::connectors::publish(state, &dest, &ctx).await?;
            Ok((
                outcome.digest,
                Some(outcome.external_url).filter(|u| !u.is_empty()),
            ))
        }
    }
}

/// Recheck a GitHub result-publish destination's frozen binding before its
/// installation token mints (design `:705-723`). The binding is the delivery
/// worker's consumption of the `result_publish` slot (invariant 21): it must
/// authorize the exact connection the destination names (belt-and-braces), then
/// pass the connection-authority recheck. Legacy destinations (no binding_id)
/// and signed webhooks are no-ops here.
async fn recheck_publish_binding(
    state: &AppState,
    dest: &ResultDestination,
    session: &SessionRow,
) -> Result<(), String> {
    let (binding_id, connection_id) = match dest {
        ResultDestination::GitHubPrComment {
            binding_id,
            connection_id,
            ..
        }
        | ResultDestination::GitHubCheck {
            binding_id,
            connection_id,
            ..
        } => (*binding_id, *connection_id),
        ResultDestination::SignedWebhook { .. } => return Ok(()),
    };
    let Some(binding_id) = binding_id else {
        return Ok(()); // legacy destination — unchanged
    };
    let scope = TenantScope::assume(session.tenant_id);
    let binding = fluidbox_db::get_run_resource_binding(&state.pool, scope, binding_id)
        .await
        .map_err(|e| format!("binding lookup failed: {e}"))?
        .ok_or("result publish binding is missing")?;
    // R2.3: mechanically verify the loaded binding authorizes THIS delivery
    // (session + slot kind + connection authority + frozen destination) before
    // any custody access.
    verify_publish_binding_scope(&binding, session, dest, "connection")?;
    if binding.connection_id != Some(connection_id) {
        return Err("result publish binding does not authorize the destination connection".into());
    }
    crate::broker::recheck_binding(state, scope, &binding)
        .await
        .map(|_| ())
        .map_err(|e| format!("result publish binding recheck failed: {e}"))
}

/// R2.3 (design :447-451): mechanically verify a loaded `result_publish` binding
/// authorizes THIS delivery, BEFORE any custody access — it belongs to the
/// delivery's session, is the `result_publish` slot kind, carries the authority
/// kind the destination type requires (github ⇒ `connection`; signed webhook ⇒
/// `subscription_secret`), and froze EXACTLY this destination (serde-normalized
/// equality). A mismatch fails the attempt with a reason; the caller's existing
/// backoff retries.
fn verify_publish_binding_scope(
    binding: &fluidbox_db::RunResourceBindingRow,
    session: &SessionRow,
    dest: &ResultDestination,
    expected_authority_kind: &str,
) -> Result<(), String> {
    if binding.session_id != session.id {
        return Err("result publish binding does not belong to this run".into());
    }
    if binding.slot_kind != "result_publish" {
        return Err("result publish binding is not a result_publish slot".into());
    }
    if binding.authority_kind != expected_authority_kind {
        return Err("result publish binding authority does not match the destination type".into());
    }
    // The frozen `resource_scope` is the destination serialized BEFORE the
    // binding_id was stamped into it, so drop that key on both sides for a
    // serde-normalized (object-order-independent) equality.
    let dest_scope = strip_binding_id(
        serde_json::to_value(dest).map_err(|e| format!("destination serialize failed: {e}"))?,
    );
    if dest_scope != strip_binding_id(binding.resource_scope.clone()) {
        return Err("result publish binding scope does not match the destination".into());
    }
    Ok(())
}

/// Drop the top-level `binding_id` key (stamped AFTER the binding froze its
/// `resource_scope`, so it is absent there) for scope equality.
fn strip_binding_id(mut v: Value) -> Value {
    if let Some(o) = v.as_object_mut() {
        o.remove("binding_id");
    }
    v
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
    dest: &ResultDestination,
    url: &str,
    binding_id: Option<Uuid>,
) -> Result<String, String> {
    let sub_id = d
        .subscription_id
        .ok_or("delivery has no subscription (cannot resolve signing secret)")?;
    let scope = TenantScope::assume(session.tenant_id);
    // Phase C: a signed-webhook destination freezes a `subscription_secret`
    // binding. Fresh-read the subscription and refuse when its authority
    // generation moved since the run bound it (a re-armed callback secret is a
    // new generation) BEFORE unsealing the callback secret (design :705-723).
    // The delivery worker owns this comparison — recheck_binding covers only
    // connection authority. Legacy destinations (no binding_id) are unchanged.
    if let Some(bid) = binding_id {
        let binding = fluidbox_db::get_run_resource_binding(&state.pool, scope, bid)
            .await
            .map_err(|e| format!("binding lookup failed: {e}"))?
            .ok_or("signed webhook binding is missing")?;
        // R2.3: mechanically verify the loaded binding authorizes THIS delivery
        // (session + slot kind + subscription_secret authority + frozen
        // destination) before any custody access.
        verify_publish_binding_scope(&binding, session, dest, "subscription_secret")?;
        if binding.subscription_id != Some(sub_id) {
            return Err("signed webhook binding does not match the delivery subscription".into());
        }
        // R2.2: the run's invoking authority (the acting subscription, here) must
        // still be valid before the callback secret is unsealed.
        crate::broker::recheck_invoking_authority(
            &state.pool,
            scope,
            &binding.resolved_by_principal_kind,
            binding.resolved_by_principal_id.as_deref(),
        )
        .await?;
        let sub = fluidbox_db::get_trigger_subscription(&state.pool, scope, sub_id)
            .await
            .map_err(|e| format!("subscription lookup failed: {e}"))?
            .ok_or("subscription is missing")?;
        if binding.authority_generation != Some(sub.authority_generation) {
            return Err(
                "subscription was re-armed after this run started — its callback binding is stale"
                    .into(),
            );
        }
    }
    let (sealed, kv) = fluidbox_db::subscription_callback_secret_sealed(&state.pool, scope, sub_id)
        .await
        .map_err(|e| format!("secret lookup failed: {e}"))?
        .ok_or("subscription has no callback secret")?;
    let sealer = state
        .sealer
        .as_ref()
        .ok_or("FLUIDBOX_CREDENTIAL_KEY not configured")?;
    let secret = sealer
        .open(
            &sealed,
            kv,
            crate::seal::SealCtx::new(
                scope.tenant_id(),
                crate::seal::SealFamily::SubscriptionCallbackSecret,
            ),
        )
        .await
        .map_err(|e| e.to_string())?;

    let payload = result_payload(state, session, Some(d.id), Some(d.attempts + 1))
        .await
        .map_err(|e| format!("payload build failed: {e}"))?;
    let body = payload.to_string();
    let digest = format!("sha256:{}", fluidbox_db::sha256_hex(&body));
    let ts = chrono::Utc::now().timestamp();
    let sig = sign_payload(&secret, ts, &body);

    // Phase E: the callback URL is user-supplied — admit it (SSRF: scheme +
    // host-literal IP) before dialing the hardened `egress_http` (redirects
    // refused, resolved addresses filtered). A denial is a normal failed attempt
    // via the Err path below; the message is non-secret (no URL echoed).
    crate::egress::admit_url(url, &state.egress_policy).map_err(|e| e.to_string())?;
    let res = state
        .egress_http
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

    /// I2: the claim TTL must clear ONE worst-case attempt, derived from the
    /// timeouts that actually bound it rather than asserted in prose. The first cut
    /// (120 s) did not — a single GitHub publish can run 195 s — and an attempt
    /// that outruns its claim loses `mark_delivery_attempt`'s owner guard, which
    /// drops the BACKOFF as well as the attempt record: `attempts` and
    /// `next_attempt_at` never move, so the row is immediately due again, never
    /// reaches MAX_ATTEMPTS, never fails terminally, and repeats its external side
    /// effect on every pass.
    ///
    /// Raising `GITHUB_TIMEOUT` or `RECONCILE_MAX_PAGES` without raising the TTL
    /// fails HERE rather than in production.
    #[test]
    fn claim_ttl_covers_the_worst_case_attempt() {
        let worst = worst_case_attempt_secs();
        assert_eq!(
            worst, 195,
            "the derived worst case moved (15s × (1 token mint + 10 reconcile pages \
             + PATCH-then-POST)); the TTL follows it automatically, but a longer \
             claim parks a crashed replica's rows for longer — re-justify it here"
        );
        assert_eq!(
            DELIVERY_CLAIM_TTL_SECS, 300,
            "the documented TTL arithmetic is 195s worst case + 105s headroom"
        );
        assert!(
            DELIVERY_CLAIM_TTL_SECS > worst,
            "DELIVERY_CLAIM_TTL_SECS ({DELIVERY_CLAIM_TTL_SECS}s) must exceed one \
             worst-case attempt ({worst}s), or a live attempt has its row stolen \
             mid-flight — duplicating the external effect AND freezing the backoff"
        );
        // The margin is for DB round trips / a Neon cold start, not decoration.
        assert!(
            DELIVERY_CLAIM_TTL_SECS - worst >= 60,
            "keep at least 60s of headroom over the pure-HTTP worst case"
        );
    }

    /// The other half of I2 is ORDER: the per-row claim re-stamp must happen
    /// BEFORE `try_deliver`, because that is the only point at which a lost claim
    /// can be handled without either duplicating the external call or stomping the
    /// new owner. A source guard, since the path itself is DB- and network-bound.
    ///
    /// Sliced to the STATEMENTS inside `attempt` (not the prose above it), so a
    /// doc comment mentioning either call cannot satisfy it.
    #[test]
    fn the_claim_is_restamped_before_the_side_effect() {
        let src = include_str!("deliveries.rs");
        let start = src
            .find("async fn attempt(")
            .expect("the per-row attempt exists");
        let end = src[start..]
            .find("    let next_attempt = d.attempts + 1;")
            .map(|i| start + i)
            .expect("attempt() computes the next attempt number");
        let body = &src[start..end];
        let restamp = concat!("fluidbox_db::extend_delivery_", "claim(");
        let deliver = concat!("try_de", "liver(state, d, &session)");
        let (r, t) = (
            body.find(restamp)
                .expect("the claim is re-stamped in attempt()"),
            body.find(deliver).expect("attempt() delivers"),
        );
        assert!(
            r < t,
            "`{restamp}` must precede `{deliver}`: re-stamping AFTER the side effect \
             cannot prevent a duplicate, and not re-stamping at all measures the TTL \
             from the batch claim instead of from this attempt"
        );
    }
}
