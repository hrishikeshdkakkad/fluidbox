//! SSE event stream. NOTIFY is only a wakeup; the seq catch-up query is the
//! delivery source of truth. Immune to missed notifies and Neon scale-to-zero
//! because a polling floor always re-checks the seq.

use crate::auth::{AuthContext, Principal};
use crate::error::{ApiError, ApiResult};
use crate::rbac;
use crate::state::AppState;
use axum::extract::{Path, State};
use axum::http::HeaderMap;
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::IntoResponse;
use std::convert::Infallible;
use std::time::Duration;
use uuid::Uuid;

/// Re-authorize a cookie-authenticated stream mid-flight: `true` = the session
/// is gone (revoked / expired / membership deactivated) and the stream must
/// terminate. `None` (bearer/operator) is always live. Kept tiny so every
/// re-auth branch — the DB-fetch race AND each per-event send — shares ONE
/// liveness rule (design 658-664).
async fn reauth_dead(
    pool: &sqlx::PgPool,
    scope: fluidbox_db::TenantScope,
    reauth: Option<Uuid>,
) -> bool {
    match reauth {
        Some(sid) => !matches!(
            fluidbox_db::identity::web_session_live(pool, scope, sid).await,
            Ok(true)
        ),
        None => false,
    }
}

pub async fn stream(
    principal: Principal,
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    headers: HeaderMap,
) -> ApiResult<impl IntoResponse> {
    // The handshake enforces run.read like any GET on the session's timeline;
    // the CSRF/Origin gate ran in the `Principal` extractor.
    let scope = principal.scope();
    let session = fluidbox_db::get_session(&state.pool, scope, id)
        .await?
        .ok_or(ApiError::NotFound)?;
    rbac::ensure_run_visible(&principal, &session)?;

    // A cookie-authenticated stream re-authorizes on a bounded interval
    // (design 658-664): the extractor runs once, so a revocation / deactivation
    // / expiry after the handshake must terminate the stream. Bearer/operator
    // streams are unaffected (`reauth` stays None).
    let reauth: Option<uuid::Uuid> = match &principal {
        Principal::User(u) => match &u.auth {
            AuthContext::BrowserSession { session_id, .. } => Some(*session_id),
            AuthContext::Pat { .. } => None,
        },
        Principal::Operator { .. } => None,
    };
    let reauth_every = Duration::from_secs(state.cfg.session_reauth_secs.max(1) as u64);

    // Resume from Last-Event-ID (the seq) if present.
    let mut last_seq: i64 = headers
        .get("last-event-id")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);

    let mut rx = state.events_tx.subscribe();
    let pool = state.pool.clone();

    let s = async_stream::stream! {
        // The re-auth clock is a `tokio::time::interval` consulted via
        // `tokio::select!` around EVERY await that can stall — the DB fetch AND
        // each per-event send — so neither a large backlog, a quiet stream, nor a
        // back-pressured client can stretch the recheck past the bound (design
        // 658-664). Consume the immediate first tick so the first recheck lands
        // one period in (the extractor just authorized). Memory stays bounded:
        // events are fetched in fixed 500-row batches, never accumulated.
        let mut reauth_tick = tokio::time::interval(reauth_every);
        reauth_tick.tick().await;

        // Immediately flush any backlog — the fetch is raced against the re-auth
        // tick, and each event is SENT from inside a select (the `ready` branch)
        // so a client that stalls past the re-auth interval between yields is
        // re-checked (the `tick` branch) BEFORE any further event is sent.
        'backlog: loop {
            tokio::select! {
                biased;
                _ = reauth_tick.tick(), if reauth.is_some() => {
                    if reauth_dead(&pool, scope, reauth).await {
                        return; // revoked / expired / membership deactivated
                    }
                }
                batch = fluidbox_db::events_after(&pool, scope, id, last_seq, 500) => {
                    let events = match batch {
                        Ok(events) if !events.is_empty() => events,
                        _ => break 'backlog,
                    };
                    for ev in events {
                        // `biased`: the tick is polled first, so an elapsed
                        // re-auth interval always rechecks (and may terminate)
                        // before the `ready` branch sends THIS event.
                        'send: loop {
                            tokio::select! {
                                biased;
                                _ = reauth_tick.tick(), if reauth.is_some() => {
                                    if reauth_dead(&pool, scope, reauth).await {
                                        return;
                                    }
                                }
                                _ = std::future::ready(()) => {
                                    last_seq = ev.seq;
                                    let data = serde_json::json!({
                                        "seq": ev.seq,
                                        "type": ev.r#type,
                                        "actor": ev.actor,
                                        "payload": ev.payload,
                                        "occurred_at": ev.occurred_at,
                                    });
                                    yield Ok::<Event, Infallible>(
                                        Event::default().id(ev.seq.to_string()).data(data.to_string())
                                    );
                                    break 'send;
                                }
                            }
                        }
                    }
                }
            }
        }

        // Then follow: wake on NOTIFY, re-poll on a floor so nothing is missed,
        // and re-authorize on the same bounded interval — during the outer wait,
        // the catch-up query, EACH per-event send under back-pressure, AND the
        // error backoff. Every await that can stall is raced against the tick, so
        // a stalled pool/query or a slow client can never stretch the recheck
        // past the bound (design 658-664).
        'follow: loop {
            let should_fetch = tokio::select! {
                _ = reauth_tick.tick(), if reauth.is_some() => {
                    if reauth_dead(&pool, scope, reauth).await {
                        break 'follow; // revoked / expired / membership deactivated
                    }
                    false
                }
                r = rx.recv() => matches!(r, Ok((sid, _)) if sid == id) || r.is_err(),
                _ = tokio::time::sleep(Duration::from_secs(2)) => true,
            };
            if !should_fetch { continue; }

            // Race the catch-up query against the re-auth tick: a stalled pool or
            // slow query must not outlive the bound. The future is PINNED so a
            // tick that fires mid-query rechecks liveness (terminating on
            // revoke/expiry/deactivation) and then resumes the SAME query — a
            // fresh `select!` each loop turn re-polls `&mut fetch`, never
            // restarting the query (no duplicated work).
            let fetch = fluidbox_db::events_after(&pool, scope, id, last_seq, 500);
            tokio::pin!(fetch);
            let batch = loop {
                tokio::select! {
                    biased;
                    _ = reauth_tick.tick(), if reauth.is_some() => {
                        if reauth_dead(&pool, scope, reauth).await {
                            break 'follow; // revoked / expired / membership deactivated
                        }
                    }
                    result = &mut fetch => break result,
                }
            };
            match batch {
                Ok(events) => {
                    for ev in events {
                        'send: loop {
                            tokio::select! {
                                biased;
                                _ = reauth_tick.tick(), if reauth.is_some() => {
                                    if reauth_dead(&pool, scope, reauth).await {
                                        break 'follow;
                                    }
                                }
                                _ = std::future::ready(()) => {
                                    last_seq = ev.seq;
                                    let data = serde_json::json!({
                                        "seq": ev.seq,
                                        "type": ev.r#type,
                                        "actor": ev.actor,
                                        "payload": ev.payload,
                                        "occurred_at": ev.occurred_at,
                                    });
                                    yield Ok(Event::default().id(ev.seq.to_string()).data(data.to_string()));
                                    break 'send;
                                }
                            }
                        }
                    }
                }
                Err(_) => {
                    // Back off after a query error, but keep the bound: race the
                    // 1s sleep against the tick. No shared future to preserve, so
                    // a single `select!` (sleep vs interval) suffices — a tick
                    // rechecks liveness and, if live, just cuts the backoff short.
                    tokio::select! {
                        biased;
                        _ = reauth_tick.tick(), if reauth.is_some() => {
                            if reauth_dead(&pool, scope, reauth).await {
                                break 'follow; // revoked / expired / membership deactivated
                            }
                        }
                        _ = tokio::time::sleep(Duration::from_secs(1)) => {}
                    }
                }
            }
        }
    };

    Ok(Sse::new(s).keep_alive(KeepAlive::new().interval(Duration::from_secs(15))))
}
