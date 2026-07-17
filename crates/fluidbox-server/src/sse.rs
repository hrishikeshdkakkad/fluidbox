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
        // Immediately flush any backlog.
        loop {
            match fluidbox_db::events_after(&pool, scope, id, last_seq, 500).await {
                Ok(events) if !events.is_empty() => {
                    for ev in events {
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
                    }
                }
                _ => break,
            }
        }

        // Then follow: wake on NOTIFY, but re-poll on a floor so nothing is missed.
        let mut last_reauth = std::time::Instant::now();
        loop {
            // Bounded re-authorization for cookie-authenticated streams.
            if let Some(sid) = reauth {
                if last_reauth.elapsed() >= reauth_every {
                    last_reauth = std::time::Instant::now();
                    if !matches!(
                        fluidbox_db::identity::web_session_live(&pool, scope, sid).await,
                        Ok(true)
                    ) {
                        break; // revoked / expired / membership deactivated
                    }
                }
            }
            let woke = tokio::select! {
                r = rx.recv() => matches!(r, Ok((sid, _)) if sid == id) || r.is_err(),
                _ = tokio::time::sleep(Duration::from_secs(2)) => true,
            };
            if !woke { continue; }
            match fluidbox_db::events_after(&pool, scope, id, last_seq, 500).await {
                Ok(events) => {
                    for ev in events {
                        last_seq = ev.seq;
                        let data = serde_json::json!({
                            "seq": ev.seq,
                            "type": ev.r#type,
                            "actor": ev.actor,
                            "payload": ev.payload,
                            "occurred_at": ev.occurred_at,
                        });
                        yield Ok(Event::default().id(ev.seq.to_string()).data(data.to_string()));
                    }
                }
                Err(_) => { tokio::time::sleep(Duration::from_secs(1)).await; }
            }
        }
    };

    Ok(Sse::new(s).keep_alive(KeepAlive::new().interval(Duration::from_secs(15))))
}
