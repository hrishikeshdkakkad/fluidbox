//! SSE event stream. NOTIFY is only a wakeup; the seq catch-up query is the
//! delivery source of truth. Immune to missed notifies and Neon scale-to-zero
//! because a polling floor always re-checks the seq.

use crate::auth::Admin;
use crate::error::ApiResult;
use crate::state::AppState;
use axum::extract::{Path, State};
use axum::http::HeaderMap;
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::IntoResponse;
use std::convert::Infallible;
use std::time::Duration;
use uuid::Uuid;

pub async fn stream(
    _: Admin,
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    headers: HeaderMap,
) -> ApiResult<impl IntoResponse> {
    // Resume from Last-Event-ID (the seq) if present.
    let mut last_seq: i64 = headers
        .get("last-event-id")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);

    let mut rx = state.events_tx.subscribe();
    let pool = state.pool.clone();
    let scope = fluidbox_db::TenantScope::assume(state.tenant_id);

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
        loop {
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
