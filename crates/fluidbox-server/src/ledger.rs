//! Thin helper to append events through the redactor (the only door).

use crate::state::AppState;
use fluidbox_core::event::{Actor, EventBody, EventEnvelope};
use uuid::Uuid;

pub async fn record(state: &AppState, session: Uuid, actor: Actor, body: EventBody) -> i64 {
    let env = EventEnvelope::new(session, actor, body);
    let redacted = state.redactor.scrub(env);
    match fluidbox_db::append_event(&state.pool, redacted).await {
        Ok(seq) => seq,
        Err(e) => {
            tracing::error!("failed to append event for {session}: {e}");
            -1
        }
    }
}
