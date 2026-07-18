//! Thin helper to append events through the redactor (the only door).

use crate::state::AppState;
use fluidbox_core::event::{Actor, EventBody, EventEnvelope};
use fluidbox_db::TenantScope;
use uuid::Uuid;

/// Append one event, scoped to the session's tenant. `scope` MUST be the
/// session's own tenant — `append_event` refuses (RowNotFound) a session that
/// does not belong to it, so a wrong scope drops the event rather than
/// cross-writing.
pub async fn record(
    state: &AppState,
    scope: TenantScope,
    session: Uuid,
    actor: Actor,
    body: EventBody,
) -> i64 {
    let env = EventEnvelope::new(session, actor, body);
    let redacted = state.redactor.scrub(env);
    match fluidbox_db::append_event(&state.pool, scope, redacted).await {
        Ok(seq) => seq,
        Err(e) => {
            tracing::error!("failed to append event for {session}: {e}");
            -1
        }
    }
}
