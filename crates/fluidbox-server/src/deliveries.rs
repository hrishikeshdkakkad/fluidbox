//! Result payload + signed webhook delivery (design doc §9).

use crate::error::ApiResult;
use crate::state::AppState;
use fluidbox_core::spec::RunSpec;
use fluidbox_db::SessionRow;
use serde_json::{json, Value};
use uuid::Uuid;

/// The canonical run result (design §9): status, summary, artifacts, usage/
/// cost, timestamps, invocation reference. Shared by the signed callback and
/// the scoped polling endpoint so external services see one shape.
pub async fn result_payload(
    state: &AppState,
    session: &SessionRow,
    delivery_id: Option<Uuid>,
    attempt: Option<i32>,
) -> ApiResult<Value> {
    let usage = fluidbox_db::usage_totals(&state.pool, session.id).await?;
    let tool_calls = fluidbox_db::tool_call_count(&state.pool, session.id).await?;
    let artifacts = fluidbox_db::list_artifacts(&state.pool, session.id).await?;
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
