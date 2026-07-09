//! LiteLLM usage callback ingestion. When LiteLLM is configured with a
//! generic webhook callback, it POSTs per-request spend here. Idempotent by
//! LiteLLM's call id; the fluidbox ledger remains the source of truth.
//!
//! In M1 the facade's SSE tee already meters usage, so this endpoint is a
//! belt-and-suspenders path (and the seam for switching metering sources).

use crate::error::ApiResult;
use crate::state::AppState;
use axum::extract::State;
use axum::http::HeaderMap;
use axum::Json;
use serde_json::{json, Value};

/// Shared-secret auth: LiteLLM includes the master key; we accept it as a
/// simple bearer since this endpoint only writes usage rows.
pub async fn litellm_usage(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<Value>,
) -> ApiResult<Json<Value>> {
    // Best-effort auth.
    let ok = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.contains(&state.cfg.llm_upstream_key))
        .unwrap_or(false);
    if !ok {
        return Ok(Json(json!({ "ignored": "unauthenticated" })));
    }
    tracing::debug!("litellm usage callback: {payload}");
    // Parsing left as a seam; the facade tee is the primary meter in M1.
    Ok(Json(json!({ "ok": true })))
}
