use crate::error::ApiError;
use crate::state::AppState;
use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use uuid::Uuid;

fn bearer(parts: &Parts) -> Option<String> {
    bearer_from_headers(&parts.headers)
}

/// Extract a `Bearer <token>` from a header map. Public so handlers that
/// need a non-standard auth path (e.g. /result acknowledging an
/// already-terminal session with a revoked token) can resolve it themselves.
pub fn bearer_from_headers(headers: &axum::http::HeaderMap) -> Option<String> {
    headers
        .get(axum::http::header::AUTHORIZATION)?
        .to_str()
        .ok()?
        .strip_prefix("Bearer ")
        .map(|s| s.to_string())
}

/// Admin authentication for the public `/v1` API.
pub struct Admin;

impl FromRequestParts<AppState> for Admin {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let token = bearer(parts).ok_or(ApiError::Unauthorized)?;
        // Constant-time-ish compare via sha256 of both sides.
        let expected = fluidbox_db::sha256_hex(&state.cfg.admin_token);
        let got = fluidbox_db::sha256_hex(&token);
        if got == expected {
            Ok(Admin)
        } else {
            Err(ApiError::Unauthorized)
        }
    }
}

/// Scoped trigger-token authentication. The token's entire authority is its
/// subscription: it can invoke that subscription and poll the runs it
/// created — it can never satisfy `Admin` or `SessionAuth`.
pub struct TriggerAuth {
    pub subscription_id: Uuid,
}

impl FromRequestParts<AppState> for TriggerAuth {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let token = bearer(parts).ok_or(ApiError::Unauthorized)?;
        let subscription_id = fluidbox_db::subscription_for_token(&state.pool, &token)
            .await?
            .ok_or(ApiError::Unauthorized)?;
        Ok(TriggerAuth { subscription_id })
    }
}

/// Per-session authentication for the internal gateway. Resolves the bearer
/// token to the session it belongs to (unexpired, unrevoked).
pub struct SessionAuth {
    pub session_id: Uuid,
    pub token: String,
}

impl FromRequestParts<AppState> for SessionAuth {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let token = bearer(parts).ok_or(ApiError::Unauthorized)?;
        let session_id = fluidbox_db::session_for_token(&state.pool, &token)
            .await?
            .ok_or(ApiError::Unauthorized)?;
        Ok(SessionAuth { session_id, token })
    }
}
