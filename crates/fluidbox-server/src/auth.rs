use crate::error::ApiError;
use crate::state::AppState;
use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use uuid::Uuid;

fn bearer(parts: &Parts) -> Option<String> {
    parts
        .headers
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
