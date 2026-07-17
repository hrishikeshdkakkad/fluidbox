//! Personal access tokens (design lines 737-755). Machine access to the `/v1`
//! API without a browser flow: a membership-scoped bearer that re-reads its
//! live membership on every use. Minting and revoking REQUIRE a browser
//! session — a PAT can never mint, extend, or revoke PATs (invariant 11), so a
//! stolen token cannot self-replicate past its expiry.

use crate::auth::{AuthContext, Principal, UserPrincipal};
use crate::error::{ApiError, ApiResult};
use crate::state::AppState;
use axum::extract::{Path, State};
use axum::Json;
use chrono::Utc;
use serde::Deserialize;
use serde_json::{json, Value};
use uuid::Uuid;

const DEFAULT_TTL_SECS: i64 = 90 * 24 * 3600; // 90 days
const MAX_TTL_SECS: i64 = 365 * 24 * 3600; // 1 year
const MIN_TTL_SECS: i64 = 60;
const MAX_NAME_CHARS: usize = 100;

/// Default 90d, clamp to [60s, 1y]. Pure so it is unit-testable.
fn clamp_ttl(requested: Option<i64>) -> i64 {
    requested
        .unwrap_or(DEFAULT_TTL_SECS)
        .clamp(MIN_TTL_SECS, MAX_TTL_SECS)
}

/// `fbx_pat_<64 hex>` — 32 bytes of OS entropy, same style as the other
/// fluidbox tokens (the `fbx_pat_` prefix is redacted in the ledger).
fn mint_token() -> String {
    let mut buf = [0u8; 32];
    getrandom::fill(&mut buf).expect("OS RNG is available");
    format!("fbx_pat_{}", hex::encode(buf))
}

/// PATs belong to a membership; the operator token has none.
fn require_user(principal: &Principal) -> ApiResult<&UserPrincipal> {
    match principal {
        Principal::User(u) => Ok(u),
        Principal::Operator { .. } => Err(ApiError::Forbidden(
            "personal access tokens belong to a membership; the operator token has none".into(),
        )),
    }
}

/// Minting / revoking is a browser-session-only surface (invariant 11).
fn require_browser(u: &UserPrincipal) -> ApiResult<()> {
    match u.auth {
        AuthContext::BrowserSession { .. } => Ok(()),
        AuthContext::Pat { .. } => Err(ApiError::Forbidden(
            "a personal access token cannot mint, extend, or revoke tokens — use a browser session"
                .into(),
        )),
    }
}

#[derive(Deserialize)]
pub struct MintPat {
    pub name: String,
    #[serde(default)]
    pub expires_in_secs: Option<i64>,
}

/// `POST /v1/auth/tokens` — mint a PAT. Returns the plaintext ONCE.
pub async fn mint(
    principal: Principal,
    State(state): State<AppState>,
    Json(req): Json<MintPat>,
) -> ApiResult<Json<Value>> {
    let user = require_user(&principal)?;
    require_browser(user)?;
    let name = req.name.trim();
    if name.is_empty() {
        return Err(ApiError::BadRequest("name is required".into()));
    }
    if name.chars().count() > MAX_NAME_CHARS {
        return Err(ApiError::BadRequest(format!(
            "name too long (> {MAX_NAME_CHARS} chars)"
        )));
    }
    let ttl = clamp_ttl(req.expires_in_secs);
    let expires_at = Utc::now() + chrono::Duration::seconds(ttl);
    let token = mint_token();
    let row = fluidbox_db::identity::mint_pat(
        &state.pool,
        principal.scope(),
        user.membership_id,
        user.user_id,
        name,
        &token,
        expires_at,
    )
    .await?;
    // The plaintext appears ONLY here, once.
    Ok(Json(json!({ "token": token, "pat": row })))
}

/// `GET /v1/auth/tokens` — list the caller's membership PATs (never the
/// secrets — display prefixes only). Browser or PAT context may list.
pub async fn list(principal: Principal, State(state): State<AppState>) -> ApiResult<Json<Value>> {
    let user = require_user(&principal)?;
    let tokens =
        fluidbox_db::identity::list_pats(&state.pool, principal.scope(), user.membership_id)
            .await?;
    Ok(Json(json!({ "tokens": tokens })))
}

/// `DELETE /v1/auth/tokens/{id}` — revoke one of the caller's PATs. Browser
/// session required; 404 when the token is not the caller's.
pub async fn revoke(
    principal: Principal,
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<Value>> {
    let user = require_user(&principal)?;
    require_browser(user)?;
    let ok =
        fluidbox_db::identity::revoke_pat(&state.pool, principal.scope(), user.membership_id, id)
            .await?;
    if !ok {
        return Err(ApiError::NotFound);
    }
    Ok(Json(json!({ "revoked": true, "id": id })))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ttl_defaults_to_90d_and_clamps() {
        assert_eq!(clamp_ttl(None), DEFAULT_TTL_SECS);
        // Below the floor clamps up.
        assert_eq!(clamp_ttl(Some(1)), MIN_TTL_SECS);
        assert_eq!(clamp_ttl(Some(0)), MIN_TTL_SECS);
        assert_eq!(clamp_ttl(Some(-100)), MIN_TTL_SECS);
        // Above the ceiling clamps down.
        assert_eq!(clamp_ttl(Some(MAX_TTL_SECS + 1)), MAX_TTL_SECS);
        assert_eq!(clamp_ttl(Some(10 * 365 * 24 * 3600)), MAX_TTL_SECS);
        // In range passes through.
        assert_eq!(clamp_ttl(Some(3600)), 3600);
    }

    #[test]
    fn minted_tokens_have_the_pat_prefix_and_full_entropy() {
        let t = mint_token();
        assert!(t.starts_with("fbx_pat_"));
        assert_eq!(t.len(), "fbx_pat_".len() + 64); // 32 bytes hex
        assert_ne!(t, mint_token());
    }
}
