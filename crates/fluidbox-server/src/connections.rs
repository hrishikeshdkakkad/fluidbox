//! Integration connections (design §3.2): fluidbox's authorized relationship
//! with an external service. A connection establishes the MAXIMUM authority
//! fluidbox can exercise; agents and triggers may only narrow it.
//!
//! Phase 1 ships GitHub via a (preferably fine-grained) personal access
//! token. The token is validated against the GitHub API, sealed at rest
//! (`seal.rs`), and unsealed server-side only — it is never present in any
//! API response, RunSpec, sandbox, ledger event, or artifact. A full GitHub
//! App installation flow lands with webhook triggers in a later phase.

use crate::auth::Admin;
use crate::error::{ApiError, ApiResult};
use crate::seal::Sealer;
use crate::state::AppState;
use axum::extract::{Path, Query, State};
use axum::Json;
use serde::Deserialize;
use serde_json::{json, Value};
use std::time::Duration;
use uuid::Uuid;

const GITHUB_TIMEOUT: Duration = Duration::from_secs(15);

fn sealer(state: &AppState) -> ApiResult<&Sealer> {
    state.sealer.as_ref().ok_or_else(|| {
        ApiError::BadRequest(
            "integration connections are disabled: set FLUIDBOX_CREDENTIAL_KEY (32-byte hex/base64) on the server".into(),
        )
    })
}

fn github_url(state: &AppState, path: &str) -> String {
    format!("{}{path}", state.cfg.github_api_url.trim_end_matches('/'))
}

async fn github_get(
    state: &AppState,
    token: &str,
    path: &str,
) -> ApiResult<(Value, reqwest::header::HeaderMap)> {
    let res = state
        .http
        .get(github_url(state, path))
        .timeout(GITHUB_TIMEOUT)
        .header("authorization", format!("Bearer {token}"))
        .header("accept", "application/vnd.github+json")
        .header("user-agent", "fluidbox")
        .header("x-github-api-version", "2022-11-28")
        .send()
        .await
        // reqwest errors carry the URL, never request headers — safe to echo.
        .map_err(|e| ApiError::BadRequest(format!("github unreachable: {e}")))?;
    let status = res.status();
    let headers = res.headers().clone();
    if status == reqwest::StatusCode::UNAUTHORIZED {
        return Err(ApiError::BadRequest(
            "github rejected the token (401) — check that it is valid and unexpired".into(),
        ));
    }
    if !status.is_success() {
        return Err(ApiError::BadRequest(format!(
            "github {path} returned {status}"
        )));
    }
    let body: Value = res
        .json()
        .await
        .map_err(|e| ApiError::Internal(format!("github {path}: bad response body: {e}")))?;
    Ok((body, headers))
}

// ─── Handlers ─────────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct CreateConnection {
    pub provider: String,
    /// The credential. Consumed here, sealed at rest, never returned.
    pub token: String,
    #[serde(default)]
    pub display_name: Option<String>,
}

pub async fn create(
    _: Admin,
    State(state): State<AppState>,
    Json(req): Json<CreateConnection>,
) -> ApiResult<Json<Value>> {
    if req.provider != "github" {
        return Err(ApiError::BadRequest(format!(
            "unsupported provider '{}' (phase 1 supports: github)",
            req.provider
        )));
    }
    let token = req.token.trim();
    if token.is_empty() {
        return Err(ApiError::BadRequest("token is required".into()));
    }
    let sealer = sealer(&state)?;

    // Prove the token works and identify the account before storing anything.
    let (user, headers) = github_get(&state, token, "/user").await?;
    let login = user
        .get("login")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown")
        .to_string();
    let account_id = user
        .get("id")
        .and_then(|v| v.as_i64())
        .map(|id| id.to_string())
        .unwrap_or_else(|| login.clone());
    // Classic PATs advertise scopes; fine-grained PATs don't (empty list).
    let scopes: Vec<String> = headers
        .get("x-oauth-scopes")
        .and_then(|v| v.to_str().ok())
        .map(|s| {
            s.split(',')
                .map(|x| x.trim().to_string())
                .filter(|x| !x.is_empty())
                .collect()
        })
        .unwrap_or_default();

    let sealed = sealer.seal(token);
    let row = fluidbox_db::create_connection(
        &state.pool,
        state.tenant_id,
        &req.provider,
        &account_id,
        req.display_name.as_deref().unwrap_or(&login),
        &sealed,
        &serde_json::to_value(&scopes)?,
        &json!({}),
        &json!({ "login": login }),
        None,
    )
    .await?;
    Ok(Json(json!({ "connection": row })))
}

pub async fn list(_: Admin, State(state): State<AppState>) -> ApiResult<Json<Value>> {
    let connections = fluidbox_db::list_connections(&state.pool, state.tenant_id).await?;
    Ok(Json(json!({ "connections": connections })))
}

pub async fn revoke(
    _: Admin,
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<Value>> {
    let row = fluidbox_db::revoke_connection(&state.pool, id)
        .await?
        .ok_or_else(|| ApiError::Conflict("connection not found or already revoked".into()))?;
    Ok(Json(json!({ "connection": row })))
}

#[derive(Deserialize)]
pub struct ReposQuery {
    #[serde(default = "default_page")]
    pub page: u32,
    #[serde(default = "default_per_page")]
    pub per_page: u32,
}
fn default_page() -> u32 {
    1
}
fn default_per_page() -> u32 {
    50
}

/// Repository picker: the control plane lists what the connection can see.
/// The token never leaves the control plane.
pub async fn repos(
    _: Admin,
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    Query(q): Query<ReposQuery>,
) -> ApiResult<Json<Value>> {
    let conn = fluidbox_db::get_connection(&state.pool, id)
        .await?
        .filter(|c| c.tenant_id == state.tenant_id)
        .ok_or(ApiError::NotFound)?;
    if conn.status != "active" {
        return Err(ApiError::Conflict(format!(
            "connection is {} — reconnect to browse repositories",
            conn.status
        )));
    }
    let sealer = sealer(&state)?;
    let sealed = fluidbox_db::connection_credential_sealed(&state.pool, id)
        .await?
        .ok_or(ApiError::NotFound)?;
    let token = sealer
        .open(&sealed)
        .map_err(|e| ApiError::Internal(e.to_string()))?;

    let per_page = q.per_page.min(100);
    let (body, _) = github_get(
        &state,
        &token,
        &format!(
            "/user/repos?per_page={per_page}&page={}&sort=updated",
            q.page
        ),
    )
    .await?;
    let repos: Vec<Value> = body
        .as_array()
        .map(|items| {
            items
                .iter()
                .map(|r| {
                    json!({
                        "id": r.get("id"),
                        "full_name": r.get("full_name"),
                        "private": r.get("private"),
                        "default_branch": r.get("default_branch"),
                        "html_url": r.get("html_url"),
                    })
                })
                .collect()
        })
        .unwrap_or_default();
    Ok(Json(json!({ "repos": repos })))
}
