//! Integration connections (design §3.2): fluidbox's authorized relationship
//! with an external service. A connection establishes the MAXIMUM authority
//! fluidbox can exercise; agents and triggers may only narrow it.
//!
//! Two GitHub flavors:
//! - `github` — a (preferably fine-grained) personal access token; fetch
//!   credential only.
//! - `github_app` — an App installation (app id + installation id + private
//!   key + webhook secret): receives webhook events at
//!   `/v1/ingress/github/{connection_id}` and publishes results under the
//!   App identity (§17 #1). PATs stay valid for fetch.
//!
//! Secrets (PAT / private key / webhook secret) are validated against the
//! provider, sealed at rest (`seal.rs`), and unsealed server-side only —
//! never present in any API response, RunSpec, sandbox, ledger, or artifact.
//! Provider API shapes live in `connectors::github`, not here.

use crate::auth::Admin;
use crate::connectors;
use crate::error::{ApiError, ApiResult};
use crate::seal::Sealer;
use crate::state::AppState;
use axum::extract::{Path, Query, State};
use axum::Json;
use serde::Deserialize;
use serde_json::{json, Value};
use uuid::Uuid;

fn sealer(state: &AppState) -> ApiResult<&Sealer> {
    state.sealer.as_ref().ok_or_else(|| {
        ApiError::BadRequest(
            "integration connections are disabled: set FLUIDBOX_CREDENTIAL_KEY (32-byte hex/base64) on the server".into(),
        )
    })
}

// ─── Handlers ─────────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct CreateConnection {
    pub provider: String,
    /// PAT flavor: the token. Consumed here, sealed at rest, never returned.
    #[serde(default)]
    pub token: Option<String>,
    /// App flavor: identity + credentials. All consumed here.
    #[serde(default)]
    pub app_id: Option<String>,
    #[serde(default)]
    pub installation_id: Option<String>,
    #[serde(default)]
    pub private_key: Option<String>,
    #[serde(default)]
    pub webhook_secret: Option<String>,
    #[serde(default)]
    pub display_name: Option<String>,
    /// mcp_http flavor: the base URL its credential is audience-bound to.
    #[serde(default)]
    pub base_url: Option<String>,
}

pub async fn create(
    _: Admin,
    State(state): State<AppState>,
    Json(req): Json<CreateConnection>,
) -> ApiResult<Json<Value>> {
    match req.provider.as_str() {
        "github" => create_github_pat(&state, req).await,
        "github_app" => create_github_app(&state, req).await,
        "mcp_http" => create_mcp_http(&state, req).await,
        other => Err(ApiError::BadRequest(format!(
            "unsupported provider '{other}' (supported: github, github_app, mcp_http)"
        ))),
    }
}

/// A sealed credential for BROKERED MCP servers (design §8.3 class 2): a
/// bearer token pinned to a base URL. The broker sends this credential only
/// to server URLs under `base_url` (audience binding — our RFC-8707
/// equivalent), so a bundle can never point this token at another host. No
/// ingress, no git fetch: this flavor exists purely for the tool broker.
async fn create_mcp_http(state: &AppState, req: CreateConnection) -> ApiResult<Json<Value>> {
    let base_url = req
        .base_url
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| ApiError::BadRequest("base_url is required for mcp_http".into()))?;
    let parsed = reqwest::Url::parse(base_url)
        .map_err(|_| ApiError::BadRequest("base_url is not a valid URL".into()))?;
    if !matches!(parsed.scheme(), "http" | "https") {
        return Err(ApiError::BadRequest("base_url must be http(s)".into()));
    }
    let token = req.token.as_deref().map(str::trim).unwrap_or_default();
    if token.is_empty() {
        return Err(ApiError::BadRequest(
            "token is required for mcp_http (credential-free servers need no connection)".into(),
        ));
    }
    let sealer = sealer(state)?;
    let host = parsed.host_str().unwrap_or("mcp").to_string();
    let sealed = sealer.seal(token);
    let row = fluidbox_db::create_connection(
        &state.pool,
        state.tenant_id,
        &req.provider,
        &host,
        req.display_name.as_deref().unwrap_or(&host),
        &sealed,
        &json!([]),
        &json!({}),
        &json!({ "base_url": base_url }),
        None,
    )
    .await?;
    Ok(Json(json!({ "connection": row })))
}

async fn create_github_pat(state: &AppState, req: CreateConnection) -> ApiResult<Json<Value>> {
    let token = req.token.as_deref().map(str::trim).unwrap_or_default();
    if token.is_empty() {
        return Err(ApiError::BadRequest("token is required".into()));
    }
    let sealer = sealer(state)?;

    // Prove the token works and identify the account before storing anything.
    let (login, account_id, scopes) = connectors::github::validate_pat(state, token)
        .await
        .map_err(ApiError::BadRequest)?;

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

async fn create_github_app(state: &AppState, req: CreateConnection) -> ApiResult<Json<Value>> {
    let field = |v: &Option<String>, name: &str| -> ApiResult<String> {
        v.as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string)
            .ok_or_else(|| ApiError::BadRequest(format!("{name} is required for github_app")))
    };
    let app_id = field(&req.app_id, "app_id")?;
    let installation_id = field(&req.installation_id, "installation_id")?;
    let private_key = field(&req.private_key, "private_key")?;
    let webhook_secret = field(&req.webhook_secret, "webhook_secret")?;
    if !app_id.chars().all(|c| c.is_ascii_digit())
        || !installation_id.chars().all(|c| c.is_ascii_digit())
    {
        return Err(ApiError::BadRequest(
            "app_id and installation_id must be numeric".into(),
        ));
    }
    let sealer = sealer(state)?;

    // Prove the app credentials + installation before storing anything.
    let metadata = connectors::github::validate_app(state, &app_id, &installation_id, &private_key)
        .await
        .map_err(ApiError::BadRequest)?;
    let app_slug = metadata["app_slug"].as_str().unwrap_or("app").to_string();
    let account = metadata["account_login"]
        .as_str()
        .unwrap_or("unknown")
        .to_string();

    let sealed_key = sealer.seal(&private_key);
    let sealed_webhook = sealer.seal(&webhook_secret);
    let row = fluidbox_db::create_connection(
        &state.pool,
        state.tenant_id,
        &req.provider,
        &installation_id,
        req.display_name
            .as_deref()
            .unwrap_or(&format!("{app_slug} → {account}")),
        &sealed_key,
        &json!([]),
        &json!({}),
        &metadata,
        Some(&sealed_webhook),
    )
    .await?;
    // The one thing the operator must paste into GitHub webhook settings.
    let ingress_path = format!("/v1/ingress/github/{}", row.id);
    Ok(Json(
        json!({ "connection": row, "ingress_path": ingress_path }),
    ))
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
/// The credential never leaves the control plane.
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
    sealer(&state)?;
    let repos = connectors::github::list_repos(&state, &conn, q.page, q.per_page.min(100))
        .await
        .map_err(ApiError::BadRequest)?;
    Ok(Json(json!({ "repos": repos })))
}
