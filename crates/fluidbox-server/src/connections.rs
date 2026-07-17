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
    /// mcp_http static flavor: which header carries the credential (default
    /// `authorization`) and how the value composes (`Bearer` default,
    /// `Basic` = base64(email:token), `""` = the bare token).
    #[serde(default)]
    pub header_name: Option<String>,
    #[serde(default)]
    pub scheme: Option<String>,
    /// mcp_http: `static` (default; paste a token now) or `oauth` (starts
    /// pending; `/v1/connections/{id}/oauth/start` begins the dance).
    #[serde(default)]
    pub auth_kind: Option<String>,
    /// oauth flavor: scopes to request, and an optional pre-registered
    /// client identity (confidential clients supply both; the secret is
    /// sealed at rest and never returned).
    #[serde(default)]
    pub scopes: Option<Vec<String>>,
    #[serde(default)]
    pub client_id: Option<String>,
    #[serde(default)]
    pub client_secret: Option<String>,
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

/// A sealed credential for BROKERED MCP servers (design §8.3 class 2),
/// pinned to a base URL. The broker sends this credential only to server
/// URLs under `base_url` (audience binding — our RFC-8707 equivalent), so a
/// bundle can never point this token at another host. No ingress, no git
/// fetch: this flavor exists purely for the tool broker.
///
/// Two auth kinds on the one custody object: `static` seals the pasted
/// secret now (optionally under a custom header/scheme — Sentry, Atlassian);
/// `oauth` creates a PENDING row whose credential arrives from the
/// authorization-code dance (`oauth.rs`) as a sealed rotating refresh token.
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
    match req.auth_kind.as_deref().unwrap_or("static") {
        "static" => {
            let row = create_mcp_http_connection(state, req).await?;
            Ok(Json(json!({ "connection": row })))
        }
        "oauth" => {
            let sealer = sealer(state)?;
            let host = parsed.host_str().unwrap_or("mcp").to_string();
            if req
                .token
                .as_deref()
                .map(str::trim)
                .is_some_and(|t| !t.is_empty())
            {
                return Err(ApiError::BadRequest(
                    "oauth connections take no token — the authorization flow supplies the credential"
                        .into(),
                ));
            }
            let resource =
                crate::oauth::canonical_resource(base_url).map_err(ApiError::BadRequest)?;
            let mut oauth = json!({
                "resource": resource,
                "scopes": req.scopes.clone().unwrap_or_default(),
            });
            if let Some(cid) = req
                .client_id
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
            {
                oauth["client_id"] = json!(cid);
                oauth["client_id_source"] = json!("preregistered");
            }
            let sealed_secret = req
                .client_secret
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(|s| sealer.seal(s));
            let row = fluidbox_db::create_connection(
                &state.pool,
                fluidbox_db::TenantScope::assume(state.tenant_id),
                &req.provider,
                &host,
                req.display_name.as_deref().unwrap_or(&host),
                None,
                &json!([]),
                &json!({}),
                &json!({ "base_url": base_url }),
                None,
                fluidbox_db::ConnectionAuth {
                    auth_kind: "oauth",
                    status: "pending",
                    oauth: Some(&oauth),
                    client_secret_sealed: sealed_secret.as_deref(),
                    registration_id: None,
                },
            )
            .await?;
            let next = format!("/v1/connections/{}/oauth/start", row.id);
            Ok(Json(json!({ "connection": row, "next": next })))
        }
        other => Err(ApiError::BadRequest(format!(
            "unsupported auth_kind '{other}' (supported: static, oauth)"
        ))),
    }
}

/// The static mcp_http creator, reusable by the catalog Connect flow:
/// validates base_url + header/scheme, seals the secret, returns the row.
pub(crate) async fn create_mcp_http_connection(
    state: &AppState,
    req: CreateConnection,
) -> ApiResult<fluidbox_db::IntegrationConnectionRow> {
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
    let sealer = sealer(state)?;
    let host = parsed.host_str().unwrap_or("mcp").to_string();
    let token = req.token.as_deref().map(str::trim).unwrap_or_default();
    if token.is_empty() {
        return Err(ApiError::BadRequest(
            "token is required for mcp_http (credential-free servers need no connection)".into(),
        ));
    }
    let mut metadata = json!({ "base_url": base_url });
    if let Some(h) = req
        .header_name
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty() && !s.eq_ignore_ascii_case("authorization"))
    {
        if !crate::broker::valid_header_name(h) {
            return Err(ApiError::BadRequest(format!(
                "'{h}' is not a usable credential header name"
            )));
        }
        metadata["header_name"] = json!(h);
    }
    if let Some(s) = req.scheme.as_deref().map(str::trim) {
        if !matches!(s, "Bearer" | "Basic" | "") {
            return Err(ApiError::BadRequest(
                "scheme must be 'Bearer', 'Basic', or '' (bare token)".into(),
            ));
        }
        if s == "Basic" && !token.contains(':') {
            return Err(ApiError::BadRequest(
                "Basic scheme expects the token as 'email:api_token'".into(),
            ));
        }
        if s != "Bearer" {
            metadata["scheme"] = json!(s);
        }
    }
    let sealed = sealer.seal(token);
    Ok(fluidbox_db::create_connection(
        &state.pool,
        fluidbox_db::TenantScope::assume(state.tenant_id),
        "mcp_http",
        &host,
        req.display_name.as_deref().unwrap_or(&host),
        Some(&sealed),
        &json!([]),
        &json!({}),
        &metadata,
        None,
        fluidbox_db::ConnectionAuth::static_active(),
    )
    .await?)
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
        fluidbox_db::TenantScope::assume(state.tenant_id),
        &req.provider,
        &account_id,
        req.display_name.as_deref().unwrap_or(&login),
        Some(&sealed),
        &serde_json::to_value(&scopes)?,
        &json!({}),
        &json!({ "login": login }),
        None,
        fluidbox_db::ConnectionAuth::static_active(),
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
    let row = match fluidbox_db::create_connection(
        &state.pool,
        fluidbox_db::TenantScope::assume(state.tenant_id),
        &req.provider,
        &installation_id,
        req.display_name
            .as_deref()
            .unwrap_or(&format!("{app_slug} → {account}")),
        Some(&sealed_key),
        &json!([]),
        &json!({}),
        &metadata,
        Some(&sealed_webhook),
        fluidbox_db::ConnectionAuth::static_active(),
    )
    .await
    {
        Ok(row) => row,
        // ONE live connection per installation (migration 0008): surface
        // the collision as a decision, not a 500.
        Err(sqlx::Error::Database(e)) if e.is_unique_violation() => {
            return Err(ApiError::Conflict(format!(
                "installation {installation_id} already has a live connection — revoke it first"
            )))
        }
        Err(e) => return Err(e.into()),
    };
    // The one thing the operator must paste into GitHub webhook settings.
    let ingress_path = format!("/v1/ingress/github/{}", row.id);
    Ok(Json(
        json!({ "connection": row, "ingress_path": ingress_path }),
    ))
}

pub async fn list(_: Admin, State(state): State<AppState>) -> ApiResult<Json<Value>> {
    let scope = fluidbox_db::TenantScope::assume(state.tenant_id);
    let connections = fluidbox_db::list_connections(&state.pool, scope).await?;
    Ok(Json(json!({ "connections": connections })))
}

pub async fn revoke(
    _: Admin,
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<Value>> {
    let scope = fluidbox_db::TenantScope::assume(state.tenant_id);
    let row = fluidbox_db::revoke_connection(&state.pool, scope, id)
        .await?
        .ok_or_else(|| ApiError::Conflict("connection not found or already revoked".into()))?;
    // A cached installation/access token must not outlive the revocation.
    crate::oauth::invalidate_access(&state, row.id).await;
    Ok(Json(json!({ "connection": row })))
}

/// Activate a `pending` github_app connection (webhook-discovered) or
/// revive a revoked/suspended/errored one — the ONE explicit admin act that
/// turns discovery into authority (design 5.6 §3). Re-verifies the
/// installation under the app JWT before any transition; the connection id
/// (and its dedup history) stays continuous.
pub async fn approve(
    _: Admin,
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<Value>> {
    let scope = fluidbox_db::TenantScope::assume(state.tenant_id);
    let conn = fluidbox_db::get_connection(&state.pool, scope, id)
        .await?
        .ok_or(ApiError::NotFound)?;
    if conn.provider != "github_app" || conn.registration_id.is_none() {
        return Err(ApiError::BadRequest(
            "approve applies to seamless github_app connections only".into(),
        ));
    }
    if conn.status == "active" {
        return Err(ApiError::Conflict("connection is already active".into()));
    }
    let reg = fluidbox_db::get_github_app_registration(
        &state.pool,
        scope,
        conn.registration_id.expect("checked above"),
    )
    .await?
    .filter(|r| r.status == "active")
    .ok_or_else(|| {
        ApiError::Conflict("the github app registration is not active — reconnect GitHub".into())
    })?;
    // Reviving a revoked row must not collide with a DIFFERENT live row
    // that took over the installation since (the partial unique index only
    // covers live rows) — surface a decision, not a 500.
    if let Some(other) = fluidbox_db::get_github_app_connection_by_installation(
        &state.pool,
        scope,
        &conn.external_account_id,
    )
    .await?
    .filter(|c| c.id != conn.id && c.status != "revoked")
    {
        return Err(ApiError::Conflict(format!(
            "installation {} is already live on connection {} — revoke that one first",
            conn.external_account_id, other.id
        )));
    }
    let inst = crate::github_app::verify_installation(&state, &reg, &conn.external_account_id)
        .await
        .map_err(ApiError::Upstream)?
        .ok_or_else(|| {
            ApiError::Conflict(
                "this installation no longer exists on GitHub — it cannot be approved".into(),
            )
        })?;
    let login = inst["account"]["login"].as_str().unwrap_or("unknown");
    let suspended = inst["suspended_at"].is_string();
    let to = if suspended { "suspended" } else { "active" };
    let row = match fluidbox_db::set_connection_status(
        &state.pool,
        scope,
        conn.id,
        to,
        &["pending", "revoked", "suspended", "error"],
    )
    .await
    {
        Ok(row) => row,
        // Race-safe fallback for the preflight above.
        Err(sqlx::Error::Database(e)) if e.is_unique_violation() => {
            return Err(ApiError::Conflict(
                "another live connection claimed this installation — revoke it first".into(),
            ))
        }
        Err(e) => return Err(e.into()),
    }
    .ok_or_else(|| ApiError::Conflict("connection changed state underneath".into()))?;
    // After the transition — the refresh skips revoked rows by design.
    fluidbox_db::refresh_connection_metadata(
        &state.pool,
        scope,
        row.id,
        &crate::github_app::installation_display(&reg, login),
        &crate::github_app::installation_metadata(&reg, &conn.external_account_id, login),
    )
    .await?;
    crate::oauth::invalidate_access(&state, conn.id).await;
    // Compensating check: a registration revoke racing this approve must
    // win. Re-read AFTER our transition — if the registration flipped, the
    // cascade either already caught our row (later writer) or we revert it
    // here (we were the later writer). Either interleaving converges on
    // revoked.
    let reg_now = fluidbox_db::get_github_app_registration(&state.pool, scope, reg.id).await?;
    if reg_now.map(|r| r.status != "active").unwrap_or(true) {
        fluidbox_db::set_connection_status(
            &state.pool,
            scope,
            conn.id,
            "revoked",
            &["active", "suspended"],
        )
        .await
        .ok();
        crate::oauth::invalidate_access(&state, conn.id).await;
        return Err(ApiError::Conflict(
            "the github app registration was revoked during approval".into(),
        ));
    }
    let row = fluidbox_db::get_connection(&state.pool, scope, row.id)
        .await?
        .ok_or_else(|| ApiError::Conflict("connection changed state underneath".into()))?;
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
    let scope = fluidbox_db::TenantScope::assume(state.tenant_id);
    let conn = fluidbox_db::get_connection(&state.pool, scope, id)
        .await?
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
