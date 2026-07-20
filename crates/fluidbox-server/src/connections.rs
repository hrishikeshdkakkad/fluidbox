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

use crate::auth::Principal;
use crate::connectors;
use crate::error::{ApiError, ApiResult};
use crate::rbac;
use crate::seal::{SealCtx, SealFamily, Sealer};
use crate::state::AppState;
use axum::extract::{Path, Query, State};
use axum::Json;
use fluidbox_db::TenantScope;
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
    /// Who owns the connection (design :274-296): `organization` (default,
    /// visible to every member, requires admin/owner) or `personal` (one
    /// member's private custody, allowed for any signed-in member).
    #[serde(default)]
    pub owner: Option<String>,
}

/// Resolved ownership for a connection create: which owner the row is stamped
/// with, and who created it. Threaded from the request `owner` field + the
/// authenticated principal into every `create_connection`.
#[derive(Clone, Copy)]
pub(crate) struct OwnerContext {
    pub owner: fluidbox_db::ConnectionOwner,
    pub created_by_user_id: Option<Uuid>,
}

/// Resolve the request `owner` field against the principal (design :274-296).
/// `organization` (the default, back-compat) requires `can_mutate_resources`;
/// `personal` requires a signed-in User (the operator has no identity to own a
/// personal row — 400) and is open to ANY member. `created_by_user_id` is
/// always stamped from the principal (None for the operator). `github_app`
/// connections are organization custody by construction and REFUSE personal.
pub(crate) fn resolve_owner(
    principal: &Principal,
    provider: &str,
    owner: Option<&str>,
) -> ApiResult<OwnerContext> {
    let created_by = principal.user_id();
    match owner.map(str::trim).unwrap_or("organization") {
        "organization" | "" => {
            if !rbac::can_mutate_resources(principal) {
                return Err(ApiError::Forbidden(
                    "creating an organization connection requires admin or owner".into(),
                ));
            }
            Ok(OwnerContext {
                owner: fluidbox_db::ConnectionOwner::Organization,
                created_by_user_id: created_by,
            })
        }
        "personal" => {
            if provider == "github_app" {
                return Err(ApiError::BadRequest(
                    "github_app connections are organization custody and cannot be personal".into(),
                ));
            }
            if !rbac::can_create_personal_connection(principal) {
                // The operator has no personal identity to own the row.
                return Err(ApiError::BadRequest(
                    "personal connections require a signed-in user (the admin token has no personal identity)"
                        .into(),
                ));
            }
            let uid = principal
                .user_id()
                .expect("can_create_personal_connection implies a user id");
            Ok(OwnerContext {
                owner: fluidbox_db::ConnectionOwner::User(uid),
                created_by_user_id: Some(uid),
            })
        }
        other => Err(ApiError::BadRequest(format!(
            "owner must be 'organization' or 'personal' (got '{other}')"
        ))),
    }
}

/// Fetch a connection for a MUTATION (revoke / oauth start / tools refresh),
/// enforcing ownership authority and returning the row. A PERSONAL connection
/// (`owner_type='user'`) is owner-only: it is fetched through the caller's
/// visibility lens, so another member's personal row is already invisible
/// (None ⇒ 404) — the deliberate 404-not-403 shape (a personal connection is
/// invisible, not forbidden, so its existence is never revealed). An
/// ORGANIZATION connection keeps the standard `can_mutate_resources` gate.
/// `action` names the verb for the forbidden message ("revoking", …).
pub(crate) async fn connection_for_mutation(
    state: &AppState,
    principal: &Principal,
    id: Uuid,
    action: &str,
) -> ApiResult<fluidbox_db::IntegrationConnectionRow> {
    let scope = principal.scope();
    let conn = fluidbox_db::get_connection_visible(
        &state.pool,
        scope,
        id,
        rbac::connection_viewer(principal),
    )
    .await?
    .ok_or(ApiError::NotFound)?;
    if conn.owner_type == "user" {
        // Personal: owner only. The User-viewer fetch already excluded other
        // members; assert the owner id so the operator (All viewer) — which is
        // never the owner — also 404s rather than mutating a personal row.
        if principal.user_id() != conn.owner_user_id {
            return Err(ApiError::NotFound);
        }
    } else if !rbac::can_mutate_resources(principal) {
        return Err(ApiError::Forbidden(format!(
            "{action} an organization connection requires admin or owner"
        )));
    }
    Ok(conn)
}

pub async fn create(
    principal: Principal,
    State(state): State<AppState>,
    Json(req): Json<CreateConnection>,
) -> ApiResult<Json<Value>> {
    // Ownership + authorization: `organization` requires admin/owner,
    // `personal` requires any signed-in member (design :274-296).
    let owner = resolve_owner(&principal, &req.provider, req.owner.as_deref())?;
    let scope = principal.scope();
    match req.provider.as_str() {
        "github" => create_github_pat(&state, scope, owner, req).await,
        "github_app" => create_github_app(&state, scope, owner, req).await,
        "mcp_http" => create_mcp_http(&state, scope, owner, req).await,
        other => Err(ApiError::BadRequest(format!(
            "unsupported provider '{other}' (supported: github, github_app, mcp_http)"
        ))),
    }
}

/// Parse + admit a connector `base_url` at SAVE time (I2 — the E3 admission
/// layer). Beyond the http(s) scheme gate, `egress::admit_url` refuses a
/// plain-http target outside the dev-loopback seam and a private/loopback/
/// metadata IP LITERAL, so a hostile destination is rejected at admission rather
/// than first-dial. DNS is deliberately NOT resolved here (admit_url is
/// literal+scheme only, keeping the request handler non-blocking); a name that
/// later resolves to a private address is still caught at dial by the hardened
/// broker client. Every mcp_http entry point (direct create + catalog Connect,
/// both auth kinds) funnels through here, so all inherit the admission. Returns
/// the parsed URL for host extraction / resource canonicalization.
fn admit_connector_base_url(
    base_url: &str,
    policy: &crate::egress::EgressPolicy,
) -> ApiResult<reqwest::Url> {
    let parsed = reqwest::Url::parse(base_url)
        .map_err(|_| ApiError::BadRequest("base_url is not a valid URL".into()))?;
    if !matches!(parsed.scheme(), "http" | "https") {
        return Err(ApiError::BadRequest("base_url must be http(s)".into()));
    }
    crate::egress::admit_url(base_url, policy)
        .map_err(|e| ApiError::BadRequest(format!("base_url rejected: {e}")))?;
    Ok(parsed)
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
async fn create_mcp_http(
    state: &AppState,
    scope: TenantScope,
    owner: OwnerContext,
    req: CreateConnection,
) -> ApiResult<Json<Value>> {
    let base_url = req
        .base_url
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| ApiError::BadRequest("base_url is required for mcp_http".into()))?;
    let parsed = admit_connector_base_url(base_url, &state.egress_policy)?;
    match req.auth_kind.as_deref().unwrap_or("static") {
        "static" => {
            // Own the endpoint before `req` moves; a static mcp_http endpoint IS
            // the base_url.
            let endpoint = base_url.to_string();
            let row = create_mcp_http_connection(state, scope, owner, req, None).await?;
            // Photograph proves the credential works AND freezes the tool
            // surface; a refused credential must not leave a dangling connection
            // (mirrors the catalog api_key rollback).
            match crate::snapshots::photograph_connection(state, scope, row.id, &endpoint).await {
                Ok(snap) => Ok(Json(json!({
                    "connection": row,
                    "snapshot": crate::snapshots::snapshot_json(&snap),
                }))),
                Err(e) => {
                    fluidbox_db::revoke_connection(&state.pool, scope, row.id)
                        .await
                        .ok();
                    Err(crate::snapshots::rolled_back(
                        "the server rejected this credential",
                        e,
                    ))
                }
            }
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
            let sealed_secret = match req
                .client_secret
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
            {
                Some(s) => Some(
                    sealer
                        .seal(
                            s,
                            SealCtx::new(scope.tenant_id(), SealFamily::ConnectionClientSecret),
                        )
                        .await?,
                ),
                None => None,
            };
            let (cs_bytes, cs_kv) = crate::seal::Sealed::split(&sealed_secret);
            let row = fluidbox_db::create_connection(
                &state.pool,
                scope,
                &req.provider,
                &host,
                req.display_name.as_deref().unwrap_or(&host),
                None,
                1,
                &json!([]),
                &json!({}),
                &json!({ "base_url": base_url }),
                None,
                1,
                fluidbox_db::ConnectionAuth {
                    auth_kind: "oauth",
                    status: "pending",
                    oauth: Some(&oauth),
                    client_secret_sealed: cs_bytes,
                    client_secret_key_version: cs_kv,
                    registration_id: None,
                },
                owner.owner,
                owner.created_by_user_id,
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
/// `catalog_slug` (Some for a catalog/BYO connect) is recorded in metadata for
/// provenance; `endpoint_url` (= base_url for a static mcp_http server) is always
/// recorded so a later `/tools/refresh` knows exactly what to re-photograph.
pub(crate) async fn create_mcp_http_connection(
    state: &AppState,
    scope: TenantScope,
    owner: OwnerContext,
    req: CreateConnection,
    catalog_slug: Option<&str>,
) -> ApiResult<fluidbox_db::IntegrationConnectionRow> {
    let base_url = req
        .base_url
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| ApiError::BadRequest("base_url is required for mcp_http".into()))?;
    let parsed = admit_connector_base_url(base_url, &state.egress_policy)?;
    let sealer = sealer(state)?;
    let host = parsed.host_str().unwrap_or("mcp").to_string();
    let token = req.token.as_deref().map(str::trim).unwrap_or_default();
    if token.is_empty() {
        return Err(ApiError::BadRequest(
            "token is required for mcp_http (credential-free servers need no connection)".into(),
        ));
    }
    // For a static mcp_http server the MCP endpoint IS the base_url; store it as
    // `endpoint_url` so a later re-photograph resolves the same target.
    let mut metadata = json!({ "base_url": base_url, "endpoint_url": base_url });
    if let Some(slug) = catalog_slug.map(str::trim).filter(|s| !s.is_empty()) {
        metadata["catalog_slug"] = json!(slug);
    }
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
    let sealed = sealer
        .seal(
            token,
            SealCtx::new(scope.tenant_id(), SealFamily::ConnectionCredential),
        )
        .await?;
    Ok(fluidbox_db::create_connection(
        &state.pool,
        scope,
        "mcp_http",
        &host,
        req.display_name.as_deref().unwrap_or(&host),
        Some(&sealed.bytes),
        sealed.key_version,
        &json!([]),
        &json!({}),
        &metadata,
        None,
        1,
        fluidbox_db::ConnectionAuth::static_active(),
        owner.owner,
        owner.created_by_user_id,
    )
    .await?)
}

async fn create_github_pat(
    state: &AppState,
    scope: TenantScope,
    owner: OwnerContext,
    req: CreateConnection,
) -> ApiResult<Json<Value>> {
    let token = req.token.as_deref().map(str::trim).unwrap_or_default();
    if token.is_empty() {
        return Err(ApiError::BadRequest("token is required".into()));
    }
    let sealer = sealer(state)?;

    // Prove the token works and identify the account before storing anything.
    let (login, account_id, scopes) = connectors::github::validate_pat(state, token)
        .await
        .map_err(ApiError::BadRequest)?;

    let sealed = sealer
        .seal(
            token,
            SealCtx::new(scope.tenant_id(), SealFamily::ConnectionCredential),
        )
        .await?;
    let row = fluidbox_db::create_connection(
        &state.pool,
        scope,
        &req.provider,
        &account_id,
        req.display_name.as_deref().unwrap_or(&login),
        Some(&sealed.bytes),
        sealed.key_version,
        &serde_json::to_value(&scopes)?,
        &json!({}),
        &json!({ "login": login }),
        None,
        1,
        fluidbox_db::ConnectionAuth::static_active(),
        owner.owner,
        owner.created_by_user_id,
    )
    .await?;
    Ok(Json(json!({ "connection": row })))
}

async fn create_github_app(
    state: &AppState,
    scope: TenantScope,
    owner: OwnerContext,
    req: CreateConnection,
) -> ApiResult<Json<Value>> {
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

    let sealed_key = sealer
        .seal(
            &private_key,
            SealCtx::new(scope.tenant_id(), SealFamily::ConnectionCredential),
        )
        .await?;
    let sealed_webhook = sealer
        .seal(
            &webhook_secret,
            SealCtx::new(scope.tenant_id(), SealFamily::ConnectionWebhookSecret),
        )
        .await?;
    let row = match fluidbox_db::create_connection(
        &state.pool,
        scope,
        &req.provider,
        &installation_id,
        req.display_name
            .as_deref()
            .unwrap_or(&format!("{app_slug} → {account}")),
        Some(&sealed_key.bytes),
        sealed_key.key_version,
        &json!([]),
        &json!({}),
        &metadata,
        Some(&sealed_webhook.bytes),
        sealed_webhook.key_version,
        fluidbox_db::ConnectionAuth::static_active(),
        // github_app connections are ALWAYS organization-owned (system custody);
        // `resolve_owner` has already refused a `personal` request for this
        // provider, so `owner.owner` is guaranteed `Organization` here.
        owner.owner,
        owner.created_by_user_id,
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

pub async fn list(principal: Principal, State(state): State<AppState>) -> ApiResult<Json<Value>> {
    let scope = principal.scope();
    // Owner-filtered: a member sees org connections + only their own personal
    // rows; the operator sees all (design :274-296).
    let connections = fluidbox_db::list_connections_visible(
        &state.pool,
        scope,
        rbac::connection_viewer(&principal),
    )
    .await?;
    Ok(Json(json!({ "connections": connections })))
}

pub async fn revoke(
    principal: Principal,
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<Value>> {
    // Personal ⇒ owner-only (else 404); organization ⇒ admin/owner.
    let conn = connection_for_mutation(&state, &principal, id, "revoking").await?;
    let scope = principal.scope();
    let row = fluidbox_db::revoke_connection(&state.pool, scope, conn.id)
        .await?
        .ok_or_else(|| ApiError::Conflict("connection is already revoked".into()))?;
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
    principal: Principal,
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<Value>> {
    if !rbac::can_mutate_resources(&principal) {
        return Err(ApiError::Forbidden(
            "approving connections requires admin or owner".into(),
        ));
    }
    let scope = principal.scope();
    // approve applies ONLY to seamless github_app connections, which are ALWAYS
    // organization-owned (create refuses `personal` for github_app) — so the
    // unfiltered `get_connection` is equivalent to the visible variant here, and
    // `can_mutate_resources` above is the correct (org) gate. Tenant is known →
    // scoped_tx (RLS: set the GUC on this executor-generic read).
    let mut conn_tx = fluidbox_db::scoped_tx(&state.pool, scope).await?;
    let conn = fluidbox_db::get_connection(&mut *conn_tx, scope, id)
        .await?
        .ok_or(ApiError::NotFound)?;
    conn_tx.commit().await?;
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
    // Reactivating a github_app connection does NOT bump the authorization
    // generation (unlike an OAuth reconnect): the installation id is a
    // positively proven stable identity, so the logical account is unchanged and
    // in-flight bindings stay valid. Only the cached installation token is
    // evicted so a re-mint picks up the reconciled state.
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
    let mut reload_tx = fluidbox_db::scoped_tx(&state.pool, scope).await?;
    let row = fluidbox_db::get_connection(&mut *reload_tx, scope, row.id)
        .await?
        .ok_or_else(|| ApiError::Conflict("connection changed state underneath".into()))?;
    reload_tx.commit().await?;
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
    principal: Principal,
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    Query(q): Query<ReposQuery>,
) -> ApiResult<Json<Value>> {
    let scope = principal.scope();
    // Owner-filtered read: another member's personal connection is invisible
    // here (None ⇒ 404), so its repositories can never be browsed.
    let conn = fluidbox_db::get_connection_visible(
        &state.pool,
        scope,
        id,
        rbac::connection_viewer(&principal),
    )
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

#[cfg(test)]
mod tests {
    //! Pure-function coverage for `resolve_owner` (DB-free). The owner-filtered
    //! reads and `connection_for_mutation` need a live connection row, so their
    //! matrix (Alice/Bob personal isolation, admin-can't-see-personal, operator
    //! mutate-personal → 404) is deferred to the Task 9 CI e2e.
    use super::*;
    use crate::auth::{AuthContext, UserPrincipal};
    use fluidbox_db::{ConnectionOwner, TenantScope};

    fn operator() -> Principal {
        Principal::Operator {
            scope: TenantScope::assume(Uuid::now_v7()),
        }
    }

    fn egress_policy(dev: bool) -> crate::egress::EgressPolicy {
        crate::egress::EgressPolicy {
            dev_loopback: dev,
            allow_cidrs: vec![],
            github_clone_base: None,
            proxy: None,
        }
    }

    // I2: base_url admission at SAVE time. Both mcp_http create paths funnel
    // through `admit_connector_base_url`, so a private/metadata/plain-http
    // destination is a 400 at admission — and the e2e's loopback URLs still save
    // under the dev seam (the seam we must not break).
    #[test]
    fn base_url_admission_refuses_hostile_destinations() {
        let prod = egress_policy(false);
        // Bad scheme / unparseable → the pre-existing clear messages.
        assert!(matches!(
            admit_connector_base_url("ftp://mcp.example/x", &prod),
            Err(ApiError::BadRequest(m)) if m.contains("http(s)")
        ));
        assert!(matches!(
            admit_connector_base_url("not a url", &prod),
            Err(ApiError::BadRequest(_))
        ));
        // Private/metadata IP literals + plain-http are refused with the
        // admission reason (E3), and never echo the target.
        for u in [
            "https://169.254.169.254/mcp",
            "https://10.0.0.1/mcp",
            "http://mcp.example.com/mcp",
        ] {
            match admit_connector_base_url(u, &prod) {
                Err(ApiError::BadRequest(m)) => assert!(m.contains("base_url rejected"), "{m}"),
                other => panic!("{u} should be refused, got {other:?}"),
            }
        }
        // A public https server is admitted and the parsed URL flows back.
        let ok = admit_connector_base_url("https://mcp.example.com/mcp", &prod).unwrap();
        assert_eq!(ok.host_str(), Some("mcp.example.com"));
    }

    #[test]
    fn base_url_admission_preserves_the_dev_loopback_seam() {
        let dev = egress_policy(true);
        // The e2e saves loopback URLs; the dev seam must keep admitting them.
        assert!(admit_connector_base_url("http://127.0.0.1:8899/mcp", &dev).is_ok());
        // Metadata stays blocked even in dev.
        assert!(admit_connector_base_url("http://169.254.169.254/mcp", &dev).is_err());
    }

    fn user(roles: &[&str]) -> Principal {
        Principal::User(UserPrincipal {
            tenant_id: Uuid::now_v7(),
            user_id: Uuid::now_v7(),
            membership_id: Uuid::now_v7(),
            roles: roles.iter().map(|r| r.to_string()).collect(),
            auth: AuthContext::Pat {
                token_id: Uuid::now_v7(),
            },
        })
    }

    #[test]
    fn organization_default_requires_mutate_and_stamps_creator() {
        // Operator: org connection, no created_by (no personal identity).
        let op = operator();
        let ctx = resolve_owner(&op, "mcp_http", None).expect("operator may create org");
        assert!(matches!(ctx.owner, ConnectionOwner::Organization));
        assert_eq!(ctx.created_by_user_id, None);

        // Admin: org connection, created_by stamped from the principal.
        let admin = user(&["admin"]);
        let ctx =
            resolve_owner(&admin, "mcp_http", Some("organization")).expect("admin may create org");
        assert!(matches!(ctx.owner, ConnectionOwner::Organization));
        assert_eq!(ctx.created_by_user_id, admin.user_id());

        // Plain member: org connection refused (needs admin/owner).
        let member = user(&["member"]);
        assert!(matches!(
            resolve_owner(&member, "mcp_http", Some("organization")),
            Err(ApiError::Forbidden(_))
        ));
    }

    #[test]
    fn personal_is_open_to_any_member_but_not_the_operator() {
        // Any member — no elevated role — may own a personal connection.
        for roles in [&["member"][..], &["admin"][..], &["owner"][..]] {
            let p = user(roles);
            let ctx = resolve_owner(&p, "mcp_http", Some("personal"))
                .unwrap_or_else(|_| panic!("member {roles:?} may create personal"));
            match ctx.owner {
                ConnectionOwner::User(uid) => {
                    assert_eq!(Some(uid), p.user_id());
                    assert_eq!(ctx.created_by_user_id, p.user_id());
                }
                ConnectionOwner::Organization => panic!("expected a personal owner"),
            }
        }
        // The operator has no identity to own a personal row → 400.
        assert!(matches!(
            resolve_owner(&operator(), "mcp_http", Some("personal")),
            Err(ApiError::BadRequest(_))
        ));
    }

    #[test]
    fn github_app_refuses_personal_for_any_principal() {
        for p in [operator(), user(&["admin"]), user(&["owner"])] {
            assert!(
                matches!(
                    resolve_owner(&p, "github_app", Some("personal")),
                    Err(ApiError::BadRequest(_))
                ),
                "github_app must refuse personal"
            );
        }
        // github_app organization still works for an admin.
        let ctx = resolve_owner(&user(&["admin"]), "github_app", Some("organization"))
            .expect("github_app org is allowed");
        assert!(matches!(ctx.owner, ConnectionOwner::Organization));
    }

    #[test]
    fn unknown_owner_value_is_rejected() {
        assert!(matches!(
            resolve_owner(&user(&["admin"]), "mcp_http", Some("everyone")),
            Err(ApiError::BadRequest(_))
        ));
        // An empty/whitespace owner falls back to the organization default.
        let ctx = resolve_owner(&user(&["admin"]), "mcp_http", Some("  "))
            .expect("blank owner defaults to organization");
        assert!(matches!(ctx.owner, ConnectionOwner::Organization));
    }
}
