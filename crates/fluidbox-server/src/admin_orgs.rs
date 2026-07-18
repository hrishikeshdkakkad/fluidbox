//! `/v1/admin/orgs*` — the operator break-glass + IdP-lifecycle surface (Phase
//! B, Task 6).
//!
//! Design: `docs/plans/2026-07-17-idp-agnostic-identity-design.md` (break-glass
//! 666-735, lifecycle/issuer-migration 757-802, audit 379-403, config
//! statuses/immutability 157-227). Every route is `Admin`-token gated and is
//! exactly what the operator retains under `FLUIDBOX_REQUIRE_SSO=1`. No
//! `Principal` here — this is the deployment credential's own surface.
//!
//! Audit semantics (transcribed from the doc): an ACCEPTED mutation writes its
//! audit row INSIDE the mutation's transaction — that lives in the `fluidbox-db`
//! transactional fns, so a failed audit insert fails the mutation. A REJECTED
//! attempt (validation refusal, 409, active-owner refusal) is audited HERE in a
//! separate transaction committed after the refusal ([`refuse`] / [`reject_audit`]).
//!
//! Save-time discovery validation reuses `login`'s SSRF-hardened fetch machinery
//! ([`login::refresh_discovery`] / [`login::view_from`]) — the SSRF policy is
//! never duplicated.

use crate::auth::Admin;
use crate::error::{ApiError, ApiResult};
use crate::login;
use crate::state::AppState;
use axum::extract::{Path, State};
use axum::http::HeaderMap;
use axum::Json;
use chrono::{DateTime, Duration, Utc};
use fluidbox_db::identity::{self, IdpConfigParams, IdpPatch, LifecycleOutcome};
use fluidbox_db::TenantScope;
use serde::Deserialize;
use serde_json::{json, Value};
use uuid::Uuid;

const BOOTSTRAP_ARM_TTL_DAYS: i64 = 7;
const TOKEN_ENDPOINT_AUTH_METHODS: &[&str] = &["client_secret_basic", "client_secret_post", "none"];
const DEFAULT_ALGS: &[&str] = &[
    "RS256", "ES256", "PS256", "RS384", "ES384", "RS512", "ES512",
];
/// Roles an IdP `role_map`/`default_role` may yield without an explicit opt-in.
const MAPPABLE_ROLES: &[&str] = &["member", "approver", "admin"];
/// The full role set the operator role surface may assign (owner included).
const ASSIGNABLE_ROLES: &[&str] = &["member", "approver", "admin", "owner"];
const IMMUTABLE_IDP_FIELDS: &[&str] = &["issuer", "client_id", "generation"];

// ─── Pure validation helpers (unit-tested) ──────────────────────────────────

/// The org slug shape enforced by the `tenants_slug_shape` CHECK
/// (`^[a-z0-9][a-z0-9-]{0,62}$`), pre-validated in Rust for a friendly 400.
fn valid_slug(s: &str) -> bool {
    let b = s.as_bytes();
    if b.is_empty() || b.len() > 63 {
        return false;
    }
    let first = b[0].is_ascii_lowercase() || b[0].is_ascii_digit();
    first
        && b.iter()
            .all(|&c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-')
}

fn valid_token_endpoint_auth(auth: &str) -> bool {
    TOKEN_ENDPOINT_AUTH_METHODS.contains(&auth)
}

/// Reject any `none`/`HS*` (symmetric) entry outright, and require the rest to
/// be a known asymmetric algorithm (design lines 832-835).
fn validate_alg_allowlist(algs: &[String]) -> Result<(), String> {
    if algs.is_empty() {
        return Err("alg_allowlist must not be empty".into());
    }
    for a in algs {
        let u = a.to_ascii_uppercase();
        if u == "NONE" || u.starts_with("HS") {
            return Err(format!(
                "algorithm '{a}' is rejected: symmetric (HS*) and 'none' are never allowed"
            ));
        }
        let asymmetric = matches!(
            u.as_str(),
            "RS256"
                | "RS384"
                | "RS512"
                | "ES256"
                | "ES384"
                | "ES512"
                | "ES256K"
                | "PS256"
                | "PS384"
                | "PS512"
                | "EDDSA"
        );
        if !asymmetric {
            return Err(format!(
                "algorithm '{a}' is not a supported asymmetric algorithm"
            ));
        }
    }
    Ok(())
}

fn default_claim_mappings() -> Value {
    json!({
        "email": "email",
        "email_verified": "email_verified",
        "name": "name",
        "roles_path": "groups",
        "role_map": {},
        "default_role": "member",
        "require_email_verified": true
    })
}

/// Overlay the operator-provided keys onto the defaults, then validate the role
/// rules: `role_map` values and `default_role` ⊆ {member,approver,admin} unless
/// `allow_owner_mapping:true` (then `role_map` may also yield `owner`; the
/// default role is never `owner`) — design lines 218-227.
fn build_claim_mappings(provided: Option<&Value>) -> Result<Value, String> {
    let mut m = default_claim_mappings();
    if let Some(p) = provided {
        let obj = p
            .as_object()
            .ok_or_else(|| "claim_mappings must be a JSON object".to_string())?;
        let base = m.as_object_mut().expect("default is an object");
        for (k, v) in obj {
            base.insert(k.clone(), v.clone());
        }
    }
    let allow_owner = m
        .get("allow_owner_mapping")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let mut allowed: Vec<&str> = MAPPABLE_ROLES.to_vec();
    if allow_owner {
        allowed.push("owner");
    }
    if let Some(rm) = m.get("role_map") {
        let obj = rm
            .as_object()
            .ok_or_else(|| "claim_mappings.role_map must be a JSON object".to_string())?;
        for (group, mapped) in obj {
            let role = mapped
                .as_str()
                .ok_or_else(|| format!("role_map['{group}'] must be a string"))?;
            if !allowed.contains(&role) {
                if role == "owner" {
                    return Err(
                        "role_map may not grant 'owner' unless allow_owner_mapping is true".into(),
                    );
                }
                return Err(format!(
                    "role_map['{group}'] maps to an unknown role '{role}'"
                ));
            }
        }
    }
    let default_role = m
        .get("default_role")
        .and_then(Value::as_str)
        .unwrap_or("member");
    if !MAPPABLE_ROLES.contains(&default_role) {
        return Err(format!(
            "default_role '{default_role}' must be one of member, approver, admin"
        ));
    }
    Ok(m)
}

/// `token_endpoint_auth` must appear in the discovered
/// `token_endpoint_auth_methods_supported`; an ABSENT list implies the OIDC
/// default `client_secret_basic` only (design lines 216, 677-682).
fn auth_method_supported(auth: &str, meta: &Value) -> bool {
    match meta
        .get("token_endpoint_auth_methods_supported")
        .and_then(Value::as_array)
    {
        Some(arr) => arr.iter().filter_map(Value::as_str).any(|m| m == auth),
        None => auth == "client_secret_basic",
    }
}

/// Refuse only when `code_challenge_methods_supported` is PRESENT and lacks
/// `S256`; absent ⇒ accept (S256 is sendable regardless) — design lines 863.
fn pkce_ok(meta: &Value) -> bool {
    match meta
        .get("code_challenge_methods_supported")
        .and_then(Value::as_array)
    {
        Some(arr) => arr.iter().filter_map(Value::as_str).any(|m| m == "S256"),
        None => true,
    }
}

/// Which immutable identity field (if any) a PATCH body tries to change —
/// `issuer`/`client_id`/`generation` are fixed on an existing row (design lines
/// 187-192); changing an issuer is a migration, never an edit.
fn patch_immutable_field(body: &Value) -> Option<&'static str> {
    let obj = body.as_object()?;
    IMMUTABLE_IDP_FIELDS
        .iter()
        .copied()
        .find(|f| obj.contains_key(*f))
}

// ─── Request bodies ──────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub(crate) struct CreateOrgBody {
    slug: String,
    #[serde(default)]
    display_name: Option<String>,
}

#[derive(Deserialize)]
pub(crate) struct CreateIdpBody {
    issuer: String,
    client_id: String,
    #[serde(default)]
    client_secret: Option<String>,
    token_endpoint_auth: String,
    #[serde(default)]
    scopes: Option<Vec<String>>,
    #[serde(default)]
    claim_mappings: Option<Value>,
    #[serde(default)]
    alg_allowlist: Option<Vec<String>>,
    #[serde(default)]
    bootstrap_owner_email: Option<String>,
}

#[derive(Deserialize)]
pub(crate) struct MigrateBody {
    #[serde(flatten)]
    config: CreateIdpBody,
    #[serde(default)]
    carry_forward: bool,
}

#[derive(Deserialize)]
pub(crate) struct BreakGlassBody {
    email: String,
}

#[derive(Deserialize)]
pub(crate) struct RolesBody {
    roles: Vec<String>,
}

// ─── Shared handler helpers ──────────────────────────────────────────────────

fn source_ip(headers: &HeaderMap) -> Option<String> {
    let ip = login::client_ip(headers);
    (ip != "unknown").then_some(ip)
}

async fn resolve_org(state: &AppState, slug: &str) -> ApiResult<fluidbox_db::identity::OrgRow> {
    identity::get_org_by_slug(&state.pool, slug)
        .await?
        .ok_or(ApiError::NotFound)
}

/// Audit a rejected attempt in a SEPARATE transaction committed after the
/// refusal (design lines 398-402) — best effort against a fully dead database.
async fn reject_audit(
    state: &AppState,
    tenant_id: Option<Uuid>,
    source_ip: Option<&str>,
    action: &str,
    target: Option<&str>,
    reason: &str,
) {
    let Ok(mut conn) = state.pool.acquire().await else {
        return;
    };
    let detail = json!({ "reason": reason });
    let _ = identity::insert_audit(
        &mut conn,
        identity::AuditEntry {
            tenant_id,
            actor_kind: "operator",
            actor_id: None,
            source_ip,
            request_id: None,
            action,
            target,
            success: false,
            detail: Some(&detail),
        },
    )
    .await;
}

/// Record a rejected attempt and return the error to raise — the one-liner every
/// validation refusal uses so the audit-then-refuse order is uniform.
async fn refuse(
    state: &AppState,
    tenant_id: Uuid,
    source_ip: Option<&str>,
    action: &str,
    target: Option<&str>,
    err: ApiError,
) -> ApiError {
    let reason = err.to_string();
    reject_audit(state, Some(tenant_id), source_ip, action, target, &reason).await;
    err
}

// ─── Orgs ─────────────────────────────────────────────────────────────────────

pub async fn create_org(
    _: Admin,
    headers: HeaderMap,
    State(state): State<AppState>,
    Json(body): Json<CreateOrgBody>,
) -> ApiResult<Json<Value>> {
    let sip = source_ip(&headers);
    let slug = body.slug.trim().to_string();
    if !valid_slug(&slug) {
        reject_audit(
            &state,
            None,
            sip.as_deref(),
            "org.create",
            Some(&slug),
            "invalid slug shape",
        )
        .await;
        return Err(ApiError::BadRequest(
            "slug must match ^[a-z0-9][a-z0-9-]{0,62}$".into(),
        ));
    }
    match identity::create_org_audited(
        &state.pool,
        &slug,
        body.display_name.as_deref(),
        sip.as_deref(),
    )
    .await?
    {
        identity::CreateOrgOutcome::Created(org) => Ok(Json(json!({ "org": org }))),
        identity::CreateOrgOutcome::SlugConflict => {
            reject_audit(
                &state,
                None,
                sip.as_deref(),
                "org.create",
                Some(&slug),
                "slug taken",
            )
            .await;
            Err(ApiError::Conflict(
                "an organization with that slug already exists".into(),
            ))
        }
    }
}

pub async fn list_orgs(_: Admin, State(state): State<AppState>) -> ApiResult<Json<Value>> {
    let orgs = identity::list_orgs(&state.pool).await?;
    Ok(Json(json!({ "orgs": orgs })))
}

// ─── IdP configs ──────────────────────────────────────────────────────────────

pub async fn list_idp(
    _: Admin,
    State(state): State<AppState>,
    Path(slug): Path<String>,
) -> ApiResult<Json<Value>> {
    let org = resolve_org(&state, &slug).await?;
    let scope = TenantScope::assume(org.id);
    let configs = identity::list_idp_configs(&state.pool, scope).await?;
    Ok(Json(json!({ "idp_configs": configs })))
}

/// Full save-time validation + staging, shared by `create_idp` and the migrate
/// swap's phase 1. On any refusal it audits `action` (rejected) — `idp.create`
/// for the create route, `idp.migrate` for the migrate path, so per-action
/// filtering stays clean — and returns the error. On success it returns the
/// freshly staged, discovery-cached row.
async fn validate_and_stage_config(
    state: &AppState,
    scope: TenantScope,
    body: &CreateIdpBody,
    sip: Option<&str>,
    action: &str,
) -> ApiResult<identity::OrgIdpConfigRow> {
    let tenant = scope.tenant_id();
    let bad = |e: ApiError| async move { refuse(state, tenant, sip, action, None, e).await };

    if body.issuer.trim().is_empty() {
        return Err(bad(ApiError::BadRequest("issuer is required".into())).await);
    }
    if !valid_token_endpoint_auth(&body.token_endpoint_auth) {
        return Err(bad(ApiError::BadRequest(
            "token_endpoint_auth must be client_secret_basic, client_secret_post, or none".into(),
        ))
        .await);
    }
    // client_secret coherence: confidential methods require a secret; a public
    // client (none) must not carry one.
    let public_client = body.token_endpoint_auth == "none";
    if public_client && body.client_secret.is_some() {
        return Err(bad(ApiError::BadRequest(
            "a public client (token_endpoint_auth=none) must not carry a client_secret".into(),
        ))
        .await);
    }
    if !public_client && body.client_secret.is_none() {
        return Err(bad(ApiError::BadRequest(format!(
            "token_endpoint_auth={} requires a client_secret",
            body.token_endpoint_auth
        )))
        .await);
    }

    // alg_allowlist: provided or the asymmetric default; validated either way.
    let algs: Vec<String> = body
        .alg_allowlist
        .clone()
        .unwrap_or_else(|| DEFAULT_ALGS.iter().map(|s| s.to_string()).collect());
    if let Err(e) = validate_alg_allowlist(&algs) {
        return Err(bad(ApiError::BadRequest(e)).await);
    }

    // claim_mappings: defaults filled, role rules enforced.
    let mappings = match build_claim_mappings(body.claim_mappings.as_ref()) {
        Ok(m) => m,
        Err(e) => return Err(bad(ApiError::BadRequest(e)).await),
    };

    // bootstrap_owner_email: normalized + armed, refused while an active owner
    // exists (design lines 709-711).
    let bootstrap_email = match &body.bootstrap_owner_email {
        Some(e) if !e.trim().is_empty() => Some(login::normalize_email(e)),
        _ => None,
    };
    let bootstrap_expires = if bootstrap_email.is_some() {
        if owner_exists(state, scope).await? {
            return Err(refuse(
                state,
                tenant,
                sip,
                action,
                None,
                ApiError::Conflict(
                    "an active owner already exists; deactivate it before arming a bootstrap owner"
                        .into(),
                ),
            )
            .await);
        }
        Some(Utc::now() + Duration::days(BOOTSTRAP_ARM_TTL_DAYS))
    } else {
        None
    };

    // Discovery: fetch + validate over the SSRF-hardened client (reused).
    let (meta, jwks) = match login::refresh_discovery(state, &body.issuer).await {
        Ok(v) => v,
        Err(e) => {
            return Err(bad(ApiError::BadRequest(format!(
                "issuer discovery failed: {e}"
            )))
            .await)
        }
    };
    if let Err(e) = login::view_from(&meta, jwks.clone()) {
        return Err(bad(ApiError::BadRequest(format!(
            "discovery is non-conformant: {e}"
        )))
        .await);
    }
    if !auth_method_supported(&body.token_endpoint_auth, &meta) {
        return Err(bad(ApiError::BadRequest(format!(
            "token_endpoint_auth={} is not advertised by the issuer",
            body.token_endpoint_auth
        )))
        .await);
    }
    if !pkce_ok(&meta) {
        return Err(bad(ApiError::BadRequest(
            "the issuer advertises code_challenge_methods_supported without S256".into(),
        ))
        .await);
    }

    // Seal the client secret (requires the Sealer).
    let sealed = match &body.client_secret {
        Some(secret) => {
            let sealer = match crate::oauth::sealer(state) {
                Ok(s) => s,
                Err(e) => return Err(refuse(state, tenant, sip, action, None, e).await),
            };
            Some(sealer.seal(secret))
        }
        None => None,
    };

    let scopes: Vec<String> = body.scopes.clone().unwrap_or_else(|| {
        ["openid", "email", "profile"]
            .iter()
            .map(|s| s.to_string())
            .collect()
    });
    let now = Utc::now();
    let params = IdpConfigParams {
        issuer: body.issuer.trim(),
        client_id: &body.client_id,
        client_secret_sealed: sealed,
        token_endpoint_auth: &body.token_endpoint_auth,
        scopes: &scopes,
        alg_allowlist: &algs,
        claim_mappings: &mappings,
        bootstrap_owner_email: bootstrap_email.as_deref(),
        bootstrap_owner_expires_at: bootstrap_expires,
        created_by: Some("operator"),
        discovered_metadata: Some(&meta),
        jwks: Some(&jwks),
        discovered_at: Some(now),
    };
    let row = identity::create_idp_config_audited(&state.pool, scope, params, sip).await?;
    Ok(row)
}

pub async fn create_idp(
    _: Admin,
    headers: HeaderMap,
    State(state): State<AppState>,
    Path(slug): Path<String>,
    Json(body): Json<CreateIdpBody>,
) -> ApiResult<Json<Value>> {
    let sip = source_ip(&headers);
    let org = resolve_org(&state, &slug).await?;
    let scope = TenantScope::assume(org.id);
    let row = validate_and_stage_config(&state, scope, &body, sip.as_deref(), "idp.create").await?;
    Ok(Json(json!({ "idp": row })))
}

pub async fn activate_idp(
    _: Admin,
    headers: HeaderMap,
    State(state): State<AppState>,
    Path((slug, id)): Path<(String, Uuid)>,
) -> ApiResult<Json<Value>> {
    let sip = source_ip(&headers);
    let org = resolve_org(&state, &slug).await?;
    let scope = TenantScope::assume(org.id);
    match identity::activate_idp_config(&state.pool, scope, id, sip.as_deref()).await? {
        LifecycleOutcome::Done(row) => Ok(Json(json!({ "idp": row }))),
        LifecycleOutcome::NotFound => Err(ApiError::NotFound),
        LifecycleOutcome::Refused(reason) => {
            Err(refuse_lifecycle(&state, org.id, sip.as_deref(), "idp.activate", id, reason).await)
        }
    }
}

pub async fn disable_idp(
    _: Admin,
    headers: HeaderMap,
    State(state): State<AppState>,
    Path((slug, id)): Path<(String, Uuid)>,
) -> ApiResult<Json<Value>> {
    let sip = source_ip(&headers);
    let org = resolve_org(&state, &slug).await?;
    let scope = TenantScope::assume(org.id);
    match identity::disable_idp_config(&state.pool, scope, id, sip.as_deref()).await? {
        LifecycleOutcome::Done(c) => Ok(Json(json!({
            "status": "disabled",
            "flows_cancelled": c.flows_cancelled,
            "switches_cancelled": c.switches_cancelled,
            "sessions_revoked": c.sessions_revoked,
        }))),
        LifecycleOutcome::NotFound => Err(ApiError::NotFound),
        LifecycleOutcome::Refused(reason) => {
            Err(refuse_lifecycle(&state, org.id, sip.as_deref(), "idp.disable", id, reason).await)
        }
    }
}

pub async fn reactivate_idp(
    _: Admin,
    headers: HeaderMap,
    State(state): State<AppState>,
    Path((slug, id)): Path<(String, Uuid)>,
) -> ApiResult<Json<Value>> {
    let sip = source_ip(&headers);
    let org = resolve_org(&state, &slug).await?;
    let scope = TenantScope::assume(org.id);
    match identity::reactivate_idp_config(&state.pool, scope, id, sip.as_deref()).await? {
        LifecycleOutcome::Done(row) => Ok(Json(json!({ "idp": row }))),
        LifecycleOutcome::NotFound => Err(ApiError::NotFound),
        LifecycleOutcome::Refused(reason) => {
            Err(
                refuse_lifecycle(&state, org.id, sip.as_deref(), "idp.reactivate", id, reason)
                    .await,
            )
        }
    }
}

pub async fn patch_idp(
    _: Admin,
    headers: HeaderMap,
    State(state): State<AppState>,
    Path((slug, id)): Path<(String, Uuid)>,
    Json(body): Json<Value>,
) -> ApiResult<Json<Value>> {
    let sip = source_ip(&headers);
    let org = resolve_org(&state, &slug).await?;
    let scope = TenantScope::assume(org.id);
    let config = identity::get_idp_config(&state.pool, scope, id)
        .await?
        .ok_or(ApiError::NotFound)?;

    // Identity fields are immutable — steer the operator to a migration.
    if let Some(f) = patch_immutable_field(&body) {
        return Err(refuse(
            &state,
            org.id,
            sip.as_deref(),
            "idp.patch",
            Some(&id.to_string()),
            ApiError::BadRequest(format!(
                "{f} is immutable; fix identity fields with POST …/idp/{{id}}/migrate"
            )),
        )
        .await);
    }
    let obj = body
        .as_object()
        .ok_or_else(|| ApiError::BadRequest("body must be a JSON object".into()))?;
    let tgt = id.to_string();
    let bad = |e: ApiError| async {
        refuse(&state, org.id, sip.as_deref(), "idp.patch", Some(&tgt), e).await
    };

    // token_endpoint_auth: validated against the config's cached (or refreshed)
    // discovery methods.
    let new_auth: Option<String> = match obj.get("token_endpoint_auth") {
        Some(v) => {
            let a = v
                .as_str()
                .ok_or_else(|| ApiError::BadRequest("token_endpoint_auth must be a string".into()))?
                .to_string();
            if !valid_token_endpoint_auth(&a) {
                return Err(bad(ApiError::BadRequest(
                    "token_endpoint_auth must be client_secret_basic, client_secret_post, or none"
                        .into(),
                ))
                .await);
            }
            let meta = config_discovery_meta(&state, &config).await?;
            if !auth_method_supported(&a, &meta) {
                return Err(bad(ApiError::BadRequest(format!(
                    "token_endpoint_auth={a} is not advertised by the issuer"
                )))
                .await);
            }
            Some(a)
        }
        None => None,
    };

    // scopes
    let new_scopes: Option<Vec<String>> = match obj.get("scopes") {
        Some(v) => Some(
            serde_json::from_value(v.clone())
                .map_err(|_| ApiError::BadRequest("scopes must be an array of strings".into()))?,
        ),
        None => None,
    };

    // claim_mappings: role rules re-validated + defaults filled.
    let new_mappings: Option<Value> = match obj.get("claim_mappings") {
        Some(v) => match build_claim_mappings(Some(v)) {
            Ok(m) => Some(m),
            Err(e) => return Err(bad(ApiError::BadRequest(e)).await),
        },
        None => None,
    };

    // alg_allowlist: HS*/none re-rejected.
    let new_algs: Option<Vec<String>> = match obj.get("alg_allowlist") {
        Some(v) => {
            let a: Vec<String> = serde_json::from_value(v.clone()).map_err(|_| {
                ApiError::BadRequest("alg_allowlist must be an array of strings".into())
            })?;
            if let Err(e) = validate_alg_allowlist(&a) {
                return Err(bad(ApiError::BadRequest(e)).await);
            }
            Some(a)
        }
        None => None,
    };

    // client_secret: re-sealed (requires the Sealer), no generation bump.
    let new_secret: Option<Vec<u8>> = match obj.get("client_secret").and_then(Value::as_str) {
        Some(secret) => {
            let sealer = match crate::oauth::sealer(&state) {
                Ok(s) => s,
                Err(e) => return Err(bad(e).await),
            };
            Some(sealer.seal(secret))
        }
        None => None,
    };

    // bootstrap_owner_email: re-armed (+7d), refused (in the DB fn) while an
    // active owner exists.
    let new_bootstrap: Option<(String, DateTime<Utc>)> =
        match obj.get("bootstrap_owner_email").and_then(Value::as_str) {
            Some(e) if !e.trim().is_empty() => Some((
                login::normalize_email(e),
                Utc::now() + Duration::days(BOOTSTRAP_ARM_TTL_DAYS),
            )),
            _ => None,
        };

    let patch = IdpPatch {
        client_secret_sealed: new_secret,
        token_endpoint_auth: new_auth.as_deref(),
        scopes: new_scopes.as_deref(),
        claim_mappings: new_mappings.as_ref(),
        alg_allowlist: new_algs.as_deref(),
        bootstrap: new_bootstrap
            .as_ref()
            .map(|(email, exp)| (email.as_str(), *exp)),
    };
    match identity::patch_idp_config(&state.pool, scope, id, patch, sip.as_deref()).await? {
        LifecycleOutcome::Done(row) => Ok(Json(json!({ "idp": row }))),
        LifecycleOutcome::NotFound => Err(ApiError::NotFound),
        LifecycleOutcome::Refused(reason) => {
            Err(refuse_lifecycle(&state, org.id, sip.as_deref(), "idp.patch", id, reason).await)
        }
    }
}

pub async fn migrate_idp(
    _: Admin,
    headers: HeaderMap,
    State(state): State<AppState>,
    Path((slug, id)): Path<(String, Uuid)>,
    Json(body): Json<MigrateBody>,
) -> ApiResult<Json<Value>> {
    let sip = source_ip(&headers);
    let org = resolve_org(&state, &slug).await?;
    let scope = TenantScope::assume(org.id);

    // Pre-check the OLD config is active BEFORE staging the new one, so a wrong
    // target does not leave an orphan staged config (the swap re-checks under
    // the lock as the authority).
    let old = identity::get_idp_config(&state.pool, scope, id)
        .await?
        .ok_or(ApiError::NotFound)?;
    if old.status != "active" {
        return Err(refuse(
            &state,
            org.id,
            sip.as_deref(),
            "idp.migrate",
            Some(&id.to_string()),
            ApiError::Conflict("the configuration being migrated must be active".into()),
        )
        .await);
    }

    // Phase 1: stage + fully validate the new (generation+1) config. Refusals
    // audit "idp.migrate" (not "idp.create") so the migrate path stays filterable.
    let new = validate_and_stage_config(&state, scope, &body.config, sip.as_deref(), "idp.migrate")
        .await?;

    // Phase 2: the atomic swap.
    match identity::migrate_idp_config(
        &state.pool,
        scope,
        id,
        new.id,
        body.carry_forward,
        sip.as_deref(),
    )
    .await?
    {
        LifecycleOutcome::Done(c) => Ok(Json(json!({
            "old_config": id,
            "new_config": new.id,
            "carry_forward": body.carry_forward,
            "flows_cancelled": c.flows_cancelled,
            "switches_cancelled": c.switches_cancelled,
            "sessions_revoked": c.sessions_revoked,
            "memberships_deactivated": c.memberships_deactivated,
        }))),
        LifecycleOutcome::NotFound => Err(ApiError::NotFound),
        LifecycleOutcome::Refused(reason) => {
            Err(refuse_lifecycle(&state, org.id, sip.as_deref(), "idp.migrate", id, reason).await)
        }
    }
}

// ─── Break-glass owner ────────────────────────────────────────────────────────

pub async fn break_glass_owner(
    _: Admin,
    headers: HeaderMap,
    State(state): State<AppState>,
    Path(slug): Path<String>,
    Json(body): Json<BreakGlassBody>,
) -> ApiResult<Json<Value>> {
    let sip = source_ip(&headers);
    let org = resolve_org(&state, &slug).await?;
    let scope = TenantScope::assume(org.id);
    let email = body.email.trim();
    if email.is_empty() || !email.contains('@') {
        return Err(refuse(
            &state,
            org.id,
            sip.as_deref(),
            "break_glass.arm",
            None,
            ApiError::BadRequest("a valid email address is required".into()),
        )
        .await);
    }
    let normalized = login::normalize_email(email);
    let Some(active) = identity::active_idp_config(&state.pool, org.id).await? else {
        return Err(refuse(
            &state,
            org.id,
            sip.as_deref(),
            "break_glass.arm",
            None,
            ApiError::Conflict("no active IdP configuration to arm".into()),
        )
        .await);
    };
    let expires_at = Utc::now() + Duration::days(BOOTSTRAP_ARM_TTL_DAYS);
    match identity::arm_bootstrap_owner(
        &state.pool,
        scope,
        active.id,
        &normalized,
        expires_at,
        sip.as_deref(),
    )
    .await?
    {
        LifecycleOutcome::Done(arm_id) => Ok(Json(json!({
            "armed": true,
            "arm_id": arm_id,
            "config": active.id,
            "expires_at": expires_at,
        }))),
        LifecycleOutcome::NotFound => Err(ApiError::NotFound),
        LifecycleOutcome::Refused(reason) => Err(refuse_lifecycle(
            &state,
            org.id,
            sip.as_deref(),
            "break_glass.arm",
            active.id,
            reason,
        )
        .await),
    }
}

// ─── Membership admin ─────────────────────────────────────────────────────────

pub async fn list_members(
    _: Admin,
    State(state): State<AppState>,
    Path(slug): Path<String>,
) -> ApiResult<Json<Value>> {
    let org = resolve_org(&state, &slug).await?;
    let scope = TenantScope::assume(org.id);
    let members = identity::list_members(&state.pool, scope).await?;
    Ok(Json(json!({ "members": members })))
}

pub async fn deactivate_member(
    _: Admin,
    headers: HeaderMap,
    State(state): State<AppState>,
    Path((slug, membership_id)): Path<(String, Uuid)>,
) -> ApiResult<Json<Value>> {
    let sip = source_ip(&headers);
    let org = resolve_org(&state, &slug).await?;
    let scope = TenantScope::assume(org.id);
    match identity::deactivate_membership_audited(&state.pool, scope, membership_id, sip.as_deref())
        .await?
    {
        Some(m) => Ok(Json(json!({ "membership": m }))),
        None => Err(ApiError::NotFound),
    }
}

pub async fn set_member_roles(
    _: Admin,
    headers: HeaderMap,
    State(state): State<AppState>,
    Path((slug, membership_id)): Path<(String, Uuid)>,
    Json(body): Json<RolesBody>,
) -> ApiResult<Json<Value>> {
    let sip = source_ip(&headers);
    let org = resolve_org(&state, &slug).await?;
    let scope = TenantScope::assume(org.id);
    if body.roles.is_empty() {
        return Err(refuse(
            &state,
            org.id,
            sip.as_deref(),
            "member.roles",
            Some(&membership_id.to_string()),
            ApiError::BadRequest("at least one role is required".into()),
        )
        .await);
    }
    for role in &body.roles {
        if !ASSIGNABLE_ROLES.contains(&role.as_str()) {
            return Err(refuse(
                &state,
                org.id,
                sip.as_deref(),
                "member.roles",
                Some(&membership_id.to_string()),
                ApiError::BadRequest(format!(
                    "'{role}' is not a valid role (member, approver, admin, owner)"
                )),
            )
            .await);
        }
    }
    // Dedup while preserving order.
    let mut roles: Vec<String> = Vec::new();
    for r in &body.roles {
        if !roles.iter().any(|x| x == r) {
            roles.push(r.clone());
        }
    }
    match identity::set_membership_roles_audited(
        &state.pool,
        scope,
        membership_id,
        &roles,
        sip.as_deref(),
    )
    .await?
    {
        Some(m) => Ok(Json(json!({ "membership": m }))),
        None => Err(ApiError::NotFound),
    }
}

// ─── shared refusal helper for the lifecycle DB outcomes ─────────────────────

/// Audit a refused lifecycle transition (a config conflict) and return the 409.
async fn refuse_lifecycle(
    state: &AppState,
    tenant_id: Uuid,
    source_ip: Option<&str>,
    action: &str,
    target: Uuid,
    reason: &'static str,
) -> ApiError {
    let tgt = target.to_string();
    refuse(
        state,
        tenant_id,
        source_ip,
        action,
        Some(&tgt),
        ApiError::Conflict(reason.into()),
    )
    .await
}

/// The config's discovery metadata: the cached photograph, or a fresh fetch if
/// the row somehow has none (reuses the SSRF-hardened machinery).
async fn config_discovery_meta(
    state: &AppState,
    config: &identity::OrgIdpConfigRow,
) -> ApiResult<Value> {
    if let Some(m) = &config.discovered_metadata {
        return Ok(m.clone());
    }
    let (meta, _jwks) = login::refresh_discovery(state, &config.issuer)
        .await
        .map_err(|e| ApiError::BadRequest(format!("issuer discovery failed: {e}")))?;
    Ok(meta)
}

/// Reader for the org-wide active-owner precondition (create-time bootstrap
/// arming). Acquires a connection to reuse the executor-generic DB helper.
async fn owner_exists(state: &AppState, scope: TenantScope) -> ApiResult<bool> {
    let mut conn = state.pool.acquire().await?;
    Ok(identity::active_owner_exists(&mut conn, scope).await?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slug_shape_matches_the_db_check() {
        assert!(valid_slug("acme"));
        assert!(valid_slug("a"));
        assert!(valid_slug("acme-corp-1"));
        assert!(valid_slug("0acme"));
        assert!(!valid_slug(""));
        assert!(!valid_slug("-acme")); // must start alnum
        assert!(!valid_slug("Acme")); // uppercase
        assert!(!valid_slug("acme_corp")); // underscore
        assert!(!valid_slug("acme corp")); // space
        assert!(!valid_slug(&"a".repeat(64))); // too long
        assert!(valid_slug(&"a".repeat(63)));
    }

    #[test]
    fn token_endpoint_auth_membership() {
        assert!(valid_token_endpoint_auth("client_secret_basic"));
        assert!(valid_token_endpoint_auth("client_secret_post"));
        assert!(valid_token_endpoint_auth("none"));
        assert!(!valid_token_endpoint_auth("private_key_jwt"));
        assert!(!valid_token_endpoint_auth(""));
    }

    #[test]
    fn alg_allowlist_rejects_symmetric_and_none() {
        assert!(validate_alg_allowlist(&["RS256".into(), "ES256".into()]).is_ok());
        assert!(validate_alg_allowlist(&["EdDSA".into()]).is_ok());
        assert!(validate_alg_allowlist(&["HS256".into()]).is_err());
        assert!(validate_alg_allowlist(&["hs512".into()]).is_err()); // case-insensitive
        assert!(validate_alg_allowlist(&["none".into()]).is_err());
        assert!(validate_alg_allowlist(&["NONE".into()]).is_err());
        assert!(validate_alg_allowlist(&["RS256".into(), "HS256".into()]).is_err()); // one bad entry taints
        assert!(validate_alg_allowlist(&["banana".into()]).is_err());
        assert!(validate_alg_allowlist(&[]).is_err());
    }

    #[test]
    fn role_map_owner_requires_opt_in() {
        // Default: role_map to member/approver/admin ok.
        let ok = json!({ "role_map": { "eng": "admin", "ops": "approver" } });
        assert!(build_claim_mappings(Some(&ok)).is_ok());
        // owner without opt-in → refused.
        let owner = json!({ "role_map": { "root": "owner" } });
        assert!(build_claim_mappings(Some(&owner)).is_err());
        // owner WITH opt-in → allowed.
        let owner_ok = json!({ "allow_owner_mapping": true, "role_map": { "root": "owner" } });
        assert!(build_claim_mappings(Some(&owner_ok)).is_ok());
        // unknown role → refused even with opt-in.
        let unknown = json!({ "allow_owner_mapping": true, "role_map": { "x": "superuser" } });
        assert!(build_claim_mappings(Some(&unknown)).is_err());
        // default_role is never owner, even with opt-in.
        let def_owner = json!({ "allow_owner_mapping": true, "default_role": "owner" });
        assert!(build_claim_mappings(Some(&def_owner)).is_err());
        // defaults are filled when absent.
        let filled = build_claim_mappings(None).unwrap();
        assert_eq!(filled["require_email_verified"], json!(true));
        assert_eq!(filled["default_role"], json!("member"));
    }

    #[test]
    fn auth_method_validation_against_discovery() {
        // Present list: membership required.
        let meta =
            json!({ "token_endpoint_auth_methods_supported": ["client_secret_post", "none"] });
        assert!(auth_method_supported("client_secret_post", &meta));
        assert!(auth_method_supported("none", &meta));
        assert!(!auth_method_supported("client_secret_basic", &meta));
        // Absent list: OIDC default → basic only.
        let empty = json!({});
        assert!(auth_method_supported("client_secret_basic", &empty));
        assert!(!auth_method_supported("client_secret_post", &empty));
        assert!(!auth_method_supported("none", &empty));
    }

    #[test]
    fn pkce_validation() {
        assert!(pkce_ok(
            &json!({ "code_challenge_methods_supported": ["S256"] })
        ));
        assert!(pkce_ok(
            &json!({ "code_challenge_methods_supported": ["plain", "S256"] })
        ));
        // Present without S256 → refuse.
        assert!(!pkce_ok(
            &json!({ "code_challenge_methods_supported": ["plain"] })
        ));
        // Absent → accept.
        assert!(pkce_ok(&json!({})));
    }

    #[test]
    fn patch_immutable_field_classification() {
        assert_eq!(
            patch_immutable_field(&json!({ "issuer": "https://x" })),
            Some("issuer")
        );
        assert_eq!(
            patch_immutable_field(&json!({ "client_id": "abc" })),
            Some("client_id")
        );
        assert_eq!(
            patch_immutable_field(&json!({ "generation": 2 })),
            Some("generation")
        );
        // Purely mutable body → nothing forbidden.
        assert_eq!(
            patch_immutable_field(&json!({ "scopes": ["openid"], "token_endpoint_auth": "none" })),
            None
        );
    }
}
