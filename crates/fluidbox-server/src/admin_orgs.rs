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
use axum::extract::rejection::JsonRejection;
use axum::extract::{ConnectInfo, Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use chrono::{DateTime, Duration, Utc};
use fluidbox_db::identity::{self, IdpConfigParams, IdpPatch, LifecycleOutcome};
use fluidbox_db::TenantScope;
use serde::Deserialize;
use serde_json::{json, Value};
use std::net::SocketAddr;
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

/// Require every entry to EXACTLY match an algorithm the verifier implements —
/// so a saved allowlist can never carry a non-functional alg (EdDSA/ES256K), a
/// symmetric/`none` alg, or a mis-cased spelling that would fail only at login
/// rather than at save (design lines 169-171, 832-835). JOSE `alg` values are
/// case-SENSITIVE (RFC 7515) and the verifier compares the JWT header alg
/// against these entries verbatim, so a case-folding shim would let e.g.
/// `rs256` validate here yet never match `RS256` at login. `none`/HS* need no
/// special-case — they are simply absent from the asymmetric implemented set.
/// The implemented-set is defined once, in `login::IMPLEMENTED_ALGS`.
fn validate_alg_allowlist(algs: &[String]) -> Result<(), String> {
    if algs.is_empty() {
        return Err("alg_allowlist must not be empty".into());
    }
    for a in algs {
        if !crate::login::IMPLEMENTED_ALGS.contains(&a.as_str()) {
            return Err(format!(
                "algorithm '{a}' is not supported; supported algorithms (exact case): {}",
                crate::login::IMPLEMENTED_ALGS.join(", ")
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

/// The three-way classification of an OIDC-discovery list field: genuinely
/// ABSENT (accept the documented default), a well-formed array of strings
/// (evaluate membership), or PRESENT-but-MALFORMED — a non-array value, an
/// explicit `null`, or an array carrying a non-string element. A malformed
/// field is REFUSED at save rather than collapsing into the absent/accept
/// branch: only a genuinely absent field keeps the documented acceptance
/// (design lines 169-171, 863). `filter_map(as_str)` alone would silently drop
/// a non-string element and treat `"S256"` (a string, not an array) as an
/// empty/absent list — the collapse this closes.
enum MetaList<'a> {
    Absent,
    Malformed,
    Values(Vec<&'a str>),
}

fn meta_list<'a>(meta: &'a Value, key: &str) -> MetaList<'a> {
    match meta.get(key) {
        None => MetaList::Absent,
        Some(Value::Array(arr)) => {
            let mut out = Vec::with_capacity(arr.len());
            for v in arr {
                match v.as_str() {
                    Some(s) => out.push(s),
                    None => return MetaList::Malformed,
                }
            }
            MetaList::Values(out)
        }
        // A present non-array (string/number/object/bool) or explicit null is
        // malformed metadata, not an absent field.
        Some(_) => MetaList::Malformed,
    }
}

/// `token_endpoint_auth` must appear in the discovered
/// `token_endpoint_auth_methods_supported`; an ABSENT list implies the OIDC
/// default `client_secret_basic` only (design lines 216, 677-682). A PRESENT-
/// but-malformed list is refused (never silently treated as absent).
fn auth_method_supported(auth: &str, meta: &Value) -> bool {
    match meta_list(meta, "token_endpoint_auth_methods_supported") {
        MetaList::Absent => auth == "client_secret_basic",
        MetaList::Malformed => false,
        MetaList::Values(v) => v.contains(&auth),
    }
}

/// Refuse when `code_challenge_methods_supported` is PRESENT and lacks `S256`,
/// AND when it is present but malformed; absent ⇒ accept (S256 is sendable
/// regardless) — design line 863.
///
/// OIDC discovery makes `code_challenge_methods_supported` an OPTIONAL field:
/// the conformance floor (design 856-871) requires the IdP to *support* PKCE
/// S256, not to *advertise* it. An issuer that omits the field entirely still
/// meets the floor (we always send S256); one that advertises the field but
/// omits S256 — or advertises it as a non-array / non-string — is declaring it
/// cannot do S256 (or is serving malformed metadata), and is refused.
fn pkce_ok(meta: &Value) -> bool {
    match meta_list(meta, "code_challenge_methods_supported") {
        MetaList::Absent => true,
        MetaList::Malformed => false,
        MetaList::Values(v) => v.contains(&"S256"),
    }
}

/// When the issuer advertises `response_types_supported`, require an entry that
/// carries the `code` response type (the authorization-code flow the floor
/// requires). Absent ⇒ accept (OIDC makes the field optional; the floor requires
/// the *capability*, and every conformant provider serves `code`). A present-
/// but-malformed list is refused.
fn response_type_code_ok(meta: &Value) -> bool {
    match meta_list(meta, "response_types_supported") {
        MetaList::Absent => true,
        MetaList::Malformed => false,
        MetaList::Values(v) => v
            .iter()
            .any(|rt| rt.split_whitespace().any(|t| t == "code")),
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

/// serde helper distinguishing an ABSENT field from a present `null`. With
/// `#[serde(default, deserialize_with = "double_option")]` a field yields `None`
/// when the key is absent, `Some(None)` when present as `null`, and `Some(Some(v))`
/// for a value — the three states the client_secret PATCH leg needs.
fn double_option<'de, D, T>(de: D) -> Result<Option<Option<T>>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    Ok(Some(Option::deserialize(de)?))
}

/// The strict IdP PATCH body. `deny_unknown_fields` rejects typos/garbage keys
/// and every value field is typed, so a malformed field type is a hard 400
/// (audited), never silently ignored. Identity fields (issuer/client_id/
/// generation) are NOT listed here — the handler checks the raw body for them
/// FIRST and returns the specific "immutable → migrate" message before this
/// strict parse runs, so `deny_unknown_fields` never masks that steer.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PatchIdpBody {
    #[serde(default)]
    token_endpoint_auth: Option<String>,
    #[serde(default)]
    scopes: Option<Vec<String>>,
    #[serde(default)]
    claim_mappings: Option<Value>,
    #[serde(default)]
    alg_allowlist: Option<Vec<String>>,
    #[serde(default)]
    bootstrap_owner_email: Option<String>,
    /// tri-state: absent = keep, null = clear, string = re-seal.
    #[serde(default, deserialize_with = "double_option")]
    client_secret: Option<Option<String>>,
}

// ─── Shared handler helpers ──────────────────────────────────────────────────

/// The audit `source_ip` for an operator mutation: the socket peer unless a
/// trusted proxy is declared (`FLUIDBOX_TRUST_FORWARDED_FOR`), never a
/// client-forgeable `X-Forwarded-For`. `None` collapses the "unknown" sentinel.
fn source_ip(headers: &HeaderMap, peer: SocketAddr, trust: bool) -> Option<String> {
    let ip = login::client_ip(headers, Some(peer), trust);
    (ip != "unknown").then_some(ip)
}

async fn resolve_org(state: &AppState, slug: &str) -> ApiResult<fluidbox_db::identity::OrgRow> {
    identity::get_org_by_slug(&state.pool, slug)
        .await?
        .ok_or(ApiError::NotFound)
}

/// Resolve an org by slug for a MUTATING handler, auditing a miss. A missing
/// slug on an admin mutation is a rejected attempt like any other refusal, so it
/// routes through [`reject_audit`] (tenant unknown ⇒ `None`) before the 404 —
/// the read-only list handlers keep [`resolve_org`]. `action` is the handler's
/// audit action so per-action filtering stays uniform.
async fn resolve_org_audited(
    state: &AppState,
    sip: Option<&str>,
    action: &str,
    slug: &str,
) -> ApiResult<fluidbox_db::identity::OrgRow> {
    match identity::get_org_by_slug(&state.pool, slug).await? {
        Some(org) => Ok(org),
        None => {
            reject_audit(state, None, sip, action, Some(slug), "org not found").await;
            Err(ApiError::NotFound)
        }
    }
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

/// Audit an authorized-but-unfulfillable request that resolves to a missing
/// target (a `LifecycleOutcome::NotFound`, or a config/membership that does not
/// exist under this tenant) and return the 404. A terse reason, no body echo —
/// every `/v1/admin/orgs*` NotFound routes through here so refusals are audited
/// uniformly (design 395-400).
async fn refuse_not_found(
    state: &AppState,
    tenant_id: Uuid,
    source_ip: Option<&str>,
    action: &str,
    target: Option<&str>,
) -> ApiError {
    reject_audit(
        state,
        Some(tenant_id),
        source_ip,
        action,
        target,
        "not found",
    )
    .await;
    ApiError::NotFound
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

/// Unwrap a JSON body whose extractor rejection was DEFERRED into a `Result`
/// (handler body param `Result<Json<Value>, JsonRejection>`), auditing the
/// rejection HERE. Malformed JSON syntax or a missing content-type is otherwise
/// refused by the `Json` extractor BEFORE the handler runs, bypassing rejection
/// auditing. On a rejection we record `action` + a terse class (never the
/// unparseable body) and return an error PRESERVING the rejection's status
/// (400 malformed syntax / 415 missing content-type) in the standard envelope.
async fn body_or_reject(
    state: &AppState,
    tenant_id: Option<Uuid>,
    source_ip: Option<&str>,
    action: &str,
    target: Option<&str>,
    body: Result<Json<Value>, JsonRejection>,
) -> ApiResult<Value> {
    match body {
        Ok(Json(raw)) => Ok(raw),
        Err(rej) => {
            let status = rej.status();
            let class = if status == StatusCode::UNSUPPORTED_MEDIA_TYPE {
                "unsupported content-type (want application/json)"
            } else {
                "malformed request body"
            };
            reject_audit(state, tenant_id, source_ip, action, target, class).await;
            Err(ApiError::Rejected(status, class.to_string()))
        }
    }
}

// ─── Orgs ─────────────────────────────────────────────────────────────────────

pub async fn create_org(
    _: Admin,
    headers: HeaderMap,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    State(state): State<AppState>,
    body: Result<Json<Value>, JsonRejection>,
) -> ApiResult<Json<Value>> {
    let sip = source_ip(&headers, peer, state.cfg.trust_forwarded_for);
    let raw = body_or_reject(&state, None, sip.as_deref(), "org.create", None, body).await?;
    // Deserialize INSIDE the handler (the body is a raw `Value`, not `Json<T>`) so
    // a malformed body is audited + 400'd here, not silently rejected by the axum
    // extractor before the handler runs.
    let body: CreateOrgBody = match serde_json::from_value(raw) {
        Ok(b) => b,
        Err(e) => {
            reject_audit(
                &state,
                None,
                sip.as_deref(),
                "org.create",
                None,
                "invalid request body",
            )
            .await;
            return Err(ApiError::BadRequest(format!(
                "invalid create-org body: {e}"
            )));
        }
    };
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
    if body.client_id.trim().is_empty() {
        return Err(bad(ApiError::BadRequest("client_id is required".into())).await);
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

    // bootstrap_owner_email: normalized + armed. The owner-absence precondition
    // is enforced UNDER the config lock inside `create_idp_config_audited`
    // (design 709-719), not here — an unlocked pre-check would race a concurrent
    // owner-granting login.
    let bootstrap_email = match &body.bootstrap_owner_email {
        Some(e) if !e.trim().is_empty() => Some(login::normalize_email(e)),
        _ => None,
    };
    let bootstrap_expires = bootstrap_email
        .is_some()
        .then(|| Utc::now() + Duration::days(BOOTSTRAP_ARM_TTL_DAYS));

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
    let view = match login::view_from(&meta, jwks.clone()) {
        Ok(v) => v,
        Err(e) => {
            return Err(bad(ApiError::BadRequest(format!(
                "discovery is non-conformant: {e}"
            )))
            .await)
        }
    };
    // The three discovery endpoints must each meet the SAME https + SSRF policy
    // the login fetches enforce (loopback only under dev). The discovery save
    // only FETCHES jwks_uri, so authorize/token would otherwise first be caught
    // at redirect/callback time — validate all three now, at save.
    for (label, url) in [
        ("authorization_endpoint", &view.authorization_endpoint),
        ("token_endpoint", &view.token_endpoint),
        ("jwks_uri", &view.jwks_uri),
    ] {
        if let Err(e) = login::validate_endpoint_target(state, url).await {
            return Err(bad(ApiError::BadRequest(format!(
                "discovered {label} is not an acceptable URL: {e}"
            )))
            .await);
        }
    }
    if !response_type_code_ok(&meta) {
        return Err(bad(ApiError::BadRequest(
            "the issuer advertises response_types_supported without the authorization-code flow (code)"
                .into(),
        ))
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

    // Seal the client secret (requires the Sealer). Carries the v2 key-version
    // companion into the IdP config row.
    let (client_secret_sealed, client_secret_key_version) = match &body.client_secret {
        Some(secret) => {
            let sealer = match crate::oauth::sealer(state) {
                Ok(s) => s,
                Err(e) => return Err(refuse(state, tenant, sip, action, None, e).await),
            };
            match sealer
                .seal(
                    secret,
                    crate::seal::SealCtx::new(tenant, crate::seal::SealFamily::IdpClientSecret),
                )
                .await
            {
                Ok(s) => (Some(s.bytes), s.key_version),
                Err(e) => {
                    return Err(refuse(state, tenant, sip, action, None, ApiError::from(e)).await)
                }
            }
        }
        None => (None, 1),
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
        client_secret_sealed,
        client_secret_key_version,
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
    match identity::create_idp_config_audited(&state.pool, scope, params, sip).await? {
        LifecycleOutcome::Done(row) => Ok(row),
        // Owner-exists refusal (checked under the config lock): 409, audited.
        LifecycleOutcome::Refused(reason) => Err(bad(ApiError::Conflict(reason.into())).await),
        // create never resolves to a missing target; keep the arm audited.
        LifecycleOutcome::NotFound => Err(bad(ApiError::BadRequest(
            "could not stage the configuration".into(),
        ))
        .await),
    }
}

pub async fn create_idp(
    _: Admin,
    headers: HeaderMap,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    State(state): State<AppState>,
    Path(slug): Path<String>,
    body: Result<Json<Value>, JsonRejection>,
) -> ApiResult<Json<Value>> {
    let sip = source_ip(&headers, peer, state.cfg.trust_forwarded_for);
    let org = resolve_org_audited(&state, sip.as_deref(), "idp.create", &slug).await?;
    let scope = TenantScope::assume(org.id);
    let raw = body_or_reject(
        &state,
        Some(org.id),
        sip.as_deref(),
        "idp.create",
        None,
        body,
    )
    .await?;
    let body: CreateIdpBody = match serde_json::from_value(raw) {
        Ok(b) => b,
        Err(e) => {
            reject_audit(
                &state,
                Some(org.id),
                sip.as_deref(),
                "idp.create",
                None,
                "invalid request body",
            )
            .await;
            return Err(ApiError::BadRequest(format!(
                "invalid create-idp body: {e}"
            )));
        }
    };
    let row = validate_and_stage_config(&state, scope, &body, sip.as_deref(), "idp.create").await?;
    Ok(Json(json!({ "idp": row })))
}

pub async fn activate_idp(
    _: Admin,
    headers: HeaderMap,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    State(state): State<AppState>,
    Path((slug, id)): Path<(String, Uuid)>,
) -> ApiResult<Json<Value>> {
    let sip = source_ip(&headers, peer, state.cfg.trust_forwarded_for);
    let org = resolve_org_audited(&state, sip.as_deref(), "idp.activate", &slug).await?;
    let scope = TenantScope::assume(org.id);
    match identity::activate_idp_config(&state.pool, scope, id, sip.as_deref()).await? {
        LifecycleOutcome::Done(row) => Ok(Json(json!({ "idp": row }))),
        LifecycleOutcome::NotFound => Err(refuse_not_found(
            &state,
            org.id,
            sip.as_deref(),
            "idp.activate",
            Some(&id.to_string()),
        )
        .await),
        LifecycleOutcome::Refused(reason) => {
            Err(refuse_lifecycle(&state, org.id, sip.as_deref(), "idp.activate", id, reason).await)
        }
    }
}

pub async fn disable_idp(
    _: Admin,
    headers: HeaderMap,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    State(state): State<AppState>,
    Path((slug, id)): Path<(String, Uuid)>,
) -> ApiResult<Json<Value>> {
    let sip = source_ip(&headers, peer, state.cfg.trust_forwarded_for);
    let org = resolve_org_audited(&state, sip.as_deref(), "idp.disable", &slug).await?;
    let scope = TenantScope::assume(org.id);
    match identity::disable_idp_config(&state.pool, scope, id, sip.as_deref()).await? {
        LifecycleOutcome::Done(c) => Ok(Json(json!({
            "status": "disabled",
            "flows_cancelled": c.flows_cancelled,
            "switches_cancelled": c.switches_cancelled,
            "sessions_revoked": c.sessions_revoked,
        }))),
        LifecycleOutcome::NotFound => Err(refuse_not_found(
            &state,
            org.id,
            sip.as_deref(),
            "idp.disable",
            Some(&id.to_string()),
        )
        .await),
        LifecycleOutcome::Refused(reason) => {
            Err(refuse_lifecycle(&state, org.id, sip.as_deref(), "idp.disable", id, reason).await)
        }
    }
}

pub async fn reactivate_idp(
    _: Admin,
    headers: HeaderMap,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    State(state): State<AppState>,
    Path((slug, id)): Path<(String, Uuid)>,
) -> ApiResult<Json<Value>> {
    let sip = source_ip(&headers, peer, state.cfg.trust_forwarded_for);
    let org = resolve_org_audited(&state, sip.as_deref(), "idp.reactivate", &slug).await?;
    let scope = TenantScope::assume(org.id);
    match identity::reactivate_idp_config(&state.pool, scope, id, sip.as_deref()).await? {
        LifecycleOutcome::Done(row) => Ok(Json(json!({ "idp": row }))),
        LifecycleOutcome::NotFound => Err(refuse_not_found(
            &state,
            org.id,
            sip.as_deref(),
            "idp.reactivate",
            Some(&id.to_string()),
        )
        .await),
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
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    State(state): State<AppState>,
    Path((slug, id)): Path<(String, Uuid)>,
    body: Result<Json<Value>, JsonRejection>,
) -> ApiResult<Json<Value>> {
    let sip = source_ip(&headers, peer, state.cfg.trust_forwarded_for);
    let org = resolve_org_audited(&state, sip.as_deref(), "idp.patch", &slug).await?;
    let scope = TenantScope::assume(org.id);
    let raw = body_or_reject(
        &state,
        Some(org.id),
        sip.as_deref(),
        "idp.patch",
        Some(&id.to_string()),
        body,
    )
    .await?;
    let config = match identity::get_idp_config(&state.pool, scope, id).await? {
        Some(c) => c,
        None => {
            return Err(refuse_not_found(
                &state,
                org.id,
                sip.as_deref(),
                "idp.patch",
                Some(&id.to_string()),
            )
            .await)
        }
    };
    let tgt = id.to_string();
    let bad = |e: ApiError| async {
        refuse(&state, org.id, sip.as_deref(), "idp.patch", Some(&tgt), e).await
    };

    // Identity fields are immutable — steer the operator to a migration. Checked
    // on the RAW body FIRST, so the specific message wins over the strict parse's
    // unknown-field rejection below.
    if let Some(f) = patch_immutable_field(&raw) {
        return Err(bad(ApiError::BadRequest(format!(
            "{f} is immutable; fix identity fields with POST …/idp/{{id}}/migrate"
        )))
        .await);
    }
    // Strict typed parse: deny_unknown_fields + typed value fields mean a typo or
    // malformed field type is a hard 400 (audited), never silently ignored.
    let body: PatchIdpBody = match serde_json::from_value(raw) {
        Ok(b) => b,
        Err(e) => return Err(bad(ApiError::BadRequest(format!("invalid patch body: {e}"))).await),
    };

    // token_endpoint_auth: validated against the config's cached (or refreshed)
    // discovery methods.
    let new_auth: Option<String> = match &body.token_endpoint_auth {
        Some(a) => {
            if !valid_token_endpoint_auth(a) {
                return Err(bad(ApiError::BadRequest(
                    "token_endpoint_auth must be client_secret_basic, client_secret_post, or none"
                        .into(),
                ))
                .await);
            }
            let meta = match config_discovery_meta(&state, &config).await {
                Ok(m) => m,
                Err(e) => return Err(bad(e).await),
            };
            if !auth_method_supported(a, &meta) {
                return Err(bad(ApiError::BadRequest(format!(
                    "token_endpoint_auth={a} is not advertised by the issuer"
                )))
                .await);
            }
            Some(a.clone())
        }
        None => None,
    };

    // scopes (already typed by the strict parse).
    let new_scopes: Option<Vec<String>> = body.scopes.clone();

    // claim_mappings: role rules re-validated + defaults filled.
    let new_mappings: Option<Value> = match &body.claim_mappings {
        Some(v) => match build_claim_mappings(Some(v)) {
            Ok(m) => Some(m),
            Err(e) => return Err(bad(ApiError::BadRequest(e)).await),
        },
        None => None,
    };

    // alg_allowlist: HS*/none re-rejected.
    let new_algs: Option<Vec<String>> = match &body.alg_allowlist {
        Some(a) => {
            if let Err(e) = validate_alg_allowlist(a) {
                return Err(bad(ApiError::BadRequest(e)).await);
            }
            Some(a.clone())
        }
        None => None,
    };

    // client_secret tri-state: absent = keep, null = clear, string = re-seal
    // (re-seal requires the Sealer). No generation bump.
    let secret_patch = match &body.client_secret {
        None => identity::SecretPatch::Keep,
        Some(None) => identity::SecretPatch::Clear,
        Some(Some(secret)) => {
            let sealer = match crate::oauth::sealer(&state) {
                Ok(s) => s,
                Err(e) => return Err(bad(e).await),
            };
            let sealed = match sealer
                .seal(
                    secret,
                    crate::seal::SealCtx::new(org.id, crate::seal::SealFamily::IdpClientSecret),
                )
                .await
            {
                Ok(s) => s,
                Err(e) => return Err(bad(ApiError::from(e)).await),
            };
            identity::SecretPatch::Set(sealed.bytes, sealed.key_version)
        }
    };

    // Auth/secret COHERENCE is validated in `patch_idp_config` under the config
    // row's FOR UPDATE lock (merged against the freshly-read current row), so two
    // concurrent PATCHes cannot each pass against stale state and commit an
    // incoherent pair. The handler keeps only request-shape validation above.

    // bootstrap_owner_email: re-armed (+7d), refused (in the DB fn, under the
    // config lock) while an active owner exists.
    let new_bootstrap: Option<(String, DateTime<Utc>)> = match &body.bootstrap_owner_email {
        Some(e) if !e.trim().is_empty() => Some((
            login::normalize_email(e),
            Utc::now() + Duration::days(BOOTSTRAP_ARM_TTL_DAYS),
        )),
        _ => None,
    };

    let patch = IdpPatch {
        client_secret: secret_patch,
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
        LifecycleOutcome::NotFound => Err(refuse_not_found(
            &state,
            org.id,
            sip.as_deref(),
            "idp.patch",
            Some(&id.to_string()),
        )
        .await),
        LifecycleOutcome::Refused(reason) => {
            Err(refuse_lifecycle(&state, org.id, sip.as_deref(), "idp.patch", id, reason).await)
        }
    }
}

pub async fn migrate_idp(
    _: Admin,
    headers: HeaderMap,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    State(state): State<AppState>,
    Path((slug, id)): Path<(String, Uuid)>,
    body: Result<Json<Value>, JsonRejection>,
) -> ApiResult<Json<Value>> {
    let sip = source_ip(&headers, peer, state.cfg.trust_forwarded_for);
    let org = resolve_org_audited(&state, sip.as_deref(), "idp.migrate", &slug).await?;
    let scope = TenantScope::assume(org.id);
    let raw = body_or_reject(
        &state,
        Some(org.id),
        sip.as_deref(),
        "idp.migrate",
        Some(&id.to_string()),
        body,
    )
    .await?;
    let body: MigrateBody = match serde_json::from_value(raw) {
        Ok(b) => b,
        Err(e) => {
            reject_audit(
                &state,
                Some(org.id),
                sip.as_deref(),
                "idp.migrate",
                Some(&id.to_string()),
                "invalid request body",
            )
            .await;
            return Err(ApiError::BadRequest(format!("invalid migrate body: {e}")));
        }
    };

    // Pre-check the OLD config is active BEFORE staging the new one, so a wrong
    // target does not leave an orphan staged config (the swap re-checks under
    // the lock as the authority).
    let old = match identity::get_idp_config(&state.pool, scope, id).await? {
        Some(c) => c,
        None => {
            return Err(refuse_not_found(
                &state,
                org.id,
                sip.as_deref(),
                "idp.migrate",
                Some(&id.to_string()),
            )
            .await)
        }
    };
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
        LifecycleOutcome::NotFound => Err(refuse_not_found(
            &state,
            org.id,
            sip.as_deref(),
            "idp.migrate",
            Some(&id.to_string()),
        )
        .await),
        LifecycleOutcome::Refused(reason) => {
            Err(refuse_lifecycle(&state, org.id, sip.as_deref(), "idp.migrate", id, reason).await)
        }
    }
}

// ─── Break-glass owner ────────────────────────────────────────────────────────

pub async fn break_glass_owner(
    _: Admin,
    headers: HeaderMap,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    State(state): State<AppState>,
    Path(slug): Path<String>,
    body: Result<Json<Value>, JsonRejection>,
) -> ApiResult<Json<Value>> {
    let sip = source_ip(&headers, peer, state.cfg.trust_forwarded_for);
    let org = resolve_org_audited(&state, sip.as_deref(), "break_glass.arm", &slug).await?;
    let scope = TenantScope::assume(org.id);
    let raw = body_or_reject(
        &state,
        Some(org.id),
        sip.as_deref(),
        "break_glass.arm",
        None,
        body,
    )
    .await?;
    let body: BreakGlassBody = match serde_json::from_value(raw) {
        Ok(b) => b,
        Err(e) => {
            reject_audit(
                &state,
                Some(org.id),
                sip.as_deref(),
                "break_glass.arm",
                None,
                "invalid request body",
            )
            .await;
            return Err(ApiError::BadRequest(format!(
                "invalid break-glass body: {e}"
            )));
        }
    };
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
    let expires_at = Utc::now() + Duration::days(BOOTSTRAP_ARM_TTL_DAYS);
    // arm_bootstrap_owner resolves + locks the org's active config in ONE
    // transaction (rechecking status='active' and owner-absence under the lock);
    // nothing is trusted from an unlocked prior read.
    match identity::arm_bootstrap_owner(&state.pool, scope, &normalized, expires_at, sip.as_deref())
        .await?
    {
        LifecycleOutcome::Done((config_id, arm_id)) => Ok(Json(json!({
            "armed": true,
            "arm_id": arm_id,
            "config": config_id,
            "expires_at": expires_at,
        }))),
        // No active config to arm — audited 409 (preserves the prior status).
        LifecycleOutcome::NotFound => Err(refuse(
            &state,
            org.id,
            sip.as_deref(),
            "break_glass.arm",
            None,
            ApiError::Conflict("no active IdP configuration to arm".into()),
        )
        .await),
        // Active owner exists / config no longer active — audited 409.
        LifecycleOutcome::Refused(reason) => Err(refuse(
            &state,
            org.id,
            sip.as_deref(),
            "break_glass.arm",
            None,
            ApiError::Conflict(reason.into()),
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
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    State(state): State<AppState>,
    Path((slug, membership_id)): Path<(String, Uuid)>,
) -> ApiResult<Json<Value>> {
    let sip = source_ip(&headers, peer, state.cfg.trust_forwarded_for);
    let org = resolve_org_audited(&state, sip.as_deref(), "member.deactivate", &slug).await?;
    let scope = TenantScope::assume(org.id);
    match identity::deactivate_membership_audited(&state.pool, scope, membership_id, sip.as_deref())
        .await?
    {
        Some(m) => Ok(Json(json!({ "membership": m }))),
        None => Err(refuse_not_found(
            &state,
            org.id,
            sip.as_deref(),
            "member.deactivate",
            Some(&membership_id.to_string()),
        )
        .await),
    }
}

pub async fn set_member_roles(
    _: Admin,
    headers: HeaderMap,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    State(state): State<AppState>,
    Path((slug, membership_id)): Path<(String, Uuid)>,
    body: Result<Json<Value>, JsonRejection>,
) -> ApiResult<Json<Value>> {
    let sip = source_ip(&headers, peer, state.cfg.trust_forwarded_for);
    let org = resolve_org_audited(&state, sip.as_deref(), "member.roles", &slug).await?;
    let scope = TenantScope::assume(org.id);
    let raw = body_or_reject(
        &state,
        Some(org.id),
        sip.as_deref(),
        "member.roles",
        Some(&membership_id.to_string()),
        body,
    )
    .await?;
    let body: RolesBody = match serde_json::from_value(raw) {
        Ok(b) => b,
        Err(e) => {
            reject_audit(
                &state,
                Some(org.id),
                sip.as_deref(),
                "member.roles",
                Some(&membership_id.to_string()),
                "invalid request body",
            )
            .await;
            return Err(ApiError::BadRequest(format!("invalid roles body: {e}")));
        }
    };
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
        None => Err(refuse_not_found(
            &state,
            org.id,
            sip.as_deref(),
            "member.roles",
            Some(&membership_id.to_string()),
        )
        .await),
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
    fn alg_allowlist_rejects_symmetric_none_and_unimplemented() {
        assert!(validate_alg_allowlist(&["RS256".into(), "ES256".into()]).is_ok());
        // The full doc default is entirely inside the implemented set.
        assert!(validate_alg_allowlist(
            &DEFAULT_ALGS
                .iter()
                .map(|s| s.to_string())
                .collect::<Vec<_>>()
        )
        .is_ok());
        // ES512 IS implemented (the default carries it).
        assert!(validate_alg_allowlist(&["ES512".into()]).is_ok());
        // Asymmetric-but-UNIMPLEMENTED algs are refused at SAVE, not at login.
        assert!(validate_alg_allowlist(&["EdDSA".into()]).is_err());
        assert!(validate_alg_allowlist(&["ES256K".into()]).is_err());
        assert!(validate_alg_allowlist(&["HS256".into()]).is_err());
        assert!(validate_alg_allowlist(&["hs512".into()]).is_err()); // HS* absent from the set
        assert!(validate_alg_allowlist(&["none".into()]).is_err());
        assert!(validate_alg_allowlist(&["NONE".into()]).is_err());
        // JOSE alg is case-SENSITIVE: a mis-cased asymmetric alg is refused at
        // SAVE (it would otherwise never match the JWT header alg at login).
        assert!(validate_alg_allowlist(&["rs256".into()]).is_err());
        assert!(validate_alg_allowlist(&["Es256".into()]).is_err());
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
        // PRESENT-but-malformed → refuse (NOT collapsed to the absent/basic
        // branch): a bare string, an explicit null, and a non-string element.
        let str_meta = json!({ "token_endpoint_auth_methods_supported": "client_secret_basic" });
        assert!(!auth_method_supported("client_secret_basic", &str_meta));
        let null_meta = json!({ "token_endpoint_auth_methods_supported": null });
        assert!(!auth_method_supported("client_secret_basic", &null_meta));
        let mixed = json!({ "token_endpoint_auth_methods_supported": ["client_secret_basic", 7] });
        assert!(!auth_method_supported("client_secret_basic", &mixed));
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
        // PRESENT-but-malformed → refuse: a string instead of an array, an
        // explicit null, and an array carrying a non-string.
        assert!(!pkce_ok(
            &json!({ "code_challenge_methods_supported": "S256" })
        ));
        assert!(!pkce_ok(
            &json!({ "code_challenge_methods_supported": null })
        ));
        assert!(!pkce_ok(
            &json!({ "code_challenge_methods_supported": ["S256", 1] })
        ));
    }

    #[test]
    fn response_type_validation() {
        // Present with a code-bearing entry → accept.
        assert!(response_type_code_ok(
            &json!({ "response_types_supported": ["code", "id_token"] })
        ));
        assert!(response_type_code_ok(
            &json!({ "response_types_supported": ["code id_token"] })
        ));
        // Present without code → refuse.
        assert!(!response_type_code_ok(
            &json!({ "response_types_supported": ["id_token", "token"] })
        ));
        // Absent → accept.
        assert!(response_type_code_ok(&json!({})));
        // PRESENT-but-malformed → refuse (non-array, null, non-string element).
        assert!(!response_type_code_ok(
            &json!({ "response_types_supported": "code" })
        ));
        assert!(!response_type_code_ok(
            &json!({ "response_types_supported": null })
        ));
        assert!(!response_type_code_ok(
            &json!({ "response_types_supported": ["code", 42] })
        ));
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
