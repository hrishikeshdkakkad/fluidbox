//! Identity layer repositories (Phase B).
//!
//! Design: `docs/plans/2026-07-17-idp-agnostic-identity-design.md`.
//!
//! Convention: every tenant-owned query takes a [`TenantScope`] right after
//! the executor and carries `scope.tenant_id()` into a `tenant_id = $n`
//! predicate. The handful of PRE-AUTH / bootstrap helpers that resolve a
//! tenant rather than assume one (`get_org_by_slug`, `active_idp_config`,
//! `claim_login_flow`, `resolve_web_session`, `resolve_pat`) take raw values
//! instead — those are the documented exceptions, and each carries its own
//! comment.
//!
//! Sealed columns never ride into a serialized row: `OrgIdpConfigRow` selects
//! an explicit column list that omits `client_secret_sealed`, mirroring
//! `IntegrationConnectionRow`. A later task adds the dedicated sealed reader
//! when token exchange needs it.

use crate::{sha256_hex, TenantScope};
use chrono::{DateTime, Utc};
use serde_json::Value;
use sqlx::PgPool;
use uuid::Uuid;

// ─── Rows ─────────────────────────────────────────────────────────────────

/// The `tenants` row, extended in place by migration 0012 (slug/display/status).
#[derive(Debug, Clone, sqlx::FromRow, serde::Serialize)]
pub struct OrgRow {
    pub id: Uuid,
    pub name: String,
    pub slug: String,
    pub display_name: Option<String>,
    pub status: String,
    pub created_at: DateTime<Utc>,
}

/// Deliberately omits `client_secret_sealed` — every select uses
/// [`IDP_CONFIG_COLS`], so the sealed secret can never ride into an API
/// response or log. Identity fields (`issuer`, `client_id`, `generation`) are
/// immutable; status/caches/mappings are not.
#[derive(Debug, Clone, sqlx::FromRow, serde::Serialize)]
pub struct OrgIdpConfigRow {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub generation: i32,
    pub issuer: String,
    pub client_id: String,
    pub token_endpoint_auth: String,
    pub scopes: Vec<String>,
    pub alg_allowlist: Vec<String>,
    pub claim_mappings: Value,
    pub bootstrap_owner_email: Option<String>,
    pub bootstrap_owner_expires_at: Option<DateTime<Utc>>,
    pub discovered_metadata: Option<Value>,
    pub jwks: Option<Value>,
    pub discovered_at: Option<DateTime<Utc>>,
    pub status: String,
    pub created_by: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

const IDP_CONFIG_COLS: &str = "id, tenant_id, generation, issuer, client_id, \
    token_endpoint_auth, scopes, alg_allowlist, claim_mappings, \
    bootstrap_owner_email, bootstrap_owner_expires_at, discovered_metadata, \
    jwks, discovered_at, status, created_by, created_at, updated_at";

#[derive(Debug, Clone, sqlx::FromRow, serde::Serialize)]
pub struct UserRow {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub idp_config_id: Uuid,
    pub subject: String,
    pub email: Option<String>,
    pub email_normalized: Option<String>,
    pub email_verified: bool,
    pub name: Option<String>,
    pub status: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub last_login_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, sqlx::FromRow, serde::Serialize)]
pub struct OrgMembershipRow {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub user_id: Uuid,
    pub roles: Vec<String>,
    pub status: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub deactivated_at: Option<DateTime<Utc>>,
}

/// Non-secret projection of a `login_flows` row (omits `pkce_verifier_sealed`);
/// the sealed verifier is surfaced ONLY by [`claim_login_flow`] into a
/// [`LoginFlowClaim`].
#[derive(Debug, Clone, sqlx::FromRow, serde::Serialize)]
pub struct LoginFlowRow {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub idp_config_id: Uuid,
    pub nonce: String,
    pub browser_hash: String,
    pub redirect_to: String,
    pub consumed_at: Option<DateTime<Utc>>,
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
}

/// What the one-time login-flow claim yields: the sealed PKCE verifier for the
/// out-of-transaction token exchange, the single-use nonce, the stored local
/// redirect, and `created_at` (the caller binds the ID token's `iat` to the
/// flow lifetime). Not `Serialize` — it carries the sealed verifier.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct LoginFlowClaim {
    pub pkce_verifier_sealed: Vec<u8>,
    pub nonce: String,
    pub redirect_to: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, sqlx::FromRow, serde::Serialize)]
pub struct UserSessionRow {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub membership_id: Uuid,
    pub user_id: Uuid,
    pub session_token_sha256: String,
    pub idp_config_id: Uuid,
    pub acr: Option<String>,
    pub amr: Option<Vec<String>>,
    pub auth_time: Option<DateTime<Utc>>,
    pub idp_sid: Option<String>,
    pub created_at: DateTime<Utc>,
    pub last_seen_at: Option<DateTime<Utc>>,
    pub idle_expires_at: DateTime<Utc>,
    pub absolute_expires_at: DateTime<Utc>,
    pub revoked_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, sqlx::FromRow, serde::Serialize)]
pub struct PendingLoginSwitchRow {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub idp_config_id: Uuid,
    pub new_membership_id: Uuid,
    pub new_user_id: Uuid,
    pub replaced_tenant_id: Uuid,
    pub replaced_session_id: Uuid,
    pub redirect_to: String,
    pub browser_hash: String,
    pub acr: Option<String>,
    pub amr: Option<Vec<String>>,
    pub auth_time: Option<DateTime<Utc>>,
    pub consumed_at: Option<DateTime<Utc>>,
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
}

/// A personal access token (`api_tokens` where `kind='pat'`). Never carries
/// the token itself — `display_prefix` (first 12 plaintext chars) is the only
/// listing hint.
#[derive(Debug, Clone, sqlx::FromRow, serde::Serialize)]
pub struct PatRow {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub membership_id: Option<Uuid>,
    pub user_id: Option<Uuid>,
    pub name: Option<String>,
    pub display_prefix: Option<String>,
    pub created_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
    pub last_used_at: Option<DateTime<Utc>>,
    pub revoked_at: Option<DateTime<Utc>>,
}

const PAT_COLS: &str = "id, tenant_id, membership_id, user_id, name, \
    display_prefix, created_at, expires_at, last_used_at, revoked_at";

/// The joined result of resolving a browser session token: the session plus
/// its live membership (status + roles), user, and tenant. The caller refuses
/// a non-`active` membership/tenant — resolution does NOT filter on status, so
/// the boundary decision stays in one place.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct WebSessionAuth {
    pub session_id: Uuid,
    pub tenant_id: Uuid,
    pub tenant_slug: String,
    pub tenant_status: String,
    pub membership_id: Uuid,
    pub user_id: Uuid,
    pub roles: Vec<String>,
    pub membership_status: String,
    pub user_status: String,
    pub email: Option<String>,
    pub name: Option<String>,
    pub idp_config_id: Uuid,
    pub idle_expires_at: DateTime<Utc>,
    pub absolute_expires_at: DateTime<Utc>,
}

/// The joined result of resolving a PAT: the token plus its live membership
/// (status + roles). The caller refuses a non-`active` membership.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct PatAuth {
    pub token_id: Uuid,
    pub tenant_id: Uuid,
    pub membership_id: Uuid,
    pub user_id: Uuid,
    pub roles: Vec<String>,
    pub membership_status: String,
}

/// One `auth_audit_log` row's worth of input. `tenant_id` is `None` for
/// deployment-level operator actions.
#[derive(Debug, Clone)]
pub struct AuditEntry<'a> {
    pub tenant_id: Option<Uuid>,
    pub actor_kind: &'a str,
    pub actor_id: Option<&'a str>,
    pub source_ip: Option<&'a str>,
    pub request_id: Option<&'a str>,
    pub action: &'a str,
    pub target: Option<&'a str>,
    pub success: bool,
    pub detail: Option<&'a Value>,
}

/// Parameters for [`create_idp_config`]. The caller seals the client secret
/// itself (the repo stores what it is given, per the sealer-optional rule).
#[derive(Debug, Clone)]
pub struct IdpConfigParams<'a> {
    pub issuer: &'a str,
    pub client_id: &'a str,
    pub client_secret_sealed: Option<Vec<u8>>,
    pub token_endpoint_auth: &'a str,
    pub scopes: &'a [String],
    pub alg_allowlist: &'a [String],
    pub claim_mappings: &'a Value,
    pub bootstrap_owner_email: Option<&'a str>,
    pub bootstrap_owner_expires_at: Option<DateTime<Utc>>,
    pub created_by: Option<&'a str>,
}

// ─── Orgs (tenants) ─────────────────────────────────────────────────────────

/// Create a new organization (a `tenants` row). `name` is set to the slug —
/// the legacy unique `name` column survives, and slug is the identifier
/// everything routes on now.
pub async fn create_org(
    pool: &PgPool,
    slug: &str,
    display_name: Option<&str>,
) -> sqlx::Result<OrgRow> {
    sqlx::query_as(
        "insert into tenants (id, name, slug, display_name, status)
         values ($1, $2, $2, $3, 'active')
         returning id, name, slug, display_name, status, created_at",
    )
    .bind(Uuid::now_v7())
    .bind(slug)
    .bind(display_name)
    .fetch_one(pool)
    .await
}

/// Pre-auth login-routing helper: resolve a slug to its org BEFORE anyone is
/// authenticated. Answers identically (None) for unknown slugs.
pub async fn get_org_by_slug(pool: &PgPool, slug: &str) -> sqlx::Result<Option<OrgRow>> {
    sqlx::query_as(
        "select id, name, slug, display_name, status, created_at
         from tenants where slug = $1",
    )
    .bind(slug)
    .fetch_optional(pool)
    .await
}

/// Operator surface: every org.
pub async fn list_orgs(pool: &PgPool) -> sqlx::Result<Vec<OrgRow>> {
    sqlx::query_as(
        "select id, name, slug, display_name, status, created_at
         from tenants order by created_at",
    )
    .fetch_all(pool)
    .await
}

pub async fn get_org(pool: &PgPool, scope: TenantScope) -> sqlx::Result<Option<OrgRow>> {
    sqlx::query_as(
        "select id, name, slug, display_name, status, created_at
         from tenants where id = $1",
    )
    .bind(scope.tenant_id())
    .fetch_optional(pool)
    .await
}

// ─── org_idp_configs ────────────────────────────────────────────────────────

/// Insert a `staged` IdP config, assigning the next per-tenant `generation`
/// (`coalesce(max(generation), 0) + 1`, satisfying `unique (tenant_id,
/// generation)`). Seals nothing itself — the caller passes an already-sealed
/// client secret. Status transitions/swap/arming are a later task (they are
/// transactional and lock the config row `FOR UPDATE`).
pub async fn create_idp_config(
    pool: &PgPool,
    scope: TenantScope,
    params: IdpConfigParams<'_>,
) -> sqlx::Result<OrgIdpConfigRow> {
    sqlx::query_as(sqlx::AssertSqlSafe(format!(
        "insert into org_idp_configs
           (id, tenant_id, generation, issuer, client_id, client_secret_sealed,
            token_endpoint_auth, scopes, alg_allowlist, claim_mappings,
            bootstrap_owner_email, bootstrap_owner_expires_at, status, created_by)
         select $1, $2,
                coalesce((select max(generation) from org_idp_configs where tenant_id = $2), 0) + 1,
                $3, $4, $5, $6, $7, $8, $9, $10, $11, 'staged', $12
         returning {IDP_CONFIG_COLS}"
    )))
    .bind(Uuid::now_v7())
    .bind(scope.tenant_id())
    .bind(params.issuer)
    .bind(params.client_id)
    .bind(params.client_secret_sealed)
    .bind(params.token_endpoint_auth)
    .bind(params.scopes.to_vec())
    .bind(params.alg_allowlist.to_vec())
    .bind(params.claim_mappings)
    .bind(params.bootstrap_owner_email)
    .bind(params.bootstrap_owner_expires_at)
    .bind(params.created_by)
    .fetch_one(pool)
    .await
}

pub async fn get_idp_config(
    pool: &PgPool,
    scope: TenantScope,
    id: Uuid,
) -> sqlx::Result<Option<OrgIdpConfigRow>> {
    sqlx::query_as(sqlx::AssertSqlSafe(format!(
        "select {IDP_CONFIG_COLS} from org_idp_configs where tenant_id = $1 and id = $2"
    )))
    .bind(scope.tenant_id())
    .bind(id)
    .fetch_optional(pool)
    .await
}

pub async fn list_idp_configs(
    pool: &PgPool,
    scope: TenantScope,
) -> sqlx::Result<Vec<OrgIdpConfigRow>> {
    sqlx::query_as(sqlx::AssertSqlSafe(format!(
        "select {IDP_CONFIG_COLS} from org_idp_configs where tenant_id = $1 order by generation"
    )))
    .bind(scope.tenant_id())
    .fetch_all(pool)
    .await
}

/// Pre-auth: the one active config for an org (login routing loads this before
/// any principal exists). At most one row by the `one_active_idp_per_org`
/// partial index.
pub async fn active_idp_config(
    pool: &PgPool,
    tenant_id: Uuid,
) -> sqlx::Result<Option<OrgIdpConfigRow>> {
    sqlx::query_as(sqlx::AssertSqlSafe(format!(
        "select {IDP_CONFIG_COLS} from org_idp_configs
         where tenant_id = $1 and status = 'active'"
    )))
    .bind(tenant_id)
    .fetch_optional(pool)
    .await
}

/// Refresh the cached discovery document + JWKS. Returns whether a row matched.
pub async fn update_idp_discovery_cache(
    pool: &PgPool,
    scope: TenantScope,
    id: Uuid,
    metadata: &Value,
    jwks: &Value,
    discovered_at: DateTime<Utc>,
) -> sqlx::Result<bool> {
    let res = sqlx::query(
        "update org_idp_configs
         set discovered_metadata = $3, jwks = $4, discovered_at = $5, updated_at = now()
         where tenant_id = $1 and id = $2",
    )
    .bind(scope.tenant_id())
    .bind(id)
    .bind(metadata)
    .bind(jwks)
    .bind(discovered_at)
    .execute(pool)
    .await?;
    Ok(res.rows_affected() == 1)
}

// ─── login_flows ────────────────────────────────────────────────────────────

/// Mint a one-time login flow with GC-on-insert (same discipline as
/// `create_github_app_flow`). The cleartext cookie nonce lives only in the
/// browser cookie; only its sha256 (`browser_hash`) is stored.
#[allow(clippy::too_many_arguments)]
pub async fn create_login_flow(
    pool: &PgPool,
    scope: TenantScope,
    idp_config_id: Uuid,
    pkce_verifier_sealed: &[u8],
    nonce: &str,
    browser_hash: &str,
    redirect_to: &str,
    ttl_secs: i64,
) -> sqlx::Result<Uuid> {
    sqlx::query(
        "delete from login_flows
         where (consumed_at is null and expires_at < now())
            or expires_at < now() - interval '7 days'",
    )
    .execute(pool)
    .await?;
    let id = Uuid::now_v7();
    sqlx::query(
        "insert into login_flows
           (id, tenant_id, idp_config_id, pkce_verifier_sealed, nonce, browser_hash, redirect_to, expires_at)
         values ($1, $2, $3, $4, $5, $6, $7, now() + make_interval(secs => $8::double precision))",
    )
    .bind(id)
    .bind(scope.tenant_id())
    .bind(idp_config_id)
    .bind(pkce_verifier_sealed)
    .bind(nonce)
    .bind(browser_hash)
    .bind(redirect_to)
    .bind(ttl_secs as f64)
    .execute(pool)
    .await?;
    Ok(id)
}

/// The one-time login-flow claim (design lines 503-524). The cookie
/// `browser_hash` sits INSIDE the predicate and the config must still be
/// `active`, so a leaked authorization URL — or a config retired mid-flight —
/// yields zero rows and burns nothing. Bootstrap exception: takes a raw
/// `tenant_id` extracted from the verified sealed `state`, not a scope.
/// Returns `created_at` too: the caller binds the ID token's `iat` to it.
pub async fn claim_login_flow(
    pool: &PgPool,
    flow_id: Uuid,
    tenant_id: Uuid,
    idp_config_id: Uuid,
    browser_hash: &str,
) -> sqlx::Result<Option<LoginFlowClaim>> {
    sqlx::query_as(
        "update login_flows f set consumed_at = now()
         from org_idp_configs c
         where f.id = $1 and f.tenant_id = $2
           and f.idp_config_id = $3
           and c.tenant_id = f.tenant_id and c.id = f.idp_config_id
           and c.status = 'active'
           and f.consumed_at is null
           and f.browser_hash = $4
           and f.expires_at > now()
         returning f.pkce_verifier_sealed, f.nonce, f.redirect_to, f.created_at",
    )
    .bind(flow_id)
    .bind(tenant_id)
    .bind(idp_config_id)
    .bind(browser_hash)
    .fetch_optional(pool)
    .await
}

// ─── user_sessions ──────────────────────────────────────────────────────────

/// Mint a browser session (sha256 of the plaintext token stored; the plaintext
/// is the `fbx_web_`-prefixed cookie value the caller mints). Executor-generic
/// so a login's provisioning transaction can mint the session inside it.
#[allow(clippy::too_many_arguments)]
pub async fn mint_user_session(
    conn: &mut sqlx::PgConnection,
    scope: TenantScope,
    membership_id: Uuid,
    user_id: Uuid,
    idp_config_id: Uuid,
    token_plain: &str,
    acr: Option<&str>,
    amr: Option<&[String]>,
    auth_time: Option<DateTime<Utc>>,
    idp_sid: Option<&str>,
    idle_secs: i64,
    absolute_secs: i64,
) -> sqlx::Result<UserSessionRow> {
    sqlx::query_as(
        "insert into user_sessions
           (id, tenant_id, membership_id, user_id, session_token_sha256, idp_config_id,
            acr, amr, auth_time, idp_sid, idle_expires_at, absolute_expires_at)
         values ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10,
                 now() + make_interval(secs => $11::double precision),
                 now() + make_interval(secs => $12::double precision))
         returning *",
    )
    .bind(Uuid::now_v7())
    .bind(scope.tenant_id())
    .bind(membership_id)
    .bind(user_id)
    .bind(sha256_hex(token_plain))
    .bind(idp_config_id)
    .bind(acr)
    .bind(amr.map(<[String]>::to_vec))
    .bind(auth_time)
    .bind(idp_sid)
    .bind(idle_secs as f64)
    .bind(absolute_secs as f64)
    .fetch_one(&mut *conn)
    .await
}

/// Resolve a browser session token AND slide its idle expiry in one UPDATE
/// (bootstrap exception: keys purely on the token sha256, like every fluidbox
/// token). The idle bump is `least(now() + idle_secs, absolute_expires_at)`;
/// `idle_secs` is the configured window (`FLUIDBOX_SESSION_IDLE_SECS`), which
/// the session row does not store — hence a parameter (see the report's
/// deviation note). Returns the joined membership/user/tenant; the caller
/// refuses a non-`active` membership.
pub async fn resolve_web_session(
    pool: &PgPool,
    token_plain: &str,
    idle_secs: i64,
) -> sqlx::Result<Option<WebSessionAuth>> {
    sqlx::query_as(
        "update user_sessions s
         set last_seen_at = now(),
             idle_expires_at = least(
                 now() + make_interval(secs => $2::double precision),
                 absolute_expires_at)
         from org_memberships m, users u, tenants t
         where s.session_token_sha256 = $1
           and s.revoked_at is null
           and s.idle_expires_at > now()
           and s.absolute_expires_at > now()
           and m.tenant_id = s.tenant_id and m.id = s.membership_id and m.user_id = s.user_id
           and u.tenant_id = s.tenant_id and u.id = s.user_id
           and t.id = s.tenant_id
         returning
           s.id as session_id, s.tenant_id as tenant_id, s.membership_id as membership_id,
           s.user_id as user_id, s.idp_config_id as idp_config_id,
           s.idle_expires_at as idle_expires_at, s.absolute_expires_at as absolute_expires_at,
           m.roles as roles, m.status as membership_status,
           u.email as email, u.name as name, u.status as user_status,
           t.slug as tenant_slug, t.status as tenant_status",
    )
    .bind(sha256_hex(token_plain))
    .bind(idle_secs as f64)
    .fetch_optional(pool)
    .await
}

/// Revoke a single session (a row update, never a delete — the audit trail and
/// the composite FKs from `pending_login_switches` stay intact).
pub async fn revoke_user_session(
    pool: &PgPool,
    scope: TenantScope,
    id: Uuid,
) -> sqlx::Result<bool> {
    let res = sqlx::query(
        "update user_sessions set revoked_at = now()
         where tenant_id = $1 and id = $2 and revoked_at is null",
    )
    .bind(scope.tenant_id())
    .bind(id)
    .execute(pool)
    .await?;
    Ok(res.rows_affected() == 1)
}

/// Revoke every live session of a membership (half of the deactivation
/// cascade). Executor-generic so it runs inside the deactivation transaction.
pub async fn revoke_sessions_for_membership(
    conn: &mut sqlx::PgConnection,
    scope: TenantScope,
    membership_id: Uuid,
) -> sqlx::Result<u64> {
    let res = sqlx::query(
        "update user_sessions set revoked_at = now()
         where tenant_id = $1 and membership_id = $2 and revoked_at is null",
    )
    .bind(scope.tenant_id())
    .bind(membership_id)
    .execute(&mut *conn)
    .await?;
    Ok(res.rows_affected())
}

// ─── PATs (api_tokens kind='pat') ───────────────────────────────────────────

/// Mint a PAT. `display_prefix` is the first 12 plaintext chars (a listing
/// hint — the `fbx_pat_` prefix plus a few token bytes); only the sha256 of
/// the token is stored. The shape CHECK requires `expires_at` non-null, so a
/// PAT always has a finite lifetime.
pub async fn mint_pat(
    pool: &PgPool,
    scope: TenantScope,
    membership_id: Uuid,
    user_id: Uuid,
    name: &str,
    token_plain: &str,
    expires_at: DateTime<Utc>,
) -> sqlx::Result<PatRow> {
    let display_prefix: String = token_plain.chars().take(12).collect();
    sqlx::query_as(sqlx::AssertSqlSafe(format!(
        "insert into api_tokens
           (id, tenant_id, kind, membership_id, user_id, name, display_prefix, token_sha256, expires_at)
         values ($1, $2, 'pat', $3, $4, $5, $6, $7, $8)
         returning {PAT_COLS}"
    )))
    .bind(Uuid::now_v7())
    .bind(scope.tenant_id())
    .bind(membership_id)
    .bind(user_id)
    .bind(name)
    .bind(display_prefix)
    .bind(sha256_hex(token_plain))
    .bind(expires_at)
    .fetch_one(pool)
    .await
}

/// Resolve a PAT (bootstrap exception: keys on the token sha256) and bump
/// `last_used_at`. Joins the membership for its live status + roles; a
/// deactivated membership's PATs are already revoked by the cascade, so this
/// matches only live tokens and the returned status is defense in depth.
pub async fn resolve_pat(pool: &PgPool, token_plain: &str) -> sqlx::Result<Option<PatAuth>> {
    sqlx::query_as(
        "update api_tokens tok set last_used_at = now()
         from org_memberships m
         where tok.kind = 'pat' and tok.token_sha256 = $1
           and tok.revoked_at is null
           and tok.expires_at > now()
           and m.tenant_id = tok.tenant_id and m.id = tok.membership_id and m.user_id = tok.user_id
         returning tok.id as token_id, tok.tenant_id as tenant_id,
                   tok.membership_id as membership_id, tok.user_id as user_id,
                   m.roles as roles, m.status as membership_status",
    )
    .bind(sha256_hex(token_plain))
    .fetch_optional(pool)
    .await
}

pub async fn list_pats(
    pool: &PgPool,
    scope: TenantScope,
    membership_id: Uuid,
) -> sqlx::Result<Vec<PatRow>> {
    sqlx::query_as(sqlx::AssertSqlSafe(format!(
        "select {PAT_COLS} from api_tokens
         where kind = 'pat' and tenant_id = $1 and membership_id = $2
         order by created_at desc"
    )))
    .bind(scope.tenant_id())
    .bind(membership_id)
    .fetch_all(pool)
    .await
}

/// Revoke one PAT, scoped to its membership so a caller can only revoke its
/// own tokens. Returns whether a live row matched.
pub async fn revoke_pat(
    pool: &PgPool,
    scope: TenantScope,
    membership_id: Uuid,
    token_id: Uuid,
) -> sqlx::Result<bool> {
    let res = sqlx::query(
        "update api_tokens set revoked_at = now()
         where kind = 'pat' and tenant_id = $1 and membership_id = $2 and id = $3
           and revoked_at is null",
    )
    .bind(scope.tenant_id())
    .bind(membership_id)
    .bind(token_id)
    .execute(pool)
    .await?;
    Ok(res.rows_affected() == 1)
}

// ─── auth_audit_log ─────────────────────────────────────────────────────────

/// Append an audit row. Executor-generic: an ACCEPTED mutation calls this
/// inside its own transaction (audit and mutation commit together — if the
/// audit insert fails, the mutation fails); a REJECTED attempt calls it on a
/// fresh connection committed after the rollback. The append-only trigger
/// blocks any later UPDATE/DELETE.
pub async fn insert_audit(
    conn: &mut sqlx::PgConnection,
    entry: AuditEntry<'_>,
) -> sqlx::Result<Uuid> {
    let id = Uuid::now_v7();
    sqlx::query(
        "insert into auth_audit_log
           (id, tenant_id, actor_kind, actor_id, source_ip, request_id, action, target, success, detail)
         values ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)",
    )
    .bind(id)
    .bind(entry.tenant_id)
    .bind(entry.actor_kind)
    .bind(entry.actor_id)
    .bind(entry.source_ip)
    .bind(entry.request_id)
    .bind(entry.action)
    .bind(entry.target)
    .bind(entry.success)
    .bind(entry.detail)
    .execute(&mut *conn)
    .await?;
    Ok(id)
}

// ─── users / memberships (reads + the deactivation cascade) ─────────────────

pub async fn get_user(
    pool: &PgPool,
    scope: TenantScope,
    id: Uuid,
) -> sqlx::Result<Option<UserRow>> {
    sqlx::query_as("select * from users where tenant_id = $1 and id = $2")
        .bind(scope.tenant_id())
        .bind(id)
        .fetch_optional(pool)
        .await
}

pub async fn list_memberships(
    pool: &PgPool,
    scope: TenantScope,
) -> sqlx::Result<Vec<OrgMembershipRow>> {
    sqlx::query_as("select * from org_memberships where tenant_id = $1 order by created_at")
        .bind(scope.tenant_id())
        .fetch_all(pool)
        .await
}

pub async fn get_membership(
    pool: &PgPool,
    scope: TenantScope,
    id: Uuid,
) -> sqlx::Result<Option<OrgMembershipRow>> {
    sqlx::query_as("select * from org_memberships where tenant_id = $1 and id = $2")
        .bind(scope.tenant_id())
        .bind(id)
        .fetch_optional(pool)
        .await
}

/// Set a membership's status. Deactivation is the kill switch: in the SAME
/// transaction it revokes the membership's sessions and PATs (design lines
/// 762-767). Reactivation (`status != 'deactivated'`) fires no cascade.
pub async fn set_membership_status(
    pool: &PgPool,
    scope: TenantScope,
    id: Uuid,
    status: &str,
) -> sqlx::Result<Option<OrgMembershipRow>> {
    let mut tx = pool.begin().await?;
    let row: Option<OrgMembershipRow> = sqlx::query_as(
        "update org_memberships
         set status = $3,
             deactivated_at = case when $3 = 'deactivated' then now() else deactivated_at end,
             updated_at = now()
         where tenant_id = $1 and id = $2
         returning *",
    )
    .bind(scope.tenant_id())
    .bind(id)
    .bind(status)
    .fetch_optional(&mut *tx)
    .await?;

    if let Some(ref m) = row {
        if status == "deactivated" {
            revoke_sessions_for_membership(&mut tx, scope, m.id).await?;
            sqlx::query(
                "update api_tokens set revoked_at = now()
                 where kind = 'pat' and tenant_id = $1 and membership_id = $2
                   and revoked_at is null",
            )
            .bind(scope.tenant_id())
            .bind(m.id)
            .execute(&mut *tx)
            .await?;
        }
    }
    tx.commit().await?;
    Ok(row)
}

// ─── Tests (run only when DATABASE_URL is set) ──────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::connect;

    /// Delete everything a test created under a throwaway tenant, children
    /// first (tenant FKs are NO ACTION — no cascade). `auth_audit_log` is
    /// append-only (its trigger blocks DELETE), so tests never COMMIT audit
    /// rows tied to a tenant — they exercise audit inside a rolled-back tx.
    async fn cleanup_tenant(pool: &PgPool, tenant: Uuid) {
        for stmt in [
            "delete from api_tokens where tenant_id = $1",
            "delete from pending_login_switches where tenant_id = $1",
            "delete from user_sessions where tenant_id = $1",
            "delete from login_flows where tenant_id = $1",
            "delete from org_memberships where tenant_id = $1",
            "delete from users where tenant_id = $1",
            "delete from org_idp_configs where tenant_id = $1",
            "delete from tenants where id = $1",
        ] {
            sqlx::query(stmt).bind(tenant).execute(pool).await.unwrap();
        }
    }

    fn claim_mappings() -> Value {
        serde_json::json!({
            "email": "email", "name": "name", "roles_path": "groups",
            "role_map": {}, "default_role": "member", "require_email_verified": true
        })
    }

    async fn staged_config(pool: &PgPool, scope: TenantScope) -> OrgIdpConfigRow {
        let mappings = claim_mappings();
        let scopes = vec!["openid".to_string(), "email".to_string()];
        let algs = vec!["RS256".to_string()];
        create_idp_config(
            pool,
            scope,
            IdpConfigParams {
                issuer: "https://issuer.example",
                client_id: "client-abc",
                client_secret_sealed: Some(vec![1, 2, 3]),
                token_endpoint_auth: "client_secret_basic",
                scopes: &scopes,
                alg_allowlist: &algs,
                claim_mappings: &mappings,
                bootstrap_owner_email: Some("owner@example.com"),
                bootstrap_owner_expires_at: None,
                created_by: Some("operator"),
            },
        )
        .await
        .unwrap()
    }

    async fn activate(pool: &PgPool, config_id: Uuid) {
        sqlx::query("update org_idp_configs set status = 'active' where id = $1")
            .bind(config_id)
            .execute(pool)
            .await
            .unwrap();
    }

    /// Raw fixture insert (JIT upsert is a later task): a user + its membership.
    async fn seed_user_membership(
        pool: &PgPool,
        scope: TenantScope,
        config_id: Uuid,
        subject: &str,
    ) -> (Uuid, Uuid) {
        let user_id = Uuid::now_v7();
        sqlx::query(
            "insert into users (id, tenant_id, idp_config_id, subject, email, email_normalized, email_verified, status)
             values ($1, $2, $3, $4, $5, $5, true, 'active')",
        )
        .bind(user_id)
        .bind(scope.tenant_id())
        .bind(config_id)
        .bind(subject)
        .bind(format!("{subject}@example.com"))
        .execute(pool)
        .await
        .unwrap();
        let membership_id = Uuid::now_v7();
        sqlx::query(
            "insert into org_memberships (id, tenant_id, user_id, roles, status)
             values ($1, $2, $3, '{member}', 'active')",
        )
        .bind(membership_id)
        .bind(scope.tenant_id())
        .bind(user_id)
        .execute(pool)
        .await
        .unwrap();
        (user_id, membership_id)
    }

    #[tokio::test]
    async fn org_config_and_login_flow_claim() {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("skipping: DATABASE_URL not set");
            return;
        };
        let pool = connect(&url).await.expect("connect");

        let slug = format!("t-{}", Uuid::now_v7().simple());
        let org = create_org(&pool, &slug, Some("Test Org")).await.unwrap();
        let scope = TenantScope::assume(org.id);
        assert_eq!(
            get_org_by_slug(&pool, &slug).await.unwrap().unwrap().id,
            org.id
        );
        assert!(get_org(&pool, scope).await.unwrap().is_some());

        let cfg = staged_config(&pool, scope).await;
        assert_eq!(cfg.generation, 1);
        assert_eq!(cfg.status, "staged");
        // second config bumps the generation
        let cfg2 = staged_config(&pool, scope).await;
        assert_eq!(cfg2.generation, 2);
        assert!(active_idp_config(&pool, org.id).await.unwrap().is_none());
        activate(&pool, cfg.id).await;
        assert_eq!(
            active_idp_config(&pool, org.id).await.unwrap().unwrap().id,
            cfg.id
        );

        let good_hash = sha256_hex("cookie-nonce");
        let flow = create_login_flow(
            &pool,
            scope,
            cfg.id,
            &[9, 8, 7],
            "nonce-1",
            &good_hash,
            "/dashboard",
            600,
        )
        .await
        .unwrap();

        // wrong browser_hash refused, and the flow is NOT burned
        assert!(claim_login_flow(&pool, flow, org.id, cfg.id, "wrong")
            .await
            .unwrap()
            .is_none());
        let claim = claim_login_flow(&pool, flow, org.id, cfg.id, &good_hash)
            .await
            .unwrap()
            .expect("valid claim");
        assert_eq!(claim.nonce, "nonce-1");
        assert_eq!(claim.redirect_to, "/dashboard");
        assert_eq!(claim.pkce_verifier_sealed, vec![9, 8, 7]);
        // replay refused (already consumed)
        assert!(claim_login_flow(&pool, flow, org.id, cfg.id, &good_hash)
            .await
            .unwrap()
            .is_none());

        // an already-expired flow is refused (claim checks expires_at > now())
        let expired = create_login_flow(&pool, scope, cfg.id, &[1], "nonce-2", &good_hash, "/", -5)
            .await
            .unwrap();
        assert!(claim_login_flow(&pool, expired, org.id, cfg.id, &good_hash)
            .await
            .unwrap()
            .is_none());

        cleanup_tenant(&pool, org.id).await;
    }

    #[tokio::test]
    async fn session_and_pat_lifecycle_and_cascade() {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("skipping: DATABASE_URL not set");
            return;
        };
        let pool = connect(&url).await.expect("connect");

        let slug = format!("t-{}", Uuid::now_v7().simple());
        let org = create_org(&pool, &slug, None).await.unwrap();
        let scope = TenantScope::assume(org.id);
        let cfg = staged_config(&pool, scope).await;
        let (user_id, membership_id) = seed_user_membership(&pool, scope, cfg.id, "sub-1").await;

        // mint + resolve + idle bump
        let mut conn = pool.acquire().await.unwrap();
        let token = "fbx_web_lifecycle";
        let session = mint_user_session(
            &mut conn,
            scope,
            membership_id,
            user_id,
            cfg.id,
            token,
            Some("urn:acr"),
            Some(&["pwd".to_string()]),
            None,
            Some("idp-sid"),
            10,
            100_000,
        )
        .await
        .unwrap();
        drop(conn);
        assert_eq!(session.user_id, user_id);

        let first = resolve_web_session(&pool, token, 1_000)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(first.membership_id, membership_id);
        assert_eq!(first.roles, vec!["member".to_string()]);
        assert_eq!(first.membership_status, "active");
        assert_eq!(first.tenant_slug, slug);
        // bumped forward from the tiny 10s mint window
        assert!(first.idle_expires_at > session.idle_expires_at);
        // and capped by the absolute expiry
        let capped = resolve_web_session(&pool, token, 10_000_000)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(capped.idle_expires_at, capped.absolute_expires_at);

        // revoke → no longer resolves
        assert!(revoke_user_session(&pool, scope, session.id).await.unwrap());
        assert!(resolve_web_session(&pool, token, 1_000)
            .await
            .unwrap()
            .is_none());

        // PATs: mint, list, resolve/bump, then the shape CHECK
        let pat_plain = "fbx_pat_abcdefghijklmnop";
        let pat = mint_pat(
            &pool,
            scope,
            membership_id,
            user_id,
            "ci-token",
            pat_plain,
            Utc::now() + chrono::Duration::days(30),
        )
        .await
        .unwrap();
        assert_eq!(pat.display_prefix.as_deref(), Some("fbx_pat_abcd"));
        assert_eq!(
            list_pats(&pool, scope, membership_id).await.unwrap().len(),
            1
        );
        let pat_auth = resolve_pat(&pool, pat_plain).await.unwrap().unwrap();
        assert_eq!(pat_auth.membership_id, membership_id);
        assert_eq!(pat_auth.membership_status, "active");

        // shape CHECK: a PAT with no expiry is rejected by the DB
        let bad = sqlx::query(
            "insert into api_tokens (id, tenant_id, kind, membership_id, user_id, name, display_prefix, token_sha256)
             values ($1, $2, 'pat', $3, $4, 'no-exp', 'fbx_pat_zzzz', $5)",
        )
        .bind(Uuid::now_v7())
        .bind(scope.tenant_id())
        .bind(membership_id)
        .bind(user_id)
        .bind(sha256_hex("fbx_pat_noexp"))
        .execute(&pool)
        .await;
        assert!(
            bad.is_err(),
            "PAT without expires_at must violate api_tokens_kind_shape"
        );

        // deactivation cascade: a second live session + the PAT both die
        let token2 = "fbx_web_cascade";
        let mut conn = pool.acquire().await.unwrap();
        mint_user_session(
            &mut conn,
            scope,
            membership_id,
            user_id,
            cfg.id,
            token2,
            None,
            None,
            None,
            None,
            3_600,
            100_000,
        )
        .await
        .unwrap();
        drop(conn);
        assert!(resolve_web_session(&pool, token2, 3_600)
            .await
            .unwrap()
            .is_some());
        assert!(resolve_pat(&pool, pat_plain).await.unwrap().is_some());

        let updated = set_membership_status(&pool, scope, membership_id, "deactivated")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(updated.status, "deactivated");
        assert!(updated.deactivated_at.is_some());
        assert!(resolve_web_session(&pool, token2, 3_600)
            .await
            .unwrap()
            .is_none());
        assert!(resolve_pat(&pool, pat_plain).await.unwrap().is_none());

        // reads
        assert!(get_user(&pool, scope, user_id).await.unwrap().is_some());
        assert_eq!(list_memberships(&pool, scope).await.unwrap().len(), 1);
        assert!(get_membership(&pool, scope, membership_id)
            .await
            .unwrap()
            .is_some());

        cleanup_tenant(&pool, org.id).await;
    }

    #[tokio::test]
    async fn audit_log_is_append_only() {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("skipping: DATABASE_URL not set");
            return;
        };
        let pool = connect(&url).await.expect("connect");

        // Everything inside one tx we roll back — an audit row can never be
        // deleted (the trigger blocks it), so we never commit one in a test.
        let mut tx = pool.begin().await.unwrap();
        let detail = serde_json::json!({"before": "a", "after": "b"});
        let id = insert_audit(
            &mut tx,
            AuditEntry {
                tenant_id: None,
                actor_kind: "operator",
                actor_id: Some("op-1"),
                source_ip: Some("127.0.0.1"),
                request_id: Some("req-1"),
                action: "test.audit",
                target: Some("thing"),
                success: true,
                detail: Some(&detail),
            },
        )
        .await
        .unwrap();

        // UPDATE is refused by the append-only trigger.
        let upd = sqlx::query("update auth_audit_log set success = false where id = $1")
            .bind(id)
            .execute(&mut *tx)
            .await;
        assert!(
            upd.is_err(),
            "UPDATE must raise auth_audit_log is append-only"
        );
        // The failed statement poisons the tx; roll it back so nothing persists.
        tx.rollback().await.ok();

        // DELETE is likewise refused (fresh tx, also rolled back).
        let mut tx = pool.begin().await.unwrap();
        let id2 = insert_audit(
            &mut tx,
            AuditEntry {
                tenant_id: None,
                actor_kind: "system",
                actor_id: None,
                source_ip: None,
                request_id: None,
                action: "test.audit.delete",
                target: None,
                success: false,
                detail: None,
            },
        )
        .await
        .unwrap();
        let del = sqlx::query("delete from auth_audit_log where id = $1")
            .bind(id2)
            .execute(&mut *tx)
            .await;
        assert!(
            del.is_err(),
            "DELETE must raise auth_audit_log is append-only"
        );
        tx.rollback().await.ok();
    }
}
