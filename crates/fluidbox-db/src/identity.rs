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
use serde_json::{json, Value};
use sqlx::error::DatabaseError;
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
    /// ID-token authentication context (verbatim, if the login carried it) — the
    /// caller derives `authentication_strength` from these; presence proves
    /// nothing on its own.
    pub acr: Option<String>,
    pub amr: Option<Vec<String>>,
    pub auth_time: Option<DateTime<Utc>>,
    pub idle_expires_at: DateTime<Utc>,
    pub absolute_expires_at: DateTime<Utc>,
}

/// The joined result of resolving a PAT: the token plus its live membership
/// (status + roles) and tenant status. The caller refuses a non-`active`
/// membership OR a non-`active` tenant (fail-closed, in one place).
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct PatAuth {
    pub token_id: Uuid,
    pub tenant_id: Uuid,
    pub tenant_status: String,
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
    /// Save-time validated discovery document + signing keys, cached at insert
    /// so a staged config carries a fresh photograph before it is ever activated.
    pub discovered_metadata: Option<&'a Value>,
    pub jwks: Option<&'a Value>,
    pub discovered_at: Option<DateTime<Utc>>,
}

// ─── Orgs (tenants) ─────────────────────────────────────────────────────────

/// Create a new organization (a `tenants` row). `name` is set to the slug —
/// the legacy unique `name` column survives, and slug is the identifier
/// everything routes on now.
async fn insert_org(
    conn: &mut sqlx::PgConnection,
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
    .fetch_one(&mut *conn)
    .await
}

pub async fn create_org(
    pool: &PgPool,
    slug: &str,
    display_name: Option<&str>,
) -> sqlx::Result<OrgRow> {
    let mut conn = pool.acquire().await?;
    insert_org(&mut conn, slug, display_name).await
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
    conn: &mut sqlx::PgConnection,
    scope: TenantScope,
    params: IdpConfigParams<'_>,
) -> sqlx::Result<OrgIdpConfigRow> {
    sqlx::query_as(sqlx::AssertSqlSafe(format!(
        "insert into org_idp_configs
           (id, tenant_id, generation, issuer, client_id, client_secret_sealed,
            token_endpoint_auth, scopes, alg_allowlist, claim_mappings,
            bootstrap_owner_email, bootstrap_owner_expires_at, status, created_by,
            discovered_metadata, jwks, discovered_at)
         select $1, $2,
                coalesce((select max(generation) from org_idp_configs where tenant_id = $2), 0) + 1,
                $3, $4, $5, $6, $7, $8, $9, $10, $11, 'staged', $12, $13, $14, $15
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
    .bind(params.discovered_metadata)
    .bind(params.jwks)
    .bind(params.discovered_at)
    .fetch_one(&mut *conn)
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

/// The sealed OIDC client secret for the token exchange — a narrow reader that
/// mirrors `connection_client_secret_sealed`'s shape. `OrgIdpConfigRow`
/// deliberately omits the sealed column, so the login callback fetches it only
/// here, only when it needs to authenticate to the token endpoint.
pub async fn idp_client_secret_sealed(
    pool: &PgPool,
    scope: TenantScope,
    id: Uuid,
) -> sqlx::Result<Option<Vec<u8>>> {
    let row: Option<(Option<Vec<u8>>,)> = sqlx::query_as(
        "select client_secret_sealed from org_idp_configs where tenant_id = $1 and id = $2",
    )
    .bind(scope.tenant_id())
    .bind(id)
    .fetch_optional(pool)
    .await?;
    Ok(row.and_then(|(s,)| s))
}

/// Count a tenant's still-claimable login flows — the per-org outstanding-flow
/// cap the start endpoint enforces to bound DB/IdP amplification from the
/// unauthenticated login surface (design lines 852-854).
pub async fn count_outstanding_login_flows(pool: &PgPool, scope: TenantScope) -> sqlx::Result<i64> {
    let (n,): (i64,) = sqlx::query_as(
        "select count(*) from login_flows
         where tenant_id = $1 and consumed_at is null and expires_at > now()",
    )
    .bind(scope.tenant_id())
    .fetch_one(pool)
    .await?;
    Ok(n)
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
           s.acr as acr, s.amr as amr, s.auth_time as auth_time,
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

/// Is this browser session still authorized RIGHT NOW — not revoked, within
/// both expiries, membership + tenant still active? Read-only and it does NOT
/// bump idle (design lines 658-664: the bounded stream re-auth must not extend
/// a session's life). Keyed on the session id under its verified scope.
pub async fn web_session_live(
    pool: &PgPool,
    scope: TenantScope,
    session_id: Uuid,
) -> sqlx::Result<bool> {
    let (live,): (bool,) = sqlx::query_as(
        "select exists(
           select 1 from user_sessions s
           join org_memberships m
             on m.tenant_id = s.tenant_id and m.id = s.membership_id and m.user_id = s.user_id
           join tenants t on t.id = s.tenant_id
           where s.tenant_id = $1 and s.id = $2
             and s.revoked_at is null
             and s.idle_expires_at > now()
             and s.absolute_expires_at > now()
             and m.status = 'active'
             and t.status = 'active')",
    )
    .bind(scope.tenant_id())
    .bind(session_id)
    .fetch_one(pool)
    .await?;
    Ok(live)
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
         from org_memberships m, tenants t
         where tok.kind = 'pat' and tok.token_sha256 = $1
           and tok.revoked_at is null
           and tok.expires_at > now()
           and m.tenant_id = tok.tenant_id and m.id = tok.membership_id and m.user_id = tok.user_id
           and t.id = tok.tenant_id
         returning tok.id as token_id, tok.tenant_id as tenant_id, t.status as tenant_status,
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
    insert_audit_with_id(conn, Uuid::now_v7(), entry).await
}

/// Append an audit row with a caller-chosen id. The break-glass arming rows use
/// this so the audit row's PK can also appear INSIDE its own `detail` (`arm_id`),
/// giving Task 5's consumption rows a stable value to correlate against.
pub async fn insert_audit_with_id(
    conn: &mut sqlx::PgConnection,
    id: Uuid,
    entry: AuditEntry<'_>,
) -> sqlx::Result<Uuid> {
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

/// Executor-generic core of a status change + its deactivation cascade. When the
/// new status is `deactivated` it revokes the membership's sessions and PATs in
/// the SAME transaction (design lines 762-767). Callers that must also write an
/// audit row inside the transaction reuse this (the operator kill switch does).
async fn apply_membership_status(
    conn: &mut sqlx::PgConnection,
    scope: TenantScope,
    id: Uuid,
    status: &str,
) -> sqlx::Result<Option<OrgMembershipRow>> {
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
    .fetch_optional(&mut *conn)
    .await?;

    if let Some(ref m) = row {
        if status == "deactivated" {
            revoke_sessions_for_membership(&mut *conn, scope, m.id).await?;
            sqlx::query(
                "update api_tokens set revoked_at = now()
                 where kind = 'pat' and tenant_id = $1 and membership_id = $2
                   and revoked_at is null",
            )
            .bind(scope.tenant_id())
            .bind(m.id)
            .execute(&mut *conn)
            .await?;
        }
    }
    Ok(row)
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
    let row = apply_membership_status(&mut tx, scope, id, status).await?;
    tx.commit().await?;
    Ok(row)
}

// ─── Admin org lifecycle (Task 6) ───────────────────────────────────────────
//
// Each mutating fn owns its transaction AND the `FOR UPDATE` lock discipline, so
// serialization (with each other and with a login's transaction B) is
// structural, not caller-dependent. An ACCEPTED mutation writes its audit row
// INSIDE that same transaction — a failed audit insert fails the mutation. A
// REJECTED attempt returns a [`LifecycleOutcome`] variant and is audited by the
// caller in a separate transaction. actor_kind is always `operator` here (these
// routes are admin-token gated); the action vocabulary lives with the operation.

/// The result of a lifecycle transition. `Done` has already committed its
/// accepted audit row; the caller audits `NotFound`/`Refused` as a rejected
/// attempt (a separate committed transaction) and maps them to 404 / 409.
pub enum LifecycleOutcome<T> {
    Done(T),
    NotFound,
    Refused(&'static str),
}

/// Cancel/revoke tallies for the disable + swap cascades.
pub struct CascadeCounts {
    pub flows_cancelled: u64,
    pub switches_cancelled: u64,
    pub sessions_revoked: u64,
}

/// The issuer-migration swap's full tally (adds membership deactivations).
pub struct MigrateCounts {
    pub flows_cancelled: u64,
    pub switches_cancelled: u64,
    pub sessions_revoked: u64,
    pub memberships_deactivated: u64,
}

/// Outcome of creating an org: the row, or a slug collision (409).
pub enum CreateOrgOutcome {
    Created(OrgRow),
    SlugConflict,
}

/// A joined member row for the operator membership list.
#[derive(Debug, Clone, sqlx::FromRow, serde::Serialize)]
pub struct MemberRow {
    pub membership_id: Uuid,
    pub user_id: Uuid,
    pub roles: Vec<String>,
    pub membership_status: String,
    pub email: Option<String>,
    pub name: Option<String>,
    pub user_status: String,
    pub idp_config_id: Uuid,
    pub created_at: DateTime<Utc>,
    pub last_login_at: Option<DateTime<Utc>>,
}

/// The mutable-field patch for an IdP config (identity fields are refused by the
/// handler, never reach here). Each `Some` field is applied via `coalesce`.
pub struct IdpPatch<'a> {
    pub client_secret_sealed: Option<Vec<u8>>,
    pub token_endpoint_auth: Option<&'a str>,
    pub scopes: Option<&'a [String]>,
    pub claim_mappings: Option<&'a Value>,
    pub alg_allowlist: Option<&'a [String]>,
    /// `Some((normalized_email, expires_at))` re-arms the bootstrap owner.
    pub bootstrap: Option<(&'a str, DateTime<Utc>)>,
}

#[derive(sqlx::FromRow)]
struct LockedConfig {
    id: Uuid,
    generation: i32,
    status: String,
}

/// Lock EVERY IdP config row of the org `FOR UPDATE` in a deterministic order
/// (by id) — the uniform lock every status transition and the swap take, so they
/// serialize with each other without deadlock, and with a login's transaction B
/// (which locks the single active row). Returns the locked triples.
async fn lock_org_configs(
    conn: &mut sqlx::PgConnection,
    scope: TenantScope,
) -> sqlx::Result<Vec<LockedConfig>> {
    sqlx::query_as(
        "select id, generation, status from org_idp_configs
         where tenant_id = $1 order by id for update",
    )
    .bind(scope.tenant_id())
    .fetch_all(&mut *conn)
    .await
}

/// Cancel a config's unconsumed login flows + pending switches and revoke its
/// live sessions — the shared half of both disable and the migration swap
/// (design lines 197-200).
async fn cancel_config_flows_switches_sessions(
    conn: &mut sqlx::PgConnection,
    scope: TenantScope,
    config_id: Uuid,
) -> sqlx::Result<CascadeCounts> {
    let flows = sqlx::query(
        "update login_flows set consumed_at = now()
         where tenant_id = $1 and idp_config_id = $2 and consumed_at is null",
    )
    .bind(scope.tenant_id())
    .bind(config_id)
    .execute(&mut *conn)
    .await?
    .rows_affected();
    let switches = sqlx::query(
        "update pending_login_switches set consumed_at = now()
         where tenant_id = $1 and idp_config_id = $2 and consumed_at is null",
    )
    .bind(scope.tenant_id())
    .bind(config_id)
    .execute(&mut *conn)
    .await?
    .rows_affected();
    let sessions = sqlx::query(
        "update user_sessions set revoked_at = now()
         where tenant_id = $1 and idp_config_id = $2 and revoked_at is null",
    )
    .bind(scope.tenant_id())
    .bind(config_id)
    .execute(&mut *conn)
    .await?
    .rows_affected();
    Ok(CascadeCounts {
        flows_cancelled: flows,
        switches_cancelled: switches,
        sessions_revoked: sessions,
    })
}

/// Deactivate every membership whose user was provisioned by `config_id`, and
/// revoke those memberships' PATs — the issuer-migration default (design lines
/// 790-792). Their sessions already carry the old config id and were revoked by
/// [`cancel_config_flows_switches_sessions`].
async fn deactivate_config_memberships(
    conn: &mut sqlx::PgConnection,
    scope: TenantScope,
    config_id: Uuid,
) -> sqlx::Result<u64> {
    let n = sqlx::query(
        "update org_memberships m
         set status = 'deactivated', deactivated_at = now(), updated_at = now()
         from users u
         where m.tenant_id = $1 and u.tenant_id = m.tenant_id and u.id = m.user_id
           and u.idp_config_id = $2 and m.status = 'active'",
    )
    .bind(scope.tenant_id())
    .bind(config_id)
    .execute(&mut *conn)
    .await?
    .rows_affected();
    sqlx::query(
        "update api_tokens tok set revoked_at = now()
         from org_memberships m, users u
         where tok.kind = 'pat' and tok.tenant_id = $1 and tok.revoked_at is null
           and tok.membership_id = m.id
           and m.tenant_id = tok.tenant_id and u.tenant_id = m.tenant_id and u.id = m.user_id
           and u.idp_config_id = $2",
    )
    .bind(scope.tenant_id())
    .bind(config_id)
    .execute(&mut *conn)
    .await?;
    Ok(n)
}

/// Build an operator (`actor_kind='operator'`, no `actor_id`) accepted-audit
/// entry — the borrowed pieces are locals the caller holds across the insert.
fn operator_audit<'a>(
    tenant_id: Uuid,
    source_ip: Option<&'a str>,
    action: &'a str,
    target: &'a str,
    detail: &'a Value,
) -> AuditEntry<'a> {
    AuditEntry {
        tenant_id: Some(tenant_id),
        actor_kind: "operator",
        actor_id: None,
        source_ip,
        request_id: None,
        action,
        target: Some(target),
        success: true,
        detail: Some(detail),
    }
}

/// Refuse to arm while an active owner exists (design 709-711); otherwise set
/// the arm + expiry. Assumes the caller already holds the config row `FOR
/// UPDATE`, so the owner read and the arm serialize with bootstrap consumption.
async fn check_and_arm_bootstrap(
    conn: &mut sqlx::PgConnection,
    scope: TenantScope,
    config_id: Uuid,
    normalized_email: &str,
    expires_at: DateTime<Utc>,
) -> sqlx::Result<bool> {
    if active_owner_exists(&mut *conn, scope).await? {
        return Ok(false);
    }
    sqlx::query(
        "update org_idp_configs
         set bootstrap_owner_email = $3, bootstrap_owner_expires_at = $4, updated_at = now()
         where tenant_id = $1 and id = $2",
    )
    .bind(scope.tenant_id())
    .bind(config_id)
    .bind(normalized_email)
    .bind(expires_at)
    .execute(&mut *conn)
    .await?;
    Ok(true)
}

/// Create an org + its accepted `org.create` audit row in one transaction. A
/// slug collision (unique violation) becomes `SlugConflict` (409), not an error.
pub async fn create_org_audited(
    pool: &PgPool,
    slug: &str,
    display_name: Option<&str>,
    source_ip: Option<&str>,
) -> sqlx::Result<CreateOrgOutcome> {
    let mut tx = pool.begin().await?;
    let row = match insert_org(&mut tx, slug, display_name).await {
        Ok(r) => r,
        Err(e) => {
            tx.rollback().await.ok();
            if e.as_database_error()
                .map(DatabaseError::is_unique_violation)
                .unwrap_or(false)
            {
                return Ok(CreateOrgOutcome::SlugConflict);
            }
            return Err(e);
        }
    };
    let detail = json!({ "slug": row.slug });
    let target = row.slug.clone();
    insert_audit(
        &mut tx,
        operator_audit(row.id, source_ip, "org.create", &target, &detail),
    )
    .await?;
    tx.commit().await?;
    Ok(CreateOrgOutcome::Created(row))
}

/// Insert a staged IdP config (discovery pre-cached in `params`) + its accepted
/// `idp.create` audit row in one transaction.
pub async fn create_idp_config_audited(
    pool: &PgPool,
    scope: TenantScope,
    params: IdpConfigParams<'_>,
    source_ip: Option<&str>,
) -> sqlx::Result<OrgIdpConfigRow> {
    let mut tx = pool.begin().await?;
    let row = create_idp_config(&mut tx, scope, params).await?;
    let detail = json!({
        "generation": row.generation,
        "issuer_sha256": sha256_hex(&row.issuer),
        "token_endpoint_auth": row.token_endpoint_auth,
        "bootstrap_armed": row.bootstrap_owner_email.is_some(),
    });
    let target = row.id.to_string();
    insert_audit(
        &mut tx,
        operator_audit(scope.tenant_id(), source_ip, "idp.create", &target, &detail),
    )
    .await?;
    tx.commit().await?;
    Ok(row)
}

/// `staged → active`, refused (409) while another row is active. The pre-check
/// gives a clean refusal; the partial unique index is the backstop.
pub async fn activate_idp_config(
    pool: &PgPool,
    scope: TenantScope,
    id: Uuid,
    source_ip: Option<&str>,
) -> sqlx::Result<LifecycleOutcome<OrgIdpConfigRow>> {
    let mut tx = pool.begin().await?;
    let configs = lock_org_configs(&mut tx, scope).await?;
    let Some(target) = configs.iter().find(|c| c.id == id) else {
        tx.rollback().await.ok();
        return Ok(LifecycleOutcome::NotFound);
    };
    if target.status != "staged" {
        tx.rollback().await.ok();
        return Ok(LifecycleOutcome::Refused(
            "only a staged configuration can be activated",
        ));
    }
    if configs.iter().any(|c| c.id != id && c.status == "active") {
        tx.rollback().await.ok();
        return Ok(LifecycleOutcome::Refused(
            "another IdP configuration is already active",
        ));
    }
    let row: OrgIdpConfigRow = sqlx::query_as(sqlx::AssertSqlSafe(format!(
        "update org_idp_configs set status = 'active', updated_at = now()
         where tenant_id = $1 and id = $2 returning {IDP_CONFIG_COLS}"
    )))
    .bind(scope.tenant_id())
    .bind(id)
    .fetch_one(&mut *tx)
    .await?;
    let detail = json!({ "generation": row.generation, "issuer_sha256": sha256_hex(&row.issuer) });
    let target_s = id.to_string();
    insert_audit(
        &mut tx,
        operator_audit(
            scope.tenant_id(),
            source_ip,
            "idp.activate",
            &target_s,
            &detail,
        ),
    )
    .await?;
    tx.commit().await?;
    Ok(LifecycleOutcome::Done(row))
}

/// `active → disabled`, cancelling the config's unconsumed flows + switches and
/// revoking its sessions in the same transaction (design lines 197-200).
pub async fn disable_idp_config(
    pool: &PgPool,
    scope: TenantScope,
    id: Uuid,
    source_ip: Option<&str>,
) -> sqlx::Result<LifecycleOutcome<CascadeCounts>> {
    let mut tx = pool.begin().await?;
    let configs = lock_org_configs(&mut tx, scope).await?;
    let Some(target) = configs.iter().find(|c| c.id == id) else {
        tx.rollback().await.ok();
        return Ok(LifecycleOutcome::NotFound);
    };
    if target.status != "active" {
        tx.rollback().await.ok();
        return Ok(LifecycleOutcome::Refused(
            "only an active configuration can be disabled",
        ));
    }
    let generation = target.generation;
    sqlx::query(
        "update org_idp_configs set status = 'disabled', updated_at = now()
         where tenant_id = $1 and id = $2",
    )
    .bind(scope.tenant_id())
    .bind(id)
    .execute(&mut *tx)
    .await?;
    let counts = cancel_config_flows_switches_sessions(&mut tx, scope, id).await?;
    let detail = json!({
        "generation": generation,
        "flows_cancelled": counts.flows_cancelled,
        "switches_cancelled": counts.switches_cancelled,
        "sessions_revoked": counts.sessions_revoked,
    });
    let target_s = id.to_string();
    insert_audit(
        &mut tx,
        operator_audit(
            scope.tenant_id(),
            source_ip,
            "idp.disable",
            &target_s,
            &detail,
        ),
    )
    .await?;
    tx.commit().await?;
    Ok(LifecycleOutcome::Done(counts))
}

/// `disabled → active`, only while no other row is active (design line 203).
pub async fn reactivate_idp_config(
    pool: &PgPool,
    scope: TenantScope,
    id: Uuid,
    source_ip: Option<&str>,
) -> sqlx::Result<LifecycleOutcome<OrgIdpConfigRow>> {
    let mut tx = pool.begin().await?;
    let configs = lock_org_configs(&mut tx, scope).await?;
    let Some(target) = configs.iter().find(|c| c.id == id) else {
        tx.rollback().await.ok();
        return Ok(LifecycleOutcome::NotFound);
    };
    if target.status != "disabled" {
        tx.rollback().await.ok();
        return Ok(LifecycleOutcome::Refused(
            "only a disabled configuration can be reactivated",
        ));
    }
    if configs.iter().any(|c| c.id != id && c.status == "active") {
        tx.rollback().await.ok();
        return Ok(LifecycleOutcome::Refused(
            "another IdP configuration is already active",
        ));
    }
    let row: OrgIdpConfigRow = sqlx::query_as(sqlx::AssertSqlSafe(format!(
        "update org_idp_configs set status = 'active', updated_at = now()
         where tenant_id = $1 and id = $2 returning {IDP_CONFIG_COLS}"
    )))
    .bind(scope.tenant_id())
    .bind(id)
    .fetch_one(&mut *tx)
    .await?;
    let detail = json!({ "generation": row.generation });
    let target_s = id.to_string();
    insert_audit(
        &mut tx,
        operator_audit(
            scope.tenant_id(),
            source_ip,
            "idp.reactivate",
            &target_s,
            &detail,
        ),
    )
    .await?;
    tx.commit().await?;
    Ok(LifecycleOutcome::Done(row))
}

/// The staged issuer-migration swap (design lines 781-802): old (must be active)
/// → `retired`, new (must be staged) → `active` — retire FIRST so the one-active
/// partial index permits the order inside the transaction. Cancels the old
/// config's flows + switches, revokes its sessions, and (unless `carry_forward`)
/// deactivates its provisioned memberships (killing their PATs). Locks the org's
/// IdP rows `FOR UPDATE`, the same lock a login's transaction B takes.
pub async fn migrate_idp_config(
    pool: &PgPool,
    scope: TenantScope,
    old_id: Uuid,
    new_id: Uuid,
    carry_forward: bool,
    source_ip: Option<&str>,
) -> sqlx::Result<LifecycleOutcome<MigrateCounts>> {
    let mut tx = pool.begin().await?;
    let configs = lock_org_configs(&mut tx, scope).await?;
    let (Some(old), Some(new)) = (
        configs.iter().find(|c| c.id == old_id),
        configs.iter().find(|c| c.id == new_id),
    ) else {
        tx.rollback().await.ok();
        return Ok(LifecycleOutcome::NotFound);
    };
    if old.status != "active" {
        tx.rollback().await.ok();
        return Ok(LifecycleOutcome::Refused(
            "the configuration being migrated must be active",
        ));
    }
    if new.status != "staged" {
        tx.rollback().await.ok();
        return Ok(LifecycleOutcome::Refused(
            "the replacement configuration must be staged",
        ));
    }
    let (old_gen, new_gen) = (old.generation, new.generation);
    // Retire old FIRST (frees the one-active slot), then activate new.
    sqlx::query(
        "update org_idp_configs set status = 'retired', updated_at = now()
         where tenant_id = $1 and id = $2",
    )
    .bind(scope.tenant_id())
    .bind(old_id)
    .execute(&mut *tx)
    .await?;
    sqlx::query(
        "update org_idp_configs set status = 'active', updated_at = now()
         where tenant_id = $1 and id = $2",
    )
    .bind(scope.tenant_id())
    .bind(new_id)
    .execute(&mut *tx)
    .await?;
    let cascade = cancel_config_flows_switches_sessions(&mut tx, scope, old_id).await?;
    let memberships_deactivated = if carry_forward {
        0
    } else {
        deactivate_config_memberships(&mut tx, scope, old_id).await?
    };
    let counts = MigrateCounts {
        flows_cancelled: cascade.flows_cancelled,
        switches_cancelled: cascade.switches_cancelled,
        sessions_revoked: cascade.sessions_revoked,
        memberships_deactivated,
    };
    let detail = json!({
        "old_config": old_id,
        "new_config": new_id,
        "old_generation": old_gen,
        "new_generation": new_gen,
        "carry_forward": carry_forward,
        "flows_cancelled": counts.flows_cancelled,
        "switches_cancelled": counts.switches_cancelled,
        "sessions_revoked": counts.sessions_revoked,
        "memberships_deactivated": counts.memberships_deactivated,
    });
    let target_s = old_id.to_string();
    insert_audit(
        &mut tx,
        operator_audit(
            scope.tenant_id(),
            source_ip,
            "idp.migrate",
            &target_s,
            &detail,
        ),
    )
    .await?;
    tx.commit().await?;
    Ok(LifecycleOutcome::Done(counts))
}

/// Re-arm the bootstrap owner on `config_id` (break-glass), refused (409) while
/// an active owner exists. Locks the config row `FOR UPDATE` (serializes with
/// bootstrap consumption). The accepted audit row's PK is recorded in its own
/// `detail` as `arm_id`, so Task 5's consumption rows can be correlated.
pub async fn arm_bootstrap_owner(
    pool: &PgPool,
    scope: TenantScope,
    config_id: Uuid,
    normalized_email: &str,
    expires_at: DateTime<Utc>,
    source_ip: Option<&str>,
) -> sqlx::Result<LifecycleOutcome<Uuid>> {
    let mut tx = pool.begin().await?;
    let locked: Option<(String,)> = sqlx::query_as(
        "select status from org_idp_configs where tenant_id = $1 and id = $2 for update",
    )
    .bind(scope.tenant_id())
    .bind(config_id)
    .fetch_optional(&mut *tx)
    .await?;
    if locked.is_none() {
        tx.rollback().await.ok();
        return Ok(LifecycleOutcome::NotFound);
    }
    if !check_and_arm_bootstrap(&mut tx, scope, config_id, normalized_email, expires_at).await? {
        tx.rollback().await.ok();
        return Ok(LifecycleOutcome::Refused(
            "an active owner already exists; deactivate it before arming",
        ));
    }
    let arm_id = Uuid::now_v7();
    let detail = json!({
        "arm_id": arm_id,
        "email_sha256": sha256_hex(normalized_email),
        "expires_at": expires_at,
    });
    let target_s = config_id.to_string();
    insert_audit_with_id(
        &mut tx,
        arm_id,
        operator_audit(
            scope.tenant_id(),
            source_ip,
            "break_glass.arm",
            &target_s,
            &detail,
        ),
    )
    .await?;
    tx.commit().await?;
    Ok(LifecycleOutcome::Done(arm_id))
}

/// Apply a mutable-field patch (+ optional bootstrap re-arm) to an IdP config in
/// one transaction, audited as `idp.patch`. Identity-field changes never reach
/// here (the handler refuses them). A refused re-arm rolls back the whole patch.
pub async fn patch_idp_config(
    pool: &PgPool,
    scope: TenantScope,
    id: Uuid,
    patch: IdpPatch<'_>,
    source_ip: Option<&str>,
) -> sqlx::Result<LifecycleOutcome<OrgIdpConfigRow>> {
    let mut tx = pool.begin().await?;
    let locked: Option<(String,)> = sqlx::query_as(
        "select status from org_idp_configs where tenant_id = $1 and id = $2 for update",
    )
    .bind(scope.tenant_id())
    .bind(id)
    .fetch_optional(&mut *tx)
    .await?;
    if locked.is_none() {
        tx.rollback().await.ok();
        return Ok(LifecycleOutcome::NotFound);
    }
    let row: OrgIdpConfigRow = sqlx::query_as(sqlx::AssertSqlSafe(format!(
        "update org_idp_configs set
           client_secret_sealed = coalesce($3::bytea, client_secret_sealed),
           token_endpoint_auth = coalesce($4::text, token_endpoint_auth),
           scopes = coalesce($5::text[], scopes),
           claim_mappings = coalesce($6::jsonb, claim_mappings),
           alg_allowlist = coalesce($7::text[], alg_allowlist),
           updated_at = now()
         where tenant_id = $1 and id = $2 returning {IDP_CONFIG_COLS}"
    )))
    .bind(scope.tenant_id())
    .bind(id)
    .bind(patch.client_secret_sealed.as_deref())
    .bind(patch.token_endpoint_auth)
    .bind(patch.scopes.map(<[String]>::to_vec))
    .bind(patch.claim_mappings)
    .bind(patch.alg_allowlist.map(<[String]>::to_vec))
    .fetch_one(&mut *tx)
    .await?;

    let mut arm_id: Option<Uuid> = None;
    if let Some((email, expires_at)) = patch.bootstrap {
        if !check_and_arm_bootstrap(&mut tx, scope, id, email, expires_at).await? {
            tx.rollback().await.ok();
            return Ok(LifecycleOutcome::Refused(
                "an active owner already exists; deactivate it before arming",
            ));
        }
        arm_id = Some(Uuid::now_v7());
    }

    let detail = json!({
        "generation": row.generation,
        "client_secret_rotated": patch.client_secret_sealed.is_some(),
        "token_endpoint_auth_changed": patch.token_endpoint_auth.is_some(),
        "scopes_changed": patch.scopes.is_some(),
        "claim_mappings_changed": patch.claim_mappings.is_some(),
        "alg_allowlist_changed": patch.alg_allowlist.is_some(),
        "bootstrap_armed": patch.bootstrap.is_some(),
        "arm_id": arm_id,
    });
    let target_s = id.to_string();
    let entry = operator_audit(
        scope.tenant_id(),
        source_ip,
        "idp.patch",
        &target_s,
        &detail,
    );
    match arm_id {
        Some(aid) => insert_audit_with_id(&mut tx, aid, entry).await?,
        None => insert_audit(&mut tx, entry).await?,
    };
    tx.commit().await?;
    Ok(LifecycleOutcome::Done(row))
}

/// The operator membership list (users + memberships + roles + status).
pub async fn list_members(pool: &PgPool, scope: TenantScope) -> sqlx::Result<Vec<MemberRow>> {
    sqlx::query_as(
        "select m.id as membership_id, m.user_id as user_id, m.roles as roles,
                m.status as membership_status, u.email as email, u.name as name,
                u.status as user_status, u.idp_config_id as idp_config_id,
                m.created_at as created_at, u.last_login_at as last_login_at
         from org_memberships m
         join users u on u.tenant_id = m.tenant_id and u.id = m.user_id
         where m.tenant_id = $1 order by m.created_at",
    )
    .bind(scope.tenant_id())
    .fetch_all(pool)
    .await
}

/// The operator kill switch: deactivate a membership (cascade revokes its
/// sessions + PATs) + its accepted `member.deactivate` audit row, one
/// transaction. `None` when the membership does not exist under this tenant.
pub async fn deactivate_membership_audited(
    pool: &PgPool,
    scope: TenantScope,
    id: Uuid,
    source_ip: Option<&str>,
) -> sqlx::Result<Option<OrgMembershipRow>> {
    let mut tx = pool.begin().await?;
    let row = apply_membership_status(&mut tx, scope, id, "deactivated").await?;
    match &row {
        Some(m) => {
            let detail = json!({ "user": m.user_id });
            let target_s = m.id.to_string();
            insert_audit(
                &mut tx,
                operator_audit(
                    scope.tenant_id(),
                    source_ip,
                    "member.deactivate",
                    &target_s,
                    &detail,
                ),
            )
            .await?;
            tx.commit().await?;
        }
        None => {
            tx.rollback().await.ok();
        }
    }
    Ok(row)
}

/// Set a membership's roles (the only owner-granting surface besides bootstrap)
/// plus its accepted `member.roles` audit row, one transaction. `None` when the
/// membership does not exist under this tenant.
pub async fn set_membership_roles_audited(
    pool: &PgPool,
    scope: TenantScope,
    id: Uuid,
    roles: &[String],
    source_ip: Option<&str>,
) -> sqlx::Result<Option<OrgMembershipRow>> {
    let mut tx = pool.begin().await?;
    // Owner-role mutations serialize on the config row lock, alongside bootstrap
    // arming + consumption (design 2026-07-17 line 718). Lock the org's IdP
    // config rows before granting OR revoking owner: a grant is visible in the
    // new `roles`; a revocation only in the membership's current roles.
    let mut touches_owner = roles.iter().any(|r| r == "owner");
    if !touches_owner {
        let holds: Option<bool> = sqlx::query_scalar(
            "select 'owner' = any(roles) from org_memberships
             where tenant_id = $1 and id = $2",
        )
        .bind(scope.tenant_id())
        .bind(id)
        .fetch_optional(&mut *tx)
        .await?;
        touches_owner = holds.unwrap_or(false);
    }
    if touches_owner {
        // Empty for a single-admin org with no IdP configs — no bootstrap race.
        lock_org_configs(&mut tx, scope).await?;
    }
    let row: Option<OrgMembershipRow> = sqlx::query_as(
        "update org_memberships set roles = $3, updated_at = now()
         where tenant_id = $1 and id = $2 returning *",
    )
    .bind(scope.tenant_id())
    .bind(id)
    .bind(roles.to_vec())
    .fetch_optional(&mut *tx)
    .await?;
    match &row {
        Some(m) => {
            let detail = json!({ "roles": m.roles });
            let target_s = m.id.to_string();
            insert_audit(
                &mut tx,
                operator_audit(
                    scope.tenant_id(),
                    source_ip,
                    "member.roles",
                    &target_s,
                    &detail,
                ),
            )
            .await?;
            tx.commit().await?;
        }
        None => {
            tx.rollback().await.ok();
        }
    }
    Ok(row)
}

// ─── Login provisioning (transaction B) ────────────────────────────────────

/// The config + tenant state captured by transaction B's OPENING
/// `select … for update`. The lock is exclusive from the start — a
/// share-then-upgrade would deadlock two concurrent bootstrap-matching logins
/// (design lines 540-544) — and this SAME lock serializes against the
/// issuer-migration swap. `bootstrap_owner_expires_at` is captured HERE and
/// nowhere else: the bootstrap decision's `was_unexpired` must read this
/// pre-update value, never `UPDATE … RETURNING` (whose unqualified columns
/// observe the post-update NULL — the v5 fix, design lines 692-696).
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct LockedIdpConfig {
    pub config_status: String,
    pub tenant_status: String,
    pub bootstrap_owner_email: Option<String>,
    pub bootstrap_owner_expires_at: Option<DateTime<Utc>>,
}

/// Transaction B's opening lock: `for update of c` takes an exclusive row lock
/// on the config alone (the joined `tenants` row is read-only), capturing the
/// bootstrap arm + both statuses in one shot.
pub async fn lock_idp_config_for_update(
    conn: &mut sqlx::PgConnection,
    scope: TenantScope,
    id: Uuid,
) -> sqlx::Result<Option<LockedIdpConfig>> {
    sqlx::query_as(
        "select c.status as config_status, t.status as tenant_status,
                c.bootstrap_owner_email as bootstrap_owner_email,
                c.bootstrap_owner_expires_at as bootstrap_owner_expires_at
         from org_idp_configs c
         join tenants t on t.id = c.tenant_id
         where c.tenant_id = $1 and c.id = $2
         for update of c",
    )
    .bind(scope.tenant_id())
    .bind(id)
    .fetch_optional(&mut *conn)
    .await
}

/// JIT-provision a user on the identity key `(tenant, idp_config, subject)`,
/// refreshing display attributes + `last_login_at` on every login. Runs inside
/// transaction B.
#[allow(clippy::too_many_arguments)]
pub async fn upsert_user(
    conn: &mut sqlx::PgConnection,
    scope: TenantScope,
    idp_config_id: Uuid,
    subject: &str,
    email: Option<&str>,
    email_normalized: Option<&str>,
    email_verified: bool,
    name: Option<&str>,
) -> sqlx::Result<UserRow> {
    sqlx::query_as(
        "insert into users
           (id, tenant_id, idp_config_id, subject, email, email_normalized, email_verified, name, last_login_at)
         values ($1, $2, $3, $4, $5, $6, $7, $8, now())
         on conflict (tenant_id, idp_config_id, subject) do update
         set email = excluded.email,
             email_normalized = excluded.email_normalized,
             email_verified = excluded.email_verified,
             name = excluded.name,
             last_login_at = now(),
             updated_at = now()
         returning *",
    )
    .bind(Uuid::now_v7())
    .bind(scope.tenant_id())
    .bind(idp_config_id)
    .bind(subject)
    .bind(email)
    .bind(email_normalized)
    .bind(email_verified)
    .bind(name)
    .fetch_one(&mut *conn)
    .await
}

/// Upsert the membership with the mapped roles, but NEVER strip `owner` on a
/// refresh (design line 553): if the existing row already holds `owner`, it is
/// preserved regardless of the mapped set. Brand-new rows are `active`; an
/// existing row's `status` is untouched (a deactivated membership stays
/// deactivated so the caller refuses the login).
pub async fn upsert_membership_preserving_owner(
    conn: &mut sqlx::PgConnection,
    scope: TenantScope,
    user_id: Uuid,
    roles: &[String],
) -> sqlx::Result<OrgMembershipRow> {
    sqlx::query_as(
        "insert into org_memberships (id, tenant_id, user_id, roles, status)
         values ($1, $2, $3, $4, 'active')
         on conflict (tenant_id, user_id) do update
         set roles = case
               when 'owner' = any(org_memberships.roles)
                 then (select array(select distinct e from unnest(excluded.roles || array['owner']) e))
               else (select array(select distinct e from unnest(excluded.roles) e))
             end,
             updated_at = now()
         returning *",
    )
    .bind(Uuid::now_v7())
    .bind(scope.tenant_id())
    .bind(user_id)
    .bind(roles.to_vec())
    .fetch_one(&mut *conn)
    .await
}

/// Is there an ACTIVE owner in this org right now? The bootstrap decision reads
/// this under the config `FOR UPDATE` lock, so owner reads are consistent.
pub async fn active_owner_exists(
    conn: &mut sqlx::PgConnection,
    scope: TenantScope,
) -> sqlx::Result<bool> {
    let (exists,): (bool,) = sqlx::query_as(
        "select exists(
           select 1 from org_memberships
           where tenant_id = $1 and status = 'active' and 'owner' = any(roles))",
    )
    .bind(scope.tenant_id())
    .fetch_one(&mut *conn)
    .await?;
    Ok(exists)
}

/// The single-winner bootstrap-owner claim (design lines 683-690): clears BOTH
/// arm and expiry where the armed email matches. Returns `Some(config_id)` iff
/// exactly this login consumed the arm — a matching arm is ALWAYS consumed;
/// the three-way promote/reject decision happens in the caller from the expiry
/// captured by [`lock_idp_config_for_update`].
pub async fn consume_bootstrap_arm(
    conn: &mut sqlx::PgConnection,
    scope: TenantScope,
    config_id: Uuid,
    normalized_email: &str,
) -> sqlx::Result<Option<Uuid>> {
    let row: Option<(Uuid,)> = sqlx::query_as(
        "update org_idp_configs
         set bootstrap_owner_email = null, bootstrap_owner_expires_at = null, updated_at = now()
         where tenant_id = $1 and id = $2 and bootstrap_owner_email = $3
         returning id",
    )
    .bind(scope.tenant_id())
    .bind(config_id)
    .bind(normalized_email)
    .fetch_optional(&mut *conn)
    .await?;
    Ok(row.map(|(id,)| id))
}

/// Promote a membership to `owner` (bootstrap consumption winner). Idempotent
/// and order-free — appends `owner` to the existing role set, deduped.
pub async fn add_owner_role(
    conn: &mut sqlx::PgConnection,
    scope: TenantScope,
    membership_id: Uuid,
) -> sqlx::Result<()> {
    sqlx::query(
        "update org_memberships
         set roles = (select array(select distinct e from unnest(roles || array['owner']) e)),
             updated_at = now()
         where tenant_id = $1 and id = $2",
    )
    .bind(scope.tenant_id())
    .bind(membership_id)
    .execute(&mut *conn)
    .await?;
    Ok(())
}

/// Revoke one session inside transaction B (the same-user re-login refresh path
/// revokes the old session and mints a new one in one commit).
pub async fn revoke_user_session_conn(
    conn: &mut sqlx::PgConnection,
    scope: TenantScope,
    id: Uuid,
) -> sqlx::Result<bool> {
    let res = sqlx::query(
        "update user_sessions set revoked_at = now()
         where tenant_id = $1 and id = $2 and revoked_at is null",
    )
    .bind(scope.tenant_id())
    .bind(id)
    .execute(&mut *conn)
    .await?;
    Ok(res.rows_affected() == 1)
}

/// Insert a one-time session-replacement confirmation (design lines 333-377),
/// GC-on-insert like the login flows. Runs inside transaction B; the row's
/// tenant is the NEW login's org, and the replaced session is composite-FK'd in
/// ITS own tenant.
#[allow(clippy::too_many_arguments)]
pub async fn create_pending_switch(
    conn: &mut sqlx::PgConnection,
    scope: TenantScope,
    idp_config_id: Uuid,
    new_membership_id: Uuid,
    new_user_id: Uuid,
    replaced_tenant_id: Uuid,
    replaced_session_id: Uuid,
    redirect_to: &str,
    browser_hash: &str,
    acr: Option<&str>,
    amr: Option<&[String]>,
    auth_time: Option<DateTime<Utc>>,
) -> sqlx::Result<Uuid> {
    sqlx::query(
        "delete from pending_login_switches
         where (consumed_at is null and expires_at < now())
            or expires_at < now() - interval '7 days'",
    )
    .execute(&mut *conn)
    .await?;
    let id = Uuid::now_v7();
    sqlx::query(
        "insert into pending_login_switches
           (id, tenant_id, idp_config_id, new_membership_id, new_user_id,
            replaced_tenant_id, replaced_session_id, redirect_to, browser_hash,
            acr, amr, auth_time, expires_at)
         values ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12,
                 now() + interval '120 seconds')",
    )
    .bind(id)
    .bind(scope.tenant_id())
    .bind(idp_config_id)
    .bind(new_membership_id)
    .bind(new_user_id)
    .bind(replaced_tenant_id)
    .bind(replaced_session_id)
    .bind(redirect_to)
    .bind(browser_hash)
    .bind(acr)
    .bind(amr.map(<[String]>::to_vec))
    .bind(auth_time)
    .execute(&mut *conn)
    .await?;
    Ok(id)
}

/// What [`claim_pending_switch`] yields: both tenant contexts, the new
/// membership triple, and the freshly minted session token to set as the new
/// `__Host-fbx_web` cookie. Not `Serialize` — it carries the plaintext token.
#[derive(Debug, Clone)]
pub struct SwitchClaim {
    pub new_tenant_id: Uuid,
    pub replaced_tenant_id: Uuid,
    pub redirect_to: String,
    pub new_session_token: String,
}

#[derive(sqlx::FromRow)]
struct SwitchClaimRow {
    tenant_id: Uuid,
    replaced_tenant_id: Uuid,
    replaced_session_id: Uuid,
    new_membership_id: Uuid,
    new_user_id: Uuid,
    idp_config_id: Uuid,
    redirect_to: String,
    acr: Option<String>,
    amr: Option<Vec<String>>,
    auth_time: Option<DateTime<Utc>>,
}

/// The dual-tenant one-time switch claim (design lines 355-377) — the second
/// (and last) credential-like bootstrap exception to single-tenant scoping. It
/// is deliberately ONE narrowly named method: the claiming UPDATE's predicate
/// requires the confirmation-cookie hash, unconsumed/unexpired state, AND that
/// the browser's currently-presented live `__Host-fbx_web` session equals the
/// row's replaced `(tenant, session)` and is still valid; the same transaction
/// rechecks config- and membership-active on the NEW org, revokes the replaced
/// session, and mints the new one — atomically, or nothing. Every failure mode
/// returns `None` (fail closed keeping the original session); the caller never
/// trusts a form-carried identity or redirect.
#[allow(clippy::too_many_arguments)]
pub async fn claim_pending_switch(
    pool: &PgPool,
    switch_id: Uuid,
    switch_browser_hash: &str,
    current_session_token: &str,
    new_token_plain: &str,
    idle_secs: i64,
    absolute_secs: i64,
) -> sqlx::Result<Option<SwitchClaim>> {
    let mut tx = pool.begin().await?;

    // (1) Atomic claim binding the currently-presented live session.
    let claimed: Option<SwitchClaimRow> = sqlx::query_as(
        "update pending_login_switches ps set consumed_at = now()
         from user_sessions cur
         where ps.id = $1
           and ps.browser_hash = $2
           and ps.consumed_at is null
           and ps.expires_at > now()
           and cur.session_token_sha256 = $3
           and cur.tenant_id = ps.replaced_tenant_id
           and cur.id = ps.replaced_session_id
           and cur.revoked_at is null
           and cur.idle_expires_at > now()
           and cur.absolute_expires_at > now()
         returning ps.tenant_id, ps.replaced_tenant_id, ps.replaced_session_id,
                   ps.new_membership_id, ps.new_user_id, ps.idp_config_id,
                   ps.redirect_to, ps.acr, ps.amr, ps.auth_time",
    )
    .bind(switch_id)
    .bind(switch_browser_hash)
    .bind(sha256_hex(current_session_token))
    .fetch_optional(&mut *tx)
    .await?;
    let Some(row) = claimed else {
        tx.rollback().await.ok();
        return Ok(None);
    };

    // (2) Recheck config-active + membership-active + tenant-active on the NEW org.
    let recheck = sqlx::query(
        "select 1 from org_idp_configs c
         join org_memberships m on m.tenant_id = c.tenant_id
         join tenants t on t.id = c.tenant_id
         where c.tenant_id = $1 and c.id = $2 and c.status = 'active'
           and m.id = $3 and m.user_id = $4 and m.status = 'active'
           and t.status = 'active'",
    )
    .bind(row.tenant_id)
    .bind(row.idp_config_id)
    .bind(row.new_membership_id)
    .bind(row.new_user_id)
    .fetch_optional(&mut *tx)
    .await?;
    if recheck.is_none() {
        tx.rollback().await.ok();
        return Ok(None);
    }

    // (3) Revoke the replaced session (in its OWN tenant).
    sqlx::query(
        "update user_sessions set revoked_at = now()
         where tenant_id = $1 and id = $2 and revoked_at is null",
    )
    .bind(row.replaced_tenant_id)
    .bind(row.replaced_session_id)
    .execute(&mut *tx)
    .await?;

    // (4) Mint the new session under the NEW org.
    mint_user_session(
        &mut tx,
        TenantScope::assume(row.tenant_id),
        row.new_membership_id,
        row.new_user_id,
        row.idp_config_id,
        new_token_plain,
        row.acr.as_deref(),
        row.amr.as_deref(),
        row.auth_time,
        None,
        idle_secs,
        absolute_secs,
    )
    .await?;

    tx.commit().await?;
    Ok(Some(SwitchClaim {
        new_tenant_id: row.tenant_id,
        replaced_tenant_id: row.replaced_tenant_id,
        redirect_to: row.redirect_to,
        new_session_token: new_token_plain.to_string(),
    }))
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
        let mut conn = pool.acquire().await.unwrap();
        create_idp_config(
            &mut conn,
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
                discovered_metadata: None,
                jwks: None,
                discovered_at: None,
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

    #[tokio::test]
    async fn jit_upsert_idempotency_and_owner_preservation() {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("skipping: DATABASE_URL not set");
            return;
        };
        let pool = connect(&url).await.expect("connect");
        let slug = format!("t-{}", Uuid::now_v7().simple());
        let org = create_org(&pool, &slug, None).await.unwrap();
        let scope = TenantScope::assume(org.id);
        let cfg = staged_config(&pool, scope).await;

        let mut conn = pool.acquire().await.unwrap();
        // Same subject twice → ONE user, fields refreshed, last_login_at bumped.
        let u1 = upsert_user(
            &mut conn,
            scope,
            cfg.id,
            "sub-jit",
            Some("A@Ex.com"),
            Some("a@ex.com"),
            true,
            Some("Al"),
        )
        .await
        .unwrap();
        let u2 = upsert_user(
            &mut conn,
            scope,
            cfg.id,
            "sub-jit",
            Some("A@Ex.com"),
            Some("a@ex.com"),
            true,
            Some("Alice"),
        )
        .await
        .unwrap();
        assert_eq!(u1.id, u2.id, "same identity key → one user row");
        assert_eq!(u2.name.as_deref(), Some("Alice"), "display attrs refreshed");
        assert!(u2.last_login_at.is_some());

        // Membership upsert: promote to owner, then a refresh with a mapped set
        // that omits owner MUST NOT strip it.
        let m1 =
            upsert_membership_preserving_owner(&mut conn, scope, u1.id, &["member".to_string()])
                .await
                .unwrap();
        add_owner_role(&mut conn, scope, m1.id).await.unwrap();
        let m2 =
            upsert_membership_preserving_owner(&mut conn, scope, u1.id, &["admin".to_string()])
                .await
                .unwrap();
        assert_eq!(m1.id, m2.id);
        assert!(m2.roles.contains(&"owner".to_string()), "owner preserved");
        assert!(
            m2.roles.contains(&"admin".to_string()),
            "mapped role applied"
        );
        drop(conn);

        cleanup_tenant(&pool, org.id).await;
    }

    #[tokio::test]
    async fn pending_switch_claim_lifecycle() {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("skipping: DATABASE_URL not set");
            return;
        };
        let pool = connect(&url).await.expect("connect");

        // The NEW login's org (config must be ACTIVE — the claim rechecks it).
        let slug_new = format!("t-{}", Uuid::now_v7().simple());
        let org_new = create_org(&pool, &slug_new, None).await.unwrap();
        let scope_new = TenantScope::assume(org_new.id);
        let cfg_new = staged_config(&pool, scope_new).await;
        activate(&pool, cfg_new.id).await;
        let (new_user, new_membership) =
            seed_user_membership(&pool, scope_new, cfg_new.id, "new-sub").await;

        // A SECOND org holds the CURRENT (to-be-replaced) session (org switch).
        let slug_old = format!("t-{}", Uuid::now_v7().simple());
        let org_old = create_org(&pool, &slug_old, None).await.unwrap();
        let scope_old = TenantScope::assume(org_old.id);
        let cfg_old = staged_config(&pool, scope_old).await;
        let (old_user, old_membership) =
            seed_user_membership(&pool, scope_old, cfg_old.id, "old-sub").await;

        let current_token = "fbx_web_current";
        let mut conn = pool.acquire().await.unwrap();
        let current = mint_user_session(
            &mut conn,
            scope_old,
            old_membership,
            old_user,
            cfg_old.id,
            current_token,
            None,
            None,
            None,
            None,
            3_600,
            100_000,
        )
        .await
        .unwrap();

        let cookie = "cookie-nonce";
        let bh = sha256_hex(cookie);
        let switch_id = create_pending_switch(
            &mut conn,
            scope_new,
            cfg_new.id,
            new_membership,
            new_user,
            org_old.id,
            current.id,
            "/dashboard",
            &bh,
            None,
            None,
            None,
        )
        .await
        .unwrap();

        // An EXPIRED switch (separate row) is refused.
        let expired = create_pending_switch(
            &mut conn,
            scope_new,
            cfg_new.id,
            new_membership,
            new_user,
            org_old.id,
            current.id,
            "/x",
            &sha256_hex("n2"),
            None,
            None,
            None,
        )
        .await
        .unwrap();
        drop(conn);
        sqlx::query("update pending_login_switches set expires_at = now() - interval '5 seconds' where id = $1")
            .bind(expired)
            .execute(&pool)
            .await
            .unwrap();
        assert!(
            claim_pending_switch(
                &pool,
                expired,
                &sha256_hex("n2"),
                current_token,
                "fbx_web_z",
                3_600,
                100_000
            )
            .await
            .unwrap()
            .is_none(),
            "expired switch refused"
        );

        // Wrong cookie hash → refused (and NOT consumed).
        assert!(
            claim_pending_switch(
                &pool,
                switch_id,
                "wronghash",
                current_token,
                "fbx_web_a",
                3_600,
                100_000
            )
            .await
            .unwrap()
            .is_none(),
            "wrong cookie refused"
        );
        // Wrong current session (a token that is not the replaced session) → refused.
        assert!(
            claim_pending_switch(
                &pool,
                switch_id,
                &bh,
                "fbx_web_not_it",
                "fbx_web_b",
                3_600,
                100_000
            )
            .await
            .unwrap()
            .is_none(),
            "wrong current session refused"
        );

        // Happy path: old revoked + new minted atomically.
        let new_token = "fbx_web_new";
        let claim = claim_pending_switch(
            &pool,
            switch_id,
            &bh,
            current_token,
            new_token,
            3_600,
            100_000,
        )
        .await
        .unwrap()
        .expect("claim succeeds");
        assert_eq!(claim.new_tenant_id, org_new.id);
        assert_eq!(claim.replaced_tenant_id, org_old.id);
        assert_eq!(claim.redirect_to, "/dashboard");
        // Old session revoked.
        assert!(resolve_web_session(&pool, current_token, 3_600)
            .await
            .unwrap()
            .is_none());
        // New session minted in the NEW org.
        let ns = resolve_web_session(&pool, new_token, 3_600)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(ns.tenant_id, org_new.id);
        assert_eq!(ns.membership_id, new_membership);

        // Replay refused (already consumed) — and the original session (already
        // revoked) can no longer satisfy the predicate anyway.
        assert!(
            claim_pending_switch(
                &pool,
                switch_id,
                &bh,
                new_token,
                "fbx_web_c",
                3_600,
                100_000
            )
            .await
            .unwrap()
            .is_none(),
            "replay refused"
        );

        // Clean the NEW org first (removes the switch rows + new session) so the
        // OLD org's cascade-FK'd sessions delete cleanly.
        cleanup_tenant(&pool, org_new.id).await;
        cleanup_tenant(&pool, org_old.id).await;
    }

    async fn audit_count(pool: &PgPool, tenant: Uuid, action: &str) -> i64 {
        let (n,): (i64,) = sqlx::query_as(
            "select count(*) from auth_audit_log where tenant_id = $1 and action = $2 and success",
        )
        .bind(tenant)
        .bind(action)
        .fetch_one(pool)
        .await
        .unwrap();
        n
    }

    #[tokio::test]
    async fn activate_enforces_one_active_and_writes_audit() {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("skipping: DATABASE_URL not set");
            return;
        };
        let pool = connect(&url).await.expect("connect");
        let slug = format!("t-{}", Uuid::now_v7().simple());
        let org = create_org(&pool, &slug, None).await.unwrap();
        let scope = TenantScope::assume(org.id);
        let c1 = staged_config(&pool, scope).await;
        let c2 = staged_config(&pool, scope).await;

        // Activate the first: staged → active, and its audit row committed.
        match activate_idp_config(&pool, scope, c1.id, Some("1.2.3.4"))
            .await
            .unwrap()
        {
            LifecycleOutcome::Done(row) => assert_eq!(row.status, "active"),
            _ => panic!("first activate must succeed"),
        }
        assert_eq!(audit_count(&pool, org.id, "idp.activate").await, 1);

        // The second is refused while the first is active (one-active index).
        assert!(matches!(
            activate_idp_config(&pool, scope, c2.id, None)
                .await
                .unwrap(),
            LifecycleOutcome::Refused(_)
        ));
        // A missing id is NotFound.
        assert!(matches!(
            activate_idp_config(&pool, scope, Uuid::now_v7(), None)
                .await
                .unwrap(),
            LifecycleOutcome::NotFound
        ));

        cleanup_tenant(&pool, org.id).await;
    }

    #[tokio::test]
    async fn disable_cancels_then_reactivate_only_when_none_active() {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("skipping: DATABASE_URL not set");
            return;
        };
        let pool = connect(&url).await.expect("connect");
        let slug = format!("t-{}", Uuid::now_v7().simple());
        let org = create_org(&pool, &slug, None).await.unwrap();
        let scope = TenantScope::assume(org.id);
        let cfg = staged_config(&pool, scope).await;
        activate(&pool, cfg.id).await;
        let (user, membership) = seed_user_membership(&pool, scope, cfg.id, "sub-dis").await;

        // A session, a pending switch (referencing that session), and a flow —
        // all under this config.
        let mut conn = pool.acquire().await.unwrap();
        let sess = mint_user_session(
            &mut conn,
            scope,
            membership,
            user,
            cfg.id,
            "fbx_web_dis",
            None,
            None,
            None,
            None,
            3_600,
            100_000,
        )
        .await
        .unwrap();
        create_pending_switch(
            &mut conn,
            scope,
            cfg.id,
            membership,
            user,
            org.id,
            sess.id,
            "/",
            &sha256_hex("n"),
            None,
            None,
            None,
        )
        .await
        .unwrap();
        drop(conn);
        create_login_flow(
            &pool,
            scope,
            cfg.id,
            &[1],
            "flow-n",
            &sha256_hex("y"),
            "/",
            600,
        )
        .await
        .unwrap();

        match disable_idp_config(&pool, scope, cfg.id, None)
            .await
            .unwrap()
        {
            LifecycleOutcome::Done(c) => {
                assert_eq!(c.flows_cancelled, 1);
                assert_eq!(c.switches_cancelled, 1);
                assert_eq!(c.sessions_revoked, 1);
            }
            _ => panic!("disable must succeed"),
        }
        assert_eq!(
            get_idp_config(&pool, scope, cfg.id)
                .await
                .unwrap()
                .unwrap()
                .status,
            "disabled"
        );
        assert!(resolve_web_session(&pool, "fbx_web_dis", 3_600)
            .await
            .unwrap()
            .is_none());

        // Reactivate: disabled → active.
        match reactivate_idp_config(&pool, scope, cfg.id, None)
            .await
            .unwrap()
        {
            LifecycleOutcome::Done(row) => assert_eq!(row.status, "active"),
            _ => panic!("reactivate must succeed"),
        }
        // Reactivating an ALREADY-active row is refused (only disabled → active).
        assert!(matches!(
            reactivate_idp_config(&pool, scope, cfg.id, None)
                .await
                .unwrap(),
            LifecycleOutcome::Refused(_)
        ));
        // With another row active, a disabled row cannot reactivate.
        let cfg2 = staged_config(&pool, scope).await;
        // cfg is active; disable it, then activate cfg2, then reactivate cfg → refused.
        disable_idp_config(&pool, scope, cfg.id, None)
            .await
            .unwrap();
        activate(&pool, cfg2.id).await;
        assert!(matches!(
            reactivate_idp_config(&pool, scope, cfg.id, None)
                .await
                .unwrap(),
            LifecycleOutcome::Refused(_)
        ));

        cleanup_tenant(&pool, org.id).await;
    }

    /// Seed an active config + a user/session/PAT provisioned by it, then run the
    /// swap. Returns nothing — asserts inline.
    async fn migrate_case(pool: &PgPool, carry_forward: bool) {
        let slug = format!("t-{}", Uuid::now_v7().simple());
        let org = create_org(pool, &slug, None).await.unwrap();
        let scope = TenantScope::assume(org.id);
        let old = staged_config(pool, scope).await;
        activate(pool, old.id).await;
        let (user, membership) = seed_user_membership(pool, scope, old.id, "sub-mig").await;

        let token = "fbx_web_mig";
        let mut conn = pool.acquire().await.unwrap();
        mint_user_session(
            &mut conn, scope, membership, user, old.id, token, None, None, None, None, 3_600,
            100_000,
        )
        .await
        .unwrap();
        drop(conn);
        let pat_plain = "fbx_pat_migrate0000";
        mint_pat(
            pool,
            scope,
            membership,
            user,
            "ci",
            pat_plain,
            Utc::now() + chrono::Duration::days(30),
        )
        .await
        .unwrap();

        let new = staged_config(pool, scope).await;
        let counts = match migrate_idp_config(pool, scope, old.id, new.id, carry_forward, None)
            .await
            .unwrap()
        {
            LifecycleOutcome::Done(c) => c,
            _ => panic!("migrate must succeed"),
        };
        assert_eq!(counts.sessions_revoked, 1, "old-config session revoked");

        // Old retired, new active.
        assert_eq!(
            get_idp_config(pool, scope, old.id)
                .await
                .unwrap()
                .unwrap()
                .status,
            "retired"
        );
        assert_eq!(
            get_idp_config(pool, scope, new.id)
                .await
                .unwrap()
                .unwrap()
                .status,
            "active"
        );
        // The old session is revoked either way.
        assert!(resolve_web_session(pool, token, 3_600)
            .await
            .unwrap()
            .is_none());

        let m = get_membership(pool, scope, membership)
            .await
            .unwrap()
            .unwrap();
        if carry_forward {
            assert_eq!(counts.memberships_deactivated, 0);
            assert_eq!(m.status, "active", "carry_forward keeps memberships");
            assert!(
                resolve_pat(pool, pat_plain).await.unwrap().is_some(),
                "carry_forward keeps PATs"
            );
        } else {
            assert_eq!(counts.memberships_deactivated, 1);
            assert_eq!(m.status, "deactivated", "default deactivates memberships");
            assert!(
                resolve_pat(pool, pat_plain).await.unwrap().is_none(),
                "default revokes PATs via the cascade"
            );
        }

        cleanup_tenant(pool, org.id).await;
    }

    #[tokio::test]
    async fn migrate_swap_default_deactivates_and_carry_forward_preserves() {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("skipping: DATABASE_URL not set");
            return;
        };
        let pool = connect(&url).await.expect("connect");
        migrate_case(&pool, false).await;
        migrate_case(&pool, true).await;
    }

    #[tokio::test]
    async fn arm_refused_while_active_owner_exists() {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("skipping: DATABASE_URL not set");
            return;
        };
        let pool = connect(&url).await.expect("connect");
        let slug = format!("t-{}", Uuid::now_v7().simple());
        let org = create_org(&pool, &slug, None).await.unwrap();
        let scope = TenantScope::assume(org.id);
        let cfg = staged_config(&pool, scope).await;
        activate(&pool, cfg.id).await;
        let (_user, membership) = seed_user_membership(&pool, scope, cfg.id, "owner-sub").await;
        // Promote to owner.
        sqlx::query("update org_memberships set roles = '{owner}' where id = $1")
            .bind(membership)
            .execute(&pool)
            .await
            .unwrap();

        let email = "new-owner@example.com";
        let exp = Utc::now() + chrono::Duration::days(7);
        assert!(
            matches!(
                arm_bootstrap_owner(&pool, scope, cfg.id, email, exp, None)
                    .await
                    .unwrap(),
                LifecycleOutcome::Refused(_)
            ),
            "arming refused while an active owner exists"
        );

        // Deactivate the owner, then arming succeeds and lands on the config.
        set_membership_status(&pool, scope, membership, "deactivated")
            .await
            .unwrap();
        assert!(matches!(
            arm_bootstrap_owner(&pool, scope, cfg.id, email, exp, None)
                .await
                .unwrap(),
            LifecycleOutcome::Done(_)
        ));
        let after = get_idp_config(&pool, scope, cfg.id).await.unwrap().unwrap();
        assert_eq!(after.bootstrap_owner_email.as_deref(), Some(email));

        cleanup_tenant(&pool, org.id).await;
    }
}
