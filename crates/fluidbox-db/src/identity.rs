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
    /// The arming audit row's id, stored when a bootstrap owner is armed; login
    /// consumption references it (`arm_id`) and clears it with the arm.
    pub bootstrap_arm_audit_id: Option<Uuid>,
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
    bootstrap_owner_email, bootstrap_owner_expires_at, bootstrap_arm_audit_id, \
    discovered_metadata, jwks, discovered_at, status, created_by, created_at, updated_at";

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

const USER_COLS: &str = "id, tenant_id, idp_config_id, subject, email, \
    email_normalized, email_verified, name, status, created_at, updated_at, \
    last_login_at";

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

const MEMBERSHIP_COLS: &str = "id, tenant_id, user_id, roles, status, \
    created_at, updated_at, deactivated_at";

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
    /// Envelope key-version companion for `pkce_verifier_sealed`.
    pub pkce_verifier_key_version: i16,
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

const USER_SESSION_COLS: &str = "id, tenant_id, membership_id, user_id, \
    session_token_sha256, idp_config_id, acr, amr, auth_time, idp_sid, \
    created_at, last_seen_at, idle_expires_at, absolute_expires_at, revoked_at";

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
/// (status + roles), user status, and tenant status. The caller refuses a
/// non-`active` membership, user, OR tenant (fail-closed, in one place) —
/// symmetric with [`WebSessionAuth`].
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct PatAuth {
    pub token_id: Uuid,
    pub tenant_id: Uuid,
    pub tenant_status: String,
    pub membership_id: Uuid,
    pub user_id: Uuid,
    pub roles: Vec<String>,
    pub membership_status: String,
    pub user_status: String,
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
    /// Envelope key-version companion for `client_secret_sealed` (1 legacy, 2 v2).
    pub client_secret_key_version: i16,
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
    // Operator org-CRUD (a sanctioned bypass category): the new `tenants` row's id
    // is not yet any GUC's tenant, so its WITH CHECK is satisfied only by the
    // audited system-worker bypass. `worker_tx` is the one grep-able choke point.
    let mut tx = crate::worker_tx(pool).await?;
    let __rls_out = insert_org(&mut tx, slug, display_name).await?;
    tx.commit().await?;
    Ok(__rls_out)
}

/// Pre-auth login-routing helper: resolve a slug to its org BEFORE anyone is
/// authenticated. Answers identically (None) for unknown slugs. Rides the audited
/// system-worker bypass (`worker_tx`): no tenant is known yet — the slug IS the
/// key — so RLS cannot filter on `fluidbox.tenant_id`; the sanctioned pre-auth
/// org-routing category (mirrors the token-digest resolvers in lib.rs).
pub async fn get_org_by_slug(pool: &PgPool, slug: &str) -> sqlx::Result<Option<OrgRow>> {
    let mut tx = crate::worker_tx(pool).await?;
    let __rls_out = sqlx::query_as(
        "select id, name, slug, display_name, status, created_at
         from tenants where slug = $1",
    )
    .bind(slug)
    .fetch_optional(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(__rls_out)
}

/// Operator surface: every org. Rides the audited system-worker bypass
/// (`worker_tx`) — a cross-tenant scan of `tenants` by construction (the operator
/// org-CRUD category); a tenant-scoped read would see only its own row.
pub async fn list_orgs(pool: &PgPool) -> sqlx::Result<Vec<OrgRow>> {
    let mut tx = crate::worker_tx(pool).await?;
    let __rls_out = sqlx::query_as(
        "select id, name, slug, display_name, status, created_at
         from tenants order by created_at",
    )
    .fetch_all(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(__rls_out)
}

pub async fn get_org(pool: &PgPool, scope: TenantScope) -> sqlx::Result<Option<OrgRow>> {
    let mut tx = crate::scoped_tx(pool, scope).await?;
    let __rls_out = sqlx::query_as(
        "select id, name, slug, display_name, status, created_at
         from tenants where id = $1",
    )
    .bind(scope.tenant_id())
    .fetch_optional(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(__rls_out)
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
            discovered_metadata, jwks, discovered_at, client_secret_key_version)
         select $1, $2,
                coalesce((select max(generation) from org_idp_configs where tenant_id = $2), 0) + 1,
                $3, $4, $5, $6, $7, $8, $9, $10, $11, 'staged', $12, $13, $14, $15, $16
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
    .bind(params.client_secret_key_version)
    .fetch_one(&mut *conn)
    .await
}

pub async fn get_idp_config(
    pool: &PgPool,
    scope: TenantScope,
    id: Uuid,
) -> sqlx::Result<Option<OrgIdpConfigRow>> {
    let mut tx = crate::scoped_tx(pool, scope).await?;
    let __rls_out = sqlx::query_as(sqlx::AssertSqlSafe(format!(
        "select {IDP_CONFIG_COLS} from org_idp_configs where tenant_id = $1 and id = $2"
    )))
    .bind(scope.tenant_id())
    .bind(id)
    .fetch_optional(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(__rls_out)
}

pub async fn list_idp_configs(
    pool: &PgPool,
    scope: TenantScope,
) -> sqlx::Result<Vec<OrgIdpConfigRow>> {
    let mut tx = crate::scoped_tx(pool, scope).await?;
    let __rls_out = sqlx::query_as(sqlx::AssertSqlSafe(format!(
        "select {IDP_CONFIG_COLS} from org_idp_configs where tenant_id = $1 order by generation"
    )))
    .bind(scope.tenant_id())
    .fetch_all(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(__rls_out)
}

/// Pre-auth: the one active config for an org (login routing loads this before
/// any principal exists). At most one row by the `one_active_idp_per_org`
/// partial index. Rides the audited system-worker bypass (`worker_tx`): the
/// `tenant_id` came from an UNAUTHENTICATED slug lookup and no principal is
/// verified yet — the sanctioned pre-auth login-routing category.
pub async fn active_idp_config(
    pool: &PgPool,
    tenant_id: Uuid,
) -> sqlx::Result<Option<OrgIdpConfigRow>> {
    let mut tx = crate::worker_tx(pool).await?;
    let __rls_out = sqlx::query_as(sqlx::AssertSqlSafe(format!(
        "select {IDP_CONFIG_COLS} from org_idp_configs
         where tenant_id = $1 and status = 'active'"
    )))
    .bind(tenant_id)
    .fetch_optional(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(__rls_out)
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
    let mut tx = crate::scoped_tx(pool, scope).await?;
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
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(res.rows_affected() == 1)
}

/// Persist ONLY the cached JWKS document (the forced key-refresh during login),
/// leaving `discovered_metadata` and `discovered_at` untouched. A key refresh
/// must never rewrite discovery freshness — doing so would mask stale discovery
/// metadata and suppress the required discovery refresh (design 815-826).
/// Returns whether a row matched (`false` ⇒ the config vanished/retired
/// concurrently, which the caller treats as terminal for the login).
pub async fn update_idp_jwks_cache(
    pool: &PgPool,
    scope: TenantScope,
    id: Uuid,
    jwks: &Value,
) -> sqlx::Result<bool> {
    let mut tx = crate::scoped_tx(pool, scope).await?;
    let res = sqlx::query(
        "update org_idp_configs
         set jwks = $3, updated_at = now()
         where tenant_id = $1 and id = $2 and status = 'active'",
    )
    .bind(scope.tenant_id())
    .bind(id)
    .bind(jwks)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
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
) -> sqlx::Result<Option<(Vec<u8>, i16)>> {
    let mut tx = crate::scoped_tx(pool, scope).await?;
    let row: Option<(Option<Vec<u8>>, i16)> = sqlx::query_as(
        "select client_secret_sealed, client_secret_key_version
         from org_idp_configs where tenant_id = $1 and id = $2",
    )
    .bind(scope.tenant_id())
    .bind(id)
    .fetch_optional(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(row.and_then(|(s, v)| s.map(|s| (s, v))))
}

/// Count a tenant's still-claimable login flows — the per-org outstanding-flow
/// cap the start endpoint enforces to bound DB/IdP amplification from the
/// unauthenticated login surface (design lines 852-854).
pub async fn count_outstanding_login_flows(pool: &PgPool, scope: TenantScope) -> sqlx::Result<i64> {
    let mut tx = crate::scoped_tx(pool, scope).await?;
    let (n,): (i64,) = sqlx::query_as(
        "select count(*) from login_flows
         where tenant_id = $1 and consumed_at is null and expires_at > now()",
    )
    .bind(scope.tenant_id())
    .fetch_one(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(n)
}

// ─── login_flows ────────────────────────────────────────────────────────────

/// Mint a one-time login flow with GC-on-insert (same discipline as
/// `create_github_app_flow`). The cleartext cookie nonce lives only in the
/// browser cookie; only its sha256 (`browser_hash`) is stored.
///
/// The outstanding-flow cap (design 852-854) is enforced ATOMICALLY with the
/// insert: one short transaction locks the tenant row, GCs, counts the still-
/// claimable flows, and inserts only when under `max_outstanding` — so
/// concurrent starts cannot race past the cap. `Ok(None)` means over-cap (the
/// caller surfaces the existing 429/refusal shape). Per-org start
/// serialization at login volume is the doc's accepted trade.
#[allow(clippy::too_many_arguments)]
pub async fn create_login_flow(
    pool: &PgPool,
    scope: TenantScope,
    idp_config_id: Uuid,
    pkce_verifier_sealed: &[u8],
    pkce_verifier_key_version: i16,
    nonce: &str,
    browser_hash: &str,
    redirect_to: &str,
    ttl_secs: i64,
    max_outstanding: i64,
) -> sqlx::Result<Option<Uuid>> {
    let mut tx = crate::scoped_tx(pool, scope).await?;
    // Serialize concurrent starts for this org on the tenant row so the cap
    // check and the insert are one atomic decision.
    sqlx::query("select id from tenants where id = $1 for update")
        .bind(scope.tenant_id())
        .execute(&mut *tx)
        .await?;
    // GC-on-insert is scoped to the inserting tenant (a per-request write must
    // never sweep another org's rows). A global sweep of expired flows across
    // all tenants belongs to a future background worker, not this hot path.
    sqlx::query(
        "delete from login_flows
         where tenant_id = $1
           and ((consumed_at is null and expires_at < now())
                or expires_at < now() - interval '7 days')",
    )
    .bind(scope.tenant_id())
    .execute(&mut *tx)
    .await?;
    let (n,): (i64,) = sqlx::query_as(
        "select count(*) from login_flows
         where tenant_id = $1 and consumed_at is null and expires_at > now()",
    )
    .bind(scope.tenant_id())
    .fetch_one(&mut *tx)
    .await?;
    if n >= max_outstanding {
        // Over cap: refuse without minting; the transaction rolls back on drop.
        return Ok(None);
    }
    let id = Uuid::now_v7();
    sqlx::query(
        "insert into login_flows
           (id, tenant_id, idp_config_id, pkce_verifier_sealed, nonce, browser_hash, redirect_to,
            expires_at, pkce_verifier_key_version)
         values ($1, $2, $3, $4, $5, $6, $7, now() + make_interval(secs => $8::double precision), $9)",
    )
    .bind(id)
    .bind(scope.tenant_id())
    .bind(idp_config_id)
    .bind(pkce_verifier_sealed)
    .bind(nonce)
    .bind(browser_hash)
    .bind(redirect_to)
    .bind(ttl_secs as f64)
    .bind(pkce_verifier_key_version)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(Some(id))
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
    // Rides the audited system-worker bypass (`worker_tx`): the login callback has
    // no principal — the `tenant_id` was extracted from the verified sealed state,
    // the browser-cookie hash sits INSIDE the predicate, and the config must still
    // be active. The sanctioned pre-auth login-bootstrap category (mirrors the
    // token-digest resolvers).
    let mut tx = crate::worker_tx(pool).await?;
    let __rls_out = sqlx::query_as(
        "update login_flows f set consumed_at = now()
         from org_idp_configs c
         where f.id = $1 and f.tenant_id = $2
           and f.idp_config_id = $3
           and c.tenant_id = f.tenant_id and c.id = f.idp_config_id
           and c.status = 'active'
           and f.consumed_at is null
           and f.browser_hash = $4
           and f.expires_at > now()
         returning f.pkce_verifier_sealed, f.pkce_verifier_key_version, f.nonce, f.redirect_to, f.created_at",
    )
    .bind(flow_id)
    .bind(tenant_id)
    .bind(idp_config_id)
    .bind(browser_hash)
    .fetch_optional(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(__rls_out)
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
    sqlx::query_as(sqlx::AssertSqlSafe(format!(
        "insert into user_sessions
           (id, tenant_id, membership_id, user_id, session_token_sha256, idp_config_id,
            acr, amr, auth_time, idp_sid, idle_expires_at, absolute_expires_at)
         values ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10,
                 least(now() + make_interval(secs => $11::double precision),
                       now() + make_interval(secs => $12::double precision)),
                 now() + make_interval(secs => $12::double precision))
         returning {USER_SESSION_COLS}"
    )))
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
    // Rides the audited system-worker bypass (`worker_tx`): keyed purely on the
    // session-token sha256 with NO tenant scope — the caller has no principal until
    // this resolves the tenant. The credential-digest bootstrap category (mirrors
    // the lib.rs token-digest resolvers).
    let mut tx = crate::worker_tx(pool).await?;
    let __rls_out = sqlx::query_as(
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
    .fetch_optional(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(__rls_out)
}

/// Is this browser session still authorized RIGHT NOW — not revoked, within
/// both expiries, membership + user + tenant still active? Read-only and it does NOT
/// bump idle (design lines 658-664: the bounded stream re-auth must not extend
/// a session's life). Keyed on the session id under its verified scope.
pub async fn web_session_live(
    pool: &PgPool,
    scope: TenantScope,
    session_id: Uuid,
) -> sqlx::Result<bool> {
    let mut tx = crate::scoped_tx(pool, scope).await?;
    let (live,): (bool,) = sqlx::query_as(
        "select exists(
           select 1 from user_sessions s
           join org_memberships m
             on m.tenant_id = s.tenant_id and m.id = s.membership_id and m.user_id = s.user_id
           join users u on u.tenant_id = s.tenant_id and u.id = s.user_id
           join tenants t on t.id = s.tenant_id
           where s.tenant_id = $1 and s.id = $2
             and s.revoked_at is null
             and s.idle_expires_at > now()
             and s.absolute_expires_at > now()
             and m.status = 'active'
             and u.status = 'active'
             and t.status = 'active')",
    )
    .bind(scope.tenant_id())
    .bind(session_id)
    .fetch_one(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(live)
}

/// Revoke a single session (a row update, never a delete — the audit trail and
/// the composite FKs from `pending_login_switches` stay intact).
pub async fn revoke_user_session(
    pool: &PgPool,
    scope: TenantScope,
    id: Uuid,
) -> sqlx::Result<bool> {
    let mut tx = crate::scoped_tx(pool, scope).await?;
    let res = sqlx::query(
        "update user_sessions set revoked_at = now()
         where tenant_id = $1 and id = $2 and revoked_at is null",
    )
    .bind(scope.tenant_id())
    .bind(id)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
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
    let mut tx = crate::scoped_tx(pool, scope).await?;
    let __rls_out = sqlx::query_as(sqlx::AssertSqlSafe(format!(
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
    .fetch_one(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(__rls_out)
}

/// Resolve a PAT (bootstrap exception: keys on the token sha256) and bump
/// `last_used_at`. Joins the membership for its live status + roles, the user
/// for its status, and the tenant for its status; a deactivated membership's
/// PATs are already revoked by the cascade, so this matches only live tokens
/// and the returned statuses are defense in depth (symmetric with
/// [`resolve_web_session`]).
pub async fn resolve_pat(pool: &PgPool, token_plain: &str) -> sqlx::Result<Option<PatAuth>> {
    // Rides the audited system-worker bypass (`worker_tx`): keyed purely on the
    // PAT sha256 with NO tenant scope — the caller has no principal until this
    // resolves the tenant. The credential-digest bootstrap category (mirrors the
    // lib.rs token-digest resolvers).
    let mut tx = crate::worker_tx(pool).await?;
    let __rls_out = sqlx::query_as(
        "update api_tokens tok set last_used_at = now()
         from org_memberships m, users u, tenants t
         where tok.kind = 'pat' and tok.token_sha256 = $1
           and tok.revoked_at is null
           and tok.expires_at > now()
           and m.tenant_id = tok.tenant_id and m.id = tok.membership_id and m.user_id = tok.user_id
           and u.tenant_id = tok.tenant_id and u.id = tok.user_id
           and t.id = tok.tenant_id
         returning tok.id as token_id, tok.tenant_id as tenant_id, t.status as tenant_status,
                   tok.membership_id as membership_id, tok.user_id as user_id,
                   m.roles as roles, m.status as membership_status, u.status as user_status",
    )
    .bind(sha256_hex(token_plain))
    .fetch_optional(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(__rls_out)
}

pub async fn list_pats(
    pool: &PgPool,
    scope: TenantScope,
    membership_id: Uuid,
) -> sqlx::Result<Vec<PatRow>> {
    let mut tx = crate::scoped_tx(pool, scope).await?;
    let __rls_out = sqlx::query_as(sqlx::AssertSqlSafe(format!(
        "select {PAT_COLS} from api_tokens
         where kind = 'pat' and tenant_id = $1 and membership_id = $2
         order by created_at desc"
    )))
    .bind(scope.tenant_id())
    .bind(membership_id)
    .fetch_all(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(__rls_out)
}

/// Revoke one PAT, scoped to its membership so a caller can only revoke its
/// own tokens. Returns whether a live row matched.
pub async fn revoke_pat(
    pool: &PgPool,
    scope: TenantScope,
    membership_id: Uuid,
    token_id: Uuid,
) -> sqlx::Result<bool> {
    let mut tx = crate::scoped_tx(pool, scope).await?;
    let res = sqlx::query(
        "update api_tokens set revoked_at = now()
         where kind = 'pat' and tenant_id = $1 and membership_id = $2 and id = $3
           and revoked_at is null",
    )
    .bind(scope.tenant_id())
    .bind(membership_id)
    .bind(token_id)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(res.rows_affected() == 1)
}

// ─── auth_audit_log ─────────────────────────────────────────────────────────

/// Append an audit row. Executor-generic: an ACCEPTED mutation calls this
/// inside its own transaction (audit and mutation commit together — if the
/// audit insert fails, the mutation fails); a REJECTED attempt calls it on a
/// fresh connection committed after the rollback. The append-only trigger
/// blocks any later UPDATE/DELETE.
///
/// RLS (Phase D): `auth_audit_log`'s INSERT policy is `with check (true)` —
/// operator actions carry a NULL `tenant_id`, and a rejected-attempt audit runs
/// pool-direct with no principal — so this INSERT needs NO tenant GUC and rides
/// whatever executor the caller supplies (an accepted mutation's scoped/worker tx,
/// or a bare pool connection for a rejected attempt). SELECTs of the log ARE
/// tenant-or-null-or-bypass gated; there is no such reader in production code.
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
    let mut tx = crate::scoped_tx(pool, scope).await?;
    let __rls_out = sqlx::query_as(sqlx::AssertSqlSafe(format!(
        "select {USER_COLS} from users where tenant_id = $1 and id = $2"
    )))
    .bind(scope.tenant_id())
    .bind(id)
    .fetch_optional(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(__rls_out)
}

pub async fn list_memberships(
    pool: &PgPool,
    scope: TenantScope,
) -> sqlx::Result<Vec<OrgMembershipRow>> {
    let mut tx = crate::scoped_tx(pool, scope).await?;
    let __rls_out = sqlx::query_as(sqlx::AssertSqlSafe(format!(
        "select {MEMBERSHIP_COLS} from org_memberships where tenant_id = $1 order by created_at"
    )))
    .bind(scope.tenant_id())
    .fetch_all(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(__rls_out)
}

pub async fn get_membership(
    pool: &PgPool,
    scope: TenantScope,
    id: Uuid,
) -> sqlx::Result<Option<OrgMembershipRow>> {
    let mut tx = crate::scoped_tx(pool, scope).await?;
    let __rls_out = sqlx::query_as(sqlx::AssertSqlSafe(format!(
        "select {MEMBERSHIP_COLS} from org_memberships where tenant_id = $1 and id = $2"
    )))
    .bind(scope.tenant_id())
    .bind(id)
    .fetch_optional(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(__rls_out)
}

/// A membership by USER id (unique(tenant_id, user_id) → a single row). The
/// broker's owner-membership recheck maps a connection's `owner_user_id` to its
/// live membership `status` (design :693-728): a `user`-owned connection whose
/// owner is no longer an active member fails closed.
pub async fn get_membership_by_user(
    pool: &PgPool,
    scope: TenantScope,
    user_id: Uuid,
) -> sqlx::Result<Option<OrgMembershipRow>> {
    let mut tx = crate::scoped_tx(pool, scope).await?;
    let __rls_out = sqlx::query_as(sqlx::AssertSqlSafe(format!(
        "select {MEMBERSHIP_COLS} from org_memberships where tenant_id = $1 and user_id = $2"
    )))
    .bind(scope.tenant_id())
    .bind(user_id)
    .fetch_optional(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(__rls_out)
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
    let row: Option<OrgMembershipRow> = sqlx::query_as(sqlx::AssertSqlSafe(format!(
        "update org_memberships
         set status = $3,
             deactivated_at = case when $3 = 'deactivated' then now() else deactivated_at end,
             updated_at = now()
         where tenant_id = $1 and id = $2
         returning {MEMBERSHIP_COLS}"
    )))
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
    let mut tx = crate::scoped_tx(pool, scope).await?;
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

/// The client-secret leg of a PATCH — a tri-state mirroring the JSON body:
/// absent = keep the current sealed secret, null = clear it, a string = re-seal.
/// `coalesce` alone cannot express "clear", so the tri-state is carried through
/// to the UPDATE explicitly.
pub enum SecretPatch {
    Keep,
    Clear,
    /// New sealed bytes + their envelope key-version companion.
    Set(Vec<u8>, i16),
}

/// The mutable-field patch for an IdP config (identity fields are refused by the
/// handler, never reach here). Each `Some` field is applied via `coalesce`.
pub struct IdpPatch<'a> {
    pub client_secret: SecretPatch,
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
///
/// Taken by every path that arms/consumes/revokes owner under the same
/// discipline — the create-IdP and owner-deactivation paths join the existing
/// status-transition/swap/role-change callers (all in this module).
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
    // Switches cancelled BEFORE sessions are revoked (deterministic order; kept
    // stable even though the switch-claim's config lock has since made the
    // ordering non-load-bearing — see `migrate_idp_config`).
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
    arm_audit_id: Uuid,
    normalized_email: &str,
    expires_at: DateTime<Utc>,
) -> sqlx::Result<bool> {
    if active_owner_exists(&mut *conn, scope).await? {
        return Ok(false);
    }
    // Store the arming audit row's id alongside the arm so consumption can
    // reference it (`arm_id`) and clear it with the arm (design 401-402).
    sqlx::query(
        "update org_idp_configs
         set bootstrap_owner_email = $3, bootstrap_owner_expires_at = $4,
             bootstrap_arm_audit_id = $5, updated_at = now()
         where tenant_id = $1 and id = $2",
    )
    .bind(scope.tenant_id())
    .bind(config_id)
    .bind(normalized_email)
    .bind(expires_at)
    .bind(arm_audit_id)
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
    // Operator org-CRUD (a sanctioned bypass category): the new `tenants` row's id
    // is not yet any GUC's tenant, so its WITH CHECK — and the audit row it commits
    // alongside — are satisfied only under the audited system-worker bypass.
    let mut tx = crate::worker_tx(pool).await?;
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
///
/// When `params` carries a bootstrap arm, the WHOLE thing runs under the org's
/// config lock ([`lock_org_configs`]): the arm's owner-absence precondition and
/// the staged insert then serialize with bootstrap consumption / role changes /
/// the issuer-migration swap (design 709-719). The lock is taken FIRST, before
/// the insert, so a login promoting a new owner cannot slip between the
/// owner-exists check and the arm landing. Returns `Refused` when an active
/// owner already exists (the caller audits + 409s); a staged insert WITHOUT an
/// arm needs no lock (nothing to serialize).
pub async fn create_idp_config_audited(
    pool: &PgPool,
    scope: TenantScope,
    params: IdpConfigParams<'_>,
    source_ip: Option<&str>,
) -> sqlx::Result<LifecycleOutcome<OrgIdpConfigRow>> {
    let arming = params.bootstrap_owner_email.is_some();
    let mut tx = crate::scoped_tx(pool, scope).await?;
    if arming {
        // Lock the org's existing config rows FIRST, then re-check owner-absence
        // under that lock — the create-path half of the arming invariant.
        lock_org_configs(&mut tx, scope).await?;
        if active_owner_exists(&mut tx, scope).await? {
            tx.rollback().await.ok();
            return Ok(LifecycleOutcome::Refused(
                "an active owner already exists; deactivate it before arming a bootstrap owner",
            ));
        }
    }
    let mut row = create_idp_config(&mut tx, scope, params).await?;
    // The arm's audit id links arming to consumption (design 401-402); generate
    // it up front so the SAME id is both the audit row's PK and the value stored
    // in `bootstrap_arm_audit_id`.
    let audit_id = Uuid::now_v7();
    let detail = json!({
        "generation": row.generation,
        "issuer_sha256": sha256_hex(&row.issuer),
        "token_endpoint_auth": row.token_endpoint_auth,
        "bootstrap_armed": arming,
        "arm_id": if arming { Some(audit_id) } else { None },
    });
    let target = row.id.to_string();
    insert_audit_with_id(
        &mut tx,
        audit_id,
        operator_audit(scope.tenant_id(), source_ip, "idp.create", &target, &detail),
    )
    .await?;
    if arming {
        sqlx::query(
            "update org_idp_configs set bootstrap_arm_audit_id = $3
             where tenant_id = $1 and id = $2",
        )
        .bind(scope.tenant_id())
        .bind(row.id)
        .bind(audit_id)
        .execute(&mut *tx)
        .await?;
        row.bootstrap_arm_audit_id = Some(audit_id);
    }
    tx.commit().await?;
    Ok(LifecycleOutcome::Done(row))
}

/// `staged → active`, refused (409) while another row is active. The pre-check
/// gives a clean refusal; the partial unique index is the backstop.
pub async fn activate_idp_config(
    pool: &PgPool,
    scope: TenantScope,
    id: Uuid,
    source_ip: Option<&str>,
) -> sqlx::Result<LifecycleOutcome<OrgIdpConfigRow>> {
    let mut tx = crate::scoped_tx(pool, scope).await?;
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
    let mut tx = crate::scoped_tx(pool, scope).await?;
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
    let mut tx = crate::scoped_tx(pool, scope).await?;
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
    let mut tx = crate::scoped_tx(pool, scope).await?;
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
    // Cascade order is deterministic: cancel unconsumed pending switches BEFORE
    // revoking the old config's sessions (the helper runs flows → switches →
    // sessions). Now that the switch-claim takes the config row FOR UPDATE (see
    // `claim_pending_switch` step 2), this ordering is no longer load-bearing —
    // a racing claim serializes behind the swap's `lock_org_configs` regardless
    // — but we keep it fixed and explicit.
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

/// Break-glass: re-arm the bootstrap owner on the org's ACTIVE config, refused
/// (409) while an active owner exists. Resolve + arm happen in ONE transaction
/// that locks the target config row `FOR UPDATE` and rechecks `status = 'active'`
/// and owner-absence UNDER the lock (design 709-719) — a config disabled/retired
/// by a concurrent transaction after an unlocked read can never be armed. The
/// active config is resolved via the `status = 'active'` partial-unique index
/// (≤1 row) INSIDE the transaction, so nothing is trusted from a prior read.
/// Returns `Done((config_id, arm_id))`; the accepted audit row's PK is recorded
/// as `arm_id` and stored on the config so consumption can correlate.
pub async fn arm_bootstrap_owner(
    pool: &PgPool,
    scope: TenantScope,
    normalized_email: &str,
    expires_at: DateTime<Utc>,
    source_ip: Option<&str>,
) -> sqlx::Result<LifecycleOutcome<(Uuid, Uuid)>> {
    let mut tx = crate::scoped_tx(pool, scope).await?;
    // Resolve + lock the active config in one shot (partial unique index ⇒ ≤1).
    let active: Option<(Uuid, String)> = sqlx::query_as(
        "select id, status from org_idp_configs
         where tenant_id = $1 and status = 'active' for update",
    )
    .bind(scope.tenant_id())
    .fetch_optional(&mut *tx)
    .await?;
    let Some((config_id, status)) = active else {
        tx.rollback().await.ok();
        return Ok(LifecycleOutcome::NotFound);
    };
    // Recheck under the lock (the WHERE already constrained it; this makes the
    // status guard explicit and survives a future non-index-backed resolve).
    if status != "active" {
        tx.rollback().await.ok();
        return Ok(LifecycleOutcome::Refused(
            "no active IdP configuration to arm",
        ));
    }
    let arm_id = Uuid::now_v7();
    if !check_and_arm_bootstrap(
        &mut tx,
        scope,
        config_id,
        arm_id,
        normalized_email,
        expires_at,
    )
    .await?
    {
        tx.rollback().await.ok();
        return Ok(LifecycleOutcome::Refused(
            "an active owner already exists; deactivate it before arming",
        ));
    }
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
    Ok(LifecycleOutcome::Done((config_id, arm_id)))
}

/// Apply a mutable-field patch (+ optional bootstrap re-arm) to an IdP config in
/// one transaction, audited as `idp.patch`. Identity-field changes never reach
/// here (the handler refuses them). A refused re-arm rolls back the whole patch.
///
/// The auth/secret COHERENCE check runs HERE, under the config row's `FOR UPDATE`
/// lock, against the freshly-read current row: a confidential method
/// (`client_secret_basic`/`post`) requires a secret present post-merge; a public
/// client (`none`) must not retain one. Reading current state before the lock (as
/// the handler once did) let two concurrent PATCHes each validate against stale
/// state and commit an incoherent auth/secret pair; merging under the lock closes
/// that. An incoherent merge is a `Refused` outcome (rolled back). The handler
/// keeps only request-shape validation (valid method, method advertised, etc.).
pub async fn patch_idp_config(
    pool: &PgPool,
    scope: TenantScope,
    id: Uuid,
    patch: IdpPatch<'_>,
    source_ip: Option<&str>,
) -> sqlx::Result<LifecycleOutcome<OrgIdpConfigRow>> {
    let mut tx = crate::scoped_tx(pool, scope).await?;
    // Lock the row and capture the CURRENT auth method + whether a sealed secret
    // is present, so the coherence merge below reads consistent, locked state.
    let locked: Option<(String, bool)> = sqlx::query_as(
        "select token_endpoint_auth, client_secret_sealed is not null
         from org_idp_configs where tenant_id = $1 and id = $2 for update",
    )
    .bind(scope.tenant_id())
    .bind(id)
    .fetch_optional(&mut *tx)
    .await?;
    let Some((cur_auth, has_secret_now)) = locked else {
        tx.rollback().await.ok();
        return Ok(LifecycleOutcome::NotFound);
    };

    // Coherence AFTER merging the tri-state secret + optional new method against
    // the LOCKED current row. Borrow `patch.client_secret` here (the move-match
    // for the UPDATE comes after).
    let secret_present_post = match &patch.client_secret {
        SecretPatch::Set(..) => true,
        SecretPatch::Clear => false,
        SecretPatch::Keep => has_secret_now,
    };
    let eff_auth = patch.token_endpoint_auth.unwrap_or(cur_auth.as_str());
    if (eff_auth == "client_secret_basic" || eff_auth == "client_secret_post")
        && !secret_present_post
    {
        tx.rollback().await.ok();
        return Ok(LifecycleOutcome::Refused(match eff_auth {
            "client_secret_post" => {
                "token_endpoint_auth=client_secret_post requires a client_secret to be present after this patch"
            }
            _ => {
                "token_endpoint_auth=client_secret_basic requires a client_secret to be present after this patch"
            }
        }));
    }
    if eff_auth == "none" && secret_present_post {
        tx.rollback().await.ok();
        return Ok(LifecycleOutcome::Refused(
            "token_endpoint_auth=none (public client) must not retain a client_secret; \
             clear it explicitly with client_secret:null",
        ));
    }

    // Client-secret tri-state: Clear ⇒ null; Set ⇒ new sealed bytes; Keep ⇒
    // coalesce($3 = null) leaves the current value. `coalesce` alone cannot
    // express Clear, so a `$4::bool` flag forces null ahead of the coalesce.
    let (clear_secret, set_secret, set_version): (bool, Option<Vec<u8>>, Option<i16>) =
        match patch.client_secret {
            SecretPatch::Keep => (false, None, None),
            SecretPatch::Clear => (true, None, None),
            SecretPatch::Set(bytes, version) => (false, Some(bytes), Some(version)),
        };
    let row: OrgIdpConfigRow = sqlx::query_as(sqlx::AssertSqlSafe(format!(
        "update org_idp_configs set
           client_secret_sealed = case when $4::bool then null
                                       else coalesce($3::bytea, client_secret_sealed) end,
           client_secret_key_version = case when $4::bool then 1
                                       else coalesce($9::smallint, client_secret_key_version) end,
           token_endpoint_auth = coalesce($5::text, token_endpoint_auth),
           scopes = coalesce($6::text[], scopes),
           claim_mappings = coalesce($7::jsonb, claim_mappings),
           alg_allowlist = coalesce($8::text[], alg_allowlist),
           updated_at = now()
         where tenant_id = $1 and id = $2 returning {IDP_CONFIG_COLS}"
    )))
    .bind(scope.tenant_id())
    .bind(id)
    .bind(set_secret.as_deref())
    .bind(clear_secret)
    .bind(patch.token_endpoint_auth)
    .bind(patch.scopes.map(<[String]>::to_vec))
    .bind(patch.claim_mappings)
    .bind(patch.alg_allowlist.map(<[String]>::to_vec))
    .bind(set_version)
    .fetch_one(&mut *tx)
    .await?;

    let mut arm_id: Option<Uuid> = None;
    if let Some((email, expires_at)) = patch.bootstrap {
        let aid = Uuid::now_v7();
        if !check_and_arm_bootstrap(&mut tx, scope, id, aid, email, expires_at).await? {
            tx.rollback().await.ok();
            return Ok(LifecycleOutcome::Refused(
                "an active owner already exists; deactivate it before arming",
            ));
        }
        arm_id = Some(aid);
    }

    let detail = json!({
        "generation": row.generation,
        "client_secret_rotated": set_secret.is_some(),
        "client_secret_cleared": clear_secret,
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
    let mut tx = crate::scoped_tx(pool, scope).await?;
    let __rls_out = sqlx::query_as(
        "select m.id as membership_id, m.user_id as user_id, m.roles as roles,
                m.status as membership_status, u.email as email, u.name as name,
                u.status as user_status, u.idp_config_id as idp_config_id,
                m.created_at as created_at, u.last_login_at as last_login_at
         from org_memberships m
         join users u on u.tenant_id = m.tenant_id and u.id = m.user_id
         where m.tenant_id = $1 order by m.created_at",
    )
    .bind(scope.tenant_id())
    .fetch_all(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(__rls_out)
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
    let mut tx = crate::scoped_tx(pool, scope).await?;
    // Deactivating an OWNER frees the org for a bootstrap re-arm, so it must
    // serialize with arming/consumption/role-changes on the SAME config lock as
    // the roles-change path. Take `lock_org_configs` FIRST, UNCONDITIONALLY
    // (config → membership → sessions order, consistent with login transaction B,
    // the issuer-migration swap, and the org-switch). Gating the lock on a prior
    // owner-status read raced a concurrent owner GRANT landing between the read
    // and this deactivation — the grant would slip past serialization and the
    // deactivation would not lock. The lock is cheap (the org's handful of config
    // rows), so we always take it and then read/mutate the membership under it.
    lock_org_configs(&mut tx, scope).await?;
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
    let mut tx = crate::scoped_tx(pool, scope).await?;
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
    let row: Option<OrgMembershipRow> = sqlx::query_as(sqlx::AssertSqlSafe(format!(
        "update org_memberships set roles = $3, updated_at = now()
         where tenant_id = $1 and id = $2 returning {MEMBERSHIP_COLS}"
    )))
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
    /// The arming audit row's id (if armed), captured so consumption's audit can
    /// reference it as `arm_id` (design 401-402).
    pub bootstrap_arm_audit_id: Option<Uuid>,
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
                c.bootstrap_owner_expires_at as bootstrap_owner_expires_at,
                c.bootstrap_arm_audit_id as bootstrap_arm_audit_id
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
         set bootstrap_owner_email = null, bootstrap_owner_expires_at = null,
             bootstrap_arm_audit_id = null, updated_at = now()
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
    // GC-on-insert is scoped to the inserting tenant (the NEW login's org); a
    // global cross-tenant sweep belongs to a future background worker.
    sqlx::query(
        "delete from pending_login_switches
         where tenant_id = $1
           and ((consumed_at is null and expires_at < now())
                or expires_at < now() - interval '7 days')",
    )
    .bind(scope.tenant_id())
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
    // The dual-tenant one-time switch claim is the second credential-like bootstrap
    // exception (design lines 355-377): it reads/writes across BOTH the new org and
    // the replaced org, keyed on the confirmation-cookie hash — no single tenant
    // scope covers it — so it rides the audited system-worker bypass. Every branch
    // still re-validates the browser hash + live replaced session atomically.
    let mut tx = crate::worker_tx(pool).await?;

    // (1) Plain-read the pending switch row to learn WHICH config to lock — NO
    // lock, no trust. The config lock (step 2) MUST precede the switch-row claim
    // (step 3) to keep the global lock order config → switch-row → membership →
    // session, the SAME order the issuer-migration swap takes (`lock_org_configs`
    // first, then `cancel_config_flows_switches_sessions` updates the switch
    // rows). Reading the config id unlocked is harmless: the one-time claim
    // UPDATE in step 3 re-validates EVERY predicate atomically (browser hash,
    // unconsumed, unexpired, live replaced session), and a switch row's
    // `idp_config_id` is immutable after creation — so a stale read here can
    // never widen authority. Row absent → fail closed.
    let pending: Option<(Uuid, Uuid)> =
        sqlx::query_as("select tenant_id, idp_config_id from pending_login_switches where id = $1")
            .bind(switch_id)
            .fetch_optional(&mut *tx)
            .await?;
    let Some((pending_tenant_id, pending_config_id)) = pending else {
        tx.rollback().await.ok();
        return Ok(None);
    };

    // (2) Lock the NEW org's config row FOR UPDATE and require it active. This
    // is the SAME lock a login's transaction B (`lock_idp_config_for_update`)
    // and the issuer-migration swap (`lock_org_configs`) take, so a concurrent
    // migration fully serializes with this switch: a migrate that retires this
    // config either commits first (then `status <> 'active'` → we fail closed)
    // or blocks behind our lock until we commit. Taken FIRST — before the
    // switch-row claim — this is the head of the lock order config → switch-row
    // → membership → session, consistent with every other path.
    let config_live = sqlx::query(
        "select 1 from org_idp_configs
         where tenant_id = $1 and id = $2 and status = 'active'
         for update",
    )
    .bind(pending_tenant_id)
    .bind(pending_config_id)
    .fetch_optional(&mut *tx)
    .await?;
    if config_live.is_none() {
        tx.rollback().await.ok();
        return Ok(None);
    }

    // (3) Atomic claim binding the currently-presented live session. The
    // replaced session must be FULLY live — not just unrevoked/unexpired, but
    // its membership, user, AND tenant still active (mirrors
    // `session_is_live`). Strictly fail-closed: a deactivation cascade already
    // revokes the session, so `cur.revoked_at is null` would normally suffice;
    // these joins are belt-and-braces against any revoke that races the cascade.
    let claimed: Option<SwitchClaimRow> = sqlx::query_as(
        "update pending_login_switches ps set consumed_at = now()
         from user_sessions cur
         join org_memberships m
           on m.tenant_id = cur.tenant_id and m.id = cur.membership_id and m.user_id = cur.user_id
         join users u on u.tenant_id = cur.tenant_id and u.id = cur.user_id
         join tenants t on t.id = cur.tenant_id
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
           and m.status = 'active'
           and u.status = 'active'
           and t.status = 'active'
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

    // (4) Recheck config-active + membership-active + tenant-active on the NEW
    // org, taking `for update of m` on the NEW membership row. That row lock
    // serializes this claim against the deactivation cascade
    // (`apply_membership_status` → `revoke_sessions_for_membership`), which
    // locks the membership row FIRST and its sessions SECOND. This claim takes
    // the same order — config (step 2), membership here (step 4), then the
    // replaced session (step 5) — so the two can never deadlock. A concurrent
    // deactivation that committed before us leaves `m.status <> 'active'` → the
    // recheck matches zero rows and we roll the WHOLE claim back (fail closed;
    // the browser retries login).
    let recheck = sqlx::query(
        "select 1 from org_idp_configs c
         join org_memberships m on m.tenant_id = c.tenant_id
         join tenants t on t.id = c.tenant_id
         where c.tenant_id = $1 and c.id = $2 and c.status = 'active'
           and m.id = $3 and m.user_id = $4 and m.status = 'active'
           and t.status = 'active'
         for update of m",
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

    // (5) Revoke the replaced session (in its OWN tenant). Lock the row FOR
    // UPDATE first (session lock AFTER the config + membership locks — the
    // order fixed in steps 2 and 4), then require the revoke to touch EXACTLY
    // ONE still-live row.
    // Zero rows means a concurrent logout/revocation already killed the
    // replaced session between the step-1 claim and here → the switch would be
    // minting a new session while silently doing nothing about the old one, so
    // we roll the whole transaction back (claim included) and fail closed.
    let locked_replaced: Option<(Uuid,)> =
        sqlx::query_as("select id from user_sessions where tenant_id = $1 and id = $2 for update")
            .bind(row.replaced_tenant_id)
            .bind(row.replaced_session_id)
            .fetch_optional(&mut *tx)
            .await?;
    if locked_replaced.is_none() {
        tx.rollback().await.ok();
        return Ok(None);
    }
    let revoked = sqlx::query(
        "update user_sessions set revoked_at = now()
         where tenant_id = $1 and id = $2 and revoked_at is null",
    )
    .bind(row.replaced_tenant_id)
    .bind(row.replaced_session_id)
    .execute(&mut *tx)
    .await?
    .rows_affected();
    if revoked != 1 {
        tx.rollback().await.ok();
        return Ok(None);
    }

    // (6) Mint the new session under the NEW org.
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
    // `test_connect` (NOT `connect`): the fixtures below write and read across
    // tenants with no TenantScope, which migration 0018's FORCEd RLS refuses on a
    // plain pool. See its doc comment on the crate root.
    use crate::test_connect;

    /// Delete everything a test created under a throwaway tenant, children
    /// first (tenant FKs are NO ACTION — no cascade). `auth_audit_log` is
    /// append-only (DELETE is denied — by the 0018 RLS policy set on an
    /// RLS-bound role, by the 0012 trigger on one that bypasses RLS), so tests
    /// never COMMIT audit rows tied to a tenant — they exercise audit inside a
    /// rolled-back tx. Runs on the fixture pool: the deletes below are
    /// cross-tenant by construction and would silently match zero rows without
    /// the audited bypass GUC.
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
                client_secret_key_version: 1,
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

    /// Count rows on a policy'd table through a runtime-role connection, optionally
    /// under a GUC. Mirrors the lib.rs RLS test helper: a Postgres SUPERUSER
    /// bypasses RLS even under FORCE, and CI's DB user is the superuser, so the
    /// assertion MUST run through a `SET ROLE fluidbox_runtime` connection for the
    /// policy to actually execute. Every query OMITS a `where tenant_id` clause on
    /// purpose (the buggy-predicate proof, #75).
    async fn count_rows(
        rt: &mut sqlx::PgConnection,
        guc: Option<(&str, String)>,
        sql: &'static str,
    ) -> i64 {
        use sqlx::Connection;
        let mut tx = rt.begin().await.unwrap();
        if let Some((name, val)) = guc {
            sqlx::query("select set_config($1, $2, true)")
                .bind(name)
                .bind(val)
                .execute(&mut *tx)
                .await
                .unwrap();
        }
        let (n,): (i64,) = sqlx::query_as(sql).fetch_one(&mut *tx).await.unwrap();
        tx.rollback().await.ok();
        n
    }

    /// Phase D (#32, #75) — RLS wave B, identity family. Proves DB-enforced tenant
    /// isolation on the FOUR identity tables `scoped_tx` now guards
    /// (`users`/`org_memberships`/`user_sessions`/`api_tokens`): a tenant-A GUC sees
    /// ONLY tenant A's rows even with NO predicate, the audited bypass sees both,
    /// and a no-GUC transaction sees nothing. Seeding runs on the FIXTURE pool
    /// (`test_connect`, session-level system-worker bypass) so it is agnostic to the
    /// base role's privilege and to the enforcement asserted below — which is
    /// asserted through a SEPARATE `SET ROLE fluidbox_runtime` connection that never
    /// carries that GUC.
    #[tokio::test]
    async fn rls_identity_family_cross_tenant_isolation() {
        use sqlx::{Connection, Executor};
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("skipping: DATABASE_URL not set");
            return;
        };
        let pool = test_connect(&url).await.expect("connect");

        // Two throwaway orgs; each gets an active IdP config, a user + membership, a
        // browser session, and a PAT — one row per identity table per tenant.
        let slug_a = format!("rlsa-{}", Uuid::now_v7().simple());
        let slug_b = format!("rlsb-{}", Uuid::now_v7().simple());
        let a = create_org(&pool, &slug_a, None).await.unwrap();
        let b = create_org(&pool, &slug_b, None).await.unwrap();
        for org in [&a, &b] {
            let scope = TenantScope::assume(org.id);
            let cfg = staged_config(&pool, scope).await;
            activate(&pool, cfg.id).await;
            let (user_id, membership_id) =
                seed_user_membership(&pool, scope, cfg.id, "rls-subj").await;
            sqlx::query(
                "insert into user_sessions
                   (id, tenant_id, membership_id, user_id, session_token_sha256, idp_config_id,
                    idle_expires_at, absolute_expires_at)
                 values ($1, $2, $3, $4, $5, $6,
                         now() + interval '1 hour', now() + interval '1 day')",
            )
            .bind(Uuid::now_v7())
            .bind(org.id)
            .bind(membership_id)
            .bind(user_id)
            .bind(sha256_hex(&format!("sess-{}", org.id)))
            .bind(cfg.id)
            .execute(&pool)
            .await
            .unwrap();
            sqlx::query(
                "insert into api_tokens
                   (id, tenant_id, kind, membership_id, user_id, token_sha256, expires_at)
                 values ($1, $2, 'pat', $3, $4, $5, now() + interval '1 day')",
            )
            .bind(Uuid::now_v7())
            .bind(org.id)
            .bind(membership_id)
            .bind(user_id)
            .bind(sha256_hex(&format!("pat-{}", org.id)))
            .execute(&pool)
            .await
            .unwrap();
        }

        // Assert through the NON-superuser runtime role — otherwise RLS is bypassed.
        let mut rt = sqlx::PgConnection::connect(&url).await.expect("rt connect");
        rt.execute("set role fluidbox_runtime")
            .await
            .expect("set role");
        let a_str = a.id.to_string();
        let tid = "fluidbox.tenant_id";
        // Literal per-table SQL (sqlx needs a `'static` query); every one OMITS a
        // `where tenant_id` clause on purpose (the buggy-predicate proof).
        for (table, sql) in [
            ("users", "select count(*) from users"),
            ("org_memberships", "select count(*) from org_memberships"),
            ("user_sessions", "select count(*) from user_sessions"),
            ("api_tokens", "select count(*) from api_tokens"),
        ] {
            assert_eq!(
                count_rows(&mut rt, Some((tid, a_str.clone())), sql).await,
                1,
                "A-scope must see ONLY tenant A's {table} row even without a predicate",
            );
            assert_eq!(
                count_rows(&mut rt, None, sql).await,
                0,
                "a no-GUC transaction must see zero {table} rows",
            );
            assert!(
                count_rows(
                    &mut rt,
                    Some(("fluidbox.bypass", "system_worker".into())),
                    sql,
                )
                .await
                    >= 2,
                "the system_worker bypass must see both tenants' {table} rows",
            );
        }
        rt.close().await.ok();

        cleanup_tenant(&pool, a.id).await;
        cleanup_tenant(&pool, b.id).await;
    }

    #[tokio::test]
    async fn org_config_and_login_flow_claim() {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("skipping: DATABASE_URL not set");
            return;
        };
        let pool = test_connect(&url).await.expect("connect");

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
            1,
            "nonce-1",
            &good_hash,
            "/dashboard",
            600,
            100,
        )
        .await
        .unwrap()
        .expect("flow created");

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
        let expired = create_login_flow(
            &pool,
            scope,
            cfg.id,
            &[1],
            1,
            "nonce-2",
            &good_hash,
            "/",
            -5,
            100,
        )
        .await
        .unwrap()
        .expect("flow created");
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
        let pool = test_connect(&url).await.expect("connect");

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

    /// Append-only-ness, asserted at the depth that ACTUALLY applies to the
    /// connecting role. Migration 0018 changed which layer fires first, so the old
    /// "UPDATE/DELETE always raise" assertion is no longer the whole truth:
    ///
    /// * **RLS-BOUND role** (what FORCE RLS produces for the plain owner and for
    ///   `fluidbox_runtime`): 0018 gives `auth_audit_log` an INSERT policy and a
    ///   SELECT policy and NOTHING else, so UPDATE/DELETE match no policy and are
    ///   FILTERED to zero rows. The statement returns `Ok`, the row is untouched,
    ///   and the 0012 trigger is never reached.
    /// * **RLS-BYPASSING role** (superuser or BYPASSRLS — CI's `postgres`, Neon's
    ///   `neon_superuser`): policies are skipped entirely and the 0012 trigger is
    ///   what refuses, raising `auth_audit_log is append-only`. Post-0018 that
    ///   trigger is the BACKSTOP for exactly these roles, not the primary
    ///   owner-path guard it was written as.
    /// * **`fluidbox_runtime`**: refused one layer earlier still — 0018 REVOKEs
    ///   UPDATE/DELETE from it (0012's deferred grant), so it is a privilege error.
    ///
    /// All three are deny. The invariant both base-role branches pin is the same:
    /// the row survives the mutation attempt unchanged.
    #[tokio::test]
    async fn audit_log_is_append_only() {
        use sqlx::{Connection, Executor};
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("skipping: DATABASE_URL not set");
            return;
        };
        let pool = test_connect(&url).await.expect("connect");

        // Which depth applies here? Role attributes are NOT inherited through
        // membership, so this must be read off the connecting role itself.
        let (bypasses_rls,): (bool,) = sqlx::query_as(
            "select rolsuper or rolbypassrls from pg_roles where rolname = current_user",
        )
        .fetch_one(&pool)
        .await
        .unwrap();

        // Everything inside one tx we roll back — an audit row can never be
        // deleted (whichever layer refuses), so we never commit one in a test.
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

        let upd = sqlx::query("update auth_audit_log set success = false where id = $1")
            .bind(id)
            .execute(&mut *tx)
            .await;
        if bypasses_rls {
            assert!(
                upd.is_err(),
                "on an RLS-bypassing role the 0012 trigger must raise \
                 'auth_audit_log is append-only'"
            );
            // The failed statement poisons the tx; roll it back so nothing persists.
            tx.rollback().await.ok();
        } else {
            assert_eq!(
                upd.expect("RLS filters the UPDATE — it must not error")
                    .rows_affected(),
                0,
                "under FORCE RLS with no UPDATE policy the mutation must affect zero rows"
            );
            let (still_true,): (bool,) =
                sqlx::query_as("select success from auth_audit_log where id = $1")
                    .bind(id)
                    .fetch_one(&mut *tx)
                    .await
                    .unwrap();
            assert!(
                still_true,
                "the audit row must survive the UPDATE unchanged"
            );
            tx.rollback().await.ok();
        }

        // DELETE is likewise denied (fresh tx, also rolled back).
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
        if bypasses_rls {
            assert!(
                del.is_err(),
                "on an RLS-bypassing role the 0012 trigger must raise \
                 'auth_audit_log is append-only'"
            );
            tx.rollback().await.ok();
        } else {
            assert_eq!(
                del.expect("RLS filters the DELETE — it must not error")
                    .rows_affected(),
                0,
                "under FORCE RLS with no DELETE policy the mutation must affect zero rows"
            );
            let (survives,): (i64,) =
                sqlx::query_as("select count(*) from auth_audit_log where id = $1")
                    .bind(id2)
                    .fetch_one(&mut *tx)
                    .await
                    .unwrap();
            assert_eq!(survives, 1, "the audit row must survive the DELETE");
            tx.rollback().await.ok();
        }

        // The third depth, and the one that is deterministic on EVERY host that ran
        // 0018: the least-privilege runtime role has UPDATE/DELETE revoked, so it is
        // refused by the grant before either RLS or the trigger is consulted.
        let has_role: bool =
            sqlx::query_scalar("select exists(select 1 from pg_roles where rolname = $1)")
                .bind("fluidbox_runtime")
                .fetch_one(&pool)
                .await
                .unwrap();
        if has_role {
            let mut rt = sqlx::PgConnection::connect(&url).await.expect("rt connect");
            rt.execute("set role fluidbox_runtime")
                .await
                .expect("set role");
            let mut rtx = rt.begin().await.unwrap();
            let denied = sqlx::query("update auth_audit_log set success = false where id = $1")
                .bind(Uuid::now_v7())
                .execute(&mut *rtx)
                .await;
            let msg = denied
                .map(|_| String::new())
                .unwrap_or_else(|e| e.to_string());
            assert!(
                msg.to_lowercase().contains("permission denied"),
                "fluidbox_runtime must be denied UPDATE on auth_audit_log by the 0018 \
                 grant (got: {msg})"
            );
            rtx.rollback().await.ok();
            rt.close().await.ok();
        }
    }

    #[tokio::test]
    async fn jit_upsert_idempotency_and_owner_preservation() {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("skipping: DATABASE_URL not set");
            return;
        };
        let pool = test_connect(&url).await.expect("connect");
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
        let pool = test_connect(&url).await.expect("connect");

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

        // Happy path: old revoked + new minted atomically. The claim now also
        // requires the replaced-session revoke to affect EXACTLY ONE live row
        // (v5 hardening: 0 rows = a concurrent logout/revocation → the whole
        // claim rolls back). A true concurrency race isn't reproducible on a
        // single test connection, so we assert the happy path still commits
        // (the replaced session IS live here, so the revoke hits exactly one
        // row) and rely on the wrong-cookie / wrong-current-session / replay /
        // expired negatives above to prove the transaction still fails closed.
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
        let pool = test_connect(&url).await.expect("connect");
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
        let pool = test_connect(&url).await.expect("connect");
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
            1,
            "flow-n",
            &sha256_hex("y"),
            "/",
            600,
            100,
        )
        .await
        .unwrap()
        .expect("flow created");

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
        let sess = mint_user_session(
            &mut conn, scope, membership, user, old.id, token, None, None, None, None, 3_600,
            100_000,
        )
        .await
        .unwrap();
        // A pending switch on the OLD config (references that session) — the
        // swap's cascade must cancel it alongside the flow + session.
        let switch_bh = sha256_hex("mig-switch");
        let switch_id = create_pending_switch(
            &mut conn, scope, old.id, membership, user, org.id, sess.id, "/", &switch_bh, None,
            None, None,
        )
        .await
        .unwrap();
        drop(conn);
        // An unconsumed login flow on the OLD config.
        let flow_bh = sha256_hex("mig-flow");
        let flow_id = create_login_flow(
            pool,
            scope,
            old.id,
            &[1],
            1,
            "mig-flow",
            &flow_bh,
            "/",
            600,
            100,
        )
        .await
        .unwrap()
        .expect("flow created");
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
        // The unconsumed flow + pending switch on the old config are both
        // counted (rows_affected on `consumed_at is null`) AND actually
        // cancelled — each is now unclaimable.
        assert_eq!(counts.flows_cancelled, 1, "old-config login flow cancelled");
        assert_eq!(
            counts.switches_cancelled, 1,
            "old-config pending switch cancelled"
        );
        assert!(
            claim_login_flow(pool, flow_id, org.id, old.id, &flow_bh)
                .await
                .unwrap()
                .is_none(),
            "cancelled flow is unclaimable"
        );
        assert!(
            claim_pending_switch(
                pool,
                switch_id,
                &switch_bh,
                token,
                "fbx_web_mig_new",
                3_600,
                100_000
            )
            .await
            .unwrap()
            .is_none(),
            "cancelled switch is unclaimable"
        );

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
        let pool = test_connect(&url).await.expect("connect");
        migrate_case(&pool, false).await;
        migrate_case(&pool, true).await;
    }

    #[tokio::test]
    async fn arm_refused_while_active_owner_exists() {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("skipping: DATABASE_URL not set");
            return;
        };
        let pool = test_connect(&url).await.expect("connect");
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
        // arm_bootstrap_owner resolves the org's ACTIVE config itself (cfg was
        // activated above), so the call takes no config id.
        assert!(
            matches!(
                arm_bootstrap_owner(&pool, scope, email, exp, None)
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
            arm_bootstrap_owner(&pool, scope, email, exp, None)
                .await
                .unwrap(),
            LifecycleOutcome::Done(_)
        ));
        let after = get_idp_config(&pool, scope, cfg.id).await.unwrap().unwrap();
        assert_eq!(after.bootstrap_owner_email.as_deref(), Some(email));

        cleanup_tenant(&pool, org.id).await;
    }

    /// An EXPIRED bootstrap arm is still consumed (single winner) but grants no
    /// owner role. The promote/reject arithmetic itself lives inline in
    /// `login::provision` (transaction B) and is not callable from fluidbox-db,
    /// so this replays the exact DB steps it drives — `lock_idp_config_for_update`
    /// (captures the pre-UPDATE expiry) → `consume_bootstrap_arm` → the
    /// `was_unexpired && !owner_exists` promote guard — and asserts BOTH the
    /// consumption (arm cleared) AND that no owner role was granted.
    #[tokio::test]
    async fn bootstrap_arm_expired_consumes_without_promoting() {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("skipping: DATABASE_URL not set");
            return;
        };
        let pool = test_connect(&url).await.expect("connect");
        let slug = format!("t-{}", Uuid::now_v7().simple());
        let org = create_org(&pool, &slug, None).await.unwrap();
        let scope = TenantScope::assume(org.id);
        // staged_config arms bootstrap_owner_email = owner@example.com (expiry NULL).
        let cfg = staged_config(&pool, scope).await;
        activate(&pool, cfg.id).await;
        // Age the arm into the past.
        sqlx::query(
            "update org_idp_configs
             set bootstrap_owner_expires_at = now() - interval '1 hour'
             where id = $1",
        )
        .bind(cfg.id)
        .execute(&pool)
        .await
        .unwrap();
        // The matching identity: seed_user_membership sets email owner@example.com.
        let (_user, membership) = seed_user_membership(&pool, scope, cfg.id, "owner").await;

        // Replay transaction B's bootstrap decision through the public fns.
        let mut tx = pool.begin().await.unwrap();
        let locked = lock_idp_config_for_update(&mut tx, scope, cfg.id)
            .await
            .unwrap()
            .expect("config locks");
        // A matching arm is ALWAYS consumed (single winner), expired or not.
        assert!(
            consume_bootstrap_arm(&mut tx, scope, cfg.id, "owner@example.com")
                .await
                .unwrap()
                .is_some(),
            "matching arm is consumed"
        );
        // The captured pre-UPDATE expiry proves the arm was expired…
        let was_unexpired = locked
            .bootstrap_owner_expires_at
            .map(|e| e > Utc::now())
            .unwrap_or(false);
        assert!(!was_unexpired, "aged arm reads expired");
        let owner_exists = active_owner_exists(&mut tx, scope).await.unwrap();
        assert!(!owner_exists, "no active owner before the decision");
        // …so the decision is reject_and_consume: promote fires only when
        // `was_unexpired && !owner_exists`, which is false here — no owner grant.
        let would_promote = was_unexpired && !owner_exists;
        assert!(!would_promote, "expired arm never promotes");
        tx.commit().await.unwrap();

        // The arm is cleared (consumed) and no owner role was granted.
        let after = get_idp_config(&pool, scope, cfg.id).await.unwrap().unwrap();
        assert!(
            after.bootstrap_owner_email.is_none(),
            "arm consumed (cleared)"
        );
        assert!(after.bootstrap_owner_expires_at.is_none());
        let m = get_membership(&pool, scope, membership)
            .await
            .unwrap()
            .unwrap();
        assert!(
            !m.roles.contains(&"owner".to_string()),
            "expired arm grants no owner role"
        );

        cleanup_tenant(&pool, org.id).await;
    }

    /// Cross-tenant isolation for the identity family: tenant A's scope reads
    /// NONE of tenant B's idp config / user / membership / PATs / sealed client
    /// secret, and cannot revoke B's session — every foreign call misses at the
    /// DB (None / empty / false), with owning-scope positive controls proving
    /// the rows really exist. Throwaway orgs; cleanup is children-first.
    #[tokio::test]
    async fn tenant_scope_isolates_identity_family() {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("skipping: DATABASE_URL not set");
            return;
        };
        let pool = test_connect(&url).await.expect("connect");

        let slug_a = format!("t-{}", Uuid::now_v7().simple());
        let slug_b = format!("t-{}", Uuid::now_v7().simple());
        let org_a = create_org(&pool, &slug_a, None).await.unwrap();
        let org_b = create_org(&pool, &slug_b, None).await.unwrap();
        let scope_a = TenantScope::assume(org_a.id);
        let scope_b = TenantScope::assume(org_b.id);

        // A full identity family under B: active config (with a sealed client
        // secret), a user + membership, a live session, and a PAT.
        let cfg_b = staged_config(&pool, scope_b).await;
        activate(&pool, cfg_b.id).await;
        let (user_b, membership_b) =
            seed_user_membership(&pool, scope_b, cfg_b.id, "iso-sub").await;
        let token_b = "fbx_web_iso";
        let mut conn = pool.acquire().await.unwrap();
        let session_b = mint_user_session(
            &mut conn,
            scope_b,
            membership_b,
            user_b,
            cfg_b.id,
            token_b,
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
        mint_pat(
            &pool,
            scope_b,
            membership_b,
            user_b,
            "iso",
            "fbx_pat_isolate0000",
            Utc::now() + chrono::Duration::days(30),
        )
        .await
        .unwrap();

        // Foreign scope (A) — every identity read/write against B's ids misses.
        let idp_a = get_idp_config(&pool, scope_a, cfg_b.id).await.unwrap();
        let user_a = get_user(&pool, scope_a, user_b).await.unwrap();
        let membership_a = get_membership(&pool, scope_a, membership_b).await.unwrap();
        let pats_a = list_pats(&pool, scope_a, membership_b).await.unwrap();
        let secret_a = idp_client_secret_sealed(&pool, scope_a, cfg_b.id)
            .await
            .unwrap();
        // Session still live here — A's revoke must match zero rows (false).
        let revoke_a = revoke_user_session(&pool, scope_a, session_b.id)
            .await
            .unwrap();

        // Owning scope (B) — the same reads succeed, and B can revoke its own.
        let idp_b = get_idp_config(&pool, scope_b, cfg_b.id).await.unwrap();
        let user_bb = get_user(&pool, scope_b, user_b).await.unwrap();
        let membership_bb = get_membership(&pool, scope_b, membership_b).await.unwrap();
        let pats_b = list_pats(&pool, scope_b, membership_b).await.unwrap();
        let secret_b = idp_client_secret_sealed(&pool, scope_b, cfg_b.id)
            .await
            .unwrap();
        let revoke_b = revoke_user_session(&pool, scope_b, session_b.id)
            .await
            .unwrap();

        // Cleanup BOTH orgs (children-first) before asserting.
        cleanup_tenant(&pool, org_b.id).await;
        cleanup_tenant(&pool, org_a.id).await;

        // Foreign misses.
        assert!(idp_a.is_none(), "A cannot read B's idp config");
        assert!(user_a.is_none(), "A cannot read B's user");
        assert!(membership_a.is_none(), "A cannot read B's membership");
        assert!(pats_a.is_empty(), "A lists none of B's PATs");
        assert!(secret_a.is_none(), "A cannot read B's sealed client secret");
        assert!(!revoke_a, "A cannot revoke B's session");
        // Owning positives.
        assert!(idp_b.is_some(), "B reads its own idp config");
        assert!(user_bb.is_some(), "B reads its own user");
        assert!(membership_bb.is_some(), "B reads its own membership");
        assert_eq!(pats_b.len(), 1, "B lists its own PAT");
        assert!(secret_b.is_some(), "B reads its own sealed client secret");
        assert!(revoke_b, "B revokes its own live session");
    }

    /// Interleaving evidence for the migration-vs-login-B serialization the
    /// identity-e2e migration section cites but cannot barrier from a black-box
    /// HTTP client. Two POOL CONNECTIONS, bounded by timeouts so CI can never
    /// hang:
    ///
    /// (1) login-B holds the config lock (`lock_idp_config_for_update`, the same
    ///     `FOR UPDATE` a real transaction B opens with); a concurrent
    ///     `migrate_idp_config` (which takes `lock_org_configs` over the same
    ///     rows) must BLOCK until B commits — proven by a 500ms `timeout`
    ///     ELAPSING while B holds, then the swap completing once B releases.
    /// (2) the REVERSE ordering: after the swap the old config is `retired`, so a
    ///     login-B status recheck that locks it reads `retired` and would refuse
    ///     (a real transaction B admits only an `active` config).
    #[tokio::test]
    async fn migration_and_login_b_serialize_on_config_lock() {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("skipping: DATABASE_URL not set");
            return;
        };
        let pool = test_connect(&url).await.expect("connect");
        let pool2 = test_connect(&url).await.expect("connect 2");

        let slug = format!("t-{}", Uuid::now_v7().simple());
        let org = create_org(&pool, &slug, None).await.unwrap();
        let scope = TenantScope::assume(org.id);
        let cfg1 = staged_config(&pool, scope).await; // generation 1
        let cfg2 = staged_config(&pool, scope).await; // generation 2 (the replacement)
                                                      // Copy the ids out so the spawned task captures only `Copy` Uuids, leaving
                                                      // `cfg1` usable in the reverse-ordering recheck below.
        let (cfg1_id, cfg2_id) = (cfg1.id, cfg2.id);
        activate(&pool, cfg1_id).await;

        // conn1 = login-B's opening lock on the active config1.
        let mut tx1 = pool.begin().await.unwrap();
        let locked = lock_idp_config_for_update(&mut tx1, scope, cfg1_id)
            .await
            .unwrap()
            .expect("config1 locks for B");
        assert_eq!(locked.config_status, "active");

        // conn2 = a concurrent migrate. Spawn it; it must NOT finish while tx1
        // holds the config lock. `&mut handle` keeps the task alive across the
        // timeout so it can be awaited after tx1 commits.
        let mut handle = tokio::spawn(async move {
            migrate_idp_config(&pool2, scope, cfg1_id, cfg2_id, false, None).await
        });
        let blocked =
            tokio::time::timeout(std::time::Duration::from_millis(500), &mut handle).await;
        assert!(
            blocked.is_err(),
            "migrate BLOCKS while login-B holds the config lock (500ms timeout elapsed)"
        );

        // Release B's lock; the swap now proceeds and succeeds.
        tx1.commit().await.unwrap();
        let swapped = tokio::time::timeout(std::time::Duration::from_secs(10), handle)
            .await
            .expect("migrate completes once the lock releases")
            .expect("migrate task joined")
            .expect("migrate returns Ok");
        assert!(
            matches!(swapped, LifecycleOutcome::Done(_)),
            "swap succeeds after B commits"
        );

        // Reverse ordering: the swap ran first, so config1 is now retired. A
        // login-B status recheck locks it and reads a non-active status — a real
        // transaction B refuses any config that is not active.
        let mut tx = pool.begin().await.unwrap();
        let post = lock_idp_config_for_update(&mut tx, scope, cfg1_id)
            .await
            .unwrap()
            .expect("config1 row still present post-swap");
        assert_eq!(
            post.config_status, "retired",
            "post-swap config1 is retired → a login-B recheck refuses it"
        );
        tx.commit().await.unwrap();

        cleanup_tenant(&pool, org.id).await;
    }

    /// A full org-switch scenario: the NEW login's org (ACTIVE config + seeded
    /// user/membership) plus a SECOND org holding the live replaced session, and
    /// a pending switch pointing at the NEW config. Returns everything a
    /// `claim_pending_switch` call needs; tenants are throwaway (cleaned up by
    /// the caller).
    struct SwitchScenario {
        org_new: Uuid,
        cfg_new: Uuid,
        org_old: Uuid,
        cookie: String,
        current_token: String,
        switch_id: Uuid,
    }

    async fn seed_switch_scenario(pool: &PgPool) -> SwitchScenario {
        let slug_new = format!("t-{}", Uuid::now_v7().simple());
        let org_new = create_org(pool, &slug_new, None).await.unwrap();
        let scope_new = TenantScope::assume(org_new.id);
        let cfg_new = staged_config(pool, scope_new).await;
        activate(pool, cfg_new.id).await;
        let (new_user, new_membership) =
            seed_user_membership(pool, scope_new, cfg_new.id, "new-sub").await;

        let slug_old = format!("t-{}", Uuid::now_v7().simple());
        let org_old = create_org(pool, &slug_old, None).await.unwrap();
        let scope_old = TenantScope::assume(org_old.id);
        let cfg_old = staged_config(pool, scope_old).await;
        let (old_user, old_membership) =
            seed_user_membership(pool, scope_old, cfg_old.id, "old-sub").await;

        let current_token = format!("fbx_web_cur_{}", Uuid::now_v7().simple());
        let cookie = format!("cookie-{}", Uuid::now_v7().simple());
        let mut conn = pool.acquire().await.unwrap();
        let current = mint_user_session(
            &mut conn,
            scope_old,
            old_membership,
            old_user,
            cfg_old.id,
            &current_token,
            None,
            None,
            None,
            None,
            3_600,
            100_000,
        )
        .await
        .unwrap();
        let switch_id = create_pending_switch(
            &mut conn,
            scope_new,
            cfg_new.id,
            new_membership,
            new_user,
            org_old.id,
            current.id,
            "/dashboard",
            &sha256_hex(&cookie),
            None,
            None,
            None,
        )
        .await
        .unwrap();
        drop(conn);

        SwitchScenario {
            org_new: org_new.id,
            cfg_new: cfg_new.id,
            org_old: org_old.id,
            cookie,
            current_token,
            switch_id,
        }
    }

    /// The switch-claim vs migration-swap serialization, the companion to
    /// `migration_and_login_b_serialize_on_config_lock`. Both take the config row
    /// `FOR UPDATE` FIRST (the swap via `lock_org_configs`, the claim as its
    /// step 2, BEFORE it touches the switch row), so the two can never deadlock —
    /// the global lock order is config → switch-row → membership → session. Two
    /// POOL CONNECTIONS, timeout-bounded so CI can never hang:
    ///
    /// (1) FORWARD: a swap holds the config lock; a concurrent claim must BLOCK
    ///     (500ms `timeout` ELAPSES). Once the swap commits (retiring the config
    ///     and cancelling the pending switch), the claim unblocks and fails
    ///     closed (`None`) against the now-retired config — the original session
    ///     is KEPT.
    /// (2) REVERSE: the claim commits FIRST (minting the new session); a
    ///     subsequent swap that retires the new config revokes that fresh session
    ///     (its `revoked_at` is set).
    #[tokio::test]
    async fn migration_and_switch_claim_serialize_on_config_lock() {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("skipping: DATABASE_URL not set");
            return;
        };
        let pool = test_connect(&url).await.expect("connect");
        let pool2 = test_connect(&url).await.expect("connect 2");

        // ---- FORWARD: swap holds the lock → claim blocks → fails closed. ----
        let s = seed_switch_scenario(&pool).await;
        let scope_new = TenantScope::assume(s.org_new);

        // conn1 = a migration swap in progress: hold the SAME config row lock the
        // claim now takes FIRST (step 2), before it ever touches the switch row.
        let mut tx1 = pool.begin().await.unwrap();
        let locked = lock_idp_config_for_update(&mut tx1, scope_new, s.cfg_new)
            .await
            .unwrap()
            .expect("new config locks for the swap");
        assert_eq!(locked.config_status, "active");

        // conn2 = the switch claim. It plain-reads the switch row then contends
        // for the config lock, so it must BLOCK while conn1 holds it. `&mut
        // handle` keeps the task alive across the timeout.
        let (switch_id, bh, cur, new_tok) = (
            s.switch_id,
            sha256_hex(&s.cookie),
            s.current_token.clone(),
            "fbx_web_switch_fwd".to_string(),
        );
        let mut handle = tokio::spawn(async move {
            claim_pending_switch(&pool2, switch_id, &bh, &cur, &new_tok, 3_600, 100_000).await
        });
        let blocked =
            tokio::time::timeout(std::time::Duration::from_millis(500), &mut handle).await;
        assert!(
            blocked.is_err(),
            "switch claim BLOCKS while the swap holds the config lock (500ms timeout elapsed)"
        );

        // The swap retires the config and cancels the pending switch, then commits.
        sqlx::query(
            "update org_idp_configs set status = 'retired', updated_at = now()
             where tenant_id = $1 and id = $2",
        )
        .bind(s.org_new)
        .bind(s.cfg_new)
        .execute(&mut *tx1)
        .await
        .unwrap();
        cancel_config_flows_switches_sessions(&mut tx1, scope_new, s.cfg_new)
            .await
            .unwrap();
        tx1.commit().await.unwrap();

        // The claim now unblocks and fails closed: the config it locked is
        // retired, so it returns None WITHOUT revoking the original session.
        let claim = tokio::time::timeout(std::time::Duration::from_secs(10), handle)
            .await
            .expect("claim completes once the lock releases")
            .expect("claim task joined")
            .expect("claim returns Ok");
        assert!(
            claim.is_none(),
            "claim fails closed against a config retired by the swap"
        );
        assert!(
            resolve_web_session(&pool, &s.current_token, 3_600)
                .await
                .unwrap()
                .is_some(),
            "the replaced session is KEPT when the claim fails closed"
        );

        // ---- REVERSE: claim commits first → a later swap revokes its session. ----
        let r = seed_switch_scenario(&pool).await;
        let scope_r = TenantScope::assume(r.org_new);
        let new_token_r = "fbx_web_switch_rev";
        let claimed = claim_pending_switch(
            &pool,
            r.switch_id,
            &sha256_hex(&r.cookie),
            &r.current_token,
            new_token_r,
            3_600,
            100_000,
        )
        .await
        .unwrap()
        .expect("claim succeeds when it wins the config lock");
        assert_eq!(claimed.new_tenant_id, r.org_new);

        // The swap runs AFTER the claim committed: retiring the new config
        // revokes the freshly minted session (it carries the new config id).
        let mut tx2 = pool.begin().await.unwrap();
        lock_org_configs(&mut tx2, scope_r).await.unwrap();
        sqlx::query(
            "update org_idp_configs set status = 'retired', updated_at = now()
             where tenant_id = $1 and id = $2",
        )
        .bind(r.org_new)
        .bind(r.cfg_new)
        .execute(&mut *tx2)
        .await
        .unwrap();
        cancel_config_flows_switches_sessions(&mut tx2, scope_r, r.cfg_new)
            .await
            .unwrap();
        tx2.commit().await.unwrap();

        let revoked_at: Option<DateTime<Utc>> = sqlx::query_scalar(
            "select revoked_at from user_sessions
             where tenant_id = $1 and session_token_sha256 = $2",
        )
        .bind(r.org_new)
        .bind(sha256_hex(new_token_r))
        .fetch_one(&pool)
        .await
        .unwrap();
        assert!(
            revoked_at.is_some(),
            "the swap revokes the newly minted switch session"
        );

        cleanup_tenant(&pool, s.org_new).await;
        cleanup_tenant(&pool, s.org_old).await;
        cleanup_tenant(&pool, r.org_new).await;
        cleanup_tenant(&pool, r.org_old).await;
    }

    /// The concurrent bootstrap-owner claim has EXACTLY ONE winner (design lines
    /// 683-690). Two logins race the consume-arm UPDATE for the same armed email
    /// on two connections; the row lock serializes them, so exactly one clears
    /// the arm (`Some`) and the other sees the now-null email and matches nothing
    /// (`None`). Bounded by a timeout so a lock-ordering regression fails fast
    /// instead of hanging CI.
    #[tokio::test]
    async fn concurrent_bootstrap_arm_has_a_single_winner() {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("skipping: DATABASE_URL not set");
            return;
        };
        let pool = test_connect(&url).await.expect("connect");
        let pool_a = test_connect(&url).await.expect("connect a");
        let pool_b = test_connect(&url).await.expect("connect b");

        let slug = format!("t-{}", Uuid::now_v7().simple());
        let org = create_org(&pool, &slug, None).await.unwrap();
        let scope = TenantScope::assume(org.id);
        // staged_config arms bootstrap_owner_email = owner@example.com.
        let cfg = staged_config(&pool, scope).await;
        activate(&pool, cfg.id).await;

        // Each racer runs the consume-arm UPDATE in its OWN transaction so the
        // row lock is held until commit — the DB serializes the two.
        async fn race_consume(pool: PgPool, scope: TenantScope, cfg_id: Uuid) -> Option<Uuid> {
            let mut tx = pool.begin().await.unwrap();
            let r = consume_bootstrap_arm(&mut tx, scope, cfg_id, "owner@example.com")
                .await
                .unwrap();
            tx.commit().await.unwrap();
            r
        }
        let (ra, rb) = tokio::time::timeout(std::time::Duration::from_secs(15), async {
            tokio::join!(
                race_consume(pool_a, scope, cfg.id),
                race_consume(pool_b, scope, cfg.id),
            )
        })
        .await
        .expect("bootstrap race completes within the bound");

        assert_eq!(
            ra.is_some() as u8 + rb.is_some() as u8,
            1,
            "exactly one login consumes the arm (single winner)"
        );

        // The arm is cleared exactly once.
        let after = get_idp_config(&pool, scope, cfg.id).await.unwrap().unwrap();
        assert!(
            after.bootstrap_owner_email.is_none(),
            "the arm is consumed (cleared)"
        );

        cleanup_tenant(&pool, org.id).await;
    }
}
