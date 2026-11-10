//! GitHub App registrations, their one-time flows, and installation connections.

use crate::connections::{IntegrationConnectionRow, CONNECTION_COLS};
use crate::scope::{scoped_tx, worker_tx, TenantScope};
use chrono::{DateTime, Utc};
use serde_json::Value;
use sqlx::{PgPool, Row};
use uuid::Uuid;

// ─── GitHub App registrations & flows (Phase 5.6) ─────────────────────────

/// The App identity created via GitHub's manifest flow. Secrets (pem,
/// webhook secret, client secret) are NEVER selected by row queries — the
/// explicit column list below cannot leak them; the dedicated active-only
/// readers are the only accessors.
#[derive(Debug, Clone, sqlx::FromRow, serde::Serialize)]
pub struct GithubAppRegistrationRow {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub status: String, // pending | active | revoked
    pub target_kind: String,
    pub target_org: Option<String>,
    pub app_id: Option<String>,
    pub slug: Option<String>,
    pub name: Option<String>,
    pub client_id: Option<String>,
    pub html_url: Option<String>,
    pub owner_login: Option<String>,
    /// False = degraded: GitHub returned no webhook secret at conversion —
    /// fetch/publish work, event ingress cannot authenticate.
    pub has_webhook_secret: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

pub(crate) const GH_REG_COLS: &str =
    "id, tenant_id, status, target_kind, target_org, app_id, slug, \
     name, client_id, html_url, owner_login, \
     (webhook_secret_sealed is not null) as has_webhook_secret, created_at, updated_at";

pub async fn create_github_app_registration(
    pool: &PgPool,
    scope: TenantScope,
    target_kind: &str,
    target_org: Option<&str>,
) -> sqlx::Result<GithubAppRegistrationRow> {
    let mut tx = scoped_tx(pool, scope).await?;

    let __rls_out = sqlx::query_as(sqlx::AssertSqlSafe(format!(
        "insert into github_app_registrations (id, tenant_id, target_kind, target_org)
         values ($1, $2, $3, $4)
         returning {GH_REG_COLS}"
    )))
    .bind(Uuid::now_v7())
    .bind(scope.tenant_id())
    .bind(target_kind)
    .bind(target_org)
    .fetch_one(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(__rls_out)
}

pub async fn list_github_app_registrations(
    pool: &PgPool,
    scope: TenantScope,
) -> sqlx::Result<Vec<GithubAppRegistrationRow>> {
    let mut tx = scoped_tx(pool, scope).await?;

    let __rls_out = sqlx::query_as(sqlx::AssertSqlSafe(format!(
        "select {GH_REG_COLS} from github_app_registrations
         where tenant_id = $1 order by created_at desc"
    )))
    .bind(scope.tenant_id())
    .fetch_all(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(__rls_out)
}

pub async fn get_github_app_registration(
    pool: &PgPool,
    scope: TenantScope,
    id: Uuid,
) -> sqlx::Result<Option<GithubAppRegistrationRow>> {
    let mut tx = scoped_tx(pool, scope).await?;

    let __rls_out = sqlx::query_as(sqlx::AssertSqlSafe(format!(
        "select {GH_REG_COLS} from github_app_registrations where id = $1 and tenant_id = $2"
    )))
    .bind(id)
    .bind(scope.tenant_id())
    .fetch_optional(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(__rls_out)
}

/// The manifest conversion landing: exactly ONE conversion may complete a
/// registration (`where status = 'pending'`); a racing second conversion
/// affects zero rows and its result is discarded by the caller.
#[allow(clippy::too_many_arguments)]
pub async fn activate_github_app_registration(
    pool: &PgPool,
    scope: TenantScope,
    id: Uuid,
    app_id: &str,
    slug: &str,
    name: &str,
    client_id: Option<&str>,
    html_url: &str,
    owner_login: Option<&str>,
    pem_sealed: &[u8],
    pem_key_version: i16,
    webhook_secret_sealed: Option<&[u8]>,
    webhook_secret_key_version: i16,
    client_secret_sealed: Option<&[u8]>,
    client_secret_key_version: i16,
) -> sqlx::Result<Option<GithubAppRegistrationRow>> {
    let mut tx = scoped_tx(pool, scope).await?;

    let __rls_out = sqlx::query_as(sqlx::AssertSqlSafe(format!(
        "update github_app_registrations
         set app_id = $2, slug = $3, name = $4, client_id = $5, html_url = $6,
             owner_login = $7, pem_sealed = $8, webhook_secret_sealed = $9,
             client_secret_sealed = $10, pem_key_version = $12,
             webhook_secret_key_version = $13, client_secret_key_version = $14,
             status = 'active', updated_at = now()
         where id = $1 and status = 'pending' and tenant_id = $11
         returning {GH_REG_COLS}"
    )))
    .bind(id)
    .bind(app_id)
    .bind(slug)
    .bind(name)
    .bind(client_id)
    .bind(html_url)
    .bind(owner_login)
    .bind(pem_sealed)
    .bind(webhook_secret_sealed)
    .bind(client_secret_sealed)
    .bind(scope.tenant_id())
    .bind(pem_key_version)
    .bind(webhook_secret_key_version)
    .bind(client_secret_key_version)
    .fetch_optional(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(__rls_out)
}

/// Revoke a registration AND its child connections in one transaction;
/// returns the affected connection ids so the caller can evict cached
/// installation tokens. Registrations are revoked, never deleted (the FK is
/// RESTRICT on purpose).
pub async fn revoke_github_app_registration(
    pool: &PgPool,
    scope: TenantScope,
    id: Uuid,
) -> sqlx::Result<Option<Vec<Uuid>>> {
    let mut tx = scoped_tx(pool, scope).await?;
    let reg = sqlx::query(
        "update github_app_registrations set status = 'revoked', updated_at = now()
         where id = $1 and status <> 'revoked' and tenant_id = $2",
    )
    .bind(id)
    .bind(scope.tenant_id())
    .execute(&mut *tx)
    .await?;
    if reg.rows_affected() == 0 {
        tx.rollback().await?;
        return Ok(None);
    }
    // Scope the child cascade to the registration's own tenant too — the
    // composite FK already makes a cross-tenant child impossible, but the
    // predicate keeps the statement self-scoped (never a bare-id UPDATE).
    let rows = sqlx::query(
        "update integration_connections set status = 'revoked', updated_at = now()
         where registration_id = $1 and status <> 'revoked' and tenant_id = $2
         returning id",
    )
    .bind(id)
    .bind(scope.tenant_id())
    .fetch_all(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(Some(rows.iter().map(|r| r.get::<Uuid, _>("id")).collect()))
}

/// Active-only reader for the App signing key (same discipline as
/// `connection_credential_sealed`): a revoked registration can never again
/// produce a JWT.
pub async fn github_app_registration_pem_sealed(
    pool: &PgPool,
    scope: TenantScope,
    id: Uuid,
) -> sqlx::Result<Option<(Vec<u8>, i16)>> {
    let mut tx = scoped_tx(pool, scope).await?;
    let row = sqlx::query(
        "select pem_sealed, pem_key_version from github_app_registrations
         where id = $1 and status = 'active' and tenant_id = $2",
    )
    .bind(id)
    .bind(scope.tenant_id())
    .fetch_optional(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(row.and_then(|r| {
        r.get::<Option<Vec<u8>>, _>("pem_sealed")
            .map(|b| (b, r.get::<i16, _>("pem_key_version")))
    }))
}

/// Active-only reader for the app-level webhook secret (verified on every
/// app-level ingress request).
pub async fn github_app_registration_webhook_secret_sealed(
    pool: &PgPool,
    scope: TenantScope,
    id: Uuid,
) -> sqlx::Result<Option<(Vec<u8>, i16)>> {
    let mut tx = scoped_tx(pool, scope).await?;
    let row = sqlx::query(
        "select webhook_secret_sealed, webhook_secret_key_version from github_app_registrations
         where id = $1 and status = 'active' and tenant_id = $2",
    )
    .bind(id)
    .bind(scope.tenant_id())
    .fetch_optional(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(row.and_then(|r| {
        r.get::<Option<Vec<u8>>, _>("webhook_secret_sealed")
            .map(|b| (b, r.get::<i16, _>("webhook_secret_key_version")))
    }))
}

/// Mint a one-time flow. Opportunistically sweeps this tenant's expired
/// unconsumed flows immediately, and consumed ones after a 7-day audit
/// window, so abandoned dances never accumulate.
///
/// TENANT-SCOPED (review L6). Minting is the AUTHENTICATED half of the GitHub-App
/// dance — all three call sites already hold a verified tenant (two admin-token'd
/// start endpoints via `principal.scope()`, and the manifest callback via the
/// scope it derives from the registration row it just resolved) — so it has no
/// business on the cross-tenant bypass. Only the two CLAIMs
/// ([`claim_github_app_bootstrap`], [`claim_github_app_flow`]) are genuinely
/// pre-auth: those arrive from GitHub/the browser with no principal, and the
/// one-time flow id + browser-cookie hash ARE the auth.
///
/// The insert derives its `registration_id` from a row selected under the scope,
/// so a caller cannot mint a flow against another tenant's registration even if
/// RLS is inert (a superuser/BYPASSRLS pool role); returns [`sqlx::Error::RowNotFound`]
/// when the registration is absent from this tenant.
pub async fn create_github_app_flow(
    pool: &PgPool,
    scope: TenantScope,
    registration_id: Uuid,
    purpose: &str,
    ttl_secs: i64,
) -> sqlx::Result<Uuid> {
    let mut tx = scoped_tx(pool, scope).await?;
    // Self-scoped sweep: only flows under THIS tenant's registrations (the RLS
    // child policy composes the same predicate; the EXISTS keeps it true without it).
    sqlx::query(
        "delete from github_app_flows f
         where ((f.consumed_at is null and f.expires_at < now())
                or f.expires_at < now() - interval '7 days')
           and exists (select 1 from github_app_registrations r
                        where r.id = f.registration_id and r.tenant_id = $1)",
    )
    .bind(scope.tenant_id())
    .execute(&mut *tx)
    .await?;
    let id = Uuid::now_v7();
    let inserted = sqlx::query(
        "insert into github_app_flows (id, registration_id, purpose, expires_at)
         select $1, r.id, $3, now() + make_interval(secs => $4::double precision)
           from github_app_registrations r
          where r.id = $2 and r.tenant_id = $5",
    )
    .bind(id)
    .bind(registration_id)
    .bind(purpose)
    .bind(ttl_secs as f64)
    .bind(scope.tenant_id())
    .execute(&mut *tx)
    .await?;
    if inserted.rows_affected() != 1 {
        tx.rollback().await.ok();
        return Err(sqlx::Error::RowNotFound);
    }
    tx.commit().await?;
    Ok(id)
}

/// The go page's one-time claim: binds a fresh browser cookie hash to the
/// flow. Exactly one browser can ever be bound.
pub async fn claim_github_app_bootstrap(
    pool: &PgPool,
    flow_id: Uuid,
    purpose: &str,
    browser_hash: &str,
) -> sqlx::Result<Option<Uuid>> {
    // Pre-auth bootstrap claim (browser cookie is the auth) — audited bypass.
    let mut tx = worker_tx(pool).await?;
    let row = sqlx::query(
        "update github_app_flows
         set bootstrap_consumed_at = now(), browser_hash = $3
         where id = $1 and purpose = $2 and bootstrap_consumed_at is null
           and expires_at > now()
         returning registration_id",
    )
    .bind(flow_id)
    .bind(purpose)
    .bind(browser_hash)
    .fetch_optional(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(row.map(|r| r.get::<Uuid, _>("registration_id")))
}

/// The callback/setup one-time claim. The browser-cookie hash sits INSIDE
/// the predicate: an attacker holding a leaked state parameter but not the
/// initiating browser's cookie cannot complete OR burn the flow.
pub async fn claim_github_app_flow(
    pool: &PgPool,
    flow_id: Uuid,
    purpose: &str,
    registration_id: Uuid,
    browser_hash: &str,
) -> sqlx::Result<bool> {
    // Pre-auth one-time claim (browser cookie inside the predicate) — audited bypass.
    let mut tx = worker_tx(pool).await?;
    let r = sqlx::query(
        "update github_app_flows
         set consumed_at = now()
         where id = $1 and purpose = $2 and registration_id = $3
           and consumed_at is null and bootstrap_consumed_at is not null
           and browser_hash = $4 and expires_at > now()",
    )
    .bind(flow_id)
    .bind(purpose)
    .bind(registration_id)
    .bind(browser_hash)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(r.rows_affected() == 1)
}

/// Insert a seamless installation connection ONLY if the installation has
/// never had a row of ANY status — the check rides inside the statement, so
/// an insert can never land just after a concurrent revoke (F‑6: revoked
/// rows revive only via approve, never via a fresh import racing in).
/// Returns None when any row (live or revoked) already exists; the caller
/// loops back through its existing-row path.
#[allow(clippy::too_many_arguments)]
pub async fn create_github_app_connection_if_absent(
    pool: &PgPool,
    scope: TenantScope,
    installation_id: &str,
    display_name: &str,
    metadata: &Value,
    status: &str,
    registration_id: Uuid,
) -> sqlx::Result<Option<IntegrationConnectionRow>> {
    let mut tx = scoped_tx(pool, scope).await?;

    let __rls_out = sqlx::query_as(sqlx::AssertSqlSafe(format!(
        // github_app connections are ALWAYS organization-owned (system custody
        // via the registration) — owner_type is stamped explicitly, never a
        // per-user personal connection.
        "insert into integration_connections
           (id, tenant_id, provider, external_account_id, display_name, credential_sealed,
            granted_scopes, resource_selection, metadata, webhook_secret_sealed,
            auth_kind, status, oauth, client_secret_sealed, registration_id, owner_type)
         select $1, $2, 'github_app', $3, $4, null, '[]'::jsonb, '{{}}'::jsonb, $5, null,
                'static', $6, null, null, $7, 'organization'
         where not exists (
             select 1 from integration_connections
             where tenant_id = $2 and provider = 'github_app' and external_account_id = $3
         )
         returning {CONNECTION_COLS}"
    )))
    .bind(Uuid::now_v7())
    .bind(scope.tenant_id())
    .bind(installation_id)
    .bind(display_name)
    .bind(metadata)
    .bind(status)
    .bind(registration_id)
    .fetch_optional(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(__rls_out)
}

/// The single live connection row for a GitHub installation, preferring a
/// live row but surfacing a revoked one (callers refuse or route revival
/// through the explicit approve path — never a second row).
pub async fn get_github_app_connection_by_installation(
    pool: &PgPool,
    scope: TenantScope,
    installation_id: &str,
) -> sqlx::Result<Option<IntegrationConnectionRow>> {
    let mut tx = scoped_tx(pool, scope).await?;

    let __rls_out = sqlx::query_as(sqlx::AssertSqlSafe(format!(
        "select {CONNECTION_COLS} from integration_connections
         where tenant_id = $1 and provider = 'github_app' and external_account_id = $2
         order by (status <> 'revoked') desc, created_at desc
         limit 1"
    )))
    .bind(scope.tenant_id())
    .bind(installation_id)
    .fetch_optional(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(__rls_out)
}
