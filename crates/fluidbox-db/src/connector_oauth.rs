//! What the connector OAuth dance persists beside the connection row:
//! shared client registrations, one-time flows, and the refresh lock.

use crate::scope::{scoped_tx, worker_tx, TenantScope};
use chrono::{DateTime, Utc};
use serde_json::Value;
use sqlx::PgPool;
use uuid::Uuid;

// ─── Reusable OAuth client registrations (Phase D Task 3, #32; design D6) ────
//
// A shared client identity keyed on (issuer, redirect_uri): the first OAuth
// connection to an authorization server registers (or resolves CIMD) once and
// every later connection to the same issuer reuses the row instead of minting
// its own per-connection DCR client. Pre-registered (operator-pasted) identities
// stay per-connection custody and get NO row.
//
// PLACEMENT (reviewer note): these are principal-less GLOBAL reads, but they are
// deliberately NOT in `system_worker` — that module is for cross-tenant scans of
// TENANT-owned data. Client registrations are deployment INFRASTRUCTURE (like
// `connector_catalog`'s global rows). v1 only ever WRITES `tenant_id NULL`; both
// lookups (`find_client_registration`, `find_client_registration_by_id`) FILTER
// `tenant_id is null`; `touch`/`delete` act on an already-resolved id. There is no
// tenant to scope by, so they live here beside the connection custody they serve,
// unscoped by construction. The nullable `tenant_id` + per-tenant partial unique
// are forward-compat only (migration 0015).

/// A shared OAuth client registration. Carries its sealed secret because every
/// read IS a credential resolution (unseal for token-endpoint auth) — the row is
/// internal deployment infrastructure and NEVER crosses an API boundary, so
/// unlike `IntegrationConnectionRow` it does not hide the sealed bytea behind a
/// dedicated reader (and is deliberately NOT `Serialize`).
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct OauthClientRegistrationRow {
    pub id: Uuid,
    /// NULL = deployment-global (v1 always). Present only for a future per-tenant
    /// client identity.
    pub tenant_id: Option<Uuid>,
    pub issuer: String,
    pub redirect_uri: String,
    pub source: String, // dcr | cimd | preregistered
    pub client_id: String,
    pub client_secret_sealed: Option<Vec<u8>>,
    pub client_secret_key_version: i16,
    pub registration_endpoint: Option<String>,
    pub registration_access_token_sealed: Option<Vec<u8>>,
    pub registration_access_token_key_version: i16,
    pub token_endpoint_auth_method: Option<String>,
    pub created_at: DateTime<Utc>,
    pub last_used_at: Option<DateTime<Utc>>,
}

/// Values for a new registration row. Sealed bytes are pre-sealed by the caller
/// (server owns the crypto); the companion key-versions ride beside them.
pub struct NewOauthClientRegistration<'a> {
    /// v1 always passes `None` (global). Present only for a future per-tenant row.
    pub tenant_id: Option<Uuid>,
    pub issuer: &'a str,
    pub redirect_uri: &'a str,
    pub source: &'a str, // dcr | cimd | preregistered
    pub client_id: &'a str,
    pub client_secret_sealed: Option<&'a [u8]>,
    pub client_secret_key_version: i16,
    pub registration_endpoint: Option<&'a str>,
    pub registration_access_token_sealed: Option<&'a [u8]>,
    pub registration_access_token_key_version: i16,
    pub token_endpoint_auth_method: Option<&'a str>,
}

/// Find the shared registration for an (issuer, redirect_uri). Global rows only
/// in v1 (`tenant_id is null`). Executor-generic so the DCR resolution can run it
/// THROUGH the advisory-lock-holding transaction (`&mut *tx`).
pub async fn find_client_registration<'e, E>(
    exec: E,
    issuer: &str,
    redirect_uri: &str,
) -> sqlx::Result<Option<OauthClientRegistrationRow>>
where
    E: sqlx::PgExecutor<'e>,
{
    sqlx::query_as(
        "select * from oauth_client_registrations
         where tenant_id is null and issuer = $1 and redirect_uri = $2",
    )
    .bind(issuer)
    .bind(redirect_uri)
    .fetch_optional(exec)
    .await
}

/// Load one GLOBAL registration by id — the exchange/refresh path resolves the
/// identity the connection's `oauth.registration_id` points at. `and tenant_id is
/// null` is a v1 belt: a connection only ever stores a GLOBAL registration id, so
/// a non-global id fails closed to None rather than crossing into a future
/// per-tenant row.
pub async fn find_client_registration_by_id<'e, E>(
    exec: E,
    id: Uuid,
) -> sqlx::Result<Option<OauthClientRegistrationRow>>
where
    E: sqlx::PgExecutor<'e>,
{
    sqlx::query_as("select * from oauth_client_registrations where id = $1 and tenant_id is null")
        .bind(id)
        .fetch_optional(exec)
        .await
}

/// Insert a shared registration. `ON CONFLICT DO NOTHING` returns `None` when a
/// concurrent connect already registered this (issuer, redirect_uri) — the caller
/// re-selects the winner (and abandons its own AS-side minted client). Global rows
/// only in v1 (`tenant_id NULL`); the partial unique enforces one per key.
pub async fn insert_client_registration<'e, E>(
    exec: E,
    new: NewOauthClientRegistration<'_>,
) -> sqlx::Result<Option<OauthClientRegistrationRow>>
where
    E: sqlx::PgExecutor<'e>,
{
    sqlx::query_as(
        "insert into oauth_client_registrations
           (id, tenant_id, issuer, redirect_uri, source, client_id,
            client_secret_sealed, client_secret_key_version,
            registration_endpoint,
            registration_access_token_sealed, registration_access_token_key_version,
            token_endpoint_auth_method, last_used_at)
         values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12, now())
         on conflict do nothing
         returning *",
    )
    .bind(Uuid::now_v7())
    .bind(new.tenant_id)
    .bind(new.issuer)
    .bind(new.redirect_uri)
    .bind(new.source)
    .bind(new.client_id)
    .bind(new.client_secret_sealed)
    .bind(new.client_secret_key_version)
    .bind(new.registration_endpoint)
    .bind(new.registration_access_token_sealed)
    .bind(new.registration_access_token_key_version)
    .bind(new.token_endpoint_auth_method)
    .fetch_optional(exec)
    .await
}

/// Mark a registration reused this dance (`last_used_at`).
pub async fn touch_client_registration<'e, E>(exec: E, id: Uuid) -> sqlx::Result<()>
where
    E: sqlx::PgExecutor<'e>,
{
    sqlx::query("update oauth_client_registrations set last_used_at = now() where id = $1")
        .bind(id)
        .execute(exec)
        .await
        .map(|_| ())
}

/// Delete a registration whose client the AS rejected (`invalid_client` self-heal
/// at code exchange) so the next resolution mints a fresh one.
pub async fn delete_client_registration<'e, E>(exec: E, id: Uuid) -> sqlx::Result<()>
where
    E: sqlx::PgExecutor<'e>,
{
    sqlx::query("delete from oauth_client_registrations where id = $1")
        .bind(id)
        .execute(exec)
        .await
        .map(|_| ())
}

/// Stable 64-bit advisory-lock key for a registration's (issuer, redirect_uri) —
/// mirrors [`oauth_lock_key`]'s fold-leading-8-bytes construction, over a sha256
/// of `issuer‖NUL‖redirect_uri` (the NUL separator keeps `a‖bc` ≠ `ab‖c`).
pub fn registration_lock_key(issuer: &str, redirect_uri: &str) -> i64 {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(issuer.as_bytes());
    h.update([0u8]);
    h.update(redirect_uri.as_bytes());
    let d = h.finalize();
    i64::from_be_bytes([d[0], d[1], d[2], d[3], d[4], d[5], d[6], d[7]])
}

/// Take a transaction-scoped advisory lock on (issuer, redirect_uri) — serializes
/// DCR across connects (and replicas) so the first connect registers and later
/// ones reuse, yielding ONE `/register` per issuer. Releases when `tx` commits or
/// drops; the caller holds it across the find → DCR HTTP → insert window.
pub async fn acquire_registration_lock(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    issuer: &str,
    redirect_uri: &str,
) -> sqlx::Result<()> {
    sqlx::query("select pg_advisory_xact_lock($1)")
        .bind(registration_lock_key(issuer, redirect_uri))
        .execute(&mut **tx)
        .await?;
    Ok(())
}

// ─── Connector OAuth flows (Phase D Task 4, #32 — invariant 20) ─────────────
//
// One-time server-side OAuth state rows, browser-bound like login_flows /
// github_app_flows. Replaces the stateless AEAD `state` param. The claim/peek
// fns are PRE-AUTH — keyed by `state_hash` (the opaque random the AS echoes back
// as `state`), which is the row's OWN authenticator (the row IS the auth, like a
// webhook signature). They take no `TenantScope`: the callback has no principal
// (a browser redirect can't carry the API token), and the verified tenant rides
// out ON the returned row. This mirrors how `claim_login_flow` (identity.rs)
// takes a raw id rather than a scope, for the same bootstrap reason.

/// A one-time connector-OAuth-flow row. NOT `Serialize` — it carries sealed key
/// material (`pkce_verifier_sealed`) and one-time secrets' hashes; nothing here
/// ever reaches an API response.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct ConnectorOauthFlowRow {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub connection_id: Uuid,
    pub initiated_by_user_id: Option<Uuid>,
    pub state_hash: String,
    pub browser_hash: String,
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub metadata_digest: String,
    pub resource: String,
    pub redirect_uri: String,
    pub scopes: Value,
    pub challenge: String,
    pub challenge_method: String,
    pub client_registration_id: Option<Uuid>,
    pub client_id: String,
    pub pkce_verifier_sealed: Vec<u8>,
    pub pkce_verifier_key_version: i16,
    pub expected_generation: i32,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub consumed_at: Option<DateTime<Utc>>,
}

/// Values for a new flow row. The PKCE verifier is pre-sealed by the caller
/// (server owns the crypto); `ttl_secs` sets `expires_at = now() + ttl` DB-side so
/// the returned row's exact expiry seeds the boot token.
pub struct NewConnectorOauthFlow<'a> {
    pub connection_id: Uuid,
    pub initiated_by_user_id: Option<Uuid>,
    pub state_hash: &'a str,
    pub browser_hash: &'a str,
    pub issuer: &'a str,
    pub authorization_endpoint: &'a str,
    pub token_endpoint: &'a str,
    pub metadata_digest: &'a str,
    pub resource: &'a str,
    pub redirect_uri: &'a str,
    pub scopes: &'a Value,
    pub challenge: &'a str,
    pub challenge_method: &'a str,
    pub client_registration_id: Option<Uuid>,
    pub client_id: &'a str,
    pub pkce_verifier_sealed: &'a [u8],
    pub pkce_verifier_key_version: i16,
    pub expected_generation: i32,
    pub ttl_secs: i64,
}

/// Insert a one-time flow, returning the persisted row (its `id` + `expires_at`
/// seed the boot token). GC-on-insert (login_flows precedent) sweeps this tenant's
/// abandoned flows first — scoped to the inserting tenant so a per-request write
/// never touches another org's rows. Takes a `TenantScope` (the start principal's
/// verified tenant) which is stamped into `tenant_id` for the composite FK and a
/// future RLS `WITH CHECK`.
pub async fn insert_connector_oauth_flow(
    pool: &PgPool,
    scope: TenantScope,
    new: NewConnectorOauthFlow<'_>,
) -> sqlx::Result<ConnectorOauthFlowRow> {
    let mut tx = scoped_tx(pool, scope).await?;
    sqlx::query(
        "delete from connector_oauth_flows
         where tenant_id = $1
           and ((consumed_at is null and expires_at < now())
                or expires_at < now() - interval '7 days')",
    )
    .bind(scope.tenant_id())
    .execute(&mut *tx)
    .await?;
    let __rls_out = sqlx::query_as(
        "insert into connector_oauth_flows
           (id, tenant_id, connection_id, initiated_by_user_id, state_hash, browser_hash,
            issuer, authorization_endpoint, token_endpoint, metadata_digest, resource,
            redirect_uri, scopes, challenge, challenge_method, client_registration_id,
            client_id, pkce_verifier_sealed, pkce_verifier_key_version, expected_generation,
            expires_at)
         values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,
                 now() + make_interval(secs => $21::double precision))
         returning *",
    )
    .bind(Uuid::now_v7())
    .bind(scope.tenant_id())
    .bind(new.connection_id)
    .bind(new.initiated_by_user_id)
    .bind(new.state_hash)
    .bind(new.browser_hash)
    .bind(new.issuer)
    .bind(new.authorization_endpoint)
    .bind(new.token_endpoint)
    .bind(new.metadata_digest)
    .bind(new.resource)
    .bind(new.redirect_uri)
    .bind(new.scopes)
    .bind(new.challenge)
    .bind(new.challenge_method)
    .bind(new.client_registration_id)
    .bind(new.client_id)
    .bind(new.pkce_verifier_sealed)
    .bind(new.pkce_verifier_key_version)
    .bind(new.expected_generation)
    .bind(new.ttl_secs as f64)
    .fetch_one(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(__rls_out)
}

/// The one-time connector-OAuth-flow claim (invariant 20). Keyed by `state_hash`
/// (pre-auth — see the module note above). The cookie `browser_hash` sits INSIDE
/// the single-use predicate alongside `consumed_at is null` and `expires_at >
/// now()`: a leaked authorization URL WITHOUT the initiating browser's cookie
/// matches ZERO rows, so it can neither complete NOR burn the flow (design
/// :646-656). Returns the burned row on success.
pub async fn claim_connector_oauth_flow(
    pool: &PgPool,
    state_hash: &str,
    browser_hash: &str,
) -> sqlx::Result<Option<ConnectorOauthFlowRow>> {
    // Pre-auth credential-digest resolution (audited bypass): the go/callback legs
    // are UNAUTHENTICATED — the sealed `state` IS the auth — and this UPDATE is
    // keyed on the state/browser digests with NO principal until it resolves the
    // flow's tenant. It rides `worker_tx` for the same reason the tokens.rs
    // token-digest resolvers do (the credential IS the key). No caller supplies a
    // scope; changing the executor-generic parameter to `pool` is compatible
    // (every call site passed a bare `&PgPool`).
    let mut tx = worker_tx(pool).await?;
    let __rls_out = sqlx::query_as(
        "update connector_oauth_flows set consumed_at = now()
         where state_hash = $1 and browser_hash = $2
           and consumed_at is null and expires_at > now()
         returning *",
    )
    .bind(state_hash)
    .bind(browser_hash)
    .fetch_optional(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(__rls_out)
}

/// Read a flow by `state_hash` WITHOUT mutating it (never consumes). Two callers:
/// (1) the go page checks liveness before it sets the cookie + redirects, and
/// (2) the callback, ONLY after a failed claim, splits "wrong browser" (row still
/// live but the cookie hash mismatched → 403, row UNBURNED) from
/// "unknown/expired/consumed" (→ 400 generic). Pre-auth, keyed by `state_hash`.
pub async fn peek_connector_oauth_flow(
    pool: &PgPool,
    state_hash: &str,
) -> sqlx::Result<Option<ConnectorOauthFlowRow>> {
    // Pre-auth credential-digest resolution (audited bypass), keyed by `state_hash`
    // with no principal — see `claim_connector_oauth_flow`. Never mutates.
    let mut tx = worker_tx(pool).await?;
    let __rls_out = sqlx::query_as("select * from connector_oauth_flows where state_hash = $1")
        .bind(state_hash)
        .fetch_optional(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(__rls_out)
}

// ─── Cross-replica OAuth refresh serialization (K8s design 2026-07-15) ─────

/// Stable 64-bit advisory-lock key from a connection id. Postgres advisory
/// locks are keyed on `bigint`; we fold the uuid's leading 8 bytes.
pub fn oauth_lock_key(connection_id: Uuid) -> i64 {
    let b = connection_id.as_bytes();
    i64::from_be_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]])
}

/// Take a transaction-scoped Postgres advisory lock keyed on a connection id,
/// on `tx`. Serializes OAuth refresh-token rotation ACROSS control-plane
/// replicas (a second replica can no longer double-rotate a refresh token
/// into `invalid_grant`) — replacing reliance on the in-process mutex. The
/// lock releases automatically when `tx` is committed or dropped, so the
/// caller holds `tx` across the refresh HTTP round-trip and the rotation
/// write, then commits.
pub async fn acquire_oauth_lock(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    connection_id: Uuid,
) -> sqlx::Result<()> {
    sqlx::query("select pg_advisory_xact_lock($1)")
        .bind(oauth_lock_key(connection_id))
        .execute(&mut **tx)
        .await?;
    Ok(())
}
