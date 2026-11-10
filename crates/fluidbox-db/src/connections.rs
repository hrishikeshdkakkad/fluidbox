//! Integration connections: ownership, visibility, lifecycle, and the
//! sealed-credential readers.

use crate::scope::{scoped_tx, TenantScope};
use chrono::{DateTime, Utc};
use serde_json::Value;
use sqlx::{PgPool, Row};
use uuid::Uuid;

/// Who owns a connection (design :274-296). `Organization` connections are
/// visible to every member; `User` connections are one member's personal
/// custody. github_app connections are ALWAYS `Organization`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionOwner {
    Organization,
    User(Uuid),
}

impl ConnectionOwner {
    /// (owner_type, owner_user_id) as stamped into the row.
    fn parts(&self) -> (&'static str, Option<Uuid>) {
        match self {
            ConnectionOwner::Organization => ("organization", None),
            ConnectionOwner::User(id) => ("user", Some(*id)),
        }
    }
}

/// The visibility lens for a connection listing (design :274-296): `All` sees
/// every connection in the tenant (operator / admin); `User` sees org-owned
/// connections plus only its OWN personal connections.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionViewer {
    All,
    User(Uuid),
}

impl ConnectionViewer {
    /// The user id whose personal rows are visible, or None for `All` — bound
    /// into the `$n is null or owner_type='organization' or owner_user_id=$n`
    /// predicate.
    fn user_id(&self) -> Option<Uuid> {
        match self {
            ConnectionViewer::All => None,
            ConnectionViewer::User(id) => Some(*id),
        }
    }
}

/// Deliberately has NO credential fields: every query selects the explicit
/// `CONNECTION_COLS` list, so the sealed credential / client secret can
/// never ride along into an API response or log.
/// `connection_credential_sealed` / `connection_client_secret_sealed` are
/// the only readers. `oauth` carries NON-secret custody state (endpoints,
/// client identity, scopes, error note).
#[derive(Debug, Clone, sqlx::FromRow, serde::Serialize)]
pub struct IntegrationConnectionRow {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub provider: String,
    pub external_account_id: String,
    pub display_name: String,
    pub granted_scopes: Value,
    pub resource_selection: Value,
    pub status: String,
    pub metadata: Value,
    pub auth_kind: String,
    pub oauth: Option<Value>,
    /// Typed custody linkage for seamless github_app connections: the pem +
    /// webhook secret live on the registration. NULL = legacy per-connection
    /// custody. Resolution fails closed — never falls back across kinds.
    pub registration_id: Option<Uuid>,
    /// Ownership (design :274-296): `organization` (visible to every member) or
    /// `user` (one member's personal custody); `owner_user_id` is set iff
    /// `owner_type='user'`. `created_by_user_id` records who connected it (null
    /// for system/admin-created rows). `authorization_generation` bumps on every
    /// re-consent/rotation so stale run bindings fail closed.
    pub owner_type: String,
    pub owner_user_id: Option<Uuid>,
    pub created_by_user_id: Option<Uuid>,
    pub authorization_generation: i32,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

// ─── Integration connections ──────────────────────────────────────────────

/// Every connection query selects this explicit column list (never `*`) so
/// the sealed credential / client secret can't ride along into a row.
pub(crate) const CONNECTION_COLS: &str =
    "id, tenant_id, provider, external_account_id, display_name, \
     granted_scopes, resource_selection, status, metadata, auth_kind, oauth, \
     registration_id, owner_type, owner_user_id, created_by_user_id, \
     authorization_generation, created_at, updated_at";

/// Auth flavor of a new connection. `static` seals the pasted secret now and
/// starts `active`; `oauth` starts `pending` with NO credential — the
/// callback exchange activates it with the sealed rotating refresh token.
pub struct ConnectionAuth<'a> {
    pub auth_kind: &'a str, // static | oauth
    pub status: &'a str,    // active | pending | suspended
    pub oauth: Option<&'a Value>,
    pub client_secret_sealed: Option<&'a [u8]>,
    /// Envelope key-version companion for `client_secret_sealed` (1 legacy, 2
    /// v2). Ignored when `client_secret_sealed` is None.
    pub client_secret_key_version: i16,
    /// Set only by the seamless github_app flows (custody on the
    /// registration); legacy/manual connections leave it NULL.
    pub registration_id: Option<Uuid>,
}

impl ConnectionAuth<'static> {
    pub fn static_active() -> Self {
        Self {
            auth_kind: "static",
            status: "active",
            oauth: None,
            client_secret_sealed: None,
            client_secret_key_version: 1,
            registration_id: None,
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub async fn create_connection(
    pool: &PgPool,
    scope: TenantScope,
    provider: &str,
    external_account_id: &str,
    display_name: &str,
    credential_sealed: Option<&[u8]>,
    credential_key_version: i16,
    granted_scopes: &Value,
    resource_selection: &Value,
    metadata: &Value,
    webhook_secret_sealed: Option<&[u8]>,
    webhook_secret_key_version: i16,
    auth: ConnectionAuth<'_>,
    owner: ConnectionOwner,
    created_by_user_id: Option<Uuid>,
) -> sqlx::Result<IntegrationConnectionRow> {
    let mut tx = scoped_tx(pool, scope).await?;

    // owner_type/owner_user_id are stamped from `owner`; authorization_generation
    // starts at 1 (the column default) and bumps only on re-consent/rotation.
    // The `_key_version` companions ride beside each sealed column (1 legacy, 2
    // v2 envelope) so the reader can dispatch on open.
    let (owner_type, owner_user_id) = owner.parts();
    let __rls_out = sqlx::query_as(sqlx::AssertSqlSafe(format!(
        "insert into integration_connections
           (id, tenant_id, provider, external_account_id, display_name, credential_sealed,
            granted_scopes, resource_selection, metadata, webhook_secret_sealed,
            auth_kind, status, oauth, client_secret_sealed, registration_id,
            owner_type, owner_user_id, created_by_user_id,
            credential_key_version, webhook_secret_key_version, client_secret_key_version)
         values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21)
         returning {CONNECTION_COLS}"
    )))
    .bind(Uuid::now_v7())
    .bind(scope.tenant_id())
    .bind(provider)
    .bind(external_account_id)
    .bind(display_name)
    .bind(credential_sealed)
    .bind(granted_scopes)
    .bind(resource_selection)
    .bind(metadata)
    .bind(webhook_secret_sealed)
    .bind(auth.auth_kind)
    .bind(auth.status)
    .bind(auth.oauth)
    .bind(auth.client_secret_sealed)
    .bind(auth.registration_id)
    .bind(owner_type)
    .bind(owner_user_id)
    .bind(created_by_user_id)
    .bind(credential_key_version)
    .bind(webhook_secret_key_version)
    .bind(auth.client_secret_key_version)
    .fetch_one(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(__rls_out)
}

pub async fn list_connections(
    pool: &PgPool,
    scope: TenantScope,
) -> sqlx::Result<Vec<IntegrationConnectionRow>> {
    let mut tx = scoped_tx(pool, scope).await?;

    let __rls_out = sqlx::query_as(sqlx::AssertSqlSafe(format!(
        "select {CONNECTION_COLS} from integration_connections
         where tenant_id = $1 order by created_at desc"
    )))
    .bind(scope.tenant_id())
    .fetch_all(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(__rls_out)
}

// Executor-generic so a caller holding the per-connection OAuth advisory lock
// can re-read THROUGH its own transaction (`&mut *tx`) instead of borrowing a
// SECOND pooled connection — the latter deadlocks the fixed-size pool under
// concurrent refreshes/callbacks. Existing `&PgPool` call sites are unchanged
// (`&PgPool: PgExecutor`).
pub async fn get_connection<'e, E>(
    exec: E,
    scope: TenantScope,
    id: Uuid,
) -> sqlx::Result<Option<IntegrationConnectionRow>>
where
    E: sqlx::PgExecutor<'e>,
{
    sqlx::query_as(sqlx::AssertSqlSafe(format!(
        "select {CONNECTION_COLS} from integration_connections where id = $1 and tenant_id = $2"
    )))
    .bind(id)
    .bind(scope.tenant_id())
    .fetch_optional(exec)
    .await
}

pub async fn revoke_connection(
    pool: &PgPool,
    scope: TenantScope,
    id: Uuid,
) -> sqlx::Result<Option<IntegrationConnectionRow>> {
    let mut tx = scoped_tx(pool, scope).await?;

    let __rls_out = sqlx::query_as(sqlx::AssertSqlSafe(format!(
        "update integration_connections set status = 'revoked', updated_at = now()
         where id = $1 and status <> 'revoked' and tenant_id = $2
         returning {CONNECTION_COLS}"
    )))
    .bind(id)
    .bind(scope.tenant_id())
    .fetch_optional(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(__rls_out)
}

/// List connections through a visibility lens (design :274-296): `All` returns
/// every connection in the tenant; `User(id)` returns org-owned connections
/// plus only that user's personal connections. `list_connections` stays the
/// unfiltered internal/worker reader.
pub async fn list_connections_visible(
    pool: &PgPool,
    scope: TenantScope,
    viewer: ConnectionViewer,
) -> sqlx::Result<Vec<IntegrationConnectionRow>> {
    let mut tx = scoped_tx(pool, scope).await?;

    let __rls_out = sqlx::query_as(sqlx::AssertSqlSafe(format!(
        "select {CONNECTION_COLS} from integration_connections
         where tenant_id = $1
           and ($2::uuid is null or owner_type = 'organization' or owner_user_id = $2)
         order by created_at desc"
    )))
    .bind(scope.tenant_id())
    .bind(viewer.user_id())
    .fetch_all(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(__rls_out)
}

/// Read one connection through the same visibility lens as
/// [`list_connections_visible`] — returns None for another user's personal row.
pub async fn get_connection_visible(
    pool: &PgPool,
    scope: TenantScope,
    id: Uuid,
    viewer: ConnectionViewer,
) -> sqlx::Result<Option<IntegrationConnectionRow>> {
    let mut tx = scoped_tx(pool, scope).await?;

    let __rls_out = sqlx::query_as(sqlx::AssertSqlSafe(format!(
        "select {CONNECTION_COLS} from integration_connections
         where id = $1 and tenant_id = $2
           and ($3::uuid is null or owner_type = 'organization' or owner_user_id = $3)"
    )))
    .bind(id)
    .bind(scope.tenant_id())
    .bind(viewer.user_id())
    .fetch_optional(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(__rls_out)
}

/// Bump a connection's authorization generation (design :296) — called on every
/// re-consent/rotation so any run binding that froze the older generation fails
/// closed at the broker recheck. Returns the new generation, or None if the
/// connection is not in scope.
pub async fn bump_connection_generation(
    pool: &PgPool,
    scope: TenantScope,
    id: Uuid,
) -> sqlx::Result<Option<i32>> {
    let mut tx = scoped_tx(pool, scope).await?;
    let row = sqlx::query(
        "update integration_connections
         set authorization_generation = authorization_generation + 1, updated_at = now()
         where id = $1 and tenant_id = $2
         returning authorization_generation",
    )
    .bind(id)
    .bind(scope.tenant_id())
    .fetch_optional(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(row.map(|r| r.get::<i32, _>("authorization_generation")))
}

/// Persist non-secret OAuth custody state (discovered endpoints, client
/// identity, pending bundle) before the connection is activated.
///
/// **Executor-generic on purpose, and the production caller MUST pass a
/// transaction that already holds this connection's OAuth advisory lock**
/// (`oauth::commit_start_epoch` — see `acquire_oauth_lock`). This write is the
/// tail of a read-modify-write that spans seconds of outbound discovery HTTP:
/// the bag it lands was assembled from a read taken BEFORE that HTTP, so it may
/// only be committed once the caller has proven — under the same lock the
/// activation path takes — that nothing re-authorized the connection meanwhile.
/// Riding the caller's lock-holding transaction makes the proof and the write
/// ONE atomic step. A standalone round trip on `&PgPool` (what this used to be)
/// leaves a window in which a SUPERSEDED start clobbers the winner's token
/// endpoint / client identity, so its refresh would authenticate to the wrong
/// endpoint under the wrong client (review #32).
///
/// The caller's bag REPLACES the stored one — except for
/// [`ACTIVATED_AT_KEY`], which is carried over unconditionally. That stamp is
/// owned by [`activate_connection_oauth`] and is half of its compare-and-swap
/// (review H2): an activation landing in the read-modify-write window would
/// otherwise have its stamp erased by a stale bag — handing a superseded sibling
/// flow a passing expectation. Belt-and-braces now that the write rides the
/// lock, and the only protection left for any caller that does not.
pub async fn update_connection_oauth<'e, E>(
    exec: E,
    scope: TenantScope,
    id: Uuid,
    oauth: &Value,
) -> sqlx::Result<()>
where
    E: sqlx::PgExecutor<'e>,
{
    sqlx::query(sqlx::AssertSqlSafe(format!(
        "update integration_connections
         set oauth = case
                 when jsonb_typeof($2::jsonb) = 'object'
                      and (oauth -> '{ACTIVATED_AT_KEY}') is not null
                 then jsonb_set($2::jsonb, '{{{ACTIVATED_AT_KEY}}}',
                                oauth -> '{ACTIVATED_AT_KEY}')
                 else $2::jsonb end,
             updated_at = now()
         where id = $1 and status <> 'revoked' and tenant_id = $3"
    )))
    .bind(id)
    .bind(oauth)
    .bind(scope.tenant_id())
    .execute(exec)
    .await?;
    Ok(())
}

/// The callback exchange completing: seal the rotating refresh token into
/// `credential_sealed` (the SAME custody column static bearers use), flip the
/// connection live, and — atomically in the SAME UPDATE — bump the authorization
/// generation on a RECONNECT (a re-consent from any non-`pending` status: the
/// account/issuer/audience may have changed, so any in-flight run bound to the
/// old generation must fail closed; design :294-296). The bump is decided from
/// the row's PRE-UPDATE `status` INSIDE the SET (`status <> 'pending'`) — under
/// the row lock the SET reads the OLD status, which IS the prior status at commit
/// time. This is deliberately NOT a caller-supplied boolean (B1): two first-
/// connect callbacks both reading `pending` before serializing on the oauth lock
/// would each pass `bump=false`; the second must still bump because by the time
/// it holds the lock the row is already `active`. First connect (from `pending`)
/// ⇒ no bump; reconnect (from `active`/`error`) ⇒ bump — all in ONE write, so no
/// crash window where a reconnected grant serves the OLD generation. The returned
/// row carries the FINAL generation the caller caches under.
///
/// **THE ACTIVATION IS A COMPARE-AND-SWAP** (Phase D review H2). The callback's
/// pre-exchange generation recheck is an optimization that avoids burning a code;
/// it is NOT the boundary, because the code exchange is a full HTTP round trip
/// during which a sibling flow can activate. TWO predicates make the write itself
/// the boundary, both frozen at the flow's START:
///   - `authorization_generation = expected_generation` — the flow row's frozen
///     generation. A sibling RECONNECT that landed first moved it, so the loser
///     matches zero rows instead of overwriting the newer refresh token.
///   - `activated_at < flow_started_at` — the connection's own last-activation
///     instant (stamped by this UPDATE, DB clock, never caller-supplied) against
///     the flow row's `created_at`. This is what covers FIRST connect, where the
///     `pending → active` activation deliberately does NOT bump the generation:
///     two callbacks racing on the same pending row both froze the same
///     generation, so the generation predicate alone cannot separate them. Every
///     successful activation stamps an instant strictly later than every
///     in-flight flow's `created_at`, so ONE activation invalidates every sibling
///     flow's expectation — including its own siblings' retries.
///
/// `None` therefore means "superseded / no longer activatable" (revoked, wrong
/// auth_kind, reauthorized, or already activated since this flow started); the
/// caller must tell the user to restart the connect flow, never retry blindly.
///
/// `activated_at` lives inside the `oauth` jsonb bag rather than its own column
/// because this wave may not add migrations; the bag is rewritten here from the
/// caller's value, so the stamp is applied SQL-side (`jsonb_set` +
/// `clock_timestamp()`) and cannot be forged or dropped by the caller.
// Executor-generic (see `get_connection`): the callback activation runs THROUGH
// the connection that holds the OAuth advisory lock, so the critical section
// uses exactly one pooled connection.
#[allow(clippy::too_many_arguments)]
pub async fn activate_connection_oauth<'e, E>(
    exec: E,
    scope: TenantScope,
    id: Uuid,
    sealed_refresh: &[u8],
    key_version: i16,
    oauth: &Value,
    granted_scopes: &Value,
    expected_generation: i32,
    flow_started_at: DateTime<Utc>,
) -> sqlx::Result<Option<IntegrationConnectionRow>>
where
    E: sqlx::PgExecutor<'e>,
{
    sqlx::query_as(sqlx::AssertSqlSafe(format!(
        "update integration_connections
         set credential_sealed = $2, credential_key_version = $6, granted_scopes = $4,
             oauth = jsonb_set(
                 case when jsonb_typeof($3::jsonb) = 'object' then $3::jsonb else '{{}}'::jsonb end,
                 '{{{ACTIVATED_AT_KEY}}}', to_jsonb(clock_timestamp())),
             status = 'active',
             authorization_generation =
                 authorization_generation + case when status <> 'pending' then 1 else 0 end,
             updated_at = now()
         where id = $1 and status <> 'revoked' and auth_kind = 'oauth' and tenant_id = $5
           and authorization_generation = $7
           and coalesce((oauth ->> '{ACTIVATED_AT_KEY}')::timestamptz, '-infinity'::timestamptz)
               < $8
         returning {CONNECTION_COLS}"
    )))
    .bind(id)
    .bind(sealed_refresh)
    .bind(oauth)
    .bind(granted_scopes)
    .bind(scope.tenant_id())
    .bind(key_version)
    .bind(expected_generation)
    .bind(flow_started_at)
    .fetch_optional(exec)
    .await
}

/// The `oauth` jsonb key carrying the connection's last successful OAuth
/// activation instant (DB clock). Written ONLY by [`activate_connection_oauth`],
/// read by its CAS predicate and by the callback's pre-exchange fast refusal.
pub const ACTIVATED_AT_KEY: &str = "activated_at";

/// Refresh-token rotation: one atomic overwrite (OAuth 2.1 MUST — old token
/// is gone the moment the new one lands). Active connections only, and ONLY
/// while the connection is still at `expected_generation` — a concurrent
/// reconnect that bumped the generation (and landed a NEW refresh token) must
/// NOT be clobbered by an in-flight refresh rotating the OLD grant's token
/// (that would restore a superseded grant). Returns false when the row was
/// revoked/errored OR reauthorized (generation moved) underneath the caller;
/// the refresh path treats a false as a stale mint and fails closed.
pub async fn rotate_connection_refresh<'e, E>(
    exec: E,
    scope: TenantScope,
    id: Uuid,
    sealed_new: &[u8],
    key_version: i16,
    expected_generation: i32,
) -> sqlx::Result<bool>
where
    E: sqlx::PgExecutor<'e>,
{
    let r = sqlx::query(
        "update integration_connections
         set credential_sealed = $2, credential_key_version = $5, updated_at = now()
         where id = $1 and status = 'active' and auth_kind = 'oauth' and tenant_id = $3
           and authorization_generation = $4",
    )
    .bind(id)
    .bind(sealed_new)
    .bind(scope.tenant_id())
    .bind(expected_generation)
    .bind(key_version)
    .execute(exec)
    .await?;
    Ok(r.rows_affected() == 1)
}

/// `invalid_grant`-class failure: the refresh token is dead, the connection
/// needs human re-consent. Everything downstream fails closed off the
/// status: `connection_credential_sealed` stops returning, run creation
/// refuses, the broker surfaces "reconnect".
pub async fn mark_connection_error<'e, E>(
    exec: E,
    scope: TenantScope,
    id: Uuid,
    note: &str,
) -> sqlx::Result<()>
where
    E: sqlx::PgExecutor<'e>,
{
    sqlx::query(
        "update integration_connections
         set status = 'error', updated_at = now(),
             oauth = jsonb_set(coalesce(oauth, '{}'::jsonb), '{error}', to_jsonb($2::text))
         where id = $1 and status = 'active' and tenant_id = $3",
    )
    .bind(id)
    .bind(note)
    .bind(scope.tenant_id())
    .execute(exec)
    .await
    .map(|_| ())
}

// (`set_connection_client_secret` retired in Phase D Task 3 (#32): DCR client
// secrets now live on the shared `oauth_client_registrations` row, not the
// connection. Pre-registered confidential secrets are still written per-connection
// at CREATE time via `ConnectionAuth.client_secret_sealed`, and read below.)

/// The only reader of the sealed client secret (confidential OAuth clients).
/// Client identity outlives token state — the dance needs it while the row
/// is still pending (first exchange) or errored (reconnect) — so any
/// non-revoked status qualifies.
pub async fn connection_client_secret_sealed<'e, E>(
    exec: E,
    scope: TenantScope,
    id: Uuid,
) -> sqlx::Result<Option<(Vec<u8>, i16)>>
where
    E: sqlx::PgExecutor<'e>,
{
    let row = sqlx::query(
        "select client_secret_sealed, client_secret_key_version from integration_connections
         where id = $1 and status <> 'revoked' and tenant_id = $2",
    )
    .bind(id)
    .bind(scope.tenant_id())
    .fetch_optional(exec)
    .await?;
    Ok(row.and_then(|r| {
        r.get::<Option<Vec<u8>>, _>("client_secret_sealed")
            .map(|b| (b, r.get::<i16, _>("client_secret_key_version")))
    }))
}

/// The only reader of the sealed credential. Returns None unless the
/// connection exists AND is active — a revoked connection can never again
/// produce a credential.
pub async fn connection_credential_sealed<'e, E>(
    exec: E,
    scope: TenantScope,
    id: Uuid,
) -> sqlx::Result<Option<(Vec<u8>, i16)>>
where
    E: sqlx::PgExecutor<'e>,
{
    let row = sqlx::query(
        "select credential_sealed, credential_key_version from integration_connections
         where id = $1 and status = 'active' and tenant_id = $2",
    )
    .bind(id)
    .bind(scope.tenant_id())
    .fetch_optional(exec)
    .await?;
    Ok(row.and_then(|r| {
        r.get::<Option<Vec<u8>>, _>("credential_sealed")
            .map(|b| (b, r.get::<i16, _>("credential_key_version")))
    }))
}

/// The only reader of the sealed webhook secret (verified on every ingress
/// request). Active connections only — a revoked connection stops receiving.
pub async fn connection_webhook_secret_sealed(
    pool: &PgPool,
    scope: TenantScope,
    id: Uuid,
) -> sqlx::Result<Option<(Vec<u8>, i16)>> {
    let mut tx = scoped_tx(pool, scope).await?;
    let row = sqlx::query(
        "select webhook_secret_sealed, webhook_secret_key_version from integration_connections
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

/// Guarded status transition: only fires when the current status is one of
/// `allowed_from`. Returns the fresh row on success.
pub async fn set_connection_status(
    pool: &PgPool,
    scope: TenantScope,
    id: Uuid,
    status: &str,
    allowed_from: &[&str],
) -> sqlx::Result<Option<IntegrationConnectionRow>> {
    let mut tx = scoped_tx(pool, scope).await?;

    let from: Vec<String> = allowed_from.iter().map(|s| s.to_string()).collect();
    let __rls_out = sqlx::query_as(sqlx::AssertSqlSafe(format!(
        "update integration_connections set status = $2, updated_at = now()
         where id = $1 and status = any($3) and tenant_id = $4
         returning {CONNECTION_COLS}"
    )))
    .bind(id)
    .bind(status)
    .bind(&from)
    .bind(scope.tenant_id())
    .fetch_optional(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(__rls_out)
}

/// Refresh the display metadata a setup/sync re-verification produced.
pub async fn refresh_connection_metadata(
    pool: &PgPool,
    scope: TenantScope,
    id: Uuid,
    display_name: &str,
    metadata: &Value,
) -> sqlx::Result<()> {
    let mut tx = scoped_tx(pool, scope).await?;

    sqlx::query(
        "update integration_connections
         set display_name = $2, metadata = $3, updated_at = now()
         where id = $1 and status <> 'revoked' and tenant_id = $4",
    )
    .bind(id)
    .bind(display_name)
    .bind(metadata)
    .bind(scope.tenant_id())
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(())
}
