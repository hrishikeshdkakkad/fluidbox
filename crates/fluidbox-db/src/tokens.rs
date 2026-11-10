//! `api_tokens`: session tokens, trigger tokens, and the digest both are stored as.

use crate::scope::{scoped_tx, worker_tx, TenantScope};
use sqlx::{PgPool, Row};
use uuid::Uuid;

pub fn sha256_hex(s: &str) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(Sha256::digest(s.as_bytes()))
}

// ─── Tokens ───────────────────────────────────────────────────────────────

/// Mint one audience-scoped session token (Gap 10, invariant 19). `audience` is
/// one of `control|tool|llm|workspace` (or `all` for a legacy single token) and
/// is enforced per-route by the auth extractors. A run mints FOUR of these, one
/// per audience, all sharing the `fbx_sess_` prefix (the Redactor scrubs by
/// prefix, so all four are covered).
pub async fn create_session_token(
    pool: &PgPool,
    scope: TenantScope,
    session: Uuid,
    token_plain: &str,
    ttl_secs: i64,
    audience: &str,
) -> sqlx::Result<()> {
    let mut tx = scoped_tx(pool, scope).await?;
    sqlx::query(
        "insert into api_tokens (id, tenant_id, kind, session_id, token_sha256, expires_at, audience)
         values ($1, $2, 'session', $3, $4, now() + make_interval(secs => $5), $6)",
    )
    .bind(Uuid::now_v7())
    .bind(scope.tenant_id())
    .bind(session)
    .bind(sha256_hex(token_plain))
    .bind(ttl_secs as f64)
    .bind(audience)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(())
}

/// What resolving a session token yields: the session it belongs to AND its
/// owning tenant. The tenant rides the credential so the caller (auth
/// extractor / facade / `/result`) can build a `TenantScope` without a second
/// query — the "bootstrap exception" pattern (token resolution keys purely on
/// the sha256, then hands back a verified tenant).
#[derive(Debug, Clone)]
pub struct SessionTokenAuth {
    pub session_id: Uuid,
    pub tenant_id: Uuid,
    /// Which routes this token opens (Gap 10): `control|tool|llm|workspace`, or
    /// the legacy `all` (pre-split tokens + e2e forgers via the column DEFAULT).
    /// The caller enforces it per-route (auth.rs `audience_allows`).
    pub audience: String,
    /// The workload identity this run's credentials were issued to (Gap 6, Phase F;
    /// `sessions.workload_addrs`, migration 0025) — the provider-reported source
    /// addresses of the sandbox. Carried on the CREDENTIAL so the internal gateway
    /// can check the socket peer without a second query: `/events` is the one
    /// internal route that never loads the session row, and a per-request query
    /// added only there would be a per-event round trip on the hottest path we
    /// have. Empty = unbindable (no provider-asserted identity, or a pre-0025 row).
    pub workload_addrs: Vec<String>,
}

/// Resolve a session token to its session IGNORING revoked_at/expiry — used
/// ONLY by /result to acknowledge an already-terminal session whose token was
/// revoked on the terminal transition (so a lost-response retry acks cleanly).
/// Every other endpoint uses the strict `session_for_token`. A completely
/// bogus token still returns None; a real token resolves to its own session,
/// and the caller gates the ack on that session being terminal.
pub async fn session_for_token_incl_revoked(
    pool: &PgPool,
    token_plain: &str,
) -> sqlx::Result<Option<SessionTokenAuth>> {
    // Credential-digest bootstrap resolution: keyed purely on the token sha256, with
    // NO tenant scope (the caller has no principal until this resolves the tenant).
    // Rides the audited bypass so api_tokens is visible across tenants — the digest
    // IS the credential (documented TenantScope bootstrap exception).
    let mut tx = worker_tx(pool).await?;
    let row = sqlx::query(
        "select t.session_id, t.tenant_id, t.audience, s.workload_addrs
           from api_tokens t
           left join sessions s on s.id = t.session_id
          where t.kind = 'session' and t.token_sha256 = $1",
    )
    .bind(sha256_hex(token_plain))
    .fetch_optional(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(row.and_then(session_token_auth))
}

/// Shape one resolved `api_tokens` row (joined to its session) into
/// [`SessionTokenAuth`]. Shared by the strict and lenient resolvers so the two
/// can never drift on which columns they carry — the Gap-6 `workload_addrs` in
/// particular must ride BOTH, since `/result` uses the lenient one and is a
/// terminalizing route.
fn session_token_auth(r: sqlx::postgres::PgRow) -> Option<SessionTokenAuth> {
    r.get::<Option<Uuid>, _>("session_id")
        .map(|session_id| SessionTokenAuth {
            session_id,
            tenant_id: r.get::<Uuid, _>("tenant_id"),
            audience: r.get::<String, _>("audience"),
            // NULL (no provider-asserted identity, or a pre-0025 row) flattens to
            // the empty vec — the caller's "unbindable" case.
            workload_addrs: r
                .get::<Option<Vec<String>>, _>("workload_addrs")
                .unwrap_or_default(),
        })
}

/// Returns the session (and its tenant + audience) a valid (unexpired,
/// unrevoked) token belongs to.
pub async fn session_for_token(
    pool: &PgPool,
    token_plain: &str,
) -> sqlx::Result<Option<SessionTokenAuth>> {
    // Credential-digest bootstrap resolution (audited bypass) — see
    // `session_for_token_incl_revoked`.
    let mut tx = worker_tx(pool).await?;
    // Gap 6 (Phase F): the LEFT JOIN carries `sessions.workload_addrs` on the SAME
    // statement that was already resolving the credential. Cost is one extra
    // primary-key index probe inside an existing round trip — no new query, and no
    // per-request query added to `/events` (the one internal route that never
    // loads the session row). LEFT, not INNER: a session-less `api_tokens` row must
    // still resolve exactly as it did before, and be discarded by the same
    // `session_id`-is-null test.
    let row = sqlx::query(
        "select t.session_id, t.tenant_id, t.audience, s.workload_addrs
           from api_tokens t
           left join sessions s on s.id = t.session_id
          where t.kind = 'session' and t.token_sha256 = $1
            and t.revoked_at is null
            and (t.expires_at is null or t.expires_at > now())",
    )
    .bind(sha256_hex(token_plain))
    .fetch_optional(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(row.and_then(session_token_auth))
}

/// Record the Gap-6 workload identity for a run (Phase F; migration 0025): the
/// provider-reported source addresses of the sandbox that this session's four
/// credentials were issued to. Written once, on the provisioning path, from data
/// the provider already held.
///
/// Deliberately NOT folded into `set_sandbox_handle`: the address is a SECURITY
/// fact with its own column and its own guard, and keeping the write explicit is
/// what lets the orchestrator order it BEFORE the handle attach (closing as much
/// of the "workload is running but its identity is not yet recorded" window as a
/// post-hoc capture can — see the call site).
///
/// Unconditional within the tenant: no status predicate, and a later write wins.
/// A workload that reports a NEW address (a reprovision) must be able to replace
/// the stale one, and refusing the write on a winding-down session would leave a
/// row whose recorded identity is a lie. Returns whether a row was touched.
pub async fn set_workload_addrs(
    pool: &PgPool,
    scope: TenantScope,
    id: Uuid,
    addrs: &[String],
) -> sqlx::Result<bool> {
    let mut tx = scoped_tx(pool, scope).await?;
    let res = sqlx::query(
        "update sessions set workload_addrs = $2, updated_at = now()
          where id = $1 and tenant_id = $3",
    )
    .bind(id)
    .bind(addrs)
    .bind(scope.tenant_id())
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(res.rows_affected() == 1)
}

/// Renew a session's tokens ahead of expiry. Gap 10 renewal contract: ONE renew
/// call (the runner presents its `control` token) extends EVERY live token for
/// that session — all four audiences move together in a single statement, so the
/// four never drift apart and the runner keeps one renew loop. Resolves the
/// session from the presented (unrevoked) token's digest, then bumps expiry on
/// all of that session's unrevoked session-kind rows. A revoked/bogus token
/// resolves no session ⇒ zero rows ⇒ `false` (never resurrects a revoked set).
pub async fn extend_session_token(
    pool: &PgPool,
    token_plain: &str,
    ttl_secs: i64,
) -> sqlx::Result<bool> {
    // Keyed on the token digest with no principal scope — audited bypass, like the
    // session-token resolvers above.
    let mut tx = worker_tx(pool).await?;
    let res = sqlx::query(
        "update api_tokens set expires_at = now() + make_interval(secs => $2)
         where kind = 'session' and revoked_at is null
           and session_id in (
             select session_id from api_tokens
              where kind = 'session' and token_sha256 = $1 and revoked_at is null
           )",
    )
    .bind(sha256_hex(token_plain))
    .bind(ttl_secs as f64)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(res.rows_affected() > 0)
}

/// Revoke every live session token for a session — called when the session
/// enters a terminal state so a still-running or wedged runner can no longer
/// authenticate to the facade or internal gateway (defense in depth beyond
/// the facade's own terminal-session refusal).
pub async fn revoke_session_tokens(
    pool: &PgPool,
    scope: TenantScope,
    session: Uuid,
) -> sqlx::Result<u64> {
    let mut tx = scoped_tx(pool, scope).await?;
    let res = sqlx::query(
        "update api_tokens set revoked_at = now()
         where kind = 'session' and session_id = $1 and revoked_at is null
           and exists (select 1 from sessions s where s.id = $1 and s.tenant_id = $2)",
    )
    .bind(session)
    .bind(scope.tenant_id())
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(res.rows_affected())
}

pub async fn create_trigger_token(
    pool: &PgPool,
    scope: TenantScope,
    subscription: Uuid,
    token_plain: &str,
) -> sqlx::Result<()> {
    let mut tx = scoped_tx(pool, scope).await?;
    create_trigger_token_tx(&mut tx, scope.tenant_id(), subscription, token_plain).await?;
    tx.commit().await?;
    Ok(())
}

/// [`create_trigger_token`] inside a caller-owned transaction (the recipes
/// deploy engine mints each stamped subscription's token in the same atomic
/// stamp; the plaintext is returned once, in the deploy response).
pub async fn create_trigger_token_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    tenant_id: Uuid,
    subscription: Uuid,
    token_plain: &str,
) -> sqlx::Result<()> {
    sqlx::query(
        "insert into api_tokens (id, tenant_id, kind, subscription_id, token_sha256)
         values ($1, $2, 'trigger', $3, $4)",
    )
    .bind(Uuid::now_v7())
    .bind(tenant_id)
    .bind(subscription)
    .bind(sha256_hex(token_plain))
    .execute(&mut **tx)
    .await?;
    Ok(())
}

/// What resolving a trigger token yields: the token row's id (the exact
/// invoking principal a trigger run freezes — design "The exact trigger token ID
/// is stored on each invocation"), the subscription it may invoke, AND its owning
/// tenant (the "bootstrap exception" pattern — keys on the sha256, hands back a
/// verified tenant).
#[derive(Debug, Clone, Copy)]
pub struct TriggerTokenAuth {
    pub token_id: Uuid,
    pub subscription_id: Uuid,
    pub tenant_id: Uuid,
}

/// Resolves a scoped trigger token to its id + subscription (and tenant). This is
/// the entire authority of the token — it can never satisfy Admin or
/// SessionAuth.
pub async fn subscription_for_token(
    pool: &PgPool,
    token_plain: &str,
) -> sqlx::Result<Option<TriggerTokenAuth>> {
    // Credential-digest bootstrap resolution (audited bypass): the trigger token's
    // sha256 is the only key; the verified tenant rides out on the returned row.
    let mut tx = worker_tx(pool).await?;
    let row = sqlx::query(
        "select id, subscription_id, tenant_id from api_tokens
         where kind = 'trigger' and token_sha256 = $1
           and revoked_at is null
           and (expires_at is null or expires_at > now())",
    )
    .bind(sha256_hex(token_plain))
    .fetch_optional(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(row.and_then(|r| {
        r.get::<Option<Uuid>, _>("subscription_id")
            .map(|subscription_id| TriggerTokenAuth {
                token_id: r.get::<Uuid, _>("id"),
                subscription_id,
                tenant_id: r.get::<Uuid, _>("tenant_id"),
            })
    }))
}

/// Revocation recheck for a trigger-invoked run's frozen principal (design
/// :741/:748, invariant R2.2): the exact api_tokens row the run froze must still
/// exist, be a live trigger token (not revoked, not expired), and JOIN to a
/// subscription that still exists and is ENABLED. The token is subscription-
/// scoped by an immutable FK, so its subscription IS the run's subscription —
/// "still belongs to the run's subscription" is verified by that JOIN. Scoped to
/// the tenant on both rows. Returns false on any drift (fail closed).
pub async fn trigger_token_active(
    pool: &PgPool,
    scope: TenantScope,
    token_id: Uuid,
) -> sqlx::Result<bool> {
    let mut tx = scoped_tx(pool, scope).await?;
    let row = sqlx::query(
        "select exists (
             select 1
               from api_tokens t
               join trigger_subscriptions s
                 on s.id = t.subscription_id and s.tenant_id = t.tenant_id
              where t.id = $1 and t.tenant_id = $2 and t.kind = 'trigger'
                and t.revoked_at is null
                and (t.expires_at is null or t.expires_at > now())
                and s.enabled
         ) as ok",
    )
    .bind(token_id)
    .bind(scope.tenant_id())
    .fetch_one(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(row.get::<bool, _>("ok"))
}

/// Rotation support: kill every live token for the subscription.
pub async fn revoke_trigger_tokens(
    pool: &PgPool,
    scope: TenantScope,
    subscription: Uuid,
) -> sqlx::Result<u64> {
    let mut tx = scoped_tx(pool, scope).await?;
    let res = sqlx::query(
        "update api_tokens set revoked_at = now()
         where kind = 'trigger' and subscription_id = $1 and revoked_at is null
           and exists (select 1 from trigger_subscriptions sub
                       where sub.id = $1 and sub.tenant_id = $2)",
    )
    .bind(subscription)
    .bind(scope.tenant_id())
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(res.rows_affected())
}
