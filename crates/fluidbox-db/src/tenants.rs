//! The tenant row and the per-tenant key material hanging off it.

use crate::scope::{scoped_tx, worker_tx, TenantScope};
use chrono::{DateTime, Utc};
use sqlx::{PgPool, Row};
use uuid::Uuid;

// ─── Tenants ──────────────────────────────────────────────────────────────

pub async fn ensure_default_tenant(pool: &PgPool) -> sqlx::Result<Uuid> {
    let id = Uuid::now_v7();
    // Boot bootstrap under the audited bypass: this writes/updates the `tenants`
    // registry ITSELF — possibly a pre-existing 'default' of unknown id via ON
    // CONFLICT (name) — so there is no tenant scope to key on, and the tenants RLS
    // policy's WITH CHECK would otherwise refuse the insert. The row IS the tenant.
    let mut tx = worker_tx(pool).await?;
    // Migration 0012 made `slug` NOT NULL; the boot tenant owns slug 'default'.
    // On a live DB the migration backfilled it already — this keeps a fresh DB
    // and any hand-edited row converged.
    let row = sqlx::query(
        "insert into tenants (id, name, slug) values ($1, 'default', 'default')
         on conflict (name) do update set slug = excluded.slug
         returning id",
    )
    .bind(id)
    .fetch_one(&mut *tx)
    .await?;
    let out = row.get("id");
    tx.commit().await?;
    Ok(out)
}

// ─── Per-tenant DEKs (Phase D envelope sealing, #32) ────────────────────────

/// One wrapped Data Encryption Key per `(tenant, version)`. `wrapped_dek` is the
/// DEK sealed by a KEK backend — NEVER the raw key. Not `Serialize`: it carries
/// wrapped key material. Keyed by a raw `tenant_id` (not a `TenantScope`): the
/// DEK orchestration in `kms::dek_for_seal`/`dek_for_open` already holds a
/// verified tenant from a `SealCtx`, and these are single-row keyed reads, not
/// cross-tenant scans.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct TenantDekRow {
    pub tenant_id: Uuid,
    pub version: i32,
    pub kek_id: String,
    pub wrapped_dek: Vec<u8>,
    pub created_at: DateTime<Utc>,
    pub retired_at: Option<DateTime<Utc>>,
}

/// Read one tenant's DEK at a specific version (`None` if never minted).
pub async fn get_tenant_dek<'e, E>(
    exec: E,
    tenant_id: Uuid,
    version: i32,
) -> sqlx::Result<Option<TenantDekRow>>
where
    E: sqlx::PgExecutor<'e>,
{
    sqlx::query_as(
        "select tenant_id, version, kek_id, wrapped_dek, created_at, retired_at
         from tenant_deks where tenant_id = $1 and version = $2",
    )
    .bind(tenant_id)
    .bind(version)
    .fetch_optional(exec)
    .await
}

/// The highest-version DEK for a tenant (a future rotation reads the current one).
pub async fn latest_tenant_dek<'e, E>(
    exec: E,
    tenant_id: Uuid,
) -> sqlx::Result<Option<TenantDekRow>>
where
    E: sqlx::PgExecutor<'e>,
{
    sqlx::query_as(
        "select tenant_id, version, kek_id, wrapped_dek, created_at, retired_at
         from tenant_deks where tenant_id = $1 order by version desc limit 1",
    )
    .bind(tenant_id)
    .fetch_optional(exec)
    .await
}

/// Claim a `(tenant, version)` DEK row. `on conflict do nothing` makes the lazy
/// mint race-safe: two concurrent first-seals both attempt the insert, one wins,
/// and both callers re-read the winner (see `kms::dek_for_seal`).
pub async fn insert_tenant_dek<'e, E>(
    exec: E,
    tenant_id: Uuid,
    version: i32,
    kek_id: &str,
    wrapped_dek: &[u8],
) -> sqlx::Result<()>
where
    E: sqlx::PgExecutor<'e>,
{
    sqlx::query(
        "insert into tenant_deks (tenant_id, version, kek_id, wrapped_dek)
         values ($1, $2, $3, $4) on conflict (tenant_id, version) do nothing",
    )
    .bind(tenant_id)
    .bind(version)
    .bind(kek_id)
    .bind(wrapped_dek)
    .execute(exec)
    .await
    .map(|_| ())
}

// ─── Per-tenant LiteLLM virtual keys (Phase D, #32) ───────────────────────

/// The outcome of an insert-or-adopt of a tenant's virtual key: the winning row's
/// sealed bytes + companion version, and whether OUR insert is the one that
/// persisted. A mint race (two concurrent first-uses) resolves here — one insert
/// wins, the loser reads `we_won = false` + the winner's sealed key to adopt.
pub struct TenantLlmKeyInsert {
    pub sealed: Vec<u8>,
    pub key_version: i16,
    pub we_won: bool,
}

/// A tenant's virtual-key row as the RECOVERY path needs it: the sealed bytes
/// EXACTLY as stored (the compare-and-swap expectation — sealing is
/// nondeterministic, so only the bytes we read can be compared), the companion
/// version, and `minted_at` = when this key was created or last rotated.
///
/// `minted_at` is the DURABLE recovery cooldown (Phase D review H3): it survives
/// restarts and is shared by every replica, so a LiteLLM outage that keeps
/// rejecting keys cannot drive re-provisioning in a loop.
pub struct TenantLlmKeyRow {
    pub sealed: Vec<u8>,
    pub key_version: i16,
    pub minted_at: DateTime<Utc>,
}

/// Read a tenant's virtual-key row (sealed bytes + version + `minted_at`).
/// `None` = not yet minted. Tenant-scoped by the PK.
pub async fn tenant_llm_key_row(
    pool: &PgPool,
    scope: TenantScope,
) -> sqlx::Result<Option<TenantLlmKeyRow>> {
    let mut tx = scoped_tx(pool, scope).await?;
    let row: Option<(Vec<u8>, i16, DateTime<Utc>)> = sqlx::query_as(
        "select litellm_key_sealed, litellm_key_key_version, coalesce(rotated_at, created_at)
           from tenant_llm_keys where tenant_id = $1",
    )
    .bind(scope.tenant_id())
    .fetch_optional(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(row.map(|(sealed, key_version, minted_at)| TenantLlmKeyRow {
        sealed,
        key_version,
        minted_at,
    }))
}

/// Compare-and-swap a tenant's virtual key: replace it ONLY while the stored
/// sealed bytes are still `expected_sealed` (Phase D review M4). The reactive
/// recovery path reads the row, proves the key LiteLLM rejected is the CURRENT
/// one, mints a replacement, and lands it here — between the read and the write
/// an operator rotation (or another replica's recovery) may have installed a new
/// key, and blindly overwriting it would leak a live key and discard a
/// successful rotation. `false` = someone else swapped first; the caller must
/// drop its fresh mint and adopt the current key instead. Tenant-scoped by the PK.
pub async fn rotate_tenant_llm_key_cas(
    pool: &PgPool,
    scope: TenantScope,
    expected_sealed: &[u8],
    sealed: &[u8],
    key_version: i16,
    key_alias: &str,
    litellm_token_id: Option<&str>,
) -> sqlx::Result<bool> {
    let mut tx = scoped_tx(pool, scope).await?;
    let r = sqlx::query(
        "update tenant_llm_keys
            set litellm_key_sealed = $2, litellm_key_key_version = $3, key_alias = $4,
                litellm_token_id = $5, rotated_at = now()
          where tenant_id = $1 and litellm_key_sealed = $6",
    )
    .bind(scope.tenant_id())
    .bind(sealed)
    .bind(key_version)
    .bind(key_alias)
    .bind(litellm_token_id)
    .bind(expected_sealed)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(r.rows_affected() == 1)
}

/// Read a tenant's sealed virtual key + companion version. `None` = not yet
/// minted. Tenant-scoped: keyed on the scope's tenant (the table's PK).
pub async fn tenant_llm_key_sealed(
    pool: &PgPool,
    scope: TenantScope,
) -> sqlx::Result<Option<(Vec<u8>, i16)>> {
    let mut tx = scoped_tx(pool, scope).await?;
    let row: Option<(Vec<u8>, i16)> = sqlx::query_as(
        "select litellm_key_sealed, litellm_key_key_version from tenant_llm_keys
         where tenant_id = $1",
    )
    .bind(scope.tenant_id())
    .fetch_optional(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(row)
}

/// Insert a tenant's freshly minted+sealed virtual key, or adopt the winner of a
/// mint race. `ON CONFLICT (tenant_id) DO NOTHING RETURNING` tells us whether our
/// row persisted; on a conflict we re-read the winner's sealed key so the caller
/// can adopt it (and drop its own orphaned LiteLLM key). Tenant-scoped by the PK.
pub async fn insert_tenant_llm_key(
    pool: &PgPool,
    scope: TenantScope,
    sealed: &[u8],
    key_version: i16,
    key_alias: &str,
    litellm_token_id: Option<&str>,
) -> sqlx::Result<TenantLlmKeyInsert> {
    let tenant_id = scope.tenant_id();
    let mut tx = scoped_tx(pool, scope).await?;
    let inserted: Option<(Vec<u8>, i16)> = sqlx::query_as(
        "insert into tenant_llm_keys
           (tenant_id, litellm_key_sealed, litellm_key_key_version, key_alias, litellm_token_id)
         values ($1, $2, $3, $4, $5)
         on conflict (tenant_id) do nothing
         returning litellm_key_sealed, litellm_key_key_version",
    )
    .bind(tenant_id)
    .bind(sealed)
    .bind(key_version)
    .bind(key_alias)
    .bind(litellm_token_id)
    .fetch_optional(&mut *tx)
    .await?;
    if let Some((s, v)) = inserted {
        tx.commit().await?;
        return Ok(TenantLlmKeyInsert {
            sealed: s,
            key_version: v,
            we_won: true,
        });
    }
    // Conflict: another minter won. Re-read the winner's sealed key to adopt.
    let (s, v): (Vec<u8>, i16) = sqlx::query_as(
        "select litellm_key_sealed, litellm_key_key_version from tenant_llm_keys
         where tenant_id = $1",
    )
    .bind(tenant_id)
    .fetch_one(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(TenantLlmKeyInsert {
        sealed: s,
        key_version: v,
        we_won: false,
    })
}

/// Drop a tenant's sealed virtual key so the next `ensure_tenant_key` MINTS a
/// fresh one. Teardown / manual-invalidation only.
///
/// NOT the reactive-401 recovery path any more (review M4): "evict + delete the
/// tenant's row" is unconditional, so a stale rejection (a request that presented
/// a key an operator had already rotated away) deleted the CURRENT row — losing a
/// live key and superseding a successful rotation. Recovery now compare-and-swaps
/// on the exact sealed bytes it read (`rotate_tenant_llm_key_cas`), which also
/// keeps `coalesce(rotated_at, created_at)` as its durable cooldown stamp — a
/// delete would reset that and re-open the loop. Tenant-scoped by the PK.
pub async fn delete_tenant_llm_key(pool: &PgPool, scope: TenantScope) -> sqlx::Result<()> {
    let mut tx = scoped_tx(pool, scope).await?;
    sqlx::query("delete from tenant_llm_keys where tenant_id = $1")
        .bind(scope.tenant_id())
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(())
}

/// Swap a tenant's sealed virtual key for a freshly minted one (rotation),
/// bumping `rotated_at`. Returns the OLD sealed bytes + version so the caller can
/// retire the old key at LiteLLM; `None` = the tenant had no prior key (this
/// created it). Reads-old-then-upserts under a row lock so a concurrent rotate
/// can't lose the old value it must delete. Tenant-scoped by the PK.
pub async fn rotate_tenant_llm_key(
    pool: &PgPool,
    scope: TenantScope,
    sealed: &[u8],
    key_version: i16,
    key_alias: &str,
    litellm_token_id: Option<&str>,
) -> sqlx::Result<Option<(Vec<u8>, i16)>> {
    let tenant_id = scope.tenant_id();
    let mut tx = scoped_tx(pool, scope).await?;
    let old: Option<(Vec<u8>, i16)> = sqlx::query_as(
        "select litellm_key_sealed, litellm_key_key_version from tenant_llm_keys
         where tenant_id = $1 for update",
    )
    .bind(tenant_id)
    .fetch_optional(&mut *tx)
    .await?;
    sqlx::query(
        "insert into tenant_llm_keys
           (tenant_id, litellm_key_sealed, litellm_key_key_version, key_alias, litellm_token_id)
         values ($1, $2, $3, $4, $5)
         on conflict (tenant_id) do update set
           litellm_key_sealed = excluded.litellm_key_sealed,
           litellm_key_key_version = excluded.litellm_key_key_version,
           key_alias = excluded.key_alias,
           litellm_token_id = excluded.litellm_token_id,
           rotated_at = now()",
    )
    .bind(tenant_id)
    .bind(sealed)
    .bind(key_version)
    .bind(key_alias)
    .bind(litellm_token_id)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(old)
}
