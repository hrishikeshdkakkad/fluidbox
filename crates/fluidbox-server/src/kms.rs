//! Key-wrapping backends + per-tenant DEK orchestration for envelope sealing
//! (Phase D, #32; design Gap 5 :1179-1200, plan D2).
//!
//! The envelope model: each tenant has a Data Encryption Key (DEK) that seals
//! its custody columns; the DEK itself is never stored in the clear — it is
//! WRAPPED by a Key Encryption Key (KEK) held by a [`KeyWrapper`] backend
//! (`static` for local/CI, `aws` for AWS KMS). Unwrapping a DEK is the auditable
//! KMS decrypt; unwrapped DEKs cache in memory only, zeroized on drop. Losing the
//! KEK — not this process's memory — is what makes custody unrecoverable, which
//! is the whole point of moving the trust root off a single deployment key.
//!
//! Three properties this module owes the rest of the system (review wave, #32):
//!   1. **The configured KEK must PROVE it can read stored DEKs before serving**
//!      ([`check_kek_compatibility`]). A syntactically valid but WRONG KEK used to
//!      pass every boot gate: existing tenants failed to unwrap while new tenants
//!      happily minted DEKs under it, producing a split-key database no single KEK
//!      could ever recover. The stored `kek_id` is now enforced, never ignored.
//!   2. **A cold cache is a SINGLEFLIGHT, not a stampede.** DEK loads serialize
//!      per `(tenant, version)` with a re-check after the lock, so N concurrent
//!      requests after a restart cost ONE KMS operation, not N billable ones.
//!   3. **The unwrapped-DEK cache is BOUNDED** (size + TTL, zeroizing eviction).
//!      A process no longer accumulates every tenant's DEK it ever touched.

use anyhow::Context;
use async_trait::async_trait;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use sqlx::PgPool;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;
use uuid::Uuid;
use zeroize::Zeroizing;

/// v1 code mints only DEK version 1; rotation to higher versions is a documented
/// runbook concern (docs/hosted/kms-operations.md, Task 2), not code here.
pub const DEK_VERSION: i32 = 1;
/// The lowest DEK version that can exist. Version 0 (and anything negative) is
/// not "an old version" — it is a malformed/forged header, refused before any DB
/// or KMS access.
pub const MIN_DEK_VERSION: i32 = 1;

/// The AWS KMS `EncryptionContext` purpose tag (AAD for the KEK wrap); the static
/// backend binds the same purpose so a wrapped DEK can't be replayed cross-use.
const DEK_PURPOSE: &str = "fluidbox-dek";

const WRAP_NONCE_LEN: usize = 24;

/// Bounded-cache parameters (review M3). A DEK lives in memory for at most
/// [`DEK_CACHE_TTL`] and at most [`DEK_CACHE_MAX`] tenants' DEKs are resident, so
/// one read-only memory disclosure yields recently-active keys, not every key the
/// process ever touched. Both are cheap to re-earn: a miss is one KEK unwrap, and
/// the singleflight makes a simultaneous miss storm cost exactly one.
const DEK_CACHE_MAX: usize = 64;
const DEK_CACHE_TTL: Duration = Duration::from_secs(600);

/// Wraps/unwraps a per-tenant DEK under a KEK.
///
/// `unwrap` takes the STORED `kek_id` + `version` and both implementations
/// ENFORCE them: a DEK wrapped under a different KEK is refused by identity (a
/// named error, not a confusing AEAD failure), and the version is bound into the
/// wrapping context so a v1 wrapped DEK cannot be replayed into a v2 row. A v1
/// deployment has exactly one KEK; there is deliberately no silent fallback to
/// "whatever is configured now" (that is how split-key databases are born).
#[async_trait]
pub trait KeyWrapper: Send + Sync {
    fn kek_id(&self) -> &str;
    async fn wrap(&self, dek: &[u8], tenant_id: Uuid, version: i32) -> anyhow::Result<Vec<u8>>;
    async fn unwrap(
        &self,
        wrapped: &[u8],
        kek_id: &str,
        tenant_id: Uuid,
        version: i32,
    ) -> anyhow::Result<Zeroizing<Vec<u8>>>;
}

/// Refuse a stored `kek_id` the configured backend cannot be responsible for.
///
/// This is the per-row half of the KEK-compatibility gate: the boot probe
/// ([`check_kek_compatibility`]) proves readability once, and this makes every
/// later unwrap fail CLOSED and NAMED if a row somehow carries another KEK's id.
/// Comparison is exact — a `kek_id` is either the static backend's key
/// fingerprint or the configured AWS key id/ARN, and a DB-provided AWS key id is
/// never trusted enough to be sent to KMS (we always call under OUR configured
/// key). Both ids are non-secret identifiers already stored in cleartext in
/// `tenant_deks`, so naming them in the error is the diagnostic an operator needs.
fn ensure_kek_id(configured: &str, stored: &str) -> anyhow::Result<()> {
    if configured != stored {
        anyhow::bail!(
            "this DEK was wrapped by KEK '{stored}' but the deployment is configured with KEK \
             '{configured}' — refusing to unwrap under a different KEK (restore the original \
             KEK; there is no multi-KEK routing or re-wrap tooling yet)"
        );
    }
    Ok(())
}

/// Refuse a DEK version this build cannot serve, BEFORE any DB or KMS access.
/// Rejects 0/negative (a forged or corrupt envelope header) and any future
/// version (a blob written by a newer build — fail closed, never guess).
pub fn ensure_supported_dek_version(version: i32) -> anyhow::Result<()> {
    if !(MIN_DEK_VERSION..=DEK_VERSION).contains(&version) {
        anyhow::bail!(
            "unsupported DEK version {version} (this build reads {MIN_DEK_VERSION}..={DEK_VERSION})"
        );
    }
    Ok(())
}

// ─── the unwrapped-DEK cache (bounded; singleflight-aware) ──────────────────

/// Cache/singleflight key: the tenant plus the DEK version it is asking for.
type DekKey = (Uuid, i32);
/// One singleflight lock — held across a cold-cache DB read + KEK operation.
type Singleflight = Arc<Mutex<()>>;

struct CacheEntry {
    dek: Zeroizing<[u8; 32]>,
    expires_at: Instant,
    last_used: Instant,
}

/// The unwrapped 32-byte DEK cache, keyed by `(tenant_id, dek_version)`, plus the
/// per-key singleflight locks. Values are zeroized on eviction and on drop. Held
/// behind an `Arc` inside `Sealer` so clones share one cache; a cache miss is the
/// (auditable, billable) KEK unwrap — which is exactly why misses are
/// singleflighted and why the cache is bounded rather than process-lifetime.
///
/// Residency is enforced lazily (on access), not by a sweeper task: an idle
/// process can hold an expired entry until the next DEK access. That bounds the
/// disclosure set to "recently active tenants", which is the property M3 asked
/// for, without a background task lifecycle.
pub struct DekCache {
    entries: Mutex<HashMap<DekKey, CacheEntry>>,
    /// Per-`(tenant, version)` singleflight locks. Pruned when unreferenced —
    /// see [`DekCache::lock_for`].
    locks: Mutex<HashMap<DekKey, Singleflight>>,
    max: usize,
    ttl: Duration,
}

impl Default for DekCache {
    fn default() -> Self {
        Self::with_limits(DEK_CACHE_MAX, DEK_CACHE_TTL)
    }
}

impl DekCache {
    fn with_limits(max: usize, ttl: Duration) -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
            locks: Mutex::new(HashMap::new()),
            max,
            ttl,
        }
    }

    /// A live cached DEK, or `None`. Expired entries are dropped (zeroized) on the
    /// way past, so a stale key is never served and never lingers once touched.
    async fn get(&self, key: DekKey) -> Option<Zeroizing<[u8; 32]>> {
        let now = Instant::now();
        let mut map = self.entries.lock().await;
        map.retain(|_, e| e.expires_at > now);
        let entry = map.get_mut(&key)?;
        entry.last_used = now;
        Some(entry.dek.clone())
    }

    /// Cache an unwrapped DEK, purging expired entries and evicting the
    /// least-recently-used ones to stay within the size cap. Every eviction drops
    /// a `Zeroizing` value, so the key bytes are scrubbed, not merely unlinked.
    async fn insert(&self, key: DekKey, dek: Zeroizing<[u8; 32]>) {
        let now = Instant::now();
        let mut map = self.entries.lock().await;
        map.retain(|_, e| e.expires_at > now);
        map.insert(
            key,
            CacheEntry {
                dek,
                expires_at: now + self.ttl,
                last_used: now,
            },
        );
        while map.len() > self.max {
            let Some(victim) = map.iter().min_by_key(|(_, e)| e.last_used).map(|(k, _)| *k) else {
                break;
            };
            map.remove(&victim); // Zeroizing drop scrubs the key bytes
        }
    }

    /// The singleflight lock for one `(tenant, version)`. Callers acquire it, then
    /// RE-CHECK the cache before doing DB/KMS work, so N concurrent cold-cache
    /// requests for the same key cost exactly ONE unwrap (or ONE mint).
    ///
    /// The lock map is pruned opportunistically: an `Arc` with a single strong
    /// reference is held only by the map, so nobody is waiting on it.
    async fn lock_for(&self, key: DekKey) -> Singleflight {
        let mut locks = self.locks.lock().await;
        if locks.len() > self.max {
            locks.retain(|_, l| Arc::strong_count(l) > 1);
        }
        locks.entry(key).or_default().clone()
    }

    #[cfg(test)]
    async fn len(&self) -> usize {
        self.entries.lock().await.len()
    }
}

// ─── static KEK backend (local dev + CI) ───────────────────────────────────

/// A 32-byte KEK from `FLUIDBOX_KMS_STATIC_KEK` that wraps DEKs with
/// XChaCha20-Poly1305. The wrap is AEAD-bound to `(tenant_id, purpose, version)`
/// so a wrapped DEK moved to another tenant's row — or to another VERSION of the
/// same tenant's row — fails to unwrap: the local analog of a KMS
/// `EncryptionContext`.
pub struct StaticKek {
    kek: Zeroizing<[u8; 32]>,
    kek_id: String,
}

impl StaticKek {
    /// Accepts a 32-byte KEK as 64 hex chars or standard base64.
    pub fn from_key_string(s: &str) -> anyhow::Result<Self> {
        let bytes = decode_32(s)?;
        // A short fingerprint distinguishes KEK generations in `kek_id` without
        // ever storing key material; the AEAD tag is what actually rejects a
        // wrong KEK at unwrap time.
        use sha2::{Digest, Sha256};
        let fp = hex::encode(Sha256::digest(bytes))[..16].to_string();
        Ok(Self {
            kek: Zeroizing::new(bytes),
            kek_id: format!("static:{fp}"),
        })
    }

    /// The wrap AAD binds tenant + purpose + DEK VERSION (review L6): without the
    /// version, a tenant's v1 wrapped DEK could be copied into its v2 row and
    /// still unwrap, so the version metadata carried alongside would be
    /// unauthenticated.
    fn aad(tenant_id: Uuid, version: i32) -> String {
        format!("fbx:kek:{tenant_id}:{DEK_PURPOSE}:v{version}")
    }

    /// The cipher, built WITHOUT copying the key onto the stack (`new_from_slice`
    /// borrows; `Key::from(*self.kek)` would materialize an unscrubbed copy). The
    /// cipher itself zeroizes its key material on drop (`chacha20poly1305`'s
    /// `zeroize` feature).
    fn cipher(&self) -> XChaCha20Poly1305 {
        XChaCha20Poly1305::new_from_slice(&self.kek[..]).expect("a KEK is 32 bytes")
    }

    // Sync helpers so the crypto is unit-testable without an async runtime.
    fn wrap_bytes(&self, dek: &[u8], tenant_id: Uuid, version: i32) -> Vec<u8> {
        let mut nonce = [0u8; WRAP_NONCE_LEN];
        getrandom::fill(&mut nonce).expect("OS RNG is available");
        let aad = Self::aad(tenant_id, version);
        let ct = self
            .cipher()
            .encrypt(
                &XNonce::from(nonce),
                Payload {
                    msg: dek,
                    aad: aad.as_bytes(),
                },
            )
            .expect("XChaCha20Poly1305 encrypt is infallible for in-memory data");
        let mut out = Vec::with_capacity(WRAP_NONCE_LEN + ct.len());
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&ct);
        out
    }

    fn unwrap_bytes(
        &self,
        wrapped: &[u8],
        tenant_id: Uuid,
        version: i32,
    ) -> anyhow::Result<Zeroizing<Vec<u8>>> {
        if wrapped.len() <= WRAP_NONCE_LEN {
            anyhow::bail!("wrapped DEK is malformed");
        }
        let (nonce, ct) = wrapped.split_at(WRAP_NONCE_LEN);
        let nonce: [u8; WRAP_NONCE_LEN] = nonce.try_into().expect("split_at guarantees length");
        let aad = Self::aad(tenant_id, version);
        let plain = self
            .cipher()
            .decrypt(
                &XNonce::from(nonce),
                Payload {
                    msg: ct,
                    aad: aad.as_bytes(),
                },
            )
            .map_err(|_| anyhow::anyhow!("DEK unwrap failed (wrong KEK or corrupt data)"))?;
        Ok(Zeroizing::new(plain))
    }
}

#[async_trait]
impl KeyWrapper for StaticKek {
    fn kek_id(&self) -> &str {
        &self.kek_id
    }
    async fn wrap(&self, dek: &[u8], tenant_id: Uuid, version: i32) -> anyhow::Result<Vec<u8>> {
        Ok(self.wrap_bytes(dek, tenant_id, version))
    }
    async fn unwrap(
        &self,
        wrapped: &[u8],
        kek_id: &str,
        tenant_id: Uuid,
        version: i32,
    ) -> anyhow::Result<Zeroizing<Vec<u8>>> {
        // The stored kek_id is ENFORCED, never ignored (review H1).
        ensure_kek_id(&self.kek_id, kek_id)?;
        self.unwrap_bytes(wrapped, tenant_id, version)
    }
}

// ─── AWS KMS backend ────────────────────────────────────────────────────────

/// AWS KMS Encrypt/Decrypt with an `EncryptionContext {tenant_id, purpose,
/// dek_version}`. The SDK client is built lazily on first use (the default
/// credential chain — which supports IRSA — resolves asynchronously), so
/// `build_sealer` stays sync. Live behavior is exercised only by the CI acceptance
/// script via an endpoint override; there is no unit test of a real KMS call.
pub struct AwsKms {
    key_id: String,
    endpoint: Option<String>,
    client: tokio::sync::OnceCell<aws_sdk_kms::Client>,
}

impl AwsKms {
    pub fn new(key_id: String, endpoint: Option<String>) -> Self {
        Self {
            key_id,
            endpoint,
            client: tokio::sync::OnceCell::new(),
        }
    }

    async fn client(&self) -> &aws_sdk_kms::Client {
        self.client
            .get_or_init(|| async {
                let mut loader = aws_config::defaults(aws_config::BehaviorVersion::latest());
                if let Some(ep) = &self.endpoint {
                    loader = loader.endpoint_url(ep);
                }
                let cfg = loader.load().await;
                aws_sdk_kms::Client::new(&cfg)
            })
            .await
    }
}

#[async_trait]
impl KeyWrapper for AwsKms {
    fn kek_id(&self) -> &str {
        &self.key_id
    }

    async fn wrap(&self, dek: &[u8], tenant_id: Uuid, version: i32) -> anyhow::Result<Vec<u8>> {
        let out = self
            .client()
            .await
            .encrypt()
            .key_id(&self.key_id)
            .plaintext(aws_sdk_kms::primitives::Blob::new(dek.to_vec()))
            .encryption_context("tenant_id", tenant_id.to_string())
            .encryption_context("purpose", DEK_PURPOSE)
            .encryption_context("dek_version", version.to_string())
            .send()
            .await
            .context("AWS KMS Encrypt failed")?;
        out.ciphertext_blob()
            .map(|b| b.as_ref().to_vec())
            .context("AWS KMS Encrypt returned no ciphertext")
    }

    async fn unwrap(
        &self,
        wrapped: &[u8],
        kek_id: &str,
        tenant_id: Uuid,
        version: i32,
    ) -> anyhow::Result<Zeroizing<Vec<u8>>> {
        // The DB-provided key id is VALIDATED against the configured expectation
        // and never sent to KMS (review H1): the call below always names OUR
        // configured key, so a rewritten `tenant_deks.kek_id` cannot redirect a
        // Decrypt at an attacker-chosen key.
        ensure_kek_id(&self.key_id, kek_id)?;
        let mut out = self
            .client()
            .await
            .decrypt()
            .key_id(&self.key_id)
            .ciphertext_blob(aws_sdk_kms::primitives::Blob::new(wrapped.to_vec()))
            .encryption_context("tenant_id", tenant_id.to_string())
            .encryption_context("purpose", DEK_PURPOSE)
            .encryption_context("dek_version", version.to_string())
            .send()
            .await
            .context("AWS KMS Decrypt failed")?;
        // TAKE the plaintext blob out of the response and own it inside a
        // zeroizing container (review M4): `plaintext().to_vec()` would leave a
        // second, unscrubbed copy alive inside the SDK output for as long as it
        // lives. Buffers the SDK's own deserializer allocated upstream remain
        // outside our control — this is as early as the SDK allows.
        let plain = out
            .plaintext
            .take()
            .map(|b| Zeroizing::new(b.into_inner()))
            .context("AWS KMS Decrypt returned no plaintext")?;
        Ok(plain)
    }
}

// ─── boot-time KEK compatibility gate (review H1) ───────────────────────────

/// One distinct KEK present in `tenant_deks`, with a sample row to probe.
/// `wrapped_dek` is WRAPPED key material (what is already stored); no plaintext.
struct KekSample {
    kek_id: String,
    tenant_id: Uuid,
    version: i32,
    wrapped_dek: Vec<u8>,
}

/// Census of the DISTINCT KEKs that wrapped the stored per-tenant DEKs, with one
/// sample row each.
///
/// Cross-tenant by construction (it is a deployment-wide key-management question,
/// asked at boot with no principal), so it rides the audited system-worker bypass
/// via `system_worker::reseal_begin` — without it, FORCE RLS returns ZERO rows and
/// the gate would fail OPEN, which is precisely the failure it exists to prevent.
/// It returns key IDENTIFIERS plus already-wrapped bytes — never a plaintext key.
///
/// The SQL lives here rather than in `fluidbox-db` only because that crate was
/// owned by a parallel change in this review wave; its natural home is a named
/// `system_worker::dek_kek_census()` (see the review report).
async fn dek_kek_census(pool: &PgPool) -> anyhow::Result<Vec<KekSample>> {
    let mut tx = fluidbox_db::system_worker::reseal_begin(pool)
        .await
        .context("opening the DEK census transaction")?;
    let rows: Vec<(String, Uuid, i32, Vec<u8>)> = sqlx::query_as(
        "select distinct on (kek_id) kek_id, tenant_id, version, wrapped_dek
           from tenant_deks
          order by kek_id, tenant_id, version",
    )
    .fetch_all(&mut *tx)
    .await
    .context("reading tenant_deks")?;
    tx.commit().await.context("committing the DEK census")?;
    Ok(rows
        .into_iter()
        .map(|(kek_id, tenant_id, version, wrapped_dek)| KekSample {
            kek_id,
            tenant_id,
            version,
            wrapped_dek,
        })
        .collect())
}

/// Boot gate: refuse to serve unless the CONFIGURED KEK can actually read the
/// DEKs already stored (review H1).
///
/// The retirement gates verify that the configured sealing state can *in
/// principle* open what is stored (v1 needs the legacy key, v2 needs KMS). They
/// cannot see WHICH KEK wrapped the stored DEKs, so a syntactically valid but
/// wrong static KEK — or a different AWS key id — used to boot happily: every
/// existing tenant failed to unwrap while every NEW tenant minted a DEK under the
/// wrong KEK, permanently splitting custody across two KEKs with no recovery. So:
///   - zero DEK rows → nothing to prove; the configured KEK wraps the first.
///   - exactly one distinct `kek_id` → it MUST match the configured backend, and a
///     real unwrap must succeed (a PROBE — identity alone does not prove the AWS
///     grant or the key material is usable).
///   - more than one → refuse. There is no multi-KEK routing or re-wrap tooling;
///     serving would mean silently reading some tenants and orphaning others.
pub async fn check_kek_compatibility(
    pool: &PgPool,
    wrapper: &dyn KeyWrapper,
) -> anyhow::Result<()> {
    let samples = dek_kek_census(pool)
        .await
        .context("KEK compatibility gate: could not read tenant_deks")?;
    match samples.len() {
        0 => {
            tracing::info!(
                kek_id = %wrapper.kek_id(),
                "KMS: no per-tenant DEKs stored yet; the configured KEK will wrap the first"
            );
            Ok(())
        }
        1 => {
            let s = &samples[0];
            ensure_kek_id(wrapper.kek_id(), &s.kek_id).context(
                "stored per-tenant DEKs were wrapped by a DIFFERENT KEK. Booting would orphan \
                 every existing tenant while new tenants minted DEKs under the configured KEK \
                 (a split-key database). Restore the original KEK",
            )?;
            // The PROBE. An id match is not proof: the AWS grant may be missing,
            // the key disabled, or the wrapping format changed. One unwrap settles it.
            wrapper
                .unwrap(&s.wrapped_dek, &s.kek_id, s.tenant_id, s.version)
                .await
                .context(
                    "the configured KEK could not unwrap a stored per-tenant DEK — refusing to \
                     serve (every sealed v2 credential would be unreadable and new tenants would \
                     mint DEKs the old ones cannot share)",
                )?;
            tracing::info!(
                kek_id = %wrapper.kek_id(),
                "KMS: KEK compatibility probe passed (a stored per-tenant DEK unwrapped)"
            );
            Ok(())
        }
        n => {
            let ids: Vec<&str> = samples.iter().map(|s| s.kek_id.as_str()).collect();
            anyhow::bail!(
                "tenant_deks holds DEKs wrapped under {n} distinct KEKs ({}) — fluidbox has no \
                 multi-KEK routing or re-wrap tooling, so serving would read some tenants and \
                 orphan others. Restore a single KEK for every stored DEK",
                ids.join(", ")
            )
        }
    }
}

// ─── per-tenant DEK get-or-create (orchestration; plan resolution 1) ────────

/// The DEK for sealing a tenant's custody: cache → existing row → mint.
///
/// SINGLEFLIGHT (review H2): the per-`(tenant, version)` lock is held across the
/// DB read, the KEK unwrap AND the mint, with a cache re-check after acquiring it.
/// Without it, a cold cache turned N concurrent requests into N KMS operations
/// (billable, and reachable pre-authentication through transit tokens), and a
/// first-ever seal turned concurrent flows into N KMS Encrypts.
///
/// Minting stays race-safe ACROSS processes too (`insert … on conflict do
/// nothing`, then re-read the winner), so two replicas' first-seals converge on
/// ONE DEK and the loser discards its freshly-generated bytes.
pub async fn dek_for_seal(
    pool: &PgPool,
    wrapper: &dyn KeyWrapper,
    cache: &DekCache,
    tenant_id: Uuid,
) -> anyhow::Result<Zeroizing<[u8; 32]>> {
    let key = (tenant_id, DEK_VERSION);
    if let Some(dek) = cache.get(key).await {
        return Ok(dek);
    }
    let lock = cache.lock_for(key).await;
    let _guard = lock.lock().await;
    // RE-CHECK under the singleflight lock: the racer we queued behind may have
    // already unwrapped (or minted) this exact DEK.
    if let Some(dek) = cache.get(key).await {
        return Ok(dek);
    }
    // `tenant_deks` is a tenant-owned table under RLS; the tenant is verified (it
    // came from a SealCtx), so the executor-generic DEK readers/writers ride a
    // scoped_tx (assume) that sets the tenant GUC.
    let scope = fluidbox_db::TenantScope::assume(tenant_id);
    let mut get_tx = fluidbox_db::scoped_tx(pool, scope).await?;
    let existing = fluidbox_db::get_tenant_dek(&mut *get_tx, tenant_id, DEK_VERSION).await?;
    get_tx.commit().await?;
    if let Some(row) = existing {
        return unwrap_and_cache(wrapper, cache, tenant_id, row).await;
    }
    // Mint a fresh DEK, wrap it, and try to claim the row. `fresh` is zeroized on
    // drop; whether we win or lose the insert race, we re-read the row that
    // actually landed and unwrap THAT, so all racers agree on one DEK.
    let mut fresh: Zeroizing<[u8; 32]> = Zeroizing::new([0u8; 32]);
    getrandom::fill(&mut fresh[..]).context("OS RNG unavailable")?;
    let wrapped = wrapper.wrap(&fresh[..], tenant_id, DEK_VERSION).await?;
    // Insert (ON CONFLICT DO NOTHING) + re-read in ONE scoped tx: the re-read sees
    // our row or a concurrent winner's, so all racers converge on one DEK.
    let mut ins_tx = fluidbox_db::scoped_tx(pool, scope).await?;
    fluidbox_db::insert_tenant_dek(
        &mut *ins_tx,
        tenant_id,
        DEK_VERSION,
        wrapper.kek_id(),
        &wrapped,
    )
    .await?;
    let row = fluidbox_db::get_tenant_dek(&mut *ins_tx, tenant_id, DEK_VERSION)
        .await?
        .context("tenant DEK missing immediately after insert")?;
    ins_tx.commit().await?;
    unwrap_and_cache(wrapper, cache, tenant_id, row).await
}

/// The DEK for opening a v2 blob's declared version — GET only, never mint (a
/// blob sealed under a now-missing DEK must fail closed, not be handed a fresh
/// unrelated key). Same singleflight as [`dek_for_seal`], and the version is
/// validated BEFORE any DB or KMS access so a forged header cannot even reach
/// them.
pub async fn dek_for_open(
    pool: &PgPool,
    wrapper: &dyn KeyWrapper,
    cache: &DekCache,
    tenant_id: Uuid,
    version: i32,
) -> anyhow::Result<Zeroizing<[u8; 32]>> {
    ensure_supported_dek_version(version)?;
    let key = (tenant_id, version);
    if let Some(dek) = cache.get(key).await {
        return Ok(dek);
    }
    let lock = cache.lock_for(key).await;
    let _guard = lock.lock().await;
    if let Some(dek) = cache.get(key).await {
        return Ok(dek);
    }
    // Tenant-scoped read under RLS (tenant verified from the SealCtx) → scoped_tx.
    let scope = fluidbox_db::TenantScope::assume(tenant_id);
    let mut get_tx = fluidbox_db::scoped_tx(pool, scope).await?;
    let row = fluidbox_db::get_tenant_dek(&mut *get_tx, tenant_id, version)
        .await?
        .with_context(|| {
            format!("no DEK for tenant {tenant_id} version {version} — cannot unseal")
        })?;
    get_tx.commit().await?;
    unwrap_and_cache(wrapper, cache, tenant_id, row).await
}

async fn unwrap_and_cache(
    wrapper: &dyn KeyWrapper,
    cache: &DekCache,
    tenant_id: Uuid,
    row: fluidbox_db::TenantDekRow,
) -> anyhow::Result<Zeroizing<[u8; 32]>> {
    let plain = wrapper
        .unwrap(&row.wrapped_dek, &row.kek_id, tenant_id, row.version)
        .await?;
    if plain.len() != 32 {
        anyhow::bail!("unwrapped DEK is not 32 bytes");
    }
    // Copy INTO the zeroizing container (never through an unscrubbed `[u8; 32]`
    // temporary on the stack — review M4).
    let mut dek: Zeroizing<[u8; 32]> = Zeroizing::new([0u8; 32]);
    dek.copy_from_slice(&plain);
    cache.insert((tenant_id, row.version), dek.clone()).await;
    Ok(dek)
}

/// Decode a 32-byte key given as 64 hex chars or standard base64.
fn decode_32(s: &str) -> anyhow::Result<[u8; 32]> {
    let s = s.trim();
    let bytes = match hex::decode(s) {
        Ok(b) => b,
        Err(_) => {
            use base64::Engine;
            base64::engine::general_purpose::STANDARD
                .decode(s)
                .map_err(|_| anyhow::anyhow!("FLUIDBOX_KMS_STATIC_KEK must be hex or base64"))?
        }
    };
    bytes.try_into().map_err(|b: Vec<u8>| {
        anyhow::anyhow!(
            "FLUIDBOX_KMS_STATIC_KEK must decode to 32 bytes (got {})",
            b.len()
        )
    })
}

/// Shared handle a `Sealer` holds for its KMS backend.
pub(crate) struct KmsBackend {
    pub wrapper: Arc<dyn KeyWrapper>,
    pub pool: PgPool,
    pub cache: Arc<DekCache>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kek(byte: &str) -> StaticKek {
        StaticKek::from_key_string(&byte.repeat(32)).unwrap()
    }

    #[test]
    fn static_kek_wrap_unwrap_roundtrip() {
        let k = kek("ab");
        let dek = [9u8; 32];
        let tenant = Uuid::now_v7();
        let wrapped = k.wrap_bytes(&dek, tenant, DEK_VERSION);
        // The wrapped blob never contains the raw DEK.
        assert!(!wrapped.windows(32).any(|w| w == dek));
        assert_eq!(
            k.unwrap_bytes(&wrapped, tenant, DEK_VERSION)
                .unwrap()
                .to_vec(),
            dek.to_vec()
        );
    }

    #[test]
    fn static_kek_wrong_key_fails_closed() {
        let dek = [3u8; 32];
        let tenant = Uuid::now_v7();
        let wrapped = kek("ab").wrap_bytes(&dek, tenant, DEK_VERSION);
        assert!(kek("cd")
            .unwrap_bytes(&wrapped, tenant, DEK_VERSION)
            .is_err());
    }

    #[test]
    fn static_kek_tenant_transplant_fails_closed() {
        let k = kek("ab");
        let dek = [1u8; 32];
        let wrapped = k.wrap_bytes(&dek, Uuid::now_v7(), DEK_VERSION);
        // Same KEK, different tenant in the AAD → unwrap must fail.
        assert!(k
            .unwrap_bytes(&wrapped, Uuid::now_v7(), DEK_VERSION)
            .is_err());
    }

    #[test]
    fn static_kek_version_transplant_fails_closed() {
        // Review L6: the DEK VERSION is bound into the wrapping context, so a v1
        // wrapped DEK copied into a v2 row cannot be unwrapped as v2 (and vice
        // versa) — the version metadata beside the blob is now authenticated.
        let k = kek("ab");
        let wrapped = k.wrap_bytes(&[5u8; 32], Uuid::nil(), 1);
        assert!(k.unwrap_bytes(&wrapped, Uuid::nil(), 1).is_ok());
        assert!(k.unwrap_bytes(&wrapped, Uuid::nil(), 2).is_err());
    }

    #[test]
    fn kek_id_is_stable_and_key_dependent() {
        assert_eq!(kek("ab").kek_id(), kek("ab").kek_id());
        assert_ne!(kek("ab").kek_id(), kek("cd").kek_id());
        assert!(kek("ab").kek_id().starts_with("static:"));
    }

    #[tokio::test]
    async fn stored_kek_id_is_enforced_not_ignored() {
        // Review H1: the wrapper used to IGNORE the stored kek_id and unwrap with
        // whatever is configured now. A row claiming another KEK must be refused
        // BY IDENTITY, with a message naming both ids.
        let k = kek("ab");
        let tenant = Uuid::now_v7();
        let wrapped = k.wrap_bytes(&[7u8; 32], tenant, DEK_VERSION);
        // Same KEK id → allowed.
        assert!(k
            .unwrap(&wrapped, k.kek_id(), tenant, DEK_VERSION)
            .await
            .is_ok());
        // Another KEK's id on the row → refused before any crypto.
        let other = kek("cd");
        let err = k
            .unwrap(&wrapped, other.kek_id(), tenant, DEK_VERSION)
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains(other.kek_id()), "names the stored id: {err}");
        assert!(err.contains(k.kek_id()), "names the configured id: {err}");
    }

    #[test]
    fn dek_version_domain_is_closed() {
        // Rejected BEFORE any DB/KMS access (review H2 + L6): 0 is not "an old
        // version", and a future version is never guessed at.
        assert!(ensure_supported_dek_version(0).is_err());
        assert!(ensure_supported_dek_version(-1).is_err());
        assert!(ensure_supported_dek_version(i32::MAX).is_err());
        assert!(ensure_supported_dek_version(DEK_VERSION + 1).is_err());
        assert!(ensure_supported_dek_version(DEK_VERSION).is_ok());
    }

    // ─── bounded cache + singleflight (review M3 / H2) ──────────────────────

    #[tokio::test]
    async fn cache_evicts_lru_beyond_the_size_cap() {
        let cache = DekCache::with_limits(2, Duration::from_secs(60));
        let (a, b, c) = (Uuid::now_v7(), Uuid::now_v7(), Uuid::now_v7());
        cache.insert((a, 1), Zeroizing::new([1u8; 32])).await;
        cache.insert((b, 1), Zeroizing::new([2u8; 32])).await;
        // Touch `a` so `b` is the least-recently-used victim.
        assert!(cache.get((a, 1)).await.is_some());
        cache.insert((c, 1), Zeroizing::new([3u8; 32])).await;
        assert_eq!(cache.len().await, 2, "size cap holds");
        assert!(cache.get((b, 1)).await.is_none(), "LRU entry evicted");
        assert!(cache.get((a, 1)).await.is_some());
        assert!(cache.get((c, 1)).await.is_some());
    }

    #[tokio::test]
    async fn cache_entries_expire() {
        let cache = DekCache::with_limits(8, Duration::from_millis(0));
        let t = Uuid::now_v7();
        cache.insert((t, 1), Zeroizing::new([1u8; 32])).await;
        // A zero TTL means the entry is already expired when read back — and the
        // read PURGES it, so an expired key does not linger in the map.
        assert!(cache.get((t, 1)).await.is_none());
        assert_eq!(cache.len().await, 0);
    }

    #[tokio::test]
    async fn singleflight_lock_is_per_key_and_pruned() {
        let cache = DekCache::with_limits(2, Duration::from_secs(60));
        let (a, b) = (Uuid::now_v7(), Uuid::now_v7());
        let la = cache.lock_for((a, 1)).await;
        let la2 = cache.lock_for((a, 1)).await;
        let lb = cache.lock_for((b, 1)).await;
        assert!(
            Arc::ptr_eq(&la, &la2),
            "same key → the SAME lock (serializes)"
        );
        assert!(!Arc::ptr_eq(&la, &lb), "different keys never contend");
        // Holding `la`, the lock is genuinely exclusive.
        let guard = la.lock().await;
        assert!(la2.try_lock().is_err(), "a second holder must wait");
        drop(guard);
        // Unreferenced locks are pruned once the map outgrows the cap.
        drop((la, la2, lb));
        for i in 0..5u8 {
            let _ = cache.lock_for((Uuid::now_v7(), i32::from(i))).await;
        }
        assert!(
            cache.locks.lock().await.len() <= 3,
            "the lock map does not grow without bound"
        );
    }

    #[tokio::test]
    async fn cold_cache_load_happens_once_under_concurrency() {
        // The singleflight property itself, with a counting fake "unwrap": N
        // concurrent cold-cache loads for ONE key must perform ONE load.
        use std::sync::atomic::{AtomicUsize, Ordering};
        let cache = Arc::new(DekCache::with_limits(8, Duration::from_secs(60)));
        let loads = Arc::new(AtomicUsize::new(0));
        let tenant = Uuid::now_v7();
        let mut tasks = Vec::new();
        for _ in 0..16 {
            let (cache, loads) = (cache.clone(), loads.clone());
            tasks.push(tokio::spawn(async move {
                let key = (tenant, 1);
                if cache.get(key).await.is_some() {
                    return;
                }
                let lock = cache.lock_for(key).await;
                let _g = lock.lock().await;
                if cache.get(key).await.is_some() {
                    return;
                }
                loads.fetch_add(1, Ordering::SeqCst);
                // Stand in for the DB read + KEK unwrap.
                tokio::time::sleep(Duration::from_millis(5)).await;
                cache.insert(key, Zeroizing::new([9u8; 32])).await;
            }));
        }
        for t in tasks {
            t.await.unwrap();
        }
        assert_eq!(
            loads.load(Ordering::SeqCst),
            1,
            "16 concurrent cold-cache requests must cost ONE unwrap, not 16"
        );
    }
}
