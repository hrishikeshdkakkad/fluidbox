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

use anyhow::Context;
use async_trait::async_trait;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use sqlx::PgPool;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;
use uuid::Uuid;
use zeroize::Zeroizing;

/// v1 code mints only DEK version 1; rotation to higher versions is a documented
/// runbook concern (docs/hosted/kms-operations.md, Task 2), not code here.
pub const DEK_VERSION: i32 = 1;

/// The AWS KMS `EncryptionContext` purpose tag (AAD for the KEK wrap); the static
/// backend binds the same purpose so a wrapped DEK can't be replayed cross-use.
const DEK_PURPOSE: &str = "fluidbox-dek";

const WRAP_NONCE_LEN: usize = 24;

/// The unwrapped 32-byte DEK cache, keyed by `(tenant_id, dek_version)`. Values
/// are zeroized on drop. Held behind an `Arc` inside `Sealer` so clones share one
/// cache; a cache miss is the (auditable) KEK unwrap.
pub type DekCache = Mutex<HashMap<(Uuid, i32), Zeroizing<[u8; 32]>>>;

/// Wraps/unwraps a per-tenant DEK under a KEK. `unwrap` takes the stored `kek_id`
/// so a future multi-KEK rotation can route to the right key; a v1 deployment has
/// exactly one KEK.
#[async_trait]
pub trait KeyWrapper: Send + Sync {
    fn kek_id(&self) -> &str;
    async fn wrap(&self, dek: &[u8], tenant_id: Uuid) -> anyhow::Result<Vec<u8>>;
    async fn unwrap(
        &self,
        wrapped: &[u8],
        kek_id: &str,
        tenant_id: Uuid,
    ) -> anyhow::Result<Vec<u8>>;
}

// ─── static KEK backend (local dev + CI) ───────────────────────────────────

/// A 32-byte KEK from `FLUIDBOX_KMS_STATIC_KEK` that wraps DEKs with
/// XChaCha20-Poly1305. The wrap is AEAD-bound to `(tenant_id, purpose)` so a
/// wrapped DEK moved to another tenant's row fails to unwrap — the local analog
/// of a KMS `EncryptionContext`.
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

    fn aad(tenant_id: Uuid) -> String {
        format!("fbx:kek:{tenant_id}:{DEK_PURPOSE}")
    }

    // Sync helpers so the crypto is unit-testable without an async runtime.
    fn wrap_bytes(&self, dek: &[u8], tenant_id: Uuid) -> Vec<u8> {
        let cipher = XChaCha20Poly1305::new(&Key::from(*self.kek));
        let mut nonce = [0u8; WRAP_NONCE_LEN];
        getrandom::fill(&mut nonce).expect("OS RNG is available");
        let aad = Self::aad(tenant_id);
        let ct = cipher
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

    fn unwrap_bytes(&self, wrapped: &[u8], tenant_id: Uuid) -> anyhow::Result<Vec<u8>> {
        if wrapped.len() <= WRAP_NONCE_LEN {
            anyhow::bail!("wrapped DEK is malformed");
        }
        let (nonce, ct) = wrapped.split_at(WRAP_NONCE_LEN);
        let nonce: [u8; WRAP_NONCE_LEN] = nonce.try_into().expect("split_at guarantees length");
        let cipher = XChaCha20Poly1305::new(&Key::from(*self.kek));
        let aad = Self::aad(tenant_id);
        cipher
            .decrypt(
                &XNonce::from(nonce),
                Payload {
                    msg: ct,
                    aad: aad.as_bytes(),
                },
            )
            .map_err(|_| anyhow::anyhow!("DEK unwrap failed (wrong KEK or corrupt data)"))
    }
}

#[async_trait]
impl KeyWrapper for StaticKek {
    fn kek_id(&self) -> &str {
        &self.kek_id
    }
    async fn wrap(&self, dek: &[u8], tenant_id: Uuid) -> anyhow::Result<Vec<u8>> {
        Ok(self.wrap_bytes(dek, tenant_id))
    }
    async fn unwrap(
        &self,
        wrapped: &[u8],
        _kek_id: &str,
        tenant_id: Uuid,
    ) -> anyhow::Result<Vec<u8>> {
        self.unwrap_bytes(wrapped, tenant_id)
    }
}

// ─── AWS KMS backend ────────────────────────────────────────────────────────

/// AWS KMS Encrypt/Decrypt with an `EncryptionContext {tenant_id, purpose}`. The
/// SDK client is built lazily on first use (the default credential chain — which
/// supports IRSA — resolves asynchronously), so `build_sealer` stays sync. Live
/// behavior is exercised only by the CI acceptance script via an endpoint
/// override; there is no unit test of a real KMS call.
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

    async fn wrap(&self, dek: &[u8], tenant_id: Uuid) -> anyhow::Result<Vec<u8>> {
        let out = self
            .client()
            .await
            .encrypt()
            .key_id(&self.key_id)
            .plaintext(aws_sdk_kms::primitives::Blob::new(dek.to_vec()))
            .encryption_context("tenant_id", tenant_id.to_string())
            .encryption_context("purpose", DEK_PURPOSE)
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
        _kek_id: &str,
        tenant_id: Uuid,
    ) -> anyhow::Result<Vec<u8>> {
        let out = self
            .client()
            .await
            .decrypt()
            .key_id(&self.key_id)
            .ciphertext_blob(aws_sdk_kms::primitives::Blob::new(wrapped.to_vec()))
            .encryption_context("tenant_id", tenant_id.to_string())
            .encryption_context("purpose", DEK_PURPOSE)
            .send()
            .await
            .context("AWS KMS Decrypt failed")?;
        out.plaintext()
            .map(|b| b.as_ref().to_vec())
            .context("AWS KMS Decrypt returned no plaintext")
    }
}

// ─── per-tenant DEK get-or-create (orchestration; plan resolution 1) ────────

/// The DEK for sealing a tenant's custody: cache → existing row → mint. Minting
/// is race-safe (`insert … on conflict do nothing`, then re-read the winner), so
/// two concurrent first-seals converge on ONE DEK and the loser discards its
/// freshly-generated bytes.
pub async fn dek_for_seal(
    pool: &PgPool,
    wrapper: &dyn KeyWrapper,
    cache: &DekCache,
    tenant_id: Uuid,
) -> anyhow::Result<Zeroizing<[u8; 32]>> {
    if let Some(dek) = cache.lock().await.get(&(tenant_id, DEK_VERSION)) {
        return Ok(dek.clone());
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
    let wrapped = wrapper.wrap(&fresh[..], tenant_id).await?;
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
/// unrelated key).
pub async fn dek_for_open(
    pool: &PgPool,
    wrapper: &dyn KeyWrapper,
    cache: &DekCache,
    tenant_id: Uuid,
    version: i32,
) -> anyhow::Result<Zeroizing<[u8; 32]>> {
    if let Some(dek) = cache.lock().await.get(&(tenant_id, version)) {
        return Ok(dek.clone());
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
    let plain = Zeroizing::new(
        wrapper
            .unwrap(&row.wrapped_dek, &row.kek_id, tenant_id)
            .await?,
    );
    let arr: [u8; 32] = plain
        .as_slice()
        .try_into()
        .context("unwrapped DEK is not 32 bytes")?;
    let dek = Zeroizing::new(arr);
    cache
        .lock()
        .await
        .insert((tenant_id, row.version), dek.clone());
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
        let wrapped = k.wrap_bytes(&dek, tenant);
        // The wrapped blob never contains the raw DEK.
        assert!(!wrapped.windows(32).any(|w| w == dek));
        assert_eq!(k.unwrap_bytes(&wrapped, tenant).unwrap(), dek.to_vec());
    }

    #[test]
    fn static_kek_wrong_key_fails_closed() {
        let dek = [3u8; 32];
        let tenant = Uuid::now_v7();
        let wrapped = kek("ab").wrap_bytes(&dek, tenant);
        assert!(kek("cd").unwrap_bytes(&wrapped, tenant).is_err());
    }

    #[test]
    fn static_kek_tenant_transplant_fails_closed() {
        let k = kek("ab");
        let dek = [1u8; 32];
        let wrapped = k.wrap_bytes(&dek, Uuid::now_v7());
        // Same KEK, different tenant in the AAD → unwrap must fail.
        assert!(k.unwrap_bytes(&wrapped, Uuid::now_v7()).is_err());
    }

    #[test]
    fn kek_id_is_stable_and_key_dependent() {
        assert_eq!(kek("ab").kek_id(), kek("ab").kek_id());
        assert_ne!(kek("ab").kek_id(), kek("cd").kek_id());
        assert!(kek("ab").kek_id().starts_with("static:"));
    }
}
