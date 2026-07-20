//! Credential sealing for integration connections (Phase D versioned envelope,
//! #32; design Gap 5 :1179-1200, plan D1-D4).
//!
//! Connections hold durable external-service credentials (e.g. a GitHub
//! token). At rest they are AEAD-sealed with a server-side key; the plaintext
//! exists only (a) at the API boundary when the user pastes it in, and (b)
//! for the duration of a control-plane-side operation (workspace fetch,
//! provider API call). It never enters a RunSpec, sandbox, ledger, artifact,
//! or API response.
//!
//! Two on-disk formats, discriminated by a per-column `<base>_key_version`
//! companion (D1), NEVER by an in-band magic byte (legacy blobs begin with 24
//! random nonce bytes, so any prefix scheme is only probabilistic):
//!   - v1 (legacy): `nonce(24) || ct`, one deployment-wide XChaCha20-Poly1305 key
//!     from `FLUIDBOX_CREDENTIAL_KEY`, no AAD. Byte-identical to pre-Phase-D.
//!   - v2 (envelope): `[0x02][dek_version u32 BE][nonce 24][ct]`, sealed under a
//!     per-tenant DEK (wrapped by a KEK backend, `kms.rs`). AAD binds
//!     `"fbx:v2:{tenant_id}:{table.column}"`, so a blob transplanted across
//!     tenants OR families fails AEAD open even under the right DEK. The leading
//!     `0x02` is an internal sanity byte only — the companion column is the
//!     discriminator.

use crate::config::{Config, KmsMode};
use crate::kms::{self, AwsKms, DekCache, KeyWrapper, KmsBackend, StaticKek, DEK_VERSION};
use anyhow::Context;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use sqlx::PgPool;
use std::sync::Arc;
use uuid::Uuid;

const NONCE_LEN: usize = 24;
/// Leading byte of a v2 envelope blob (internal sanity check, not the format
/// discriminator — the companion `_key_version` column is).
const V2_TAG: u8 = 0x02;
/// v2 header = tag(1) + dek_version(4). The nonce and ciphertext follow.
const V2_HEADER_LEN: usize = 1 + 4;
/// Companion key-version values stored beside each sealed column.
const KV_LEGACY: i16 = 1;
const KV_ENVELOPE: i16 = 2;

/// AAD family segment for ephemeral transit tokens (see [`Sealer::seal_token`]).
/// These are deployment-level wire values with no column family, so they use one
/// fixed AAD; their tenant binding comes from the deployment tenant's DEK.
const TRANSIT_AAD: &str = "fbx:v2:transit";

/// The sealed families = the sealed `table.column` pairs. `Display` renders
/// `"table.column"` — the AAD's family segment and the human label in boot-gate
/// counts. Columns 10-13 land with their tables in Tasks 3-5 (the families are
/// declared now so those tasks seal v2-natively; global rows seal under the nil
/// UUID = the deployment context — documented at those call sites).
// The last four variants have no Task-1 seal site — they belong to migrations
// 0015-0017 (Tasks 3-5). Declared here to fix the interface across tasks.
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SealFamily {
    ConnectionCredential,
    ConnectionWebhookSecret,
    ConnectionClientSecret,
    SubscriptionCallbackSecret,
    GithubAppPem,
    GithubAppWebhookSecret,
    GithubAppClientSecret,
    IdpClientSecret,
    LoginPkceVerifier,
    OauthFlowPkceVerifier,
    RegistrationClientSecret,
    RegistrationAccessToken,
    TenantLlmKey,
}

impl std::fmt::Display for SealFamily {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            SealFamily::ConnectionCredential => "integration_connections.credential_sealed",
            SealFamily::ConnectionWebhookSecret => "integration_connections.webhook_secret_sealed",
            SealFamily::ConnectionClientSecret => "integration_connections.client_secret_sealed",
            SealFamily::SubscriptionCallbackSecret => {
                "trigger_subscriptions.callback_secret_sealed"
            }
            SealFamily::GithubAppPem => "github_app_registrations.pem_sealed",
            SealFamily::GithubAppWebhookSecret => "github_app_registrations.webhook_secret_sealed",
            SealFamily::GithubAppClientSecret => "github_app_registrations.client_secret_sealed",
            SealFamily::IdpClientSecret => "org_idp_configs.client_secret_sealed",
            SealFamily::LoginPkceVerifier => "login_flows.pkce_verifier_sealed",
            SealFamily::OauthFlowPkceVerifier => "connector_oauth_flows.pkce_verifier_sealed",
            SealFamily::RegistrationClientSecret => {
                "oauth_client_registrations.client_secret_sealed"
            }
            SealFamily::RegistrationAccessToken => {
                "oauth_client_registrations.registration_access_token_sealed"
            }
            SealFamily::TenantLlmKey => "tenant_llm_keys.litellm_key_sealed",
        };
        f.write_str(s)
    }
}

/// Everything a v2 seal binds: the tenant whose DEK seals it and the family whose
/// name goes into the AAD. `tenant_id` is the nil UUID for deployment-global rows
/// (Task 3's global client registrations).
#[derive(Debug, Clone, Copy)]
pub struct SealCtx {
    pub tenant_id: Uuid,
    pub family: SealFamily,
}

impl SealCtx {
    pub fn new(tenant_id: Uuid, family: SealFamily) -> Self {
        Self { tenant_id, family }
    }
}

/// A sealed blob plus the companion key-version to persist beside it.
pub struct Sealed {
    pub bytes: Vec<u8>,
    pub key_version: i16,
}

impl Sealed {
    /// Split an optional sealed value into the `(Option<&[u8]>, key_version)` a DB
    /// writer binds. `None` maps to `(None, 1)` — the column default — so a caller
    /// with an optional secret binds a version uniformly (the version is moot when
    /// the bytes are null).
    pub fn split(o: &Option<Sealed>) -> (Option<&[u8]>, i16) {
        match o {
            Some(s) => (Some(&s.bytes), s.key_version),
            None => (None, KV_LEGACY),
        }
    }
}

/// The one deployment-wide legacy key (`FLUIDBOX_CREDENTIAL_KEY`). Seals/opens v1
/// blobs exactly as pre-Phase-D.
struct LegacyKey {
    key: Key,
}

impl LegacyKey {
    /// Accepts a 32-byte key as 64 hex chars or standard base64.
    fn from_key_string(s: &str) -> anyhow::Result<Self> {
        let s = s.trim();
        let bytes = match hex::decode(s) {
            Ok(b) => b,
            Err(_) => {
                use base64::Engine;
                base64::engine::general_purpose::STANDARD
                    .decode(s)
                    .map_err(|_| anyhow::anyhow!("FLUIDBOX_CREDENTIAL_KEY must be hex or base64"))?
            }
        };
        let key: [u8; 32] = bytes.try_into().map_err(|b: Vec<u8>| {
            anyhow::anyhow!(
                "FLUIDBOX_CREDENTIAL_KEY must decode to 32 bytes (got {})",
                b.len()
            )
        })?;
        Ok(Self {
            key: Key::from(key),
        })
    }

    /// v1: `nonce(24) || ct`, fresh random nonce, no AAD.
    fn seal(&self, plaintext: &str) -> Vec<u8> {
        let cipher = XChaCha20Poly1305::new(&self.key);
        let mut nonce_bytes = [0u8; NONCE_LEN];
        getrandom::fill(&mut nonce_bytes).expect("OS RNG is available");
        let nonce = XNonce::from(nonce_bytes);
        let ct = cipher
            .encrypt(&nonce, plaintext.as_bytes())
            .expect("XChaCha20Poly1305 encrypt is infallible for in-memory data");
        let mut out = Vec::with_capacity(NONCE_LEN + ct.len());
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&ct);
        out
    }

    /// Error messages stay generic on purpose — never echo key or payload.
    fn open(&self, sealed: &[u8]) -> anyhow::Result<String> {
        if sealed.len() <= NONCE_LEN {
            anyhow::bail!("sealed credential is malformed");
        }
        let (nonce, ct) = sealed.split_at(NONCE_LEN);
        let nonce: [u8; NONCE_LEN] = nonce.try_into().expect("split_at guarantees length");
        let cipher = XChaCha20Poly1305::new(&self.key);
        let pt = cipher
            .decrypt(&XNonce::from(nonce), ct)
            .map_err(|_| anyhow::anyhow!("credential unseal failed (wrong key or corrupt data)"))?;
        String::from_utf8(pt).map_err(|_| anyhow::anyhow!("sealed credential is malformed"))
    }
}

struct SealerInner {
    /// Present whenever `FLUIDBOX_CREDENTIAL_KEY` is set; the ONLY way to open v1
    /// blobs. Absent post-retirement (D4 boot gate proved zero v1 rows first).
    legacy: Option<LegacyKey>,
    /// Present whenever `FLUIDBOX_KMS_MODE` is static|aws; enables v2 seals.
    kms: Option<KmsBackend>,
    /// The tenant whose DEK seals TRANSIT tokens (see [`Sealer::seal_token`]) in
    /// KMS mode. Transit tokens are deployment-level and their owning tenant is
    /// NOT knowable at open time (it rides INSIDE the sealed blob, or is absent),
    /// so a single fixed tenant must key them — the always-present boot/seed
    /// tenant (a real `tenants` row, satisfying the `tenant_deks` FK). Unused in
    /// KMS-off mode (transit tokens seal legacy there).
    deployment_tenant: Uuid,
}

/// Seals/unseals credentials. Cheap to clone (Arc'd inner, shared DEK cache).
#[derive(Clone)]
pub struct Sealer {
    inner: Arc<SealerInner>,
}

impl Sealer {
    /// Legacy-only sealer (KMS off): seals v1, opens v1. Test-only constructor —
    /// production builds the sealer via [`build_sealer`] (which uses the private
    /// `LegacyKey`); the transit-token and legacy-crypto unit tests across modules
    /// build one directly.
    #[cfg(test)]
    pub fn from_key_string(s: &str) -> anyhow::Result<Self> {
        Ok(Self {
            inner: Arc::new(SealerInner {
                legacy: Some(LegacyKey::from_key_string(s)?),
                kms: None,
                deployment_tenant: Uuid::nil(),
            }),
        })
    }

    /// Test-only: a Sealer carrying BOTH the legacy key and a static-KEK KMS
    /// backend over a REAL (connected) pool — exactly what the re-seal job holds
    /// (open v1 with the legacy key, seal v2 under a per-tenant DEK). Production
    /// builds this via [`build_sealer`]; `reseal.rs`'s DB-backed job-core tests
    /// build one directly since the private inner is module-scoped.
    #[cfg(test)]
    pub fn for_test_static_kms(
        legacy: Option<&str>,
        static_kek: &str,
        pool: PgPool,
        deployment_tenant: Uuid,
    ) -> anyhow::Result<Self> {
        let wrapper: Arc<dyn KeyWrapper> = Arc::new(StaticKek::from_key_string(static_kek)?);
        Ok(Self {
            inner: Arc::new(SealerInner {
                legacy: legacy.map(LegacyKey::from_key_string).transpose()?,
                kms: Some(KmsBackend {
                    wrapper,
                    pool,
                    cache: Arc::new(DekCache::default()),
                }),
                deployment_tenant,
            }),
        })
    }

    /// Seal a durable custody value. KMS off → v1 (`key_version = 1`); KMS on → v2
    /// under the tenant's DEK (`key_version = 2`). The returned `key_version` MUST
    /// be persisted in the column's companion so [`open`](Self::open) can dispatch.
    pub async fn seal(&self, plaintext: &str, ctx: SealCtx) -> anyhow::Result<Sealed> {
        match &self.inner.kms {
            None => {
                let legacy = self
                    .inner
                    .legacy
                    .as_ref()
                    .context("sealing is disabled (no key configured)")?;
                Ok(Sealed {
                    bytes: legacy.seal(plaintext),
                    key_version: KV_LEGACY,
                })
            }
            Some(kms) => {
                let dek =
                    kms::dek_for_seal(&kms.pool, kms.wrapper.as_ref(), &kms.cache, ctx.tenant_id)
                        .await?;
                let aad = aad_for(ctx.tenant_id, ctx.family);
                Ok(Sealed {
                    bytes: seal_with_dek(&dek, DEK_VERSION as u32, &aad, plaintext),
                    key_version: KV_ENVELOPE,
                })
            }
        }
    }

    /// Open a durable custody value given its stored companion `key_version`.
    /// Fails closed on every incoherence: a v1 blob with the legacy key absent, a
    /// v2 blob with KMS off, a missing DEK, or an unknown version.
    pub async fn open(
        &self,
        sealed: &[u8],
        key_version: i16,
        ctx: SealCtx,
    ) -> anyhow::Result<String> {
        match key_version {
            KV_LEGACY => {
                let legacy = self.inner.legacy.as_ref().context(
                    "a v1 (legacy) sealed blob was found but FLUIDBOX_CREDENTIAL_KEY is not set — \
                     restore the legacy key",
                )?;
                legacy.open(sealed)
            }
            KV_ENVELOPE => {
                let kms = self.inner.kms.as_ref().context(
                    "a v2 (envelope) sealed blob was found but FLUIDBOX_KMS_MODE=off — set \
                     FLUIDBOX_KMS_MODE (static|aws) and provide the KEK",
                )?;
                let dek_version = envelope_dek_version(sealed)?;
                let dek = kms::dek_for_open(
                    &kms.pool,
                    kms.wrapper.as_ref(),
                    &kms.cache,
                    ctx.tenant_id,
                    dek_version as i32,
                )
                .await?;
                let aad = aad_for(ctx.tenant_id, ctx.family);
                open_with_dek(&dek, &aad, sealed)
            }
            other => anyhow::bail!("unknown sealed key version {other}"),
        }
    }

    /// Self-describing ephemeral TRANSIT-token sealing — github_app flow tokens
    /// and oauth/login `state` params, NOT durable custody. These wire values have
    /// NO companion `_key_version` column, so the version rides IN-BAND: KMS off →
    /// legacy `nonce||ct`; KMS on → the v2 envelope under the DEPLOYMENT tenant's
    /// DEK (`deployment_tenant`; the token's own owning tenant is not knowable at
    /// open time — it rides inside the blob or is absent — so a single fixed tenant
    /// must key them). [`open_token`](Self::open_token) dispatches on the first
    /// byte and, on ANY v2 parse/decrypt failure, falls back to the legacy open IFF
    /// the legacy key is present. That bounded fallback is acceptable ONLY here —
    /// these tokens live minutes (TTL), so a KMS mode flip mid-flow just makes the
    /// user restart the flow. Stored custody columns NEVER first-byte-dispatch:
    /// their version is the companion column (D1).
    pub async fn seal_token(&self, plaintext: &str) -> anyhow::Result<Vec<u8>> {
        match &self.inner.kms {
            None => {
                let legacy = self
                    .inner
                    .legacy
                    .as_ref()
                    .context("token sealing is disabled (no key configured)")?;
                Ok(legacy.seal(plaintext))
            }
            Some(kms) => {
                let dek = kms::dek_for_seal(
                    &kms.pool,
                    kms.wrapper.as_ref(),
                    &kms.cache,
                    self.inner.deployment_tenant,
                )
                .await?;
                Ok(seal_with_dek(
                    &dek,
                    DEK_VERSION as u32,
                    TRANSIT_AAD,
                    plaintext,
                ))
            }
        }
    }

    /// Open an ephemeral transit token (see [`seal_token`](Self::seal_token)).
    pub async fn open_token(&self, sealed: &[u8]) -> anyhow::Result<String> {
        // v2 path when the blob announces itself AND KMS is available. Any failure
        // (parse, missing DEK, decrypt) falls through to the bounded legacy open.
        if sealed.first() == Some(&V2_TAG) {
            if let Some(kms) = &self.inner.kms {
                if let Ok(v) = envelope_dek_version(sealed) {
                    if let Ok(dek) = kms::dek_for_open(
                        &kms.pool,
                        kms.wrapper.as_ref(),
                        &kms.cache,
                        self.inner.deployment_tenant,
                        v as i32,
                    )
                    .await
                    {
                        if let Ok(pt) = open_with_dek(&dek, TRANSIT_AAD, sealed) {
                            return Ok(pt);
                        }
                    }
                }
            }
        }
        // Legacy: either byte0 != 0x02, or a v2 attempt that failed (a legacy blob
        // whose random nonce happened to start with 0x02, during a mode flip).
        let legacy = self
            .inner
            .legacy
            .as_ref()
            .context("token failed verification")?;
        legacy.open(sealed)
    }
}

/// Build the sealer from config (Phase D). Returns `None` — sealing disabled,
/// today's behavior — ONLY when KMS is off AND `FLUIDBOX_CREDENTIAL_KEY` is
/// absent. Enforces the config-level D4 gate: a mode set without its required key
/// fails boot naming the variable. The row-count retirement gates run separately
/// in [`check_retirement_gates`] (they need the DB). `deployment_tenant` is the
/// boot/seed tenant whose DEK keys transit tokens in KMS mode (see
/// [`Sealer::seal_token`]) — a real, always-present `tenants` row.
pub fn build_sealer(
    cfg: &Config,
    pool: &PgPool,
    deployment_tenant: Uuid,
) -> anyhow::Result<Option<Sealer>> {
    let legacy = match &cfg.credential_key {
        Some(k) => Some(LegacyKey::from_key_string(k)?),
        None => None,
    };
    let kms = match cfg.kms_mode {
        KmsMode::Off => None,
        KmsMode::Static => {
            let kek = cfg.kms_static_kek.as_deref().context(
                "FLUIDBOX_KMS_MODE=static requires FLUIDBOX_KMS_STATIC_KEK (32-byte hex/base64)",
            )?;
            let wrapper: Arc<dyn KeyWrapper> = Arc::new(StaticKek::from_key_string(kek)?);
            Some(KmsBackend {
                wrapper,
                pool: pool.clone(),
                cache: Arc::new(DekCache::default()),
            })
        }
        KmsMode::Aws => {
            let key_id = cfg
                .kms_aws_key_id
                .clone()
                .context("FLUIDBOX_KMS_MODE=aws requires FLUIDBOX_KMS_AWS_KEY_ID")?;
            let wrapper: Arc<dyn KeyWrapper> =
                Arc::new(AwsKms::new(key_id, cfg.kms_aws_endpoint.clone()));
            Some(KmsBackend {
                wrapper,
                pool: pool.clone(),
                cache: Arc::new(DekCache::default()),
            })
        }
    };
    if kms.is_none() && legacy.is_none() {
        return Ok(None);
    }
    Ok(Some(Sealer {
        inner: Arc::new(SealerInner {
            legacy,
            kms,
            deployment_tenant,
        }),
    }))
}

/// D4 retirement boot gates (the DB-backed half; the config half is in
/// [`build_sealer`]). Refuses boot when sealing state and stored custody are
/// incoherent, so a misconfigured deployment fails loud rather than orphaning or
/// silently dropping credentials.
pub async fn check_retirement_gates(cfg: &Config, pool: &PgPool) -> anyhow::Result<()> {
    let kms_on = cfg.kms_mode != KmsMode::Off;
    let legacy_present = cfg.credential_key.is_some();

    if kms_on && !legacy_present {
        // (a) KMS on, legacy retired: every row MUST be v2 — a leftover v1 row is
        // unreadable now. Refuse with per-family legacy counts.
        let counts = fluidbox_db::system_worker::sealed_key_version_counts(pool).await?;
        let stragglers: Vec<_> = counts.iter().filter(|c| c.legacy > 0).collect();
        if !stragglers.is_empty() {
            let total: i64 = stragglers.iter().map(|c| c.legacy).sum();
            let detail = stragglers
                .iter()
                .map(|c| format!("{}={}", c.family, c.legacy))
                .collect::<Vec<_>>()
                .join(", ");
            anyhow::bail!(
                "FLUIDBOX_KMS_MODE is on but FLUIDBOX_CREDENTIAL_KEY is absent while {total} \
                 legacy (v1) sealed row(s) remain — they are now unreadable. Run the re-seal job \
                 to completion (parity zero) before retiring the legacy key. Per-family: {detail}"
            );
        }
    } else if !kms_on && legacy_present {
        // (b) KMS off, legacy present: a v2 row can't be opened without KMS. A
        // rollback to legacy-only with KMS-sealed custody is broken custody.
        let counts = fluidbox_db::system_worker::sealed_key_version_counts(pool).await?;
        let stragglers: Vec<_> = counts.iter().filter(|c| c.envelope > 0).collect();
        if !stragglers.is_empty() {
            let total: i64 = stragglers.iter().map(|c| c.envelope).sum();
            let detail = stragglers
                .iter()
                .map(|c| format!("{}={}", c.family, c.envelope))
                .collect::<Vec<_>>()
                .join(", ");
            anyhow::bail!(
                "FLUIDBOX_KMS_MODE=off but {total} v2 (envelope) sealed row(s) exist that only KMS \
                 can open — re-enable FLUIDBOX_KMS_MODE. Rolling back to legacy-only with \
                 KMS-sealed custody would orphan them. Per-family: {detail}"
            );
        }
    }
    Ok(())
}

// ─── pure envelope helpers (unit-tested without a DB) ───────────────────────

fn aad_for(tenant_id: Uuid, family: SealFamily) -> String {
    format!("fbx:v2:{tenant_id}:{family}")
}

/// v2 layout: `[0x02][dek_version u32 BE][nonce 24][ct]`.
fn seal_with_dek(dek: &[u8; 32], dek_version: u32, aad: &str, plaintext: &str) -> Vec<u8> {
    let cipher = XChaCha20Poly1305::new(&Key::from(*dek));
    let mut nonce = [0u8; NONCE_LEN];
    getrandom::fill(&mut nonce).expect("OS RNG is available");
    let ct = cipher
        .encrypt(
            &XNonce::from(nonce),
            Payload {
                msg: plaintext.as_bytes(),
                aad: aad.as_bytes(),
            },
        )
        .expect("XChaCha20Poly1305 encrypt is infallible for in-memory data");
    let mut out = Vec::with_capacity(V2_HEADER_LEN + NONCE_LEN + ct.len());
    out.push(V2_TAG);
    out.extend_from_slice(&dek_version.to_be_bytes());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    out
}

fn open_with_dek(dek: &[u8; 32], aad: &str, blob: &[u8]) -> anyhow::Result<String> {
    // tag(1) + version(4) + nonce(24) + tag/ct(>=16).
    if blob.len() < V2_HEADER_LEN + NONCE_LEN + 16 || blob[0] != V2_TAG {
        anyhow::bail!("sealed blob is malformed");
    }
    let nonce_start = V2_HEADER_LEN;
    let ct_start = nonce_start + NONCE_LEN;
    let nonce: [u8; NONCE_LEN] = blob[nonce_start..ct_start]
        .try_into()
        .expect("checked length");
    let ct = &blob[ct_start..];
    let cipher = XChaCha20Poly1305::new(&Key::from(*dek));
    let pt = cipher
        .decrypt(
            &XNonce::from(nonce),
            Payload {
                msg: ct,
                aad: aad.as_bytes(),
            },
        )
        .map_err(|_| anyhow::anyhow!("credential unseal failed (wrong key or corrupt data)"))?;
    String::from_utf8(pt).map_err(|_| anyhow::anyhow!("sealed credential is malformed"))
}

/// Read the declared `dek_version` from a v2 blob header (fail closed on a blob
/// too short or missing the sanity tag).
fn envelope_dek_version(blob: &[u8]) -> anyhow::Result<u32> {
    if blob.len() < V2_HEADER_LEN + NONCE_LEN + 16 || blob[0] != V2_TAG {
        anyhow::bail!("sealed blob is malformed");
    }
    Ok(u32::from_be_bytes([blob[1], blob[2], blob[3], blob[4]]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kms::StaticKek;

    fn ctx() -> SealCtx {
        SealCtx::new(Uuid::now_v7(), SealFamily::ConnectionCredential)
    }

    // A Sealer with a KMS backend over a NON-connected (lazy) pool. The tests
    // using it exercise only paths that resolve before any DB access (v1 open
    // with the legacy key absent), so the pool is never touched.
    fn sealer_with_static_kms(legacy: Option<&str>) -> Sealer {
        let pool = sqlx::postgres::PgPoolOptions::new()
            .connect_lazy("postgres://user:pass@127.0.0.1:5432/placeholder")
            .expect("lazy pool builds without connecting");
        let wrapper: Arc<dyn KeyWrapper> =
            Arc::new(StaticKek::from_key_string(&"11".repeat(32)).unwrap());
        Sealer {
            inner: Arc::new(SealerInner {
                legacy: legacy.map(|k| LegacyKey::from_key_string(k).unwrap()),
                kms: Some(KmsBackend {
                    wrapper,
                    pool,
                    cache: Arc::new(DekCache::default()),
                }),
                deployment_tenant: Uuid::nil(),
            }),
        }
    }

    // ─── pure v2 envelope surface ───────────────────────────────────────────

    #[test]
    fn v2_envelope_roundtrip_and_layout() {
        let dek = [7u8; 32];
        let aad = aad_for(Uuid::nil(), SealFamily::ConnectionCredential);
        let blob = seal_with_dek(&dek, 1, &aad, "ghp_notARealToken");
        // Self-describing header: sanity tag + version.
        assert_eq!(blob[0], V2_TAG);
        assert_eq!(envelope_dek_version(&blob).unwrap(), 1);
        // Ciphertext never contains the plaintext.
        assert!(!String::from_utf8_lossy(&blob).contains("notARealToken"));
        assert_eq!(
            open_with_dek(&dek, &aad, &blob).unwrap(),
            "ghp_notARealToken"
        );
    }

    #[test]
    fn v2_aad_tenant_transplant_refused() {
        let dek = [7u8; 32];
        let a = aad_for(Uuid::now_v7(), SealFamily::ConnectionCredential);
        let b = aad_for(Uuid::now_v7(), SealFamily::ConnectionCredential);
        let blob = seal_with_dek(&dek, 1, &a, "secret");
        // Right DEK, wrong tenant in the AAD → open fails.
        assert!(open_with_dek(&dek, &b, &blob).is_err());
    }

    #[test]
    fn v2_aad_family_transplant_refused() {
        let dek = [7u8; 32];
        let tenant = Uuid::now_v7();
        let a = aad_for(tenant, SealFamily::ConnectionCredential);
        let b = aad_for(tenant, SealFamily::ConnectionWebhookSecret);
        let blob = seal_with_dek(&dek, 1, &a, "secret");
        // Right DEK + tenant, wrong family in the AAD → open fails.
        assert!(open_with_dek(&dek, &b, &blob).is_err());
    }

    #[test]
    fn v2_wrong_dek_refused() {
        let aad = aad_for(Uuid::nil(), SealFamily::ConnectionCredential);
        let blob = seal_with_dek(&[7u8; 32], 1, &aad, "secret");
        assert!(open_with_dek(&[8u8; 32], &aad, &blob).is_err());
    }

    #[test]
    fn v2_tampered_or_truncated_refused() {
        let dek = [7u8; 32];
        let aad = aad_for(Uuid::nil(), SealFamily::ConnectionCredential);
        let mut blob = seal_with_dek(&dek, 1, &aad, "secret");
        let last = blob.len() - 1;
        blob[last] ^= 0x01;
        assert!(open_with_dek(&dek, &aad, &blob).is_err());
        assert!(open_with_dek(&dek, &aad, &[V2_TAG; 10]).is_err());
        assert!(envelope_dek_version(&[V2_TAG; 3]).is_err());
    }

    // ─── Sealer dispatch (no pool touched) ──────────────────────────────────

    #[tokio::test]
    async fn legacy_seal_open_roundtrip_kms_off() {
        let s = Sealer::from_key_string(&"ab".repeat(32)).unwrap();
        let sealed = s.seal("ghp_notARealToken", ctx()).await.unwrap();
        assert_eq!(sealed.key_version, KV_LEGACY);
        // v1 blobs carry no envelope tag structure (nonce is random 24 bytes).
        assert_eq!(
            sealed.bytes.len(),
            NONCE_LEN + "ghp_notARealToken".len() + 16
        );
        assert_eq!(
            s.open(&sealed.bytes, KV_LEGACY, ctx()).await.unwrap(),
            "ghp_notARealToken"
        );
    }

    #[tokio::test]
    async fn kms_off_refuses_v2_blob_and_unknown_version() {
        let s = Sealer::from_key_string(&"ab".repeat(32)).unwrap();
        // A v2-shaped blob with KMS off → hard error naming the fix.
        let fake_v2 = {
            let mut b = vec![V2_TAG, 0, 0, 0, 1];
            b.extend_from_slice(&[0u8; NONCE_LEN + 16]);
            b
        };
        let err = s
            .open(&fake_v2, KV_ENVELOPE, ctx())
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("FLUIDBOX_KMS_MODE"), "got: {err}");
        // Unknown version → refused.
        assert!(s.open(&fake_v2, 99, ctx()).await.is_err());
    }

    #[tokio::test]
    async fn tampered_and_wrong_key_fail_closed_kms_off() {
        let s = Sealer::from_key_string(&"ab".repeat(32)).unwrap();
        let mut sealed = s.seal("secret", ctx()).await.unwrap();
        let last = sealed.bytes.len() - 1;
        sealed.bytes[last] ^= 0x01;
        assert!(s.open(&sealed.bytes, KV_LEGACY, ctx()).await.is_err());
        assert!(s.open(&[0u8; 10], KV_LEGACY, ctx()).await.is_err());

        let good = Sealer::from_key_string(&"ab".repeat(32)).unwrap();
        let other = Sealer::from_key_string(&"cd".repeat(32)).unwrap();
        let blob = good.seal("secret", ctx()).await.unwrap();
        assert!(other.open(&blob.bytes, KV_LEGACY, ctx()).await.is_err());
    }

    #[tokio::test]
    async fn legacy_absent_v1_open_refused() {
        // KMS on, legacy key absent (post-retirement): a v1 blob is unreadable and
        // refuses BEFORE any DB access (the lazy pool is never touched).
        let s = sealer_with_static_kms(None);
        let err = s
            .open(&[0u8; NONCE_LEN + 16], KV_LEGACY, ctx())
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("FLUIDBOX_CREDENTIAL_KEY"), "got: {err}");
    }

    #[test]
    fn key_parsing_hex_and_base64() {
        use base64::Engine;
        let raw = [7u8; 32];
        let hex_key = hex::encode(raw);
        let b64_key = base64::engine::general_purpose::STANDARD.encode(raw);
        // Same key bytes → interoperable legacy keys.
        let a = LegacyKey::from_key_string(&hex_key).unwrap();
        let b = LegacyKey::from_key_string(&b64_key).unwrap();
        assert_eq!(b.open(&a.seal("x")).unwrap(), "x");
        // Wrong lengths are rejected.
        assert!(LegacyKey::from_key_string("deadbeef").is_err());
        assert!(LegacyKey::from_key_string("not-a-key!").is_err());
    }

    #[test]
    fn family_display_is_table_dot_column() {
        assert_eq!(
            SealFamily::ConnectionCredential.to_string(),
            "integration_connections.credential_sealed"
        );
        assert_eq!(
            SealFamily::LoginPkceVerifier.to_string(),
            "login_flows.pkce_verifier_sealed"
        );
    }
}
