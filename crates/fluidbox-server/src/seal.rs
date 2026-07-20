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
//!     per-tenant DEK (wrapped by a KEK backend, `kms.rs`). AAD binds the blob's
//!     own 5-byte HEADER followed by `"fbx:v2:{tenant_id}:{table.column}"`, so a
//!     blob transplanted across tenants OR families — or one whose declared
//!     dek_version was rewritten in place — fails AEAD open even under the right
//!     DEK. The leading `0x02` is an internal sanity byte only — the companion
//!     column is the discriminator. Ephemeral TRANSIT tokens (no column, no
//!     companion) bind `"fbx:v2:transit:{purpose}"` instead — same idea, purpose
//!     in the family slot (`Sealer::seal_token`).

use crate::config::{Config, KmsMode};
use crate::kms::{self, AwsKms, DekCache, KeyWrapper, KmsBackend, StaticKek, DEK_VERSION};
use anyhow::Context;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use sqlx::PgPool;
use std::sync::Arc;
use uuid::Uuid;
use zeroize::Zeroizing;

const NONCE_LEN: usize = 24;
/// Leading byte of a v2 envelope blob (internal sanity check, not the format
/// discriminator — the companion `_key_version` column is).
const V2_TAG: u8 = 0x02;
/// v2 header = tag(1) + dek_version(4). The nonce and ciphertext follow. The
/// header is AUTHENTICATED: it is the first segment of the data cipher's AAD (see
/// [`seal_with_dek`]), so its version bytes cannot be flipped after the fact.
const V2_HEADER_LEN: usize = 1 + 4;
/// Companion key-version values stored beside each sealed column.
const KV_LEGACY: i16 = 1;
const KV_ENVELOPE: i16 = 2;
/// Upper bound on a decoded TRANSIT token (review H2). Every transit payload is a
/// small JSON object (a few ids + an expiry ≈ 200 bytes); 4 KiB is far above any
/// legitimate one. Enforced BEFORE any DB/KMS work so an unauthenticated caller
/// cannot spend our resources on an oversized blob that was never going to open.
const MAX_TRANSIT_TOKEN_LEN: usize = 4096;

// AAD family segments for ephemeral transit tokens (see [`Sealer::seal_token`]).
// These are deployment-level wire values with no column family, so the AAD's
// family segment is the token's PURPOSE; their tenant binding comes from the
// deployment tenant's DEK. Distinct purposes are cryptographically
// non-interchangeable (a token sealed for one purpose fails AEAD open under
// another, even under the same DEK) — the payload discriminators each consumer
// checks are then a second, independent line rather than the only one.
/// The `login.rs` OIDC `state` parameter.
pub const TRANSIT_LOGIN: &str = "login";
/// The `oauth.rs` connector-dance boot token (`/v1/oauth/go?f=`).
pub const TRANSIT_OAUTH_BOOT: &str = "oauth-boot";
/// The `github_app.rs` flow tokens (`gh-boot` / `gh-manifest` / `gh-install`).
pub const TRANSIT_GITHUB_APP_FLOW: &str = "github-app-flow";

/// The sealed families = the sealed `table.column` pairs. `Display` renders
/// `"table.column"` — the AAD's family segment and the human label in boot-gate
/// counts. Columns 10-13 land with their tables in Tasks 3-5 (the families are
/// declared now so those tasks seal v2-natively; global rows seal under the nil
/// UUID = the deployment context — documented at those call sites).
// The last four variants have no Task-1 seal site — they belong to migrations
// 0015-0017 (Tasks 3-5). Declared here to fix the interface across tasks.
// oauth_client_registrations (Task 3) rows are deployment-global (tenant_id
// NULL); their secrets seal under the DEPLOYMENT tenant's DEK
// (`Sealer::deployment_ctx`), NOT the nil UUID — tenant_deks has a real FK.
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
/// name goes into the AAD. For deployment-global rows (Task 3's global client
/// registrations, `tenant_id` NULL) this carries the DEPLOYMENT tenant's id —
/// a real `tenants` row — via [`Sealer::deployment_ctx`], never the nil UUID
/// (`tenant_deks` has a real FK on it).
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
///
/// The key bytes live in a `Zeroizing` container (review M4): a plain `Key` is an
/// ordinary array whose bytes survive in reclaimed memory after the process drops
/// it, which contradicted the manifest's claim that key material is scrubbed. The
/// ciphers built from it zeroize their own copies on drop (`chacha20poly1305`'s
/// `zeroize` feature, enabled in the workspace manifest).
struct LegacyKey {
    key: Zeroizing<[u8; 32]>,
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
            key: Zeroizing::new(key),
        })
    }

    /// The cipher, built WITHOUT copying the key onto the stack: `new_from_slice`
    /// borrows, where `Key::from(*self.key)` would materialize an unscrubbed copy.
    fn cipher(&self) -> XChaCha20Poly1305 {
        XChaCha20Poly1305::new_from_slice(&self.key[..]).expect("a LegacyKey is 32 bytes")
    }

    /// v1: `nonce(24) || ct`, fresh random nonce, no AAD.
    fn seal(&self, plaintext: &str) -> Vec<u8> {
        let cipher = self.cipher();
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
        let cipher = self.cipher();
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
                    dek_version,
                )
                .await?;
                let aad = aad_for(ctx.tenant_id, ctx.family);
                open_with_dek(&dek, &aad, sealed)
            }
            other => anyhow::bail!("unknown sealed key version {other}"),
        }
    }

    /// The [`SealCtx`] for a deployment-global row's sealed column (`tenant_id`
    /// NULL): it seals/opens under the DEPLOYMENT tenant's DEK. A global row has
    /// no tenant of its own, and `tenant_deks` has a real FK, so the nil UUID
    /// cannot key it — the always-present boot/seed tenant does (the same tenant
    /// [`seal_token`](Self::seal_token) keys transit tokens under). Task 3's
    /// `oauth_client_registrations` are the first global family. In KMS-off mode
    /// the tenant is moot (the legacy seal ignores it).
    pub fn deployment_ctx(&self, family: SealFamily) -> SealCtx {
        SealCtx::new(self.inner.deployment_tenant, family)
    }

    /// The [`SealCtx`] for a re-sealed row given its stored `tenant_id`: a real
    /// tenant for tenant-owned families, or `None` for a deployment-global family
    /// (`oauth_client_registrations`) → the deployment tenant's DEK, exactly as
    /// [`deployment_ctx`](Self::deployment_ctx). The re-seal job resolves each
    /// row's ctx through this so a NULL-tenant global row seals under a real DEK.
    pub fn row_ctx(&self, tenant_id: Option<Uuid>, family: SealFamily) -> SealCtx {
        SealCtx::new(tenant_id.unwrap_or(self.inner.deployment_tenant), family)
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
    ///
    /// `purpose` binds the token's KIND into the AAD (`TRANSIT_LOGIN`,
    /// `TRANSIT_OAUTH_BOOT`, `TRANSIT_GITHUB_APP_FLOW`): one DEK seals all three
    /// kinds, so without it any transit token would open as any other and only the
    /// consumers' payload discriminators would separate them. `open_token` MUST be
    /// called with the same purpose.
    ///
    /// FORMAT CHANGE (Phase D final review): the v2 AAD gained the purpose
    /// segment, so a token sealed by a BUILD BEFORE this change fails to open
    /// after the upgrade (KMS mode only — legacy seals carry no AAD). That is
    /// acceptable: all three transit tokens are minutes-TTL flow tokens, so an
    /// in-flight one simply fails verification and the user restarts the flow.
    pub async fn seal_token(&self, purpose: &str, plaintext: &str) -> anyhow::Result<Vec<u8>> {
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
                    &transit_aad(purpose),
                    plaintext,
                ))
            }
        }
    }

    /// Open an ephemeral transit token (see [`seal_token`](Self::seal_token)).
    /// `purpose` MUST match the one it was sealed with — a mismatch fails the AEAD
    /// open (KMS mode) and falls through to the legacy attempt, which either has no
    /// key (refuse) or was sealed without an AAD at all (the pre-KMS posture, where
    /// the consumers' payload discriminators are the separation).
    pub async fn open_token(&self, purpose: &str, sealed: &[u8]) -> anyhow::Result<String> {
        // Bound the work an UNAUTHENTICATED caller can trigger (review H2): a
        // transit token arrives on public endpoints, so anything that cannot be a
        // legitimate token is refused HERE — before the DEK lookup that a cold
        // cache turns into a (billable) KMS Decrypt. The version check inside
        // `envelope_dek_version` + `kms::dek_for_open` is the other half.
        if sealed.len() > MAX_TRANSIT_TOKEN_LEN {
            anyhow::bail!("token failed verification");
        }
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
                        v,
                    )
                    .await
                    {
                        if let Ok(pt) = open_with_dek(&dek, &transit_aad(purpose), sealed) {
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
    let kms = build_wrapper(cfg)?.map(|wrapper| KmsBackend {
        wrapper,
        pool: pool.clone(),
        cache: Arc::new(DekCache::default()),
    });
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

/// The configured KEK backend (`None` = KMS off). Shared by [`build_sealer`] and
/// the boot-time KEK gate in [`check_retirement_gates`] so both judge exactly the
/// same configuration — a gate that validated a DIFFERENTLY-built wrapper would
/// be theater.
fn build_wrapper(cfg: &Config) -> anyhow::Result<Option<Arc<dyn KeyWrapper>>> {
    Ok(match cfg.kms_mode {
        KmsMode::Off => None,
        KmsMode::Static => {
            let kek = cfg.kms_static_kek.as_deref().context(
                "FLUIDBOX_KMS_MODE=static requires FLUIDBOX_KMS_STATIC_KEK (32-byte hex/base64)",
            )?;
            Some(Arc::new(StaticKek::from_key_string(kek)?))
        }
        KmsMode::Aws => {
            let key_id = cfg
                .kms_aws_key_id
                .clone()
                .context("FLUIDBOX_KMS_MODE=aws requires FLUIDBOX_KMS_AWS_KEY_ID")?;
            Some(Arc::new(AwsKms::new(key_id, cfg.kms_aws_endpoint.clone())))
        }
    })
}

/// D4 retirement boot gates (the DB-backed half; the config half is in
/// [`build_sealer`]). Refuses boot when sealing state and stored custody are
/// incoherent, so a misconfigured deployment fails loud rather than orphaning or
/// silently dropping credentials.
///
/// TWO independent gates run here:
///
///  1. **KEK compatibility** ([`kms::check_kek_compatibility`]) — whenever KMS is
///     configured, INDEPENDENT of the legacy key. The retirement counts below can
///     only see key VERSIONS, never which KEK wrapped the stored DEKs, so a
///     syntactically valid but WRONG KEK sailed through every quadrant: existing
///     tenants failed every unwrap while new tenants happily minted DEKs under it,
///     splitting custody across two KEKs with no recovery (review H1). This gate
///     proves the configured backend can actually READ a stored DEK before we
///     serve. Pass the already-built `sealer` and the probe runs on ITS backend and
///     ITS cache, so the one unwrap the gate performs anyway warms the live DEK
///     cache (and an `aws` deployment does not construct a second client just to
///     probe). `None` falls back to a wrapper built from the same config.
///  2. **Version retirement** — the counts are fetched ONLY when a key is missing:
///     with both keys present (the migration window) every stored version is
///     openable, so there is nothing a scan could refuse.
pub async fn check_retirement_gates(
    cfg: &Config,
    pool: &PgPool,
    sealer: Option<&Sealer>,
) -> anyhow::Result<()> {
    match sealer.and_then(|s| s.inner.kms.as_ref()) {
        Some(kms) => {
            kms::check_kek_compatibility(pool, kms.wrapper.as_ref(), Some(&kms.cache)).await?
        }
        None => {
            if let Some(wrapper) = build_wrapper(cfg)? {
                kms::check_kek_compatibility(pool, wrapper.as_ref(), None).await?;
            }
        }
    }
    let kms_on = cfg.kms_mode != KmsMode::Off;
    let legacy_present = cfg.credential_key.is_some();
    if kms_on && legacy_present {
        return Ok(());
    }
    let counts = fluidbox_db::system_worker::sealed_key_version_counts(pool).await?;
    if let Some(msg) = retirement_refusal(kms_on, legacy_present, &counts) {
        anyhow::bail!(msg);
    }
    Ok(())
}

/// The PURE half of the retirement gate (unit-tested without a DB): the refusal
/// message for a sealing posture + the per-family key-version counts, or `None`
/// to boot.
///
/// TWO INDEPENDENT checks, deliberately NOT an if/else chain — each key's absence
/// is judged on its own, so all FOUR config quadrants are covered:
///   - legacy key absent + v1 rows exist → refuse (unreadable), whatever KMS does;
///   - KMS off + v2 rows exist → refuse (unreadable), whatever the legacy key does.
///
/// The chain this replaced left `!kms_on && !legacy_present` unchecked, so dropping
/// BOTH variables on a KMS deployment booted "successfully" with every stored
/// credential unreadable behind a "connections disabled" warning. Both checks are
/// no-ops on a healthy deployment, and the `kms_on && legacy_present` migration
/// window never reaches here at all.
fn retirement_refusal(
    kms_on: bool,
    legacy_present: bool,
    counts: &[fluidbox_db::system_worker::FamilyKeyVersionCounts],
) -> Option<String> {
    fn tally(rows: impl Iterator<Item = (String, i64)>) -> Option<(i64, String)> {
        let present: Vec<(String, i64)> = rows.filter(|(_, n)| *n > 0).collect();
        if present.is_empty() {
            return None;
        }
        let total = present.iter().map(|(_, n)| *n).sum();
        let detail = present
            .iter()
            .map(|(f, n)| format!("{f}={n}"))
            .collect::<Vec<_>>()
            .join(", ");
        Some((total, detail))
    }
    // (a) The legacy key is gone: every v1 row is unreadable NOW — whether KMS is
    // on (the retirement path: re-seal first) or off (sealing disabled entirely).
    if !legacy_present {
        if let Some((total, detail)) = tally(counts.iter().map(|c| (c.family.clone(), c.legacy))) {
            return Some(format!(
                "FLUIDBOX_CREDENTIAL_KEY is absent while {total} legacy (v1) sealed row(s) remain \
                 — they are now unreadable. Restore the legacy key; on a KMS deployment, run the \
                 re-seal job to completion (parity zero) BEFORE retiring it. Per-family: {detail}"
            ));
        }
    }
    // (b) KMS is off: every v2 row is unreadable NOW — whether the legacy key is
    // present (a rollback to legacy-only) or absent (both dropped).
    if !kms_on {
        if let Some((total, detail)) = tally(counts.iter().map(|c| (c.family.clone(), c.envelope)))
        {
            return Some(format!(
                "FLUIDBOX_KMS_MODE=off but {total} v2 (envelope) sealed row(s) exist that only KMS \
                 can open — set FLUIDBOX_KMS_MODE (static|aws) and provide its KEK. Rolling back \
                 to legacy-only with KMS-sealed custody would orphan them. Per-family: {detail}"
            ));
        }
    }
    None
}

// ─── pure envelope helpers (unit-tested without a DB) ───────────────────────

fn aad_for(tenant_id: Uuid, family: SealFamily) -> String {
    format!("fbx:v2:{tenant_id}:{family}")
}

/// AAD for an ephemeral transit token of a given purpose. The purpose takes the
/// family segment's place (transit tokens have no column family) so distinct
/// kinds of transit token cannot open as one another (see
/// [`Sealer::seal_token`]).
fn transit_aad(purpose: &str) -> String {
    format!("fbx:v2:transit:{purpose}")
}

/// The data cipher's AAD for a v2 blob: the 5-byte HEADER followed by the context
/// string (`fbx:v2:{tenant}:{family}` or `fbx:v2:transit:{purpose}`).
///
/// Binding the header (review L6) is what makes the declared `dek_version`
/// TRUSTWORTHY. Before this, the version bytes rode outside the AEAD entirely: a
/// database-write attacker could flip them and — combined with a wrapped DEK moved
/// between version rows — have the same raw DEK selected while the ciphertext
/// still opened, so the format's own version metadata proved nothing. Now a
/// single flipped header bit changes the AAD and the open fails.
fn v2_payload_aad(header: &[u8], ctx: &str) -> Vec<u8> {
    let mut aad = Vec::with_capacity(header.len() + ctx.len());
    aad.extend_from_slice(header);
    aad.extend_from_slice(ctx.as_bytes());
    aad
}

/// v2 layout: `[0x02][dek_version u32 BE][nonce 24][ct]`; the header is
/// authenticated as the AAD prefix.
fn seal_with_dek(dek: &[u8; 32], dek_version: u32, aad: &str, plaintext: &str) -> Vec<u8> {
    // new_from_slice BORROWS the key — Key::from(*dek) would copy it onto the
    // stack where nothing scrubs it (review M4).
    let cipher = XChaCha20Poly1305::new_from_slice(&dek[..]).expect("a DEK is 32 bytes");
    let mut header = [0u8; V2_HEADER_LEN];
    header[0] = V2_TAG;
    header[1..].copy_from_slice(&dek_version.to_be_bytes());
    let mut nonce = [0u8; NONCE_LEN];
    getrandom::fill(&mut nonce).expect("OS RNG is available");
    let ct = cipher
        .encrypt(
            &XNonce::from(nonce),
            Payload {
                msg: plaintext.as_bytes(),
                aad: &v2_payload_aad(&header, aad),
            },
        )
        .expect("XChaCha20Poly1305 encrypt is infallible for in-memory data");
    let mut out = Vec::with_capacity(V2_HEADER_LEN + NONCE_LEN + ct.len());
    out.extend_from_slice(&header);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    out
}

fn open_with_dek(dek: &[u8; 32], aad: &str, blob: &[u8]) -> anyhow::Result<String> {
    // tag(1) + version(4) + nonce(24) + tag/ct(>=16).
    if blob.len() < V2_HEADER_LEN + NONCE_LEN + 16 || blob[0] != V2_TAG {
        anyhow::bail!("sealed blob is malformed");
    }
    let header = &blob[..V2_HEADER_LEN];
    let ct_start = V2_HEADER_LEN + NONCE_LEN;
    let nonce: [u8; NONCE_LEN] = blob[V2_HEADER_LEN..ct_start]
        .try_into()
        .expect("checked length");
    let ct = &blob[ct_start..];
    let cipher = XChaCha20Poly1305::new_from_slice(&dek[..]).expect("a DEK is 32 bytes");
    let pt = cipher
        .decrypt(
            &XNonce::from(nonce),
            Payload {
                msg: ct,
                // The header the blob CARRIES is authenticated, so a tampered
                // version (or tag) fails the open rather than silently selecting a
                // different DEK.
                aad: &v2_payload_aad(header, aad),
            },
        )
        .map_err(|_| anyhow::anyhow!("credential unseal failed (wrong key or corrupt data)"))?;
    String::from_utf8(pt).map_err(|_| anyhow::anyhow!("sealed credential is malformed"))
}

/// Read the declared `dek_version` from a v2 blob header (fail closed on a blob
/// too short, missing the sanity tag, or declaring an impossible version).
/// Returns the DB-side type (`i32`, the `tenant_deks.version` column): a header
/// declaring a value above `i32::MAX` is MALFORMED, not a negative version — a
/// bare `as i32` cast turned `0xFFFFFFFE` into a lookup for version `-2` and
/// failed with a confusing "no DEK for version -2147483648"-style message instead
/// of naming the real problem. Version 0 is likewise MALFORMED, not "an old
/// version" (review L6): DEK versions start at 1, so a zero header is a forged or
/// corrupt blob and is refused before any DB/KMS access.
fn envelope_dek_version(blob: &[u8]) -> anyhow::Result<i32> {
    if blob.len() < V2_HEADER_LEN + NONCE_LEN + 16 || blob[0] != V2_TAG {
        anyhow::bail!("sealed blob is malformed");
    }
    let raw = u32::from_be_bytes([blob[1], blob[2], blob[3], blob[4]]);
    let v = i32::try_from(raw).map_err(|_| anyhow::anyhow!("sealed blob is malformed"))?;
    if v < kms::MIN_DEK_VERSION {
        anyhow::bail!("sealed blob is malformed");
    }
    Ok(v)
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

    #[test]
    fn v2_out_of_range_dek_version_is_malformed() {
        // A header declaring a version above i32::MAX is MALFORMED — never a
        // negative version handed to the DEK lookup.
        let mut blob = seal_with_dek(&[7u8; 32], 1, "aad", "secret");
        blob[1..5].copy_from_slice(&u32::MAX.to_be_bytes());
        let err = envelope_dek_version(&blob).unwrap_err().to_string();
        assert!(err.contains("malformed"), "got: {err}");
        // Version 0 is not "an old version" — DEK versions start at 1 (review L6).
        blob[1..5].copy_from_slice(&0u32.to_be_bytes());
        assert!(envelope_dek_version(&blob).is_err(), "version 0 is refused");
        // The largest representable version is still readable.
        blob[1..5].copy_from_slice(&(i32::MAX as u32).to_be_bytes());
        assert_eq!(envelope_dek_version(&blob).unwrap(), i32::MAX);
    }

    #[test]
    fn v2_header_is_authenticated() {
        // Review L6: the version bytes ride OUTSIDE the ciphertext, so they must be
        // authenticated as AAD. Flipping the declared version (a database-write
        // attacker's move, paired with a wrapped DEK copied between version rows)
        // must break the open, not silently select a different DEK.
        let dek = [7u8; 32];
        let aad = aad_for(Uuid::nil(), SealFamily::ConnectionCredential);
        let good = seal_with_dek(&dek, 1, &aad, "secret");
        assert_eq!(open_with_dek(&dek, &aad, &good).unwrap(), "secret");
        let mut tampered = good.clone();
        tampered[1..5].copy_from_slice(&2u32.to_be_bytes());
        assert!(
            open_with_dek(&dek, &aad, &tampered).is_err(),
            "a flipped dek_version must fail the AEAD open"
        );
        // Two blobs of the same plaintext under different declared versions are
        // NOT interchangeable — the header is part of what is authenticated.
        let v2 = seal_with_dek(&dek, 2, &aad, "secret");
        let mut swapped = v2.clone();
        swapped[1..5].copy_from_slice(&1u32.to_be_bytes());
        assert!(open_with_dek(&dek, &aad, &swapped).is_err());
    }

    #[test]
    fn v2_transit_purpose_transplant_refused() {
        // One DEK seals every transit token, so the AAD's purpose segment is the
        // ONLY thing making a login state and an oauth boot token cryptographically
        // distinct: a blob sealed for one purpose must not open under another.
        let dek = [7u8; 32];
        let blob = seal_with_dek(&dek, 1, &transit_aad(TRANSIT_LOGIN), "state");
        assert_eq!(
            open_with_dek(&dek, &transit_aad(TRANSIT_LOGIN), &blob).unwrap(),
            "state"
        );
        for other in [TRANSIT_OAUTH_BOOT, TRANSIT_GITHUB_APP_FLOW] {
            assert!(
                open_with_dek(&dek, &transit_aad(other), &blob).is_err(),
                "purpose '{other}' must not open a '{TRANSIT_LOGIN}' token"
            );
        }
        // The three purposes are distinct strings under one namespace.
        let aads = [TRANSIT_LOGIN, TRANSIT_OAUTH_BOOT, TRANSIT_GITHUB_APP_FLOW]
            .map(transit_aad)
            .to_vec();
        assert!(aads.iter().all(|a| a.starts_with("fbx:v2:transit:")));
        let unique: std::collections::HashSet<_> = aads.iter().collect();
        assert_eq!(unique.len(), 3, "transit purposes must not collide");
    }

    // ─── D4 retirement gate (the pure half — all four quadrants) ────────────

    fn fam(
        name: &str,
        legacy: i64,
        envelope: i64,
    ) -> fluidbox_db::system_worker::FamilyKeyVersionCounts {
        fluidbox_db::system_worker::FamilyKeyVersionCounts {
            family: name.into(),
            legacy,
            envelope,
        }
    }

    #[test]
    fn retirement_gate_covers_every_quadrant() {
        let v1_only = vec![fam("integration_connections.credential_sealed", 3, 0)];
        let v2_only = vec![fam("integration_connections.credential_sealed", 0, 4)];
        let mixed = vec![
            fam("integration_connections.credential_sealed", 3, 0),
            fam("tenant_llm_keys.litellm_key_sealed", 0, 4),
        ];
        let empty: Vec<_> = vec![fam("integration_connections.credential_sealed", 0, 0)];

        // (1) KMS on + legacy present (the migration window): never refuses — both
        // versions are openable.
        assert!(retirement_refusal(true, true, &mixed).is_none());

        // (2) KMS on + legacy retired: a leftover v1 row is unreadable.
        let msg = retirement_refusal(true, false, &v1_only).expect("must refuse");
        assert!(msg.contains("FLUIDBOX_CREDENTIAL_KEY is absent"), "{msg}");
        assert!(
            msg.contains("integration_connections.credential_sealed=3"),
            "per-family counts: {msg}"
        );
        // Fully re-sealed → boots.
        assert!(retirement_refusal(true, false, &v2_only).is_none());

        // (3) KMS off + legacy present: a v2 row is unreadable.
        let msg = retirement_refusal(false, true, &v2_only).expect("must refuse");
        assert!(msg.contains("FLUIDBOX_KMS_MODE=off"), "{msg}");
        assert!(
            msg.contains("integration_connections.credential_sealed=4"),
            "per-family counts: {msg}"
        );
        assert!(retirement_refusal(false, true, &v1_only).is_none());

        // (4) THE PREVIOUSLY UNGUARDED QUADRANT — both dropped. Sealing is disabled
        // and EVERY stored credential is unreadable, so any sealed row refuses boot
        // instead of booting behind a "connections disabled" warning.
        assert!(retirement_refusal(false, false, &v1_only).is_some());
        assert!(retirement_refusal(false, false, &v2_only).is_some());
        assert!(retirement_refusal(false, false, &mixed).is_some());
        // …but a deployment with NO sealed custody at all still boots (sealing
        // simply stays disabled) — in every quadrant.
        for (kms_on, legacy) in [(true, true), (true, false), (false, true), (false, false)] {
            assert!(retirement_refusal(kms_on, legacy, &empty).is_none());
            assert!(retirement_refusal(kms_on, legacy, &[]).is_none());
        }
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
    async fn oversized_transit_token_refused_before_any_lookup() {
        // Review H2: `open_token` is reachable UNAUTHENTICATED, and a cold DEK cache
        // turns a lookup into a (billable) KMS Decrypt. Two guards run BEFORE the
        // lookup — the length bound and the version parse — so a blob shaped like a
        // v2 envelope but impossible on its face never reaches the DB/KMS. (The
        // helper's pool is lazy and unreachable; these paths return without it.)
        let s = sealer_with_static_kms(Some(&"ab".repeat(32)));
        let mut huge = vec![V2_TAG, 0, 0, 0, 1];
        huge.extend_from_slice(&vec![0u8; MAX_TRANSIT_TOKEN_LEN + 1]);
        assert!(s.open_token(TRANSIT_LOGIN, &huge).await.is_err());
        // A version-0 header is rejected at the parse (no DEK lookup); the only
        // path left is the bounded legacy attempt, which refuses the garbage.
        let mut zero_version = vec![V2_TAG, 0, 0, 0, 0];
        zero_version.extend_from_slice(&[0u8; NONCE_LEN + 16]);
        assert!(s.open_token(TRANSIT_LOGIN, &zero_version).await.is_err());
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
