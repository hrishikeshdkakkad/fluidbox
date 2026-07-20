//! Per-tenant LiteLLM virtual keys — the provisioning component (Phase D, #32;
//! design "Per-tenant LLM quota" :1087-1098, plan D7).
//!
//! In `FLUIDBOX_LLM_KEY_MODE=tenant` the facade presents a per-tenant LiteLLM
//! virtual key on every upstream model request, so the LiteLLM MASTER key is
//! confined to exactly ONE job: minting/deleting those virtual keys HERE. Nothing
//! else in the codebase turns the master key into an outbound credential — the
//! facade's per-call path uses the resolved virtual key (this module's output),
//! never the master (grep: `llm_upstream_key` outside `llm_keys.rs`/`config.rs` is
//! only the explicit SHARED-mode facade branch, which the SSO refusal locks out of
//! hosted deployments).
//!
//! A tenant's key is:
//!   - minted on demand (`POST {llm_admin_url}/key/generate`, master-key bearer),
//!     with the tenant's id in `metadata` + an `fbx-tenant-{uuid}` alias, and the
//!     configured spend/rate knobs only when set;
//!   - sealed at rest (`tenant_llm_keys.litellm_key_sealed`, family `TenantLlmKey`,
//!     under the tenant's OWN DEK) — never returned in an API response;
//!   - cached unsealed in memory (`AppState.tenant_llm_keys`, keyed by tenant_id),
//!     re-read from the sealed row on a cold cache / restart, evicted on rotation.
//!
//! PROVISIONING IS BOUNDED IN THREE PLACES (Phase D review H3/M4/M5), because
//! minting is reachable from an authenticated request path:
//!   - a per-tenant singleflight lock, so a stampede is ONE mint;
//!   - a durable per-tenant cooldown (the row's `coalesce(rotated_at,
//!     created_at)`) plus a deployment-wide mint budget, so repeated upstream
//!     rejections cannot re-provision in a loop;
//!   - a post-mint cleanup guard, so a key that is minted but not durably
//!     adopted is deleted rather than left live and unreferenced.
//!
//! This is the tenant-fairness BACKSTOP (each virtual key carries its own
//! spend/tpm/rpm ceiling server-side); it is NOT the per-run budget-race fix
//! (durable reservations, Phase E — design :1100-1114).

use crate::config::{Config, LlmKeyMode};
use crate::error::{ApiError, ApiResult};
use crate::seal::{SealCtx, SealFamily};
use crate::state::AppState;
use chrono::Utc;
use fluidbox_db::TenantScope;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::{Arc, LazyLock};
use std::time::{Duration, Instant};
use tokio::sync::Mutex;
use uuid::Uuid;

/// LiteLLM's `/key/generate` response field carrying the minted virtual key
/// (`sk-...`). Named once so the shape is asserted in one place (and against the
/// fake in Task 8's acceptance).
const LITELLM_KEY_FIELD: &str = "key";

/// Per-call timeout for the LiteLLM ADMIN plane (`/key/generate`, `/key/delete`).
/// `state.http` is the FACADE client — built with a 15-minute timeout because a
/// model request legitimately streams for that long — and these control-plane
/// calls must not inherit it: a hung LiteLLM admin plane would otherwise block the
/// first model request of every tenant for 15 minutes (nothing caches the failure,
/// so each retry re-hangs) and stall `create_org`'s eager mint. Mirrors `oauth.rs`'s
/// explicit `HTTP_TIMEOUT` on every outbound OAuth call.
const HTTP_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15);

/// Which credential the facade presents upstream for THIS request. A PURE decision
/// (no I/O), so the facade's branch is unit-testable without HTTP: tenant mode
/// always resolves a per-tenant virtual key; shared mode presents the deployment
/// key UNLESS SSO is on — that is the forbidden hosted posture (a routine model
/// request on a shared key), refused at the facade, never a silent shared-key
/// fallback (design :1094).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeySource {
    /// Present `cfg.llm_upstream_key` (today's behavior; local/single-admin).
    Shared,
    /// Resolve/mint the session tenant's virtual key.
    Tenant,
    /// SSO on + shared mode → refuse EVERY facade model request (503).
    RefuseSsoShared,
}

/// The pure mode decision (see [`KeySource`]).
pub fn key_source(mode: LlmKeyMode, require_sso: bool) -> KeySource {
    match (mode, require_sso) {
        (LlmKeyMode::Tenant, _) => KeySource::Tenant,
        (LlmKeyMode::Shared, true) => KeySource::RefuseSsoShared,
        (LlmKeyMode::Shared, false) => KeySource::Shared,
    }
}

/// Substrings that prove LiteLLM's OWN virtual-key check rejected the key we
/// presented (its proxy-auth layer, before any provider call). Matched
/// case-insensitively against the bounded error text.
const VIRTUAL_KEY_REJECTED_MARKERS: &[&str] = &[
    // Unknown key: "Invalid proxy server token passed. Received API Key = …,
    // Unable to find token in cache or `LiteLLM_VerificationTokenTable`".
    "invalid proxy server token",
    "unable to find token",
    "key not found",
    // Key present but no longer usable as an identity.
    "expiredkeyerror",
    "expired key",
];

/// Substrings that prove the 401 came from the GATEWAY'S OWN upstream provider
/// credential (LiteLLM maps provider exceptions into its error body), NOT from
/// our virtual key. These VETO re-provisioning: minting a new virtual key cannot
/// fix a bad `ANTHROPIC_API_KEY` inside LiteLLM, and treating it as proof was
/// exactly the amplification this guard removes (review H3).
const UPSTREAM_PROVIDER_MARKERS: &[&str] = &[
    "litellm.authenticationerror",
    "litellm.permissiondeniederror",
    "authenticationerror:",
];

/// How much of an error body is scanned. Bounds the work an upstream can force
/// and keeps a giant body from turning into a giant lowercase allocation.
const ERROR_SCAN_BYTES: usize = 8 * 1024;

/// Deployment-wide ceiling on `/key/generate` calls, and its window. A blast
/// door, not a quota: legitimate provisioning is once per tenant (plus operator
/// rotations), so any deployment approaching this is looping. Applies to EVERY
/// mint path — first use, operator rotation, and reactive recovery.
const MINT_WINDOW: Duration = Duration::from_secs(60);
const MINT_MAX_PER_WINDOW: u32 = 60;

/// A tenant's key must be at least this old before an upstream rejection may
/// re-provision it. THE bound across requests (review H3): re-minting is capped
/// at one per tenant per window no matter how many requests 401, and the stamp
/// is the DB's `coalesce(rotated_at, created_at)` — durable, shared by every
/// replica, and unaffected by a restart.
const RECOVERY_COOLDOWN_SECS: i64 = 300;

/// Per-tenant provisioning singleflight. Module-level (not `AppState`) because
/// it is an implementation detail of this module and nothing else may take it;
/// same shape as `state.rs`'s `oauth_locks` (per-key async mutex behind a map),
/// for the same reason: a stampede must not become N mints.
///
/// Cross-REPLICA races are handled durably instead — `insert_tenant_llm_key`'s
/// insert-or-adopt and `rotate_tenant_llm_key_cas`'s compare-and-swap are the
/// arbiters there; this lock only collapses the in-process stampede.
static PROVISION_LOCKS: LazyLock<Mutex<HashMap<Uuid, Arc<Mutex<()>>>>> =
    LazyLock::new(Default::default);

/// The deployment-wide mint budget (fixed window). In-process by construction —
/// it bounds what THIS replica can do to LiteLLM.
static MINT_BUDGET: LazyLock<Mutex<MintWindow>> = LazyLock::new(|| {
    Mutex::new(MintWindow {
        started: Instant::now(),
        minted: 0,
    })
});

/// Fixed-window mint counter (see [`MINT_BUDGET`]).
struct MintWindow {
    started: Instant,
    minted: u32,
}

/// The PURE window decision: `true` = a mint is allowed (and counted). Rolls the
/// window over when it has elapsed. Unit-tested without a clock or a socket.
fn try_consume_mint(win: &mut MintWindow, now: Instant, max: u32, window: Duration) -> bool {
    if now.duration_since(win.started) >= window {
        win.started = now;
        win.minted = 0;
    }
    if win.minted >= max {
        return false;
    }
    win.minted += 1;
    true
}

/// The bounded, lowercased error text a rejection decision is made on. Prefers
/// the structured message LiteLLM returns (`error.message`, or FastAPI's
/// `detail`), falling back to the raw body when it is not the shape we know.
fn error_text(body: &[u8]) -> String {
    let raw = &body[..body.len().min(ERROR_SCAN_BYTES)];
    if let Ok(v) = serde_json::from_slice::<Value>(raw) {
        let structured: Vec<String> = ["error", "detail"]
            .iter()
            .filter_map(|k| v.get(*k))
            .flat_map(|e| {
                [
                    e.get("message").and_then(Value::as_str),
                    e.as_str(),
                    e.get("type").and_then(Value::as_str),
                ]
            })
            .flatten()
            .map(str::to_ascii_lowercase)
            .collect();
        if !structured.is_empty() {
            return structured.join(" ");
        }
    }
    String::from_utf8_lossy(raw).to_ascii_lowercase()
}

/// Did LiteLLM reject the VIRTUAL KEY ITSELF? A PURE decision (no I/O) so the
/// facade's recovery branch is unit-testable.
///
/// Why it must be this narrow (review H3): LiteLLM answers 401 for BOTH "I have
/// never heard of this virtual key" and "my own upstream provider credential was
/// refused", and 403 for policy/budget refusals. Only the first is something
/// re-provisioning can fix. Treating every 401/403 as proof let ONE authenticated
/// tenant amplify a provider outage into unbounded `/key/generate` traffic and
/// unbounded LiteLLM key-table growth — every failing request minting another
/// live key that was never deleted.
///
/// So: status must be exactly 401 (403 never re-provisions), the body must carry
/// a marker of LiteLLM's own key check failing, and no provider-origin marker may
/// be present. Ambiguity ⇒ false ⇒ the 401 is forwarded verbatim, which is the
/// honest answer. Recovery is bounded AGAIN downstream by
/// [`recover_rejected_tenant_key`]'s cooldown and mint budget, so even a marker
/// we misread cannot loop.
pub fn virtual_key_rejected(source: KeySource, status: u16, body: &[u8]) -> bool {
    if source != KeySource::Tenant || status != 401 {
        return false;
    }
    let text = error_text(body);
    if UPSTREAM_PROVIDER_MARKERS.iter().any(|m| text.contains(m)) {
        return false;
    }
    VIRTUAL_KEY_REJECTED_MARKERS
        .iter()
        .any(|m| text.contains(m))
}

/// The tenant-key alias LiteLLM stores for attribution/debugging.
fn key_alias(tenant_id: Uuid) -> String {
    format!("fbx-tenant-{tenant_id}")
}

/// The configured `/key/generate` knobs (spend/rate limits + model allowlist).
#[derive(Debug, Default, Clone)]
struct TenantKeyKnobs {
    models: Vec<String>,
    max_budget: Option<f64>,
    budget_duration: Option<String>,
    tpm_limit: Option<i64>,
    rpm_limit: Option<i64>,
}

fn knobs_from_cfg(cfg: &Config) -> TenantKeyKnobs {
    TenantKeyKnobs {
        models: cfg.llm_tenant_models.clone(),
        max_budget: cfg.llm_tenant_max_budget,
        budget_duration: cfg.llm_tenant_budget_duration.clone(),
        tpm_limit: cfg.llm_tenant_tpm,
        rpm_limit: cfg.llm_tenant_rpm,
    }
}

/// Build the `/key/generate` request body. `key_alias` + `metadata.tenant_id` are
/// always present; every optional knob is inserted ONLY when configured, so an
/// unset knob is ABSENT from the JSON (LiteLLM applies its own default). Pure +
/// unit-tested at the serialized-byte level.
fn mint_body(tenant_id: Uuid, knobs: &TenantKeyKnobs) -> Value {
    let mut body = json!({
        "key_alias": key_alias(tenant_id),
        "metadata": { "tenant_id": tenant_id.to_string() },
    });
    let obj = body.as_object_mut().expect("mint body is an object");
    if !knobs.models.is_empty() {
        obj.insert("models".into(), json!(knobs.models));
    }
    if let Some(b) = knobs.max_budget {
        obj.insert("max_budget".into(), json!(b));
    }
    if let Some(d) = &knobs.budget_duration {
        obj.insert("budget_duration".into(), json!(d));
    }
    if let Some(t) = knobs.tpm_limit {
        obj.insert("tpm_limit".into(), json!(t));
    }
    if let Some(r) = knobs.rpm_limit {
        obj.insert("rpm_limit".into(), json!(r));
    }
    body
}

/// A freshly minted virtual key + the optional `litellm_token_id` from the mint
/// response (informational only — deletion uses the key value itself).
struct Minted {
    key: String,
    token_id: Option<String>,
}

/// Mint a virtual key at LiteLLM with the MASTER key (the one master-key use).
/// Never logs the key or the master. A non-2xx or a missing `key` field is an
/// upstream error (502) — fail closed, never a shared-key fallback.
///
/// EVERY mint passes the deployment-wide budget first (review H3): whatever a
/// caller believes, this replica cannot create more than [`MINT_MAX_PER_WINDOW`]
/// virtual keys per [`MINT_WINDOW`].
async fn mint_at_litellm(
    state: &AppState,
    tenant_id: Uuid,
    knobs: &TenantKeyKnobs,
) -> ApiResult<Minted> {
    {
        let mut budget = MINT_BUDGET.lock().await;
        if !try_consume_mint(
            &mut budget,
            Instant::now(),
            MINT_MAX_PER_WINDOW,
            MINT_WINDOW,
        ) {
            tracing::error!(
                tenant = %tenant_id,
                "llm key provisioning rate limit hit ({MINT_MAX_PER_WINDOW}/{}s) — refusing to \
                 mint; something is looping or LiteLLM is unhealthy",
                MINT_WINDOW.as_secs()
            );
            return Err(ApiError::ServiceUnavailable(
                "llm key provisioning is rate limited".into(),
            ));
        }
    }
    let url = format!(
        "{}/key/generate",
        state.cfg.llm_admin_url.trim_end_matches('/')
    );
    let resp = state
        .http
        .post(&url)
        .timeout(HTTP_TIMEOUT)
        .header(
            "authorization",
            format!("Bearer {}", state.cfg.llm_upstream_key),
        )
        .header("content-type", "application/json")
        .json(&mint_body(tenant_id, knobs))
        .send()
        .await
        .map_err(|e| ApiError::Upstream(format!("litellm /key/generate request failed: {e}")))?;
    let status = resp.status();
    if !status.is_success() {
        return Err(ApiError::Upstream(format!(
            "litellm /key/generate returned {status}"
        )));
    }
    let v: Value = resp
        .json()
        .await
        .map_err(|e| ApiError::Upstream(format!("litellm /key/generate response parse: {e}")))?;
    let key = v
        .get(LITELLM_KEY_FIELD)
        .and_then(|k| k.as_str())
        .filter(|k| !k.is_empty())
        .ok_or_else(|| ApiError::Upstream("litellm /key/generate response missing 'key'".into()))?
        .to_string();
    // Best-effort id capture (informational): LiteLLM /key/delete takes the key
    // value, so token_id is never load-bearing.
    let token_id = v
        .get("token_id")
        .or_else(|| v.get("token"))
        .and_then(|t| t.as_str())
        .map(|s| s.to_string());
    Ok(Minted { key, token_id })
}

/// Best-effort delete of a virtual key at LiteLLM (`/key/delete` takes the key
/// value). Used for a mint-race loser's orphan and a rotated-out old key. Failure
/// leaves an orphaned virtual key at LiteLLM (harmless, unreachable) — warn, never
/// fail the caller, never log the key.
async fn delete_at_litellm(state: &AppState, key: &str) {
    let url = format!(
        "{}/key/delete",
        state.cfg.llm_admin_url.trim_end_matches('/')
    );
    match state
        .http
        .post(&url)
        .timeout(HTTP_TIMEOUT)
        .header(
            "authorization",
            format!("Bearer {}", state.cfg.llm_upstream_key),
        )
        .header("content-type", "application/json")
        .json(&json!({ "keys": [key] }))
        .send()
        .await
    {
        Ok(r) if r.status().is_success() => {}
        Ok(r) => tracing::warn!(
            "litellm /key/delete returned {} — an orphaned virtual key remains at LiteLLM",
            r.status()
        ),
        Err(e) => tracing::warn!("litellm /key/delete request failed: {e}"),
    }
}

/// The per-tenant provisioning lock (see [`PROVISION_LOCKS`]). Held across the
/// read + mint + persist so an in-process stampede collapses to ONE mint.
async fn provision_lock(tenant_id: Uuid) -> Arc<Mutex<()>> {
    PROVISION_LOCKS
        .lock()
        .await
        .entry(tenant_id)
        .or_default()
        .clone()
}

/// Resolve the tenant's virtual key: cache → sealed row → mint. Fails closed
/// (`Err`, never the master key) so the facade turns any failure into a 503. The
/// caller in tenant mode passes the AUTHENTICATED session's tenant.
///
/// Mint race: the per-tenant singleflight lock collapses concurrent first-uses
/// in THIS process to one mint; across replicas `ON CONFLICT (tenant_id) DO
/// NOTHING` still arbitrates — the loser adopts the winner's sealed key and
/// best-effort deletes its own now-orphaned minted key.
pub async fn ensure_tenant_key(state: &AppState, tenant_id: Uuid) -> ApiResult<String> {
    // Uncontended steady state: no lock, no I/O.
    if let Some(k) = cached_key(state, tenant_id).await {
        return Ok(k);
    }
    let lock = provision_lock(tenant_id).await;
    let _guard = lock.lock().await;
    ensure_locked(state, tenant_id).await
}

/// [`ensure_tenant_key`]'s body, with the per-tenant provisioning lock ALREADY
/// held. Split out so the recovery path can reuse it without re-entering the
/// lock (a `tokio::sync::Mutex` is not reentrant — re-acquiring would deadlock).
async fn ensure_locked(state: &AppState, tenant_id: Uuid) -> ApiResult<String> {
    // 1. In-memory cache — re-checked under the lock: a concurrent provisioner
    //    may have finished while we waited, and re-minting then would be exactly
    //    the stampede the lock exists to prevent.
    if let Some(k) = cached_key(state, tenant_id).await {
        return Ok(k);
    }
    let scope = TenantScope::assume(tenant_id);
    let sealer = state
        .sealer
        .as_ref()
        .ok_or_else(|| ApiError::ServiceUnavailable("credential sealing is disabled".into()))?;
    let ctx = SealCtx::new(tenant_id, SealFamily::TenantLlmKey);

    // 2. Sealed row (cold cache / restart).
    if let Some((sealed, kv)) = fluidbox_db::tenant_llm_key_sealed(&state.pool, scope).await? {
        let key = sealer
            .open(&sealed, kv, ctx)
            .await
            .map_err(|_| ApiError::Internal("tenant llm key unseal failed".into()))?;
        publish_key(state, tenant_id, &key).await;
        return Ok(key);
    }

    // 3. Mint, seal, insert-or-adopt — under the cleanup guard.
    let knobs = knobs_from_cfg(&state.cfg);
    let minted = mint_at_litellm(state, tenant_id, &knobs).await?;
    match adopt_minted(state, tenant_id, scope, &minted).await {
        Ok(Adoption::Ours(key)) => {
            publish_key(state, tenant_id, &key).await;
            Ok(key)
        }
        Ok(Adoption::Other(winner)) => {
            // A concurrent minter (another replica) won: adopt its sealed key
            // and drop our orphan.
            delete_at_litellm(state, &minted.key).await;
            publish_key(state, tenant_id, &winner).await;
            Ok(winner)
        }
        // THE CLEANUP GUARD (review M5): `/key/generate` already succeeded, so a
        // failure in sealing / the insert / unsealing the winner would otherwise
        // leave a LIVE virtual key nothing references — and every retry would
        // mint another. The guard is armed the moment the mint returns and
        // disarmed only once the key is durably adopted AND published; until
        // then EVERY error path deletes it.
        Err(e) => {
            delete_at_litellm(state, &minted.key).await;
            Err(e)
        }
    }
}

/// Who owns the key that is now persisted for this tenant.
enum Adoption {
    /// Our mint won the insert — `minted.key` is the tenant's key.
    Ours(String),
    /// Someone else's key was already there; this is THEIRS (ours is an orphan).
    Other(String),
}

/// Seal + insert-or-adopt. Every failure here happens with a LIVE minted key
/// outstanding, so the caller's cleanup guard deletes it.
async fn adopt_minted(
    state: &AppState,
    tenant_id: Uuid,
    scope: TenantScope,
    minted: &Minted,
) -> ApiResult<Adoption> {
    let sealer = state
        .sealer
        .as_ref()
        .ok_or_else(|| ApiError::ServiceUnavailable("credential sealing is disabled".into()))?;
    let ctx = SealCtx::new(tenant_id, SealFamily::TenantLlmKey);
    let sealed = sealer
        .seal(&minted.key, ctx)
        .await
        .map_err(|_| ApiError::Internal("tenant llm key seal failed".into()))?;
    let outcome = fluidbox_db::insert_tenant_llm_key(
        &state.pool,
        scope,
        &sealed.bytes,
        sealed.key_version,
        &key_alias(tenant_id),
        minted.token_id.as_deref(),
    )
    .await?;
    if outcome.we_won {
        return Ok(Adoption::Ours(minted.key.clone()));
    }
    let winner = sealer
        .open(&outcome.sealed, outcome.key_version, ctx)
        .await
        .map_err(|_| ApiError::Internal("tenant llm key unseal failed".into()))?;
    Ok(Adoption::Other(winner))
}

/// The cached key for a tenant, if any.
async fn cached_key(state: &AppState, tenant_id: Uuid) -> Option<String> {
    state.tenant_llm_keys.lock().await.get(&tenant_id).cloned()
}

/// Publish a key to the in-memory cache (replacing any prior entry).
async fn publish_key(state: &AppState, tenant_id: Uuid, key: &str) {
    state
        .tenant_llm_keys
        .lock()
        .await
        .insert(tenant_id, key.to_string());
}

/// What the facade should do after LiteLLM rejected the virtual key it presented.
#[derive(Debug)]
pub enum KeyRecovery {
    /// Replay the request ONCE with this key — freshly provisioned, or the key a
    /// concurrent rotation already installed.
    Retry(String),
    /// Nothing was re-provisioned; forward the upstream rejection verbatim. The
    /// reason is a stable, log-safe label (never key material).
    Refused(&'static str),
}

/// Reactive recovery for a tenant key LiteLLM says it does not know.
///
/// Why it exists: nothing else recovers a dead tenant key. LiteLLM redeployed
/// with a fresh database (or an operator pruning keys) leaves a sealed row
/// LiteLLM has never heard of, and `ensure_tenant_key` reads cache → sealed row,
/// so even a restart re-reads the SAME dead key — every model request 401s
/// forever, and only the operator-only rotate endpoint could fix it (an org owner
/// under `FLUIDBOX_REQUIRE_SSO` cannot).
///
/// Three bounds make it safe to run on an authenticated request path:
///  - **the rejected key is compared against the CURRENT one** (review M4). A
///    request that read K0, paused, and 401'd after an operator rotated to K1
///    must NOT delete K1: the stale rejection proves nothing about the key that
///    is live now. Mismatch ⇒ replay with the current key, nothing deleted,
///    nothing minted.
///  - **a durable cooldown** (review H3): the DB's `coalesce(rotated_at,
///    created_at)` gates re-provisioning to once per tenant per
///    [`RECOVERY_COOLDOWN_SECS`], across replicas and restarts. Repeated
///    rejections cannot re-provision in a loop.
///  - **a compare-and-swap** on the exact sealed bytes we read, so two
///    concurrent recoveries (or a recovery racing an operator rotation) cannot
///    delete each other's winner; the loser drops its own fresh mint.
///
/// Plus the deployment-wide mint budget inside `mint_at_litellm`.
///
/// The rejected key is deliberately NOT deleted at LiteLLM: by hypothesis LiteLLM
/// does not know it, and if the marker was misread it may still be a live key —
/// deleting on a guess would be the destructive mistake.
pub async fn recover_rejected_tenant_key(
    state: &AppState,
    tenant_id: Uuid,
    rejected: &str,
) -> KeyRecovery {
    let scope = TenantScope::assume(tenant_id);
    let Some(sealer) = state.sealer.as_ref() else {
        return KeyRecovery::Refused("sealing disabled");
    };
    let ctx = SealCtx::new(tenant_id, SealFamily::TenantLlmKey);

    let lock = provision_lock(tenant_id).await;
    let _guard = lock.lock().await;

    let row = match fluidbox_db::tenant_llm_key_row(&state.pool, scope).await {
        Ok(Some(r)) => r,
        // No durable key at all (an operator deleted the row): provision one
        // through the normal path — still budget-bounded, and the row it writes
        // starts this tenant's cooldown.
        Ok(None) => {
            return match ensure_locked(state, tenant_id).await {
                Ok(k) => KeyRecovery::Retry(k),
                Err(e) => {
                    tracing::warn!(tenant = %tenant_id, error = %e, "llm key recovery: provisioning failed");
                    KeyRecovery::Refused("provisioning failed")
                }
            };
        }
        Err(e) => {
            tracing::warn!(tenant = %tenant_id, error = %e, "llm key recovery: key lookup failed");
            return KeyRecovery::Refused("key lookup failed");
        }
    };
    let Ok(current) = sealer.open(&row.sealed, row.key_version, ctx).await else {
        return KeyRecovery::Refused("unseal failed");
    };
    if current != rejected {
        // M4: a stale rejection. The key the caller presented is already gone;
        // the current one has never been tried. Replay with it — no delete, no
        // mint, and the successful rotation stands.
        tracing::info!(
            tenant = %tenant_id,
            "llm key recovery: the rejected key was already rotated away — retrying with the current key"
        );
        publish_key(state, tenant_id, &current).await;
        return KeyRecovery::Retry(current);
    }
    let age = Utc::now() - row.minted_at;
    if age < chrono::Duration::seconds(RECOVERY_COOLDOWN_SECS) {
        // Includes a negative age (clock skew) — fail closed.
        tracing::warn!(
            tenant = %tenant_id,
            "llm key recovery: this tenant's key was provisioned {}s ago (< {RECOVERY_COOLDOWN_SECS}s cooldown) \
             and was rejected again — forwarding the rejection instead of re-minting",
            age.num_seconds()
        );
        return KeyRecovery::Refused("recovery cooldown");
    }

    let knobs = knobs_from_cfg(&state.cfg);
    let minted = match mint_at_litellm(state, tenant_id, &knobs).await {
        Ok(m) => m,
        Err(e) => {
            tracing::warn!(tenant = %tenant_id, error = %e, "llm key recovery: mint failed");
            return KeyRecovery::Refused("mint failed");
        }
    };
    // The cleanup guard again (M5): from here every failure deletes the fresh
    // key before returning, so a failing recovery cannot leave live orphans.
    let sealed = match sealer.seal(&minted.key, ctx).await {
        Ok(s) => s,
        Err(_) => {
            delete_at_litellm(state, &minted.key).await;
            return KeyRecovery::Refused("seal failed");
        }
    };
    match fluidbox_db::rotate_tenant_llm_key_cas(
        &state.pool,
        scope,
        &row.sealed,
        &sealed.bytes,
        sealed.key_version,
        &key_alias(tenant_id),
        minted.token_id.as_deref(),
    )
    .await
    {
        Ok(true) => {
            publish_key(state, tenant_id, &minted.key).await;
            KeyRecovery::Retry(minted.key)
        }
        Ok(false) => {
            // Someone else swapped first (another replica's recovery, or an
            // operator rotation). Theirs wins; ours is an orphan.
            delete_at_litellm(state, &minted.key).await;
            evict_tenant_llm_key(state, tenant_id).await;
            match ensure_locked(state, tenant_id).await {
                Ok(k) => KeyRecovery::Retry(k),
                Err(e) => {
                    tracing::warn!(tenant = %tenant_id, error = %e, "llm key recovery: could not read the winning key");
                    KeyRecovery::Refused("key lookup failed")
                }
            }
        }
        Err(e) => {
            delete_at_litellm(state, &minted.key).await;
            tracing::warn!(tenant = %tenant_id, error = %e, "llm key recovery: persist failed");
            KeyRecovery::Refused("persist failed")
        }
    }
}

/// Rotate the tenant's virtual key (operator surface): mint a new key → swap the
/// sealed row (bumping `rotated_at`) → evict + re-seed the cache → best-effort
/// delete the OLD key at LiteLLM. On a tenant with no key yet this creates one
/// (nothing to delete). The org's existence 404 is enforced by the route; this
/// never surfaces the key.
pub async fn rotate_tenant_key(state: &AppState, tenant_id: Uuid) -> ApiResult<()> {
    let scope = TenantScope::assume(tenant_id);
    let sealer = state
        .sealer
        .as_ref()
        .ok_or_else(|| ApiError::ServiceUnavailable("credential sealing is disabled".into()))?;
    let ctx = SealCtx::new(tenant_id, SealFamily::TenantLlmKey);

    // Serialize against the reactive recovery + first-use provisioning: an
    // operator rotation and a recovery both swap this row, and interleaving them
    // is how a live key gets stranded.
    let lock = provision_lock(tenant_id).await;
    let _guard = lock.lock().await;

    let knobs = knobs_from_cfg(&state.cfg);
    let minted = mint_at_litellm(state, tenant_id, &knobs).await?;

    // The cleanup guard (review M5): the mint has already created a live key, so
    // a failed seal or a failed swap must retire it — otherwise every retry of a
    // transient KMS/DB incident leaves another live orphan behind.
    let sealed = match sealer.seal(&minted.key, ctx).await {
        Ok(s) => s,
        Err(_) => {
            delete_at_litellm(state, &minted.key).await;
            return Err(ApiError::Internal("tenant llm key seal failed".into()));
        }
    };
    let old = match fluidbox_db::rotate_tenant_llm_key(
        &state.pool,
        scope,
        &sealed.bytes,
        sealed.key_version,
        &key_alias(tenant_id),
        minted.token_id.as_deref(),
    )
    .await
    {
        Ok(o) => o,
        Err(e) => {
            delete_at_litellm(state, &minted.key).await;
            return Err(e.into());
        }
    };

    // Re-seed the cache with the new key (the old entry is now stale). Doing this
    // BEFORE the LiteLLM delete keeps in-flight facade calls on the new key — and
    // it is what disarms the guard: the key is now durable AND published.
    publish_key(state, tenant_id, &minted.key).await;

    // Best-effort retire the old key at LiteLLM (unseal it first; never fail the
    // rotation on a LiteLLM hiccup). `None` = the tenant had no prior key.
    if let Some((old_sealed, old_kv)) = old {
        if let Ok(old_key) = sealer.open(&old_sealed, old_kv, ctx).await {
            delete_at_litellm(state, &old_key).await;
        }
    }
    Ok(())
}

/// Drop a tenant's cached virtual key so the next use re-reads the sealed row.
/// Used by the recovery path when a concurrent writer won the compare-and-swap
/// (our cached value is then provably stale), and available as the standalone
/// evict hook (e.g. a future tenant-suspend or manual invalidation).
///
/// Deliberately NOT paired with a row delete any more (review M4): an
/// unconditional "evict + delete the tenant's row" is how a stale 401 destroyed a
/// freshly rotated key. Recovery now compare-and-swaps instead.
pub async fn evict_tenant_llm_key(state: &AppState, tenant_id: Uuid) {
    state.tenant_llm_keys.lock().await.remove(&tenant_id);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_source_decision_matrix() {
        // Tenant mode always resolves a tenant key (SSO irrelevant).
        assert_eq!(key_source(LlmKeyMode::Tenant, false), KeySource::Tenant);
        assert_eq!(key_source(LlmKeyMode::Tenant, true), KeySource::Tenant);
        // Shared mode without SSO = today's behavior (the deployment key).
        assert_eq!(key_source(LlmKeyMode::Shared, false), KeySource::Shared);
        // Shared mode WITH SSO = the forbidden hosted posture → refuse.
        assert_eq!(
            key_source(LlmKeyMode::Shared, true),
            KeySource::RefuseSsoShared
        );
    }

    /// LiteLLM's own 401 for a virtual key it has never heard of.
    const LITELLM_UNKNOWN_KEY: &[u8] = br#"{"error":{"message":"Authentication Error, Invalid proxy server token passed. Received API Key = sk-abc, Key Hash = h, Unable to find token in cache or `LiteLLM_VerificationTokenTable`","type":"auth_error","param":"None","code":"401"}}"#;
    /// A 401 that is really the GATEWAY's own upstream provider credential.
    const PROVIDER_401: &[u8] = br#"{"error":{"message":"litellm.AuthenticationError: AnthropicException - {\"type\":\"error\",\"error\":{\"type\":\"authentication_error\",\"message\":\"invalid x-api-key\"}}","type":"None","param":"None","code":"401"}}"#;

    #[test]
    fn only_a_proven_virtual_key_rejection_re_provisions() {
        // The one case re-provisioning can fix.
        assert!(virtual_key_rejected(
            KeySource::Tenant,
            401,
            LITELLM_UNKNOWN_KEY
        ));

        // H3: LiteLLM accepted our virtual key and its OWN provider credential was
        // refused. Minting another virtual key cannot fix that, so it must not —
        // this is the request-amplification path the review found.
        assert!(!virtual_key_rejected(KeySource::Tenant, 401, PROVIDER_401));

        // A policy/budget refusal is never key-death, whatever the body says.
        assert!(!virtual_key_rejected(
            KeySource::Tenant,
            403,
            LITELLM_UNKNOWN_KEY
        ));
        // An unattributable 401 (no marker) is ambiguous ⇒ forwarded verbatim.
        for body in [
            &br#"{"error":{"message":"Unauthorized","type":"auth_error"}}"#[..],
            &b""[..],
            &b"<html>401</html>"[..],
        ] {
            assert!(!virtual_key_rejected(KeySource::Tenant, 401, body));
        }
        // Any other status is the model's own answer — forwarded verbatim.
        for status in [200, 400, 404, 429, 500, 502, 529] {
            assert!(
                !virtual_key_rejected(KeySource::Tenant, status, LITELLM_UNKNOWN_KEY),
                "status {status} must not re-provision"
            );
        }
        // Shared mode has no tenant key to re-provision (and the deployment key's
        // 401 is an operator problem, not something the facade may rotate); the
        // SSO refusal never reaches an upstream call at all.
        for source in [KeySource::Shared, KeySource::RefuseSsoShared] {
            assert!(!virtual_key_rejected(source, 401, LITELLM_UNKNOWN_KEY));
        }
        // Non-JSON bodies still scan (LiteLLM behind a proxy that rewrote it).
        assert!(virtual_key_rejected(
            KeySource::Tenant,
            401,
            b"Authentication Error, Invalid proxy server token passed."
        ));
    }

    #[test]
    fn mint_budget_is_a_deployment_wide_fixed_window() {
        let t0 = Instant::now();
        let mut win = MintWindow {
            started: t0,
            minted: 0,
        };
        let window = Duration::from_secs(60);
        // The budget is spendable…
        for i in 0..3 {
            assert!(
                try_consume_mint(&mut win, t0 + Duration::from_secs(1), 3, window),
                "mint {i} is within budget"
            );
        }
        // …and then it is CLOSED, no matter who asks or how often.
        for _ in 0..100 {
            assert!(!try_consume_mint(
                &mut win,
                t0 + Duration::from_secs(59),
                3,
                window
            ));
        }
        // The window rolls over on its own.
        assert!(try_consume_mint(
            &mut win,
            t0 + Duration::from_secs(61),
            3,
            window
        ));
    }

    #[test]
    fn error_text_prefers_the_structured_message() {
        let t = error_text(LITELLM_UNKNOWN_KEY);
        assert!(t.contains("invalid proxy server token"));
        assert!(t.contains("auth_error"), "the error type is scanned too");
        // FastAPI's `detail` shape (a bare string) is understood as well.
        assert_eq!(
            error_text(br#"{"detail":"Invalid Proxy Server Token"}"#),
            "invalid proxy server token"
        );
        // A body larger than the scan bound is truncated, not scanned whole.
        let big = vec![b'x'; ERROR_SCAN_BYTES * 2];
        assert_eq!(error_text(&big).len(), ERROR_SCAN_BYTES);
    }

    #[test]
    fn mint_body_omits_unset_knobs() {
        let tid = Uuid::now_v7();
        let body = mint_body(tid, &TenantKeyKnobs::default());
        // Assert against the SERIALIZED bytes: no knob key appears at all.
        let s = serde_json::to_string(&body).unwrap();
        assert!(s.contains(&format!("fbx-tenant-{tid}")), "alias present");
        assert!(s.contains(&tid.to_string()), "tenant_id metadata present");
        for absent in [
            "models",
            "max_budget",
            "budget_duration",
            "tpm_limit",
            "rpm_limit",
        ] {
            assert!(
                !s.contains(absent),
                "unset knob '{absent}' must be absent from the mint body: {s}"
            );
        }
    }

    #[test]
    fn mint_body_includes_configured_knobs() {
        let tid = Uuid::now_v7();
        let knobs = TenantKeyKnobs {
            models: vec!["claude-haiku-4-5".into(), "gpt-5.4-mini".into()],
            max_budget: Some(25.0),
            budget_duration: Some("30d".into()),
            tpm_limit: Some(100_000),
            rpm_limit: Some(500),
        };
        let body = mint_body(tid, &knobs);
        assert_eq!(body["key_alias"], format!("fbx-tenant-{tid}"));
        assert_eq!(body["metadata"]["tenant_id"], tid.to_string());
        assert_eq!(body["models"][0], "claude-haiku-4-5");
        assert_eq!(body["models"][1], "gpt-5.4-mini");
        assert_eq!(body["max_budget"], 25.0);
        assert_eq!(body["budget_duration"], "30d");
        assert_eq!(body["tpm_limit"], 100_000);
        assert_eq!(body["rpm_limit"], 500);
    }

    #[test]
    fn key_alias_is_stable_per_tenant() {
        let tid = Uuid::now_v7();
        assert_eq!(key_alias(tid), format!("fbx-tenant-{tid}"));
    }
}
