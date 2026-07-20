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
//!     with the tenant's id in `metadata` + an `fbx-tenant-{uuid}-{op}` alias (the
//!     tenant prefix plus a client-generated operation id — see [`mint_alias`]),
//!     and the configured spend/rate knobs only when set;
//!   - sealed at rest (`tenant_llm_keys.litellm_key_sealed`, family `TenantLlmKey`,
//!     under the tenant's OWN DEK) — never returned in an API response;
//!   - cached unsealed in memory (`AppState.tenant_llm_keys`, keyed by tenant_id),
//!     re-read from the sealed row on a cold cache / restart, evicted on rotation.
//!
//! PROVISIONING IS BOUNDED IN THREE PLACES (Phase D review H3/M4/M5), because
//! minting is reachable from an authenticated request path:
//!   - a per-tenant singleflight lock, so a stampede is ONE mint;
//!   - a durable per-tenant cooldown (the row's `coalesce(rotated_at,
//!     created_at)`) — that one IS deployment-wide, being a DB stamp every
//!     replica reads — plus a PER-REPLICA mint budget, so repeated upstream
//!     rejections cannot re-provision in a loop;
//!   - a mint guard armed BEFORE the request is dispatched and disarmed only on
//!     durable adoption, so a key that LiteLLM created but we never adopted —
//!     including one whose response timed out, arrived truncated, or whose caller
//!     was cancelled mid-flight — is retired rather than left live and
//!     unreferenced.
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

/// LiteLLM's proxy-auth refusal message for a virtual key it does not know:
/// "Authentication Error, Invalid proxy server token passed. Received API Key =
/// …, Key Hash = …, Unable to find token in cache or
/// `LiteLLM_VerificationTokenTable`". Matched case-insensitively against the
/// bounded error text.
///
/// BOTH halves are required (re-verification, #32). The first half alone is not
/// proof — and generic markers ("key not found", "expired key") are not proof at
/// all: a provider can emit them verbatim through the gateway. The concrete
/// counterexample that used to qualify: `{"error":{"message":"OpenAI API key not
/// found","type":"auth_error"}}` with a 401. The second half names LiteLLM's OWN
/// cache/verification table, so it cannot be provider-originated text — that is
/// the structure the decision now rests on, and `auth_error` is deliberately NOT
/// part of it (the counterexample carries `auth_error` too; it is the weakest of
/// the three signals, not a discriminator).
const PROXY_AUTH_REFUSAL: &str = "invalid proxy server token";
const PROXY_AUTH_DIAGNOSTICS: &[&str] = &["unable to find token", "litellm_verificationtokentable"];

/// LiteLLM's own exception class for a key whose expiry has passed. A LiteLLM
/// SDK class name, not prose — a provider body cannot produce it. (The bare
/// phrase "expired key" can, and no longer qualifies.)
const EXPIRED_KEY_CLASS: &str = "expiredkeyerror";

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

/// PER-REPLICA ceiling on `/key/generate` calls, and its window. A blast door,
/// not a quota: legitimate provisioning is once per tenant (plus operator
/// rotations), so any replica approaching this is looping. Applies to EVERY mint
/// path — first use, operator rotation, and reactive recovery.
///
/// It is honestly per-replica and nothing more (re-verification, #32 — the
/// earlier "deployment-wide" claim was false). That is deliberate, not a gap
/// waiting on shared state: the bound that actually caps re-provisioning ACROSS
/// the deployment is [`RECOVERY_COOLDOWN_SECS`], a durable per-tenant DB stamp
/// every replica honors, so a fleet of N replicas still cannot re-mint a given
/// tenant more than once per cooldown. This window only stops ONE process from
/// hammering LiteLLM when something local goes wrong — a job a distributed
/// counter would do no better and would pay a DB round trip per mint for.
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

/// The per-replica mint budget (fixed window). In-process by construction — it
/// bounds what THIS replica can do to LiteLLM, and says nothing about the fleet
/// (see the constants above for why that is the right split).
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
/// LiteLLM's own proxy-auth STRUCTURE (see [`PROXY_AUTH_REFUSAL`] /
/// [`EXPIRED_KEY_CLASS`] for why generic markers were removed), and no
/// provider-origin marker may be present. Ambiguity ⇒ false ⇒ the 401 is
/// forwarded verbatim, which is the honest answer. Recovery is bounded AGAIN
/// downstream by [`recover_rejected_tenant_key`]'s durable cooldown and this
/// replica's mint budget, so even a marker we misread cannot loop.
pub fn virtual_key_rejected(source: KeySource, status: u16, body: &[u8]) -> bool {
    if source != KeySource::Tenant || status != 401 {
        return false;
    }
    let text = error_text(body);
    if UPSTREAM_PROVIDER_MARKERS.iter().any(|m| text.contains(m)) {
        return false;
    }
    let unknown_key = text.contains(PROXY_AUTH_REFUSAL)
        && PROXY_AUTH_DIAGNOSTICS.iter().any(|d| text.contains(d));
    unknown_key || text.contains(EXPIRED_KEY_CLASS)
}

/// The stable per-tenant alias PREFIX LiteLLM stores for attribution/debugging.
/// Every alias this module mints starts with it, so an operator can still find a
/// tenant's keys by prefix; `metadata.tenant_id` remains the authoritative
/// attribution.
fn key_alias_prefix(tenant_id: Uuid) -> String {
    format!("fbx-tenant-{tenant_id}")
}

/// The alias for ONE mint attempt: the tenant prefix plus a client-generated
/// operation id.
///
/// Per-ATTEMPT, not per-tenant, and that is the whole point (re-verification,
/// #32). After an ambiguous `/key/generate` the alias is the only handle we have
/// on a key LiteLLM may have created — we never learned its value — so cleanup
/// must delete by alias. A tenant-stable alias would make that indiscriminate:
/// rotation and reactive recovery both mint while the tenant's PREVIOUS key is
/// still live under the same name, so retiring "the tenant's alias" could delete
/// the live key. An operation id makes the retire provably scoped to the one
/// attempt that went ambiguous.
fn mint_alias(tenant_id: Uuid) -> String {
    format!(
        "{}-{}",
        key_alias_prefix(tenant_id),
        Uuid::now_v7().simple()
    )
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
fn mint_body(tenant_id: Uuid, alias: &str, knobs: &TenantKeyKnobs) -> Value {
    let mut body = json!({
        "key_alias": alias,
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

/// A freshly minted virtual key, the alias this attempt chose (persisted with the
/// row, and the handle an ambiguous-result retire uses), and the optional
/// `litellm_token_id` from the mint response (informational only).
struct Minted {
    key: String,
    token_id: Option<String>,
    alias: String,
}

/// The mint guard (re-verification, #32). Armed BEFORE `/key/generate` is
/// dispatched and disarmed only once the key is durably adopted AND published;
/// everything in between retires the attempt's alias at LiteLLM on drop:
///
///   - LiteLLM created the key and the response then timed out, or a proxy
///     truncated/mangled the successful JSON (the old cleanup only armed AFTER a
///     `Minted` existed, so these left a live, unreferenced key);
///   - sealing, the insert/CAS, or unsealing the winner failed;
///   - the caller's future was DROPPED between mint and adoption (client
///     disconnect / cancellation), which no manual cleanup branch can catch.
///
/// Retiring by ALIAS is what makes firing on an AMBIGUOUS result safe: we may
/// never have learned the key value, but we chose the alias, and it belongs to
/// exactly one attempt — so a retire can never delete the tenant's live key.
struct MintGuard {
    state: AppState,
    alias: String,
    armed: bool,
}

impl MintGuard {
    fn arm(state: &AppState, alias: String) -> Self {
        Self {
            state: state.clone(),
            alias,
            armed: true,
        }
    }

    /// The key is durable and published — this attempt owns nothing to clean up.
    fn disarm(mut self) {
        self.armed = false;
    }
}

impl Drop for MintGuard {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        let state = self.state.clone();
        let alias = std::mem::take(&mut self.alias);
        // `Drop` cannot await, and the future we are inside may itself be being
        // cancelled — so the retire is DETACHED. Outside a runtime there is
        // nothing to spawn onto (and nothing was ever minted).
        if let Ok(rt) = tokio::runtime::Handle::try_current() {
            rt.spawn(async move { retire_alias_at_litellm(&state, &alias).await });
        }
    }
}

/// Mint a virtual key at LiteLLM with the MASTER key (the one master-key use).
/// Never logs the key or the master. A non-2xx or a missing `key` field is an
/// upstream error (502) — fail closed, never a shared-key fallback.
///
/// EVERY mint passes this replica's budget first (review H3): whatever a caller
/// believes, this process cannot create more than [`MINT_MAX_PER_WINDOW`] virtual
/// keys per [`MINT_WINDOW`].
async fn mint_at_litellm(
    state: &AppState,
    tenant_id: Uuid,
    knobs: &TenantKeyKnobs,
) -> ApiResult<(Minted, MintGuard)> {
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
                "llm key provisioning rate limit hit on this replica \
                 ({MINT_MAX_PER_WINDOW}/{}s) — refusing to mint; something is looping or \
                 LiteLLM is unhealthy",
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
    let alias = mint_alias(tenant_id);
    // ARMED BEFORE DISPATCH: from here on, every exit that is not a durable
    // adoption retires this alias — including the one that matters most, a
    // request that created the key and then failed to tell us about it.
    let guard = MintGuard::arm(state, alias.clone());
    let resp = state
        .http
        .post(&url)
        .timeout(HTTP_TIMEOUT)
        .header(
            "authorization",
            format!("Bearer {}", state.cfg.llm_upstream_key),
        )
        .header("content-type", "application/json")
        .json(&mint_body(tenant_id, &alias, knobs))
        .send()
        .await
        .map_err(|e| ApiError::Upstream(format!("litellm /key/generate request failed: {e}")))?;
    let status = resp.status();
    if !status.is_success() {
        // A 4xx is LiteLLM validating and refusing BEFORE it inserts a key (bad
        // knob, bad master key): nothing exists to retire, so don't spend a
        // pointless `/key/delete`. 5xx and transport/parse failures stay
        // AMBIGUOUS and keep the guard armed.
        if status.is_client_error() {
            guard.disarm();
        }
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
    Ok((
        Minted {
            key,
            token_id,
            alias,
        },
        guard,
    ))
}

/// Retire a mint attempt's key by ALIAS — the reconciliation for an AMBIGUOUS
/// `/key/generate` (see [`MintGuard`]). `/key/delete` accepts `key_aliases`
/// alongside `keys`; the alias is per-attempt, so this deletes at most the one
/// key that attempt may have created and never the tenant's live key. A
/// not-found alias (nothing was created) answers non-2xx — logged, never fatal,
/// and the key value is never logged because we do not have one.
async fn retire_alias_at_litellm(state: &AppState, alias: &str) {
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
        .json(&json!({ "key_aliases": [alias] }))
        .send()
        .await
    {
        Ok(r) if r.status().is_success() => {}
        Ok(r) => tracing::warn!(
            alias,
            "litellm /key/delete (by alias) returned {} — either nothing was minted under this \
             alias, or an orphaned virtual key remains at LiteLLM",
            r.status()
        ),
        Err(e) => tracing::warn!(alias, "litellm /key/delete (by alias) request failed: {e}"),
    }
}

/// Best-effort delete of a virtual key at LiteLLM BY VALUE (`/key/delete` takes
/// `keys`). The one caller left is the rotated-out OLD key, whose value we hold
/// and whose alias we do not (aliases are per mint attempt now); everything
/// minted-but-not-adopted goes through [`MintGuard`]'s alias retire instead.
/// Failure leaves an orphaned virtual key at LiteLLM (harmless, unreachable) —
/// warn, never fail the caller, never log the key.
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

    // 3. Mint, seal, insert-or-adopt — under the mint guard (review M5, widened
    //    in #32). `guard` is armed before `/key/generate` is even dispatched and
    //    is disarmed ONLY on the adoption path below; every other exit — a
    //    failure in sealing / the insert / unsealing the winner, a losing race, an
    //    ambiguous mint, or this future being cancelled — drops it, which retires
    //    the attempt's alias. Without that, a retry would mint another live key
    //    nothing references.
    let knobs = knobs_from_cfg(&state.cfg);
    let (minted, guard) = mint_at_litellm(state, tenant_id, &knobs).await?;
    match adopt_minted(state, tenant_id, scope, &minted).await {
        Ok(Adoption::Ours(key)) => {
            publish_key(state, tenant_id, &key).await;
            guard.disarm();
            Ok(key)
        }
        Ok(Adoption::Other(winner)) => {
            // A concurrent minter (another replica) won: adopt its sealed key.
            // Our orphan carries OUR alias, so the guard's retire targets exactly
            // it and never the winner's key.
            publish_key(state, tenant_id, &winner).await;
            Ok(winner)
        }
        Err(e) => Err(e),
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
        &minted.alias,
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
/// Plus this replica's mint budget inside `mint_at_litellm`.
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
            // LOW (#32): the durable row is gone (an operator deleted it) but the
            // REJECTED key may still be cached — and `ensure_locked`'s first act
            // is a cache read, which would hand back the very key LiteLLM just
            // refused and wedge this tenant until eviction or restart.
            // COMPARE-and-drop, never unconditional: a concurrent provisioner may
            // have published a GOOD key between the rejection and here, and
            // dropping that one is the exact race class that already produced a
            // real singleflight bug in this codebase.
            evict_rejected_key(state, tenant_id, rejected).await;
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
    let (minted, guard) = match mint_at_litellm(state, tenant_id, &knobs).await {
        Ok(m) => m,
        Err(e) => {
            tracing::warn!(tenant = %tenant_id, error = %e, "llm key recovery: mint failed");
            return KeyRecovery::Refused("mint failed");
        }
    };
    // The mint guard again: from here every exit that is not a won CAS retires
    // the fresh key's alias, so a failing recovery cannot leave live orphans.
    let sealed = match sealer.seal(&minted.key, ctx).await {
        Ok(s) => s,
        Err(_) => return KeyRecovery::Refused("seal failed"),
    };
    match fluidbox_db::rotate_tenant_llm_key_cas(
        &state.pool,
        scope,
        &row.sealed,
        &sealed.bytes,
        sealed.key_version,
        &minted.alias,
        minted.token_id.as_deref(),
    )
    .await
    {
        Ok(true) => {
            publish_key(state, tenant_id, &minted.key).await;
            guard.disarm();
            KeyRecovery::Retry(minted.key)
        }
        Ok(false) => {
            // Someone else swapped first (another replica's recovery, or an
            // operator rotation). Theirs wins; ours is an orphan the guard
            // retires by alias.
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
    let (minted, guard) = mint_at_litellm(state, tenant_id, &knobs).await?;

    // The mint guard (review M5): the mint may already have created a live key, so
    // a failed seal or a failed swap must retire it — otherwise every retry of a
    // transient KMS/DB incident leaves another live orphan behind.
    let sealed = match sealer.seal(&minted.key, ctx).await {
        Ok(s) => s,
        Err(_) => return Err(ApiError::Internal("tenant llm key seal failed".into())),
    };
    let old = fluidbox_db::rotate_tenant_llm_key(
        &state.pool,
        scope,
        &sealed.bytes,
        sealed.key_version,
        &minted.alias,
        minted.token_id.as_deref(),
    )
    .await?;

    // Re-seed the cache with the new key (the old entry is now stale). Doing this
    // BEFORE the LiteLLM delete keeps in-flight facade calls on the new key — and
    // it is what disarms the guard: the key is now durable AND published.
    publish_key(state, tenant_id, &minted.key).await;
    guard.disarm();

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

/// COMPARE-and-drop: evict the tenant's cached key only if it is STILL the one
/// that was rejected. PURE (the caller owns the map) so the race is testable.
fn drop_if_rejected(cache: &mut HashMap<Uuid, String>, tenant_id: Uuid, rejected: &str) -> bool {
    if cache.get(&tenant_id).is_some_and(|k| k == rejected) {
        cache.remove(&tenant_id);
        return true;
    }
    false
}

/// [`drop_if_rejected`] against the live cache.
async fn evict_rejected_key(state: &AppState, tenant_id: Uuid, rejected: &str) -> bool {
    let mut cache = state.tenant_llm_keys.lock().await;
    drop_if_rejected(&mut cache, tenant_id, rejected)
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

    /// A 401 that is really the PROVIDER's, phrased so it trips every generic
    /// marker the classifier used to carry — the re-verification counterexample.
    const PROVIDER_KEY_NOT_FOUND: &[u8] =
        br#"{"error":{"message":"OpenAI API key not found","type":"auth_error"}}"#;

    #[test]
    fn only_a_proven_virtual_key_rejection_re_provisions() {
        // The one case re-provisioning can fix.
        assert!(virtual_key_rejected(
            KeySource::Tenant,
            401,
            LITELLM_UNKNOWN_KEY
        ));

        // #32: provider-originated text that reads like a key rejection. It
        // carries `auth_error` and "key not found" and trips NONE of the provider
        // veto strings — under the old generic markers it re-provisioned, so a
        // persistent provider fault minted one live orphan per cooldown.
        assert!(
            !virtual_key_rejected(KeySource::Tenant, 401, PROVIDER_KEY_NOT_FOUND),
            "a provider can say 'key not found'; only LiteLLM's own proxy-auth structure counts"
        );
        for generic in [
            &br#"{"error":{"message":"api key not found","type":"auth_error"}}"#[..],
            &br#"{"error":{"message":"expired key","type":"auth_error"}}"#[..],
            &br#"{"detail":"Key not found"}"#[..],
        ] {
            assert!(
                !virtual_key_rejected(KeySource::Tenant, 401, generic),
                "generic phrasing is not proof of a virtual-key rejection"
            );
        }
        // Half the proxy-auth structure is not proof either: the refusal line
        // alone could be echoed, the LiteLLM cache/table diagnostic could not.
        assert!(!virtual_key_rejected(
            KeySource::Tenant,
            401,
            br#"{"error":{"message":"Invalid proxy server token passed.","type":"auth_error"}}"#
        ));
        // Both halves, either diagnostic spelling ⇒ proof.
        assert!(virtual_key_rejected(
            KeySource::Tenant,
            401,
            br#"{"error":{"message":"Invalid proxy server token passed. Key Hash = h, not in LiteLLM_VerificationTokenTable","type":"auth_error"}}"#
        ));
        // LiteLLM's own exception class for an expired key stands alone — a
        // provider body cannot produce a LiteLLM class name.
        assert!(virtual_key_rejected(
            KeySource::Tenant,
            401,
            br#"{"error":{"message":"ExpiredKeyError: Authentication Error - Expired Key","type":"auth_error"}}"#
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
        // Non-JSON bodies still scan (LiteLLM behind a proxy that rewrote the
        // envelope) — but the SAME structure is required, so a rewrite that kept
        // only the headline sentence is ambiguous and forwards.
        assert!(virtual_key_rejected(
            KeySource::Tenant,
            401,
            b"Authentication Error, Invalid proxy server token passed. Received API Key = sk-x, \
              Unable to find token in cache or `LiteLLM_VerificationTokenTable`"
        ));
        assert!(!virtual_key_rejected(
            KeySource::Tenant,
            401,
            b"Authentication Error, Invalid proxy server token passed."
        ));
    }

    #[test]
    fn a_rejected_cached_key_is_compare_and_dropped() {
        let (t, other) = (Uuid::now_v7(), Uuid::now_v7());
        let mut cache: HashMap<Uuid, String> = HashMap::new();
        cache.insert(t, "sk-rejected".into());
        cache.insert(other, "sk-other".into());

        // The rejected value is still cached ⇒ drop it, so recovery's cache-first
        // read cannot hand the dead key straight back (#32 LOW).
        assert!(drop_if_rejected(&mut cache, t, "sk-rejected"));
        assert!(!cache.contains_key(&t));
        // Another tenant's entry is untouched.
        assert_eq!(cache.get(&other).map(String::as_str), Some("sk-other"));

        // A concurrent provisioner already published a GOOD key: the stale
        // rejection must NOT evict it (an unconditional evict here is the race
        // class that produced a real singleflight bug).
        cache.insert(t, "sk-fresh".into());
        assert!(!drop_if_rejected(&mut cache, t, "sk-rejected"));
        assert_eq!(cache.get(&t).map(String::as_str), Some("sk-fresh"));
        // Nothing cached at all is a no-op, not a panic.
        cache.remove(&t);
        assert!(!drop_if_rejected(&mut cache, t, "sk-rejected"));
    }

    #[test]
    fn mint_budget_is_a_per_replica_fixed_window() {
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
        let alias = mint_alias(tid);
        let body = mint_body(tid, &alias, &TenantKeyKnobs::default());
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
        let alias = mint_alias(tid);
        let body = mint_body(tid, &alias, &knobs);
        assert_eq!(body["key_alias"], alias);
        assert_eq!(body["metadata"]["tenant_id"], tid.to_string());
        assert_eq!(body["models"][0], "claude-haiku-4-5");
        assert_eq!(body["models"][1], "gpt-5.4-mini");
        assert_eq!(body["max_budget"], 25.0);
        assert_eq!(body["budget_duration"], "30d");
        assert_eq!(body["tpm_limit"], 100_000);
        assert_eq!(body["rpm_limit"], 500);
    }

    #[test]
    fn mint_aliases_are_per_attempt_under_a_stable_tenant_prefix() {
        let tid = Uuid::now_v7();
        let prefix = key_alias_prefix(tid);
        assert_eq!(prefix, format!("fbx-tenant-{tid}"));
        let (a, b) = (mint_alias(tid), mint_alias(tid));
        assert!(
            a.starts_with(&prefix) && b.starts_with(&prefix),
            "still attributable by prefix"
        );
        // Distinct per attempt — this is what makes an ambiguous-result retire
        // provably scoped to the one attempt instead of to the tenant's LIVE key.
        assert_ne!(a, b);
        assert_ne!(a, prefix);
    }
}
