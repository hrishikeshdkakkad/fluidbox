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
//! This is the tenant-fairness BACKSTOP (each virtual key carries its own
//! spend/tpm/rpm ceiling server-side); it is NOT the per-run budget-race fix
//! (durable reservations, Phase E — design :1100-1114).

use crate::config::{Config, LlmKeyMode};
use crate::error::{ApiError, ApiResult};
use crate::seal::{SealCtx, SealFamily};
use crate::state::AppState;
use fluidbox_db::TenantScope;
use serde_json::{json, Value};
use uuid::Uuid;

/// LiteLLM's `/key/generate` response field carrying the minted virtual key
/// (`sk-...`). Named once so the shape is asserted in one place (and against the
/// fake in Task 8's acceptance).
const LITELLM_KEY_FIELD: &str = "key";

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
async fn mint_at_litellm(
    state: &AppState,
    tenant_id: Uuid,
    knobs: &TenantKeyKnobs,
) -> ApiResult<Minted> {
    let url = format!(
        "{}/key/generate",
        state.cfg.llm_admin_url.trim_end_matches('/')
    );
    let resp = state
        .http
        .post(&url)
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

/// Resolve the tenant's virtual key: cache → sealed row → mint. Fails closed
/// (`Err`, never the master key) so the facade turns any failure into a 503. The
/// caller in tenant mode passes the AUTHENTICATED session's tenant.
///
/// Mint race (two concurrent first-uses for the same new tenant): both mint at
/// LiteLLM, both attempt the insert; `ON CONFLICT (tenant_id) DO NOTHING` lets one
/// win, the loser adopts the winner's sealed key and best-effort deletes its own
/// now-orphaned minted key (design resolution: no lock, DB is the arbiter).
pub async fn ensure_tenant_key(state: &AppState, tenant_id: Uuid) -> ApiResult<String> {
    // 1. In-memory cache (steady state).
    if let Some(k) = state.tenant_llm_keys.lock().await.get(&tenant_id).cloned() {
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
        state
            .tenant_llm_keys
            .lock()
            .await
            .insert(tenant_id, key.clone());
        return Ok(key);
    }

    // 3. Mint, seal, insert-or-adopt.
    let knobs = knobs_from_cfg(&state.cfg);
    let minted = mint_at_litellm(state, tenant_id, &knobs).await?;
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

    let key = if outcome.we_won {
        minted.key
    } else {
        // A concurrent minter won: adopt its sealed key and drop our orphan.
        let winner = sealer
            .open(&outcome.sealed, outcome.key_version, ctx)
            .await
            .map_err(|_| ApiError::Internal("tenant llm key unseal failed".into()))?;
        delete_at_litellm(state, &minted.key).await;
        winner
    };
    state
        .tenant_llm_keys
        .lock()
        .await
        .insert(tenant_id, key.clone());
    Ok(key)
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

    let knobs = knobs_from_cfg(&state.cfg);
    let minted = mint_at_litellm(state, tenant_id, &knobs).await?;
    let sealed = sealer
        .seal(&minted.key, ctx)
        .await
        .map_err(|_| ApiError::Internal("tenant llm key seal failed".into()))?;

    let old = fluidbox_db::rotate_tenant_llm_key(
        &state.pool,
        scope,
        &sealed.bytes,
        sealed.key_version,
        &key_alias(tenant_id),
        minted.token_id.as_deref(),
    )
    .await?;

    // Re-seed the cache with the new key (the old entry is now stale). Doing this
    // BEFORE the LiteLLM delete keeps in-flight facade calls on the new key.
    state
        .tenant_llm_keys
        .lock()
        .await
        .insert(tenant_id, minted.key);

    // Best-effort retire the old key at LiteLLM (unseal it first; never fail the
    // rotation on a LiteLLM hiccup). `None` = the tenant had no prior key.
    if let Some((old_sealed, old_kv)) = old {
        if let Ok(old_key) = sealer.open(&old_sealed, old_kv, ctx).await {
            delete_at_litellm(state, &old_key).await;
        }
    }
    Ok(())
}

/// Drop a tenant's cached virtual key. The rotate path re-seeds instead; this is
/// the standalone evict hook (e.g. a future tenant-suspend or manual invalidation)
/// so a cached key can be forced to re-read from the sealed row on next use.
// For-future-use per plan D7 resolution 7 (an explicit eviction site beyond
// rotate's re-seed); no current caller, mirrors Task 1's forward-declared surface.
#[allow(dead_code)]
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
