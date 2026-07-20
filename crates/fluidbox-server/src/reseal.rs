//! Legacy → KMS envelope re-seal job + parity/status admin surface (Phase D,
//! #32; design Gap 5 :1179-1200, plan D3-D4).
//!
//! Turning on KMS makes NEW seals v2 envelopes, but every credential written
//! before the flip is still a v1 (legacy) blob. Retiring `FLUIDBOX_CREDENTIAL_KEY`
//! is only safe once ZERO v1 blobs remain (the D4 boot gate in
//! `seal::check_retirement_gates` refuses otherwise). This module is the bridge:
//! a resumable, CAS-guarded job that walks all twelve sealed families, unseals
//! each v1 blob and re-seals it v2 under the row's per-tenant DEK (deployment-
//! global rows re-seal under the deployment tenant's DEK), plus the operator
//! endpoints that start it and report count parity.
//!
//! Design properties (plan D3):
//!   - **Predicate-driven, restart-safe.** Paging filters `<col>_key_version = 1`,
//!     so an already-re-sealed row is excluded — a crash mid-job leaves NO lock
//!     or cursor to reconcile; a re-run just re-scans and skips finished rows.
//!   - **Row-lock + CAS, no advisory lock.** Each row re-seals in its own short
//!     transaction: `SELECT … FOR UPDATE` (re-check still v1 under the lock) →
//!     unseal v1 → seal v2 → `UPDATE … SET col=$new, col_kv=2 WHERE id=$1 AND
//!     col_kv=1`. The lock + CAS make the oauth advisory lock unnecessary: a
//!     concurrent OAuth rotation (itself v2 once KMS is on) blocks on the lock and
//!     overwrites afterward — the re-sealed old token is superseded, never a
//!     clobber (system_worker.rs documents this at the call sites).
//!   - **One bad row never wedges the migration.** A per-row unseal failure (wrong
//!     legacy key / corrupt blob) is tallied and the job CONTINUES; the keyset
//!     cursor advances past it so it is never re-fetched within a pass.
//!   - **Auditable.** `reseal.start` / `reseal.finish` rows (`auth_audit_log`,
//!     tenant NULL — a deployment-level operator action). No per-row audit rows.
//!   - **Singleton.** `AppState.reseal_running` (an `AtomicBool`) is CAS-claimed;
//!     a second `POST` while a run is live gets a 409.
//!
//! Plaintext lives only for the microseconds between unseal and re-seal, inside a
//! `Zeroizing<String>` scrubbed on drop; it never enters `fluidbox-db` (sealed
//! bytes out of the lock reader, sealed bytes back into the CAS writer).

use crate::auth::Admin;
use crate::config::KmsMode;
use crate::error::{ApiError, ApiResult};
use crate::seal::{SealFamily, Sealer};
use crate::state::AppState;
use axum::extract::{ConnectInfo, State};
use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use chrono::{DateTime, Utc};
use fluidbox_db::identity::{self, AuditEntry};
use serde::Serialize;
use serde_json::{json, Value};
use sqlx::PgPool;
use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use uuid::Uuid;
use zeroize::Zeroizing;

/// One sealed family the job walks: its table, the sealed `bytea` column, that
/// column's `_key_version` companion, the row's stable unique KEY column
/// (`id` for every family except `tenant_llm_keys`, keyed by its `tenant_id`
/// primary key), and the [`SealFamily`] whose per-tenant DEK and AAD re-seal it.
/// EVERY field is a compile-time constant — the `fluidbox-db` layer builds its
/// `format!` SQL from these (never request data), which is exactly why that SQL is
/// injection-safe. This array IS the re-seal coverage set; it must stay in lockstep
/// with the twelve families `system_worker::sealed_key_version_counts` counts (a
/// unit test enforces the `table.column` ↔ `SealFamily` correspondence).
struct Family {
    table: &'static str,
    column: &'static str,
    version_column: &'static str,
    key_column: &'static str,
    seal_family: SealFamily,
}

const FAMILIES: &[Family] = &[
    Family {
        table: "integration_connections",
        column: "credential_sealed",
        version_column: "credential_key_version",
        key_column: "id",
        seal_family: SealFamily::ConnectionCredential,
    },
    Family {
        table: "integration_connections",
        column: "webhook_secret_sealed",
        version_column: "webhook_secret_key_version",
        key_column: "id",
        seal_family: SealFamily::ConnectionWebhookSecret,
    },
    Family {
        table: "integration_connections",
        column: "client_secret_sealed",
        version_column: "client_secret_key_version",
        key_column: "id",
        seal_family: SealFamily::ConnectionClientSecret,
    },
    Family {
        table: "trigger_subscriptions",
        column: "callback_secret_sealed",
        version_column: "callback_secret_key_version",
        key_column: "id",
        seal_family: SealFamily::SubscriptionCallbackSecret,
    },
    Family {
        table: "github_app_registrations",
        column: "pem_sealed",
        version_column: "pem_key_version",
        key_column: "id",
        seal_family: SealFamily::GithubAppPem,
    },
    Family {
        table: "github_app_registrations",
        column: "webhook_secret_sealed",
        version_column: "webhook_secret_key_version",
        key_column: "id",
        seal_family: SealFamily::GithubAppWebhookSecret,
    },
    Family {
        table: "github_app_registrations",
        column: "client_secret_sealed",
        version_column: "client_secret_key_version",
        key_column: "id",
        seal_family: SealFamily::GithubAppClientSecret,
    },
    Family {
        table: "org_idp_configs",
        column: "client_secret_sealed",
        version_column: "client_secret_key_version",
        key_column: "id",
        seal_family: SealFamily::IdpClientSecret,
    },
    Family {
        table: "login_flows",
        column: "pkce_verifier_sealed",
        version_column: "pkce_verifier_key_version",
        key_column: "id",
        seal_family: SealFamily::LoginPkceVerifier,
    },
    // Deployment-global (tenant_id NULL) — Task 3. `reseal_one` resolves the NULL
    // tenant to the deployment tenant's DEK via `Sealer::row_ctx`.
    Family {
        table: "oauth_client_registrations",
        column: "client_secret_sealed",
        version_column: "client_secret_key_version",
        key_column: "id",
        seal_family: SealFamily::RegistrationClientSecret,
    },
    Family {
        table: "oauth_client_registrations",
        column: "registration_access_token_sealed",
        version_column: "registration_access_token_key_version",
        key_column: "id",
        seal_family: SealFamily::RegistrationAccessToken,
    },
    // Tenant-owned, keyed by `tenant_id` (the PK — no `id` column) — Task 5.
    Family {
        table: "tenant_llm_keys",
        column: "litellm_key_sealed",
        version_column: "litellm_key_key_version",
        key_column: "tenant_id",
        seal_family: SealFamily::TenantLlmKey,
    },
];

/// Ids fetched per page. Bounded so each pass holds no more than this many ids in
/// memory; the keyset cursor advances one page at a time.
const PAGE: i64 = 100;

/// The v2 companion value a re-seal must produce (KMS on). Belt for the defensive
/// check in [`reseal_one`] — the job never runs with KMS off.
const KV_ENVELOPE: i16 = 2;

/// Per-family running tally, surfaced in status + the finish audit detail.
#[derive(Clone, Debug, Default, Serialize)]
pub struct FamilyProgress {
    pub family: String,
    pub resealed: u64,
    pub skipped: u64,
    pub failed: u64,
}

/// Live progress of the current/last re-seal run (behind `AppState.reseal_status`).
#[derive(Clone, Debug, Default, Serialize)]
pub struct ResealStatus {
    pub started_at: Option<DateTime<Utc>>,
    pub finished_at: Option<DateTime<Utc>>,
    pub families: Vec<FamilyProgress>,
    pub last_error: Option<String>,
}

/// A per-row outcome. NEVER an error — every row-level failure (unseal, seal, tx)
/// is folded into `Failed` so one bad row cannot wedge the migration.
enum RowOutcome {
    Resealed,
    Skipped,
    /// A redaction-safe reason (`family:id` + a generic class — never bytes,
    /// plaintext, or the underlying crypto error text).
    Failed(String),
}

// ─── admin surface ──────────────────────────────────────────────────────────

/// `POST /v1/admin/reseal` — start the background re-seal (operator only).
/// `202 Accepted` with the initial status; `409` if a run is already live or KMS
/// is off (re-sealing to v2 is meaningless without a KMS backend). Restart-safe,
/// so there is no persisted job to reconcile.
pub async fn start(
    _: Admin,
    headers: HeaderMap,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    State(state): State<AppState>,
) -> ApiResult<(StatusCode, Json<Value>)> {
    ensure_can_start(state.cfg.kms_mode, state.sealer.is_some(), false)?;
    // Atomically claim the singleton — TOCTOU-safe against a concurrent POST.
    if state
        .reseal_running
        .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
        .is_err()
    {
        return Err(ApiError::Conflict(
            "a re-seal job is already running".into(),
        ));
    }
    let sealer = state
        .sealer
        .clone()
        .expect("sealer present (KMS on ⇒ build_sealer returns Some; checked above)");
    let source_ip = client_source_ip(&headers, peer, state.cfg.trust_forwarded_for);
    // Reset the status so the endpoints reflect THIS run immediately (before the
    // spawned task has ticked).
    {
        let mut s = state.reseal_status.lock().await;
        *s = ResealStatus {
            started_at: Some(Utc::now()),
            finished_at: None,
            families: FAMILIES
                .iter()
                .map(|f| FamilyProgress {
                    family: f.seal_family.to_string(),
                    ..Default::default()
                })
                .collect(),
            last_error: None,
        };
    }
    tokio::spawn(run_job(state.clone(), sealer, source_ip));
    let body = status_body(&state).await?;
    Ok((StatusCode::ACCEPTED, Json(body)))
}

/// `GET /v1/admin/reseal` — authoritative live parity counts + job status
/// (operator only).
pub async fn status(_: Admin, State(state): State<AppState>) -> ApiResult<Json<Value>> {
    Ok(Json(status_body(&state).await?))
}

/// The shared response body: the AUTHORITATIVE live per-family legacy/envelope
/// counts (reused from `sealed_key_version_counts` — the same input the D4
/// retirement gate reads, so `legacy_total = 0` is exactly the retire-safe
/// condition) plus the in-memory run progress + running flag. The parity counts
/// reflect committed rows, so they show real-time progress even between the job's
/// per-family status snapshots.
async fn status_body(state: &AppState) -> ApiResult<Value> {
    let counts = fluidbox_db::system_worker::sealed_key_version_counts(&state.pool).await?;
    let families: Vec<Value> = counts
        .iter()
        .map(|c| json!({ "family": c.family, "legacy": c.legacy, "envelope": c.envelope }))
        .collect();
    let legacy_total: i64 = counts.iter().map(|c| c.legacy).sum();
    let job = state.reseal_status.lock().await.clone();
    let last_error = job.last_error.clone();
    Ok(json!({
        "running": state.reseal_running.load(Ordering::SeqCst),
        "kms_mode": kms_label(state.cfg.kms_mode),
        "legacy_total": legacy_total,
        "families": families,
        "job": job,
        "last_error": last_error,
    }))
}

/// Pure precondition guard, unit-tested without an `AppState`. The job re-seals to
/// v2, so it is meaningless with KMS off; a second run while one is live is
/// refused. Both are 409s carrying operator-facing text.
fn ensure_can_start(
    kms_mode: KmsMode,
    sealer_present: bool,
    already_running: bool,
) -> ApiResult<()> {
    if already_running {
        return Err(ApiError::Conflict(
            "a re-seal job is already running".into(),
        ));
    }
    if kms_mode == KmsMode::Off {
        return Err(ApiError::Conflict(
            "re-seal requires FLUIDBOX_KMS_MODE to be on (static or aws); it is currently off"
                .into(),
        ));
    }
    if !sealer_present {
        // Unreachable when KMS is on (build_sealer returns Some), but fail closed.
        return Err(ApiError::Conflict(
            "credential sealing is unavailable — cannot re-seal".into(),
        ));
    }
    Ok(())
}

fn kms_label(m: KmsMode) -> &'static str {
    match m {
        KmsMode::Off => "off",
        KmsMode::Static => "static",
        KmsMode::Aws => "aws",
    }
}

/// The audit `source_ip` for the operator action: the socket peer unless a
/// trusted proxy is declared (`FLUIDBOX_TRUST_FORWARDED_FOR`), never a
/// client-forgeable `X-Forwarded-For`. `None` collapses the "unknown" sentinel
/// (mirrors `admin_orgs::source_ip`).
fn client_source_ip(headers: &HeaderMap, peer: SocketAddr, trust: bool) -> Option<String> {
    let ip = crate::login::client_ip(headers, Some(peer), trust);
    (ip != "unknown").then_some(ip)
}

// ─── the job ────────────────────────────────────────────────────────────────

/// Drive one full re-seal pass over every family, snapshotting per-family
/// progress into `AppState.reseal_status` and bracketing the run with
/// `reseal.start` / `reseal.finish` audit rows. A drop guard ALWAYS releases the
/// singleton flag — even on an early return or a panic — so a failed run never
/// wedges future ones.
async fn run_job(state: AppState, sealer: Sealer, source_ip: Option<String>) {
    struct RunningGuard(AppState);
    impl Drop for RunningGuard {
        fn drop(&mut self) {
            self.0.reseal_running.store(false, Ordering::SeqCst);
        }
    }
    let _guard = RunningGuard(state.clone());

    let started = Utc::now();
    audit(&state, source_ip.as_deref(), "reseal.start", None).await;

    let mut families: Vec<FamilyProgress> = Vec::with_capacity(FAMILIES.len());
    let mut last_error: Option<String> = None;
    for fam in FAMILIES {
        let (progress, err) = reseal_family(&state.pool, &sealer, fam).await;
        if err.is_some() {
            last_error = err;
        }
        families.push(progress);
        // Snapshot after each family. The authoritative live counts in
        // status_body show intra-family progress; this is the running tally.
        let mut s = state.reseal_status.lock().await;
        s.families = families.clone();
        s.last_error = last_error.clone();
    }

    let finished = Utc::now();
    let detail = finish_detail(&families, &last_error, started, finished);
    {
        let mut s = state.reseal_status.lock().await;
        s.families = families.clone();
        s.last_error = last_error.clone();
        s.finished_at = Some(finished);
    }
    audit(&state, source_ip.as_deref(), "reseal.finish", Some(&detail)).await;
}

/// Re-seal every still-v1 row of ONE family, keyset-paged. Returns the family's
/// tally and the last row-level error seen (surfaced in status + the finish
/// audit). Never returns `Err` — paging failures break the loop with the error
/// recorded, row failures are tallied and skipped past by the cursor.
async fn reseal_family(
    pool: &PgPool,
    sealer: &Sealer,
    fam: &Family,
) -> (FamilyProgress, Option<String>) {
    let mut progress = FamilyProgress {
        family: fam.seal_family.to_string(),
        ..Default::default()
    };
    let mut last_error: Option<String> = None;
    let mut after = Uuid::nil();
    loop {
        let ids = match fluidbox_db::system_worker::reseal_candidate_ids(
            pool,
            fam.table,
            fam.column,
            fam.version_column,
            fam.key_column,
            after,
            PAGE,
        )
        .await
        {
            Ok(v) => v,
            Err(e) => {
                last_error = Some(format!("{}: paging failed: {e}", fam.seal_family));
                break;
            }
        };
        if ids.is_empty() {
            break;
        }
        for id in &ids {
            match reseal_one(pool, sealer, fam, *id).await {
                RowOutcome::Resealed => progress.resealed += 1,
                RowOutcome::Skipped => progress.skipped += 1,
                RowOutcome::Failed(reason) => {
                    progress.failed += 1;
                    last_error = Some(reason);
                }
            }
        }
        // Advance the cursor past this page — this is what guarantees forward
        // progress even past a row we cannot re-seal (it stays v1 but is never
        // re-fetched within the pass).
        after = *ids.last().expect("non-empty page");
    }
    (progress, last_error)
}

/// Re-seal ONE row in a short transaction. Locks the row, re-checks it is still
/// v1 under the lock, unseals the v1 blob and re-seals it v2 under the row's
/// per-tenant DEK, then CAS-writes it. Any row-level failure becomes `Failed` (the
/// job continues); an already-v2 row or a lost CAS is `Skipped`.
async fn reseal_one(pool: &PgPool, sealer: &Sealer, fam: &Family, id: Uuid) -> RowOutcome {
    let family = fam.seal_family;
    // The per-row lock + CAS are cross-tenant (the job walks every tenant), so the
    // transaction carries the audited system-worker bypass GUC — opened inside
    // fluidbox-db (`reseal_begin` → `worker_tx`) so the bypass stays one grep-able
    // choke point. Without it the `SELECT … FOR UPDATE` sees no row under FORCE RLS.
    let mut tx = match fluidbox_db::system_worker::reseal_begin(pool).await {
        Ok(t) => t,
        Err(e) => return RowOutcome::Failed(format!("{family}:{id}: begin failed: {e}")),
    };
    let locked = match fluidbox_db::system_worker::reseal_lock_row(
        &mut tx,
        fam.table,
        fam.column,
        fam.version_column,
        fam.key_column,
        id,
    )
    .await
    {
        Ok(l) => l,
        Err(e) => {
            let _ = tx.rollback().await;
            return RowOutcome::Failed(format!("{family}:{id}: lock failed: {e}"));
        }
    };
    // Row vanished since paging, column now NULL, or already re-sealed (the
    // re-check under the lock) → skip. A concurrent writer that moved it off v1
    // is not an error.
    let Some((maybe_bytes, kv, tenant_id)) = locked else {
        let _ = tx.rollback().await;
        return RowOutcome::Skipped;
    };
    if kv != 1 {
        let _ = tx.rollback().await;
        return RowOutcome::Skipped;
    }
    let Some(bytes) = maybe_bytes else {
        let _ = tx.rollback().await;
        return RowOutcome::Skipped;
    };

    // A deployment-global row (oauth_client_registrations) carries a NULL tenant;
    // `row_ctx` resolves it to the deployment tenant's DEK. Tenant-owned rows keep
    // their own tenant.
    let ctx = sealer.row_ctx(tenant_id, family);
    // Unseal v1 → re-seal v2. A per-row unseal failure (wrong legacy key / corrupt
    // blob) is recorded and the migration CONTINUES.
    let plaintext = match sealer.open(&bytes, 1, ctx).await {
        Ok(p) => Zeroizing::new(p),
        Err(_) => {
            let _ = tx.rollback().await;
            return RowOutcome::Failed(format!(
                "{family}:{id}: unseal failed (wrong legacy key or corrupt blob)"
            ));
        }
    };
    let sealed = match sealer.seal(plaintext.as_str(), ctx).await {
        Ok(s) => s,
        Err(_) => {
            let _ = tx.rollback().await;
            return RowOutcome::Failed(format!("{family}:{id}: re-seal failed"));
        }
    };
    drop(plaintext); // scrubbed on drop
                     // The job only runs with KMS on, so seal() MUST yield v2 — never stamp a v1
                     // blob with the v2 companion.
    if sealed.key_version != KV_ENVELOPE {
        let _ = tx.rollback().await;
        return RowOutcome::Failed(format!("{family}:{id}: unexpected non-v2 seal"));
    }
    let affected = match fluidbox_db::system_worker::reseal_write_row(
        &mut tx,
        fam.table,
        fam.column,
        fam.version_column,
        fam.key_column,
        id,
        &sealed.bytes,
    )
    .await
    {
        Ok(n) => n,
        Err(e) => {
            let _ = tx.rollback().await;
            return RowOutcome::Failed(format!("{family}:{id}: write failed: {e}"));
        }
    };
    if let Err(e) = tx.commit().await {
        return RowOutcome::Failed(format!("{family}:{id}: commit failed: {e}"));
    }
    // rows-affected 0 = a concurrent writer won the CAS (already off v1) → skip.
    if affected == 1 {
        RowOutcome::Resealed
    } else {
        RowOutcome::Skipped
    }
}

/// The `reseal.finish` audit detail: per-family tallies + totals + duration +
/// the last error. No secrets — only counts and a family:id-shaped reason.
fn finish_detail(
    families: &[FamilyProgress],
    last_error: &Option<String>,
    started: DateTime<Utc>,
    finished: DateTime<Utc>,
) -> Value {
    let resealed: u64 = families.iter().map(|f| f.resealed).sum();
    let skipped: u64 = families.iter().map(|f| f.skipped).sum();
    let failed: u64 = families.iter().map(|f| f.failed).sum();
    json!({
        "families": families,
        "total": { "resealed": resealed, "skipped": skipped, "failed": failed },
        "duration_ms": (finished - started).num_milliseconds(),
        "last_error": last_error,
    })
}

/// Append a deployment-level operator audit row (`tenant_id` NULL). Best-effort:
/// a dead database must not panic the job task.
async fn audit(state: &AppState, source_ip: Option<&str>, action: &str, detail: Option<&Value>) {
    let Ok(mut conn) = state.pool.acquire().await else {
        tracing::warn!("re-seal audit '{action}' skipped: database unavailable");
        return;
    };
    if let Err(e) = identity::insert_audit(
        &mut conn,
        AuditEntry {
            tenant_id: None,
            actor_kind: "operator",
            actor_id: None,
            source_ip,
            request_id: None,
            action,
            target: None,
            success: true,
            detail,
        },
    )
    .await
    {
        tracing::warn!("re-seal audit '{action}' insert failed: {e}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::seal::SealCtx;

    // ─── pure unit tests (no DB) ────────────────────────────────────────────

    #[test]
    fn ensure_can_start_guards() {
        // KMS off → refused (nothing to re-seal to).
        assert!(matches!(
            ensure_can_start(KmsMode::Off, true, false),
            Err(ApiError::Conflict(_))
        ));
        // A second run while one is live → refused.
        assert!(matches!(
            ensure_can_start(KmsMode::Static, true, true),
            Err(ApiError::Conflict(_))
        ));
        // KMS on but sealing somehow unavailable → refused (fail closed).
        assert!(matches!(
            ensure_can_start(KmsMode::Static, false, false),
            Err(ApiError::Conflict(_))
        ));
        // The green paths.
        assert!(ensure_can_start(KmsMode::Static, true, false).is_ok());
        assert!(ensure_can_start(KmsMode::Aws, true, false).is_ok());
    }

    #[test]
    fn families_cover_all_sealed_columns() {
        // Nine tenant-owned families + Task 3's two deployment-global
        // oauth_client_registrations columns + Task 5's tenant_llm_keys. MUST match
        // system_worker::sealed_key_version_counts (both feed the retirement gate).
        assert_eq!(FAMILIES.len(), 12, "one entry per sealed column");
        for f in FAMILIES {
            // The SealFamily Display IS "table.column" — keep the triple coherent.
            assert_eq!(
                f.seal_family.to_string(),
                format!("{}.{}", f.table, f.column),
                "SealFamily label must match table.column"
            );
            // The companion column is the sealed column with `_sealed` → `_key_version`.
            assert_eq!(
                f.version_column,
                f.column.replace("_sealed", "_key_version"),
                "companion column derives from the sealed column"
            );
            // Every family has a Uuid row key the job pages/locks/CAS-writes by.
            assert!(
                f.key_column == "id" || f.key_column == "tenant_id",
                "unexpected key column '{}' for {}",
                f.key_column,
                f.seal_family
            );
        }
    }

    // Cross-crate lockstep belt: the family SET the fluidbox-db retirement counter
    // reports MUST equal the family set reseal::FAMILIES walks. A column added to
    // one and not the other (a v1 row of an uncounted family) would escape the
    // re-seal job AND the retirement gate and orphan when the legacy key retires.
    #[tokio::test]
    async fn counts_and_families_cover_the_same_set() {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("skipping: DATABASE_URL not set");
            return;
        };
        let pool = fluidbox_db::connect(&url, None).await.expect("connect");
        let from_counts: std::collections::BTreeSet<String> =
            fluidbox_db::system_worker::sealed_key_version_counts(&pool)
                .await
                .unwrap()
                .into_iter()
                .map(|c| c.family)
                .collect();
        let from_families: std::collections::BTreeSet<String> =
            FAMILIES.iter().map(|f| f.seal_family.to_string()).collect();
        assert_eq!(
            from_counts, from_families,
            "sealed_key_version_counts and reseal::FAMILIES must cover the identical family set"
        );
    }

    #[test]
    fn status_serializes_expected_shape() {
        let s = ResealStatus {
            started_at: None,
            finished_at: None,
            families: vec![FamilyProgress {
                family: "integration_connections.credential_sealed".into(),
                resealed: 2,
                skipped: 1,
                failed: 0,
            }],
            last_error: Some("integration_connections.credential_sealed:… : boom".into()),
        };
        let v = serde_json::to_value(&s).unwrap();
        assert_eq!(
            v["families"][0]["family"],
            "integration_connections.credential_sealed"
        );
        assert_eq!(v["families"][0]["resealed"], 2);
        assert_eq!(v["families"][0]["skipped"], 1);
        assert!(v["last_error"].is_string());
        assert!(v["started_at"].is_null());
    }

    #[test]
    fn finish_detail_sums_totals() {
        let fams = vec![
            FamilyProgress {
                family: "a".into(),
                resealed: 3,
                skipped: 1,
                failed: 1,
            },
            FamilyProgress {
                family: "b".into(),
                resealed: 2,
                skipped: 0,
                failed: 0,
            },
        ];
        let d = finish_detail(&fams, &Some("boom".into()), Utc::now(), Utc::now());
        assert_eq!(d["total"]["resealed"], 5);
        assert_eq!(d["total"]["skipped"], 1);
        assert_eq!(d["total"]["failed"], 1);
        assert_eq!(d["last_error"], "boom");
        assert!(d["families"].as_array().unwrap().len() == 2);
    }

    // ─── DB-backed job core (self-skips without DATABASE_URL) ───────────────

    // A legacy-only Sealer seeds v1 blobs; a legacy+KMS Sealer runs the job.
    // Keys are throwaway hex (32 bytes = 64 hex chars).
    fn legacy_hex() -> String {
        "ab".repeat(32)
    }
    fn kek_hex() -> String {
        "cd".repeat(32)
    }

    async fn cleanup(pool: &PgPool, tenant: Uuid) {
        // Children first (tenant FKs are NO ACTION); login_flows references
        // org_idp_configs, so it precedes it.
        for stmt in [
            "delete from login_flows where tenant_id = $1",
            "delete from org_idp_configs where tenant_id = $1",
            "delete from github_app_registrations where tenant_id = $1",
            "delete from integration_connections where tenant_id = $1",
            "delete from tenant_deks where tenant_id = $1",
            "delete from tenants where id = $1",
        ] {
            sqlx::query(stmt).bind(tenant).execute(pool).await.unwrap();
        }
    }

    #[tokio::test]
    async fn job_core_reseals_three_families_and_survives_a_corrupt_row() {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("skipping: DATABASE_URL not set");
            return;
        };
        let pool = fluidbox_db::connect(&url, None).await.expect("connect");
        let org = fluidbox_db::identity::create_org(
            &pool,
            &format!("t-{}", Uuid::now_v7().simple()),
            None,
        )
        .await
        .unwrap();
        let tenant = org.id;
        let scope = fluidbox_db::TenantScope::assume(tenant);

        let legacy = Sealer::from_key_string(&legacy_hex()).unwrap();
        let sealer =
            Sealer::for_test_static_kms(Some(&legacy_hex()), &kek_hex(), pool.clone(), tenant)
                .unwrap();

        // Seal a v1 blob for a family under this tenant.
        let seal_v1 = |plaintext: &'static str, family: SealFamily| {
            let legacy = legacy.clone();
            async move {
                legacy
                    .seal(plaintext, SealCtx::new(tenant, family))
                    .await
                    .unwrap()
                    .bytes
            }
        };

        // (1) integration_connections.credential_sealed — seed a good v1 row.
        let cred_v1 = seal_v1("cred-secret", SealFamily::ConnectionCredential).await;
        let conn = fluidbox_db::create_connection(
            &pool,
            scope,
            "custom",
            "rs-acct",
            "rs-conn",
            Some(cred_v1.as_slice()),
            1,
            &json!([]),
            &json!({}),
            &json!({}),
            None,
            1,
            fluidbox_db::ConnectionAuth::static_active(),
            fluidbox_db::ConnectionOwner::Organization,
            None,
        )
        .await
        .unwrap();

        // (2) github_app_registrations.pem_sealed.
        let pem_v1 = seal_v1("pem-secret", SealFamily::GithubAppPem).await;
        let reg_id = Uuid::now_v7();
        sqlx::query(
            "insert into github_app_registrations (id, tenant_id, pem_sealed, pem_key_version)
             values ($1, $2, $3, 1)",
        )
        .bind(reg_id)
        .bind(tenant)
        .bind(pem_v1.as_slice())
        .execute(&pool)
        .await
        .unwrap();

        // (3) org_idp_configs.client_secret_sealed.
        let idp_v1 = seal_v1("idp-secret", SealFamily::IdpClientSecret).await;
        let idp_id = Uuid::now_v7();
        sqlx::query(
            "insert into org_idp_configs
               (id, tenant_id, issuer, client_id, claim_mappings, client_secret_sealed, client_secret_key_version)
             values ($1, $2, 'https://issuer.test', 'client-abc', '{}'::jsonb, $3, 1)",
        )
        .bind(idp_id)
        .bind(tenant)
        .bind(idp_v1.as_slice())
        .execute(&pool)
        .await
        .unwrap();

        // Re-seal each seeded row directly (scoped to OUR ids — reseal_family is a
        // global scan and the shared test DB holds other tenants' rows).
        assert!(matches!(
            reseal_one(&pool, &sealer, &FAMILIES[0], conn.id).await,
            RowOutcome::Resealed
        ));
        assert!(matches!(
            reseal_one(&pool, &sealer, &FAMILIES[4], reg_id).await,
            RowOutcome::Resealed
        ));
        assert!(matches!(
            reseal_one(&pool, &sealer, &FAMILIES[7], idp_id).await,
            RowOutcome::Resealed
        ));

        // Parity flipped: each row is now v2 AND re-opens to the original plaintext.
        let (cred_bytes, cred_kv) =
            fluidbox_db::connection_credential_sealed(&pool, scope, conn.id)
                .await
                .unwrap()
                .unwrap();
        assert_eq!(cred_kv, 2);
        assert_eq!(
            sealer
                .open(
                    &cred_bytes,
                    2,
                    SealCtx::new(tenant, SealFamily::ConnectionCredential)
                )
                .await
                .unwrap(),
            "cred-secret"
        );
        assert_eq!(
            reopen(
                &pool,
                &sealer,
                "github_app_registrations",
                "pem_sealed",
                "pem_key_version",
                reg_id,
                tenant,
                SealFamily::GithubAppPem
            )
            .await,
            "pem-secret"
        );
        assert_eq!(
            reopen(
                &pool,
                &sealer,
                "org_idp_configs",
                "client_secret_sealed",
                "client_secret_key_version",
                idp_id,
                tenant,
                SealFamily::IdpClientSecret
            )
            .await,
            "idp-secret"
        );

        // Re-running a now-v2 row is a no-op skip (the re-check under the lock).
        assert!(matches!(
            reseal_one(&pool, &sealer, &FAMILIES[0], conn.id).await,
            RowOutcome::Skipped
        ));

        // A corrupt v1 blob → Failed tally, and a sibling good row still re-seals.
        let bad = fluidbox_db::create_connection(
            &pool,
            scope,
            "custom",
            "rs-bad",
            "rs-bad",
            Some(b"not-a-valid-sealed-blob"),
            1,
            &json!([]),
            &json!({}),
            &json!({}),
            None,
            1,
            fluidbox_db::ConnectionAuth::static_active(),
            fluidbox_db::ConnectionOwner::Organization,
            None,
        )
        .await
        .unwrap();
        let good2_v1 = seal_v1("cred-2", SealFamily::ConnectionCredential).await;
        let good2 = fluidbox_db::create_connection(
            &pool,
            scope,
            "custom",
            "rs-good2",
            "rs-good2",
            Some(good2_v1.as_slice()),
            1,
            &json!([]),
            &json!({}),
            &json!({}),
            None,
            1,
            fluidbox_db::ConnectionAuth::static_active(),
            fluidbox_db::ConnectionOwner::Organization,
            None,
        )
        .await
        .unwrap();
        assert!(matches!(
            reseal_one(&pool, &sealer, &FAMILIES[0], bad.id).await,
            RowOutcome::Failed(_)
        ));
        // The corrupt row stays v1 (untouched); the good sibling re-seals.
        let (_b, bad_kv) = fluidbox_db::connection_credential_sealed(&pool, scope, bad.id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(bad_kv, 1, "a failed row is left untouched at v1");
        assert!(matches!(
            reseal_one(&pool, &sealer, &FAMILIES[0], good2.id).await,
            RowOutcome::Resealed
        ));

        cleanup(&pool, tenant).await;
    }

    #[tokio::test]
    async fn job_reseals_a_global_registration_row_under_the_deployment_dek() {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("skipping: DATABASE_URL not set");
            return;
        };
        let pool = fluidbox_db::connect(&url, None).await.expect("connect");
        // A real tenant is the DEPLOYMENT tenant here: a global row (tenant_id
        // NULL) has no DEK of its own, so it seals under this one.
        let org = fluidbox_db::identity::create_org(
            &pool,
            &format!("t-{}", Uuid::now_v7().simple()),
            None,
        )
        .await
        .unwrap();
        let tenant = org.id;

        let legacy = Sealer::from_key_string(&legacy_hex()).unwrap();
        let sealer =
            Sealer::for_test_static_kms(Some(&legacy_hex()), &kek_hex(), pool.clone(), tenant)
                .unwrap();

        // Seed a v1 GLOBAL registration row carrying a confidential secret.
        let secret_v1 = legacy
            .seal(
                "reg-secret",
                SealCtx::new(tenant, SealFamily::RegistrationClientSecret),
            )
            .await
            .unwrap()
            .bytes;
        let reg_id = Uuid::now_v7();
        sqlx::query(
            "insert into oauth_client_registrations
               (id, tenant_id, issuer, redirect_uri, source, client_id,
                client_secret_sealed, client_secret_key_version)
             values ($1, null, 'https://as.reseal.test', 'https://fbx.test/v1/oauth/callback',
                     'dcr', 'dcr-client-reseal', $2, 1)",
        )
        .bind(reg_id)
        .bind(secret_v1.as_slice())
        .execute(&pool)
        .await
        .unwrap();

        // FAMILIES[9] is oauth_client_registrations.client_secret_sealed.
        assert_eq!(
            FAMILIES[9].seal_family.to_string(),
            "oauth_client_registrations.client_secret_sealed"
        );
        assert!(matches!(
            reseal_one(&pool, &sealer, &FAMILIES[9], reg_id).await,
            RowOutcome::Resealed
        ));

        // The row is now v2 and re-opens under the DEPLOYMENT ctx (NULL tenant →
        // deployment tenant's DEK), proving row_ctx resolved the global row.
        let (bytes, kv): (Vec<u8>, i16) = sqlx::query_as(
            "select client_secret_sealed, client_secret_key_version
             from oauth_client_registrations where id = $1",
        )
        .bind(reg_id)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(kv, 2);
        assert_eq!(
            sealer
                .open(
                    &bytes,
                    2,
                    sealer.deployment_ctx(SealFamily::RegistrationClientSecret)
                )
                .await
                .unwrap(),
            "reg-secret"
        );

        sqlx::query("delete from oauth_client_registrations where id = $1")
            .bind(reg_id)
            .execute(&pool)
            .await
            .unwrap();
        cleanup(&pool, tenant).await;
    }

    // Read a sealed column + its companion version back and open it as v2.
    #[allow(clippy::too_many_arguments)]
    async fn reopen(
        pool: &PgPool,
        sealer: &Sealer,
        table: &str,
        column: &str,
        version_column: &str,
        id: Uuid,
        tenant: Uuid,
        family: SealFamily,
    ) -> String {
        let (bytes, kv): (Vec<u8>, i16) = sqlx::query_as(sqlx::AssertSqlSafe(format!(
            "select {column}, {version_column} from {table} where id = $1"
        )))
        .bind(id)
        .fetch_one(pool)
        .await
        .unwrap();
        assert_eq!(kv, 2, "re-sealed to v2");
        sealer
            .open(&bytes, 2, SealCtx::new(tenant, family))
            .await
            .unwrap()
    }
}
