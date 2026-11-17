//! KEK rotation: re-wrap every per-tenant DEK from the previous KEK to the
//! current one (`FLUIDBOX_KMS_PREVIOUS_STATIC_KEK`).
//!
//! Rotating a KEK does not touch a single sealed credential. Blobs are sealed
//! under per-tenant DEKs; the KEK only wraps those DEKs. So a rotation unwraps
//! each `tenant_deks` row under the PREVIOUS KEK and re-wraps the SAME DEK under
//! the CURRENT one, and the boot gate in [`crate::kms`] then sees a single KEK
//! again. It runs at boot, before that gate (`seal::check_retirement_gates`).
//!
//! The guarantees, in the order the code establishes them:
//!   1. A row under any THIRD KEK refuses the whole run before anything is
//!      unwrapped - this never guesses at keys it was not given.
//!   2. Every new wrapping is PROVEN (re-opened under the current KEK and compared
//!      to the original DEK) for EVERY row before ANY row is written. A row the
//!      previous KEK cannot open aborts the run with the store untouched.
//!   3. Each write is a compare-and-swap on the exact wrapping that was read, so
//!      two replicas rotating at once converge instead of interleaving.
//!   4. A crash part-way leaves rows under either the previous or the current
//!      KEK, both of which a re-run accepts, so the run is resumable; a finished
//!      store makes a re-run a no-op.

use crate::kms::KeyWrapper;
use anyhow::Context;
use async_trait::async_trait;
use sqlx::PgPool;
use uuid::Uuid;

/// The storage a KEK rotation needs. Production uses [`PgDekStore`]; the tests
/// use an in-memory store, because the rotation is deployment-wide and a shared
/// test database holds other tests' DEKs under other KEKs.
#[async_trait]
pub(crate) trait DekStore: Send + Sync {
    /// Every DEK row, all tenants and versions.
    async fn all(&self) -> anyhow::Result<Vec<fluidbox_db::TenantDekRow>>;
    /// One row, re-read after a lost compare-and-swap.
    async fn get(
        &self,
        tenant_id: Uuid,
        version: i32,
    ) -> anyhow::Result<Option<fluidbox_db::TenantDekRow>>;
    /// Replace `expected`'s wrapping if the row still holds it; `false` if it changed.
    async fn swap(
        &self,
        expected: &fluidbox_db::TenantDekRow,
        new_kek_id: &str,
        new_wrapped: &[u8],
    ) -> anyhow::Result<bool>;
}

/// [`DekStore`] over Postgres, through the named `system_worker` entry points
/// (the listing and the swap are cross-tenant by construction).
pub(crate) struct PgDekStore<'a>(pub &'a PgPool);

#[async_trait]
impl DekStore for PgDekStore<'_> {
    async fn all(&self) -> anyhow::Result<Vec<fluidbox_db::TenantDekRow>> {
        Ok(fluidbox_db::system_worker::tenant_deks_for_rewrap(self.0).await?)
    }
    async fn get(
        &self,
        tenant_id: Uuid,
        version: i32,
    ) -> anyhow::Result<Option<fluidbox_db::TenantDekRow>> {
        let scope = fluidbox_db::TenantScope::assume(tenant_id);
        let mut tx = fluidbox_db::scoped_tx(self.0, scope).await?;
        let row = fluidbox_db::get_tenant_dek(&mut *tx, tenant_id, version).await?;
        tx.commit().await?;
        Ok(row)
    }
    async fn swap(
        &self,
        expected: &fluidbox_db::TenantDekRow,
        new_kek_id: &str,
        new_wrapped: &[u8],
    ) -> anyhow::Result<bool> {
        Ok(fluidbox_db::system_worker::swap_tenant_dek_wrapping(
            self.0,
            expected,
            new_kek_id,
            new_wrapped,
        )
        .await?)
    }
}

/// What a rotation did: rows it re-wrapped, and rows already under the current
/// KEK (left by an earlier, interrupted run or by a concurrent replica).
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct RewrapReport {
    pub rewrapped: usize,
    pub already_current: usize,
}

/// Rotate the deployment's KEK: re-wrap every DEK stored under `previous` so it
/// is wrapped under `current`. Runs at boot, BEFORE the KEK compatibility gate,
/// when `FLUIDBOX_KMS_PREVIOUS_STATIC_KEK` is set.
pub async fn rewrap_previous_kek(
    pool: &PgPool,
    previous: &dyn KeyWrapper,
    current: &dyn KeyWrapper,
) -> anyhow::Result<RewrapReport> {
    rewrap_with(&PgDekStore(pool), previous, current).await
}

pub(crate) async fn rewrap_with(
    store: &dyn DekStore,
    previous: &dyn KeyWrapper,
    current: &dyn KeyWrapper,
) -> anyhow::Result<RewrapReport> {
    let (prev_id, cur_id) = (previous.kek_id(), current.kek_id());
    if prev_id == cur_id {
        anyhow::bail!(
            "FLUIDBOX_KMS_PREVIOUS_STATIC_KEK is the SAME key as the configured KEK ('{cur_id}') — \
             there is nothing to rotate; remove the variable"
        );
    }
    let rows = store
        .all()
        .await
        .context("KEK rotation: could not read tenant_deks")?;

    // (1) Refuse a third KEK before unwrapping anything.
    let foreign: std::collections::BTreeSet<&str> = rows
        .iter()
        .map(|r| r.kek_id.as_str())
        .filter(|k| *k != prev_id && *k != cur_id)
        .collect();
    if !foreign.is_empty() {
        anyhow::bail!(
            "KEK rotation refused: tenant_deks holds DEKs wrapped under {} KEK(s) that are \
             neither the previous ('{prev_id}') nor the current ('{cur_id}'): {}. Nothing was \
             changed",
            foreign.len(),
            foreign.into_iter().collect::<Vec<_>>().join(", ")
        );
    }

    // (2) Compute and PROVE every new wrapping before writing any.
    let mut report = RewrapReport::default();
    let mut planned = Vec::new();
    for row in &rows {
        if row.kek_id == cur_id {
            report.already_current += 1;
            continue;
        }
        let dek = previous
            .unwrap(&row.wrapped_dek, &row.kek_id, row.tenant_id, row.version)
            .await
            .with_context(|| {
                format!(
                    "KEK rotation: the previous KEK could not open tenant {} DEK v{} — nothing \
                     was changed",
                    row.tenant_id, row.version
                )
            })?;
        if dek.len() != 32 {
            anyhow::bail!(
                "KEK rotation: tenant {} DEK v{} is not 32 bytes — nothing was changed",
                row.tenant_id,
                row.version
            );
        }
        let wrapped = current.wrap(&dek, row.tenant_id, row.version).await?;
        let reopened = current
            .unwrap(&wrapped, cur_id, row.tenant_id, row.version)
            .await
            .context("KEK rotation: the current KEK could not open its own wrapping")?;
        if reopened.as_slice() != dek.as_slice() {
            anyhow::bail!(
                "KEK rotation: re-wrapping tenant {} DEK v{} did not round-trip — nothing was \
                 changed",
                row.tenant_id,
                row.version
            );
        }
        planned.push((row, wrapped));
    }

    // (3) Write each one with a compare-and-swap.
    for (row, wrapped) in planned {
        if store.swap(row, cur_id, &wrapped).await? {
            report.rewrapped += 1;
            continue;
        }
        match store.get(row.tenant_id, row.version).await? {
            Some(now) if now.kek_id == cur_id => {
                // Another replica finished this row first. Confirm it opens.
                current
                    .unwrap(&now.wrapped_dek, &now.kek_id, now.tenant_id, now.version)
                    .await
                    .with_context(|| {
                        format!(
                            "KEK rotation: tenant {} DEK v{} was re-wrapped concurrently but the \
                             current KEK cannot open it",
                            now.tenant_id, now.version
                        )
                    })?;
                report.already_current += 1;
            }
            Some(now) => anyhow::bail!(
                "KEK rotation: tenant {} DEK v{} changed during the run and is now under KEK \
                 '{}', which is neither the previous nor the current KEK — refusing",
                now.tenant_id,
                now.version,
                now.kek_id
            ),
            None => anyhow::bail!(
                "KEK rotation: tenant {} DEK v{} disappeared during the run — refusing",
                row.tenant_id,
                row.version
            ),
        }
    }
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kms::{StaticKek, DEK_VERSION};

    fn kek(byte: &str) -> StaticKek {
        StaticKek::from_key_string(&byte.repeat(32)).unwrap()
    }

    fn dek_row(tenant: Uuid, kek_id: &str, wrapped: Vec<u8>) -> fluidbox_db::TenantDekRow {
        fluidbox_db::TenantDekRow {
            tenant_id: tenant,
            version: DEK_VERSION,
            kek_id: kek_id.to_string(),
            wrapped_dek: wrapped,
            created_at: chrono::Utc::now(),
            retired_at: None,
        }
    }

    //
    // The re-wrap is deployment-wide by construction, so its ALGORITHM is tested
    // against an in-memory store: a shared test database holds other tests' DEK
    // rows under other KEKs, which would (correctly) make a real global run refuse.
    // The Postgres store's compare-and-swap is tested separately below.

    /// One planted race: just before the swap numbered `at` (0-based) lands, the
    /// stored row is replaced as a concurrent writer would.
    type PlantedRace = Option<(usize, String, Vec<u8>)>;

    #[derive(Default)]
    struct MemStore {
        rows: std::sync::Mutex<Vec<fluidbox_db::TenantDekRow>>,
        race: std::sync::Mutex<PlantedRace>,
        swaps: std::sync::atomic::AtomicUsize,
    }

    impl MemStore {
        fn with(rows: Vec<fluidbox_db::TenantDekRow>) -> Self {
            Self {
                rows: std::sync::Mutex::new(rows),
                ..Self::default()
            }
        }
        fn snapshot(&self) -> Vec<(Uuid, i32, String, Vec<u8>)> {
            self.rows
                .lock()
                .unwrap()
                .iter()
                .map(|r| {
                    (
                        r.tenant_id,
                        r.version,
                        r.kek_id.clone(),
                        r.wrapped_dek.clone(),
                    )
                })
                .collect()
        }
    }

    #[async_trait]
    impl DekStore for MemStore {
        async fn all(&self) -> anyhow::Result<Vec<fluidbox_db::TenantDekRow>> {
            Ok(self.rows.lock().unwrap().clone())
        }
        async fn get(
            &self,
            tenant_id: Uuid,
            version: i32,
        ) -> anyhow::Result<Option<fluidbox_db::TenantDekRow>> {
            Ok(self
                .rows
                .lock()
                .unwrap()
                .iter()
                .find(|r| r.tenant_id == tenant_id && r.version == version)
                .cloned())
        }
        async fn swap(
            &self,
            expected: &fluidbox_db::TenantDekRow,
            new_kek_id: &str,
            new_wrapped: &[u8],
        ) -> anyhow::Result<bool> {
            use std::sync::atomic::Ordering;
            let n = self.swaps.fetch_add(1, Ordering::SeqCst);
            let mut rows = self.rows.lock().unwrap();
            let row = rows
                .iter_mut()
                .find(|r| r.tenant_id == expected.tenant_id && r.version == expected.version)
                .expect("row exists");
            let mut race = self.race.lock().unwrap();
            if matches!(race.as_ref(), Some((at, _, _)) if *at == n) {
                let (_, kek_id, wrapped) = race.take().unwrap();
                row.kek_id = kek_id;
                row.wrapped_dek = wrapped;
            }
            if row.kek_id == expected.kek_id && row.wrapped_dek == expected.wrapped_dek {
                row.kek_id = new_kek_id.to_string();
                row.wrapped_dek = new_wrapped.to_vec();
                Ok(true)
            } else {
                Ok(false)
            }
        }
    }

    /// `n` tenants, each with a random DEK wrapped under `k`. Returns the rows and
    /// the plaintext DEKs they must still open to after any rotation.
    async fn seeded(
        k: &StaticKek,
        n: usize,
    ) -> (Vec<fluidbox_db::TenantDekRow>, Vec<(Uuid, [u8; 32])>) {
        let mut rows = Vec::new();
        let mut deks = Vec::new();
        for _ in 0..n {
            let tenant = Uuid::now_v7();
            let mut dek = [0u8; 32];
            getrandom::fill(&mut dek).unwrap();
            rows.push(dek_row(
                tenant,
                k.kek_id(),
                k.wrap(&dek, tenant, DEK_VERSION).await.unwrap(),
            ));
            deks.push((tenant, dek));
        }
        (rows, deks)
    }

    /// Every row is under `k` and opens to the original DEK.
    async fn assert_all_open_under(store: &MemStore, k: &StaticKek, deks: &[(Uuid, [u8; 32])]) {
        for (tenant, dek) in deks {
            let row = store.get(*tenant, DEK_VERSION).await.unwrap().unwrap();
            assert_eq!(
                row.kek_id,
                k.kek_id(),
                "tenant {tenant} is not under the new KEK"
            );
            let opened = k
                .unwrap(&row.wrapped_dek, &row.kek_id, *tenant, DEK_VERSION)
                .await
                .unwrap();
            assert_eq!(opened.as_slice(), dek, "the DEK itself must not change");
        }
    }

    #[tokio::test]
    async fn rewrap_moves_every_dek_and_keeps_the_key_material() {
        let (old, new) = (kek("ab"), kek("cd"));
        let (rows, deks) = seeded(&old, 3).await;
        let store = MemStore::with(rows);
        let report = rewrap_with(&store, &old, &new).await.unwrap();
        assert_eq!(
            report,
            RewrapReport {
                rewrapped: 3,
                already_current: 0
            }
        );
        assert_all_open_under(&store, &new, &deks).await;
        // The OLD KEK can no longer open anything that is stored.
        for (tenant, _) in &deks {
            let row = store.get(*tenant, DEK_VERSION).await.unwrap().unwrap();
            assert!(old
                .unwrap(&row.wrapped_dek, old.kek_id(), *tenant, DEK_VERSION)
                .await
                .is_err());
        }
    }

    #[tokio::test]
    async fn rewrap_run_twice_is_a_no_op() {
        let (old, new) = (kek("ab"), kek("cd"));
        let (rows, deks) = seeded(&old, 2).await;
        let store = MemStore::with(rows);
        rewrap_with(&store, &old, &new).await.unwrap();
        let after_first = store.snapshot();
        let report = rewrap_with(&store, &old, &new).await.unwrap();
        assert_eq!(
            report,
            RewrapReport {
                rewrapped: 0,
                already_current: 2
            }
        );
        assert_eq!(
            store.snapshot(),
            after_first,
            "a re-run must not rewrite anything"
        );
        assert_all_open_under(&store, &new, &deks).await;
    }

    #[tokio::test]
    async fn rewrap_resumes_a_store_left_half_rotated_by_a_crash() {
        let (old, new) = (kek("ab"), kek("cd"));
        let (mut rows, deks) = seeded(&old, 4).await;
        // Two rows were already swapped before the crash.
        for (row, (tenant, dek)) in rows.iter_mut().zip(&deks).take(2) {
            row.kek_id = new.kek_id().to_string();
            row.wrapped_dek = new.wrap(dek, *tenant, DEK_VERSION).await.unwrap();
        }
        let store = MemStore::with(rows);
        let report = rewrap_with(&store, &old, &new).await.unwrap();
        assert_eq!(
            report,
            RewrapReport {
                rewrapped: 2,
                already_current: 2
            }
        );
        assert_all_open_under(&store, &new, &deks).await;
    }

    #[tokio::test]
    async fn rewrap_refuses_a_third_kek_and_writes_nothing() {
        let (old, new, stranger) = (kek("ab"), kek("cd"), kek("ef"));
        let (mut rows, _) = seeded(&old, 2).await;
        let (foreign, _) = seeded(&stranger, 1).await;
        rows.extend(foreign);
        let store = MemStore::with(rows);
        let before = store.snapshot();
        let err = rewrap_with(&store, &old, &new)
            .await
            .unwrap_err()
            .to_string();
        assert!(
            err.contains(stranger.kek_id()),
            "the refusal names the stranger: {err}"
        );
        assert_eq!(store.snapshot(), before, "nothing may be written");
    }

    #[tokio::test]
    async fn rewrap_refuses_when_previous_and_current_are_the_same_key() {
        let k = kek("ab");
        let (rows, _) = seeded(&k, 1).await;
        let store = MemStore::with(rows);
        let before = store.snapshot();
        let err = rewrap_with(&store, &k, &kek("ab"))
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("SAME"), "{err}");
        assert_eq!(store.snapshot(), before);
    }

    #[tokio::test]
    async fn rewrap_proves_every_row_before_writing_any() {
        // The third row claims the previous KEK but its bytes are corrupt. The run
        // must fail with ALL rows untouched - not with the first two rotated and
        // the third stranded.
        let (old, new) = (kek("ab"), kek("cd"));
        let (mut rows, _) = seeded(&old, 3).await;
        let last = rows.last_mut().unwrap();
        let tail = last.wrapped_dek.len() - 1;
        last.wrapped_dek[tail] ^= 0xff;
        let store = MemStore::with(rows);
        let before = store.snapshot();
        assert!(rewrap_with(&store, &old, &new).await.is_err());
        assert_eq!(
            store.snapshot(),
            before,
            "a bad row must abort before any write"
        );
    }

    #[tokio::test]
    async fn a_lost_swap_to_a_replica_that_finished_the_same_job_converges() {
        // Two replicas rotate at once. Ours reads the row under the old KEK; the
        // other swaps it to the new KEK first. Our CAS loses, and that is fine:
        // the row is where it should be.
        let (old, new) = (kek("ab"), kek("cd"));
        let (rows, deks) = seeded(&old, 2).await;
        let (tenant0, dek0) = deks[0];
        let store = MemStore::with(rows);
        *store.race.lock().unwrap() = Some((
            0,
            new.kek_id().to_string(),
            new.wrap(&dek0, tenant0, DEK_VERSION).await.unwrap(),
        ));
        let report = rewrap_with(&store, &old, &new).await.unwrap();
        assert_eq!(
            report,
            RewrapReport {
                rewrapped: 1,
                already_current: 1
            }
        );
        assert_all_open_under(&store, &new, &deks).await;
    }

    #[tokio::test]
    async fn a_lost_swap_to_an_unexpected_kek_refuses() {
        let (old, new, stranger) = (kek("ab"), kek("cd"), kek("ef"));
        let (rows, deks) = seeded(&old, 1).await;
        let (tenant0, dek0) = deks[0];
        let store = MemStore::with(rows);
        *store.race.lock().unwrap() = Some((
            0,
            stranger.kek_id().to_string(),
            stranger.wrap(&dek0, tenant0, DEK_VERSION).await.unwrap(),
        ));
        let err = rewrap_with(&store, &old, &new)
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains(stranger.kek_id()), "{err}");
    }

    // DB-gated (self-skips without DATABASE_URL): the Postgres store swaps a row
    // only while it still holds the EXPECTED wrapping, under the RLS bypass the
    // cross-tenant write needs. Assertions touch only this test's own tenant.
    #[tokio::test]
    async fn pg_dek_store_swaps_only_the_expected_wrapping_db() {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("skipping: DATABASE_URL not set");
            return;
        };
        let pool = fluidbox_db::connect(&url, None).await.expect("connect");
        let org = fluidbox_db::identity::create_org(
            &pool,
            &format!("kekrot-{}", Uuid::now_v7().simple()),
            None,
        )
        .await
        .unwrap();
        let tenant = org.id;
        let (old, new) = (kek("a7"), kek("b8"));
        let dek = [6u8; 32];
        let wrapped_old = old.wrap(&dek, tenant, DEK_VERSION).await.unwrap();
        let scope = fluidbox_db::TenantScope::assume(tenant);
        let mut tx = fluidbox_db::scoped_tx(&pool, scope).await.unwrap();
        fluidbox_db::insert_tenant_dek(&mut *tx, tenant, DEK_VERSION, old.kek_id(), &wrapped_old)
            .await
            .unwrap();
        tx.commit().await.unwrap();

        let store = PgDekStore(&pool);
        let expected = store
            .all()
            .await
            .unwrap()
            .into_iter()
            .find(|r| r.tenant_id == tenant)
            .expect("the cross-tenant listing sees this tenant's row");
        let wrapped_new = new.wrap(&dek, tenant, DEK_VERSION).await.unwrap();
        assert!(store
            .swap(&expected, new.kek_id(), &wrapped_new)
            .await
            .unwrap());
        assert!(
            !store
                .swap(&expected, new.kek_id(), &wrapped_new)
                .await
                .unwrap(),
            "a stale expectation must lose the compare-and-swap"
        );
        let now = store.get(tenant, DEK_VERSION).await.unwrap().unwrap();
        assert_eq!(now.kek_id, new.kek_id());
        assert_eq!(
            new.unwrap(&now.wrapped_dek, &now.kek_id, tenant, DEK_VERSION)
                .await
                .unwrap()
                .as_slice(),
            dek
        );

        for stmt in [
            "delete from tenant_deks where tenant_id = $1",
            "delete from tenants where id = $1",
        ] {
            sqlx::query(stmt).bind(tenant).execute(&pool).await.unwrap();
        }
    }
}
