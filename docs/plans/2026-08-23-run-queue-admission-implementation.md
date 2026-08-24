# Run Admission & Queueing — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking. Each task maps 1:1 to a GitHub issue under the epic; land each task as its own PR into `release/run-queue-admission`.

**Goal:** Add capacity admission to fluidbox runs: a `queued` session status, a per-replica dispatcher admitting runs FIFO under `FLUIDBOX_MAX_CONCURRENT_RUNS`, bounded queue depth+age, and requeue-instead-of-fail on Kubernetes quota 403 — inert unless configured.

**Architecture:** Runs are born `created`, parked post-commit to `queued` (the `awaiting_authorization` precedent), and admitted by a dispatcher whose decision is serialized with a transaction-scoped advisory lock; occupancy is derived by counting session rows; claims stamp the existing 0021 orchestrator lease via `FOR UPDATE SKIP LOCKED`. Everything is audit-visible through the existing `StatusChanged` ledger funnel.

**Tech Stack:** Rust (axum/sqlx/tokio), PostgreSQL only, kube-rs (provider classification), bash e2e.

**Spec:** `docs/plans/2026-08-23-run-queue-admission-design.md` — the design doc travels with this plan; every task cites its section. All `file:line` anchors below were verified at `main` @ `7b51ce2`; treat them as anchors (search for the named symbol if lines have drifted).

## Global Constraints

- **Inert by default:** with `FLUIDBOX_MAX_CONCURRENT_RUNS` unset, behavior must be byte-identical to today. Every task preserves this.
- **NEVER run `just` recipes** (`just check`, `just e2e`, `just db-up`, …): `justfile:1` has `set dotenv-load := true` and injects the real `.env` (live Neon `DATABASE_URL`, real keys). Use explicit `cargo`/`bash` commands only.
- **DB tests run ONLY against the local container Postgres:** `export DATABASE_URL=postgres://fluidbox:fluidbox@127.0.0.1:5433/fluidbox_e2e` (credentials are the documented defaults from `deploy/docker-compose.dev.yml`; port 5433 is deliberate). Start it with `docker compose -f deploy/docker-compose.dev.yml up -d postgres` — local Docker is colima, so export `DOCKER_HOST` per the operator's colima setup if the socket isn't found. Create the test DB once: `psql postgres://fluidbox:fluidbox@127.0.0.1:5433/fluidbox -c 'create database fluidbox_e2e'` (ignore "already exists"). Before ANY `cargo test -p fluidbox-db`, verify `echo $DATABASE_URL` shows `127.0.0.1:5433`, never a Neon host. Tests self-skip when `DATABASE_URL` is unset (`crates/fluidbox-db/src/lib.rs:7907` pattern).
- **sqlx bakes migrations at compile time:** after adding `migrations/0034_run_queue.sql`, touch `crates/fluidbox-db/src/lib.rs` (any edit) so the `migrate!` macro picks it up. NEVER edit an already-applied migration — if you must, drop and recreate every local DB (sqlx checksum) and rebuild the server binary.
- **Migration number:** `0034` (next free as of 2026-08-23; `ls migrations/ | tail` to re-verify before creating the file).
- **Branch/PR flow:** work lands as PRs into `release/run-queue-admission` (a draft release PR tracks it). `main` is PR-only. Conventional commits (`feat:`, `fix:`, `docs:`, `test:`).
- **Green bar per task:** `cargo fmt --all` + `cargo clippy --workspace --all-targets -- -D warnings` + the task's named `cargo test -p …` commands. `cargo test -p fluidbox-core` needs no DB. Full e2e suites are **maintainer-triggered only** — never run `scripts/e2e-*.sh` against the operator's live stack unprompted; the new hermetic `scripts/e2e-queue.sh` (Task 9) is the exception you may run because it is isolated by construction (own DB name, own port, null provider).
- **New cross-tenant DB functions** go in `crates/fluidbox-db/src/system_worker.rs` and MUST be added to that module's doc-comment inventory ("The FULL bypass-bearing inventory") — invariant 6.
- **Adopted defaults** (design §16 recommendations, owner may override): max wait 3600 s; webhook shed = recorded skip + 2xx; authorized network-grant releases go through the queue; depth = 4× cap floor 50; status name `queued`; stage 2 (per-tenant fairness) deferred until a second org onboards.

---

### Task 1: `Queued` session status (fluidbox-core)

Design §6. The parking state, its edges, and its classifications. The wildcard-free `accepts_work` match forces most classifications at compile time; `metrics::status_is_active` does NOT force (it is a `matches!`) and must be handled deliberately.

**Files:**
- Modify: `crates/fluidbox-core/src/state.rs` (enum at `:24-40`, `as_str` `:43`, `parse` `:60`, `can_transition_to` `:116`, `accepts_work` `:103`, tests `:162+`)
- Modify: `crates/fluidbox-server/src/metrics.rs` (`status_is_active` `:619`, its doc comment `:615`, tests)

**Interfaces:**
- Produces: `SessionStatus::Queued`, string `"queued"`; edges `(Created|AwaitingAuthorization) → Queued`, `Queued → Provisioning`, `Provisioning → Queued`, `Queued → Cancelling|Finalizing`. Every later task depends on these.

- [ ] **Step 1: Write the failing core tests** — extend `crates/fluidbox-core/src/state.rs` tests:

```rust
const ACTIVE: [SessionStatus; 7] = [
    Created, AwaitingAuthorization, Queued, Provisioning, Initializing, Running, AwaitingApproval,
];

#[test]
fn queued_parks_before_provisioning() {
    // The capacity park mirrors the authorization park: in, through, and out.
    assert!(Created.can_transition_to(Queued));
    assert!(AwaitingAuthorization.can_transition_to(Queued)); // authorization-then-capacity
    assert!(Queued.can_transition_to(Provisioning));
    // The ONE backward edge besides AwaitingApproval→Running: a provider
    // CapacityDenied re-parks the run (design §7.4).
    assert!(Provisioning.can_transition_to(Queued));
    // No other state may re-enter the queue.
    assert!(!Running.can_transition_to(Queued));
    assert!(!Initializing.can_transition_to(Queued));
    // Parked = no sandbox, no tokens, no work.
    assert!(!Queued.accepts_work());
    assert!(!Queued.is_terminal());
    assert!(!Queued.is_winding_down());
}
```

Also add `Queued` to the `no_skipping_init` test (`assert!(!Queued.can_transition_to(Running)); assert!(!Queued.can_transition_to(Initializing));`) and to `roundtrip_strings`.

- [ ] **Step 2:** `cargo test -p fluidbox-core state::` — expect COMPILE FAILURE (`Queued` not defined). That is the red state.
- [ ] **Step 3: Implement.** Add the variant between `AwaitingAuthorization` and `Provisioning` with a doc comment mirroring `AwaitingAuthorization`'s (`:26-28`): *"Frozen, parked, waiting for a capacity slot. No sandbox, no runner, no tokens — nothing to reap and nothing that can spend. The dispatcher admits it; the queue-age sweeper is its only reaper."* Add `"queued"` to `as_str`/`parse`. In `accepts_work`, add `Queued => false` with a comment (the wildcard-free match now fails to compile until you do — that is by design). In `can_transition_to`, add the four edges and add `Queued` to the wind-down source tuple (the `Created | AwaitingAuthorization | Provisioning | … , Cancelling | Finalizing` arm).
- [ ] **Step 4:** `cargo test -p fluidbox-core state::` — all green, including the pre-existing `every_nonterminal_can_reach_failed` and `cancel_rides_cancelling` which now cover `Queued` via the widened `ACTIVE` array.
- [ ] **Step 5: metrics classification.** In `crates/fluidbox-server/src/metrics.rs`, `status_is_active` (`:619`) already answers `false` for `Queued` (it is a `matches!` allowlist) — make it deliberate: extend the doc comment at `:615` ("`created`, `awaiting_authorization` **and `queued`** are all PRE-SANDBOX …") and add a test:

```rust
#[test]
fn queued_is_not_active_for_the_gauge() {
    use fluidbox_core::state::SessionStatus::*;
    assert!(!status_is_active(Queued));
    assert_eq!(active_delta(Queued, Provisioning), 1);   // dispatch enters the band
    assert_eq!(active_delta(Provisioning, Queued), -1);  // a capacity bounce leaves it
    assert_eq!(active_delta(Created, Queued), 0);        // parking moves nothing
}
```

- [ ] **Step 6:** `cargo test -p fluidbox-server metrics::` green; `cargo clippy --workspace --all-targets -- -D warnings` (this also surfaces any other non-exhaustive `SessionStatus` match in the workspace — classify each the way `AwaitingAuthorization` is classified next to it).
- [ ] **Step 7:** `cargo fmt --all` and commit: `feat(core): add queued session status with capacity-park edges`

---

### Task 2: Migration 0034 + timestamp stamping + stale-launch anchor fix (fluidbox-db)

Design §5 and §3.10. Adds the four columns, stamps `queued_at`/`launched_at` in both transition functions (the `started_at` pattern), and fixes the latent watchdog bug by anchoring provisioning/initializing staleness to `launched_at`.

**Files:**
- Create: `migrations/0034_run_queue.sql`
- Modify: `crates/fluidbox-db/src/lib.rs` — `SessionRow` (`:745`), `transition_session` SQL (`:4504-4512`), `transition_session_fenced` SQL (`:4566-4575`)
- Modify: `crates/fluidbox-db/src/system_worker.rs` — `stale_nonstarted_sessions` (`:288-307`)

**Interfaces:**
- Consumes: `SessionStatus::Queued` (Task 1).
- Produces: columns `queued_at`, `launched_at`, `dispatch_after timestamptz`, `dispatch_attempts int not null default 0`; `SessionRow.queued_at/launched_at/dispatch_after: Option<DateTime<Utc>>`, `SessionRow.dispatch_attempts: i32`; partial index `sessions_queued_dispatch`.

- [ ] **Step 1: Write the migration** — `migrations/0034_run_queue.sql`, exactly the design §5 sketch (including its ROLLOUT DISCIPLINE header comment verbatim — deploy everywhere FIRST, then enable). Columns: `queued_at`, `launched_at`, `dispatch_after` (all `timestamptz`), `dispatch_attempts int not null default 0`; index `create index sessions_queued_dispatch on sessions (created_at) where status = 'queued';`
- [ ] **Step 2:** Touch `crates/fluidbox-db/src/lib.rs` so `sqlx::migrate!` re-bakes (Global Constraints). Add the four fields to `SessionRow`:

```rust
    /// First entry into `queued` (coalesce-stamped, like started_at). The
    /// queue-age bound measures from here, never created_at.
    pub queued_at: Option<DateTime<Utc>>,
    /// First entry into `provisioning` — the stale-launch watchdog's anchor.
    pub launched_at: Option<DateTime<Utc>>,
    /// Not-before gate for redispatch after a provider capacity bounce.
    pub dispatch_after: Option<DateTime<Utc>>,
    /// Dispatch attempts (the claim increments it); bounded by config.
    pub dispatch_attempts: i32,
```

- [ ] **Step 3: Write the failing stamping test** in the fluidbox-db integration test module (reuse the `seed_tenant_session` fixture at `lib.rs:15412` and the `DATABASE_URL` self-skip guard at `:7907`):

```rust
#[tokio::test]
async fn queue_timestamps_stamp_once_and_survive_a_bounce() {
    let Ok(url) = std::env::var("DATABASE_URL") else {
        eprintln!("skipping: DATABASE_URL not set");
        return;
    };
    let pool = PgPool::connect(&url).await.unwrap();
    let (tenant, session) = seed_tenant_session(&pool).await;
    let scope = TenantScope::assume(tenant);
    use fluidbox_core::state::SessionStatus::*;

    // created → queued stamps queued_at.
    let (_, row) = transition_session(&pool, scope, session, Queued, Some("park"))
        .await.unwrap().unwrap();
    let first_queued_at = row.queued_at.expect("queued_at stamped on first park");
    assert!(row.launched_at.is_none());

    // queued → provisioning stamps launched_at.
    let (_, row) = transition_session(&pool, scope, session, Provisioning, None)
        .await.unwrap().unwrap();
    assert!(row.launched_at.is_some());

    // provisioning → queued (capacity bounce) keeps the ORIGINAL queued_at:
    // the age bound is total time-in-queue, so a bounce loop cannot be infinite.
    let (_, row) = transition_session(&pool, scope, session, Queued, Some("bounce"))
        .await.unwrap().unwrap();
    assert_eq!(row.queued_at, Some(first_queued_at));
}
```

- [ ] **Step 4:** `cargo test -p fluidbox-db queue_timestamps` — FAILS (`queued_at` never stamped).
- [ ] **Step 5: Implement stamping.** In BOTH `transition_session` and `transition_session_fenced` UPDATE statements, directly after the `started_at` CASE line, add:

```sql
queued_at   = case when $2 = 'queued'       then coalesce(queued_at, now())   else queued_at   end,
launched_at = case when $2 = 'provisioning' then coalesce(launched_at, now()) else launched_at end,
```

- [ ] **Step 6:** `cargo test -p fluidbox-db queue_timestamps` — PASS.
- [ ] **Step 7: Write the failing stale-anchor test** (the §3.10 regression — this is a live-bug fix for network grants too):

```rust
#[tokio::test]
async fn stale_launch_sweep_uses_the_launch_anchor_not_created_at() {
    let Ok(url) = std::env::var("DATABASE_URL") else {
        eprintln!("skipping: DATABASE_URL not set"); return;
    };
    let pool = PgPool::connect(&url).await.unwrap();
    let (tenant, session) = seed_tenant_session(&pool).await;
    let scope = TenantScope::assume(tenant);
    use fluidbox_core::state::SessionStatus::*;
    transition_session(&pool, scope, session, Queued, None).await.unwrap();
    transition_session(&pool, scope, session, Provisioning, None).await.unwrap();
    // Simulate a run that waited 2 hours before dispatch: created_at is
    // ancient, launched_at is fresh.
    sqlx::query("update sessions set created_at = now() - interval '2 hours' where id = $1")
        .bind(session).fetch_optional(&pool).await.unwrap();
    let stale = system_worker::stale_nonstarted_sessions(&pool, 30).await.unwrap();
    assert!(
        !stale.iter().any(|s| s.id == session),
        "a freshly-launched run must not read as stalled just because it waited"
    );
    // …but an actually-stalled launch (old launched_at) IS swept.
    sqlx::query("update sessions set launched_at = now() - interval '2 hours' where id = $1")
        .bind(session).fetch_optional(&pool).await.unwrap();
    let stale = system_worker::stale_nonstarted_sessions(&pool, 30).await.unwrap();
    assert!(stale.iter().any(|s| s.id == session));
}
```

- [ ] **Step 8:** Run it — FAILS (the current predicate ages everything from `created_at`).
- [ ] **Step 9: Implement** — replace `stale_nonstarted_sessions`' query (keep the signature; update its doc comment to explain the split anchor and cite design §3.10):

```sql
select * from sessions
 where (status = 'created'
        and created_at < now() - make_interval(mins => $1))
    or (status in ('provisioning','initializing')
        and coalesce(launched_at, created_at) < now() - make_interval(mins => $1))
```

- [ ] **Step 10:** Both new tests + the whole `cargo test -p fluidbox-db` suite green (container DB). `cargo clippy --workspace --all-targets -- -D warnings`, `cargo fmt --all`.
- [ ] **Step 11:** Commit: `feat(db): run-queue columns (0034), transition stamps, launch-anchored stale sweep`

---

### Task 3: Serialized dispatch claim + capacity loaders (fluidbox-db::system_worker)

Design §7.2–§7.3 — the two hot-path queries, fused into ONE named bypass entry point so the advisory lock, the occupancy count, and the claim share a transaction. Plus the depth/expiry/adoption scans and the scoped backoff setter.

**Files:**
- Modify: `crates/fluidbox-db/src/system_worker.rs` (new functions + the module-doc inventory)
- Modify: `crates/fluidbox-db/src/lib.rs` (scoped `set_dispatch_backoff`)

**Interfaces:**
- Consumes: Task 2's columns; `worker_tx` (crate-private, in-module).
- Produces (exact signatures later tasks call):

```rust
pub const DISPATCH_ADVISORY_KEY: i64 = 0x666c_7569_6462_7871; // "fluidbxq"; single-purpose, documented

pub struct ClaimedRun { pub id: Uuid, pub tenant_id: Uuid,
                        pub queued_at: Option<DateTime<Utc>>, pub dispatch_attempts: i32 }
pub struct DispatchOutcome { pub active: i64, pub leased_queued: i64, pub claimed: Vec<ClaimedRun> }

/// None = another replica holds the dispatch lock this instant (try-lock).
pub async fn dispatch_claim(pool: &PgPool, cap: i64, batch: i64, owner: Uuid,
                            lease_ttl_secs: i64) -> sqlx::Result<Option<DispatchOutcome>>;
pub async fn count_queued_sessions(pool: &PgPool) -> sqlx::Result<i64>;
pub async fn expired_queued_sessions(pool: &PgPool, max_wait_secs: i64, limit: i64)
    -> sqlx::Result<Vec<SessionRow>>;
pub async fn orphaned_created_sessions(pool: &PgPool, older_than_secs: i64, limit: i64)
    -> sqlx::Result<Vec<SessionRow>>;
// lib.rs, tenant-scoped (NOT a bypass): backoff gate + lease clear after a bounce.
pub async fn set_dispatch_backoff(pool: &PgPool, scope: TenantScope, id: Uuid,
                                  not_before_secs: i64) -> sqlx::Result<()>;
```

- [ ] **Step 1: Write the failing claim tests** (fluidbox-db integration module; same skip-guard + fixture as Task 2):

```rust
#[tokio::test]
async fn dispatch_claim_honors_cap_counting_leased_queued_as_occupied() {
    let Ok(url) = std::env::var("DATABASE_URL") else {
        eprintln!("skipping: DATABASE_URL not set"); return;
    };
    let pool = PgPool::connect(&url).await.unwrap();
    // Three queued runs, cap 1: exactly one claim; the claimed row is still
    // status='queued' but its live lease must count as occupied, so a second
    // dispatch pass claims NOTHING. Dropping the occupancy FILTER clause must
    // make this test fail (the design's double-admit mutation guard, §7.3).
    let (_, a) = seed_tenant_session(&pool).await;
    let (_, b) = seed_tenant_session(&pool).await;
    let (_, c) = seed_tenant_session(&pool).await;
    for s in [a, b, c] {
        let row = system_worker::get_session(&pool, s).await.unwrap().unwrap();
        transition_session(&pool, TenantScope::assume(row.tenant_id), s,
            fluidbox_core::state::SessionStatus::Queued, None).await.unwrap();
    }
    let owner = Uuid::now_v7();
    let one = system_worker::dispatch_claim(&pool, 1, 200, owner, 30).await.unwrap().unwrap();
    assert_eq!(one.claimed.len(), 1);
    assert_eq!(one.claimed[0].dispatch_attempts, 1, "the claim increments attempts");
    let two = system_worker::dispatch_claim(&pool, 1, 200, owner, 30).await.unwrap().unwrap();
    assert_eq!(two.claimed.len(), 0, "leased-queued must count as occupied");
    assert_eq!(two.leased_queued, 1);
    // Expire the lease → the row returns to the pool (crash-reclaim, §7.3).
    sqlx::query("update sessions set orchestrator_lease_until = now() - interval '1 second'
                 where id = $1").bind(one.claimed[0].id).fetch_optional(&pool).await.unwrap();
    let three = system_worker::dispatch_claim(&pool, 1, 200, owner, 30).await.unwrap().unwrap();
    assert_eq!(three.claimed.len(), 1);
    assert_eq!(three.claimed[0].id, one.claimed[0].id);
    assert_eq!(three.claimed[0].dispatch_attempts, 2);
}

#[tokio::test]
async fn dispatch_claim_yields_when_another_connection_holds_the_lock() {
    let Ok(url) = std::env::var("DATABASE_URL") else {
        eprintln!("skipping: DATABASE_URL not set"); return;
    };
    let pool = PgPool::connect(&url).await.unwrap();
    let mut holder = pool.begin().await.unwrap();
    let (locked,): (bool,) = sqlx::query_as("select pg_try_advisory_xact_lock($1)")
        .bind(system_worker::DISPATCH_ADVISORY_KEY)
        .fetch_one(&mut *holder).await.unwrap();
    assert!(locked);
    let out = system_worker::dispatch_claim(&pool, 10, 200, Uuid::now_v7(), 30).await.unwrap();
    assert!(out.is_none(), "a losing tick yields instead of queueing behind the winner");
    holder.rollback().await.unwrap();
}
```

Also add tests: FIFO order by `created_at` across claims; a `dispatch_after` in the future excludes a row; `expired_queued_sessions` respects `queued_at` (not `created_at`); `orphaned_created_sessions` excludes rows with a live lease. (Note: `seed_tenant_session` mints its own tenant per call — the queue is deployment-wide, so cross-tenant rows are exactly what these tests should exercise. Isolate assertions per-run-id, not by table emptiness: the shared `fluidbox_e2e` DB carries other tests' rows.)

- [ ] **Step 2:** `cargo test -p fluidbox-db dispatch_claim` — compile failure (functions missing).
- [ ] **Step 3: Implement `dispatch_claim`** in `system_worker.rs`, one `worker_tx` transaction: ① `select pg_try_advisory_xact_lock($KEY)` → `false` ⇒ commit + `Ok(None)`; ② the occupancy query — design §7.3 verbatim (the `count(*) filter (…)` pair; `awaiting_authorization` and unleased `queued` excluded; leased-queued counted); ③ `headroom = cap - active - leased_queued`; if `<= 0`, commit + `Ok(Some(empty outcome))`; ④ the claim CTE — design §7.3 verbatim: `for update skip locked` over `status='queued'`, `dispatch_after` null-or-past, lease free-or-expired, `order by created_at limit least(headroom, batch)`; the UPDATE stamps `orchestrator_owner_id`, `orchestrator_lease_until = now() + make_interval(secs => $ttl)`, `orchestrator_epoch + (case when orchestrator_owner_id is distinct from $owner then 1 else 0 end)` (mirror `acquire_session_lease`'s epoch rule exactly, `lib.rs:4620+`), `dispatch_attempts + 1`, `updated_at`; `returning id, tenant_id, queued_at, dispatch_attempts`. ⑤ commit, return the outcome.
- [ ] **Step 4: Implement the small loaders.** `count_queued_sessions` (`select count(*) … where status='queued'`); `expired_queued_sessions` (`where status='queued' and queued_at < now() - make_interval(secs => $1) order by queued_at limit $2`); `orphaned_created_sessions` (`where status='created' and created_at < now() - make_interval(secs => $1) and (orchestrator_lease_until is null or orchestrator_lease_until < now()) order by created_at limit $2`) — each via `worker_tx`. And scoped `set_dispatch_backoff` in `lib.rs` (`scoped_tx`): `update sessions set dispatch_after = now() + make_interval(secs => $3), orchestrator_owner_id = null, orchestrator_lease_until = null, updated_at = now() where id = $1 and tenant_id = $2` — the epoch is deliberately NOT bumped here; the next claim's owner-change bumps it, keeping the fencing-token semantics intact.
- [ ] **Step 5: Update the `system_worker` module-doc inventory** — add the four new functions to category (a) with one-line purposes (invariant 6; the property is "short, named, grep-able").
- [ ] **Step 6:** `cargo test -p fluidbox-db` green (container DB); clippy; fmt.
- [ ] **Step 7:** Commit: `feat(db): serialized dispatch claim + capacity occupancy loaders`

---

### Task 4: `ProviderError::CapacityDenied` + Kubernetes classifier

Design §7.4. The typed capacity signal, mapped from the quota 403 (and apiserver 429) at the pod-create site.

**Files:**
- Modify: `crates/fluidbox-core/src/traits.rs` (`ProviderError` at `:373-377`)
- Modify: `crates/fluidbox-provider-k8s/src/lib.rs` (pod create at `:479-483`, generic `map_err` at `:269`)

**Interfaces:**
- Produces: `ProviderError::CapacityDenied(String)` — Task 7 matches on it.

- [ ] **Step 1: Write the failing classifier test** in `fluidbox-provider-k8s`:

```rust
#[test]
fn quota_403_and_apiserver_429_classify_as_capacity() {
    let quota = kube::Error::Api(kube::core::ErrorResponse {
        status: "Failure".into(),
        message: r#"pods "fbx-run-x" is forbidden: exceeded quota: fluidbox-sandboxes, requested: pods=1"#.into(),
        reason: "Forbidden".into(),
        code: 403,
    });
    assert!(matches!(classify_create_err(quota),
        fluidbox_core::traits::ProviderError::CapacityDenied(_)));
    let throttle = kube::Error::Api(kube::core::ErrorResponse {
        status: "Failure".into(), message: "too many requests".into(),
        reason: "TooManyRequests".into(), code: 429,
    });
    assert!(matches!(classify_create_err(throttle),
        fluidbox_core::traits::ProviderError::CapacityDenied(_)));
    // An RBAC 403 is NOT capacity — it must stay terminal.
    let rbac = kube::Error::Api(kube::core::ErrorResponse {
        status: "Failure".into(),
        message: r#"pods is forbidden: User "x" cannot create resource"#.into(),
        reason: "Forbidden".into(), code: 403,
    });
    assert!(matches!(classify_create_err(rbac),
        fluidbox_core::traits::ProviderError::Other(_)));
}
```

- [ ] **Step 2:** `cargo test -p fluidbox-provider-k8s classify` — compile failure.
- [ ] **Step 3: Implement.** In `traits.rs`:

```rust
#[derive(Debug, thiserror::Error)]
pub enum ProviderError {
    #[error("provider error: {0}")]
    Other(String),
    /// The substrate refused for CAPACITY reasons (namespace quota, apiserver
    /// throttle): the run is healthy, the world is full. The orchestrator
    /// re-parks instead of failing (design §7.4). Carries the verbatim
    /// substrate message for the ledger's status_reason.
    #[error("provider capacity denied: {0}")]
    CapacityDenied(String),
}
```

In `fluidbox-provider-k8s/src/lib.rs`, add next to `map_err`:

```rust
/// Pod-create-only classification: a ResourceQuota 403 carries reason
/// "Forbidden" with "exceeded quota" in the message (the RBAC 403 does not),
/// and an apiserver 429 is throttling. Everything else stays `Other` (terminal).
fn classify_create_err(e: kube::Error) -> ProviderError {
    if let kube::Error::Api(ref ae) = e {
        let quota = ae.code == 403 && ae.reason == "Forbidden"
            && ae.message.contains("exceeded quota");
        if quota || ae.code == 429 {
            return ProviderError::CapacityDenied(ae.message.clone());
        }
    }
    map_err(e)
}
```

and switch the pod create call (`self.pods.create(…).await.map_err(map_err)?` at `:483`) to `.map_err(classify_create_err)?`. Only the POD create — the quota counts pods, and Secret/policy creates keep the generic mapping.

- [ ] **Step 4:** `cargo test -p fluidbox-provider-k8s` green; `cargo check --workspace` (surfaces any non-exhaustive `ProviderError` match elsewhere — treat `CapacityDenied` like `Other` at every site except the orchestrator provision site, which Task 7 owns); clippy; fmt.
- [ ] **Step 5:** Commit: `feat(provider): typed CapacityDenied classification for quota and throttle rejections`

---

### Task 5: Queue configuration knobs (fluidbox-server config)

Design §8. Four envs, parsed at boot, malformed fails boot naming the variable (house convention; extract a pure resolver so the failure messages are testable without env vars — the file's own pattern, `config.rs:124`).

**Files:**
- Modify: `crates/fluidbox-server/src/config.rs` (struct fields + `from_env` at `:451` + pure resolver + tests)

**Interfaces:**
- Produces:

```rust
#[derive(Debug, Clone)]
pub struct QueueCfg {          // resolved; lives on Config as `pub queue: Option<QueueCfg>`
    pub max_concurrent_runs: i64,   // >= 1
    pub max_depth: i64,             // default max(4 * cap, 50)
    pub max_wait_secs: i64,         // default 3600
    pub requeue_max: i32,           // default 5
}
impl Config { pub fn queueing_enabled(&self) -> bool { self.queue.is_some() } }
```

- [ ] **Step 1: Write the failing resolver tests:**

```rust
#[test]
fn queue_cfg_resolves_defaults_and_refuses_nonsense() {
    // Unset cap ⇒ feature off; other queue vars alone are dead config → refuse.
    assert!(resolve_queue_cfg(None, None, None, None).unwrap().is_none());
    assert!(resolve_queue_cfg(None, Some("10".into()), None, None).is_err(),
        "FLUIDBOX_QUEUE_MAX_DEPTH without FLUIDBOX_MAX_CONCURRENT_RUNS must fail boot");
    // Cap set ⇒ derived defaults: depth = max(4*cap, 50), wait 3600, requeue 5.
    let q = resolve_queue_cfg(Some("60".into()), None, None, None).unwrap().unwrap();
    assert_eq!((q.max_concurrent_runs, q.max_depth, q.max_wait_secs, q.requeue_max),
               (60, 240, 3600, 5));
    let q = resolve_queue_cfg(Some("5".into()), None, None, None).unwrap().unwrap();
    assert_eq!(q.max_depth, 50, "the depth floor");
    // Malformed and out-of-range values fail loudly, naming the variable.
    assert!(resolve_queue_cfg(Some("zero".into()), None, None, None).is_err());
    assert!(resolve_queue_cfg(Some("0".into()), None, None, None).is_err());
}
```

- [ ] **Step 2:** `cargo test -p fluidbox-server config::` — compile failure.
- [ ] **Step 3: Implement** `fn resolve_queue_cfg(cap: Option<String>, depth: Option<String>, wait: Option<String>, requeue: Option<String>) -> anyhow::Result<Option<QueueCfg>>` (each error message names its `FLUIDBOX_*` variable, mirroring `parse_i64_env`'s style), wire it in `from_env` with `get("FLUIDBOX_MAX_CONCURRENT_RUNS").ok()` etc., and carry the design-§8 derivations in the field doc comments.
- [ ] **Step 4:** Tests green; clippy; fmt. Commit: `feat(server): run-queue configuration knobs (inert unless cap set)`

---

### Task 6: Dispatcher worker + park-at-admission + netgrant enqueue

Design §7.1, §7.2, §7.5, §7.6. The state-driven worker (the `network_grant_gate` shape), the post-commit park, and routing the two netgrant release sites through the queue. All transitions go through the orchestrator's `transition` wrapper so `StatusChanged` ledger events + `active_delta` accounting come for free. (Note: the netgrant park itself calls `fluidbox_db::transition_session` directly and emits no `StatusChanged` — pre-existing; do NOT "fix" it in this epic.)

**Files:**
- Create: `crates/fluidbox-server/src/dispatcher.rs`
- Modify: `crates/fluidbox-server/src/main.rs` (`mod dispatcher;`)
- Modify: `crates/fluidbox-server/src/orchestrator.rs` (`async fn transition` → `pub(crate) async fn transition`; make `replica_id()` and `SESSION_TOKEN`-adjacent `SESSION_LEASE_TTL_SECS` `pub(crate)` if not already)
- Modify: `crates/fluidbox-server/src/workers.rs` (`fn periodic` + `SWEEP_BATCH` → `pub(crate)`; `spawn_all` registers the dispatcher; `network_grant_gate`'s `grant_status == "active"` arm enqueues when enabled)
- Modify: `crates/fluidbox-server/src/run_service.rs` (Tail 1 at `:606`)
- Modify: `crates/fluidbox-server/src/netgrant.rs` (`release_authorized_grant`'s spawn arm)
- Modify: `crates/fluidbox-server/src/metrics.rs` (declare `queue_dispatched: Counter`, `queue_shed: Family("fluidbox_queue_shed_total", "reason", &["depth","age","_other"])`, `queue_wait_seconds: Histogram` — constructed like `run_provisioning_ms`; Task 10 extends the render section)

**Interfaces:**
- Consumes: `system_worker::dispatch_claim/expired_queued_sessions/orphaned_created_sessions` (Task 3), `QueueCfg` (Task 5), `SessionStatus::Queued` (Task 1).
- Produces: `dispatcher::spawn(state: AppState)` (no-op when `cfg.queue` is `None`); the park behavior every entry point now exhibits.

- [ ] **Step 1: Implement `dispatcher.rs`** (behavior tests land in Task 9's hermetic suite — this task's bar is compile + clippy + the workspace staying green with the feature off; that is a declared dependency, not an omission):

```rust
//! Capacity dispatcher (design 2026-08-23 §7): the state-driven admission
//! worker. One per replica; the dispatch DECISION is serialized in Postgres
//! (advisory try-lock inside `system_worker::dispatch_claim`), so replicas
//! never double-admit and a losing tick simply re-polls. Poll-only at 1 s by
//! design — a NOTIFY channel is a named omission (design §13) until a real
//! latency requirement appears.

use crate::state::AppState;
use fluidbox_core::state::SessionStatus;
use fluidbox_db::TenantScope;
use std::time::Duration;

/// Ticks between sweep passes (expiry + orphan adoption): ~15 s at a 1 s tick.
const SWEEP_EVERY_TICKS: u64 = 15;
/// A `created` row this old with no live lease was orphaned between the
/// create-commit and the park transition (or predates enabling the feature).
const ADOPT_CREATED_AFTER_SECS: i64 = 120;

pub fn spawn(state: AppState) {
    if state.cfg.queue.is_none() {
        return; // inert by default
    }
    tokio::spawn(dispatch_loop(state));
}

async fn dispatch_loop(state: AppState) {
    let q = state.cfg.queue.clone().expect("spawn() gates on Some");
    let mut tick = crate::workers::periodic(Duration::from_secs(1));
    let mut n: u64 = 0;
    loop {
        tick.tick().await;
        n += 1;
        match fluidbox_db::system_worker::dispatch_claim(
            &state.pool,
            q.max_concurrent_runs,
            crate::workers::SWEEP_BATCH,
            crate::orchestrator::replica_id(),
            crate::orchestrator::SESSION_LEASE_TTL_SECS,
        )
        .await
        {
            Ok(Some(out)) => {
                for run in out.claimed {
                    if let Some(t) = run.queued_at {
                        let waited = (chrono::Utc::now() - t).num_milliseconds().max(0);
                        state.metrics.queue_wait_seconds.observe(waited as f64 / 1000.0);
                    }
                    state.metrics.queue_dispatched.inc();
                    crate::orchestrator::spawn_run(state.clone(), run.id);
                }
            }
            Ok(None) => {} // another replica dispatched this tick
            Err(e) => tracing::warn!("dispatch tick failed: {e}"),
        }
        if n % SWEEP_EVERY_TICKS == 0 {
            sweep(&state, &q).await;
        }
    }
}

/// Expiry + adoption (design §7.6). CAS-guarded on both arms: `fail` is the
/// idempotent request-side intent, and the adoption transition refuses if the
/// row left `created` meanwhile.
async fn sweep(state: &AppState, q: &crate::config::QueueCfg) {
    match fluidbox_db::system_worker::expired_queued_sessions(
        &state.pool, q.max_wait_secs, crate::workers::SWEEP_BATCH).await
    {
        Ok(expired) => {
            for s in expired {
                state.metrics.queue_shed.inc("age");
                let _ = crate::orchestrator::fail(
                    state, s.id,
                    "queued for longer than the configured maximum wait \
                     (FLUIDBOX_QUEUE_MAX_WAIT_SECS)").await;
            }
        }
        Err(e) => tracing::warn!("queue expiry scan failed: {e}"),
    }
    match fluidbox_db::system_worker::orphaned_created_sessions(
        &state.pool, ADOPT_CREATED_AFTER_SECS, crate::workers::SWEEP_BATCH).await
    {
        Ok(orphans) => {
            for s in orphans {
                let scope = TenantScope::assume(s.tenant_id);
                crate::orchestrator::transition(
                    state, scope, s.id, SessionStatus::Queued,
                    Some("adopted by the dispatcher (orphaned before park)")).await;
            }
        }
        Err(e) => tracing::warn!("orphan adoption scan failed: {e}"),
    }
}
```

(Check `orchestrator::fail`'s exact signature at the watchdog call site `workers.rs:435` and match it.)

- [ ] **Step 2: Park at admission** — in `run_service.rs` Tail 1 (`:606`), replace the unconditional spawn:

```rust
    // ── Tail 1 — FREEZE, THEN PARK OR SPAWN ─────────────────────────────
    // Queueing enabled: EVERY run parks and the dispatcher admits it (design
    // §7.1; the rejected fast-path alternative is §15). The park is
    // post-commit, exactly like the netgrant park above, so the
    // create_session transaction stays byte-for-byte untouched (invariant 3).
    if state.cfg.queueing_enabled() {
        orchestrator::transition(
            state, scope, session.id, SessionStatus::Queued,
            Some("parked at admission: waiting for a capacity slot"),
        ).await;
        let parked = fluidbox_db::get_session(&state.pool, scope, session.id)
            .await?.unwrap_or(session);
        return Ok(RunCreation::Created(Box::new(parked)));
    }
    orchestrator::spawn_run(state.clone(), session.id);
    Ok(RunCreation::Created(Box::new(session)))
```

(Import `SessionStatus` at the top of `run_service.rs` if absent.)

- [ ] **Step 3: Netgrant releases enqueue** (design §7.5) — in `netgrant.rs::release_authorized_grant`, the `Ok(Some(_))` CAS-winner arm becomes:

```rust
        Ok(Some(_)) => {
            state.metrics.network_grants.inc("active");
            if state.cfg.queueing_enabled() {
                // Authorization-first, capacity-second (design §4.3): the
                // released run takes a queue slot like any other; run()'s own
                // grant gate re-verifies authority at dispatch time however
                // long the wait.
                crate::orchestrator::transition(
                    state, scope, session_id,
                    fluidbox_core::state::SessionStatus::Queued,
                    Some("network grant authorized; waiting for a capacity slot"),
                ).await;
            } else {
                crate::orchestrator::spawn_run(state.clone(), session_id);
            }
        }
```

and in `workers.rs::network_grant_gate`, the crash-window arm (`p.grant_status == "active"` at `:919`) gets the same branch — transition-to-Queued when enabled (the transition CAS makes re-runs idempotent: a session already `queued` refuses the edge and nothing duplicates), else `spawn_run` as today. Note the scan predicate at `system_worker.rs:401` keys on `status = 'awaiting_authorization'`, so an enqueued session naturally leaves the gate's worklist.

- [ ] **Step 4: Register** — `crate::dispatcher::spawn(state.clone());` inside `workers::spawn_all`, `mod dispatcher;` in `main.rs`, and the visibility-only diffs (`pub(crate)`) listed in Files.
- [ ] **Step 5:** `cargo check --workspace` + clippy + fmt; `cargo test -p fluidbox-server` and `-p fluidbox-core` green.
- [ ] **Step 6:** Commit: `feat(server): capacity dispatcher + park-at-admission (inert unless configured)`

---

### Task 7: Requeue on CapacityDenied (orchestrator)

Design §7.4. The provision site distinguishes capacity from failure: revoke the attempt's tokens, clean up what the attempt created, re-park with backoff — or fail terminally with an explained reason after `requeue_max` bounces.

**Files:**
- Modify: `crates/fluidbox-server/src/orchestrator.rs` (provision call site, shortly after `:1347`; new helpers)

**Interfaces:**
- Consumes: `ProviderError::CapacityDenied` (Task 4), `SessionRow.dispatch_attempts` (Task 2), `set_dispatch_backoff` (Task 3), `QueueCfg.requeue_max` (Task 5).
- Produces: `pub(crate) fn capacity_backoff_secs(attempt: i32) -> i64` (Task 9's suite asserts the observable bounce behavior).

- [ ] **Step 1: Write the failing backoff test** (pure, in `orchestrator.rs`'s test module):

```rust
#[test]
fn capacity_backoff_series_floors_at_the_lease_ttl_and_caps_at_five_minutes() {
    // Floor 30 s: a bounced row must not be re-claimable while its stale lease
    // could still read live (design §7.4 derives this from the lease TTL).
    assert_eq!(
        [1, 2, 3, 4, 5, 6].map(capacity_backoff_secs),
        [30, 60, 120, 240, 300, 300]
    );
    assert_eq!(capacity_backoff_secs(0), 30); // defensive: never below the floor
}
```

- [ ] **Step 2:** Run — compile failure.
- [ ] **Step 3: Implement:**

```rust
/// Backoff before redispatching a capacity-bounced run: 30 s · 2^(attempt-1),
/// capped at 300 s. The 30 s floor is derived, not chosen — it must be ≥ the
/// driver lease TTL so a bounced row cannot be re-claimed while a stale lease
/// could still read live.
pub(crate) fn capacity_backoff_secs(attempt: i32) -> i64 {
    let shift = attempt.saturating_sub(1).clamp(0, 4) as u32;
    (30i64 << shift).min(300)
}
```

- [ ] **Step 4: Wire the provision site.** Where `run()` calls `state.provider.provision(&sandbox_spec).await` (after `:1347`), replace the bare error propagation with:

```rust
    let handle = match state.provider.provision(&sandbox_spec).await {
        Ok(h) => h,
        Err(fluidbox_core::traits::ProviderError::CapacityDenied(detail))
            if state.cfg.queueing_enabled() =>
        {
            return requeue_capacity_denied(&state, scope, session_id, epoch, &detail).await;
        }
        Err(e) => return Err(e.into()), // today's terminal path, unchanged
    };
```

and implement the helper (it returns `Ok(())` so `spawn_run`'s catch never converts a bounce into `fail()`):

```rust
/// A CapacityDenied bounce re-parks the run (design §7.4). Order matters:
/// revoke this attempt's tokens FIRST (no minted secret outlives the attempt),
/// clean up what the attempt created (the abandon_launch discipline), then
/// transition back under the fence, then set the backoff gate (which clears
/// the lease — the next claimant is a fresh owner, so the epoch bumps and
/// fencing stays intact). A crash between the transition and the backoff-set
/// leaves a queued row with a live lease: it re-enters the claim pool at
/// lease expiry (~30 s) without a backoff gate — bounded and harmless.
async fn requeue_capacity_denied(
    state: &AppState, scope: TenantScope, session_id: Uuid, epoch: i64, detail: &str,
) -> anyhow::Result<()> {
    if let Err(e) = fluidbox_db::revoke_session_tokens(&state.pool, scope, session_id).await {
        tracing::warn!("revoking tokens for bounced run {session_id} failed: {e}");
    }
    abandon_launch(state, scope, session_id).await; // removes what THIS attempt created
    let session = fluidbox_db::get_session(&state.pool, scope, session_id)
        .await?.ok_or_else(|| anyhow::anyhow!("session vanished during requeue"))?;
    let q = state.cfg.queue.as_ref().expect("guarded by queueing_enabled");
    if session.dispatch_attempts >= q.requeue_max {
        state.metrics.queue_shed.inc("_other");
        fail(state, session_id, &format!(
            "provider refused capacity {} times: {detail}", session.dispatch_attempts)).await;
        return Ok(());
    }
    if !transition_fenced(
        state, scope, session_id, SessionStatus::Queued,
        Some(&format!("provider at capacity: {detail}")), epoch,
    ).await {
        // A finalizer or another replica took the session — nothing to re-park.
        return Ok(());
    }
    if let Err(e) = fluidbox_db::set_dispatch_backoff(
        &state.pool, scope, session_id,
        capacity_backoff_secs(session.dispatch_attempts),
    ).await {
        tracing::warn!("setting dispatch backoff for {session_id} failed: {e}");
    }
    Ok(())
}
```

Before wiring, READ `abandon_launch` (its call site is `:1314`) — reuse it as-is if its cleanup set matches (this attempt's workspace dir / archive); if it also mutates launch-ownership state that a requeue must NOT touch, factor the file-cleanup half out rather than duplicating it. Match `fail`'s and `transition_fenced`'s real signatures at their call sites (`workers.rs:435`, `orchestrator.rs:1243`).

- [ ] **Step 5:** `cargo test -p fluidbox-server capacity_backoff` green; `cargo check --workspace`; clippy; fmt. End-to-end bounce behavior is asserted in Task 9's suite.
- [ ] **Step 6:** Commit: `feat(server): requeue runs on provider capacity denial with bounded backoff`

---

### Task 8: Depth bound + `AtCapacity` 429 + per-entry-point shed semantics

Design §7.1 and §9. The pre-create depth check, the new error variant with `Retry-After`, and the entry-point mappings (manual/API → 429; webhook → recorded skip + 2xx; schedule → recorded skip).

**Files:**
- Modify: `crates/fluidbox-server/src/error.rs` (`ApiError` at `:7`, `IntoResponse` at `:41`)
- Modify: `crates/fluidbox-server/src/run_service.rs` (depth check at the head of `create_run`, before the create transaction)
- Modify: `crates/fluidbox-server/src/events.rs` (the per-dispatch `Err` arm near `:211` — detect `AtCapacity`, record reason `"capacity"`)
- Modify: `crates/fluidbox-server/src/scheduler.rs` (the `Err(e)` arm — same refinement, skip reason `"capacity"`)

**Interfaces:**
- Consumes: `count_queued_sessions` (Task 3), `QueueCfg.max_depth` (Task 5).
- Produces: `ApiError::AtCapacity { retry_after_secs: u64 }` → HTTP 429 + `Retry-After` header.

- [ ] **Step 1: Write the failing response test** (error.rs test module):

```rust
#[test]
fn at_capacity_maps_to_429_with_retry_after() {
    let resp = ApiError::AtCapacity { retry_after_secs: 30 }.into_response();
    assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(resp.headers().get("retry-after").unwrap(), "30");
}
```

- [ ] **Step 2:** Run — compile failure.
- [ ] **Step 3: Implement** the variant (`#[error("at capacity: the run queue is full; retry after {retry_after_secs}s")] AtCapacity { retry_after_secs: u64 }`) and a dedicated `IntoResponse` arm that inserts the `Retry-After` header onto the standard error envelope (the 429 construction at `facade.rs:169` is the house shape to mirror).
- [ ] **Step 4: Depth check** at the head of `create_run` (after argument resolution, BEFORE the subscription concurrency check and BEFORE `create_session` — deliberately outside the transaction per invariant 3, and deliberately racy-by-a-bounded-amount, design §7.1):

```rust
    if let Some(q) = &state.cfg.queue {
        let depth = fluidbox_db::system_worker::count_queued_sessions(&state.pool).await?;
        if depth >= q.max_depth {
            state.metrics.queue_shed.inc("depth");
            return Err(ApiError::AtCapacity { retry_after_secs: 30 });
        }
    }
```

- [ ] **Step 5: Entry-point mappings.** Manual (`api.rs`) and API invoke (`triggers.rs`) need NO change — `ApiError` propagates to 429 via `IntoResponse`. Webhook fan-out: in `events.rs`'s per-dispatch `Err` arm, match `ApiError::AtCapacity { .. }` FIRST and record `mark_dispatch_outcome(…, "skipped", Some("capacity"))`, keeping the 2xx ack (repo precedent at `events.rs:211-213`; design §9's amplification rationale). Scheduler: in the `Err(e)` arm, `if matches!(e, ApiError::AtCapacity { .. })` record `mark_invocation_skipped(…, "capacity")` instead of the `"error: {e}"` string (the next cron fire retries naturally).
- [ ] **Step 6:** `cargo test -p fluidbox-server error::` green; clippy; fmt. Live shed behavior is asserted in Task 9's suite.
- [ ] **Step 7:** Commit: `feat(server): bounded queue depth with per-entry-point shed semantics`

---

### Task 9: NullProvider (feature-gated) + hermetic queue e2e

Design §12 layer 3. No fake `ExecutionProvider` exists in the tree (verified at `7b51ce2`); this creates one behind a cargo feature so release builds cannot select it, plus a self-isolated bash suite proving the queue over real HTTP with zero model spend and zero sandboxes.

**Files:**
- Modify: `crates/fluidbox-provider/Cargo.toml` (`[features] test-provider = []`)
- Create: `crates/fluidbox-provider/src/null.rs`
- Modify: `crates/fluidbox-provider/src/lib.rs` (`#[cfg(feature = "test-provider")] pub mod null;` + `pub use null::NullProvider;` under the same cfg)
- Modify: `crates/fluidbox-server/Cargo.toml` (`[features] test-provider = ["fluidbox-provider/test-provider"]`)
- Modify: `crates/fluidbox-server/src/main.rs` (`build_provider` at `:54`: cfg-gated `"null"` arm)
- Create: `scripts/e2e-queue.sh`

**Interfaces:**
- Produces: `NullProvider::from_env()` — provisions instantly; `FLUIDBOX_NULL_CAPACITY_DENIALS=N` makes the first N provisions return `CapacityDenied` (the bounce-path lever).

- [ ] **Step 1: Implement `null.rs`:**

```rust
//! A provider that provisions NOTHING — the queue/lifecycle test double
//! (design §12). Feature-gated (`test-provider`) so a release build cannot
//! select it.
use fluidbox_core::traits::*;
use std::sync::atomic::{AtomicUsize, Ordering};
use uuid::Uuid;

pub struct NullProvider {
    /// First N provisions answer CapacityDenied (FLUIDBOX_NULL_CAPACITY_DENIALS).
    deny_remaining: AtomicUsize,
}

impl NullProvider {
    pub fn from_env() -> Self {
        let n = std::env::var("FLUIDBOX_NULL_CAPACITY_DENIALS")
            .ok().and_then(|v| v.parse().ok()).unwrap_or(0);
        Self { deny_remaining: AtomicUsize::new(n) }
    }
}

#[async_trait::async_trait]
impl ExecutionProvider for NullProvider {
    async fn provision(&self, spec: &SandboxSpec) -> Result<SandboxHandle, ProviderError> {
        if self.deny_remaining
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_sub(1))
            .is_ok()
        {
            return Err(ProviderError::CapacityDenied(
                "null provider: injected quota denial".into()));
        }
        Ok(null_handle(spec.session_id))
    }
    async fn state(&self, _h: &SandboxHandle) -> Result<SandboxStatus, ProviderError> {
        Ok(SandboxStatus::Running) // never dies on its own; tests drive cancels
    }
    async fn collect_artifacts(&self, _h: Option<&SandboxHandle>, _c: &CollectContext)
        -> Result<CollectedArtifacts, ProviderError> {
        Ok(CollectedArtifacts::Collected(vec![])) // collection ran; worktree clean
    }
    async fn terminate(&self, _h: &SandboxHandle) -> Result<(), ProviderError> { Ok(()) }
    async fn list_managed(&self) -> Result<Vec<(Uuid, SandboxHandle)>, ProviderError> {
        Ok(vec![])
    }
    async fn healthcheck(&self) -> Result<(), ProviderError> { Ok(()) }
    fn runtime_name(&self) -> &'static str { "null" }
}
```

(`null_handle`: construct `SandboxHandle` exactly as `DockerProvider::provision` does — copy that struct literal, substituting runtime `"null"` and the session id; do not invent fields. Default trait methods — `workspace_transport` = `HostDir`, the refuse-above-offline `network_enforcer` — are correct as-is.)

- [ ] **Step 2:** `build_provider` arm in `main.rs`:

```rust
        #[cfg(feature = "test-provider")]
        "null" => Ok(Arc::new(fluidbox_provider::NullProvider::from_env())),
```

Verify both: `cargo check -p fluidbox-server --features test-provider` AND plain `cargo check --workspace` (the arm must vanish without the feature; `FLUIDBOX_PROVIDER=null` on a release build stays an unknown-provider boot error).

- [ ] **Step 3: Write `scripts/e2e-queue.sh`** — self-isolated by construction: does NOT `source .env`; owns database `fluidbox_queue_e2e` on the local container; binds `127.0.0.1:18791` (the null provider needs no `host.docker.internal`, so loopback is safe HERE — unlike the live suites); fixed admin token. Skeleton (align the curl payloads and `ok()/no()/say()` helpers with `scripts/governance-e2e.sh`; `"repo":{"kind":"none"}` means no git fixture is needed):

```bash
#!/usr/bin/env bash
# Hermetic queue-admission e2e (design §12): real HTTP, real Postgres, ZERO
# sandboxes and ZERO model spend (FLUIDBOX_PROVIDER=null, feature-gated build).
# Self-isolated: own database, own port, no .env. Safe to run locally and in CI.
set -uo pipefail
cd "$(dirname "$0")/.."
PG=postgres://fluidbox:fluidbox@127.0.0.1:5433
psql "$PG/fluidbox" -c 'drop database if exists fluidbox_queue_e2e' >/dev/null
psql "$PG/fluidbox" -c 'create database fluidbox_queue_e2e' >/dev/null
cargo build -p fluidbox-server --features test-provider
export DATABASE_URL="$PG/fluidbox_queue_e2e"
export FLUIDBOX_BIND=127.0.0.1:18791 FLUIDBOX_ADMIN_TOKEN=queue-e2e-token
export FLUIDBOX_PROVIDER=null FLUIDBOX_DATA_DIR="$(mktemp -d)"
export FLUIDBOX_MAX_CONCURRENT_RUNS=1 FLUIDBOX_QUEUE_MAX_DEPTH=3
export FLUIDBOX_QUEUE_MAX_WAIT_SECS=3600 FLUIDBOX_QUEUE_REQUEUE_MAX=5
./target/debug/fluidbox-server & SRV=$!
trap 'kill $SRV 2>/dev/null' EXIT
# wait-for-health loop against http://127.0.0.1:18791, then seed an agent via
# the API (mirror governance-e2e.sh's agent bootstrap), then FOUR phases:
#
# P1 cap=1 FIFO: create runs A,B,C ("repo":{"kind":"none"}). Assert A reaches
#    provisioning/initializing (poll GET /v1/sessions/{id}); B,C sit 'queued';
#    cancel A → B dispatches next (FIFO by created_at); C follows after
#    cancelling B.
# P2 depth bound: fill to 3 queued, next create returns HTTP 429 with a
#    Retry-After header (curl -i, grep both).
# P3 bounce: restart the server with FLUIDBOX_NULL_CAPACITY_DENIALS=1. One
#    run: first dispatch bounces — psql asserts status back to 'queued',
#    dispatch_attempts=2, dispatch_after IS NOT NULL, status_reason LIKE
#    'provider at capacity%' — then (backoff floor 30 s) it provisions.
#    Keep the phase fast by asserting the parked-with-backoff state, not by
#    waiting out the redispatch.
# P4 expiry: restart with FLUIDBOX_QUEUE_MAX_WAIT_SECS=5 and a slot held by
#    one live run; a second run parks and, within ~25 s (5 s age + 15 s sweep
#    cadence + margin), fails with the max-wait reason in status_reason.
#
# Every assertion prints via ok()/no(); exit nonzero if any failed.
```

Write the four phases fully in the script (status polling via `GET /v1/sessions/{id}`, DB assertions via `psql "$DATABASE_URL" -tAc`).

- [ ] **Step 4:** Run `bash scripts/e2e-queue.sh` locally — the sanctioned exception in Global Constraints (isolated by construction). All phases green.
- [ ] **Step 5:** clippy with and without the feature; fmt. Commit: `feat(test): feature-gated NullProvider + hermetic queue-admission e2e`

---

### Task 10: Queue observability (metrics render + session API exposure)

Design §13. The Live gauges (depth + oldest wait, read at render time — the registry's own doctrine for DB-derived point-in-time values), the requeue counter, and `queued_at`/`queue_position` on the session API so "why is my run not running" is answerable per run.

**Files:**
- Modify: `crates/fluidbox-server/src/metrics.rs` (render section + `queue_requeues: Family` — `queue_dispatched`/`queue_shed`/`queue_wait_seconds` landed in Task 6)
- Modify: `crates/fluidbox-db/src/system_worker.rs` (`queue_gauges` + inventory entry, invariant 6)
- Modify: `crates/fluidbox-db/src/lib.rs` (scoped `queued_position`)
- Modify: the session GET serialization site in `crates/fluidbox-server/src/api.rs` (grep for where `SessionRow` becomes the response body; if a projection struct exists, extend it)

**Interfaces:**
- Produces: `system_worker::queue_gauges(pool) -> sqlx::Result<(i64, i64)>` (depth, oldest-wait-secs); `queued_position(pool, scope, created_at) -> sqlx::Result<i64>`; API fields `queued_at`, `queue_position` (present only while status is `queued`).

- [ ] **Step 1: DB tests first** — `queue_gauges` returns `(0, 0)` with no queued rows and `(n, ≥0)` with n; `queued_position` counts only OLDER queued rows in the SAME tenant: `select count(*) from sessions where tenant_id = $1 and status = 'queued' and created_at < $2`. (Tenant-scoped by design: the position is relative to what the caller may see; a deployment-wide number would need a bypass and leak cross-tenant load. Disclose this in the fn doc.)
- [ ] **Step 2: Implement** both, plus `queue_requeues: Family::new("fluidbox_queue_requeues_total", "reason", &["capacity", "_other"])` — and add the `state.metrics.queue_requeues.inc("capacity");` line inside Task 7's `requeue_capacity_denied`. Render `fluidbox_runs_queued_depth` and `fluidbox_queue_oldest_wait_seconds` in the metrics handler's Live section (on query error: `scrape_errors.inc()` and render 0 — the existing Live convention).
- [ ] **Step 3: Session API** — when `row.status == "queued"`, attach `queued_at` and `queue_position` to the session JSON.
- [ ] **Step 4:** `cargo test -p fluidbox-db queue_gauges` + `-p fluidbox-server metrics::` green; re-run `bash scripts/e2e-queue.sh` extending its P1 to assert `queue_position` is 1 for B and 2 for C.
- [ ] **Step 5:** clippy; fmt. Commit: `feat(server): queue observability — live gauges, requeue counter, queued position in the session API`

---

### Task 11: Operator surfaces (Helm, doctor, OpenAPI, dashboard chip, runbook)

Design §6 (presentation + rollout), §8 (chart), §13 (doctor). Presentation-only on the web side.

**Files:**
- Modify: `deploy/helm/fluidbox/values.yaml` (add `server.maxConcurrentRuns: ""` + the three queue vars; REWRITE the sandbox-quota comment block: the app cap is now the waiting room and the ResourceQuota the backstop — set cap ≤ quota `pods`)
- Modify: the server Deployment template env block (thread the four `FLUIDBOX_*` vars the way every other optional server env is threaded)
- Modify: `scripts/doctor.sh`
- Modify: `apps/web/public/docs/openapi.yaml` (status enum at `:4029` + a description paragraph paralleling `awaiting_authorization`'s at `:4026`)
- Modify: `apps/web/app/lib/activity.ts` (`:14` — `queued` classifies as a neutral/waiting chip: NOT `ATTENTION_STATUSES`, NOT `FAILED_STATUSES`; add an explicit label if the file maps labels) + `apps/web/app/lib/activity.test.ts`
- Create: `docs/hosted/run-queue-operations.md`

- [ ] **Step 1: doctor checks** (append to `scripts/doctor.sh` using its existing check helpers): if `FLUIDBOX_MAX_CONCURRENT_RUNS` is set → fail unless it parses as an integer ≥ 1; fail if any of `FLUIDBOX_QUEUE_MAX_DEPTH`/`MAX_WAIT_SECS`/`REQUEUE_MAX` are set while the cap is not ("dead queue config — the server will refuse to boot"); warn if `FLUIDBOX_QUEUE_MAX_WAIT_SECS` ≥ 10800 (the 3 h session-token TTL — benign because bounces re-mint, but flags operator confusion).
- [ ] **Step 2: OpenAPI + chip.** Enum value `queued` described as: *"the pre-provisioning capacity park: the run's spec is frozen but no sandbox exists and no model spend is possible until the dispatcher admits it under `FLUIDBOX_MAX_CONCURRENT_RUNS`."* Dashboard: `queued` renders the neutral waiting treatment; extend `activity.test.ts` with the classification assertion.
- [ ] **Step 3: Runbook** — `docs/hosted/run-queue-operations.md`, short and complete: enablement order (① apply 0034 — additive, safe early; ② roll the binary to EVERY replica; ③ set the env), why (old binaries read `queued` as terminal — zombie rows, not destroyed state; the boot sweep's strict parse leaves unknown statuses alone), the rollback drain procedure (unset the env everywhere → wait for `select count(*) from sessions where status='queued'` = 0, cancelling stragglers via the API → roll back), the K8s sizing rule (cap ≤ quota `pods`; the quota is the backstop and a `CapacityDenied` bounce is the signal it fired), and the four envs with defaults (link design §8).
- [ ] **Step 4:** `bash scripts/doctor.sh` runs clean with and without the vars (test via a subshell exporting dummies). Web: run only the unit tests for the touched file (the repo's existing invocation for `activity.test.ts`); `pnpm lint` is already red on main — do not chase it.
- [ ] **Step 5:** Commit: `docs+chart: run-queue operator surfaces (helm, doctor, openapi, dashboard chip, runbook)`

---

### Task 12: Live e2e phase on the replay tier (maintainer-triggered)

Design §12 layer 4 — the wiring proof with REAL containers and zero keys: the replay runner (the `just demo` machinery) under `FLUIDBOX_MAX_CONCURRENT_RUNS=1`.

**Files:**
- Create: `scripts/e2e-queue-live.sh` (modeled on the replay tier used by `scripts/e2e-codex-replay.sh` and the demo fixtures)
- Modify: the `just e2e` chain's script list to include it (justfile edit only — do NOT run it)

- [ ] **Step 1:** Write the phase: boot the stack with the replay runner image, cap 1, depth 2; three runs → assert park + FIFO dispatch through REAL Docker provisioning + a depth 429 on the fourth; one cancel-while-queued.
- [ ] **Step 2:** **Do not execute it.** Full e2e is maintainer-triggered (Global Constraints); open the PR with the script and state "maintainer to run `just e2e` before merge" in the PR body — the house convention for e2e-bearing PRs.
- [ ] **Step 3:** Commit: `test(e2e): live queue phase on the replay tier`

---

## Self-review (performed at plan-writing time)

- **Spec coverage:** design §5→Task 2, §6→Tasks 1/11, §7.1→Tasks 6/8, §7.2–7.3→Task 3, §7.4→Tasks 4/7, §7.5→Task 6, §7.6→Tasks 2/6, §8→Task 5, §9→Task 8, §12→Tasks 9/12, §13→Tasks 10/11. Stage 2/3 intentionally unplanned (design §11 — the trigger has not fired).
- **Type consistency:** `QueueCfg` field names, the `dispatch_claim` signature, `ClaimedRun.dispatch_attempts: i32`, and `capacity_backoff_secs(i32) -> i64` are used identically across Tasks 3/5/6/7/9.
- **Known drift risks called out in-task:** the migration number (re-verify), `abandon_launch` reuse (read before wiring), the `SandboxHandle` literal (copy from DockerProvider, never invent), e2e helper alignment (`governance-e2e.sh` conventions), and `fail`/`transition_fenced` signatures (match their call sites).
