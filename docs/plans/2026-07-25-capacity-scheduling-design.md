# fluidbox — Capacity-aware sandbox scheduling design (queue, admission, dispatch — 100k-proof)

**Date:** 2026-07-25
**Status:** DRAFT v1.0 — pending adversarial review. Nothing here is implemented; the current system has no run queue, no capacity signal, and no admission control beyond the k8s ResourceQuota (which rejects rather than queues).
**Audience:** fluidbox maintainers, engineers implementing the queue/dispatcher phases, and reviewers of the 100k-scale direction
**Relationship to other docs:** `PLAN.md` stays authoritative (§2 convergence invariants bind every decision here; §6.2 defines the `ExecutionProvider` seam this design schedules above; §7 M2 defines the MicroVM provider the direction section targets). `docs/plans/2026-07-15-kubernetes-native-provider-design.md` built the provider this design paces; its v1 non-goals (warm pools, multi-replica) are re-examined here with data. `docs/plans/2026-07-14-multi-user-mcp-control-plane-design.md` §"Scale model" recommended per-tenant concurrency limits and "queue-backed provisioning" without building them — this design is that build. `docs/hosted/rollout-gates.md` Gate 3 defines the pass criteria the validation ladder extends. External reference: Modal, *"Scaling to 1 million concurrent sandboxes in seconds"* (modal.com/blog) — analyzed §1.

## Executive verdict

Today a fluidbox run is scheduled anywhere, anytime: `create_run` inserts the session and fires an
unbounded in-process `tokio::spawn` that provisions immediately. There is no holding state, no
capacity accounting, no cross-replica pickup, and the only quantity gate in the whole system — the
k8s namespace ResourceQuota — **fails runs terminally** instead of queueing them. The 60/150/300
concurrent-run tiers the chart advertises are explicitly unproven (README.md:114).

This design adds capacity-based scheduling in four shippable phases, then charts the path to 100k+
concurrent sandboxes:

1. **A durable `queued` session state** and a per-replica **dispatcher** worker (tick + NOTIFY,
   `FOR UPDATE SKIP LOCKED`, tenant-fair dequeue) that drains it under the existing 0021 lease/epoch
   fencing. This also fixes a real robustness gap for free: a `created` run whose replica dies today
   is *never re-driven* — only swept to `failed` after 30 minutes; with the dispatcher any replica
   picks it up in about a tick.
2. **Atomic capacity claims** — per-tenant + deployment-global counter rows claimed by a
   single-statement CAS at admission and released on band exit inside the one `transition` funnel,
   healed by a reconcile sweep. Try-then-queue: when there is headroom (the common case) the run
   launches inline exactly as today, zero added latency.
3. **A typed `CapacityExhausted` provider error** that converts the ResourceQuota-403-terminal
   failure into requeue-with-backoff — and is exactly the retry semantics that optimistic in-memory
   placement will need later.
4. **A scale program**: load math shows the first three ceilings (DB pool at hundreds; NOTIFY +
   watchdog scans at low thousands; the k8s API at ~10k) and the flattening work for each, then the
   plane split that carries further.

The Modal synthesis, adapted rather than adopted: Modal's v1 — Postgres as the source of truth in
the creation/scheduling critical path, optimistic parallel schedulers, assignment as another PG
write — is architecturally where fluidbox is today, and it died of O(sandboxes) load. Their v2 moved
placement to in-memory schedulers fed by worker-published state, with **no datastore in the creation
path**. fluidbox cannot copy that verbatim: the governance ledger (policy decisions, approvals,
budgets, the event timeline) *is the product*, so durable writes cannot vanish. The synthesis is a
**plane split**: the *placement decision* moves off the Postgres hot path and becomes O(1) against
cached state, while every *governance record* — session status, ledger, and the capacity claim
itself — stays durable. A durable audit of placement decisions is on-brand for a governance product;
it just must not sit inside the placement loop. The near-term PG-backed dispatcher is built behind a
seam (`CapacitySource`) so the 100k implementation swaps in without a rewrite.

Nothing in this design weakens a §2 invariant. RunSpec stays frozen at creation (placement is
runtime state, never spec); the server stays the single status writer; the `create_session`
transaction that binds trigger idempotency claims is byte-for-byte untouched; queue wait burns
neither the wall-clock budget (`started_at` stamps only on `running`) nor the 3-hour session-token
TTL (tokens mint post-dequeue).

## Goals

- A durable run queue: at capacity, new runs park in a real, persisted, cancellable `queued` state —
  never silently dropped, never terminally failed for lack of room.
- Per-tenant `max_active` quotas + FIFO within tenant; per-tenant queue-depth caps + queue TTL;
  a deployment-global ceiling. Defaults preserve today's behavior exactly (unlimited).
- Cross-replica dispatch: any replica drains the queue; a dead replica's queued and mid-launch runs
  are re-driven, not just swept to failure.
- Typed provider capacity errors; k8s quota rejection becomes requeue-with-backoff.
- Provisioning concurrency + start-rate bounded per replica (the k8s API and the kernel are both
  targets a mass drain can hurt — Modal's rtnl war story has two direct fluidbox parallels).
- A quantified scale model with named ceilings and the flattening plan for each, so the 100k claim
  is an engineering roadmap, not a slogan.
- Full observability: queue depth, wait histograms, admission/rejection counters, timeline events,
  a dashboard status chip — within the bounded-cardinality rule (no per-tenant metric labels).

## Non-goals

- **Warm pools / pre-provisioned sandboxes.** Still the k8s design's non-goal, and PLAN §2 #1 ("no
  persistent, privileged agent servers — ever") means any future revisit is limited to blank,
  credential-free, workspace-free sandboxes. Nothing in this design depends on them.
- **Weighted fair-share / priority scheduling.** v1 fairness is per-tenant quotas + FIFO. A
  `priority` lane is an open question (§Open questions), not a v1 deliverable.
- **A stream store (Redis/NATS/Kafka) for worker state.** Explicitly a *future deliberate decision*,
  gated on observed data at the ~10k rung. Neon + LISTEN/NOTIFY + the flattening plan carries to
  ~10k with no new infrastructure (§8).
- **Uniform everything-through-queue admission.** Only at-capacity runs traverse `queued`;
  `created→provisioning` stays legal (§5).
- **Autoscaling the node fleet.** This design decides *whether and where* a run may start; growing
  the substrate underneath (Karpenter/ASGs/MicroVM fleet sizing) stays the operator's and M2's
  concern.
- **Placement in RunSpec.** Where a run lands is runtime state on the session (`sandbox_handle`,
  and later a pool id), never part of the frozen spec.

## Current scheduling architecture (verified 2026-07-25)

Everything below was verified at file:line against main (`7b75b20`).

### The launch path — unbounded, in-process, one-shot

- All four entry points (manual `api.rs:1011`, trigger invoke `triggers.rs:1015`, schedule tick
  `scheduler.rs:204`, webhook fan-out `events.rs:272`) converge on `run_service::create_run`
  (`crates/fluidbox-server/src/run_service.rs:111-506`).
- `create_session` (`run_service.rs:441-462`) freezes RunSpec + resource bindings + the trigger
  idempotency claims in ONE transaction. It inserts **no explicit status** — every run is born
  `created` via the column default (`migrations/0001_init.sql:52`). This detail is load-bearing for
  this design: admission can branch after the commit without touching the exactly-once machinery.
- `orchestrator::spawn_run` (`run_service.rs:503` → `orchestrator.rs:144-151`) is a bare detached
  `tokio::spawn(run(...))`. **No semaphore, no queue, no counter** — grep confirms no concurrency
  primitive anywhere on the run path. `main.rs:82-101` deliberately rejects an HTTP-layer
  concurrency limit (it would starve long-poll handlers); the only shed mechanism under load is DB
  pool acquire timeout (`crates/fluidbox-db/src/lib.rs:118-121` — "the deployment's real
  back-pressure valve").
- `run()` (`orchestrator.rs:1169-1447`): take the driver lease (`:1186`; `acquire_session_lease`
  `lib.rs:4026-4053`, TTL 30 s, epoch bumps only on owner change) → `created→provisioning` (`:1191`)
  → mint the four audience tokens, TTL 3 h (`:1204-1233`) → `provisioning→initializing` (`:1243`) →
  `materialize_workspace` (`:1256` — the control-plane git clone, "can take minutes") →
  `provider.provision()` (`:1323`) → `set_sandbox_handle` attach fence (`:1377-1399`) →
  `initializing→running` (`:1412-1426`).
- Driver lifecycle edges ride `transition_session_fenced` (`lib.rs:3954-4003`); request-side intents
  (cancel, forced finalize) stay deliberately unfenced. `transition`/`transition_fenced` share
  `transition_inner` (`orchestrator.rs:153-232`), whose doc comment states the property this design
  reuses: *"the ledger event and the terminal-entry side effects (token revocation + delivery
  enqueue) ride the SINGLE winner of whichever compare-and-set the caller ran."*
- **Provision failure is terminal.** The `?` at `orchestrator.rs:1323` propagates to `spawn_run`'s
  `fail()`. No retry, no reclassification.

### The gates that exist — and what they are not

- The netpol run-gate (`run_service.rs:119-129`): binary, fail-closed, not quantity-aware.
- Subscription `concurrency_policy` (`run_service.rs:189-254`): per-subscription overlap control
  (skip/replace), where "active" = any non-terminal status (`active_subscription_sessions`,
  `lib.rs:6205-6225`). Manual runs are never gated.
- The k8s namespace ResourceQuota (`deploy/helm/fluidbox/values.yaml:256-263`, tiers 20/60/300
  pods at `:279-282`): the ONLY concurrent-quantity gate, enforced by the API server — and it
  **rejects with 403 at pod create, which today fails the run terminally**. There is deliberately no
  application-side counter (the values.yaml comment says so; this design is its named replacement).

### The orphan gap

A `created`/`provisioning`/`initializing` session whose driving replica dies is never re-driven —
pickup is in-process only. The watchdog's `stale_nonstarted_sessions`
(`crates/fluidbox-db/src/system_worker.rs:288-307`) sweeps those statuses to `failed` after
`FLUIDBOX_STALE_LAUNCH_MINS` (default 30, `workers.rs:364-372`), aging by `created_at` —
deliberately, because heartbeats bump `updated_at` (the M5 lesson recorded in its doc comment).
Terminal *finalization* is already recoverable cross-replica (`finalize_worker`, claims + fences);
the *launch* is not.

### The per-run standing costs (what O(sandboxes) means here)

- **Heartbeat:** every runner POSTs `/heartbeat` every 10 s (`images/runner-lib/contract.mjs:466-471`).
  The handler (`internal.rs:1929-1949`) runs TWO transactions per beat — the `UPDATE sessions`
  (`lib.rs:4211-4223`) plus a `get_session` read to compute the quiesce action — and each is a
  `scoped_tx` carrying a `set_config` round trip. **One beat ≈ 2 tx / ~4 statements.**
- **Events:** `append_event()` (`migrations/0001_init.sql:91`) takes a per-session row lock for the
  gapless `seq`, inserts, and `pg_notify`s `fluidbox_events` — one NOTIFY per event, broadcast to a
  `PgListener` on every replica (`lib.rs:7071`, `7088`).
- **Watchdog:** `sessions_in_status` (`system_worker.rs:268-277`) is `SELECT *` (all jsonb columns)
  over the whole active set, no LIMIT, every 15 s (`workers.rs:377`), **on every replica** — all six
  periodic workers are per-replica (`workers.rs:123-137`).
- **SSE:** per-viewer catch-up query with a 2 s poll floor (`sse.rs`).
- **Multi-replica is not actually shipped.** The chart is `replicas: 1` + `Recreate`; >1 requires
  the s3 archive store (the RWO PVC is the first hard blocker to two servers). The 0021
  lease/epoch machinery is real and tested, but today it fences a fleet of one.

### Properties queue wait must not break (verified)

- `started_at` stamps only on entry to `running` (`lib.rs:3921-3926`, `:3985-3989`) — wall-clock
  budget (`workers.rs:591-620` sweeps vs `started_at`) is untouched by time spent queued.
- Session tokens mint inside `run()` after dequeue (`orchestrator.rs:1204-1233`) — queue wait cannot
  expire them.
- `SessionStatus::parse` returns `None` for unknown strings, and both transition functions
  `unwrap_or(SessionStatus::Failed)` on the CURRENT status (`lib.rs:3915`, `:3978`) — a terminal
  source refuses every edge, so an OLD binary that ever loads a `queued` row can neither drive nor
  corrupt it; the old watchdog compares status strings that `"queued"` never matches
  (`workers.rs:395`). (§11 rollout.)

## §1 Workload model and load math

fluidbox runs are minutes-scale agent sessions, not sub-second function calls. Assume an average
run of 10 minutes; by Little's law the steady start rate is **λ = N/600**. Webhook fan-outs and
schedule storms are the bursty overlay (one delivery × many subscriptions arrives in seconds).

| Metric (steady state) | 1k concurrent | 10k | 100k | Basis |
|---|---|---|---|---|
| Start rate λ | 1.7/s | 17/s | **167/s** | N/600 |
| Heartbeat tx/s (today: 2 tx/beat) | 200 | 2,000 | **20,000** | N/10 × 2 |
| Event-append tx/s (20-60 events/run) | 33-100 | 333-1k | **3.3k-10k** | (20..60)/600 × N |
| NOTIFY/s (≈ events), each broadcast to every replica listener | 33-100 | 330-1k | **3.3k-10k** | append_event |
| Start-path tx/s (~20 tx/start, bursty) | ~34 | ~340 | **~3,300** | λ × 20 |
| Watchdog scan | `SELECT *` of the active set / 15 s / replica | | **~1 GB/scan/replica** | ~10 KB/row × N |
| k8s provision-poll GETs/s | ~100-200 | ~1k-2k | **~10k-20k** | in-flight = λ × T_block; 1 s poll (`provider-k8s/src/lib.rs:356-391`) |
| k8s mutating ops/s (pod+secret create/delete) | ~5 | ~50 | **~500** | λ × 3 |

k8s context: upstream scalability envelopes are ~110 pods/node, 5k nodes, 150k pods per cluster —
and the provision-poll GET storm arrives first. **The inline 1 s poll loop is a self-inflicted
API-server DoS at scale** and must become an informer/watch (§7) before ~10k regardless of any
other choice.

### The first three ceilings, in order

1. **DB connection pool — at HUNDREDS of concurrent runs.** Empirically the "first hard ceiling
   found" (rollout-gates Gate 3). Heartbeat tx + SSE poll floors + bursty start paths exhaust
   25 conns/replica long before compute does; Neon requires direct connections (no PgBouncer
   transaction pooling — it breaks sqlx prepared statements and LISTEN/NOTIFY).
   Fixes, cheapest first: fold the quiesce read into the heartbeat write
   (`UPDATE … RETURNING status` — halves heartbeat load, a one-liner); per-replica in-memory
   heartbeat coalesce with a batched `unnest` flush (§8 — turns O(N) writes into O(replicas));
   adaptive SSE floor; pool/CU sizing from Gate-3 measurements.
2. **NOTIFY volume + SSE broadcast + the unbounded watchdog scan — at LOW THOUSANDS.**
   One NOTIFY per event on one global channel × every replica, plus ~N-row `SELECT *` scans × six
   workers × R replicas.
   Fixes: rate-collapse NOTIFY to one-per-session-per-flush (safe: NOTIFY is wakeup-only, the seq
   catch-up query is the delivery truth); partial indexes + keyset pagination + column projection
   for the watchdog; leader-elect the periodic sweepers; per-session SSE wakeup.
3. **The k8s API — at ~10k+.** The poll-GET storm, then ~500/s mutating churn on etcd, then the
   pod-count ceiling — all while the quota rejects rather than queues.
   Fixes: watch/informer-driven provisioning (provision returns after create; a reconciler drives
   `initializing→running`), multi-cluster pool sharding (§9), digest-pinned images + pull-through
   mirror + pre-pull.

**Meta-ceiling:** Postgres as source of truth *in the placement critical path*. That is the boundary
the plane split (§9) exists to cross — everything before it is reachable on Neon + NOTIFY.

## §2 Capacity model

### Accounting: counter rows, CAS-claimed, funnel-released, sweep-healed

A new table `tenant_capacity` holds one row per tenant plus one deployment-global row
(`tenant_id NULL`):

- **Claim** is a single-statement take-then-check (the 0023 `RATE_UPSERT` shape):
  `UPDATE tenant_capacity SET active = active + 1 WHERE tenant_id = $1 AND (cap_active IS NULL OR
  active < cap_active) RETURNING …` — tenant dimension first, global dimension second, both in ONE
  transaction; refusal of either rolls back both so a refused admission charges nothing
  (`governance::admit` precedent, `crates/fluidbox-db/src/governance.rs:513`). O(1), race-free
  under READ COMMITTED — the exact race the 0022 header warns a CTE alone cannot close.
- **Release rides the transition funnel.** `transition_inner` (`orchestrator.rs:153-232`) is where
  terminal-entry side effects already ride the single CAS winner; the decrement hooks there, gated
  by the existing band-edge accounting (`metrics::active_delta`, `metrics.rs:593`). The **capacity
  band = the occupancy band** already defined for the `active_runs` gauge
  (`metrics.rs:576-593`): `provisioning..finalizing`. `queued` and `created` hold NO slot.
- **Reconcile sweep is first-class, not a nicety.** The funnel's side effects are
  post-CAS/at-least-once (verified in `transition_inner`), so a crash can leak a decrement. A sweep
  recomputes `active` from `count(*)` over the band per tenant (plus the global row) every N
  seconds; drift is bounded to one interval. If drift ever proves troublesome in practice, the
  fallback is reservation-rows-per-run (the 0022 shape — exact and self-healing, at the cost of an
  aggregate on the hot path).
- **Rejected alternative:** `count(*)` + advisory-lock serialization — advisory locks are the
  house-rejected primitive (0021 header: connection-bound, fragile across pool reconnects and Neon
  scale-to-zero, unobservable), and it serializes a tenant's admissions.

### RLS and the global row

Capacity is deployment-operational and its global dimension crosses tenants, so all writes go
through **named `worker_tx` bypass entry points** in `fluidbox-db` (the grep-able escape-hatch
discipline; the `system_worker` module-doc inventory grows accordingly). The table still carries
the house RLS trio in its migration: `ENABLE` + `FORCE`; a policy allowing a tenant to `SELECT` its
own row while the global row and ALL DML stay bypass-only (the `connector_catalog` /
`oauth_client_registrations` global-row split precedent); an enumerated DML grant resolved from
`current_setting('fluidbox.runtime_role')` — never hardcoded. The exact bypass-GUC predicate must
be copied from 0018's policy text at implementation time.

### DDL sketch (migration number = next free at implementation time; 0026 is taken by an unmerged branch)

```sql
alter table sessions
  add column queued_at        timestamptz,
  add column admitted_at      timestamptz,
  add column launch_attempts  int not null default 0,
  add column queue_not_before timestamptz;
-- column-adds on the 0018-protected sessions table: NO new RLS objects needed
-- (policies are column-agnostic; grants are table-level — the 0021 argument).

create index sessions_queued
  on sessions (tenant_id, queued_at)
  where status = 'queued';

create table tenant_capacity (
  tenant_id       uuid unique references tenants(id) on delete cascade,  -- NULL = global row
  cap_active      int,           -- NULL = unlimited
  cap_queue_depth int,           -- NULL = unlimited
  active          int not null default 0,
  updated_at      timestamptz not null default now()
);
create unique index tenant_capacity_global on tenant_capacity ((true)) where tenant_id is null;
-- + RLS trio + runtime-role grant, per the house rule (see above).
```

`admitted_at` (stamped on `queued→provisioning` and on the inline fast path) exists to fix a trap:
the stale-launch sweep ages by `created_at`, so a run that waited longer than
`FLUIDBOX_STALE_LAUNCH_MINS` in queue would be swept to `failed` the instant it was admitted. The
sweep's age predicate becomes `coalesce(admitted_at, created_at)`.

## §3 The `queued` state

Add `Queued` to `SessionStatus` (`crates/fluidbox-core/src/state.rs:16`). New edges in
`can_transition_to` (`state.rs:85-115`):

| Edge | Meaning |
|---|---|
| `Created → Queued` | at-capacity detour (only path into queued) |
| `Queued → Provisioning` | admission (dispatcher, or inline retry) |
| `Queued → Cancelling \| Finalizing` | cancel / TTL expiry — terminal stays reachable ONLY via `finalizing` |
| `Provisioning → Queued` | requeue on `CapacityExhausted` (§7) |
| `Created → Provisioning` | **kept** — the headroom fast path |

Semantics: `is_terminal`/`is_winding_down` false; `accepts_work` true (same as `Created` — no
runner exists to call anything); **excluded from the occupancy band** (`status_is_active`) — a
queued run holds no sandbox and no capacity slot.

Tests that change (`state.rs`): `Queued` joins the `ACTIVE` fixture (`:122`), which makes
`no_direct_terminal_entry` (`:152`), `every_nonterminal_can_reach_failed`, and the wind-down suite
cover it automatically; `happy_path` (`:131`) gains the `created→queued→provisioning` variant;
new assertions pin `!Queued→Running`, `!Queued→Initializing` (`no_skipping_init` `:207` unchanged);
`Provisioning→Queued` legal. Round-trip string tests gain `"queued"`.

Cancel-while-queued and TTL expiry ride the existing finalize funnel, which already handles
sessions with no sandbox and no quiesce.

## §4 Admission — try-then-queue

Inserted in `create_run` between `create_session` (`run_service.rs:441-462`) and today's
`spawn_run` (`:503`):

1. `create_session` commits — **byte-identical**: idempotency/dispatch claims still bind in that
   transaction; the row is born `created`.
2. Depth pre-check happens BEFORE `create_session` for the depth-cap rejection (nothing to unwind).
3. `capacity::try_admit(tenant)` — the same atomic claim the dispatcher uses:
   - **Won** → `spawn_run` exactly as today. Zero added latency on the headroom path, which at k8s
     scale is the common case.
   - **Lost** → `transition(created→queued)` (unfenced; stamps `queued_at`) + `NOTIFY
     fluidbox_dispatch` + ledger `RunQueued`. The API returns the session normally — callers see
     `status: queued` and watch the same SSE timeline.
4. A crash between `create_session` and either branch leaves the row `created` — the identical
   window that exists today before `spawn_run`, and the dispatcher's recovery scan (§5) now heals
   it in ~a tick instead of the 30-minute sweep.

Why not everything-through-queue: it adds a dispatcher hop to every interactive run, makes manual
UX depend on dispatcher health, and forces removing `created→provisioning` — a larger blast radius
for no governance gain. Why not admission before `create_session`: the claim tx must never wrap the
idempotency-binding tx (lock scope, and a refused admission must not consume an invocation claim).

`concurrency_policy` interplay: zero changes. "Active" is already "any non-terminal status"
(`lib.rs:6205-6225`), so a queued run correctly blocks `skip_if_running` and is cancelled by
`replace` — and because `Replace` cancels inline before creating, the freed slot is visible to the
replacement's inline `try_admit` immediately.

### Backpressure per entry point (per-tenant queue-depth cap hit)

New `RunCreation::QueuedDepthExceeded { depth, cap, retry_after_secs }` (`run_service.rs:92`
enum) + `ApiError::TooManyRequests` rendering **429 + `Retry-After`**:

| Entry point | Behavior at depth cap | Rationale |
|---|---|---|
| Manual API (`api.rs:1011`) | 429 + Retry-After | interactive caller backs off |
| Trigger invoke (`triggers.rs:1015`) | `release_invocation` (free the claim) then 429 | a wedged claim would block the retry |
| Schedule tick (`scheduler.rs:204`) | record a skip row (`tenant_queue_full`) + advance | the `SkippedOverlap` precedent; non-wedging, visible per subscription |
| Webhook (`events.rs:272`) | 503 so the provider retries; the two-level dedup heals the fan-out | external truth — prefer enqueue whenever possible, size event depth caps generously |

**Queue TTL:** rows with `queued_at < now() - FLUIDBOX_QUEUE_TTL_SECS` →
`fail("queue_ttl_expired")` via `queued→finalizing→failed`. Independent of token TTL and wall-clock
budget by the verified stamping properties above.

## §5 The dispatcher

New worker `crates/fluidbox-server/src/dispatcher.rs`, on every replica, following the
`deliveries.rs`/`scheduler.rs` worker shape:

- **Wakeup:** tick (default 1 s — the scheduler's floor; the two existing PgListeners hold Neon's
  compute open regardless) + a third listener on `fluidbox_dispatch`, NOTIFYed on enqueue AND on
  every capacity release so a freed slot drains promptly. NOTIFY = wakeup; the dequeue query =
  truth.
- **Fair dequeue:** one query — tenants with headroom (`active < cap_active`) joined `LATERAL` to
  their oldest `queued` rows (`ORDER BY queued_at LIMIT <tenant headroom>`), honoring
  `queue_not_before`, `FOR UPDATE SKIP LOCKED`, trimmed to global headroom. The cap check lives
  **inside the claim predicate** — a capped tenant's rows are never even locked, which kills the
  starvation mode where a headroom tenant's oldest items repeatedly lose the lock race to a capped
  tenant's head-of-line. FIFO within tenant; round-robin across tenants falls out of per-tenant
  LIMITs. Per pick, the atomic `try_admit` remains the authority (the dequeue is candidate
  selection, not accounting).
- **Drive:** per admitted pick — `acquire_session_lease` → `transition_session_fenced
  (queued→provisioning, epoch)` (stamps `admitted_at`) → **`drive_from_provisioning`**, the
  factored tail of `run()` from token-mint (`orchestrator.rs:1204`) onward. `run()` (from
  `created`) and the dispatcher (from `queued`) share that one launch tail. It must tolerate
  entry with `current_status ∈ {provisioning, initializing}` (resume, not only first-entry) — that
  is what makes recovery re-drive possible.
- **Bounding:** each admitted run drives on its own spawned task, gated by a per-replica
  `Semaphore(FLUIDBOX_DISPATCH_MAX_CONCURRENT_PROVISIONS)` and a starts/sec pacer. k8s
  `provision()` blocks its task for the whole pod boot (up to `init_grace_secs.max(60)`), so
  in-flight provisions = λ × T_block (Little again): Gate-3 shape (60 runs, λ=0.1/s, T_block
  60-120 s) needs ~4 permits/replica at R=3; the 300 tier ~10-20; keep `R × P ≤ quota.pods`.
  Default `P = 8`, formula `clamp(ceil(quota.pods / R), 4, 24)` in the chart. Past ~300 concurrent
  the right fix is non-blocking provisioning (watch-driven), after which the permit models a
  concurrent-create budget (~8-16) protecting the API server, plus a per-node create budget for
  the rtnl-class hazard — Modal's mass-start war story has two direct fluidbox parallels: CNI
  veth/netns setup on k8s, and the Docker provider's per-session bridge
  (`ensure_network`, `crates/fluidbox-provider/src/lib.rs:54`).
- **Herd control:** jittered ticks + claimed-0 backoff (a replica that claimed nothing backs off
  its next tick); SKIP LOCKED already prevents double-claims, batching prevents hot-head scans.
- **Recovery (the orphan-gap fix):** the dispatcher's scan also re-drives (a) `queued` rows whose
  enqueueing replica died — any replica picks them up next tick; (b) `provisioning`/`initializing`
  rows whose lease expired — re-`acquire_session_lease` bumps the epoch on owner change, fencing
  the dead driver; every launch side effect is already idempotent-or-fenced (token revoke,
  `abandon_launch`, and the `set_sandbox_handle` attach fence under which a redundant pod loses and
  self-terminates — wasteful, never unsafe), bounded by `launch_attempts`. Net: today's
  30-minute sweep-to-fail becomes a ~30-second re-drive, with the sweep kept as final backstop.

## §6 Provider capacity signal

- `ProviderError` (`crates/fluidbox-core/src/traits.rs:205-209`) gains
  `CapacityExhausted(String)`. The k8s provider classifies `kube::Error::Api { code: 403 }` with
  "exceeded quota" on `pods.create` (`provider-k8s/src/lib.rs:331-335`) as `CapacityExhausted`;
  everything else stays `Other`. Unschedulable-past-deadline stays `Other` for now (conservative;
  revisit with operational data).
- In `drive_from_provisioning`, the blanket fail becomes a match:
  `CapacityExhausted` + `launch_attempts < FLUIDBOX_LAUNCH_MAX_ATTEMPTS` → `abandon_launch` →
  `transition_fenced(provisioning→queued)` + `launch_attempts+1` + `queue_not_before = now() +
  backoff(attempt)` + capacity release + NOTIFY. At the attempt cap →
  `fail("capacity_exhausted_max_attempts")`. `Other` → fail as today.
  **This converts the documented ResourceQuota-403-terminal behavior into requeue — the single
  biggest robustness win in the design** — and is precisely the semantics a later optimistic
  in-memory placement needs when its async durable claim loses a race.
- **The `CapacitySource` seam (built now, swapped later):**
  `try_claim(tenant, pool, spec) → Claim | CapacityExhausted`. Near-term impl: the PG counter CAS.
  100k impl: an in-memory occupancy cache fed by worker/pool state, with the durable claim written
  through asynchronously. Callers (inline admission, dispatcher) never change. This is the
  concrete mechanism by which the near-term design evolves instead of being rewritten.

## §7 Non-blocking provisioning (the k8s follow-up this design forces)

The inline 1 s poll (`provider-k8s/src/lib.rs:356-391`) is fine at tens of concurrent provisions
and hostile at thousands (§1 table). The successor: `provision()` returns after pod+secret create;
a per-cluster informer/watch cache drives `initializing→running` via the existing fenced
transitions; `runner_status`'s fatal-waiting classification moves into the reconciler. This is a
scoped provider change behind the same trait — scheduled as its own phase after the queue lands,
prerequisite for the 1k+ rungs.

## §8 Flattening the O(sandboxes) planes (phase-able, ordered by leverage)

1. **Heartbeats.** (a) Fold the quiesce read into the write: `UPDATE … RETURNING status` — one
   transaction per beat, immediately halving heartbeat load. (b) Per-replica in-memory coalesce →
   one batched `UPDATE … FROM unnest($ids, $ts)` flush per ~10 s — O(replicas) writes; quiesce is
   then served from an in-memory cancelling-set fed by a new `fluidbox_cancellations` NOTIFY.
   (c) End-state: **provider-watch liveness** — on k8s the informer already knows the pod is alive;
   the watchdog consults the provider cache, and runner heartbeats become a quiesce channel only.
   The DB stops carrying liveness entirely (Modal's "worker owns its truth", fluidbox-shaped).
2. **Event appends.** Preserve the DB-assigned gapless per-session `seq` (client-side numbering
   cannot survive multi-replica) while amortizing: block-reserve
   `UPDATE sessions SET event_seq = event_seq + n RETURNING event_seq` + one multi-row insert —
   K appends, one transaction, same row-lock serialization, gapless by construction. Batching
   happens AFTER `Redactor::scrub` — the `Redacted<EventEnvelope>`-only ledger invariant is
   untouched. Product lever: coalesce high-frequency low-value events (usage deltas) into
   summaries; decision/approval/tool events stay 1:1 (they are the governance record).
3. **NOTIFY.** Rate-collapse to one per session per flush (carrying max seq). Safe by the house
   contract — NOTIFY is a wakeup, the seq catch-up query is delivery truth. Channel sharding only
   pays off with session affinity; defer.
4. **Watchdog / sweepers.** Column projection + keyset pagination + partial indexes
   (`WHERE status='running'` on `last_heartbeat_at`; the queued partial index from §2) so scans
   return only candidate rows; leader-elect the six per-replica workers (they are single-winner by
   claims already — election just deletes redundant load); ultimately subsumed by provider-watch
   liveness.

## §9 Direction: the 100k fleet (explicitly not specced here)

**The plane split, stated as a table:**

| Plane | Store | Contents |
|---|---|---|
| Governance (durable, Neon) | Postgres, single status writer, lease/epoch-fenced | session lifecycle, the event ledger, approvals/decisions, budgets/usage, **capacity claims** (the audit of what was placed where — written through, async where hot) |
| Placement (fast, rebuildable) | per-scheduler-replica memory | pool/worker occupancy caches, in-flight provision counts, pool health, the "which pool has room for tenant T" answer |

**Path A — multi-cluster k8s sharding (evolutionary):** a `pools` registry (cluster, namespace,
quota, health), per-pool dispatchers + pacers, `SandboxHandle` already carries its namespace and is
serializable jsonb — add the pool id. Shard at 10-20k pods/cluster for headroom. Mandatory
companion: §7 informer provisioning.

**Path B — M2 MicroVM worker-fleet (the Modal-shaped target):** PLAN §7 M2's designed-not-started
provider maps onto Modal's worker model *more naturally than k8s does*: `RunMicrovm` is
fast-notification (no poll loop by construction); the worker accepts/rejects on local resources
(the worker IS its own source of truth); the 8-hour lease + idle-suspend/resume gives snapshot-only
billing for idle minutes-scale sessions — decisive at 100k mostly-idle agents; and M2's S3
workspace store is the SAME deliverable that unblocks control-plane multi-replica (the RWO PVC).
One roadmap item, two epics served.

**Image distribution:** digest-pinned runner images, `imagePullPolicy: IfNotPresent`, per-region
pull-through mirror, optional pre-pull DaemonSet (the k8s design already lists it as post-v1) —
mass-start on cold nodes otherwise stampedes the registry.

**The line that keeps this honest:** Neon + LISTEN/NOTIFY + §8 flattening carries to **~10k
concurrent with no new infrastructure**. A stream store (Redis Streams / NATS) for worker-state
publish — Modal's Redis — is a **new, deliberate stack decision** to be made on observed 10k data,
never adopted speculatively. Until then the `CapacitySource` seam is the firewall that keeps
today's code compatible with that future.

## §10 Config, chart, doctor, observability

| Env | Default | Meaning |
|---|---|---|
| `FLUIDBOX_CAPACITY_GLOBAL_MAX_ACTIVE` | unset = unlimited | deployment-wide active-run ceiling (global counter row) |
| `FLUIDBOX_CAPACITY_TENANT_MAX_ACTIVE` | unset = unlimited | default per-tenant cap (per-tenant override via `tenant_capacity` row) |
| `FLUIDBOX_CAPACITY_TENANT_QUEUE_DEPTH` | unset = unlimited | per-tenant max queued |
| `FLUIDBOX_QUEUE_TTL_SECS` | 900 | max queue wait before `queue_ttl_expired` |
| `FLUIDBOX_DISPATCH_TICK_SECS` | 1 | dispatcher poll floor |
| `FLUIDBOX_DISPATCH_MAX_CONCURRENT_PROVISIONS` | 8 | per-replica provision semaphore |
| `FLUIDBOX_DISPATCH_MAX_STARTS_PER_SEC` | 10 | per-replica start pacer |
| `FLUIDBOX_LAUNCH_MAX_ATTEMPTS` | 5 | capacity-requeue attempt cap |
| `FLUIDBOX_LAUNCH_REQUEUE_BACKOFF_SECS` | 5 | exponential requeue backoff base |

**Unset caps = today's behavior, exactly** — that property is what makes the rollout safe and the
first phase inert. The chart, by contrast, SETS them: `capacity.globalMaxActive` defaults to the
tier's `quota.pods`, so k8s installs get queue-instead-of-403 out of the box; the
`values.yaml:256-263` comment ("no application-side counter … REJECTS rather than queues") is
updated to name this design as its replacement. `just doctor`/`k8s-doctor` warn on
quota-enabled-but-cap-unset and on cap > `quota.pods`.

**Metrics** (bounded cardinality — NO per-tenant labels; per-tenant occupancy/depth is an admin
API/DB question): counters `runs_queued_total`, `queue_admissions_total`, `queue_ttl_expired_total`,
`launch_requeues_total`, `capacity_rejections_total{reason}`; histogram `queue_wait_ms`
(`queued_at→provisioning`, sibling of `run_provisioning_ms`); live gauge `queue_depth`
(deployment-wide). Plus, ahead of the validation rungs: in-flight-provisions gauge, heartbeat-flush
size/latency, NOTIFY/s, dispatcher dequeue latency + claimed/skipped counts, watchdog scan
rows/duration.

**Timeline events** (`EventBody`): `RunQueued{reason}`, `RunAdmitted`, `RunRequeued{attempt}`,
`RunQueueExpired`. **Dashboard**: a `queued` status chip (presentation-only; the status string is
already surfaced).

## §11 Migration and rollout

- Migration = next free number at implementation time (0026 is taken by the unmerged
  `feat/db-native-policies`). Contents: §2 DDL. Down-safe (nullable/defaulted columns + additive
  table).
- **Migrate-then-deploy, mixed fleet verified safe:** an old binary never produces or drains
  `queued` (born `created`; no cap check — it over-admits, which is temporary and self-correcting);
  `SessionStatus::parse("queued") → None → unwrap_or(Failed)` + the terminal-source transition
  refusal make any accidental old-binary write a no-op; the old watchdog's status filter enumerates
  `created/provisioning/initializing` and ignores `queued`.
- **Rollback caveat (document loudly):** rolling back to an all-old fleet orphans queued rows (no
  dispatcher, and the old sweep ignores them). Drain the queue first, or accept manual cleanup.

## §12 Convergence-invariant cross-check (PLAN §2 + house invariants)

- **Definition ≠ run; no persistent privileged agent servers:** untouched — queueing delays fresh
  disposable sandboxes; warm pools stay out.
- **RunSpec frozen at creation:** untouched — placement/queue state lives on the session row,
  never in the spec; `create_session` is byte-identical.
- **Server is the single status writer:** strengthened — the new edges ride the same
  `transition`/`transition_fenced` funnel; the dispatcher is fenced by the 0021 lease/epoch.
- **Tenant isolation (signature + RLS floor):** `tenant_capacity` carries the trio; cross-tenant
  writes are named bypass entry points; the queued partial index leads with `tenant_id`.
- **Exactly-once invocation claims:** the claim-binding transaction is unmodified; admission is
  strictly after it.
- **Ledger accepts only `Redacted<…>`:** queue events go through `ledger::record` like every other;
  future append-batching batches post-scrub values.
- **Approvals/locks:** the lock-order pairs (approvals→sessions; sessions→claims/reservations) gain
  no new edges — capacity claims touch `tenant_capacity` only, after the session row in the
  release path (sessions→capacity, a new leaf; no cycle).
- **Autonomous ≠ ungoverned:** budgets/containment unaffected; queue wait burns no budget.

## §13 Implementation sequence (each phase lands green: `just check` + relevant e2e)

- **P1 — state + plumbing, inert (L).** `Queued` + edges + core tests; the migration;
  `tenant_capacity` DB entry points; `dispatcher.rs` + `fluidbox_dispatch` listener + fair-dequeue
  SQL + semaphore/pacer; the `run()` → `drive_from_provisioning` split. Caps unset ⇒ zero behavior
  change; the phase's e2e sets a cap and watches queue + drain.
- **P2 — admission on (L).** `try_admit`/release wired into `create_run` + `transition_inner`;
  depth caps + the four entry-point mappings (+ `ApiError::TooManyRequests`); TTL sweep; reconcile
  sweep; timeline events.
- **P3 — capacity requeue (M).** `CapacityExhausted` + k8s 403 classification; requeue with
  backoff + attempt cap; e2e drives a quota-constrained namespace and watches 403→requeue→run.
- **P4 — recovery + polish (M).** Lease-expiry re-drive (the orphan fix, with the deliberate-kill
  e2e); metrics + dashboard chip; chart tier wiring + doctor checks.
- **Then, as separate epics:** §7 informer provisioning; §8 flattening (heartbeat first); §9 pools.

**Validation ladder** (extends rollout-gates Gate 3; a rung closes on owner sign-off, never on a
green suite alone):
1. **300 real** — the 60/150/300 exercises actually executed, real sandboxes: provisioning p95
   shows no upward trend; DB pool never sustains 100%, zero acquire timeouts; zero orphans.
2. **1k mixed** — mostly loadgen-seeded sessions (heartbeat/event/SSE load) + a real slice:
   flattening holds (heartbeat tx/s flat vs N); no fairness starvation under a saturating tenant.
3. **10k placement-sim** — a **fake `ExecutionProvider`** (must be built; the existing loadgen
   fakes an MCP upstream, not a provider) modeling provision latency + `CapacityExhausted`:
   dispatcher/semaphore/requeue proven at zero sandbox cost; O(sandboxes) DB load proven flat.

## Open questions (for review)

1. Reserve a `priority` column on sessions now (cheap) vs. add it with the priority feature
   (avoids speculative schema)? Default recommendation: add later; the queued partial index is
   unaffected.
2. Per-tenant cap admin surface in v1: env-default only, or `/v1/admin/orgs/{slug}/capacity`
   endpoints writing `tenant_capacity`? (Leaning endpoints in P2 — the rows exist anyway.)
3. Does the lease-expiry re-drive (P4) move into P1 to close the orphan gap earlier, at the cost
   of P1 size?
4. Reconcile sweep interval, and whether to emit a deployment-wide `capacity_drift` gauge
   (observability for the counter-vs-truth delta).
5. Webhook behavior under *sustained* exhaustion: 503-retry heals only within the provider's retry
   window; is a dead-letter row (visible, replayable) worth building, or is generous depth + TTL
   enough for v1?

## Risks and trade-offs

- **Counter drift** starves a tenant until the reconcile sweep heals it — bounded by the interval;
  reservation-rows are the named fallback.
- **The `run()` refactor** (`drive_from_provisioning`) is the highest-care change in P1: every
  ownership/attach fence must survive verbatim, and resume-from-provisioning must be idempotent.
  Guard: the existing failure-path e2e + a deliberate mid-launch kill test.
- **Double-provision on re-drive** is fence-contained (the loser pod self-terminates) — wasteful,
  never unsafe, bounded by `launch_attempts`.
- **Global-row bypass friction:** the cross-tenant global counter forces bypass writes; the
  discipline is a short, named, grep-able entry-point set — reviewers should hold that line.
- **Mixed-fleet over-admission** during rollout is temporary and self-correcting; the rollback
  caveat is documented above.
- **Dispatcher herd** on release storms: NOTIFY-driven wakeups + jitter + claimed-0 backoff +
  the pacer bound it; loadgen rung 2 verifies.
- **Sustained-exhaustion webhook drops** (open question 5).

## Acceptance statement

This design is accepted when: (1) the four phases land green under the working agreement with caps
inert by default; (2) a capped deployment queues instead of failing at quota, drains FIFO-fairly,
and survives replica kill mid-launch with a ~tick-scale re-drive; (3) rung 1 of the validation
ladder (the real 60/150/300) passes its Gate-3 criteria; and (4) the 10k placement-sim demonstrates
the dispatcher and capacity planes hold with flat per-run DB cost — at which point the stream-store
decision for 100k is made on data, exactly as §9 prescribes.
