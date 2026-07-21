-- Phase E (#33) — multi-replica coordination: per-session orchestrator lease +
-- epoch fencing token, delivery row claims, and the post-approval-wait
-- single-emission marker (Gap 13; design :1049-1097, :1357-1366; plan E12).
--
-- WHY
-- "Two or three stateless replicas" needs every piece of process-local lifecycle
-- state either DB-authoritative or explicitly coordinated (design :1049-1055).
-- Three things were unfenced:
--   1. the orchestrator/finalizer driver had a session-scoped, TIME-only
--      finalization claim (0011) with no owner identity and no fencing token — a
--      paused-then-resumed driver could still mutate a session another replica had
--      taken over (design :1067-1078);
--   2. the delivery worker polled due rows with no claim at all, so two replicas
--      attempted the SAME delivery concurrently (design :1079-1084);
--   3. the post-approval-wait terminality deny (0019's Task-4 slice) is computed by
--      EVERY awakened waiter, so two handlers re-attached to one approvals row
--      would both ledger it.
--
-- WHAT
-- (a) `sessions` gains `orchestrator_owner_id` / `orchestrator_lease_until` /
--     `orchestrator_epoch`. The lease is TIME-BASED and takeover-able, exactly like
--     0011's `claim_finalization` — deliberately NOT a Postgres advisory lock,
--     which the design REJECTS for this purpose (design :1067-1072: tied to one
--     connection, fragile under pool reconnects and Neon scale-to-zero, poorly
--     observable). `orchestrator_epoch` increments ONLY on an owner CHANGE (a
--     renew by the same owner keeps it), so it is a monotonic fencing token: every
--     driver lifecycle mutation carries the epoch it acquired and a stale driver's
--     UPDATE matches zero rows. The k8s UID-preconditioned delete stays as the
--     PROVIDER-scope fence beneath it.
-- (b) `result_deliveries` gains `claimed_by` / `claimed_until` so the poll becomes
--     a claim-in-one-tx (`for update skip locked` + stamp) and two replicas take
--     DISJOINT row sets. The claim fences the ATTEMPT; the crash window between a
--     remote create and recording its external id is closed separately, in
--     `connectors/github.rs`, by reconcile-before-create against a deterministic
--     per-subscription comment marker (design :1082-1084).
-- (c) `approvals` gains `terminal_deny_at` — the single-emission marker for the
--     post-wait terminality deny. It is NOT a verdict column (the verdict stays
--     immutable in `status`): it records that the deny was LEDGERED once.
--
-- NO NEW RLS OBJECTS — VERIFIED, not assumed. All three are column-adds on tables
-- migration 0018 already protects, and 0018's policies are COLUMN-AGNOSTIC:
--   * `sessions` is a section-(b) standard tenant table: its `tenant_isolation`
--     policy is `tenant_id::text = current_setting('fluidbox.tenant_id', true) or
--     bypass` (0018:164-181) — it names one column, `tenant_id`, which is unchanged.
--   * `result_deliveries` and `approvals` are section-(c) CHILD tables: their
--     policies are `exists (select 1 from sessions p where p.id = <child>.session_id)`
--     (0018:194-199, 0018:210-215) — they name only the FK, also unchanged.
--   * The 0018 grants are TABLE-level, not column-level (0018:439-441
--     `grant select, insert, update, delete on table %I`), so a new column on an
--     already-granted table is reachable by the runtime role with no new grant, and
--     0018's drift guard (which keys on tables carrying our policies) sees no new
--     table. This migration therefore adds no policy and no grant, by construction.
--
-- DEPLOY ORDER: safe in EITHER order (unlike 0018). Every column is nullable or
-- defaulted, and a pre-0021 binary simply never reads or writes them: it keeps the
-- pre-lease behavior (one process, no epoch) while a post-0021 binary fences only
-- against other post-0021 binaries. During a rolling deploy the mixed window is
-- exactly today's behavior for the old replicas, so migrate-then-deploy needs no
-- downtime and rolling back the binary needs no down-migration.

set local lock_timeout = '5s';

-- ─── (a) per-session orchestrator lease + epoch fencing token ───────────────
alter table sessions
    -- The replica that currently drives this session. A process-wide UUID minted
    -- at boot (orchestrator::replica_id) — identity only, never a credential.
    add column orchestrator_owner_id uuid,
    -- Lease deadline. Past it any replica may steal (the takeover discipline of
    -- 0011's claim_finalization, which this generalizes to the whole lifecycle).
    add column orchestrator_lease_until timestamptz,
    -- Monotonic fencing token. Bumped ONLY when the owner changes; a renew by the
    -- same owner keeps it, so a healthy driver's fence never moves under it.
    add column orchestrator_epoch bigint not null default 0;

-- The lease is always read by primary key (drive/spawn paths resolve the session
-- first), so no index is added for acquisition. This partial index serves the
-- operational question "which sessions does replica X currently hold" and keeps
-- expired-lease scans cheap without indexing the vast majority of rows (which
-- have never had a lease).
create index sessions_orchestrator_lease
    on sessions (orchestrator_owner_id, orchestrator_lease_until)
    where orchestrator_owner_id is not null;

-- ─── (b) delivery row claims ────────────────────────────────────────────────
alter table result_deliveries
    add column claimed_by uuid,
    add column claimed_until timestamptz;

-- The claim scan is `status='pending' and next_attempt_at <= now() and (claim free
-- or mine)` ordered by next_attempt_at. 0003's `result_deliveries_due` partial
-- index already covers the (status, next_attempt_at) selection; this one lets the
-- claim predicate discard rows another replica holds without a heap visit.
create index result_deliveries_claim
    on result_deliveries (claimed_until)
    where status = 'pending';

-- ─── (c) post-approval-wait terminality-deny single-emission marker ─────────
-- NOT a verdict: `status` keeps the immutable decision. This records that the
-- "session went terminal DURING the approval wait" deny was already ledgered, so
-- exactly one of N re-attached waiters emits its `tool.decision`.
alter table approvals
    add column terminal_deny_at timestamptz;
