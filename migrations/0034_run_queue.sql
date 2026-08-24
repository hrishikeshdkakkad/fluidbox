-- Run admission & queueing (design 2026-08-23): the park-and-dispatch columns.
--
-- The queue IS the sessions table: a run's queue entry and its audit record are
-- the same row, claimed via the 0021 orchestrator lease. No new table, so the
-- 0018 RLS posture (ENABLE+FORCE, tenant policy, enumerated table-level grants)
-- already covers everything here — the drift guard does not fire on column
-- additions to an already-enumerated table.
--
-- ROLLOUT DISCIPLINE — deploy everywhere FIRST, then enable (the 0028 rule).
-- `SessionStatus::parse` maps an unrecognized status to `Failed` at the
-- transition sites, so a binary that predates `queued` reads a parked run as
-- TERMINAL: it will not drive it and its API reports it failed. (The boot
-- orphan sweep's STRICT parse deliberately leaves unknown statuses alone, so
-- nothing is destroyed — the failure mode of a premature rollback is zombie
-- queued rows, not lost state.) Roll the binary to every replica before setting
-- FLUIDBOX_MAX_CONCURRENT_RUNS anywhere. The migration itself is additive and
-- safe to apply early; with the env unset the columns are simply never written.

alter table sessions
    -- First entry into `queued` (coalesce-stamped like started_at). The age
    -- bound (FLUIDBOX_QUEUE_MAX_WAIT_SECS) measures from here, NOT created_at,
    -- so a run that spent days in awaiting_authorization is not expired the
    -- moment it becomes dispatchable.
    add column queued_at timestamptz,
    -- First entry into `provisioning` (coalesce-stamped). The stale-launch
    -- watchdog measures provisioning/initializing age from
    -- coalesce(launched_at, created_at): fixes the latent 0028 bug where a run
    -- released from a >30-minute authorization pause is killed by the watchdog
    -- as "stalled before launch" (design §3.10), and gives queued runs the
    -- same protection.
    add column launched_at timestamptz,
    -- Not-before gate for redispatch after a provider CapacityDenied bounce
    -- (exponential backoff, floor 30s >= the lease TTL, cap 300s). NULL = no gate.
    add column dispatch_after timestamptz,
    -- Dispatch attempts (the claim increments it). Bounded by
    -- FLUIDBOX_QUEUE_REQUEUE_MAX; exceeding it is a terminal, explained failure.
    add column dispatch_attempts int not null default 0;

-- The dispatch scan's hot path: oldest-first over ONLY the queued rows, so the
-- audit-retained terminal mass (never pruned — sessions is the audit record)
-- costs the dispatcher nothing.
create index sessions_queued_dispatch
    on sessions (created_at)
    where status = 'queued';
