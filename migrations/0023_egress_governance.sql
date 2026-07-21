-- Phase F (Task 1) — CROSS-REPLICA outbound egress governance: durable per-minute
-- rate windows and a durable circuit breaker.
--
-- WHY
-- Phase E's `EgressGovernor` (crates/fluidbox-server/src/governor.rs) is entirely
-- in-memory and REPLICA-LOCAL, and said so: "with N replicas the effective ceiling
-- is N × the configured rate and a breaker opened on one replica does not stop the
-- others" (governor.rs:40-47). That is a fairness/abuse control that quietly stops
-- being one the moment the deployment scales past a single pod. These two tables
-- are the durable tier that closes it.
--
-- TWO TIERS, NOT A REPLACEMENT. The in-memory governor is unchanged and is still
-- consulted FIRST — it is free, it catches a runaway loop with zero DB load, and it
-- keeps its token-bucket smoothing. A dial must pass the local tier AND this one.
-- The durable tier DEGRADES: if these statements error (DB down, timeout), the
-- server logs, counts it, and admits on the local verdict alone. A rate limiter is
-- an abuse/fairness control, not a quota system — and `0` already means "disable
-- that dimension", never "block everything".
--
-- ONE ROW PER KEY, NOT ONE ROW PER MINUTE. `egress_rate_windows` is keyed
-- (tenant_id, scope, subject) and carries the window it is counting; a dial in a
-- NEW minute RESETS `hits` to 1 rather than inserting a new row. So the table's
-- live size is "distinct keys currently dialing", not "distinct keys × minutes" —
-- the difference between a bounded working set and an append-only log. See the
-- sweeper note at the bottom for what bounds the residue.
--
-- THE WINDOW IS COMPUTED IN SQL (`date_trunc('minute', now())`). The in-memory
-- governor's clock is `Instant`, a per-process monotonic base that is meaningless
-- across replicas, so NOTHING derived from it (`last_ms`, `opened_ms`, `probe_ms`)
-- is persisted here. Every timestamp in these tables comes from the DATABASE clock,
-- which is the only clock all replicas share.
--
-- FIXED WINDOW vs TOKEN BUCKET (disclosed). A `date_trunc`'d minute is a FIXED
-- window, so across a boundary it can admit up to 2 × the per-minute ceiling within
-- one rolling 60-second span. The local token bucket cannot (governor.rs:105-111),
-- and it still binds per replica. This is the deliberate trade for a single-statement
-- take-then-check: a sliding window needs either per-request rows (unbounded growth)
-- or a second statement.
--
-- FOUR DURABLE DIMENSIONS: tenant, user, connection, (tenant, host_digest).
-- The cross-tenant `host_global` tier of the local governor is deliberately NOT
-- durable. It is the one dimension whose key spans tenants, so a durable version
-- would need a row no `fluidbox.tenant_id` GUC can match — i.e. a per-dial RLS
-- bypass on the hottest path in the broker. Trading a grep-able, audited bypass
-- inventory for a slightly tighter stampede ceiling is the wrong trade: the
-- disclosed N× looseness on ONE loose upstream-protection tier is cheaper than a
-- bypass that every future reader has to re-justify.
--
-- THE USER DIMENSION (new here) keys on `sessions.invoked_by_user_id`, which is
-- NULLABLE (migration 0012:260 — trigger and schedule invocations have no user).
-- A NULL user SKIPS the tier rather than bucketing every unattended run under the
-- nil uuid, which would make one shared bucket for all automation.
--
-- BREAKER PROBE ELECTION. `probe_epoch` is the durable analogue of the in-memory
-- breaker's per-breaker epoch (governor.rs:296-320): open → half_open is a CAS that
-- bumps the epoch and stamps `probe_owner`, so exactly ONE replica deployment-wide
-- is elected to probe, and a completion transitions the breaker only if it carries
-- the MATCHING epoch. Straggler completions are ignored in BOTH directions — a late
-- success must not close a breaker it knows nothing about, and a late failure must
-- not reopen a window the real probe was about to close.
--
-- RLS (migration 0018's rule for a NEW tenant-owned table — 0018 already ran and
-- its drift guard cannot see these, so the triple lives HERE): ENABLE + FORCE RLS,
-- a `tenant_isolation` policy, and an ENUMERATED DML grant to the deployment's
-- runtime role resolved from `current_setting('fluidbox.runtime_role')` — never
-- hardcoded. Both tables carry `tenant_id` DIRECTLY (they are not `sessions`
-- children), so the policy is 0018 section (b)'s own-`tenant_id` shape, not section
-- (c)'s parent-EXISTS shape.
--
-- DEPLOY ORDER: safe in EITHER order. A pre-0023 binary never reads or writes these
-- tables and keeps exactly today's per-replica behaviour; a post-0023 binary with
-- `FLUIDBOX_EGRESS_DURABLE=0` does the same. No down-migration is needed to roll a
-- binary back.

set local lock_timeout = '5s';

-- ─── Rate windows ───────────────────────────────────────────────────────────

create table egress_rate_windows (
    tenant_id uuid not null references tenants(id),
    -- 'tenant' | 'user' | 'connection' | 'host'. Deliberately text and NOT a
    -- check-constrained enum: adding a dimension must not need a migration, and an
    -- unknown scope is inert (the server only compares scopes it asked for).
    scope text not null,
    -- The dimension's key WITHIN the tenant: a uuid rendered as text for
    -- tenant/user/connection, and a DIGEST (`sha256:<16 hex>`) for host — the raw
    -- upstream hostname never lands in this table, matching the discipline that
    -- keeps it out of runner-facing error strings (governor.rs:177-195).
    subject text not null,
    -- The minute this row is counting, always `date_trunc('minute', now())` from
    -- the DATABASE clock. A dial in a later minute resets `hits` instead of
    -- inserting a row.
    window_start timestamptz not null,
    hits bigint not null,
    primary key (tenant_id, scope, subject)
);

-- The sweep deletes rows whose window is long past. Every sweep predicate LEADS
-- with `tenant_id` (the sweep is tenant-scoped so that it needs no RLS bypass), so
-- the index does too: on `(window_start)` alone a tenant's pass scanned every
-- tenant's expired rows and then filtered.
create index egress_rate_windows_sweep on egress_rate_windows (tenant_id, window_start);

-- ─── Circuit breakers ───────────────────────────────────────────────────────

create table egress_breakers (
    tenant_id uuid not null references tenants(id),
    -- The legacy credential-free brokered path has no connection id and passes the
    -- NIL uuid (broker.rs). That is exactly why `tenant_id` is part of the key:
    -- without it, every tenant's legacy traffic to one host would share ONE breaker
    -- and five failures from one tenant would refuse another's dials (the review-I5
    -- bug the in-memory key already fixed — governor.rs:407-414). No FK to
    -- `integration_connections`: the nil id has no row, and a deleted connection
    -- must not orphan-cascade a breaker mid-window. The sweeper collects the debris.
    connection_id uuid not null,
    host_digest text not null,
    state text not null check (state in ('closed', 'open', 'half_open')),
    -- CONSECUTIVE transport failures. Any healthy answer resets it to 0 — same rule
    -- as the in-memory breaker (governor.rs:284-286).
    failures int not null default 0,
    -- When the current open window started (NULL unless state = 'open').
    opened_at timestamptz,
    -- Monotonic and never reset WITHIN A ROW'S LIFETIME — not even when a probe
    -- closes the breaker. A completion may transition this breaker only if it
    -- carries this exact value, so reuse would let a stale completion decide a
    -- later window.
    --
    -- NOT globally unique, and the difference is worth stating: the sweeper deletes
    -- idle breakers, and the INSERT arm of the report statement re-seeds a fresh row
    -- at 0. (An earlier comment here claimed "NEVER reused, and never reset", which
    -- the sweep+re-insert path makes false.) What keeps that safe is the sweep
    -- predicate, not the counter: only a `closed` breaker with zero consecutive
    -- failures and no activity for the idle period is collectable, so a row with an
    -- outstanding probe (`half_open`) or an open window is never deleted. For a
    -- superseded completion to decide anything after a re-seed, its epoch would have
    -- to be re-reached by that many FRESH elections and the row would have to be
    -- half_open at that moment — a disclosed residual, not an eliminated one.
    probe_epoch bigint not null default 0,
    -- Which replica was elected to probe. INFORMATIONAL ONLY (logs, debugging):
    -- correctness rides entirely on `probe_epoch`, because a replica id can be
    -- reused by a restarted pod while an epoch cannot.
    probe_owner text,
    -- When the elected probe was admitted. Bounds a LOST probe: a replica that dies
    -- between admission and completion would otherwise wedge the breaker half-open
    -- forever, so after one open window the next caller is elected instead (with a
    -- fresh epoch, which is what makes the abandoned probe's late completion inert).
    probe_started_at timestamptz,
    updated_at timestamptz not null default now(),
    primary key (tenant_id, connection_id, host_digest)
);

-- The sweep collects only IDLE, INFORMATION-FREE breakers (closed with no
-- consecutive failures); a partial index keeps an open or degrading breaker out of
-- the scan entirely, so the sweep can never be the thing that forgets one. Leading
-- column `tenant_id` for the same reason as the rate index above: the sweep is
-- tenant-scoped and its predicate leads with it.
create index egress_breakers_sweep on egress_breakers (tenant_id, updated_at)
    where state = 'closed' and failures = 0;

-- ─── Bounded growth: what actually bounds these tables ──────────────────────
--
-- A rate-limit table must not grow forever, and "one row per key, reset per minute"
-- alone does not bound it: `host` subjects are attacker-cyclable (one connection can
-- name arbitrarily many upstream hosts across a run) and a deleted connection leaves
-- its rows behind. So the server sweeps, TENANT-SCOPED and BOUNDED, from the same
-- admission path that writes them (`governance::sweep`, at most once per replica per
-- sweep interval, `limit`-capped per pass, deleting only rows untouched for an idle
-- period). Tenant-scoped is deliberate: it needs no RLS bypass, and the tenants
-- generating rows are exactly the tenants paying to clean them.
--
-- WHAT ACTUALLY BOUNDS THE TABLE. The sweeper visits tenants on a deterministic
-- ROTATION over the tenants a replica is serving (`governor::sweep_batch`),
-- `SWEEP_TENANTS_PER_TICK` of them per tick. So for a replica serving T tenants a
-- given tenant is collected once per
--
--     SWEEP_INTERVAL_SECS × ceil(T / SWEEP_TENANTS_PER_TICK)
--
-- seconds, and its residue is bounded by "keys dialed within SWEEP_IDLE_SECS + that
-- period". That is what makes the bound a function of the CONFIGURED constants
-- rather than of luck. The first cut swept whichever tenant's dial happened to win
-- the once-per-interval CAS, which is O(replicas) of capacity against O(tenants) of
-- demand: with T tenants and R replicas a tenant was collected roughly once per
-- 300·T/R seconds, so past T > 12R the idle threshold never bound and the lottery
-- did — for a deployment at the design's 300-user / 1,500-connection scale, that is
-- the normal case, not a corner.
--
-- WHAT IT STILL DOES NOT BOUND (disclosed): a tenant that stops dialing ENTIRELY
-- leaves this replica's rotation set (the set is the local governor's tenant map),
-- so its last working set is frozen in place — finite and no longer growing, but not
-- collected until it dials again. A deployment-wide collector belongs in
-- `workers.rs` with the other system-worker sweeps.

-- ─── RLS triple (0018 rule for a new tenant-owned table) ────────────────────
alter table egress_rate_windows enable row level security;
alter table egress_rate_windows force row level security;
alter table egress_breakers enable row level security;
alter table egress_breakers force row level security;

-- 0018 section (b) shape: these tables carry `tenant_id` themselves, so the policy
-- keys on the GUC directly (no parent EXISTS). USING and WITH CHECK are the SAME
-- predicate, so a row is invisible to read AND refused on insert/update unless it
-- is in-tenant or the audited system-worker bypass is set.
create policy tenant_isolation on egress_rate_windows as permissive for all to public
    using (tenant_id::text = current_setting('fluidbox.tenant_id', true)
           or current_setting('fluidbox.bypass', true) = 'system_worker')
    with check (tenant_id::text = current_setting('fluidbox.tenant_id', true)
           or current_setting('fluidbox.bypass', true) = 'system_worker');

create policy tenant_isolation on egress_breakers as permissive for all to public
    using (tenant_id::text = current_setting('fluidbox.tenant_id', true)
           or current_setting('fluidbox.bypass', true) = 'system_worker')
    with check (tenant_id::text = current_setting('fluidbox.tenant_id', true)
           or current_setting('fluidbox.bypass', true) = 'system_worker');

-- Enumerated DML grant to the deployment's runtime role (resolved from the session
-- GUC `fluidbox.runtime_role`, default `fluidbox_runtime` — NEVER hardcoded; a
-- shared-cluster deployment picks its own name). Copied verbatim from 0018 (e),
-- via 0019/0022.
--
-- THE `if exists` IS LOAD-BEARING AND IT IS ALSO A TRAP. It is here because 0018
-- section (a) WARNS rather than fails when the role is absent — a managed host may
-- not let the migration role create roles, and refusing the migration would be the
-- worse outcome. The trap: if the role is created AFTERWARDS, this grant was
-- silently skipped, every `admit`/`report` answers `permission denied`, and the
-- server's (correct) degrade path converts that into admit-and-count. The
-- deployment then believes it has a cross-replica ceiling and has none.
--
-- Two things close it: the RAISE WARNING below makes the skip visible in the
-- migration output, and — because migration output scrolls past — the server runs a
-- BOOT USABILITY PROBE (`governance::preflight`, called once by
-- `EgressGovernor::check_durable`) that exercises select/insert/update/delete on
-- both tables as the role it actually runs as and logs at ERROR, once, with the
-- remediation, distinguishably from the per-dial degrade warning. Remediation is
-- exactly the two grants below, or re-running this migration's grant block.
do $$
declare
    v_role text := coalesce(nullif(current_setting('fluidbox.runtime_role', true), ''),
                            'fluidbox_runtime');
begin
    if exists (select 1 from pg_roles where rolname = v_role) then
        execute format('grant select, insert, update, delete on table egress_rate_windows to %I', v_role);
        execute format('grant select, insert, update, delete on table egress_breakers to %I', v_role);
    else
        raise warning 'egress governance: runtime role % does not exist, so the DML grants on egress_rate_windows / egress_breakers were SKIPPED. Create the role and re-run these two grants, or the durable (cross-replica) egress tier will degrade to per-replica limiting on every dial. The server logs this at boot too (governance::preflight).', v_role;
    end if;
end $$;
