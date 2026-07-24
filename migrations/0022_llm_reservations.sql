-- Phase E (#33) — durable request-keyed LLM budget reservations
-- (Gap 14; design :1098-1126, :1367-1376; plan .superpowers/sdd/phase-e-plan.md E13).
--
-- WHY
-- The facade CHECKED accumulated usage before forwarding and RECORDED usage only
-- after completion (`usage_totals` → forward → `add_usage`). Nothing was held in
-- between, so N concurrent requests all read the same remaining budget and all
-- passed it — and agent harnesses issue parallel model calls by design (subagents),
-- so serializing per session is explicitly REFUSED as the fix (design :1113-1115).
-- This table is the durable, request-ID-keyed reservation that closes the race
-- instead: a conservative maximum is booked ATOMICALLY before the request is
-- forwarded, concurrent admissions see each other's bookings, and a finite ceiling
-- bounds how many can be outstanding at once.
--
-- THE PRIMARY KEY IS THE REQUEST ID. `id` is minted per facade request and becomes
-- `usage_entries.external_id` at reconcile time, so the existing partial-unique
-- index `usage_external` (0001:160) makes the charge idempotent: the drain task's
-- authoritative usage row and the sweeper's conservative timeout row are the SAME
-- key, and whichever arrives second is an `on conflict do nothing` no-op. That is
-- what makes a late drain and the expiry sweep safe in EITHER order.
--
-- THREE STATES, and the arrows are one-way:
--   reserved — booked, request in flight (or its process died → swept at expiry).
--              Counted IN FULL by every subsequent admission and by the budget
--              sweeper's projection.
--   charged  — settled. Either the drain reported authoritative usage (recorded
--              under `external_id = id`, then this CAS) or the sweeper converted
--              the reservation into a conservative `usage_entries` row
--              (`source='reservation_timeout'`). Spend now lives in usage_entries.
--   released — POSITIVELY-PROVEN non-dispatch only (a pre-send refusal, or an
--              upstream 401 — which the facade already treats as proof the request
--              never executed). NEVER on "we could not parse usage": design :1122
--              says retain the conservative charge, never assume zero.
--
-- ACTIVE = `state = 'reserved'`, with NO expiry predicate. Deliberate: dropping an
-- expired-but-unswept row from the sum would open an unbudgeted window between
-- expiry and the sweep. A reservation stops counting as a reservation at exactly
-- the moment it starts counting as usage.
--
-- RLS (migration 0018's rule for a NEW tenant-owned table — 0018 already ran, so
-- its drift guard cannot see this table; the triple lives HERE): ENABLE + FORCE
-- RLS, a child-EXISTS `tenant_isolation` policy composing the parent `sessions`
-- policy (0018 section (c) shape), and an ENUMERATED DML grant to the deployment's
-- runtime role resolved from `current_setting('fluidbox.runtime_role')` (never
-- hardcoded). The row also carries `tenant_id` + a COMPOSITE FK into
-- `sessions (tenant_id, id)` (0012's `sessions_tenant_id_id_key` target; the 0013
-- and 0019 precedent) so a reservation can never point at another tenant's session.

set local lock_timeout = '5s';

create table llm_reservations (
    -- NOT defaulted: the server mints this id BEFORE the insert because the same
    -- value has to key the usage row at reconcile time.
    id uuid primary key,
    tenant_id uuid not null references tenants(id),
    session_id uuid not null,
    -- The frozen RunSpec model, carried so the sweeper's conservative
    -- `usage_entries` row is attributable in the cost report.
    model text not null,
    -- Conservative maximum: declared max output tokens + an input approximation.
    -- One bucket on purpose — the token budget sums all four usage columns, so the
    -- split only matters for display.
    reserved_tokens bigint not null,
    -- NULL when the model is not in the price table (`estimate_cost_usd` → None):
    -- the COST arm of admission then cannot bind for this request, exactly as the
    -- pre-existing cost budget already degrades for unpriced models. The TOKEN arm
    -- still binds.
    reserved_cost_usd double precision,
    state text not null check (state in ('reserved', 'charged', 'released')),
    created_at timestamptz not null default now(),
    -- Must comfortably exceed the facade's upstream request timeout (15 min,
    -- main.rs) — see `RESERVATION_TTL_SECS` in facade.rs. A shorter TTL would let
    -- the sweeper conservatively charge a request that is still legitimately in
    -- flight, and the `external_id` conflict would then make that over-charge
    -- STICK against the real usage that arrives later.
    expires_at timestamptz not null,
    foreign key (tenant_id, session_id) references sessions (tenant_id, id) on delete cascade
);

-- Admission reads `sum/count(*) … where session_id = $ and state = 'reserved'` on
-- the hot path of every model request; this partial index keeps that a small index
-- scan over only the live rows.
create index llm_reservations_active
    on llm_reservations (session_id)
    where state = 'reserved';

-- The expiry sweep scans only `reserved` rows past their expiry, ordered by
-- expires_at; a partial index keeps it cheap without indexing the settled rows.
create index llm_reservations_sweep
    on llm_reservations (expires_at)
    where state = 'reserved';

-- ─── RLS triple (0018 rule for a new tenant-owned table) ────────────────────
alter table llm_reservations enable row level security;
alter table llm_reservations force row level security;
-- Child-EXISTS: no tenant_id predicate in the policy itself — the parent
-- `sessions` policy composes through the subquery (it runs under RLS too), so a
-- reservation is visible/writable iff its session is, and the system_worker bypass
-- opens the parent (and thus the child) for the cross-tenant expiry sweep.
create policy tenant_isolation on llm_reservations as permissive for all to public
    using (exists (select 1 from sessions p where p.id = llm_reservations.session_id))
    with check (exists (select 1 from sessions p where p.id = llm_reservations.session_id));

-- Enumerated DML grant to the deployment's runtime role (resolved from the session
-- GUC `fluidbox.runtime_role`, default `fluidbox_runtime` — NEVER hardcoded; a
-- shared-cluster deployment picks its own name). Copied verbatim from 0018 (e).
do $$
declare
    v_role text := coalesce(nullif(current_setting('fluidbox.runtime_role', true), ''),
                            'fluidbox_runtime');
begin
    if exists (select 1 from pg_roles where rolname = v_role) then
        execute format('grant select, insert, update, delete on table llm_reservations to %I', v_role);
    end if;
end $$;
