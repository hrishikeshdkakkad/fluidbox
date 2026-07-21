-- Phase E (#33) — durable four-state execution claims around brokered dispatch
-- (Gap 11; design :924-987, :1331-1343; plan .superpowers/sdd/phase-e-plan.md E10).
--
-- WHY
-- A brokered tool call executes CONTROL-PLANE-SIDE (broker.rs turns the sealed
-- credential and POSTs the upstream MCP server). Two things were unfenced:
--   1. a run cancelled/budget-terminated DURING a minutes-long approval wait would
--      still dispatch (the approval said "allow"; nothing re-checked terminality);
--   2. two concurrent `/tools/call` for one tool_call_id (a runner retry across a
--      crash/timeout) both faithful-retry to `auto_allowed` and both POST upstream.
-- This table is the durable claim that closes both: exactly ONE dispatch per
-- (session, tool_call_id, input_digest), taken under the SAME sessions-row lock
-- order as cancellation (`transition_session`/`begin_finalization`), refused once
-- the session stops accepting work, and carrying the settled outcome so a
-- duplicate ADOPTS it instead of re-sending.
--
-- FOUR + one states (design :931-934). The claim is a state machine DISTINCT from
-- the approval verdict (which stays immutable):
--   claimed            — a dispatch is in flight (or crashed mid-flight → swept).
--   succeeded          — definitive upstream result, not an error.
--   failed_upstream    — definitive upstream error (HTTP error status, JSON-RPC
--                        error object, or an MCP isError result). TERMINAL.
--   failed_before_send — POSITIVE proof no request was written (URL admission,
--                        auth resolution, binding recheck, breaker-open, or a
--                        reqwest connect error). The ONLY re-claimable state.
--   ambiguous          — sent, outcome unknown (timeout / mid-stream decode /
--                        post-connect redirect refusal), OR a `claimed` row swept
--                        past its expiry. NEVER auto-retried (invariant 15).
--
-- `result_content` (capped jsonb) + `is_error` let a duplicate re-request return
-- the ORIGINAL runner-facing result verbatim; `result_digest`/`error_message` feed
-- the ledger (digest-only — no payloads, no secrets).
--
-- RLS (migration 0018 rule for a NEW tenant-owned table — 0018 already ran, so its
-- drift guard cannot see this table; the triple lives HERE): ENABLE + FORCE RLS, a
-- child-EXISTS `tenant_isolation` policy composing the parent `sessions` policy
-- (0018 section (c) shape), and an ENUMERATED DML grant to the deployment's runtime
-- role resolved from `current_setting('fluidbox.runtime_role')` (never hardcoded).
-- The row also carries `tenant_id` + a COMPOSITE FK into `sessions (tenant_id, id)`
-- (the 0012 `sessions_tenant_id_id_key` unique target; the 0013 binding precedent)
-- so a claim can never point at another tenant's session.

set local lock_timeout = '5s';

create table tool_execution_claims (
    id uuid primary key default gen_random_uuid(),
    tenant_id uuid not null references tenants(id),
    session_id uuid not null,
    tool_call_id text not null,
    -- Binds the claim to the EXACT arguments the intent registered (the gate's
    -- `digest_json`), so a reused tool_call_id with different content is a new
    -- claim, never an adoption of the old one.
    input_digest text not null,
    state text not null check (state in
        ('claimed', 'succeeded', 'failed_upstream', 'failed_before_send', 'ambiguous')),
    -- Bumped only when a `failed_before_send` row is re-claimed (the one path that
    -- re-dispatches the same claim row).
    attempt int not null default 1,
    claimed_at timestamptz not null default now(),
    claim_expires_at timestamptz not null,
    completed_at timestamptz,
    result_digest text,
    is_error boolean,
    result_content jsonb,
    error_message text,
    unique (session_id, tool_call_id, input_digest),
    -- Composite tenant FK: the claim's session must belong to the same tenant.
    foreign key (tenant_id, session_id) references sessions (tenant_id, id) on delete cascade
);

-- The stale-claim sweep scans only `claimed` rows past their expiry; a partial
-- index keeps it cheap without indexing the terminal rows.
create index tool_execution_claims_sweep
    on tool_execution_claims (state, claim_expires_at)
    where state = 'claimed';

-- ─── RLS triple (0018 rule for a new tenant-owned table) ────────────────────
alter table tool_execution_claims enable row level security;
alter table tool_execution_claims force row level security;
-- Child-EXISTS: no tenant_id predicate in the policy itself — the parent
-- `sessions` policy composes through the subquery (it runs under RLS too), so a
-- claim is visible/writable iff its session is, and the system_worker bypass opens
-- the parent (and thus the child) for the cross-tenant sweep. (0018 section (c).)
create policy tenant_isolation on tool_execution_claims as permissive for all to public
    using (exists (select 1 from sessions p where p.id = tool_execution_claims.session_id))
    with check (exists (select 1 from sessions p where p.id = tool_execution_claims.session_id));

-- Enumerated DML grant to the deployment's runtime role (resolved from the session
-- GUC `fluidbox.runtime_role`, default `fluidbox_runtime` — NEVER hardcoded; a
-- shared-cluster deployment picks its own name). Copied verbatim from 0018 (e).
do $$
declare
    v_role text := coalesce(nullif(current_setting('fluidbox.runtime_role', true), ''),
                            'fluidbox_runtime');
begin
    if exists (select 1 from pg_roles where rolname = v_role) then
        execute format('grant select, insert, update, delete on table tool_execution_claims to %I', v_role);
    end if;
end $$;
