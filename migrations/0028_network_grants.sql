-- Governed sandbox network access: the durable grant record.
--
-- The grant ITSELF is frozen in `sessions.run_spec` and is immutable. This table
-- holds what the RunSpec cannot: the grant's mutable LIFECYCLE (pending →
-- active → revoked/denied), which is what the authorization pause, the
-- orchestrator's pre-provisioning re-check, and revocation all CAS against.
--
-- ROLLOUT DISCIPLINE — deploy everywhere FIRST, then enable. `SessionRow::
-- status_enum` maps an unrecognized status to `Failed`, so a binary that
-- predates `awaiting_authorization` reads a parked session as TERMINAL and
-- would reap its way through the pause. Same discipline migration 0018 needed:
-- roll the binary to every replica before any policy grants a mode above
-- `offline`. The migration itself is additive and safe to apply early.

create table session_network_grants (
    id uuid primary key,
    tenant_id uuid not null references tenants (id),
    session_id uuid not null,
    -- One grant per session: a session IS an epoch, and an epoch has exactly one
    -- network authority. (The follow-on continuation effort keys on epoch, not
    -- session, and will widen this key rather than reinterpret it.)
    unique (session_id),

    mode text not null check (mode in ('offline', 'approved', 'public')),
    -- The full frozen `NetworkGrant`, byte-identical to `run_spec.network`. Kept
    -- here too so the enforcement and revocation paths never have to parse a
    -- whole RunSpec to learn what to program or tear down.
    grant_doc jsonb not null,
    -- The consent anchor: `approvals.input_digest` equals this for a parked
    -- grant, so what a human authorized is provably what gets activated.
    grant_digest text not null,
    -- Digest of the `network:` policy section that produced the grant. A policy
    -- edit between freeze and decision is therefore DETECTABLE — the decision
    -- path re-resolves and refuses rather than silently activating stale
    -- authority.
    policy_digest text not null,

    status text not null check (status in ('pending', 'active', 'denied', 'revoked')),
    -- Absolute, and null only for `offline` (which has no authority to lapse).
    -- Validated at resolution to outlive the run's wall clock, so it never
    -- fires mid-run.
    expires_at timestamptz,
    -- The `approvals` row gating this grant, when parked. Null for a grant that
    -- needed no human.
    approval_id uuid,

    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now(),
    activated_at timestamptz,
    revoked_at timestamptz,
    -- Why it left `pending`/`active` — enumerated denial codes from
    -- `network::DenialReason::code()`, or a revocation reason.
    status_reason text,

    -- Composite tenant FK: the grant's session must belong to the same tenant.
    foreign key (tenant_id, session_id) references sessions (tenant_id, id) on delete cascade
);

-- The gate worker scans parked grants; the expiry sweep scans live ones. Both
-- are partial so neither indexes the terminal rows they will never read.
create index session_network_grants_pending
    on session_network_grants (created_at)
    where status = 'pending';

create index session_network_grants_expiry
    on session_network_grants (expires_at)
    where status = 'active';

-- ─── RLS triple (0018 rule for a new tenant-owned table) ────────────────────
alter table session_network_grants enable row level security;
alter table session_network_grants force row level security;
-- Child-EXISTS: no tenant_id predicate in the policy itself — the parent
-- `sessions` policy composes through the subquery (it runs under RLS too), so a
-- grant is visible/writable iff its session is, and the system_worker bypass
-- opens the parent (and thus the child) for cross-tenant workers. (0018 (c).)
create policy tenant_isolation on session_network_grants as permissive for all to public
    using (exists (select 1 from sessions p where p.id = session_network_grants.session_id))
    with check (exists (select 1 from sessions p where p.id = session_network_grants.session_id));

-- Enumerated DML grant to the deployment's runtime role (resolved from the session
-- GUC `fluidbox.runtime_role`, default `fluidbox_runtime` — NEVER hardcoded; a
-- shared-cluster deployment picks its own name). Copied verbatim from 0018 (e).
do $$
declare
    v_role text := coalesce(nullif(current_setting('fluidbox.runtime_role', true), ''),
                            'fluidbox_runtime');
begin
    if exists (select 1 from pg_roles where rolname = v_role) then
        execute format('grant select, insert, update, delete on table session_network_grants to %I', v_role);
    end if;
end $$;

-- ─── The declaration on the agent revision ──────────────────────────────────
--
-- What the agent DECLARES it needs (a `NetworkRequest`). Policy caps it; a
-- subscription or per-run override may only narrow it. Without a declaration
-- here every scheduled and webhook-triggered run would be offline-only, because
-- a schedule has no caller to pass a request.
--
-- A column-add on an existing tenant-owned table needs no new RLS — the table's
-- policy already binds every row (migration 0021 proves the pattern).
alter table agent_revisions add column network jsonb;

comment on column agent_revisions.network is
    'Declared NetworkRequest (mode + targets + duration). Null = offline.';
