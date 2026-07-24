-- Phase F (Task 3) — CROSS-REPLICA teardown of upstream MCP sessions.
--
-- WHY
-- Phase E's per-run MCP session manager keeps its `(run session, peer) → upstream
-- session` map in memory on `AppState` (crates/fluidbox-server/src/state.rs:57-59:
-- "Replica-local by design — Phase F owns cross-replica affinity"). The disclosed
-- consequence: if a run's brokered calls were made on replica A but the run is
-- FINALIZED on replica B, B drains an empty map, no `DELETE` is ever sent upstream,
-- and the upstream session leaks until A's process exits. There was no sweeper.
-- This table is the durable half that lets ANY replica tear down EVERY replica's
-- upstream sessions for a run.
--
-- PERSISTED FOR TEARDOWN, NOT FOR ADOPTION. A replica NEVER adopts another
-- replica's upstream session. Adoption would put two replicas on one upstream
-- session with no serialization, and force a JSON-RPC id-space change (the id
-- counter is a per-entry in-process `u64`, state.rs:88) — all to save an
-- `initialize` that MCP explicitly allows us to repeat. So the row is keyed by
-- OWNING REPLICA, every replica keeps initializing its own session exactly as
-- today, and the only cross-replica operation this table enables is the terminal
-- `DELETE`.
--
-- NO CREDENTIAL IS EVER STORED HERE. The teardown `DELETE` carries the same
-- authorization header a live call would, and that header is RE-RESOLVED LIVE at
-- teardown through `broker::terminal_peer_auth` (invariants 9 + 22:
-- broker.rs:1345-1358 — "Do not 'optimize' this into a stored header"). A row
-- carries only routing state: which endpoint, which upstream session id, which
-- negotiated protocol version. A revoked connection is precisely the case where we
-- must NOT send a credential, so a resolution failure still SKIPS the DELETE and
-- leaves the row for the sweeper to retire.
--
-- ONE ROW PER (run session, peer, owning replica). A sessionless upstream server —
-- one that issues no `Mcp-Session-Id` — gets NO ROW AT ALL: there is nothing to
-- DELETE, and a row would be a permanent sweep candidate that can never be
-- satisfied. Re-initialize (the 404-with-session path) UPDATES the row in place:
-- the old upstream session is provably dead (that is what the 404 meant), so
-- overwriting its id leaks nothing.
--
-- `deleted_at` IS THE TEARDOWN PROOF, and it is stamped only AFTER a `DELETE` was
-- actually attempted (or the sweeper retired the row) — never optimistically. That
-- makes the table the introspection seam the Phase E handover asked for
-- (follow-up #4): registry eviction was unassertable because an in-memory map has
-- no read surface. From SQL alone — and note it takes BOTH counts, because a run
-- that opened no upstream session at all also has zero undeleted rows:
--     select count(*) as opened,
--            count(*) filter (where deleted_at is null) as still_live
--       from mcp_upstream_sessions where session_id = '<run>';
--     -- opened > 0 and still_live = 0  ⇒  it opened sessions AND tore them all down
--     select peer_kind, peer_id, replica, upstream_session_id, delete_outcome
--       from mcp_upstream_sessions where session_id = '<run>';
--
-- `delete_outcome` is a DIAGNOSTIC, deliberately NOT check-constrained (0023's
-- reasoning): today `'deleted'` (a DELETE was attempted — best-effort, the upstream
-- reply is not required) and `'swept'` (retired by the deployment-wide GC without
-- an upstream DELETE). Adding a third must not need a migration, and an unknown
-- value is inert — nothing branches on it.
--
-- RLS (migration 0018's rule for a NEW tenant-owned table — 0018 already ran and
-- its drift guard cannot see this table, so the triple lives HERE): ENABLE + FORCE
-- RLS, a child-EXISTS `tenant_isolation` policy composing the parent `sessions`
-- policy (0018 section (c), the 0019/0022 shape), and an ENUMERATED DML grant to
-- the deployment's runtime role resolved from `current_setting('fluidbox.runtime_role')`
-- — never hardcoded. The row also carries `tenant_id` + a COMPOSITE FK into
-- `sessions (tenant_id, id)` (the 0012 `sessions_tenant_id_id_key` target) so a
-- teardown row can never point at another tenant's session.
--
-- DEPLOY ORDER: safe in EITHER order, and no down-migration is needed to roll a
-- binary back. A pre-0024 binary never reads or writes this table and keeps exactly
-- today's replica-local behaviour; a post-0024 binary against a pre-0024 database
-- fails its writes (logged, best-effort) and also degrades to replica-local.

set local lock_timeout = '5s';

create table mcp_upstream_sessions (
    id uuid primary key default gen_random_uuid(),
    tenant_id uuid not null references tenants(id),
    -- The FLUIDBOX run session (not the upstream one) — the registry's first key.
    session_id uuid not null,
    -- The registry's second key, split into a storable pair. 'binding' = the Phase C
    -- run-resource-binding path (`McpPeer::Binding`), 'connection' = the legacy
    -- embedded-connection path (`McpPeer::Conn`). Check-constrained because the
    -- server MUST round-trip this back into the enum to re-resolve a credential:
    -- an unknown kind is not inert here, it is an unusable row.
    peer_kind text not null check (peer_kind in ('binding', 'connection')),
    peer_id uuid not null,
    -- Which replica opened (and therefore owns) this upstream session. Part of the
    -- key: two replicas legitimately hold two DIFFERENT upstream sessions for the
    -- same (run, peer), and both must be torn down. INFORMATIONAL for correctness —
    -- teardown never routes back to this replica, it just DELETEs the session id.
    replica uuid not null,
    -- The `Mcp-Session-Id` the upstream issued. NOT NULL: a sessionless server
    -- gets no row (see header).
    upstream_session_id text not null,
    -- The endpoint the DELETE goes to. Stored rather than re-derived from the run's
    -- frozen surface so teardown needs no RunSpec parse — and so a replica that
    -- never saw this run can still address the session.
    endpoint_url text not null,
    -- The version negotiated at initialize, echoed on the DELETE as
    -- `MCP-Protocol-Version`. Nullable only for defensive symmetry with the
    -- in-memory sentinel (empty string = not yet negotiated).
    protocol_version text,
    opened_at timestamptz not null default now(),
    -- NULL = still live (undeleted). Stamped only after a DELETE was attempted or
    -- the sweeper retired the row.
    deleted_at timestamptz,
    delete_outcome text,
    unique (session_id, peer_kind, peer_id, replica),
    -- Composite tenant FK: the teardown row's run must belong to the same tenant.
    foreign key (tenant_id, session_id) references sessions (tenant_id, id) on delete cascade
);

-- Terminal teardown reads every LIVE row of one run; the sweeper scans live rows
-- deployment-wide. One partial index over the undeleted set serves both and keeps
-- the (dominant, terminal) deleted rows out of the scan entirely.
create index mcp_upstream_sessions_live
    on mcp_upstream_sessions (session_id)
    where deleted_at is null;

-- ─── RLS triple (0018 rule for a new tenant-owned table) ────────────────────
alter table mcp_upstream_sessions enable row level security;
alter table mcp_upstream_sessions force row level security;
-- Child-EXISTS (0018 section (c), as 0019): no tenant_id predicate in the policy
-- itself — the parent `sessions` policy composes through the subquery (it runs
-- under RLS too), so a teardown row is visible/writable iff its session is, and the
-- audited `system_worker` bypass opens the parent (and thus the child) for the
-- cross-tenant sweep.
create policy tenant_isolation on mcp_upstream_sessions as permissive for all to public
    using (exists (select 1 from sessions p where p.id = mcp_upstream_sessions.session_id))
    with check (exists (select 1 from sessions p where p.id = mcp_upstream_sessions.session_id));

-- Enumerated DML grant to the deployment's runtime role (resolved from the session
-- GUC `fluidbox.runtime_role`, default `fluidbox_runtime` — NEVER hardcoded; a
-- shared-cluster deployment picks its own name). Copied verbatim from 0018 (e), via
-- 0019/0022/0023.
do $$
declare
    v_role text := coalesce(nullif(current_setting('fluidbox.runtime_role', true), ''),
                            'fluidbox_runtime');
begin
    if exists (select 1 from pg_roles where rolname = v_role) then
        execute format('grant select, insert, update, delete on table mcp_upstream_sessions to %I', v_role);
    end if;
end $$;
