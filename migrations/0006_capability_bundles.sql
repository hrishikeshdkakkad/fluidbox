-- Phase 5 of "borrow the agent, on demand": capability & MCP catalog
-- (design doc §3.6/§8/§10/§12 Phase 5).
-- §17 #7 settled 2026-07-10: agent revisions PIN exact bundle versions at
-- attach time; upgrading = appending a new agent revision — no floating
-- refs exist anywhere. §17 #4 (first brokered git-write ops) is explicitly
-- deferred; the brokered gateway ships now, proven on MCP.

-- The bundle registry. Append-only like agent revisions: publishing a
-- changed definition = a new (name, version) row, never an update. The
-- definition holds the PHOTOGRAPHED tool-schema snapshots (brokered servers
-- are discovered via tools/list at registration; sandbox servers are
-- declared) — the ecosystem's registries pin no content hash for npm/pypi,
-- so definition_digest + the per-server tools digest are OUR supply-chain
-- anchor (see docs/research/2026-07-10-mcp-ecosystem-findings.md).
create table capability_bundles (
    id uuid primary key,
    tenant_id uuid not null references tenants(id),
    name text not null,
    version int not null,
    description text,
    definition jsonb not null,
    definition_digest text not null,
    created_at timestamptz not null default now(),
    unique (tenant_id, name, version)
);
create index capability_bundles_tenant_name on capability_bundles(tenant_id, name, version desc);

-- Subscription-level narrowing (§3.5): an optional keep-list of bundle
-- NAMES intersected with the revision's attachments in run_service —
-- narrowing REMOVES, never adds (a name the revision lacks intersects to
-- nothing). NULL = keep everything the revision attached.
alter table trigger_subscriptions add column capability_bundles jsonb;
