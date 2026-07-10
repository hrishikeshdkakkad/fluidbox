-- Phase 1 of "borrow the agent, on demand": connected Git workspaces.
-- (docs/plans/2026-07-10-agent-workspaces-triggers-integrations-design.md §3.2/§10)

-- A connection is fluidbox's authorized relationship with an external
-- service. It establishes the MAXIMUM authority fluidbox can exercise;
-- agents and (later) trigger bindings may only use a narrower subset.
create table integration_connections (
    id uuid primary key,
    tenant_id uuid not null references tenants(id),
    provider text not null,             -- github | gitlab | jira | slack | custom
    external_account_id text not null,  -- e.g. GitHub user/installation id
    display_name text not null,
    -- AEAD-sealed credential (nonce || ciphertext), sealed with the server's
    -- FLUIDBOX_CREDENTIAL_KEY. Never returned by any API; opened server-side
    -- only for workspace materialization / provider API calls.
    credential_sealed bytea not null,
    granted_scopes jsonb not null default '[]',
    resource_selection jsonb not null default '{}',
    status text not null default 'active', -- active | revoked | error
    metadata jsonb not null default '{}',
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now()
);
create index integration_connections_tenant on integration_connections(tenant_id);

-- An agent revision may carry an optional default workspace (WorkspaceSpec
-- jsonb). It stays optional: run creation resolves
-- explicit invocation workspace > this default > scratch.
alter table agent_revisions add column default_workspace jsonb;
