-- Phase 5.6 — seamless GitHub connect (App manifest + install dance).
-- Design: docs/plans/2026-07-11-github-seamless-connect-design.md.
-- The App identity (created via GitHub's manifest flow) becomes a
-- first-class custody object; connections stay one-per-installation and
-- reference their registration with a REAL column (fail-closed resolution,
-- never a jsonb pointer). Legacy hand-pasted github_app connections keep
-- per-connection custody (registration_id stays NULL).

create table github_app_registrations (
    id uuid primary key,
    tenant_id uuid not null references tenants(id),
    status text not null default 'pending',   -- pending | active | revoked
    target_kind text not null default 'personal', -- personal | organization
    target_org text,
    -- Identity from the manifest conversion; null while pending.
    app_id text,
    slug text,
    name text,
    client_id text,
    html_url text,
    owner_login text,
    -- AEAD-sealed custody (seal.rs). pem signs installation-token JWTs;
    -- webhook_secret authenticates app-level ingress (null = GitHub
    -- returned none: fetch/publish work, events are degraded); the client
    -- secret is returned exactly once by the conversion and kept sealed for
    -- future user-OAuth. None of these are ever selected by row queries.
    pem_sealed bytea,
    webhook_secret_sealed bytea,
    client_secret_sealed bytea,
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now()
);
create index github_app_registrations_tenant on github_app_registrations(tenant_id);

-- One-time admin intents driving the two browser dances. Two claims per
-- row: the go page consumes the bootstrap token exactly once (binding a
-- fresh browser cookie hash), the returning callback/setup consumes the
-- flow exactly once — and only with the matching cookie hash IN the claim
-- predicate, so a leaked state parameter can neither complete nor burn a
-- flow without the initiating browser.
create table github_app_flows (
    id uuid primary key,
    registration_id uuid not null references github_app_registrations(id) on delete cascade,
    purpose text not null,            -- manifest | install
    browser_hash text,                -- sha256(cookie nonce); null until go binds
    bootstrap_consumed_at timestamptz,
    consumed_at timestamptz,
    expires_at timestamptz not null,
    created_at timestamptz not null default now()
);
create index github_app_flows_registration on github_app_flows(registration_id);
create index github_app_flows_expiry on github_app_flows(expires_at);

-- Typed authority linkage: RESTRICT keeps a registration row around while
-- connections point at it (registrations are revoked, never deleted).
alter table integration_connections
    add column registration_id uuid references github_app_registrations(id) on delete restrict;
create index integration_connections_registration
    on integration_connections(registration_id) where registration_id is not null;

-- Exactly ONE live connection row per GitHub installation. Duplicates are
-- deliberately NOT auto-remediated: connection ids are referenced beyond
-- trigger_subscriptions (agent default workspaces, subscription workspace
-- overrides, frozen RunSpecs, queued result deliveries), so silently
-- revoking one duplicate could strand live configuration. A database that
-- actually holds live duplicates fails HERE with instructions instead of
-- being mutated behind the operator's back.
do $$
declare dup record;
begin
    select tenant_id, external_account_id, count(*) as n
      into dup
      from integration_connections
     where provider = 'github_app' and status <> 'revoked'
     group by tenant_id, external_account_id
    having count(*) > 1
     limit 1;
    if found then
        raise exception
            'migration 0008: installation % has % live github_app connections — revoke the redundant one(s) in Connections, then restart the server',
            dup.external_account_id, dup.n;
    end if;
end $$;

create unique index integration_connections_live_installation
    on integration_connections(tenant_id, provider, external_account_id)
    where provider = 'github_app' and status <> 'revoked';
