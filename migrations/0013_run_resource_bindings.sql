-- Phase C (#31) — connection ownership + run resource bindings.
-- Design: docs/plans/2026-07-14-multi-user-mcp-control-plane-design.md (v4),
--   connection fields :274-296, snapshots :298-318, requirements :349-389,
--   run resource bindings :391-463, subscription_secret generations :428-431,
--   catalog backfill :262-266, security invariants :1367-1405 (esp. 7, 21),
--   Gap 3 :1150-1162.
--
-- Separates connector definition, credential-bearing connection, agent
-- connection requirement, and per-run resource binding: a shared agent binds
-- to DIFFERENT connections per invocation, resolved at run time into
-- write-once `run_resource_bindings`, and consumers recheck
-- status + generation + owner-membership before every credentialed use.
--
-- NOTE: migrations run BEFORE the boot seed (crates/fluidbox-server/src/main.rs
-- runs `connect()` — which applies migrations — then `seed::run`). This file
-- must NOT assume the `default` tenant row exists (it does not yet at migration
-- time); every backfill below tolerates zero tenants.

-- ─── (a) integration_connections: ownership + authorization generation ──────
-- A shared connection gains an owner (org-wide vs a single user's personal
-- connection) and a monotonic `authorization_generation` that bumps on every
-- re-consent/rotation so stale bindings fail closed (design :274-296). The
-- composite (tenant_id, id) unique is the prerequisite for the composite tenant
-- FKs the snapshots + bindings tables need (a unique including the PK is
-- permitted, exactly as 0012 did for sessions/trigger_subscriptions).
alter table integration_connections
    add constraint integration_connections_tenant_id_id_key unique (tenant_id, id);
alter table integration_connections
    add column owner_type text not null default 'organization',
    add column owner_user_id uuid,
    add column created_by_user_id uuid,
    add column authorization_generation int not null default 1;
-- Existing rows: the defaults ARE the backfill — organization-owned, generation
-- 1 (design Gap 3 "migration of current attached connections to
-- organization-service requirements").
alter table integration_connections add constraint integration_connections_owner_shape
    check (owner_type in ('organization','user')
           and ((owner_type = 'user') = (owner_user_id is not null)));
alter table integration_connections add constraint integration_connections_owner_user_fk
    foreign key (tenant_id, owner_user_id) references users (tenant_id, id);
alter table integration_connections add constraint integration_connections_created_by_fk
    foreign key (tenant_id, created_by_user_id) references users (tenant_id, id);
-- auth_kind is now `static | oauth | none` — Task 3 introduces `none` for
-- credentialless remotes. No CHECK existed on this column; add one (existing
-- rows are all static|oauth, so this never fails on live data).
alter table integration_connections add constraint integration_connections_auth_kind_shape
    check (auth_kind in ('static','oauth','none'));

-- ─── (b) connection_tool_snapshots: append-only tool photographs ────────────
-- The photograph of a brokered connection's tools/list, versioned per
-- (tenant, connection). Append-only (publish = a new snapshot_version row);
-- a run freezes the version it resolved (design :298-318).
create table connection_tool_snapshots (
    id uuid primary key,
    tenant_id uuid not null references tenants(id),
    connection_id uuid not null,
    snapshot_version int not null,
    authorization_generation int not null,
    protocol_version text not null,
    tools_json jsonb not null,
    tools_digest text not null,
    discovered_at timestamptz not null default now(),
    created_at timestamptz not null default now(),
    unique (tenant_id, id),
    unique (tenant_id, connection_id, snapshot_version),
    foreign key (tenant_id, connection_id)
        references integration_connections (tenant_id, id) on delete cascade
);
create index connection_tool_snapshots_conn
    on connection_tool_snapshots (connection_id, snapshot_version desc);

-- ─── (c) trigger_subscriptions: authority generation ────────────────────────
-- Invariant 7 spans every credential-bearing authority kind — a subscription's
-- callback secret is one, so its authority also carries a generation the
-- binding freezes (design :428-431).
alter table trigger_subscriptions add column authority_generation int not null default 1;

-- ─── (d) agent_revisions: connection requirements ───────────────────────────
-- Which brokered connections an agent needs, by slot/connector/tools/mode.
-- agent_revisions has NO tenant_id column (its tenancy is the parent agent), so
-- this is validated jsonb (app-side by Task 2's `validate_requirements`), never
-- an FK. Append-only like the revision itself.
alter table agent_revisions
    add column connection_requirements jsonb not null default '[]'::jsonb;

-- ─── (e) run_resource_bindings: per-run resolved authority ──────────────────
-- The tagged authority union (connection | subscription_secret | none) is
-- realized as two typed FK columns — a single `authority_id` cannot be
-- composite-FK'd to two parents, and composite tenant FKs are mandatory. Rows
-- are write-once per (session, slot_kind, requirement_slot): a NEW record of
-- what a run resolved, never a mutation of the frozen RunSpec (design :433-457).
create table run_resource_bindings (
    id uuid primary key,
    tenant_id uuid not null references tenants(id),
    session_id uuid not null,
    requirement_slot text not null,
    slot_kind text not null check (slot_kind in ('mcp','workspace_fetch','result_publish')),
    authority_kind text not null
        check (authority_kind in ('connection','subscription_secret','none')),
    connection_id uuid,
    subscription_id uuid,
    authority_generation int,
    connection_owner_type text,
    connection_owner_user_id uuid,
    snapshot_version int,
    effective_tools_json jsonb,
    effective_tools_digest text,
    resource_scope jsonb not null default '{}'::jsonb,
    resolved_by_principal_kind text not null,
    resolved_by_principal_id text,
    binding_mode text not null
        check (binding_mode in ('invoking_user','organization','explicit')),
    created_at timestamptz not null default now(),
    unique (tenant_id, id),
    unique (tenant_id, session_id, slot_kind, requirement_slot),
    foreign key (tenant_id, session_id) references sessions (tenant_id, id) on delete cascade,
    foreign key (tenant_id, connection_id) references integration_connections (tenant_id, id),
    foreign key (tenant_id, subscription_id) references trigger_subscriptions (tenant_id, id),
    -- The tagged union: exactly the columns the chosen authority_kind needs are
    -- set, and the rest are null (fail-closed — no ambiguous half-populated row).
    constraint run_resource_bindings_authority_shape check (
        (authority_kind = 'connection' and connection_id is not null and subscription_id is null
           and authority_generation is not null
           and connection_owner_type in ('organization','user')
           and ((connection_owner_type = 'user') = (connection_owner_user_id is not null)))
        or (authority_kind = 'subscription_secret' and subscription_id is not null
           and connection_id is null and authority_generation is not null
           and connection_owner_type is null and connection_owner_user_id is null)
        or (authority_kind = 'none' and connection_id is null and subscription_id is null
           and authority_generation is null
           and connection_owner_type is null and connection_owner_user_id is null)),
    -- An mcp slot carries a photographed tool set; a non-mcp slot carries none.
    constraint run_resource_bindings_mcp_shape check (
        (slot_kind = 'mcp') = (snapshot_version is not null and effective_tools_json is not null
                               and effective_tools_digest is not null)),
    -- An mcp slot is always backed by a connection authority.
    constraint run_resource_bindings_mcp_authority check (
        slot_kind <> 'mcp' or authority_kind = 'connection')
);
create index run_resource_bindings_session on run_resource_bindings (session_id);

-- ─── (f) connector_catalog: tenant scoping + custom-row backfill ────────────
-- The catalog is global reference data; custom (BYO) rows become tenant-owned
-- so one org's pasted server never leaks into another's catalog (design
-- :262-266). Curated `fluidbox` + registry-imported rows keep tenant_id null =
-- global. `disabled_at` soft-disables an unattributable custom row.
alter table connector_catalog
    add column tenant_id uuid references tenants(id),
    add column disabled_at timestamptz;
-- Attribution: custom rows were admitted by the single boot tenant. If EXACTLY
-- ONE tenant exists, it is that tenant; with zero or multiple candidates the row
-- cannot be attributed and is DISABLED, never inherited by every tenant
-- (design :265-266). Both updates tolerate zero tenants (fresh DB: no custom
-- rows exist — only the curated `fluidbox` seeds, untouched here).
update connector_catalog c
   set tenant_id = (select t.id from tenants t)
 where (c.provenance->>'source') = 'custom'
   and (select count(*) from tenants) = 1;
update connector_catalog c
   set disabled_at = now()
 where (c.provenance->>'source') = 'custom' and c.tenant_id is null;
-- The inline unique from 0007 (`slug text not null unique`) auto-named
-- `connector_catalog_slug_key`. Replace it with two partial uniques: slug is
-- unique among globals, and unique per tenant among custom rows — a tenant
-- custom slug may deliberately shadow a same-slug global.
alter table connector_catalog drop constraint connector_catalog_slug_key;
create unique index connector_catalog_slug_global on connector_catalog (slug)
    where tenant_id is null;
create unique index connector_catalog_slug_tenant on connector_catalog (tenant_id, slug)
    where tenant_id is not null;

-- (Task 7 appends the capability-bundle conversion here)
