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

-- ─── (g) capability-bundle conversion: legacy brokered bundles → requirements ─
-- Design :320-347 (settled fate + additive migration rules): `capability_bundles`
-- survives ONLY for sandbox-class stdio tools; brokered tools move to immutable
-- agent connection requirements (+ per-connection snapshots + per-run bindings,
-- both other tasks). This block APPENDS a migrated revision per affected agent and
-- explicitly repoints pinned subscriptions. It touches nothing else: bundle rows
-- stay (historical pins/RunSpecs keep deserializing), sessions/RunSpecs are
-- untouched, and unconverted (sandbox-only or bundle-less) agents get no revision.
--
-- Deterministic + idempotent. It is defined as a plain SQL function CALLED ONCE by
-- the DO block below (at migration time) and LEFT IN PLACE so the DB test can call
-- it again after inserting legacy fixtures (0013 already ran at connect() time).
-- Idempotence: an agent is processed ONLY when its LATEST revision pins at least
-- one bundle whose definition contains a `"class":"brokered"` server — which a
-- converted agent's new latest revision (sandbox-only pins, no brokered) never
-- does, so re-running never double-appends. Nothing floats: surviving sandbox
-- pins are re-emitted as exact BundleRef objects `{id,name,version}` (the shape
-- run_service's `frozen_capabilities` deserializes — the pin's version IS the
-- explicit `name@<version>` the design mandates).
create or replace function fluidbox_convert_legacy_bundles() returns void
language plpgsql as $$
declare
    v_agent          record;
    v_latest         record;
    v_pin            jsonb;
    v_pin_name       text;
    v_pin_version    int;
    v_pin_suffix     text;
    v_bundle_id      uuid;
    v_bundle_name    text;
    v_bundle_version int;
    v_def            jsonb;
    v_server         jsonb;
    v_surviving      jsonb;
    v_requirements   jsonb;
    v_has_brokered   boolean;
    v_bundle_brokered boolean;
    v_base_slot      text;
    v_slot           text;
    v_suffix         int;
    v_url            text;
    v_slug           text;
    v_dropped_sandbox text;
    v_cnt            int;
    v_new_rev        int;
    v_new_rev_id     uuid;
begin
    for v_agent in select id, tenant_id from agents loop
        -- The agent's LATEST revision governs future runs; only it is converted.
        select * into v_latest
          from agent_revisions r
         where r.agent_id = v_agent.id
         order by r.rev desc
         limit 1;
        if not found then
            continue;
        end if;

        v_has_brokered := false;
        v_surviving    := '[]'::jsonb;
        v_requirements := '[]'::jsonb;

        -- Pins in ARRAY ORDER (deterministic via WITH ORDINALITY).
        for v_pin in
            select elem
              from jsonb_array_elements(coalesce(v_latest.capability_bundles, '[]'::jsonb))
                       with ordinality as p(elem, ord)
             order by p.ord
        loop
            -- Resolve the pin to a bundle row WITHIN the agent's tenant, mirroring
            -- run_service's semantics. The live stored shape is a BundleRef object
            -- `{id,name,version}` (resolve by id); a bare/`name@N` string is also
            -- accepted defensively ("name" = the max version at conversion time,
            -- "name@N" = exact). Reset first so a malformed element can't inherit a
            -- prior iteration's resolution.
            v_bundle_id := null;
            v_bundle_name := null;
            v_bundle_version := null;
            v_def := null;
            if jsonb_typeof(v_pin) = 'object' and (v_pin ? 'id') then
                select b.id, b.name, b.version, b.definition
                  into v_bundle_id, v_bundle_name, v_bundle_version, v_def
                  from capability_bundles b
                 where b.tenant_id = v_agent.tenant_id
                   and b.id = (v_pin->>'id')::uuid;
            elsif jsonb_typeof(v_pin) = 'string' then
                v_pin_name := split_part(v_pin #>> '{}', '@', 1);
                if position('@' in (v_pin #>> '{}')) > 0 then
                    -- Defensive `name@N` string: only a purely-numeric suffix is a
                    -- version. A non-numeric one (e.g. `name@abc`) must NOT abort the
                    -- whole migration on an int cast — leave v_bundle_id null so the
                    -- unresolvable drop+notice path below handles it, exactly like a
                    -- BundleRef pointing at a missing bundle.
                    v_pin_suffix := split_part(v_pin #>> '{}', '@', 2);
                    if v_pin_suffix ~ '^[0-9]+$' then
                        v_pin_version := v_pin_suffix::int;
                        select b.id, b.name, b.version, b.definition
                          into v_bundle_id, v_bundle_name, v_bundle_version, v_def
                          from capability_bundles b
                         where b.tenant_id = v_agent.tenant_id
                           and b.name = v_pin_name
                           and b.version = v_pin_version;
                    end if;
                else
                    select b.id, b.name, b.version, b.definition
                      into v_bundle_id, v_bundle_name, v_bundle_version, v_def
                      from capability_bundles b
                     where b.tenant_id = v_agent.tenant_id
                       and b.name = v_pin_name
                     order by b.version desc
                     limit 1;
                end if;
            end if;

            if v_bundle_id is null then
                -- A dangling pin already fails runs today; do not invent new
                -- behavior — drop it from the copied list and skip requirement
                -- derivation (name/id only, never secrets).
                raise notice 'convert_legacy_bundles: agent % has an unresolvable capability pin — dropped', v_agent.id;
                continue;
            end if;

            v_bundle_brokered := exists (
                select 1
                  from jsonb_array_elements(coalesce(v_def->'servers', '[]'::jsonb)) s
                 where s->>'class' = 'brokered');

            if not v_bundle_brokered then
                -- Sandbox-only bundle survives, re-pinned EXPLICITLY (exact
                -- id+name+version; the version IS the `name@<version>` pin).
                v_surviving := v_surviving || jsonb_build_array(jsonb_build_object(
                    'id', v_bundle_id, 'name', v_bundle_name, 'version', v_bundle_version));
                continue;
            end if;

            -- This bundle carries brokered servers: it is DROPPED from the copied
            -- pins (a mixed bundle's sandbox servers go with it — the design's
            -- per-bundle rule), and each brokered server becomes a requirement.
            v_has_brokered := true;

            -- Settled (the controller's call): a mixed bundle is dropped WHOLE and
            -- its sandbox servers are surfaced by notice — we do NOT synthesize a
            -- new sandbox-only bundle version. No real mixed bundles exist, so
            -- synthesis would add migration write surface for a nonexistent case,
            -- and the brokered cutoff makes keeping the original pin impossible.
            -- Name the dropped sandbox server(s) so an operator can re-add them by
            -- hand (names only; every value is a % arg, never concatenated in).
            select string_agg(elem->>'name', ', ' order by ord)
              into v_dropped_sandbox
              from jsonb_array_elements(coalesce(v_def->'servers', '[]'::jsonb))
                       with ordinality as srv(elem, ord)
             where elem->>'class' <> 'brokered';
            if v_dropped_sandbox is not null then
                raise notice 'convert_legacy_bundles: agent % dropped mixed bundle %@% — sandbox server(s) % must be re-added manually',
                    v_agent.id, v_bundle_name, v_bundle_version, v_dropped_sandbox;
            end if;

            for v_server in
                select elem
                  from jsonb_array_elements(coalesce(v_def->'servers', '[]'::jsonb))
                           with ordinality as s(elem, ord)
                 order by s.ord
            loop
                if v_server->>'class' <> 'brokered' then
                    continue;
                end if;
                -- A brokered server with zero photographed tools can satisfy no
                -- requirement — skip it (tool/slot names only in the notice).
                if jsonb_array_length(coalesce(v_server->'tools', '[]'::jsonb)) = 0 then
                    raise notice 'convert_legacy_bundles: agent % brokered server ''%'' has zero tools — skipped', v_agent.id, v_server->>'name';
                    continue;
                end if;

                v_url := v_server->>'url';

                -- Slug reverse-match: the UNIQUE connector_catalog row whose url
                -- equals the server url exactly, tenant row shadowing global;
                -- ambiguous (>1) or absent ⇒ null (display hint only).
                select count(*), min(c.slug) into v_cnt, v_slug
                  from connector_catalog c
                 where c.url = v_url and c.disabled_at is null
                   and c.tenant_id = v_agent.tenant_id;
                if v_cnt > 1 then
                    v_slug := null;
                elsif v_cnt = 0 then
                    select count(*), min(c.slug) into v_cnt, v_slug
                      from connector_catalog c
                     where c.url = v_url and c.disabled_at is null
                       and c.tenant_id is null;
                    if v_cnt <> 1 then
                        v_slug := null;
                    end if;
                end if;

                -- Slot = server name, with duplicates suffixed -2, -3 … across the
                -- requirements built so far (encounter order → deterministic).
                v_base_slot := v_server->>'name';
                v_slot := v_base_slot;
                v_suffix := 2;
                while exists (
                    select 1 from jsonb_array_elements(v_requirements) rq
                     where rq->>'slot' = v_slot)
                loop
                    v_slot := v_base_slot || '-' || v_suffix;
                    v_suffix := v_suffix + 1;
                end loop;

                -- Build EXACTLY ConnectionRequirement's serde shape (snake_case,
                -- deny_unknown_fields): {slot, connector{url,slug}, required_tools,
                -- binding_mode}. required_tools keeps the photographed tool order.
                v_requirements := v_requirements || jsonb_build_array(jsonb_build_object(
                    'slot', v_slot,
                    'connector', jsonb_build_object('url', v_url, 'slug', to_jsonb(v_slug)),
                    'required_tools', (
                        select coalesce(jsonb_agg(t.elem->>'name' order by t.ord), '[]'::jsonb)
                          from jsonb_array_elements(v_server->'tools')
                                   with ordinality as t(elem, ord)
                         where t.elem ? 'name'),
                    'binding_mode', 'organization'));
            end loop;
        end loop;

        -- No brokered pins on the latest revision ⇒ nothing to convert. This is
        -- also the idempotence guard: a previously-converted agent's latest
        -- revision is sandbox-only, so it lands here and is skipped.
        if not v_has_brokered then
            continue;
        end if;

        select coalesce(max(rev), 0) + 1 into v_new_rev
          from agent_revisions where agent_id = v_agent.id;

        insert into agent_revisions
            (id, agent_id, rev, harness, runner_image, model, system_prompt, policy_id,
             budgets, default_workspace, capability_bundles, connection_requirements)
        values
            (gen_random_uuid(), v_agent.id, v_new_rev, v_latest.harness, v_latest.runner_image,
             v_latest.model, v_latest.system_prompt, v_latest.policy_id, v_latest.budgets,
             v_latest.default_workspace, v_surviving, v_requirements)
        returning id into v_new_rev_id;

        -- Explicitly repoint EVERY subscription pinned to ANY revision of this
        -- agent onto the new revision (design :346).
        update trigger_subscriptions ts
           set pinned_revision_id = v_new_rev_id,
               updated_at = now()
         where ts.agent_id = v_agent.id
           and ts.pinned_revision_id is not null
           and ts.pinned_revision_id in (
                 select r.id from agent_revisions r where r.agent_id = v_agent.id);
    end loop;
end;
$$;

-- Run the conversion once, now, at migration time (a no-op on a fresh DB — the
-- boot seed's agents don't exist yet). The function stays defined for the DB test.
do $$ begin perform fluidbox_convert_legacy_bundles(); end $$;
