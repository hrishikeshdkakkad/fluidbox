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
    resolved_by_principal_kind text not null
        check (resolved_by_principal_kind in
               ('user','operator','trigger','schedule','webhook','system')),
    resolved_by_principal_id text,
    binding_mode text not null
        check (binding_mode in ('invoking_user','organization','explicit')),
    created_at timestamptz not null default now(),
    unique (tenant_id, id),
    unique (tenant_id, session_id, slot_kind, requirement_slot),
    foreign key (tenant_id, session_id) references sessions (tenant_id, id) on delete cascade,
    foreign key (tenant_id, connection_id) references integration_connections (tenant_id, id),
    foreign key (tenant_id, subscription_id) references trigger_subscriptions (tenant_id, id),
    -- An mcp binding names an EXACT frozen snapshot version — bind it relationally
    -- so a binding can never reference a snapshot that does not exist (R1.5). The
    -- three columns are nullable (non-mcp rows leave them NULL); MATCH SIMPLE (the
    -- default) skips the FK entirely when ANY column is null, so only fully-
    -- populated mcp rows are checked.
    foreign key (tenant_id, connection_id, snapshot_version)
        references connection_tool_snapshots (tenant_id, connection_id, snapshot_version),
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
-- agent connection requirements. This block APPENDS migrated revisions and
-- explicitly repoints pinned subscriptions. It touches nothing else: bundle rows
-- stay (historical pins/RunSpecs keep deserializing), sessions/RunSpecs are
-- untouched, and unconverted (sandbox-only or bundle-less) agents get no revision.
--
-- Convert PER SOURCE REVISION, not just the latest (R1.1/R1.2). A subscription
-- may pin an OLDER revision (different model/prompt/pins) and carry its OWN
-- `capability_bundles` keep-list (a remove-only §3.5 narrowing). Repointing every
-- subscription to the latest's FULL conversion would (a) silently replace its
-- model/prompt and (b) re-grant brokered authority a keep-list had removed. So:
--   * the agent's LATEST revision converts with the FULL (no keep-list)
--     derivation — the live/unpinned path, appended LAST so it stays `latest`;
--   * every revision a subscription pins converts using THAT subscription's
--     keep-list (NULL = all bundles; [] = none ⇒ zero requirements — the sub had
--     removed all brokered authority and must not regain it), copying all other
--     fields from the SOURCE revision;
--   * converted copies dedupe on (source_revision, derived requirement set):
--     subscriptions sharing both share one copy; a subscription pinning the
--     latest at FULL authority shares the live copy;
--   * a FLOATING subscription (pinned_revision_id IS NULL) whose NON-NULL
--     keep-list narrows the latest's brokered authority is PINNED to a tailored
--     copy of the latest (R1.1/R1.2) — the only way to freeze the narrowing; a
--     NULL keep-list floater keeps floating (the full converted latest is right);
--   * NOTHING here ever rewrites a historical revision (append-only is sacred,
--     design :338-339): when the latest is sandbox-only but older revisions
--     converted above it, an exact CLONE of the latest is APPENDED (not its rev
--     bumped) so unpinned runs still resolve the sandbox-only semantics.
-- Sandbox pins survive as exact BundleRef objects `{id,name,version}` (the shape
-- `frozen_capabilities` deserializes; the version IS the `name@<version>` pin);
-- the subscription's keep-list still narrows them at run time.
--
-- Deterministic + idempotent. Three plain functions: a per-(revision,keep-list)
-- derivation, an append helper, and the orchestrator called once by the DO block
-- (at migration time) and LEFT IN PLACE so the DB test can re-call it after
-- inserting fixtures. Idempotence: a revision is a conversion SOURCE only when its
-- pins resolve to ≥1 brokered server; after one run the latest is brokered-free
-- and every subscription pin points at a brokered-free copy, so a second run is a
-- no-op.

-- Derive, for ONE revision's pins under ONE keep-list, the surviving sandbox pins
-- (keep-list-independent — narrowed at run time), the brokered requirements (only
-- from bundles the keep-list keeps), and whether the pins hold ANY brokered
-- bundle (source qualification, keep-list-independent).
create or replace function fluidbox_convert_derive(
    p_agent uuid, p_tenant uuid, p_pins jsonb, p_keep jsonb,
    out o_surviving jsonb, out o_requirements jsonb, out o_has_brokered boolean
) language plpgsql as $$
declare
    v_pin          jsonb;
    v_pin_name     text;
    v_pin_version  int;
    v_pin_suffix   text;
    v_bundle_id    uuid;
    v_bundle_name  text;
    v_bundle_version int;
    v_def          jsonb;
    v_server       jsonb;
    v_bundle_brokered boolean;
    v_base_slot    text;
    v_slot         text;
    v_suffix       int;
    v_url          text;
    v_slug         text;
    v_dropped_sandbox text;
    v_cnt          int;
begin
    o_surviving := '[]'::jsonb;
    o_requirements := '[]'::jsonb;
    o_has_brokered := false;

    for v_pin in
        select elem
          from jsonb_array_elements(coalesce(p_pins, '[]'::jsonb))
                   with ordinality as p(elem, ord)
         order by p.ord
    loop
        -- Resolve the pin to a bundle row WITHIN the tenant, mirroring
        -- run_service's semantics. The live stored shape is a BundleRef object
        -- `{id,name,version}` (resolve by id); a bare/`name@N` string is also
        -- accepted defensively. Reset first so a malformed element can't inherit
        -- a prior iteration's resolution.
        v_bundle_id := null;
        v_bundle_name := null;
        v_bundle_version := null;
        v_def := null;
        if jsonb_typeof(v_pin) = 'object' and (v_pin ? 'id') then
            select b.id, b.name, b.version, b.definition
              into v_bundle_id, v_bundle_name, v_bundle_version, v_def
              from capability_bundles b
             where b.tenant_id = p_tenant and b.id = (v_pin->>'id')::uuid;
        elsif jsonb_typeof(v_pin) = 'string' then
            v_pin_name := split_part(v_pin #>> '{}', '@', 1);
            if position('@' in (v_pin #>> '{}')) > 0 then
                -- Only a purely-numeric suffix is a version; a non-numeric one
                -- (`name@abc`) must NOT abort the migration on an int cast — leave
                -- v_bundle_id null so the drop+notice path handles it.
                v_pin_suffix := split_part(v_pin #>> '{}', '@', 2);
                if v_pin_suffix ~ '^[0-9]+$' then
                    v_pin_version := v_pin_suffix::int;
                    select b.id, b.name, b.version, b.definition
                      into v_bundle_id, v_bundle_name, v_bundle_version, v_def
                      from capability_bundles b
                     where b.tenant_id = p_tenant
                       and b.name = v_pin_name
                       and b.version = v_pin_version;
                end if;
            else
                select b.id, b.name, b.version, b.definition
                  into v_bundle_id, v_bundle_name, v_bundle_version, v_def
                  from capability_bundles b
                 where b.tenant_id = p_tenant and b.name = v_pin_name
                 order by b.version desc
                 limit 1;
            end if;
        end if;

        if v_bundle_id is null then
            raise notice 'convert_legacy_bundles: agent % has an unresolvable capability pin — dropped', p_agent;
            continue;
        end if;

        v_bundle_brokered := exists (
            select 1
              from jsonb_array_elements(coalesce(v_def->'servers', '[]'::jsonb)) s
             where s->>'class' = 'brokered');

        if not v_bundle_brokered then
            -- Sandbox-only bundle survives, re-pinned EXPLICITLY (exact
            -- id+name+version). Keep-list-independent: the subscription's keep-list
            -- still narrows it at run time against the converted revision.
            o_surviving := o_surviving || jsonb_build_array(jsonb_build_object(
                'id', v_bundle_id, 'name', v_bundle_name, 'version', v_bundle_version));
            continue;
        end if;

        -- A brokered bundle qualifies the revision as a conversion SOURCE,
        -- REGARDLESS of the keep-list (so an empty keep-list still yields a copy
        -- with zero requirements rather than skipping the revision entirely).
        o_has_brokered := true;

        -- Keep-list gate for REQUIREMENT derivation (R1.2): NULL keep = all;
        -- otherwise only bundles whose NAME is kept contribute requirements. A
        -- removed brokered bundle adds nothing (and never survives — it is
        -- brokered), so its authority is not regained.
        if p_keep is not null and not (p_keep @> to_jsonb(v_bundle_name)) then
            continue;
        end if;

        -- Name the dropped sandbox server(s) of this (dropped WHOLE) mixed bundle
        -- so an operator can re-add them by hand (names only; every value is a %
        -- arg, never concatenated in).
        select string_agg(elem->>'name', ', ' order by ord)
          into v_dropped_sandbox
          from jsonb_array_elements(coalesce(v_def->'servers', '[]'::jsonb))
                   with ordinality as srv(elem, ord)
         where elem->>'class' <> 'brokered';
        if v_dropped_sandbox is not null then
            raise notice 'convert_legacy_bundles: agent % dropped mixed bundle %@% — sandbox server(s) % must be re-added manually',
                p_agent, v_bundle_name, v_bundle_version, v_dropped_sandbox;
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
            if jsonb_array_length(coalesce(v_server->'tools', '[]'::jsonb)) = 0 then
                raise notice 'convert_legacy_bundles: agent % brokered server ''%'' has zero tools — skipped', p_agent, v_server->>'name';
                continue;
            end if;

            v_url := v_server->>'url';

            -- Slug reverse-match: the UNIQUE catalog row whose url equals the
            -- server url, tenant row shadowing global; ambiguous/absent ⇒ null.
            select count(*), min(c.slug) into v_cnt, v_slug
              from connector_catalog c
             where c.url = v_url and c.disabled_at is null
               and c.tenant_id = p_tenant;
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

            -- Slot = server name, duplicates suffixed -2, -3 … in encounter order.
            v_base_slot := v_server->>'name';
            v_slot := v_base_slot;
            v_suffix := 2;
            while exists (
                select 1 from jsonb_array_elements(o_requirements) rq
                 where rq->>'slot' = v_slot)
            loop
                v_slot := v_base_slot || '-' || v_suffix;
                v_suffix := v_suffix + 1;
            end loop;

            o_requirements := o_requirements || jsonb_build_array(jsonb_build_object(
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
end;
$$;

-- Append ONE converted revision (rev = max+1 at call time), copying the SOURCE
-- revision's fields and stamping the derived surviving pins + requirements.
-- Returns the new revision id.
create or replace function fluidbox_convert_append(
    p_agent uuid, p_source_rev_id uuid, p_surviving jsonb, p_requirements jsonb
) returns uuid language plpgsql as $$
declare
    v_new_rev int;
    v_id      uuid;
begin
    select coalesce(max(rev), 0) + 1 into v_new_rev
      from agent_revisions where agent_id = p_agent;
    insert into agent_revisions
        (id, agent_id, rev, harness, runner_image, model, system_prompt, policy_id,
         budgets, default_workspace, capability_bundles, connection_requirements)
    select gen_random_uuid(), p_agent, v_new_rev, s.harness, s.runner_image, s.model,
           s.system_prompt, s.policy_id, s.budgets, s.default_workspace,
           p_surviving, p_requirements
      from agent_revisions s
     where s.id = p_source_rev_id
    returning id into v_id;
    return v_id;
end;
$$;
-- The orchestrator: convert per source revision, dedupe copies, repoint each
-- subscription to its own copy, and keep the live (latest) conversion as `latest`.
create or replace function fluidbox_convert_legacy_bundles() returns void
language plpgsql as $$
declare
    v_agent          record;
    v_latest         agent_revisions%rowtype;
    v_surviving_l    jsonb;
    v_requirements_l jsonb;
    v_brokered_l     boolean;
    v_sub            record;
    v_source         agent_revisions%rowtype;
    v_surviving      jsonb;
    v_requirements   jsonb;
    v_has_brokered   boolean;
    v_reqs_key       text;
    v_new_rev_id     uuid;
    v_existing       uuid;
    v_live_copy      uuid;
    v_deferred       uuid[];
    -- Per-agent dedup map for NON-deferred subscription copies, keyed
    -- (source_revision, derived requirement set). Parallel arrays (not a temp
    -- table — a plpgsql function that creates/drops a temp table across calls
    -- trips the cached-plan/OID gotcha).
    v_map_source     uuid[];
    v_map_reqs       text[];
    v_map_newrev     uuid[];
    i                int;
begin
    for v_agent in select id, tenant_id from agents loop
        select * into v_latest
          from agent_revisions r
         where r.agent_id = v_agent.id
         order by r.rev desc
         limit 1;
        if not found then
            continue;
        end if;

        -- Live (unpinned/manual) derivation of the LATEST with the FULL keep-list
        -- (NULL = all). Used to decide the live append AND to dedup subscriptions
        -- pinning the latest at full authority onto the live copy.
        select * into v_surviving_l, v_requirements_l, v_brokered_l
          from fluidbox_convert_derive(v_agent.id, v_agent.tenant_id,
                 coalesce(v_latest.capability_bundles, '[]'::jsonb), null);

        v_deferred := '{}';
        v_map_source := '{}';
        v_map_reqs := '{}';
        v_map_newrev := '{}';

        -- Every subscription pinned to a brokered SOURCE revision, per keep-list.
        for v_sub in
            select ts.id as sub_id, ts.pinned_revision_id, ts.capability_bundles as keep
              from trigger_subscriptions ts
             where ts.agent_id = v_agent.id and ts.pinned_revision_id is not null
             order by ts.created_at, ts.id
        loop
            select * into v_source
              from agent_revisions r
             where r.id = v_sub.pinned_revision_id and r.agent_id = v_agent.id;
            if not found then
                continue;  -- dangling pin: leave the subscription untouched
            end if;

            select * into v_surviving, v_requirements, v_has_brokered
              from fluidbox_convert_derive(v_agent.id, v_agent.tenant_id,
                     coalesce(v_source.capability_bundles, '[]'::jsonb), v_sub.keep);
            if not v_has_brokered then
                continue;  -- pinned to a brokered-free revision: untouched
            end if;

            -- A subscription pinning the LATEST at FULL authority shares the live
            -- copy — deferred until after it is appended (LAST) so the live
            -- conversion stays the agent's `latest`.
            if v_brokered_l and v_source.id = v_latest.id
               and v_requirements::text = v_requirements_l::text then
                v_deferred := array_append(v_deferred, v_sub.sub_id);
                continue;
            end if;

            -- Otherwise: dedup on (source_revision, requirement set) among the
            -- subscription copies built so far; append a fresh copy on a miss.
            v_reqs_key := v_requirements::text;
            v_existing := null;
            for i in 1 .. coalesce(array_length(v_map_source, 1), 0) loop
                if v_map_source[i] = v_source.id and v_map_reqs[i] = v_reqs_key then
                    v_existing := v_map_newrev[i];
                    exit;
                end if;
            end loop;
            if v_existing is null then
                v_new_rev_id := fluidbox_convert_append(
                    v_agent.id, v_source.id, v_surviving, v_requirements);
                v_map_source := array_append(v_map_source, v_source.id);
                v_map_reqs := array_append(v_map_reqs, v_reqs_key);
                v_map_newrev := array_append(v_map_newrev, v_new_rev_id);
            else
                v_new_rev_id := v_existing;
            end if;
            update trigger_subscriptions
               set pinned_revision_id = v_new_rev_id, updated_at = now()
             where id = v_sub.sub_id;
        end loop;

        -- Floating subscriptions (pinned_revision_id IS NULL) resolve the LATEST
        -- at run time. Post-conversion the latest becomes the FULL live copy, so a
        -- floating sub whose NON-NULL keep-list REMOVED brokered authority would
        -- REGAIN it by following the live copy (A1). A NULL keep-list floater is
        -- correct to keep floating (full authority); a restrictive/empty keep-list
        -- floater must be PINNED to a copy derived under ITS keep-list — pinning is
        -- the ONLY way to freeze the narrowing, and it DELIBERATELY stops the sub
        -- floating (design R1.1/R1.2). Only meaningful when the latest actually
        -- holds brokered authority; appended BEFORE the live copy so the live copy
        -- stays the highest rev / new `latest`.
        if v_brokered_l then
            for v_sub in
                select ts.id as sub_id, ts.capability_bundles as keep
                  from trigger_subscriptions ts
                 where ts.agent_id = v_agent.id and ts.pinned_revision_id is null
                   and ts.capability_bundles is not null
                 order by ts.created_at, ts.id
            loop
                select * into v_surviving, v_requirements, v_has_brokered
                  from fluidbox_convert_derive(v_agent.id, v_agent.tenant_id,
                         coalesce(v_latest.capability_bundles, '[]'::jsonb), v_sub.keep);
                -- A keep-list that removes NO brokered authority derives the full
                -- live requirements — leave the sub floating (== a NULL keep-list).
                if v_requirements::text = v_requirements_l::text then
                    continue;
                end if;
                -- Narrowing keep-list: dedup on (latest source, requirement set)
                -- among the copies built so far, append a fresh copy on a miss,
                -- then PIN (this deliberately stops the sub floating).
                v_reqs_key := v_requirements::text;
                v_existing := null;
                for i in 1 .. coalesce(array_length(v_map_source, 1), 0) loop
                    if v_map_source[i] = v_latest.id and v_map_reqs[i] = v_reqs_key then
                        v_existing := v_map_newrev[i];
                        exit;
                    end if;
                end loop;
                if v_existing is null then
                    v_new_rev_id := fluidbox_convert_append(
                        v_agent.id, v_latest.id, v_surviving, v_requirements);
                    v_map_source := array_append(v_map_source, v_latest.id);
                    v_map_reqs := array_append(v_map_reqs, v_reqs_key);
                    v_map_newrev := array_append(v_map_newrev, v_new_rev_id);
                else
                    v_new_rev_id := v_existing;
                end if;
                update trigger_subscriptions
                   set pinned_revision_id = v_new_rev_id, updated_at = now()
                 where id = v_sub.sub_id;
            end loop;

            -- Live path LAST so its copy has the highest rev and is the new
            -- `latest`; then repoint every deferred subscription to it.
            v_live_copy := fluidbox_convert_append(
                v_agent.id, v_latest.id, v_surviving_l, v_requirements_l);
            if array_length(v_deferred, 1) is not null then
                update trigger_subscriptions
                   set pinned_revision_id = v_live_copy, updated_at = now()
                 where id = any(v_deferred);
            end if;
        elsif (select max(rev) from agent_revisions where agent_id = v_agent.id) > v_latest.rev then
            -- The latest is brokered-free (NOT converted). If subscription copies
            -- from OLDER brokered revisions were appended with higher revs, the
            -- untouched latest is no longer the max rev, so unpinned/manual runs
            -- would resolve a converted OLDER revision. Append-only is SACRED
            -- (design :338-339 — never rewrite a historical agent revision): rather
            -- than bumping v_latest's rev, APPEND an exact CLONE of it as the new
            -- highest rev (A2). Content identical — same bundles/requirements plus
            -- model/prompt/policy/budgets copied from the source by
            -- fluidbox_convert_append — with a fresh id + rev; unpinned runs then
            -- resolve the clone, semantically the sandbox-only latest. Idempotent:
            -- on a re-run the latest IS already the max rev (the clone), so this
            -- does not fire.
            v_new_rev_id := fluidbox_convert_append(
                v_agent.id, v_latest.id, v_latest.capability_bundles,
                v_latest.connection_requirements);
        end if;
    end loop;
end;
$$;

-- Run the conversion once, now, at migration time (a no-op on a fresh DB — the
-- boot seed's agents don't exist yet). The functions stay defined for the DB test.
do $$ begin perform fluidbox_convert_legacy_bundles(); end $$;
