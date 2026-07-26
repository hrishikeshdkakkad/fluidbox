-- DB-native policies (§17 #11; design docs/plans/2026-07-14-db-native-policies-design.md,
-- implementation docs/plans/2026-07-25-db-native-policies-implementation.md).
--
-- Identity/content split: `policies` keeps the stable id an agent_revision
-- points at (the FK never changes); `policy_versions` is the append-only
-- history. The LATEST version governs future runs; every run still freezes its
-- snapshot into the RunSpec. `managed_overrides` (0010) folds into HEAD rules
-- — verdict-preservation is pinned by fluidbox-core's
-- `override_fold_preserves_every_verdict` property test; this SQL is only the
-- mechanism.
--
-- FROZEN RunSpecs ARE NOT TOUCHED — terminal or in-flight. `sessions.run_spec`
-- stays byte-identical; the ENGINE folds a legacy snapshot's
-- `managed_overrides` at deserialization (fluidbox-core::policy), so an
-- in-flight run keeps exactly the semantics it froze while its stored audit
-- record keeps exactly its bytes.
--
-- DEPLOY ORDER: stop-the-old-binary, migrate, then deploy (the 0018 posture).
-- An old binary `select *`s columns this migration drops, so it cannot serve
-- beside it — and because the drops land in the same migration, there is NO
-- binary rollback past this point (a pre-0026 binary cannot boot against a
-- post-0026 database). A single-binary docker/dev deploy satisfies this by
-- construction (migrations run on the new binary's boot, after the old one
-- stopped). **The Helm chart does NOT**: its Deployment uses RollingUpdate,
-- so a new pod would run this migration while old pods still serve queries
-- against the dropped columns. For THIS upgrade, scale the server Deployment
-- to zero first (or switch its strategy to Recreate for one release) —
-- exactly the 0018 operational posture.

set local lock_timeout = '5s';

-- This is the first DATA-BACKFILLING migration since 0018 ENABLE+FORCEd RLS on
-- `policies`. The migration connection carries no tenant GUC, so without the
-- audited bypass the backfill's `select … from policies` would read ZERO rows
-- — silently: an empty backfill, not an error. Transaction-local by
-- construction (sqlx runs each migration file in one transaction; the
-- `set local` above relies on the same fact).
select set_config('fluidbox.bypass', 'system_worker', true);

-- Preflight: the fold below trusts the shapes the retired write path enforced.
-- A violation would otherwise abort mid-fold with a postgres error naming no
-- policy (`cannot delete from scalar`), or — worse — fold silently into
-- nonsense. Fail HERE instead, naming the row AND the reason.
--
-- Checked, in order (the CASE short-circuits, and every `jsonb_array_elements`
-- is guarded by an inner CASE rather than by evaluation order — the planner is
-- free to hoist a subexpression, so the guard must be in the expression):
--
--   1. `parsed` is a json OBJECT. The fold does `parsed - 'managed_overrides'`
--      and `jsonb_set(parsed, '{tools}', …)`; both raise on a scalar.
--   2. `parsed.tools`, when present, is an ARRAY. `heads || parsed->'tools'`
--      against a scalar (including json `null`) yields an array with a
--      non-rule element in it, which no engine can deserialize. Absent is
--      fine — the fold coalesces it to `[]`.
--   3. `managed_overrides` is an ARRAY.
--   4. Every entry's tool AND action are json STRINGS with a known action. A
--      missing/null action makes `->>` yield SQL NULL, and `NULL NOT IN (…)`
--      is NULL — never rely on it, hence the explicit type checks.
--
-- Trailing-WILDCARD tools are handled separately, below: they are droppable
-- rather than fatal, so blocking an upgrade on one would be the wrong trade.
do $$
declare bad record;
begin
    select p.id, p.name, r.reason into bad
      from policies p
      cross join lateral (select case
          when jsonb_typeof(p.parsed) is distinct from 'object'
            then 'its `parsed` column is not a json object'
          when jsonb_typeof(p.parsed->'tools') is not null
               and jsonb_typeof(p.parsed->'tools') <> 'array'
            then 'its `parsed.tools` is present but not an array'
          when jsonb_typeof(p.managed_overrides) is distinct from 'array'
            then 'its `managed_overrides` is not an array'
          when exists (
              select 1 from jsonb_array_elements(
                  case when jsonb_typeof(p.managed_overrides) = 'array'
                       then p.managed_overrides else '[]'::jsonb end) o
               where jsonb_typeof(o->'tool') is distinct from 'string'
                  or jsonb_typeof(o->'action') is distinct from 'string'
                  or o->>'action' not in ('allow', 'approve', 'deny'))
            then 'its `managed_overrides` carries an entry that is not {"tool": <string>, "action": "allow"|"approve"|"deny"}'
        end as reason) r
     where r.reason is not null
     limit 1;
    if found then
        raise exception 'migration 0026: cannot fold policy % (%): %; repair the row before migrating',
            bad.id, bad.name, bad.reason;
    end if;
end $$;

-- TRAILING-WILDCARD overrides are DROPPED, loudly, rather than folded.
--
-- The retired engine matched an override by EXACT STRING EQUALITY
-- (`o.tool == req.tool`), never through `tool_matches`. A stored `mcp__*`
-- therefore fired for nothing except a tool whose LITERAL name was `mcp__*`.
-- Folded into a head rule it would go through `tool_matches` and match the
-- whole namespace — a silent WIDENING of the policy, which is precisely the
-- class of change this migration exists to make impossible.
--
-- The predicate is `like '%*'`, not `like '%*%'`, because it must name exactly
-- the strings `tool_matches` treats as wildcards: a TRAILING `*` (prefix
-- match) or the bare `*` (matches everything, and which `'%*'` also covers).
-- A `*` anywhere ELSE — `fo*o` — is not special to `tool_matches`, so such an
-- entry folds to an exact-equality rule that means precisely what the override
-- meant. Dropping it would narrow for no reason.
--
-- EXACT SCOPE, stated honestly: dropping preserves every verdict for every
-- tool whose LITERAL NAME DOES NOT END IN `*` — which is every tool anyone
-- would name. For a tool that DOES (tool names are not constrained; an MCP
-- server names its own), the entry used to decide by exact equality and now
-- does not, so the verdict falls through to the rules. That can go EITHER WAY,
-- including WIDER (override `deny` + policy default `allow` ⇒ allow). This is
-- NOT "always fail-safe", and fluidbox-core's
-- `a_wildcard_override_diverges_only_for_star_suffixed_tool_names` pins the
-- divergence with exactly that input so the claim cannot drift.
--
-- Dropping is still the right side of the trade, on BLAST RADIUS rather than
-- direction: dropping can move the verdict for the ONE literal name, keeping
-- moves it for an entire namespace. The API never allowed such an entry
-- (`validate()` refused wildcard overrides from the day the column shipped),
-- so reaching this at all takes a hand-edited database — which is also why the
-- warning above exists rather than a silent rewrite.
do $$
declare v record; v_n int := 0;
begin
    for v in
        select p.id, p.name, o.value->>'tool' as tool
          from policies p
          cross join lateral jsonb_array_elements(p.managed_overrides) o
         where o.value->>'tool' like '%*'
    loop
        raise warning 'migration 0026: policy % (%) carried a TRAILING-WILDCARD managed override for %; it was unreachable under exact-name matching and has been dropped rather than folded into a wildcard rule (which would widen the policy)',
            v.id, v.name, v.tool;
        v_n := v_n + 1;
    end loop;
    if v_n > 0 then
        update policies p
           set managed_overrides = coalesce(
                 (select jsonb_agg(o.value order by o.ord)
                    from jsonb_array_elements(p.managed_overrides) with ordinality o(value, ord)
                   where o.value->>'tool' not like '%*'),
                 '[]'::jsonb)
         where exists (select 1 from jsonb_array_elements(p.managed_overrides) o
                        where o.value->>'tool' like '%*');
    end if;
end $$;

-- Composite-FK target on the parent (0012's `unique (tenant_id, id)` pattern —
-- the 0013/0019/0022 child-table precedent).
alter table policies add constraint policies_tenant_id_id_key unique (tenant_id, id);

create table policy_versions (
    id              uuid primary key,
    tenant_id       uuid not null references tenants(id),
    policy_id       uuid not null,
    version         int  not null check (version > 0),
    -- The canonical Policy document. Structure is the source of truth; YAML is
    -- an interchange format (design §4.1).
    content         jsonb not null,
    -- Verbatim YAML when this version arrived as YAML (seed / POST /v1/policies);
    -- null for structured publishes — export regenerates from `content`.
    yaml_source     text,
    -- Publish note; null for seeds and imports.
    summary         text,
    -- Provenance channel (design §3). CONSTRAINED, not merely documented: the
    -- dashboard renders one label per channel and falls back to "dashboard",
    -- so an unconstrained column would let a typo'd channel silently
    -- mis-attribute a version in the audit trail. The acting USER, when one
    -- exists, is the column below — multi-user shipped after the design froze
    -- this as text precisely so a principal could ride alongside without a
    -- migration.
    author          text not null check (author in ('seed', 'api', 'ui', 'import')),
    -- The authenticated user behind an api/ui version; null for the operator
    -- token, seeds, and the 0026 import. Deliberately NO foreign key (the 0012
    -- `sessions.invoked_by_user_id` precedent: history may outlive users).
    author_user_id  uuid,
    created_at      timestamptz not null default now(),
    unique (policy_id, version),
    -- ONE parent FK, the composite (0022's shape): it both anchors the row to
    -- its policy AND proves the version cannot point at another tenant's
    -- policy — a second direct `references policies(id)` would only re-check
    -- the same relationship on every write.
    foreign key (tenant_id, policy_id) references policies (tenant_id, id) on delete cascade
);

-- Backfill: today's single mutable row becomes one immutable version, keeping
-- the odometer's number. Overrides are PREPENDED as head rules in stored order
-- — exactly where `evaluate_supervised` consulted them — and the legacy
-- `managed_overrides` key is stripped from the canonical content.
--
-- `yaml_source` survives ONLY when there was nothing to fold: the authored
-- YAML never contained the overrides (0010 kept them in their own column), so
-- for a folded policy the stored YAML would DESCRIBE A DIFFERENT POLICY than
-- the canonical content — and the export/history endpoint prefers stored YAML.
-- NULL makes export regenerate from the folded truth; the un-folded majority
-- keeps its authored comments.
insert into policy_versions
    (id, tenant_id, policy_id, version, content, yaml_source, summary, author)
select
  gen_random_uuid(), p.tenant_id, p.id, p.version,
  jsonb_set(
    (p.parsed - 'managed_overrides'), '{tools}',
    coalesce(
      (select jsonb_agg(jsonb_build_object('match', jsonb_build_array(o->>'tool'),
                                           'action', o->'action')
                        order by ord)
         from jsonb_array_elements(p.managed_overrides) with ordinality t(o, ord)),
      '[]'::jsonb
    ) || coalesce(p.parsed->'tools', '[]'::jsonb),
    true
  ),
  case when jsonb_array_length(p.managed_overrides) = 0 then p.yaml_source end,
  'migrated from 0010 managed_overrides', 'import'
from policies p;

-- Drop what moved or is superseded. `version` lives on the version row now;
-- `parsed`/`yaml_source` live on `content`/`yaml_source` there; the 0010
-- override column dies with its feature.
alter table policies drop column yaml_source;
alter table policies drop column parsed;
alter table policies drop column managed_overrides;
alter table policies drop column version;

-- ─── RLS triple (0018's rule for a new tenant-owned table) ─────────────────
alter table policy_versions enable row level security;
alter table policy_versions force row level security;
-- 0018's section-(b) template VERBATIM — the predicate for a table that CARRIES
-- `tenant_id`, keyed directly on the GUC with the system_worker bypass arm.
--
-- Not the section-(c) child-EXISTS shape, even though this table has a parent:
-- (c) exists for children with NO tenant_id, where the parent FK is the only
-- expression of tenancy. Here `tenant_id` is present AND the composite FK below
-- proves it equals the parent's, so the direct predicate is both the cheaper
-- one (no correlated subquery per row, and `latest_policy_version` is on
-- `create_run`'s path) and the one a reader expects to find next to a
-- `tenant_id` column. Isolation is unchanged and closes both ways: a row naming
-- another tenant fails THIS predicate, and a row naming our tenant but a
-- stranger's policy fails the composite FK.
create policy tenant_isolation on policy_versions as permissive for all to public
    using (tenant_id::text = current_setting('fluidbox.tenant_id', true)
           or current_setting('fluidbox.bypass', true) = 'system_worker')
    with check (tenant_id::text = current_setting('fluidbox.tenant_id', true)
           or current_setting('fluidbox.bypass', true) = 'system_worker');

-- Enumerated DML grant to the deployment's runtime role (resolved from the
-- session GUC `fluidbox.runtime_role`, default `fluidbox_runtime` — NEVER
-- hardcoded). DELIBERATELY select+insert ONLY — no update, no delete: history
-- is append-only, and here that is a DATABASE property, not an application
-- convention (the 0012 auth_audit_log posture). The one sanctioned erasure
-- path is deleting the parent policy through the composite FK's cascade — and
-- no application surface deletes policies today.
do $$
declare
    v_role text := coalesce(nullif(current_setting('fluidbox.runtime_role', true), ''),
                            'fluidbox_runtime');
begin
    if exists (select 1 from pg_roles where rolname = v_role) then
        execute format('grant select, insert on table policy_versions to %I', v_role);
    end if;
end $$;
