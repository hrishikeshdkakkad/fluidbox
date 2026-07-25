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
-- post-0026 database). Since migrations run on the new binary's boot, the
-- ordinary single-binary deploy already satisfies the order.

set local lock_timeout = '5s';

-- This is the first DATA-BACKFILLING migration since 0018 ENABLE+FORCEd RLS on
-- `policies`. The migration connection carries no tenant GUC, so without the
-- audited bypass the backfill's `select … from policies` would read ZERO rows
-- — silently: an empty backfill, not an error. Transaction-local by
-- construction (sqlx runs each migration file in one transaction; the
-- `set local` above relies on the same fact).
select set_config('fluidbox.bypass', 'system_worker', true);

-- Preflight: the fold below trusts `managed_overrides` to be an array of
-- {"tool": <text>, "action": "allow"|"approve"|"deny"} rows (the shape the
-- retired write path enforced). A malformed value would abort mid-fold with an
-- error naming no policy — fail HERE, naming the row, instead.
do $$
declare bad record;
begin
    select p.id, p.name into bad
      from policies p
     where jsonb_typeof(p.managed_overrides) is distinct from 'array'
        or exists (
            select 1 from jsonb_array_elements(p.managed_overrides) o
             where jsonb_typeof(o->'tool') is distinct from 'string'
                or o->>'action' not in ('allow', 'approve', 'deny'))
     limit 1;
    if found then
        raise exception 'migration 0026: policy % (%) carries a malformed managed_overrides value; repair it before migrating', bad.id, bad.name;
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
    -- Provenance channel: 'seed' | 'api' | 'ui' | 'import' (design §3). The
    -- acting USER, when one exists, is the column below — multi-user shipped
    -- after the design froze this as text precisely so a principal could ride
    -- alongside without a migration.
    author          text not null,
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
  p.yaml_source, 'migrated from 0010 managed_overrides', 'import'
from policies p;

-- Drop what moved or is superseded. `version` lives on the version row now;
-- `parsed`/`yaml_source` live on `content`/`yaml_source` there; the 0010
-- override column dies with its feature.
alter table policies drop column yaml_source;
alter table policies drop column parsed;
alter table policies drop column managed_overrides;
alter table policies drop column version;

-- ─── RLS triple (0018's rule for a new tenant-owned table; 0022 template) ───
alter table policy_versions enable row level security;
alter table policy_versions force row level security;
-- Child-EXISTS: the parent `policies` policy composes through the subquery (it
-- runs under RLS too), so a version is visible/writable iff its policy is, and
-- the system_worker bypass opens the parent (and thus the child).
create policy tenant_isolation on policy_versions as permissive for all to public
    using (exists (select 1 from policies p where p.id = policy_versions.policy_id))
    with check (exists (select 1 from policies p where p.id = policy_versions.policy_id));

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
