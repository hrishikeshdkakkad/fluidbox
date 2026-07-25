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
-- DEPLOY ORDER: stop-the-old-binary, migrate, then deploy (the 0018 posture).
-- An old binary `select *`s columns this migration drops, so it cannot serve
-- beside it — and since migrations run on the new binary's boot, the ordinary
-- single-binary deploy already satisfies this.

set local lock_timeout = '5s';

-- This is the first DATA-BACKFILLING migration since 0018 ENABLE+FORCEd RLS on
-- `policies` and `sessions`. The migration connection carries no tenant GUC, so
-- without the audited bypass the backfill's `select … from policies` would read
-- ZERO rows (silently — an empty backfill, not an error) and the in-flight
-- snapshot fold below would update nothing. Transaction-local by construction
-- (sqlx runs each migration file in one transaction; `set local` above relies
-- on the same fact).
select set_config('fluidbox.bypass', 'system_worker', true);

-- Composite-FK target on the parent (0012's `unique (tenant_id, id)` pattern —
-- the 0013/0019/0022 child-table precedent).
alter table policies add constraint policies_tenant_id_id_key unique (tenant_id, id);

create table policy_versions (
    id              uuid primary key,
    tenant_id       uuid not null references tenants(id),
    policy_id       uuid not null references policies(id) on delete cascade,
    version         int  not null,
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

-- In-flight runs: the engine no longer reads `managed_overrides`, so a
-- NON-TERMINAL session whose frozen snapshot carries overrides would silently
-- change verdicts at its next tool call. Fold those snapshots with the SAME
-- verdict-preserving transform — the run's law is unchanged in meaning, only
-- in representation. TERMINAL sessions stay byte-identical: a completed run's
-- audit record is never rewritten (the fold's `where` is the state machine's
-- terminal vocabulary, fluidbox-core::state).
update sessions s
   set run_spec = jsonb_set(
     s.run_spec, '{policy_snapshot}',
     jsonb_set(
       (s.run_spec->'policy_snapshot') - 'managed_overrides', '{tools}',
       coalesce(
         (select jsonb_agg(jsonb_build_object('match', jsonb_build_array(o->>'tool'),
                                              'action', o->'action')
                           order by ord)
            from jsonb_array_elements(s.run_spec->'policy_snapshot'->'managed_overrides')
                 with ordinality t(o, ord)),
         '[]'::jsonb
       ) || coalesce(s.run_spec->'policy_snapshot'->'tools', '[]'::jsonb),
       true
     ),
     false
   )
 where s.status not in ('completed', 'failed', 'cancelled', 'budget_exceeded')
   and jsonb_array_length(coalesce(s.run_spec->'policy_snapshot'->'managed_overrides',
                                   '[]'::jsonb)) > 0;

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
-- hardcoded). Copied from 0018 (e) via the 0022 template.
do $$
declare
    v_role text := coalesce(nullif(current_setting('fluidbox.runtime_role', true), ''),
                            'fluidbox_runtime');
begin
    if exists (select 1 from pg_roles where rolname = v_role) then
        execute format('grant select, insert, update, delete on table policy_versions to %I', v_role);
    end if;
end $$;
