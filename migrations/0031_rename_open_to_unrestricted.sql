-- Rename the `open` tier to `unrestricted`.
-- Design: docs/superpowers/specs/2026-08-11-tiered-policies-design.md
--
-- WHY. The dashboard's "Free rein" preset resolves a policy by the LITERAL name
-- `unrestricted` and disables itself when none exists, rather than inventing one
-- (apps/web/app/components/RunComposer.tsx). The tier shipped as `open` in 0029,
-- so the preset stayed greyed out even though a fully-permissive policy existed.
-- The name is a contract with the UI; the policy conforms to it, not the reverse.
--
-- WHY A RENAME AND NOT DELETE+INSERT. Agent revisions reference a policy by ID.
-- Dropping and re-creating would break every revision pointing at it -- and one
-- already did when this was written. UPDATE preserves the id, so agents keep
-- working, and frozen RunSpec snapshots (which legitimately still say "open",
-- because that is what governed those runs) stay untouched.
--
-- WHY THE BYPASS: a migration connection carries NO tenant GUC, and `policies`
-- is ENABLE+FORCE RLS keyed on current_setting('fluidbox.tenant_id'). Without
-- the audited system-worker bypass this updates ZERO rows -- silently.
set local fluidbox.bypass = 'system_worker';

-- Idempotent and conflict-safe: skips any tenant that somehow already has an
-- `unrestricted` policy (the unique index on (tenant_id, name) would otherwise
-- abort the whole migration), and a re-run finds no `open` left to rename.
with doc(name, content) as (
  values
    ('unrestricted', '{"name":"unrestricted","defaults":{"tool_action":"allow"},"egress":{"mode":"proxy-only"},"network":{"max_mode":"public","allow":[],"deny":[],"require_approval":false,"allow_public_with_brokered":true,"max_grant_secs":null},"budgets":{"max_wall_clock_secs":7200,"max_tokens":null,"max_cost_usd":25.0,"max_tool_calls":null},"approvals":{"default_ttl_secs":600,"scope":"session","timeout_action":"deny"},"autonomy":{"permitted":true,"on_approval_rule":"allow"},"tools":[]}'::jsonb)
),
renamed as (
  update policies p
     set name = 'unrestricted', updated_at = now()
   where p.name = 'open'
     and not exists (
       select 1 from policies o
        where o.tenant_id = p.tenant_id and o.name = 'unrestricted')
  returning p.id
)
-- Only untouched seeds: an operator-edited version keeps its content. This
-- brings the stored document's own `name` field in line with the row's.
update policy_versions pv
   set content = doc.content
  from renamed r, doc
 where pv.policy_id = r.id
   and pv.author = 'seed'
   and pv.content->>'name' = 'open';
