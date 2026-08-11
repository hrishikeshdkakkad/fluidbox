-- Backfill the `default` policy into every existing tenant.
-- Design: docs/superpowers/specs/2026-08-11-tiered-policies-design.md
--
-- WHY THIS EXISTS SEPARATELY FROM 0029. 0029 seeded only the three new tiers,
-- deliberately: `default` already existed for the boot tenant and the migration
-- had no business inventing one elsewhere. But a NON-boot tenant never had it
-- either -- `seed::run` only ever seeds the boot tenant -- so every org created
-- before the create_org fix holds the tiers and no `default`, and an agent
-- revision pointing at it fails closed at `create_run`, where the policy is
-- resolved. 0029 is already applied and sqlx checksums it, so this is a NEW
-- file rather than an edit: that is how seeded policy data evolves.
--
-- WHY THE BYPASS: a migration connection carries NO tenant GUC, and `policies`
-- is ENABLE+FORCE RLS keyed on current_setting('fluidbox.tenant_id'). Without
-- the audited system-worker bypass this reads and writes ZERO rows -- silently.
set local fluidbox.bypass = 'system_worker';

-- ADDITIVE, and NON-DESTRUCTIVE to any existing `default`: ON CONFLICT makes
-- the insert a no-op for a tenant that already has one -- including the boot
-- tenant's, and any an operator has since edited through the Governance page --
-- and only rows this migration actually CREATED come back through `created`, so
-- only they get a version row. Re-running is inert.
--
-- Same rolling-deploy residual as 0029: under RollingUpdate an old pod can
-- create an org after this records, and that org gets nothing. Repair is a
-- re-seed of the tenant, never an edit to this file.
with seed_doc(name, content) as (
  values
    ('default', '{"name":"default","defaults":{"tool_action":"approve"},"egress":{"mode":"proxy-only"},"budgets":{"max_wall_clock_secs":1800,"max_tokens":1000000,"max_cost_usd":2.5,"max_tool_calls":100},"approvals":{"default_ttl_secs":600,"scope":"once","timeout_action":"deny"},"autonomy":{"permitted":true,"on_approval_rule":"deny"},"tools":[{"match":["Read","Glob","Grep","LS","TodoWrite","NotebookRead","ToolSearch","EnterPlanMode","ExitPlanMode","AskUserQuestion","ReportFindings","TaskGet","TaskList","TaskOutput","CronList"],"action":"allow","risk":null,"paths":null,"shell":null,"on_autonomous":null,"approval_ttl_secs":null,"approval_scope":null},{"match":["Agent","Task","Workflow","Skill","TaskCreate"],"action":"deny","risk":"spawns sub-execution whose nested tool calls the gate may never see","paths":null,"shell":null,"on_autonomous":null,"approval_ttl_secs":null,"approval_scope":null},{"match":["Edit","Write","MultiEdit","NotebookEdit"],"action":"allow","risk":null,"paths":{"allow":["/workspace/**"],"deny":["**/.env","**/.env.*","**/.git/config","**/.git/hooks/**"]},"shell":null,"on_autonomous":null,"approval_ttl_secs":null,"approval_scope":null},{"match":["Bash","BashOutput","KillShell"],"action":"allow","risk":null,"paths":null,"shell":{"allow_prefixes":["ls","cat","head","tail","wc","grep","rg","find","pwd","echo","which","env | grep","python","python3","pytest","pip install -r","node","npm test","npm run test","npx jest","npx vitest","cargo test","cargo build","cargo check","go test","make test","git status","git diff","git log","git add","git commit","git show","cd","mkdir","touch","mv","cp","sed","awk","diff","sort","uniq","cut","tr","stat","file","du","printf","basename","dirname","date"],"deny_regex":["rm\\s+(-[a-z]+\\s+)*-[a-z]*r[a-z]*(\\s+-[a-z]+)*\\s+/\\*?(\\s|$)","\\bcurl\\b","\\bwget\\b","\\bnc\\b","\\bssh\\b","\\bscp\\b","git\\s+push\\b.*\\s(--force(-with-lease)?|-f)\\b","\\bsudo\\b","/etc/passwd","\\bchmod\\s+777\\b"],"on_no_match":"approve"},"on_autonomous":null,"approval_ttl_secs":null,"approval_scope":null},{"match":["WebFetch","WebSearch","DesignSync","Monitor"],"action":"deny","risk":"network egress from sandbox","paths":null,"shell":null,"on_autonomous":null,"approval_ttl_secs":null,"approval_scope":null},{"match":["TaskStop","TaskUpdate","SendMessage","CronCreate","CronDelete","ScheduleWakeup","PushNotification","EnterWorktree","ExitWorktree"],"action":"approve","risk":"effect outside this run''s disposable workspace","paths":null,"shell":null,"on_autonomous":null,"approval_ttl_secs":null,"approval_scope":null},{"match":["mcp__*"],"action":"approve","risk":"unreviewed MCP tool","paths":null,"shell":null,"on_autonomous":null,"approval_ttl_secs":null,"approval_scope":null}]}'::jsonb)
),
created as (
  insert into policies (id, tenant_id, name)
  select gen_random_uuid(), t.id, seed_doc.name
    from tenants t cross join seed_doc
  on conflict (tenant_id, name) do nothing
  returning id, tenant_id, name
)
insert into policy_versions
  (id, tenant_id, policy_id, version, content, yaml_source, summary, author)
select gen_random_uuid(), c.tenant_id, c.id, 1, seed_doc.content, null,
       'seeded default policy', 'seed'
  from created c join seed_doc on seed_doc.name = c.name;
