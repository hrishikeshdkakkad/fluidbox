-- Enterprise Recipes (design docs/plans/2026-07-31-enterprise-recipes-design.md).
--
-- Four tables:
--   recipes                  catalog identity — global curated rows (tenant_id NULL,
--                            tier 'official', seeded here) + tenant custom rows
--                            (tier forced 'custom' by the API), the connector_catalog
--                            split (0007/0013) applied to recipes.
--   recipe_versions          append-only content: the stamp `definition` + the frozen
--                            `params_schema` per version (the policy_versions shape).
--   recipe_instances         a tenant's deployment of a recipe version: provenance
--                            (slug + version + params digest) + lifecycle status.
--                            Instances are DETACHED from the recipe after stamping —
--                            upgrade is explicit and manual, never a re-render.
--   recipe_instance_objects  provenance links to every stamped object (policy /
--                            agent / subscription / session), keyed by recipe slot.
--
-- The stamped objects themselves are ordinary rows in their own tables, created
-- through the existing creators inside ONE transaction (the deploy engine's
-- atomic stamp) — this migration adds no new execution or permission surface.
--
-- RLS follows the 0018 rule set: recipes + recipe_versions get the MIXED
-- catalog policies (global rows readable by every scope, writable only via the
-- audited bypass); instances + objects get the standard tenant_isolation
-- policy. Grants are enumerated per table against the deployment's runtime
-- role (session GUC fluidbox.runtime_role, default fluidbox_runtime), exactly
-- the 0026 shape.

set local lock_timeout = '5s';

-- Uniform with 0026: seeds below INSERT global rows after FORCE RLS is enabled
-- in this same file would need the bypass arm; setting it up front keeps the
-- statement order in this file free to change without silently writing zero
-- rows. Transaction-local (sqlx runs each migration in one transaction).
select set_config('fluidbox.bypass', 'system_worker', true);

-- ─── Tables ─────────────────────────────────────────────────────────────────

create table recipes (
    id          uuid primary key,
    -- NULL = deployment-global curated row; set = a tenant's custom recipe.
    tenant_id   uuid references tenants(id),
    slug        text not null,
    name        text not null,
    tagline     text not null default '',
    description text not null default '',
    category    text not null default 'general',
    tags        jsonb not null default '[]',
    tier        text not null default 'custom' check (tier in ('official', 'custom')),
    icon        text not null default 'custom',
    created_at  timestamptz not null default now(),
    updated_at  timestamptz not null default now(),
    -- Soft-disable (the connector_catalog convention): a disabled recipe stops
    -- listing and deploying; history and instances remain intact.
    disabled_at timestamptz
);
-- One global namespace + one per-tenant namespace (a tenant custom row may
-- shadow a global slug — list/get prefer the tenant row, like the catalog).
create unique index recipes_global_slug_key on recipes (slug) where tenant_id is null;
create unique index recipes_tenant_slug_key on recipes (tenant_id, slug) where tenant_id is not null;

create table recipe_versions (
    id            uuid primary key,
    -- Matches the parent recipe's tenant (NULL for curated rows). Kept
    -- denormalized for the RLS predicate; app code + the parent FK keep it
    -- consistent. No composite (tenant_id, recipe_id) FK here — 0026's shape
    -- assumes NOT NULL tenants, and a NULL tenant_id would silently unenforce
    -- a composite FK (MATCH SIMPLE), so the plain parent FK is the honest one.
    tenant_id     uuid references tenants(id),
    recipe_id     uuid not null references recipes(id) on delete cascade,
    version       int  not null check (version > 0),
    -- The stamp plan (fluidbox-core::recipe::RecipeDefinition, strict-parsed).
    definition    jsonb not null,
    -- The frozen parameter contract (JSON Schema 2020-12 + x-fluidbox widget
    -- annotations). Validation is reproducible per version forever.
    params_schema jsonb not null,
    changelog     text,
    author        text not null check (author in ('seed', 'api')),
    created_at    timestamptz not null default now(),
    unique (recipe_id, version)
);

create table recipe_instances (
    id                 uuid primary key,
    tenant_id          uuid not null references tenants(id),
    recipe_id          uuid not null references recipes(id),
    -- Denormalized provenance: survives recipe renames and keeps the audit
    -- record self-describing.
    recipe_slug        text not null,
    recipe_version     int  not null,
    name               text not null,
    -- The RAW user-supplied params (defaults applied), never secrets —
    -- reference params store ids of existing sealed objects.
    params             jsonb not null default '{}',
    params_digest      text  not null default '',
    status             text  not null default 'active'
                       check (status in ('active', 'paused', 'deleted')),
    created_by_user_id uuid,
    created_at         timestamptz not null default now(),
    updated_at         timestamptz not null default now(),
    deleted_at         timestamptz
);
-- Live instance names are unique per tenant: the practical idempotency guard
-- for deploys (a retried deploy after failure is clean — the stamp is atomic —
-- and a duplicate name after success is a clear 409).
create unique index recipe_instances_live_name_key
    on recipe_instances (tenant_id, name) where deleted_at is null;
create index recipe_instances_tenant_created_idx
    on recipe_instances (tenant_id, created_at desc);

create table recipe_instance_objects (
    id          uuid primary key,
    tenant_id   uuid not null references tenants(id),
    instance_id uuid not null references recipe_instances(id) on delete cascade,
    kind        text not null check (kind in ('policy', 'agent', 'subscription', 'session')),
    object_id   uuid not null,
    slot        text not null default '',
    created_at  timestamptz not null default now()
);
create index recipe_instance_objects_instance_idx on recipe_instance_objects (instance_id);

-- ─── RLS (the 0018 rule: enable+force, policy, enumerated grant) ───────────

alter table recipes enable row level security;
alter table recipes force row level security;
alter table recipe_versions enable row level security;
alter table recipe_versions force row level security;
alter table recipe_instances enable row level security;
alter table recipe_instances force row level security;
alter table recipe_instance_objects enable row level security;
alter table recipe_instance_objects force row level security;

-- recipes / recipe_versions: the MIXED shape (0018 section on connector_catalog).
-- Read = global-or-mine-or-bypass; write = mine-or-bypass (global curated rows
-- mutate only through the audited bypass / migrations).
create policy recipe_read on recipes as permissive for select to public
    using (tenant_id is null
           or tenant_id::text = current_setting('fluidbox.tenant_id', true)
           or current_setting('fluidbox.bypass', true) = 'system_worker');
create policy recipe_insert on recipes as permissive for insert to public
    with check (tenant_id::text = current_setting('fluidbox.tenant_id', true)
           or current_setting('fluidbox.bypass', true) = 'system_worker');
create policy recipe_update on recipes as permissive for update to public
    using (tenant_id::text = current_setting('fluidbox.tenant_id', true)
           or current_setting('fluidbox.bypass', true) = 'system_worker')
    with check (tenant_id::text = current_setting('fluidbox.tenant_id', true)
           or current_setting('fluidbox.bypass', true) = 'system_worker');
create policy recipe_delete on recipes as permissive for delete to public
    using (tenant_id::text = current_setting('fluidbox.tenant_id', true)
           or current_setting('fluidbox.bypass', true) = 'system_worker');

create policy recipe_version_read on recipe_versions as permissive for select to public
    using (tenant_id is null
           or tenant_id::text = current_setting('fluidbox.tenant_id', true)
           or current_setting('fluidbox.bypass', true) = 'system_worker');
-- Versions are append-only: INSERT is the only write policy. There is
-- deliberately no update/delete policy — history is immutable at the DATABASE
-- level (the 0026 posture); the one erasure path is the parent-recipe cascade,
-- which referential actions perform outside RLS.
create policy recipe_version_insert on recipe_versions as permissive for insert to public
    with check (tenant_id::text = current_setting('fluidbox.tenant_id', true)
           or current_setting('fluidbox.bypass', true) = 'system_worker');

-- instances / objects: standard tenant isolation (0026's verbatim shape).
create policy tenant_isolation on recipe_instances as permissive for all to public
    using (tenant_id::text = current_setting('fluidbox.tenant_id', true)
           or current_setting('fluidbox.bypass', true) = 'system_worker')
    with check (tenant_id::text = current_setting('fluidbox.tenant_id', true)
           or current_setting('fluidbox.bypass', true) = 'system_worker');
create policy tenant_isolation on recipe_instance_objects as permissive for all to public
    using (tenant_id::text = current_setting('fluidbox.tenant_id', true)
           or current_setting('fluidbox.bypass', true) = 'system_worker')
    with check (tenant_id::text = current_setting('fluidbox.tenant_id', true)
           or current_setting('fluidbox.bypass', true) = 'system_worker');

-- Enumerated DML grants to the deployment's runtime role (resolved from the
-- session GUC — never hardcoded). recipe_versions is select+insert ONLY
-- (append-only history); recipes/instances have no DELETE (soft lifecycle);
-- instance objects are insert-only links that die with their instance's
-- cascade (which runs outside the grant system).
do $$
declare
    v_role text := coalesce(nullif(current_setting('fluidbox.runtime_role', true), ''),
                            'fluidbox_runtime');
begin
    if exists (select 1 from pg_roles where rolname = v_role) then
        execute format('grant select, insert, update on table recipes to %I', v_role);
        execute format('grant select, insert on table recipe_versions to %I', v_role);
        execute format('grant select, insert, update on table recipe_instances to %I', v_role);
        execute format('grant select, insert on table recipe_instance_objects to %I', v_role);
    end if;
end $$;

-- ─── Seed: the v1 official catalog (five recipes) ──────────────────────────
--
-- Seeded by migration, API-managed afterward — the connector_catalog
-- convention (no seed file, no boot sync). Definitions are strict
-- fluidbox-core::recipe::RecipeDefinition documents; params_schema is JSON
-- Schema 2020-12 with x-fluidbox widget annotations. A fluidbox-db test
-- re-validates every seeded row against the parser so these blobs cannot
-- drift from the Rust types unnoticed.

insert into recipes (id, tenant_id, slug, name, tagline, description, category, tags, tier, icon)
values
('5eed0001-0000-4000-8000-000000000001', null, 'pr-review-panel', 'PR review panel',
 'Three specialized reviewers on every pull request',
 'A multi-agent review panel: correctness, security, and test-coverage reviewers each run in their own governed sandbox on every opened pull request. The correctness lead maintains one stable PR comment; every reviewer publishes its own commit check. Fork PRs are automatically frozen read-only.',
 'code-review', '["github", "multi-agent", "pull-requests"]', 'official', 'review'),
('5eed0001-0000-4000-8000-000000000002', null, 'ci-failure-triage', 'CI failure triage',
 'Root-cause a red CI run and propose the fix',
 'Wire your CI to call this recipe when a run goes red: the agent checks out the repository, reproduces the failure, identifies the root cause, and proposes a minimal fix as a reviewable diff. Results return over a signed webhook or the poll endpoint.',
 'ci-cd', '["github", "ci", "automation"]', 'official', 'triage'),
('5eed0001-0000-4000-8000-000000000003', null, 'repo-compliance-sweep', 'Repo compliance sweep',
 'Scheduled hygiene report: secrets, licenses, ownership',
 'A scheduled sweep of a repository for committed credentials, license-header coverage, CODEOWNERS gaps, and dependency lockfile drift. Produces a prioritized findings report on the timeline (and a signed webhook if configured). Read-only by policy.',
 'compliance', '["github", "schedule", "security"]', 'official', 'sweep'),
('5eed0001-0000-4000-8000-000000000004', null, 'ticket-investigator', 'Ticket investigator',
 'Investigate tickets against the codebase via your ticketing MCP',
 'Connect a ticketing MCP server (Jira, ServiceNow, Linear-class): invoked with a ticket id, the agent fetches the ticket through the governed broker (credentials never enter the sandbox), correlates it with the checked-out codebase, and reports root cause and suggested next actions. Supervised by design — autonomous runs are refused by its policy.',
 'support', '["mcp", "tickets", "investigation"]', 'official', 'tickets'),
('5eed0001-0000-4000-8000-000000000005', null, 'codebase-brief', 'Codebase brief',
 'Ask one question, get an architecture-grade answer',
 'Deploys a question-answering agent over a repository and fires the first run immediately. Ask how a subsystem works, where an invariant is enforced, or what a change would touch — the brief lands on the run timeline with file references. Re-ask any time through the run action or the API trigger.',
 'onboarding', '["github", "docs", "q-and-a"]', 'official', 'brief');

-- 1) pr-review-panel ────────────────────────────────────────────────────────
insert into recipe_versions (id, tenant_id, recipe_id, version, definition, params_schema, changelog, author)
values (gen_random_uuid(), null, '5eed0001-0000-4000-8000-000000000001', 1,
$fbx${
  "schema": 1,
  "summary_md": "Every opened pull request gets three independent, sandboxed reviewers — correctness, security, and test coverage. Each reviewer sees a fresh checkout of the PR head, may run read-only inspection commands and the test suite, and cannot write files or reach any integration. The correctness lead keeps one stable comment on the PR; all three publish commit checks named after their automation. Fork PRs are frozen to the read-only trust tier by the platform before any policy runs.",
  "success_criteria": [
    "Every opened or reopened pull request in the selected repositories receives all three panel verdicts",
    "The correctness reviewer maintains exactly one up-to-date summary comment per pull request",
    "No reviewer ever modifies the repository or calls an external integration"
  ],
  "policy": { "content": {
    "name": "pr-review-panel",
    "defaults": { "tool_action": "deny" },
    "budgets": { "max_wall_clock_secs": 900, "max_cost_usd": 1.0, "max_tool_calls": 80 },
    "autonomy": { "permitted": true, "on_approval_rule": "deny" },
    "tools": [
      { "match": ["Read", "Glob", "Grep", "LS"], "action": "allow", "risk": "low" },
      { "match": ["Bash"], "action": "allow",
        "shell": { "allow_prefixes": ["ls", "cat", "head", "tail", "grep", "rg", "find", "wc", "git log", "git show", "git diff", "git status", "git branch", "cargo check", "cargo test", "npm test", "pnpm test", "npx vitest", "pytest", "go test", "make test"],
                   "on_no_match": "deny" } },
      { "match": ["Edit", "Write", "MultiEdit"], "action": "deny" },
      { "match": ["mcp__*"], "action": "deny" }
    ]
  } },
  "agents": [
    { "slot": "correctness",
      "name": "{{instance.name}} · correctness",
      "harness": "claude-agent-sdk",
      "model": "$param:model",
      "budgets": { "max_cost_usd": 1.0, "max_wall_clock_secs": 900, "max_tool_calls": 80 },
      "system_prompt": "You are the correctness lead of a pull-request review panel. Review the diff between the base and head of the checked-out pull request for logic errors, broken invariants, unhandled edge cases, API-contract violations, and regressions. Read the surrounding code before judging a hunk — a change that looks wrong in isolation may be right in context, and vice versa. Run the test suite when one exists and weigh failures. Report findings as a prioritized list: each with file:line, what breaks, a concrete failure scenario, and a suggested fix. If the change is sound, say so plainly and name the risks you checked. You are the panel lead: end with a one-paragraph verdict (approve / request changes) that a busy maintainer can act on." },
    { "slot": "security",
      "name": "{{instance.name}} · security",
      "harness": "claude-agent-sdk",
      "model": "$param:model",
      "budgets": { "max_cost_usd": 1.0, "max_wall_clock_secs": 900, "max_tool_calls": 80 },
      "system_prompt": "You are the security reviewer of a pull-request review panel. Review the pull request diff for vulnerabilities and security regressions: injection (SQL, shell, template), path traversal, SSRF, insecure deserialization, secrets or credentials in code or config, authentication and authorization gaps, unsafe defaults, weakened validation, and dependency risks visible in lockfile changes. Trace untrusted input from its entry point to every sink the diff touches. Report only findings you can ground in the code — each with file:line, the attack path, impact, and a concrete remediation. If nothing is exploitable, state that and list what you verified." },
    { "slot": "tests",
      "name": "{{instance.name}} · test coverage",
      "harness": "claude-agent-sdk",
      "model": "$param:model",
      "budgets": { "max_cost_usd": 1.0, "max_wall_clock_secs": 900, "max_tool_calls": 80 },
      "system_prompt": "You are the test-coverage reviewer of a pull-request review panel. Determine whether the pull request's behavior changes are adequately tested. Map each changed behavior to the tests that exercise it; run the suite when one exists. Flag: new logic with no covering test, edge cases the tests skip (error paths, boundaries, concurrency), tests that assert too little to catch a plausible regression, and deleted or weakened assertions. For each gap, name the exact test file and the case to add, with a sketch of the assertion. Distinguish must-add gaps from nice-to-have hardening." }
  ],
  "subscriptions": [
    { "slot": "panel-correctness",
      "agent_slot": "correctness",
      "kind": "event",
      "name": "{{instance.name}} · correctness",
      "connection": "$param:github_connection",
      "repositories": "$param:repositories",
      "events": "$param:events",
      "publish": ["pr_comment", "check"],
      "autonomous": true,
      "concurrency_policy": "allow",
      "task_template": "Review pull request #{{pr_number}} ({{pr_title}}) of {{repository}} at head {{head_sha}}. The PR is checked out in /workspace. Compare against base {{base_sha}}. PR: {{pr_url}}" },
    { "slot": "panel-security",
      "agent_slot": "security",
      "kind": "event",
      "name": "{{instance.name}} · security",
      "connection": "$param:github_connection",
      "repositories": "$param:repositories",
      "events": "$param:events",
      "publish": ["check"],
      "autonomous": true,
      "concurrency_policy": "allow",
      "task_template": "Security-review pull request #{{pr_number}} ({{pr_title}}) of {{repository}} at head {{head_sha}}. The PR is checked out in /workspace. Compare against base {{base_sha}}." },
    { "slot": "panel-tests",
      "agent_slot": "tests",
      "kind": "event",
      "name": "{{instance.name}} · tests",
      "connection": "$param:github_connection",
      "repositories": "$param:repositories",
      "events": "$param:events",
      "publish": ["check"],
      "autonomous": true,
      "concurrency_policy": "allow",
      "task_template": "Assess test coverage of pull request #{{pr_number}} ({{pr_title}}) of {{repository}} at head {{head_sha}}. The PR is checked out in /workspace. Compare against base {{base_sha}}." }
  ]
}$fbx$::jsonb,
$fbx${
  "type": "object",
  "additionalProperties": false,
  "required": ["github_connection", "repositories"],
  "properties": {
    "github_connection": {
      "type": "string",
      "title": "GitHub connection",
      "description": "The GitHub App connection whose repositories the panel reviews.",
      "x-fluidbox": { "widget": "connection", "provider": "github" }
    },
    "repositories": {
      "type": "array", "items": { "type": "string" }, "minItems": 1,
      "title": "Repositories",
      "description": "owner/name repositories the panel watches.",
      "x-fluidbox": { "widget": "repositories" }
    },
    "events": {
      "type": "array",
      "items": { "enum": ["opened", "reopened", "synchronize"] },
      "minItems": 1,
      "default": ["opened", "reopened"],
      "title": "Pull request events",
      "description": "synchronize fires on every push to an open PR — opt in deliberately.",
      "x-fluidbox": { "widget": "events" }
    },
    "model": {
      "type": "string",
      "enum": ["claude-haiku-4-5", "claude-sonnet-5", "claude-opus-4-8"],
      "default": "claude-haiku-4-5",
      "title": "Model",
      "x-fluidbox": { "widget": "model", "harness": "claude-agent-sdk" }
    }
  },
  "x-fluidbox-ui": { "order": ["github_connection", "repositories", "events", "model"] }
}$fbx$::jsonb,
'Initial version', 'seed');

-- 2) ci-failure-triage ──────────────────────────────────────────────────────
insert into recipe_versions (id, tenant_id, recipe_id, version, definition, params_schema, changelog, author)
values (gen_random_uuid(), null, '5eed0001-0000-4000-8000-000000000002', 1,
$fbx${
  "schema": 1,
  "summary_md": "An on-call triage agent your CI invokes when a run goes red. The invocation carries the failure context (log excerpt, commit, job name) as the task; the agent checks out the repository, reproduces the failure where possible, and proposes a minimal fix as a reviewable diff on the run timeline. Configure the signed webhook to route the verdict back into your incident tooling. The trigger token is the only credential your CI needs.",
  "success_criteria": [
    "Given a failing run's log excerpt and commit, the report names the root cause with file references",
    "Where a code fix applies, the run ends with a minimal diff artifact a human can review and apply",
    "Results reach the configured webhook (or poll endpoint) without anyone opening the dashboard"
  ],
  "policy": { "content": {
    "name": "ci-failure-triage",
    "defaults": { "tool_action": "deny" },
    "budgets": { "max_wall_clock_secs": 1200, "max_cost_usd": 1.5, "max_tool_calls": 100 },
    "autonomy": { "permitted": true, "on_approval_rule": "deny" },
    "tools": [
      { "match": ["Read", "Glob", "Grep", "LS"], "action": "allow", "risk": "low" },
      { "match": ["Edit", "Write", "MultiEdit"], "action": "allow",
        "risk": "medium" },
      { "match": ["Bash"], "action": "allow",
        "shell": { "allow_prefixes": ["ls", "cat", "head", "tail", "grep", "rg", "find", "wc", "git log", "git show", "git diff", "git status", "git bisect", "cargo build", "cargo check", "cargo test", "npm test", "npm run", "pnpm test", "pnpm run", "npx", "pytest", "python -m pytest", "go build", "go test", "make"],
                   "on_no_match": "deny" } },
      { "match": ["mcp__*"], "action": "deny" }
    ]
  } },
  "agents": [
    { "slot": "triager",
      "name": "{{instance.name}}",
      "harness": "claude-agent-sdk",
      "model": "$param:model",
      "budgets": { "max_cost_usd": 1.5, "max_wall_clock_secs": 1200, "max_tool_calls": 100 },
      "system_prompt": "You are a CI-failure triage engineer. You receive the context of a failing CI run for the repository checked out in /workspace. Work the failure like an on-call engineer: read the failure output carefully, locate the failing test or build step in the code, reproduce it locally when the toolchain allows, and identify the true root cause — not the first suspicious line. Distinguish product bugs, test bugs, flaky tests, and infrastructure failures, and say which this is. When a code fix applies, make the minimal change that fixes the cause (never weaken or delete a failing assertion to go green) and re-run the relevant tests to prove it. Your final report: root cause with file:line references, the category, what you changed and why it is safe, and what to do if this recurs." }
  ],
  "subscriptions": [
    { "slot": "invoke",
      "agent_slot": "triager",
      "kind": "api",
      "name": "{{instance.name}}",
      "allow_task_override": true,
      "allow_workspace_override": true,
      "autonomous": true,
      "concurrency_policy": "allow",
      "callback_url": "$param:callback_url",
      "workspace": { "kind": "git_repository",
                     "connection_id": "$param:github_connection",
                     "repository": "$param:repository" },
      "task_template": "Investigate the most recent failing CI run for this repository. Identify the failing step, reproduce it if possible, find the root cause, and propose a minimal fix. If the caller supplied no failure details, start from the test suite and recent commits." }
  ]
}$fbx$::jsonb,
$fbx${
  "type": "object",
  "additionalProperties": false,
  "required": ["github_connection", "repository"],
  "properties": {
    "github_connection": {
      "type": "string",
      "title": "GitHub connection",
      "x-fluidbox": { "widget": "connection", "provider": "github" }
    },
    "repository": {
      "type": "string",
      "pattern": "^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$",
      "title": "Repository",
      "description": "owner/name of the repository your CI builds.",
      "x-fluidbox": { "widget": "text" }
    },
    "callback_url": {
      "type": "string",
      "pattern": "^https?://.+",
      "title": "Result webhook (optional)",
      "description": "HTTPS endpoint that receives the signed run.finished payload.",
      "x-fluidbox": { "widget": "url" }
    },
    "model": {
      "type": "string",
      "enum": ["claude-haiku-4-5", "claude-sonnet-5", "claude-opus-4-8"],
      "default": "claude-haiku-4-5",
      "title": "Model",
      "x-fluidbox": { "widget": "model", "harness": "claude-agent-sdk" }
    }
  },
  "x-fluidbox-ui": { "order": ["github_connection", "repository", "callback_url", "model"] }
}$fbx$::jsonb,
'Initial version', 'seed');

-- 3) repo-compliance-sweep ──────────────────────────────────────────────────
insert into recipe_versions (id, tenant_id, recipe_id, version, definition, params_schema, changelog, author)
values (gen_random_uuid(), null, '5eed0001-0000-4000-8000-000000000003', 1,
$fbx${
  "schema": 1,
  "summary_md": "A scheduled, read-only hygiene sweep. On the cron you choose, a fresh sandbox checks out the repository and audits four compliance surfaces: committed credentials and secret-shaped strings, license-header coverage against the repository license, CODEOWNERS coverage of the tree, and dependency lockfile drift (manifest vs lockfile). The findings report lands on the run timeline; wire the signed webhook to file it wherever your compliance evidence lives. The policy denies every write and every integration — this recipe can only ever read.",
  "success_criteria": [
    "The sweep fires on schedule and skips (visibly) when a previous sweep is still running",
    "The report enumerates findings with file paths and a severity ordering",
    "The run's diff artifact is empty — the sweep never modifies the repository"
  ],
  "policy": { "content": {
    "name": "repo-compliance-sweep",
    "defaults": { "tool_action": "deny" },
    "budgets": { "max_wall_clock_secs": 900, "max_cost_usd": 1.0, "max_tool_calls": 80 },
    "autonomy": { "permitted": true, "on_approval_rule": "deny" },
    "tools": [
      { "match": ["Read", "Glob", "Grep", "LS"], "action": "allow", "risk": "low" },
      { "match": ["Bash"], "action": "allow",
        "shell": { "allow_prefixes": ["ls", "cat", "head", "tail", "grep", "rg", "find", "wc", "git log", "git show", "git diff", "git status", "git ls-files", "sha256sum", "du"],
                   "on_no_match": "deny" } },
      { "match": ["Edit", "Write", "MultiEdit"], "action": "deny" },
      { "match": ["mcp__*"], "action": "deny" }
    ]
  } },
  "agents": [
    { "slot": "auditor",
      "name": "{{instance.name}}",
      "harness": "claude-agent-sdk",
      "model": "$param:model",
      "budgets": { "max_cost_usd": 1.0, "max_wall_clock_secs": 900, "max_tool_calls": 80 },
      "system_prompt": "You are a repository compliance auditor. You run on a schedule against the repository checked out in /workspace, read-only. Audit exactly these surfaces: (1) SECRETS — credential-shaped strings committed to the tree (API keys, private keys, tokens, connection strings, .env files), checking both content patterns and suspicious filenames; (2) LICENSING — the repository license and whether source files carry the headers the project's convention implies; (3) OWNERSHIP — CODEOWNERS existence, syntax, and coverage of top-level areas; (4) DEPENDENCIES — manifest vs lockfile drift and obviously unmaintained or duplicated dependencies visible from the files alone. You have no network access — judge only from the repository contents. Produce a findings report ordered by severity: each finding names the file path, what is wrong, why it matters, and the concrete remediation. End with a short scorecard (pass / warn / fail per surface). If a surface is clean, say so explicitly — absence of findings must be a verified claim, not an omission." }
  ],
  "subscriptions": [
    { "slot": "sweep",
      "agent_slot": "auditor",
      "kind": "schedule",
      "name": "{{instance.name}}",
      "autonomous": true,
      "concurrency_policy": "skip_if_running",
      "callback_url": "$param:callback_url",
      "workspace": { "kind": "git_repository",
                     "connection_id": "$param:github_connection",
                     "repository": "$param:repository" },
      "schedule": { "cron": "$param:cron", "timezone": "$param:timezone", "missed_run_policy": "skip" },
      "task_template": "Scheduled compliance sweep fired at {{fire_time}}. Audit the repository in /workspace per your standing instructions and produce the findings report." }
  ]
}$fbx$::jsonb,
$fbx${
  "type": "object",
  "additionalProperties": false,
  "required": ["github_connection", "repository"],
  "properties": {
    "github_connection": {
      "type": "string",
      "title": "GitHub connection",
      "x-fluidbox": { "widget": "connection", "provider": "github" }
    },
    "repository": {
      "type": "string",
      "pattern": "^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$",
      "title": "Repository",
      "x-fluidbox": { "widget": "text" }
    },
    "cron": {
      "type": "string",
      "default": "0 9 * * 1",
      "title": "Schedule (cron)",
      "description": "Five-field cron in the selected timezone. Default: Mondays 09:00.",
      "x-fluidbox": { "widget": "cron" }
    },
    "timezone": {
      "type": "string",
      "default": "UTC",
      "title": "Timezone",
      "x-fluidbox": { "widget": "timezone" }
    },
    "callback_url": {
      "type": "string",
      "pattern": "^https?://.+",
      "title": "Report webhook (optional)",
      "x-fluidbox": { "widget": "url" }
    },
    "model": {
      "type": "string",
      "enum": ["claude-haiku-4-5", "claude-sonnet-5", "claude-opus-4-8"],
      "default": "claude-haiku-4-5",
      "title": "Model",
      "x-fluidbox": { "widget": "model", "harness": "claude-agent-sdk" }
    }
  },
  "x-fluidbox-ui": { "order": ["github_connection", "repository", "cron", "timezone", "callback_url", "model"] }
}$fbx$::jsonb,
'Initial version', 'seed');

-- 4) ticket-investigator ────────────────────────────────────────────────────
insert into recipe_versions (id, tenant_id, recipe_id, version, definition, params_schema, changelog, author)
values (gen_random_uuid(), null, '5eed0001-0000-4000-8000-000000000004', 1,
$fbx${
  "schema": 1,
  "summary_md": "Connects a ticketing MCP server through the governed broker: the credential stays in the control plane and never enters the sandbox; every tool call crosses the permission gate and lands in the audit ledger. Invoked with a ticket id, the agent fetches the ticket through the tools you selected at deploy time (the frozen tool surface — nothing else is callable), correlates it with the checked-out repository, and reports root cause and next actions. The recipe's policy refuses autonomous runs outright: this workload is supervised by design.",
  "success_criteria": [
    "The report cites ticket fields actually fetched through the brokered tools (visible as tool.brokered ledger events)",
    "Code correlation names concrete files and, where possible, the commit or area that introduced the issue",
    "The run makes no write anywhere: repository writes are denied and only the selected read tools are callable"
  ],
  "policy": { "content": {
    "name": "ticket-investigator",
    "defaults": { "tool_action": "deny" },
    "budgets": { "max_wall_clock_secs": 900, "max_cost_usd": 1.5, "max_tool_calls": 80 },
    "autonomy": { "permitted": false, "on_approval_rule": "deny" },
    "tools": [
      { "match": ["Read", "Glob", "Grep", "LS"], "action": "allow", "risk": "low" },
      { "match": ["Bash"], "action": "allow",
        "shell": { "allow_prefixes": ["ls", "cat", "head", "tail", "grep", "rg", "find", "wc", "git log", "git show", "git diff", "git status", "git blame"],
                   "on_no_match": "deny" } },
      { "match": ["Edit", "Write", "MultiEdit"], "action": "deny" },
      { "match": ["mcp__*"], "action": "allow", "risk": "medium" }
    ]
  } },
  "agents": [
    { "slot": "investigator",
      "name": "{{instance.name}}",
      "harness": "claude-agent-sdk",
      "model": "$param:model",
      "budgets": { "max_cost_usd": 1.5, "max_wall_clock_secs": 900, "max_tool_calls": 80 },
      "connection_requirements": [
        { "slot": "tickets",
          "connector": { "url": "$param:tickets_connection.base_url" },
          "required_tools": "$param:ticket_tools",
          "binding_mode": "organization" }
      ],
      "workspace": { "kind": "git_repository",
                     "connection_id": "$param:github_connection",
                     "repository": "$param:repository" },
      "system_prompt": "You are a support-engineering investigator. Given a ticket reference, use the connected ticketing tools (mcp__tickets__*) to fetch the ticket and everything relevant on it — description, comments, environment, reporter context. Then investigate against the repository checked out in /workspace: reproduce the described behavior in the code, locate the responsible components, and use git history where it clarifies when and why the behavior arrived. Never guess at ticket contents — if a fetch fails, report the failure rather than inventing details. Your report: a summary of the ticket in one paragraph; root cause (or the most probable causes, ranked, when certainty is impossible) with file references; affected surface; suggested next actions for the assignee, distinguishing code fixes from configuration or user-error outcomes." }
  ],
  "subscriptions": [
    { "slot": "invoke",
      "agent_slot": "investigator",
      "kind": "api",
      "name": "{{instance.name}}",
      "allow_task_override": true,
      "autonomous": false,
      "concurrency_policy": "allow",
      "callback_url": "$param:callback_url",
      "task_template": "Investigate ticket {{ticket}}. Fetch it with the connected ticketing tools, correlate with the codebase in /workspace, and produce your investigation report." }
  ]
}$fbx$::jsonb,
$fbx${
  "type": "object",
  "additionalProperties": false,
  "required": ["tickets_connection", "ticket_tools", "github_connection", "repository"],
  "properties": {
    "tickets_connection": {
      "type": "string",
      "title": "Ticketing MCP connection",
      "description": "An organization MCP connection to your ticketing system (Jira, ServiceNow, Linear…).",
      "x-fluidbox": { "widget": "connection", "mcp": true }
    },
    "ticket_tools": {
      "type": "array", "items": { "type": "string" }, "minItems": 1,
      "title": "Ticket tools",
      "description": "The tools the investigator may call — pick the read tools. This selection IS the frozen surface: nothing outside it is callable.",
      "x-fluidbox": { "widget": "connection_tools", "connection_param": "tickets_connection" }
    },
    "github_connection": {
      "type": "string",
      "title": "GitHub connection",
      "x-fluidbox": { "widget": "connection", "provider": "github" }
    },
    "repository": {
      "type": "string",
      "pattern": "^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$",
      "title": "Repository",
      "description": "The codebase tickets are investigated against.",
      "x-fluidbox": { "widget": "text" }
    },
    "callback_url": {
      "type": "string",
      "pattern": "^https?://.+",
      "title": "Result webhook (optional)",
      "x-fluidbox": { "widget": "url" }
    },
    "model": {
      "type": "string",
      "enum": ["claude-haiku-4-5", "claude-sonnet-5", "claude-opus-4-8"],
      "default": "claude-haiku-4-5",
      "title": "Model",
      "x-fluidbox": { "widget": "model", "harness": "claude-agent-sdk" }
    }
  },
  "x-fluidbox-ui": { "order": ["tickets_connection", "ticket_tools", "github_connection", "repository", "callback_url", "model"] }
}$fbx$::jsonb,
'Initial version', 'seed');

-- 5) codebase-brief ─────────────────────────────────────────────────────────
insert into recipe_versions (id, tenant_id, recipe_id, version, definition, params_schema, changelog, author)
values (gen_random_uuid(), null, '5eed0001-0000-4000-8000-000000000005', 1,
$fbx${
  "schema": 1,
  "summary_md": "The fastest way to see a governed run end to end: deploy with a question and the first run fires immediately against a fresh checkout of the repository. The agent answers with file references on the run timeline. The deploy also leaves an API trigger behind, so new questions are one authenticated POST away — or use Run again from the deployment page.",
  "success_criteria": [
    "The first run starts at deploy time without further input",
    "The answer cites concrete files and symbols from the repository, not generalities",
    "The run's diff artifact is empty — a brief never modifies the workspace"
  ],
  "policy": { "content": {
    "name": "codebase-brief",
    "defaults": { "tool_action": "deny" },
    "budgets": { "max_wall_clock_secs": 600, "max_cost_usd": 0.75, "max_tool_calls": 60 },
    "autonomy": { "permitted": true, "on_approval_rule": "deny" },
    "tools": [
      { "match": ["Read", "Glob", "Grep", "LS"], "action": "allow", "risk": "low" },
      { "match": ["Bash"], "action": "allow",
        "shell": { "allow_prefixes": ["ls", "cat", "head", "tail", "grep", "rg", "find", "wc", "git log", "git show", "git diff", "git status", "git ls-files"],
                   "on_no_match": "deny" } },
      { "match": ["Edit", "Write", "MultiEdit"], "action": "deny" },
      { "match": ["mcp__*"], "action": "deny" }
    ]
  } },
  "agents": [
    { "slot": "guide",
      "name": "{{instance.name}}",
      "harness": "claude-agent-sdk",
      "model": "$param:model",
      "budgets": { "max_cost_usd": 0.75, "max_wall_clock_secs": 600, "max_tool_calls": 60 },
      "workspace": { "kind": "git_repository",
                     "connection_id": "$param:github_connection",
                     "repository": "$param:repository" },
      "system_prompt": "You are a codebase guide producing architecture-grade briefs. Answer the question you are given about the repository checked out in /workspace. Ground every claim in the code: read the relevant files before answering, cite file paths (and symbols) for each substantive point, and prefer showing the load-bearing lines over paraphrasing them. Structure the brief for a competent engineer new to this codebase: lead with the direct answer, then the supporting walkthrough, then pointers for going deeper. Where the honest answer is uncertain or the code is contradictory, say so — a wrong-but-confident brief is worse than a bounded one. Never modify anything: you are read-only." }
  ],
  "subscriptions": [
    { "slot": "ask",
      "agent_slot": "guide",
      "kind": "api",
      "name": "{{instance.name}}",
      "allow_task_override": true,
      "autonomous": false,
      "concurrency_policy": "allow",
      "task_template": "{{recipe.question}}" }
  ],
  "first_run": { "agent_slot": "guide", "task": "{{recipe.question}}", "autonomous": false }
}$fbx$::jsonb,
$fbx${
  "type": "object",
  "additionalProperties": false,
  "required": ["github_connection", "repository", "question"],
  "properties": {
    "github_connection": {
      "type": "string",
      "title": "GitHub connection",
      "x-fluidbox": { "widget": "connection", "provider": "github" }
    },
    "repository": {
      "type": "string",
      "pattern": "^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$",
      "title": "Repository",
      "x-fluidbox": { "widget": "text" }
    },
    "question": {
      "type": "string",
      "minLength": 8,
      "title": "Your question",
      "description": "What should the first brief answer?",
      "x-fluidbox": { "widget": "textarea" }
    },
    "model": {
      "type": "string",
      "enum": ["claude-haiku-4-5", "claude-sonnet-5", "claude-opus-4-8"],
      "default": "claude-haiku-4-5",
      "title": "Model",
      "x-fluidbox": { "widget": "model", "harness": "claude-agent-sdk" }
    }
  },
  "x-fluidbox-ui": { "order": ["github_connection", "repository", "question", "model"] }
}$fbx$::jsonb,
'Initial version', 'seed');
