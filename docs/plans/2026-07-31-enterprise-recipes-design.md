# Enterprise Recipes — design

**Date:** 2026-07-31 · **Status:** approved for implementation · **Branch:** `feat/enterprise-recipes`

Recipes package common agentic workloads into opinionated, versioned templates an enterprise user
can discover, configure, and deploy in a few clicks — without understanding sandboxes, runners,
policies, bindings, or orchestration. A recipe *stamps* ordinary fluidbox objects (policies, agents,
trigger subscriptions, schedules, runs) through the existing services; it introduces **no parallel
execution path** and no new runtime authority.

This document is research-backed: three external studies (template-catalog UX across 14 cloud/dev-infra
products; agent-platform packaging across 15 agent products; template schema/versioning/lifecycle
architecture across Helm/Terraform/Backstage/Home-Assistant/CloudFormation/Crossplane and friends)
plus a four-way internal codebase survey. Key citations inline; the full pattern lists live in the
research appendix of the validation report.

---

## 1. Why, and why now

fluidbox already has every primitive an enterprise agent workload needs — governed sandboxes, frozen
RunSpecs, DB-native versioned policies, connection slots with fail-closed binding, triggers,
schedules, deliveries, budgets, an immutable ledger. What it lacks is the **assembly**: today a user
must hand-compose an agent (system prompt, model, policy, capability slots), a trigger subscription
(matchers, task template, destinations), and a schedule — and know why each knob matters. That is a
platform-engineer workflow, not an enterprise-buyer workflow.

The research is unambiguous about what buyers want here:

- **Enterprises buy on controls, not capability.** Gartner projects 40% of enterprises abandoning
  autonomous-agent programs by 2027 over governance failures; the recurring non-negotiables are
  SSO, audit trails, sandbox isolation, approvals, and cost ceilings. fluidbox's differentiator is
  that its recipes can ship *with the governance baked in* — a frozen policy, budget, and approval
  posture per recipe that deploys under the org's rules (AWS Service Catalog "launch constraints"
  model: the requester can narrow, never widen).
- **The market's weak spots are exactly our strengths.** The low-code automation galleries
  (Zapier/Make/n8n/Retool) show *no* pre-deploy cost estimate and *no* consolidated permissions
  view; most platforms stamp fire-and-forget instances with no upgrade path (Backstage's own
  maintainers call the lost template→instance mapping unfixable after the fact). A permissions +
  cost summary before deploy, and a recorded provenance link enabling "update available", are cheap
  for us and rare in the market.
- **Multi-agent review panels and investigation pipelines are the flagship enterprise shapes**
  (Claude Code agent teams, Devin playbooks, incident pipelines). fluidbox's per-agent isolation +
  one audit ledger across a whole panel is the credibility story competitors can't match.

## 2. Concepts

| Concept | What it is | Precedent |
|---|---|---|
| **Recipe** | Catalog identity: slug, name, category, tier (`official` seeded / `custom` tenant-authored), description. Global rows (`tenant_id NULL`) are curated + seeded by migration; tenant rows are custom. | `connector_catalog` (0007/0013) |
| **Recipe version** | Append-only content row: `definition` (what gets stamped), `params_schema` (frozen JSON-Schema contract), changelog. Bump = new row; never mutate. | `policy_versions` (0026) |
| **Recipe instance** | A tenant's deployment of a recipe version with concrete params. Records provenance (slug + version + params) and links every stamped object. Detached from the recipe after stamping — **upgrade is explicit and manual**, never automatic re-render. | Crossplane `compositionUpdatePolicy: Manual`; Railway updatable templates; avoids Backstage #14416 (lost mapping) and Home-Assistant auto-re-render fleet breakage |
| **Stamped objects** | Ordinary policies / agents+revisions / trigger subscriptions (+schedules) / sessions created through the existing creation code, tagged with the instance id. They appear in the normal Agents/Automations/Governance/Runs UIs and remain fully editable there — that *is* the "eject to advanced custom" path. | LangGraph assistants (config wrapper) + fork ejection |

**Non-goals for v1** (explicitly deferred, documented in §12): sequential agent→agent chaining as a
first-class destination (no primitive exists; deliveries cannot self-invoke through the SSRF
boundary); GitHub *issue*-event recipes (the connector supports only `pull_request.*` events);
browser-automation recipes (sandbox egress is closed under Hardened/k8s); a marketplace/community
lane; automatic instance re-render.

## 3. Invariants this design must preserve (from PLAN.md §2 + CLAUDE.md)

1. **Everything stamps through existing funnels.** Agents via append-only revisions; runs via
   `run_service::create_run` (the single entry point); policies via the 0026 versioned store. No
   recipe-specific execution, status-writing, or permission path.
2. **Narrowing only.** A recipe ships budgets/policy/trust posture; the deploying user may tighten,
   never widen. Governance-critical knobs are simply *not parameters*.
3. **Secrets are never recipe parameters.** Reference params (`connection`) carry ids of existing
   sealed objects; the deploy response returns once-only minted secrets (trigger tokens) exactly like
   `POST /v1/triggers` does today.
4. **Tenancy triple** for every new table: `ENABLE`+`FORCE` RLS, tenant policy keyed on
   `current_setting('fluidbox.tenant_id')` (mixed read policy for the global catalog rows, like
   `connector_catalog`), and an enumerated DML grant resolved from
   `current_setting('fluidbox.runtime_role')` — all in migration `0027`, self-managed like 0026.
5. **Atomic stamp.** All rows of one deploy commit in **one** `scoped_tx` (Helm `--atomic` /
   CloudFormation-rollback school; Terraform partial-state is the explicit anti-model). A failed
   deploy leaves nothing behind; a retry is clean.
6. **Audit.** Deploy/pause/resume/upgrade/delete write `auth_audit_log` entries inside the mutating
   transaction; instance rows carry `created_by_user_id`, params digest, and version provenance.

## 4. Data model — migration `0027_recipes.sql`

```
recipes                       -- identity; global (tenant_id NULL, tier 'official') + tenant custom
  id uuid pk, tenant_id uuid null, slug text, name text, tagline text,
  description text, category text, tags jsonb '[]', tier text ('official'|'custom'),
  icon text, created_at, updated_at, disabled_at timestamptz null
  unique global slug (partial: tenant_id is null); unique (tenant_id, slug) for custom
  slug: 1-64 [a-z0-9-], reserved: 'instances'

recipe_versions               -- append-only content
  id uuid pk, tenant_id uuid null (= parent's), recipe_id uuid fk→recipes on delete cascade,
  version int > 0, definition jsonb, params_schema jsonb, changelog text,
  author text ('seed'|'api'), created_at
  unique (recipe_id, version)

recipe_instances              -- tenant-owned deployments
  id uuid pk, tenant_id uuid not null, recipe_id uuid fk (restrict), recipe_slug text,
  recipe_version int, name text, params jsonb, params_digest text,
  status text ('active'|'paused'|'deleted'), created_by_user_id uuid null,
  created_at, updated_at, deleted_at timestamptz null
  unique (tenant_id, name) where deleted_at is null

recipe_instance_objects       -- provenance links to stamped objects
  id uuid pk, tenant_id uuid not null, instance_id uuid fk→recipe_instances on delete cascade,
  kind text ('policy'|'agent'|'subscription'|'session'), object_id uuid, slot text, created_at
```

RLS: `recipes`/`recipe_versions` get the **mixed** policies (read = global-or-tenant-or-bypass;
write = tenant-or-bypass) copied from 0018's `catalog_*` section; `recipe_instances`/
`recipe_instance_objects` get the standard `tenant_isolation` policy. Grants: `select, insert,
update` on `recipes` + instances tables; `select, insert` only on `recipe_versions` (append-only);
`select, insert, update, delete` on `recipe_instance_objects` (object links die with their
instance). No FK from `recipe_versions.tenant_id` composite — global rows have NULL tenant and a
composite FK would silently unenforce (MATCH SIMPLE); app code + RLS keep parent/child tenant equal.

The five v1 recipes and their version-1 rows are **seeded inline in 0027** (connector-catalog
precedent: no seed file, no boot sync). `crates/fluidbox-db/src/lib.rs` migration-bake comment is
updated to `Latest: 0027`.

## 5. Recipe definition (`recipe_versions.definition`)

A declarative stamp plan, validated strictly (`deny_unknown_fields`) in `fluidbox-core`:

```jsonc
{
  "schema": 1,
  "summary_md": "…detail-page body…",
  "success_criteria": ["Every opened PR gets a review comment within one run", "…"],
  "policy": {                       // optional; omitted ⇒ agents use the org "default" policy
    "content": { /* full Policy document, 0026 canonical shape */ }
  },
  "agents": [{
    "slot": "reviewer",                       // stable role id within the recipe
    "name": "{{instance.name}} reviewer",     // templated
    "harness": "claude-agent-sdk",
    "model": "$param:model",                  // typed injection (see below)
    "system_prompt": "…",
    "budgets": { "max_cost_usd": 1.5, "max_wall_clock_secs": 900 },
    "capability_bundles": [],                 // sandbox bundle names (pin-at-attach preserved)
    "connection_requirements": [{
      "slot": "tickets",
      "connector": { "url": "$param:tickets_connection.base_url" },   // rendered from a connection ref
      "required_tools": "$param:ticket_tools",
      "binding_mode": "organization"
    }],
    "workspace": { "kind": "git_repository",
                   "connection_id": "$param:github_connection",
                   "repository": "$param:repository" }
  }],
  "subscriptions": [{
    "slot": "on-pr",
    "agent_slot": "reviewer",
    "kind": "event" | "api" | "schedule",
    "name": "{{instance.name}} — on PR",
    "task_template": "Review PR #{{pr_number}} of {{repository}} …",   // event vars survive rendering
    "autonomous": true,
    "concurrency_policy": "allow",
    "connection": "$param:github_connection",       // event kind
    "repositories": "$param:repositories",
    "events": "$param:events",
    "publish": ["check"],
    "schedule": { "cron": "$param:cron", "timezone": "$param:timezone" },  // schedule kind
    "allow_task_override": true,                    // api kind
    "callback_url": "$param:callback_url"
  }],
  "first_run": { "agent_slot": "reviewer", "task": "{{recipe.question}}" }   // optional instant run
}
```

**Two rendering mechanisms, one pass** over the definition tree:

- A string that is *exactly* `"$param:name"` (optionally with one `.field` accessor for connection
  refs) is replaced by the **typed** parameter value (arrays, numbers, booleans, objects). Absent
  optional param ⇒ the key is dropped.
- Any other string gets `{{recipe.<param>}}` and `{{instance.name}}` interpolation (string params
  only). Runtime placeholders (`{{pr_number}}`, `{{repository}}`, …) are left untouched for the
  existing event renderer — recipe-time and run-time templating never collide because they use
  different namespaces.

## 6. Parameters (`recipe_versions.params_schema`)

JSON Schema (2020-12) — the same substrate every studied system converged on (Helm
`values.schema.json`, Backstage scaffolder, CRD `openAPIV3Schema`) — pre-guarded by the existing
`schema_guard` bounds (size/depth/local-refs) because a custom recipe's schema is untrusted input.
Widget + reference semantics ride vendor keys, mirroring Backstage `EntityPicker` / CloudFormation
AWS-typed params / Home-Assistant selectors:

```jsonc
{
  "type": "object", "additionalProperties": false,
  "required": ["github_connection", "repositories"],
  "properties": {
    "github_connection": { "type": "string", "title": "GitHub connection",
      "x-fluidbox": { "widget": "connection", "provider": "github" } },
    "tickets_connection": { "type": "string", "title": "Ticketing MCP connection",
      "x-fluidbox": { "widget": "connection", "kind": "mcp_http" } },
    "ticket_tools": { "type": "array", "items": {"type":"string"}, "minItems": 1,
      "x-fluidbox": { "widget": "connection_tools", "connection_param": "tickets_connection" } },
    "repositories": { "type": "array", "items": {"type":"string"}, "minItems": 1,
      "x-fluidbox": { "widget": "repositories" } },
    "events": { "type": "array", "default": ["opened","reopened"],
      "items": { "enum": ["opened","reopened","synchronize"] } },
    "model": { "type": "string", "default": "claude-haiku-4-5",
      "x-fluidbox": { "widget": "model", "harness": "claude-agent-sdk" } },
    "cron": { "type": "string", "default": "0 9 * * 1", "x-fluidbox": { "widget": "cron" } },
    "callback_url": { "type": "string", "format": "uri",
      "x-fluidbox": { "widget": "url", "optional_note": "Signed run.finished webhook" } }
  },
  "x-fluidbox-ui": { "order": ["github_connection", "repositories", "events", "model"] }
}
```

Server-side validation layers (all before any write): (1) structural JSON-Schema validation;
(2) **semantic widget validation** — connection exists + `active` + tenant-visible + matches the
declared provider/kind filter; each repository is `owner/name`; cron parses via `CronSchedule::parse`;
model belongs to the harness (`validate_model`); `connection_tools` ⊆ the connection's latest
snapshot; URLs pass `egress::admit_url` where they'll be dialed. Unknown params are rejected
(`additionalProperties: false` enforced). **There is deliberately no `secret` widget.**

## 7. API surface (new `crates/fluidbox-server/src/recipes.rs`)

| Route | Auth | Behavior |
|---|---|---|
| `GET /v1/recipes` | any principal | Catalog list (global + tenant custom, shadowing by slug like the connector catalog), card fields + latest version + derived facets (trigger kinds, connectors used, agent count) |
| `GET /v1/recipes/{slug}` | any principal | Identity + latest version (definition, params_schema) + "what's included" manifest + permissions/cost summary + version history |
| `POST /v1/recipes` | `can_mutate_resources` | Create a **custom** tenant recipe (definition + schema validated; tier forced `custom`) — the documented authoring path |
| `POST /v1/recipes/{slug}/versions` | `can_mutate_resources` | Append a version to a custom recipe (official recipes version via migrations) |
| `POST /v1/recipes/{slug}/deploy` | `can_deploy_recipes` (admin\|owner\|operator) | Body `{name, params, dry_run?}`. Dry-run ⇒ 200 plan (objects to create, rendered names, permissions matrix summary, per-run cost ceiling, trigger cadence) with **no writes** — the Terraform-plan step. Real ⇒ 201 `{instance, objects[], secrets{trigger tokens, callback secrets — once}, first_run?}` |
| `GET /v1/recipes/instances` | any principal | Tenant's instances + status + provenance + update_available |
| `GET /v1/recipes/instances/{id}` | any principal | Instance + hydrated objects + recent sessions (via stamped subscription/session ids) + update_available |
| `POST …/instances/{id}/pause` · `/resume` | `can_deploy_recipes` | Disables/enables every stamped subscription (schedule clock stops/uses missed-run path — existing semantics) + flips instance status |
| `POST …/instances/{id}/run` | `can_deploy_recipes` | "Run now" for recipes whose definition has a runnable target (`first_run` or an `api` subscription): renders the task and calls `run_service::create_run`; records the session as an instance object |
| `POST …/instances/{id}/upgrade` | `can_deploy_recipes` | Body `{params?, dry_run?}`. Renders the **latest** version with (merged) params; dry-run returns the diff plan (revisions to append, subscription PATCHes); real applies atomically and bumps `recipe_version`. Incompatible params (new required without default) ⇒ 422 naming them |
| `DELETE …/instances/{id}` | `can_deploy_recipes` | Soft delete: disable subscriptions, status `deleted`. Agents/policies/runs remain (append-only history; runs reference them) — stated in the confirm UI |

Slug `instances` is reserved at creation so the route space cannot collide. Errors use the standard
envelope (`400` malformed / `403` RBAC / `404` scope / `409` duplicate-name & stale / `422`
validation with human-readable, field-naming messages).

**Deploy engine order** (mirrors `create_run`'s validate-before-spend discipline):
parse definition → validate params (§6) → render → assemble plan → *(dry-run stops here)* →
one `scoped_tx`: create policy+version (if the recipe carries one, named `{instance-name}-policy`) →
create agents + initial revisions → create subscriptions (+schedules, +minted trigger tokens,
+sealed callback secrets) → instance + object links → audit row → commit → ledger-visible first run
via `create_run` (post-commit; a first-run failure is reported on the instance, never unwinds the
deploy). The db layer gains `*_in_tx` variants of the existing creators (`create_agent`,
`append_agent_revision`, `create_trigger_subscription`, `create_schedule`, token mint), with the
current pool-level functions delegating to them — one creation code path, two entry shapes.

## 8. Product experience (dashboard)

New top-level **Recipes** nav item (masthead, `components/Sidebar.tsx`), all presentation-only per
the hard constraint — every verdict, plan, and validation message renders server output verbatim.

1. **`/recipes` — discovery.** Card grid in the existing `connector-grid` language: outcome-line
   title, category chip, connector marks, trigger-kind badge, tier badge (`official`), "deployed N×
   in your org" (tenant-local count — honest, no fake global popularity). Facets: category chips +
   search; "uses your connected apps" filter lights up recipes whose required connectors are already
   connected (the highest-intent entry point per the n8n/Zapier research).
2. **`/recipes/[slug]` — detail.** `PageHead` + panels: what it does (summary_md), **What gets
   created** manifest (agents, automations, schedule, policy), **Integrations required** (connector
   slots, connected-state aware), **Permissions** (server-rendered matrix summary from the recipe's
   policy — the pre-activation blast-radius view the automation incumbents lack), **Budgets & cost**
   (per-run ceilings + cadence ⇒ "≤ $X per run, runs on every opened PR"), success criteria,
   version history. Primary CTA → Deploy.
3. **Deploy wizard** (`ModalShell`, `creation-steps`): schema-driven form rendered natively from
   `params_schema` + `x-fluidbox` widgets — connection params use an existing-or-connect-new picker
   (reusing the catalog connect flow, `openVia` popup discipline), `connection_tools` fetches the
   live snapshot for pick-lists, model/cron/repositories get purpose-built inputs. Defaults
   prefilled; a single `blockingIssue`-style gate labels the primary button; server 4xx surfaced
   verbatim. **Review step = server dry-run plan** (objects + permissions + cost) before the real
   deploy. Success screen shows once-only secrets (existing `ShowAutomationSecrets` pattern) and
   lands on the instance page — the "observability handoff" (Railway/Backstage pattern).
4. **`/recipes/instances/[id]` — the deployment.** Status, provenance (recipe vX), stamped objects
   (deep links into Agents/Automations/Governance), recent runs with live status (`useSmartPolling`),
   actions: Run now / Pause / Resume / Duplicate (prefilled deploy) / Delete (consequence-explicit
   confirm) / **Update available → upgrade preview diff → apply** (the lifecycle everyone else
   punts). "Customize" affordances link straight to the stamped objects' native editors and say so —
   ejection without a new mechanism.

## 9. Catalog v1 (five recipes)

Chosen to cover every trigger kind, single- and multi-agent shapes, all three destination kinds, and
one brokered-MCP integration — while using **only** capabilities that exist today (no issue events,
no in-sandbox egress assumptions, no git write-back promises).

| # | Recipe (category) | Persona / problem | Shape | Params (beyond model) | Outputs & success criteria |
|---|---|---|---|---|---|
| 1 | **PR review panel** (Code review) | Eng lead wants every PR reviewed for correctness, security, and test coverage without burning reviewer hours | **Multi-agent fan-out**: 3 agents + 3 `event` subscriptions on `pull_request` (default opened+reopened; synchronize opt-in). Correctness lead publishes the stable PR comment + check; security & tests publish checks. Fork PRs auto-freeze `ReadOnly` (existing spine) | GitHub connection, repositories, events, panel toggles | 3 checks + 1 comment per PR; criteria: every opened PR gets all enabled panel verdicts |
| 2 | **CI failure triage** (CI/CD) | On-call eng pastes a red CI run; wants a root-cause + suggested fix in minutes | 1 agent + `api` subscription (`allow_task_override`, context vars); CI calls `invoke` with log excerpt + SHA; optional signed webhook back | GitHub connection, repository, callback_url? | Diagnosis + patch suggestion as run artifacts/webhook; criteria: actionable root cause referencing failing job |
| 3 | **Repo compliance sweep** (Compliance) | Platform/security team wants a scheduled hygiene report | 1 agent + `schedule` subscription (cron param, default Mon 09:00 UTC; `skip` missed-run default; `skip_if_running`) | GitHub connection, repository, cron, timezone, callback_url? | Weekly report artifact (secrets hygiene, license headers, CODEOWNERS, lockfile drift); criteria: report enumerates findings w/ file paths |
| 4 | **Ticket investigator** (Support/ITSM) | Support engineer wants Jira/ServiceNow-class tickets investigated against the codebase | 1 agent with a **brokered MCP connection slot** (`connection_requirements` rendered from the chosen connection; required tools picked from its live snapshot) + `api` subscription; supervised by default — MCP writes require approval | Ticketing MCP connection, ticket tools, GitHub connection?, repository? | Investigation summary linking ticket ↔ code; criteria: cites ticket fields fetched through the brokered gate |
| 5 | **Codebase brief** (Onboarding/Docs) | New team member / AE needs an architecture brief on demand | 1 agent + `api` subscription + **instant `first_run`** (question param) | GitHub connection, repository, question | Markdown brief artifact + diff-free run; criteria: answers the question with file references |

All five default to `claude-haiku-4-5` (overridable via the model param), carry recipe-specific
policies (read-leaning tool rules; autonomous permitted only where the workload is read-only-shaped;
approval posture preserved for MCP writes), and tight budgets. Definitions live in the 0027 seed and
are the reference examples for the authoring guide.

## 10. Testing strategy

- **fluidbox-core**: definition parse/validate (strictness, unknown fields, bad slots), template
  rendering (typed injection, interpolation, runtime-placeholder preservation), params validation
  matrix (each widget's accept/reject table), plan assembly.
- **fluidbox-db** (DATABASE_URL-gated, self-skip): store CRUD, RLS negatives as `fluidbox_runtime`
  (cross-tenant invisibility, global-read/tenant-write split), **atomicity** (induced mid-stamp
  failure leaves zero rows), instance lifecycle transitions, provenance links.
- **server**: route tests for validation errors, dry-run purity (no writes), RBAC denials, 409s
  (duplicate name), upgrade diffs, reserved slug.
- **`scripts/recipes-e2e.sh`** (new phase in `scripts/e2e.sh`), hermetic against a throwaway DB:
  deploy each catalog recipe through real HTTP; drive the `api` recipes end-to-end — **one run
  executes in a real sandbox via the replay runner image** (deterministic transcript through the
  real gate, $0, no key), proving artifacts/diff/cost/timeline; schedule fire via the sub-minute
  cron seam; ticket-investigator against the fake MCP upstream (snapshot → deploy → binding);
  event-kind deploy against the fake GitHub seam; negative paths (missing connection, bad params,
  wrong-tenant invisibility, pause blocks firing, delete cleanup, invoke idempotency replay,
  concurrent deploy name race); upgrade path (seeded v2).
- **Web**: vitest for the pure form-model/plan helpers in `lib/`; full user-journey validation in a
  live browser (isolated stack from the worktree) — discovery → configure → deploy → watch run →
  outputs → rerun/pause/upgrade/delete, including error-recovery journeys.

## 11. Alternatives considered

- **Boot-time seed sync for the catalog** — rejected; the connector catalog deliberately seeds via
  migration only, and drift between binary and DB seed is a known operational trap.
- **Live-linked instances (Home-Assistant blueprints)** — rejected; silent re-render of governed,
  budgeted, credentialed automations violates the snapshot-audit model. Detached + provenance +
  manual upgrade preserves both safety and the upgrade story.
- **HTTP-composed stamping (call our own routes)** — rejected; no atomicity, double auth handling.
  One transaction with `*_in_tx` creator variants keeps a single creation code path.
- **Generic rjsf form engine in the dashboard** — rejected; presentation-only constraint + no new
  deps. A small native renderer for the closed widget set keeps the server the sole validator.
- **Sequential chaining in v1 (delivery→trigger destination)** — deferred; it needs a first-class
  in-process destination kind with loop bounds and its own idempotency claims. Designed but not
  built; fan-out panels already deliver the multi-agent value. (§12)
- **Numeric-suffix instance object names vs templated names** — templated names with the instance
  name as the namespace; collisions surface as ordinary 409s at deploy (atomic, so safe to retry
  with a new name).

## 12. Follow-ups this design tees up

1. **Chaining destination** (`ResultDestination::Trigger{subscription_id}` resolved in-process
   through `create_run` with depth bounds + the existing delivery idempotency) — unlocks
   investigator→fixer pipelines.
2. **GitHub issue events** in the connector — unlocks issue-to-code recipes.
3. **Recipe analytics** (per-instance run success/cost rollups on the instance page).
4. **Private-catalog curation controls** (pin/feature per org; approval-before-deploy for
   high-blast-radius recipes — ServiceNow User-Criteria shape).
5. **Marketplace/community lane** with provenance signing (sigstore/OCI precedent).

## 13. Phasing

1. `0027` migration + core domain (definition/params/render/plan) + db store — unit-tested.
2. Server API (catalog, deploy engine, instances lifecycle) — route-tested.
3. Catalog v1 seed content.
4. Dashboard (discovery, detail, wizard, instance page).
5. `recipes-e2e.sh` + e2e.sh wiring.
6. Docs (guide + authoring) + validation report + full quality bar.
