# Recipes

Recipes package common agentic workloads into opinionated, versioned templates you deploy in a
few clicks. A deploy **stamps ordinary fluidbox objects** — a policy, agents (with revisions),
trigger subscriptions (with schedules and tokens) — in **one atomic transaction**, then optionally
fires a first run through the same `run_service::create_run` funnel every other run uses. There is
no recipe-specific execution or permission path; design:
`docs/plans/2026-07-31-enterprise-recipes-design.md`.

## Using recipes

- **Browse** `Recipes` in the dashboard (`/app/recipes`) or `GET /v1/recipes`. Cards show the
  trigger model, agent count, a per-run **cost ceiling** (sum of the agents' hard budget caps),
  and whether your connections already satisfy the recipe.
- **Detail** (`/app/recipes/{slug}`, `GET /v1/recipes/{slug}`) answers everything before any
  commit: what gets created, integrations required, the **permissions table** (the exact policy
  the deploy stamps — enforced server-side at the gate on every tool call), budgets, success
  criteria, and version history.
- **Deploy** — the wizard collects a deployment name + the recipe's parameters (connections are
  picked from existing ones; secrets are never parameters), then shows the server's **dry-run
  plan** (`POST /v1/recipes/{slug}/deploy` with `"dry_run": true` — no writes). The real deploy
  returns minted trigger tokens and webhook secrets **once**.
- **Manage** (`/app/recipes/instances/{id}`): runs (live), the stamped objects with deep links,
  the invoke contract, and Run now / Pause / Resume / Duplicate / Upgrade / Delete.
  - **Pause** disables every stamped subscription atomically (invokes 409, schedules stop
    advancing; re-enable goes through the missed-run path).
  - **Delete** is soft: subscriptions are disabled and the deployment leaves the list; stamped
    agents, policies, and run history remain (append-only audit records).
  - **Upgrade** applies the recipe's newest version **in place** for compatible changes only
    (agent revision appends, policy version appends, mutable subscription fields, schedule
    cadence). Structural changes (slots added/removed, trigger kind/connection/events changed)
    are refused with a named 422 — deploy the new version as a fresh instance. Runs in flight
    keep their frozen RunSpecs either way.
  - **Take it custom**: the stamped objects are ordinary agents/automations/policies — edit them
    in their own pages. That is the eject path; nothing re-renders behind your back (instances
    are detached from the recipe; provenance is recorded for the upgrade diff).

## The v1 official catalog

| Recipe | Trigger | Shape | Publishes |
|---|---|---|---|
| PR review panel | `pull_request` events | 3 agents (correctness/security/tests), fan-out | 1 stable PR comment + 3 checks |
| CI failure triage | API invoke (from CI) | 1 agent, task override + workspace narrowing | signed webhook / poll |
| Repo compliance sweep | schedule (cron) | 1 agent, read-only by policy | timeline report / webhook |
| Ticket investigator | API invoke | 1 agent + brokered MCP slot (tools frozen at deploy) | webhook / poll |
| Codebase brief | instant first run + API | 1 agent, read-only | timeline answer |

## Authoring a recipe

Custom recipes are tenant-scoped: `POST /v1/recipes` (admin/owner), append versions with
`POST /v1/recipes/{slug}/versions`. Official slugs cannot be shadowed. Both blobs are strictly
validated at write time; a definition referencing an undeclared parameter is refused.

### `definition` (the stamp plan)

Strict JSON (`fluidbox-core::recipe::RecipeDefinition`; unknown fields refused):

```jsonc
{
  "schema": 1,
  "summary_md": "Detail-page body.",
  "success_criteria": ["What working means, verifiable"],
  "policy": { "content": { /* canonical Policy document; name is overwritten per instance */ } },
  "agents": [{
    "slot": "worker",                       // [a-z0-9-], unique
    "name": "{{instance.name}} worker",
    "harness": "claude-agent-sdk",
    "model": "$param:model",
    "system_prompt": "…",
    "budgets": { "max_cost_usd": 1.0, "max_wall_clock_secs": 900, "max_tool_calls": 80 },
    "connection_requirements": [{ "slot": "tickets",
        "connector": { "url": "$param:mcp_connection.base_url" },
        "required_tools": "$param:tools", "binding_mode": "organization" }],
    "workspace": { "kind": "git_repository",
        "connection_id": "$param:github_connection", "repository": "$param:repository" }
  }],
  "subscriptions": [{
    "slot": "go", "agent_slot": "worker",
    "kind": "api",                          // api | schedule | event
    "name": "{{instance.name}}",
    "task_template": "…",                   // {{fire_time}} / {{pr_number}} etc. survive to run time
    "allow_task_override": true,
    "autonomous": false,
    "schedule": { "cron": "$param:cron", "timezone": "$param:timezone" },   // schedule kind
    "connection": "$param:github_connection", "repositories": "$param:repos",
    "events": "$param:events", "publish": ["check"],                        // event kind
    "callback_url": "$param:callback_url"
  }],
  "first_run": { "agent_slot": "worker", "task": "{{recipe.question}}" }
}
```

Rendering (one pass, two mechanisms):
- a string that is exactly `"$param:name"` (or `"$param:name.field"`) injects the **typed** value
  (arrays, booleans, objects); an absent optional parameter **drops the key**;
- other strings interpolate `{{recipe.<param>}}` and `{{instance.name}}` only — every other
  `{{…}}` is left for the run-time renderer (event/schedule context), so the two never collide.
- Connection parameters resolve to `{id, provider, display_name, base_url}` before rendering;
  bare `$param:x` yields the id, `.base_url` yields the URL binding resolution matches on.

### `params_schema` (the frozen contract)

JSON Schema 2020-12, `"type":"object"` + `"additionalProperties": false`, guarded by the same
bounds as frozen tool schemas. Widgets ride `x-fluidbox`:

| widget | schema type | semantic validation at deploy |
|---|---|---|
| `connection` (`provider` / `mcp` filter) | string | exists, `active`, matches the filter |
| `connection_tools` (`connection_param`) | string[] | ⊆ the connection's live snapshot |
| `repositories` | string[] | each `owner/name` |
| `cron` / `timezone` | string | parses via the scheduler's own parser |
| `model` (`harness`) | string | belongs to the harness |
| `url` | string | http(s) + egress admission (SSRF predicate) |
| `text` `textarea` `number` `boolean` `select` `string_list` `events` | — | schema only |

There is deliberately **no secret widget** — reference a connection instead. Defaults prefill the
form and apply server-side; `x-fluidbox-ui.order` orders the form.

### Rules the engine enforces (fail-closed)

- Params validate structurally, then semantically, then the definition renders, then every stamped
  object passes the same checks the manual creation APIs run — **before anything is written**.
- The stamp is one transaction: any failure (including a duplicate deployment/agent/policy name →
  409) leaves zero rows; retrying is always clean.
- Budgets/policies are narrowing-only downstream, exactly like everything else; a recipe cannot
  widen an agent's authority at run time.
- A first-run failure reports on the deploy response and the instance page; it never unwinds the
  deploy.

### Versioning official recipes

Official catalog rows are seeded by migration (`migrations/0027_recipes.sql`) and versioned by
releases: append a `recipe_versions` row (`author='seed'`) in a new migration. The fluidbox-db test
`recipes::tests::seeded_catalog_parses_and_is_renderable` re-validates every seeded blob against
the current Rust types — seed drift fails CI against a real migrated database. Bump the version for
any behavior change; a MAJOR-feeling change to `params_schema` (new required parameter without a
default, structural stamp changes) means existing instances will refuse in-place upgrade — that is
intended.

## Operations & security notes

- Tables (`recipes`, `recipe_versions`, `recipe_instances`, `recipe_instance_objects`) carry the
  full RLS triple; catalog rows are global-read/bypass-write like `connector_catalog`;
  `recipe_versions` is append-only at the database level.
- Deploy/lifecycle require admin/owner (`rbac::can_deploy_recipes` — deliberately the union of
  `resources.mutate` + `subscriptions.manage`); browsing is open to any member.
- Trigger tokens and callback secrets are minted inside the stamp transaction, returned once,
  sha256/AEAD at rest, and rotate on the automation page like any subscription credential.
- Acceptance: `scripts/recipes-e2e.sh` (e2e phase 10/11) — hermetic throwaway DB, RLS-enforcing,
  fake GitHub + file:// clone seams; set
  `FLUIDBOX_RECIPES_SANDBOX_IMAGE=fluidbox-replay-runner:dev` to run the execution phases through
  a real sandbox at $0.
