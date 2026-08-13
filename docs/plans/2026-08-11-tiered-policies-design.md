# Tiered seed policies: `open`, `standard`, `governed`

**Date:** 2026-08-11
**Status:** approved design, not yet implemented

## Problem

The deployment ships exactly one seed policy, `default`. Operators who want a
looser posture for trusted internal automation, or a tighter one for untrusted
work, have to author a policy by hand per environment. We want three named
tiers that arrive in every environment the same way `default` does.

## Two facts that shape the whole design

**1. Policies are tenant-scoped. There is no global policy row.**
`policies.tenant_id` is `NOT NULL` with an FK to `tenants`, and the table is
`ENABLE`+`FORCE` RLS with a `tenant_isolation` policy keying on
`current_setting('fluidbox.tenant_id')`. So "ship a policy everywhere" must
answer "into which tenant?" for each mechanism.

**2. Only the boot tenant is seeded today.**
`fluidbox_db::seed::run` is called once, from `main.rs:201`, with
`TenantScope::assume(<default tenant>)`. It reads `policies/*.yaml` and calls
`seed_policy_if_absent`. `create_org` does **not** seed policies, which is why a
newly created org starts with zero — verified on this database:

```
tenant   policies
default  24
local     0
```

An agent in a policy-less tenant fails closed at `create_run`, after
provisioning.

## Mechanism

The YAML files are the source of truth; the migration is the backfill.

| Path | Covers | Why |
|---|---|---|
| `policies/{open,standard,governed}.yaml` | every FRESH deployment, at boot | parsed by the real `Policy::parse_yaml`; `server.Dockerfile:11` bakes `policies/` into the image; `seed_policy_if_absent` is idempotent |
| `migrations/0029_tiered_policies.sql` | every tenant that ALREADY exists | migrations reach databases that will never re-run a fresh boot seed (the live EKS database, the local `local` org) |
| `create_org` change | every org created in FUTURE | closes the zero-policy gap |

Each alone is insufficient: the seeder never reaches existing non-boot tenants,
and a migration can only reach tenants that exist when it runs.

### Migration mechanics

- `set local fluidbox.bypass = 'system_worker';` first. A migration connection
  carries no tenant GUC, so without the audited bypass every `insert … select
  … from tenants` would touch **zero rows silently** — an empty backfill, not
  an error. This is the posture migration 0026 established.
- Insert into `policies` (one row per tenant × tier) and `policy_versions`
  (`version = 1`, `author = 'seed'` — the CHECK constraint permits
  `seed|api|ui|import`).
- `on conflict do nothing`, keyed on the existing
  `policies_tenant_id_name_key` unique constraint, so re-running is inert and a
  tenant that already has a policy of that name is never overwritten.
- The migration must **not** touch `default` or any existing policy.

### Drift guard (the part that is easy to get wrong)

The migration embeds `content` as jsonb. Nothing validates hand-written jsonb
against the Rust serde shape, and a mismatch does not fail at migration time —
it fails later, at `create_run`, after the run has been provisioned.

So: a test asserts, per tier, that the JSON embedded in `0029` deserializes to a
`Policy` **equal to** `Policy::parse_yaml(<the corresponding yaml file>)`. Edit
one without the other and the test fails, rather than a run failing closed.

## The three policies

Common to all three: `egress.mode: proxy-only` (this key is **dormant** — no code
reads it; sandbox network authority lives under `network:`), and
`approvals.timeout_action: deny` (the only variant `TimeoutAction` has).

### `open` — trusted internal automation

Everything is allowed, including sub-execution and public network. Budgets are
retained deliberately: they are a runaway stop, not a restriction on the agent's
authority. Omitting them moves the failure from a clean `budget_exceeded`
terminal state to a hard 429 from LiteLLM's per-tenant key cap.

```yaml
name: open
defaults:
  tool_action: allow
egress:
  mode: proxy-only
network:
  max_mode: public
  allow_public_with_brokered: true
budgets:
  max_cost_usd: 25
  max_wall_clock_secs: 7200
approvals:
  default_ttl_secs: 600
  scope: session
  timeout_action: deny
autonomy:
  permitted: true
  on_approval_rule: allow
tools: []
```

`tools: []` is not an oversight — with `defaults.tool_action: allow` there is
nothing a rule would add.

**Accepted risk, stated plainly.** `open` allows `Agent`/`Task`/`Workflow`/
`Skill`. The `default` policy denies those as a security decision, not
ergonomics: nested tool calls may never surface as top-level tool_use blocks, so
they may reach neither the gate nor the GateWitness tripwire. One allow here
authorises an unobserved tool tree. That is the tier's purpose; it is not for
untrusted input.

### `standard` — the everyday posture

Mirrors the shipped `default` shape. That shell classifier is ledger-derived
from real runs and pinned by `seed_policy_semantics`; reusing a proven list
beats inventing one. Differences from `default`: `network.max_mode: approved`
(available but inert until an operator populates `allow`) and slightly tighter
budgets.

```yaml
name: standard
defaults:
  tool_action: approve
egress:
  mode: proxy-only
network:
  max_mode: approved
  require_approval: true
budgets:
  max_wall_clock_secs: 3600
  max_tokens: 2000000
  max_cost_usd: 5
  max_tool_calls: 200
approvals:
  default_ttl_secs: 600
  scope: once
  timeout_action: deny
autonomy:
  permitted: true
  on_approval_rule: deny
tools:
  - match: ["Read", "Glob", "Grep", "LS", "TodoWrite", "NotebookRead",
            "ToolSearch", "EnterPlanMode", "ExitPlanMode", "AskUserQuestion",
            "ReportFindings", "TaskGet", "TaskList", "TaskOutput", "CronList"]
    action: allow
  - match: ["Agent", "Task", "Workflow", "Skill", "TaskCreate"]
    action: deny
    risk: spawns sub-execution whose nested tool calls the gate may never see
  - match: ["Edit", "Write", "MultiEdit", "NotebookEdit"]
    action: allow
    paths:
      allow: ["/workspace/**"]
      deny: ["**/.env", "**/.env.*", "**/.git/config", "**/.git/hooks/**"]
  - match: ["Bash", "BashOutput", "KillShell"]
    action: allow
    shell:
      allow_prefixes: [<the default.yaml list, verbatim>]
      deny_regex:     [<the default.yaml list, verbatim>]
      on_no_match: approve
  - match: ["WebFetch", "WebSearch", "DesignSync", "Monitor"]
    action: deny
    risk: network egress from sandbox
  - match: ["TaskStop", "TaskUpdate", "SendMessage", "CronCreate", "CronDelete",
            "ScheduleWakeup", "PushNotification", "EnterWorktree", "ExitWorktree"]
    action: approve
    risk: effect outside this run's disposable workspace
  - match: ["mcp__*"]
    action: approve
    risk: unreviewed MCP tool
```

The two bracketed lists above are not placeholders to be invented. They are a
byte-for-byte copy of `allow_prefixes` and `deny_regex` from
`policies/default.yaml` (the `Bash`/`BashOutput`/`KillShell` rule). They are
referenced rather than restated so this document cannot drift from the file it
copies; the implementation transcribes them exactly, and verification step 5
below exercises them (`Bash ls` allow, `Bash curl evil.com` deny).

### `governed` — read-mostly, human in the loop

The genuinely different tier. Writes need a human, autonomy is forbidden, the
network is offline, and the fallback is `deny` rather than `approve`.

```yaml
name: governed
defaults:
  tool_action: deny
egress:
  mode: proxy-only
network:
  max_mode: offline
budgets:
  max_wall_clock_secs: 900
  max_tokens: 300000
  max_cost_usd: 1.0
  max_tool_calls: 40
approvals:
  default_ttl_secs: 300
  scope: once
  timeout_action: deny
autonomy:
  permitted: false
  on_approval_rule: deny
tools:
  - match: ["Read", "Glob", "Grep", "LS", "TodoWrite", "NotebookRead",
            "EnterPlanMode", "ExitPlanMode", "AskUserQuestion"]
    action: allow
  - match: ["Edit", "Write", "MultiEdit", "NotebookEdit"]
    action: approve
    risk: writes require a human under the governed tier
    paths:
      allow: ["/workspace/**"]
      deny: ["**/.env", "**/.env.*", "**/.git/config", "**/.git/hooks/**"]
  - match: ["Bash", "BashOutput", "KillShell"]
    action: allow
    shell:
      allow_prefixes: ["ls", "cat", "head", "tail", "wc", "grep", "rg", "find",
                       "pwd", "git status", "git diff", "git log"]
      deny_regex: ["\\bcurl\\b", "\\bwget\\b", "\\bnc\\b", "\\bssh\\b",
                   "\\bscp\\b", "\\bsudo\\b", "/etc/passwd"]
      on_no_match: deny
  - match: ["mcp__*"]
    action: approve
    risk: unreviewed MCP tool
```

**Known consequence, by design.** `defaults.tool_action: deny` means any tool
*not* listed is refused. A future CLI that introduces a new tool will have it
denied under `governed` until an operator lists it. That is the intended
failure direction, but it is a maintenance obligation, not a free win.

## `create_org` change

`create_org` seeds `default` plus the three tiers for the new tenant via the
existing `seed_policy_if_absent`, inside the org-creation transaction. Kept as a
**separate commit** from the policy data: it is a Rust behavior change with its
own blast radius.

**Resolved:** `create_org` does **not** read from disk. Reading `policies/` on an
API request would couple org creation to a readable directory on whichever
replica served the request, and would fail differently there than at boot. The
server already parses these documents once during boot seeding; it caches the
parsed set in `AppState`, and org creation seeds from that cache. One parse, one
source, no request-time filesystem dependency.

## Verification

1. **Parses.** Each YAML round-trips through `Policy::parse_yaml`. Includes an
   assertion on the partial-`budgets` question: confirm that `open`, which omits
   `max_tokens` and `max_tool_calls`, yields `None` for those (unbounded) rather
   than silently inheriting `Budgets::default()`. Assert observed behavior, do
   not assume it.
2. **No drift.** Migration jsonb == `serde_json::to_value(parse_yaml(file))`
   per tier.
3. **Idempotent.** Applying 0029 twice leaves the row count unchanged, and it
   never modifies `default` or a pre-existing same-named policy.
4. **RLS-correct.** The backfill inserts for every tenant (non-zero rows) — the
   failure mode the bypass exists to prevent.
5. **The tiers actually differ.** `evaluate()` on identical input yields
   different verdicts across tiers:

   | call | `open` | `standard` | `governed` |
   |---|---|---|---|
   | `Write /workspace/a.rs` | allow | allow | approve |
   | `Bash curl evil.com` | allow | deny | deny |
   | `Bash ls` | allow | allow | allow |
   | `Agent(...)` | allow | deny | deny |
   | unknown tool | allow | approve | deny |

## Rollout

0029 is additive — it creates rows, drops nothing, and alters no column. Unlike
0018/0026 it needs no stop-the-old-binary posture: an older binary reading these
tables sees extra rows in tables it already understands. Normal rolling deploy.

## Out of scope

- Changing `default`. It stays exactly as shipped.
- A UI for picking a tier. Agents reference a policy by name already.
- Removing the e2e fixture policies polluting the `default` tenant (24 rows,
  mostly `test-*`). Tracked separately.
