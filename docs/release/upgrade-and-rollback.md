# Upgrading to `v0.4.0-rc.1`, and rolling back

Two things in this release need action before you deploy it. Both are stated
here in the order you will hit them, with the evidence for each.

---

## 1. The seed policy will NOT reach your existing deployment. Import it.

**This is the one that will bite you, and it will bite you on the first run.**

Making the permission gate mandatory changed which tool names the control plane
ever sees. Twenty-three tools the pinned Claude Code CLI advertises used to be
auto-approved inside the CLI and never reached `/permission` at all. They now all
arrive — and an unmatched tool falls to your policy's `defaults.tool_action`.

With the shipped default of `approve` that means **every supervised run pauses on
ordinary agent tooling** (plan-mode toggles, task bookkeeping, tool discovery),
and in autonomous runs `autonomy.on_approval_rule` **denies** them.

`policies/default.yaml` in this release governs all of them. But
`seed_policy_if_absent` never re-applies over a stored policy, so the file is the
source of truth only for a database that has never had a `default` policy. Your
deployment already has one.

**Do this before deploying the new runner image:**

```bash
# Option A — import the updated seed (appends a version; byte-equal is a no-op)
curl -fsS -X POST "$FLUIDBOX_API/v1/policies" \
  -H "authorization: Bearer $FLUIDBOX_ADMIN_TOKEN" \
  -H 'content-type: application/json' \
  -d "$(python3 -c 'import json;print(json.dumps({"name":"default","yaml":open("policies/default.yaml").read()}))')"

# Validate first if you prefer
curl -fsS -X POST "$FLUIDBOX_API/v1/policies/validate" ... 
```

Option B is the Governance page, which appends a version the same way.

**If you have customised your policy**, do not import over it blindly — take the
three new rule groups and merge them into your own ordering. They are, in the
order they appear in the file:

1. Observational tools added to the existing read-only `allow` rule:
   `EnterPlanMode`, `ExitPlanMode`, `AskUserQuestion`, `ReportFindings`,
   `Monitor`, `TaskGet`, `TaskList`, `TaskOutput`, `CronList`.
2. A new **deny** rule for sub-execution: `Agent`, `Task`, `Workflow`, `Skill`,
   `TaskCreate`. Read §3 before weakening this one.
3. A new **approve** rule for effects that outlive the run: `TaskStop`,
   `TaskUpdate`, `SendMessage`, `CronCreate`, `CronDelete`, `ScheduleWakeup`,
   `PushNotification`, `EnterWorktree`, `ExitWorktree`. Plus `DesignSync` joining
   the existing `WebFetch`/`WebSearch` **deny** rule.

`Task` also **moves out of** the read-only allow rule. It was allowed before and
inert only because this CLI names its subagent tool `Agent` — a standing
allow-rule for a sub-execution tool waiting for an upstream rename. If your
policy allows `Task`, move it.

## 2. Migration `0026` — stop the old binary, migrate, then deploy

`v0.3.0` ships 25 migrations; this candidate adds `0026_policy_versions.sql`,
which **drops four columns** from `policies`. That makes it the `0018` posture:
the old binary must be gone before the migration runs.

**Verified for this candidate**, against a real database:

| Direction | Result |
|---|---|
| Candidate binary against a 25-migration database | **applied `0026` and booted healthy** (`max(version)` → 26) |
| Pre-`0026` binary against a 26-migration database | **refused to boot**: `migration 26 was previously applied but is missing in the resolved migrations` |

So the failure mode on an attempted rollback is loud, not silent — which is the
property that matters, because the alternative is a binary that boots and then
answers policy queries with `column "version" does not exist`.

### Helm

- **Default values — no action needed.** `server.archiveStore: ""` and
  `values/eks.yaml` render `strategy: Recreate` with `replicas: 1`, which
  satisfies stop-the-old-binary by construction: the old pod terminates fully
  before the new one starts. Cost is roughly 30 seconds of downtime.
- **`server.archiveStore: "s3"` — act before upgrading.** Only that configuration
  (the multi-replica shape) renders `RollingUpdate`, where old and new pods
  coexist. **Scale the server Deployment to zero, upgrade, then scale back up.**
  There is no values knob for the strategy — it is derived from `archiveStore`
  alone — and patching the Deployment does not help, because the same
  `helm upgrade` rewrites the field. Without the scale-to-zero, surviving old
  replicas answer policy queries with `42703` until they are replaced, and their
  in-flight transactions can block the migration's `ACCESS EXCLUSIVE` DDL against
  its 5s `lock_timeout`.

### Rolling back

**There is no binary rollback past `0026`.** If you must return to `v0.3.0` you
need to restore the database from a backup taken before the migration. Take that
backup. The refusal above means you will find out immediately rather than
subtly, but it is still a refusal, not a recovery.

Everything *before* `0026` rolls back normally.

## 3. The eval Docker profile now requires an admin token

If you use `deploy/docker-compose.eval.yml`, or anything scripted around it:

```bash
export FLUIDBOX_ADMIN_TOKEN=$(openssl rand -hex 32)
```

`docker compose up` now **refuses to start** without one, naming the fix. The
previous default was `fluidbox-eval-only`, a literal published in this
repository, on an API port reachable from your whole network segment, beside a
mounted Docker socket. Anything relying on that default was relying on a
credential everyone has.

Two related changes: the dashboard now publishes on `127.0.0.1` only, and
`FLUIDBOX_EVAL_API_BIND` lets you pin the API port's interface. The API port
itself still publishes on all interfaces by default and **cannot** be
loopback-bound — sandboxes are sibling containers that reach the control plane
over `host.docker.internal`, which resolves to the host gateway rather than
`127.0.0.1`, so a loopback publish breaks every run. Run this profile on a
network you trust.

## 4. Before you weaken the sub-execution deny

`Agent`, `Task`, `Workflow`, `Skill` and `TaskCreate` do not act themselves —
they start an agent, workflow, skill or background task that then calls tools of
its own. Those nested calls may never surface as top-level
`tool_use`/`tool_result` blocks, which means they would be neither routed to the
gate by the runner's `PreToolUse` hook nor caught by the `GateWitness` tripwire —
which documents itself as a knowingly incomplete detector for exactly this case.

`approve` is therefore not a middle ground: one human click would authorise an
unbounded, unobserved tool tree. If you need these tools, measure first — confirm
that nested calls appear in the ledger as `tool.requested`/`tool.decision` on
your harness and image — and then widen the rule per agent rather than globally.

## 5. What has NOT been re-validated for this candidate

Stated so you can decide what to check in your own environment:

- **No live Claude run.** The available Anthropic key is out of credit. The
  permission gate is proven without a model by `scripts/gate-proof.sh`; "a real
  model completes a real task" is not proven here.
- **Kubernetes.** The NetworkPolicy admission fix was validated on kind + Calico
  and real EKS on 2026-07-29, but the two full EKS acceptances predate it and
  were not re-run; no cloud resources were created for this candidate.
- **Platforms.** macOS arm64 host with Linux arm64 containers only. Not amd64,
  not a Linux host, not Windows. See
  [`compatibility-matrix.md`](compatibility-matrix.md).

## Verifying your upgrade

```bash
bash scripts/version-check.sh          # every version site agrees
bash deploy/compose-assertions.sh      # compose files parse and are loopback-safe
just gate-proof                        # the permission gate, no API key, no spend
just demo                              # a full governed run, no API key
```

Then confirm on your own deployment that a supervised run does **not** pause on
ordinary agent tooling — which is the symptom of having skipped §1.
