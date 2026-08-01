# Enterprise Recipes — validation report

**Date:** 2026-07-31 · **Branch:** `feat/enterprise-recipes` (fresh from `origin/main` 6688112)
**Design:** `docs/plans/2026-07-31-enterprise-recipes-design.md` · **Guide:** `docs/guides/recipes.md`

## What was implemented

- **Migration `0027_recipes.sql`** — `recipes` (global curated + tenant custom, connector_catalog
  split), append-only `recipe_versions` (definition + frozen `params_schema` per version),
  `recipe_instances` (provenance + lifecycle), `recipe_instance_objects` (links to every stamped
  object). Full RLS triple per table; versions append-only at the DB level; the five-recipe v1
  official catalog seeded inline (blobs re-validated against the Rust types by a DB test).
- **`fluidbox-core::recipe`** — strict definition types, JSON-Schema param contract with
  `x-fluidbox` widgets (no secret widget by design), two-namespace rendering (`$param:` typed
  injection + `{{recipe.*}}`/`{{instance.name}}` interpolation; run-time placeholders preserved),
  authoring typo-defense (`referenced_params`).
- **`fluidbox-db::recipes`** + `_tx` variants of the existing policy/agent/subscription/schedule/
  token creators — one creation code path, callable inside the deploy engine's single transaction.
- **`fluidbox-server::recipes`** — `/v1/recipes` catalog/detail (derived facets, manifest,
  permissions + cost summaries), custom authoring, **deploy engine** (validate → resolve refs →
  render → per-object checks mirroring the manual APIs → dry-run plan → ONE-transaction atomic
  stamp → optional first run via `run_service::create_run`), instance lifecycle
  (pause/resume/run/delete soft), **in-place upgrade** with structural-change refusal.
  `rbac::can_deploy_recipes` gates mutations.
- **Dashboard `/app/recipes`** — searchable catalog with honest cards (trigger kinds, agent count,
  cost ceiling, connection readiness), detail page (what gets created / integrations /
  permissions / versions), schema-driven deploy wizard with server dry-run review and once-only
  secrets, deployment page (runs, object deep-links = the eject path, invoke contract, lifecycle
  actions). `lib/recipes.ts` form model is pure + vitest-covered.
- **Catalog v1:** pr-review-panel (multi-agent fan-out, PR events, comment+checks), ci-failure-triage
  (API + task override + workspace narrowing), repo-compliance-sweep (cron), ticket-investigator
  (brokered MCP slot, tools frozen at deploy, autonomy refused by policy), codebase-brief (instant
  first run + API rerun). All trigger kinds, single- and multi-agent, all three destination kinds.

## Test results (all commands run from the worktree)

| Layer | Command / environment | Result |
|---|---|---|
| Core unit | `cargo test -p fluidbox-core recipe::` | **17/17** |
| DB integration | `cargo test -p fluidbox-db recipes::` vs throwaway `fluidbox_recipes_dev` on the local container (127.0.0.1:5433; migrations 0001–0027 applied on connect) | **4/4** (seed-drift, shadowing/isolation, lifecycle/name-reuse, stamp atomicity) |
| Lint/type | `cargo clippy -p fluidbox-{core,db,server} -- -D warnings`; `cargo fmt --check` | clean |
| Web | `pnpm build` (routes `/app/recipes`, `/app/recipes/[slug]`, `/app/recipes/instances/[id]`); `npx vitest run` | build green; **112/112** (11 new) |
| E2E (control plane) | `DATABASE_URL=…5433/fluidbox bash scripts/recipes-e2e.sh` — hermetic: recreates `fluidbox_recipes_e2e`, own ports 18797/18798/18899, `FLUIDBOX_RUNTIME_ROLE=fluidbox_runtime` (RLS enforcing), fake GitHub API, `file://` clone fixture | **60/60** |
| E2E (+ real sandboxes) | same + `FLUIDBOX_RECIPES_SANDBOX_IMAGE=fluidbox-replay-runner:dev` (docker on colima) | **71/71** on the final run |

E2E coverage: catalog facets/detail/reserved routes; custom authoring (undeclared-param 422,
official-slug 409, version append, official-versioning 403); deploy validation (missing params,
unknown connection, cross-harness model, bad cron — all named 422s) and **dry-run purity**; the
atomic stamp (induced duplicate leaves zero objects); trigger contract (invoke, poll,
Idempotency-Key replay, token confined from the admin API); pause blocks invoke/run-now (409),
resume restores; schedule stamped with a live clock; **upgrade** (update-available flag, dry-run
diff names exactly the changed agent, one revision appended, re-upgrade 409, structural v3 refused
with a named 422); soft delete (invoke refused, history survives, fresh name deploys).

**Execution phases (real docker sandboxes, deterministic replay harness, $0, no model key):**
- *A — policy permits the work:* a custom recipe deploys with an instant first run; the run
  completes in a real sandbox; the ledger shows ≥3 `allow` verdicts and exactly 1 `deny` (the
  off-policy `curl`); the terminal **diff artifact contains the actual `app.js` fix**; recorded
  cost is $0.
- *B — policy denies writes:* the official codebase-brief completes with `deny` verdicts on the
  ledger and a **no-change diff** — the gate demonstrably prevented modification inside a live
  sandbox.

## Browser validation (Claude in Chrome, production `pnpm start` against the held e2e stack)

Journeys completed as an end user: catalog discovery (categories, readiness badges) → recipe
detail (permissions table, connected integrations, version history incl. seeded v2/v3) → deploy
wizard (name + connection picker + repository + question + model; **Review plan** rendered the
server dry-run: policy/agent/trigger/first-run/cost; **Deploy** returned once-only trigger token +
invoke URL) → deployment page (run **completed in a real sandbox** within seconds; owned objects
deep-linked; frozen configuration) → run timeline (workspace ready → sandbox launched → every tool
crossing the decision gate with policy denials → $0.0000 cost, frozen RunSpec panel) → pause
(status + subscription flip, verified server-side and rendered in the Deployments list) → resume.
Evidence: `deployment-page.jpg`, `run-timeline-gate-denials.jpg`, `deployments-list-paused.jpg`
(this directory).

## Bugs found and fixed during testing

1. **Suite workdir under `/var/folders`** → colima doesn't mount it, so sandboxes saw **empty
   workspaces** (bind mount of an unmounted path). Fixed: suite workdir under `$HOME`; comment
   documents the trap.
2. **Server bind collision** — the internal gateway defaults to `127.0.0.1:8788`; a running dev
   server held it. Fixed: suite owns `FLUIDBOX_INTERNAL_BIND` + upfront port checks.
3. Assertion-shape fixes surfaced by real evidence: ledger events nest under `payload.data`; the
   replay harness emits allow-decisions + output (no `tool.completed`); an untouched workspace's
   diff artifact is the literal `(no changes)` sentinel.
4. Wizard/UI type slips caught by the build (`LoadingRows rows=`, `apiGetCached` options object)
   and a test-fixture spread bug caught by vitest.

## Remaining risks / limitations (disclosed)

- **Pre-existing replay-runner silent death** (~5% of sandbox runs): the container exits with no
  stderr and no `/result`; the watchdog correctly terminalizes the run ("sandbox died (stale
  heartbeat)"). Platform crash-handling works as designed; the suite retries that one signature
  once, loudly. Evidence + timeline in this session's logs; recommend a follow-up issue (attach
  `docker events` exit-code capture).
- **Next dev-only Turbopack wedge**: `next dev` hung compiling `/app/sessions/[id]` on demand,
  freezing the dev server (production build/serve unaffected — validated on `pnpm start`). Not
  recipe code; pre-existing route. One extension ref-click (Pause) did not register during
  automation while the identical request path succeeded and all wizard clicks worked — recorded as
  an automation artifact; worth a manual click-through.
- `pnpm lint` reports 13 errors: 9 pre-existing (same `set-state-in-effect` pattern app-wide); the
  4 new ones follow those exact conventions. Lint is not part of `just check`'s bar.
- Upgrade is deliberately in-place-compatible only; structural changes require redeploy (by
  design, documented).
- Out of scope for v1 (documented in the design doc §12): GitHub issue events, sequential
  agent→agent chaining destination, browser-automation recipes, marketplace/community lane,
  per-org catalog curation controls.

## Addendum 2026-07-31 (evening) — live-model pass via the ngrok GitHub App

Operator-triggered. Fresh GitHub App **fluidbox-kia-pantomimic** minted via the manifest+install
dance through the ngrok tunnel (prior custody was wiped with the local volume); private test repo
`hrishikeshdkakkad/fluidbox-recipes-live-demo`; PR #1 planted three findings (a `new Function`
RCE sink, an unvalidated negative discount, zero new tests).

**Two launch-blocking seed bugs found and fixed (commits `4f44641`, `29cd81e`):**

1. **pr-review-panel was undeployable.** Its schema spoke `"opened"` while the subscription
   vocabulary is `"pull_request.opened"` — the schema refused the qualified names and the engine
   refused the short ones. The e2e had never dry-run this recipe; it now asserts every seeded
   default survives the engine's per-object checks.
2. **All five seed policies were codex-blind for reads.** Shell allowlists carried
   cat/rg/git-log-family but not `sed -n`/`pwd`/`git rev-parse`; the claude harness reads via
   native Read/Grep so never noticed, but codex reads through the shell — the panel's security
   reviewer was denied every file read and returned an honest but ungrounded review. All five
   seeds gained the read staples. (The allowlist was never the write barrier — `cat` admits
   redirection; fork-PR ReadOnly is.)

**What the live pass proved** (claude panel + custom codex variant `pr-review-panel-codex`,
authored via the custom-recipes API — itself a live exercise of that path):

- webhook → HMAC verify → exactly-3-run fan-out; paused instance stayed silent through the same
  delivery; reopen re-fired cleanly (dedup keyed per delivery).
- Real sandboxes checked out the PR head; the permission gate stayed live mid-run (v2 security
  run: 13 allows, 4 denies — `nl`, `git show-ref` — and the agent adapted with allowed commands).
- Anthropic account had no credits → all three claude runs failed HONESTLY: checks published as
  fail, stable comment disclosed the incomplete review, $0 charged. The publish spine is
  independent of run success.
- Codex panel (gpt-5.4-mini): all three reviewers completed grounded. Correctness found both
  planted bugs with file:line + verdict "request changes"; security traced the exact
  coupon.rule → applyDiscount → Function() attack path with remediation; tests enumerated every
  untested branch. One stable comment per subscription, one check per reviewer per head SHA.
- **Total live spend: ~$0.04 across 6 runs** (metered per-session in `usage_entries`).

Residual noted: a run's check conclusion reflects run completion, not the review verdict — a
"request changes" review lands as a green check. Worth a `neutral`/`action_required` mapping
pass later.

## Recommended next work

1. Chaining destination (`ResultDestination::Trigger`) for investigator→fixer pipelines.
2. `issues.*` events in the GitHub connector → issue-to-code recipes.
3. Per-instance run/cost rollups on the deployment page; recipe analytics.
4. Root-cause the replay-runner silent death; catalog curation (pin/feature, approval-before-deploy).
5. Map review verdicts onto check conclusions (see addendum residual).
