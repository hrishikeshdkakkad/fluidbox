# Overnight integration review — four worktrees, independently verified

**Date:** 2026-07-29 → 2026-07-30
**Integration branch:** `worktree-morning-prime-time-integration`
**Base:** `9515069` (main, merge-base of all four source branches)
**Mandate:** independently review and integrate four completed overnight worktrees. Trust no completion claim. Reproduce the load-bearing tests. Cherry-pick only what survives verification.
**Constraints observed:** the four source worktrees were never modified (all four still clean at their original SHAs); nothing pushed, merged, published, or released; no PR opened; **no cloud resources created** (AWS access was read-only; Kubernetes verification used a local kind cluster).

**Verdict: LIMITED BETA.** Reasoning in §9. The two P0s that made the prior assessment a NO-GO are closed and re-verified; the blocker that remains is a one-line default in the install path the README lists *first*, plus a set of absolute public claims that outrun even the fixed implementation.

---

## 1. Worktree inventory (recorded before any change)

All four were **clean** (zero dirty files) and all share the merge-base `9515069`.

| Worktree | Branch | HEAD | Commits | Files changed | Own validation report |
|---|---|---|---|---|---|
| `.claude/worktrees/claude-tool-gate` | `fix/claude-tool-gate` | `2bcf66b` | 2 | 8 | `docs/reviews/claude-tool-gate-validation.md` |
| `.claude/worktrees/k8s-network-admission` | `feat/k8s-network-admission-gate` | `bd17fa3` | 2 | 19 | `docs/reviews/k8s-network-admission-validation.md` |
| `.claude/worktrees/five-minute-demo-film` | `worktree-five-minute-demo-film` | `489941b` | 7 | 44 | `docs/reviews/2026-07-29-demo-validation/README.md` + 8 drill logs + 3 receipt sets |
| `.claude/worktrees/prime-time-red-team` | `worktree-prime-time-red-team` | `e7db0ae` | 1 | 4 | the reports *are* the deliverable |

Sibling film repo `~/Documents/fluidbox-demo-film` @ `demo-clips` / `7872b9d`, clean; five rendered launch clips.

One discrepancy: the tool-gate report cites its second commit as `505674b`; the actual SHA is `2bcf66b` (rebased). Content matches.

---

## 2. Method

The four red-team documents were read **first and treated as hypotheses**, not findings. Every load-bearing claim was then re-derived independently: four adversarial diff reviews, plus reproductions I ran myself. Where my evidence contradicted a report — in both directions — the contradiction is recorded below, including two cases where **I** was wrong (§8).

The central obstacle was that the `ANTHROPIC_API_KEY` in `.env` is exhausted — independently confirmed, HTTP 400 `"Your credit balance is too low"`. The tool-gate branch's decisive live-agent phase self-skipped for the same reason, so its most important claim arrived **unreproducible as written**.

**Resolution — the technique that made this review possible.** Instead of a live model, I pointed the runner's `ANTHROPIC_BASE_URL` at a mock upstream that returns a canned `tool_use`, and its `FLUIDBOX_CONTROL_URL` at a mock control plane whose verdict I control per scenario. This drives the **real** runner image, the **real** `index.mjs`, and the **real** Claude Code CLI through the **real** hook → callback → `/permission` path at **zero model cost**, and it yields two unfabricatable execution witnesses:

1. a **real filesystem side effect** in the bind-mounted `/workspace`, host-visible; and
2. for read-only-classified commands (which have no side effect), the **digest of a nonce minted seconds earlier** arriving back in the `tool_result` the mock receives on the next turn.

This is strictly stronger than a live-model run: deterministic, repeatable, free, and it can hold the verdict open to test ordering. Harness at `$CLAUDE_JOB_DIR/tmp/gateproof/`.

---

## 3. Branch 1 — `fix/claude-tool-gate`

### 3.1 The vulnerability, independently reproduced on unfixed `main`

Two runner images built from source: `:prefix` from `9515069`, `:toolgate` from the branch.

| # | Image | Gate answers | Probe | `/permission` calls | Command executed? |
|---|---|---|---|---|---|
| **A1** | **`main` (unfixed)** | **deny everything** | read-only-classified (`sha256sum`) | **0** | **YES — digest returned** |
| A2 | `main` (unfixed) | deny everything | mutating (`printf > file`) | 1 | no |
| **B1** | **branch (fixed)** | **deny everything** | read-only-classified | **1** | **no** |
| B2 | branch (fixed) | deny everything | mutating | 1 | no |
| C1 | branch (fixed) | allow | read-only-classified | 1 | yes *(positive control)* |
| C2 | branch (fixed) | allow | mutating | 1 | yes, nonce matched *(positive control)* |

**A1 is the P0, reproduced.** On unfixed `main`, a read-only-classified `Bash` command executed while the gate was configured to deny *everything*, with **zero** gate consultations. A2 shows a *mutating* command in the same image **was** gated — which is exactly why the failure looked intermittent, and it confirms the report's root-cause analysis. B1 shows the fix closes it on the precise class that bypassed. C1/C2 are the positive controls that make B1/B2's absence meaningful rather than evidence of a broken harness.

### 3.2 Approval precedes execution — measured, not inferred

Scenario D1 held the verdict open for 8 seconds:

```
tool_use emitted        1785385284369
/permission requested   1785385284389   (+20 ms)
/permission answered    1785385292390   (+8001 ms — held)
SIDE_EFFECT.txt written 1785385292410   (+20 ms AFTER the verdict)
```

Nothing executed during the 8-second pending window; the file appeared 20 ms after the allow. The server-side half of the same property is asserted independently by the acceptance suite ("the tool call is still blocked — no verdict issued yet").

### 3.3 Fails closed on invalid authorization and control-plane loss

| # | Gate behaviour | Attempts | Executed? | Notes |
|---|---|---|---|---|
| E1 | HTTP 500 | 43 | **no** | retries forever, never allows |
| E2 | socket destroyed | 22 | **no** | `fetch failed`, retries |
| E3 | 401 | 1 | **no** | hard deny |
| E4 | 403 `wrong_audience` | 1 | **no** | **exit 3** — aborts rather than laundering a credential fault into a verdict |
| E5 | 200 + non-JSON | 1 | **no** | unparseable ⇒ deny |
| E6 | 200 + `{}` | 1 | **no** | missing `decision` ⇒ deny |

No path allows. Control-plane loss blocks indefinitely (the tool never runs) rather than failing open.

### 3.4 `approved_once` executes once

`scripts/e2e-tool-gate.sh` against a real control plane on a throwaway database: **14 passed, 0 failed**, reproducing the branch's result exactly, including `approved_once decided exactly once (a faithful replay adopts, 1 intent)`, replay-with-different-input ⇒ deny, and cancellation ⇒ credential revoked. Phase 1 self-skipped (no model) — independently confirming the exhausted key rather than hiding it.

`scripts/governance-e2e.sh`: **47 passed, 0 failed**, including `RunSpec froze default v1 — snapshot BYTE-EQUAL`.

### 3.5 Two findings the branch and the red team both missed

**(a) The gate test suite could not detect its own regression — now fixed.** Mutation testing found the 12-test suite passes **12/12** on two changes that fully restore the P0:

| Mutation | Before | After my fix |
|---|---|---|
| `preToolUseGate = async () => ({})` (report's own table: `{}` ⇒ tool **executes**) | 12/12 pass | **fails** |
| `[{ hooks: [preToolUseGate], matcher: "Write" }]` (scopes the hook) | 12/12 pass | **fails** |
| hook deleted entirely | caught | caught |
| unmutated | 12/12 | 14/14 |

Only the crude regression was caught. Two assertions added in `e5cf8da`, red-green verified.

**(b) A tool-vocabulary/policy mismatch that the fix exposes — P1, open.** Captured from the pinned SDK by logging the tool list the shipped runner actually advertises: **30 tools**, of which **23 have no rule in the seed policy** — `Agent`, `AskUserQuestion`, `CronCreate/Delete/List`, `DesignSync`, `Enter/ExitPlanMode`, `Enter/ExitWorktree`, `Monitor`, `PushNotification`, `ReportFindings`, `ScheduleWakeup`, `SendMessage`, `Skill`, `TaskCreate/Get/List/Output/Stop/Update`, `Workflow`. Conversely ten names the policy and `CANONICAL` *do* govern are **not advertised**: `Glob`, `Grep`, `LS`, `TodoWrite`, `Task`, `MultiEdit`, `NotebookRead`, `BashOutput`, `KillShell`, and `ToolSearch` itself.

Because the fix makes the gate mandatory and an unmatched tool falls to `defaults.tool_action: approve`, **ordinary agent tools now pause every supervised run** (and are denied in autonomous runs via `on_approval_rule: deny`). The branch identified this category and fixed exactly one name (`ToolSearch`). The subagent tool in this CLI version is `Agent`, not `Task` — so the policy's `Task` allow-rule is inert and the reviewer's `Task`-auto-allow concern does not apply as stated, but `Agent` is unmatched and will pause.

Related: `max_tool_calls` was calibrated pre-fix, when read-only calls never reached the gate and therefore never registered an intent. The default (100) has headroom; the acceptance suite's own ceiling (20) does not.

### 3.6 Verdict

| Commit | Verdict |
|---|---|
| `58b4b02` → `66e0bb2` `fix(runner): gate EVERY Claude tool call via a PreToolUse hook` | **ACCEPT WITH FOLLOW-UP** |
| `2bcf66b` → `92fec3c` `fix(core): register ToolSearch in the canonical tool vocabulary` | **ACCEPT** |

Follow-ups: the vocabulary mismatch (§3.5b); AT-01a server-side detection never built, so an older pinned `runner_image` on a newer server still bypasses silently; Codex harness unexamined; AT-01d regression gate absent (`ci.yml:417` still `workflow_dispatch`).

---

## 4. Branch 2 — `feat/k8s-network-admission-gate`

### 4.1 No blind sleep

`netpol::enforcement_script` resets both variables every iteration, re-probes both targets in the same pass, and exits 0 only when positive-reachable **and** negative-blocked hold in **one** observation. The only `sleep`s are the 1 s poll interval and a 2 s phase-poll — poll cadence, not "wait and assume". The deadline fails **closed** with the original exit-code contract (`3` = not enforced, `2` = positive unreachable). All three consumers — boot probe, per-sandbox init container, helm test — share the one generated script.

### 4.2 No isolation weakened

Verified directly rather than accepted:

- `crates/fluidbox-core/src/traits.rs` — the diff is **purely additive** (`network_admission: Option<NetworkAdmission>` + the struct). `#[default] HostDev` is **untouched**.
- `netpol.requireEnforced` default still `true`, still fail-closed; `waitSeconds: 60` added. `helm lint` clean.
- `SandboxSpec` derives only `Debug, Clone` and is absent from `spec.rs`, so the new field **cannot** perturb frozen-`RunSpec` byte-equality — confirmed by governance-e2e's byte-equality assertion passing.
- The gate init container carries no env, volumes, tokens, or capabilities, and is genuinely **first** (before `workspace-init`).
- The provider refuses to provision an enforcement-required spec with no admission targets, and the provider/server falsey parses agree on every input.

### 4.3 kind + Calico regression, re-run by me

`scripts/netpol-admission-validation.sh` → **ALL 12 ASSERTIONS PASSED**, `KIND_EXIT=0`, cluster removed afterwards (`kind get clusters` empty).

- A1–A5 steady state: gate admitted on its first observation each time; runner found `public:8787=blocked internet:443=blocked internal:8788=ok`.
- **B0 reproduced the vulnerability**: a pre-fix pod with no gate reported `public:8787=OPEN internet:443=OPEN`.
- B1–B3 the race: gate observed the open network 8× each, runner held at `PodInitializing`, and the ordering proof is numerically valid (`started 1785386175 ≥ apply 1785386170`).
- C-old: pre-fix probe `Failed`/exit 3 — the measured EKS-503 cause, reproduced. C-new: converged in 14 s after 10 open observations.
- D: policy never applied ⇒ exit 3 at the deadline, no hang, runner never started.

### 4.4 Zero orphaned AWS resources — independently audited, read-only

| Check | Result |
|---|---|
| `eks list-clusters` in us-east-1, us-west-2, eu-west-1, ap-south-1 | **empty** |
| Both validation stacks (`fbx-netadm-07290046`, `fbx-netadm-07290125`, cluster + nodegroup) | **DELETE_COMPLETE** |
| Both validation VPCs (`vpc-0503d5e9f21f81fbb`, `vpc-0ed306a9441f321f3`) | **`InvalidVpcID.NotFound`** |
| Resources tagged `fluidbox-ephemeral=true` | **0** |
| EC2 instances / EBS volumes / unattached EIPs / `eks-cluster-sg-*` | **0 / 0 / 0 / 0** |

One NAT gateway survives (`nat-1d0c58bf66f36fed7`) — attributed to `forceplatforms-regional-nat`, created 2025-12-12, an **unrelated pre-existing project**, not this validation. The report's "4 ARNs per run" tagging-index ghosts have since aged out, consistent with its eventual-consistency explanation.

### 4.5 Verdict

| Commit | Verdict |
|---|---|
| `f81aae7` → `95e8459` `fix(k8s): close the netpol admission race…` | **ACCEPT** |
| `bd17fa3` → `7904464` `test(k8s): two-environment validation…` | **ACCEPT WITH FOLLOW-UP** |

Follow-ups (test quality, not security): `enforcement_script_is_a_bounded_convergence_loop` asserts on the script's **text**, so a reordered deadline/success check or inverted polarity could pass; `enforced_flag_parses_like_the_server` never references the server, so the two duplicated parses could silently diverge; the EKS script's N1 and N3-old **pass whether or not the race is observed**, so "vulnerability reproduced natively" rests on observed rather than required outcomes; the per-sandbox gate's effective window is `min(waitSeconds, init_grace_secs)`, not `waitSeconds` (fails closed, but §2's "no shorter clock" holds only for the boot probe); the EKS teardown audit prints but does not assert.

---

## 5. Branch 3 — five-minute demo + launch film

### 5.1 The demo, run twice from a clean Docker state

**Run 1 — a failure worth more than the success.** With `DOCKER_HOST` unset, the run failed at `initializing`: `No such image: fluidbox-replay-runner:dev`. Root cause is an environment mismatch, **not** a branch defect: `/var/run/docker.sock` symlinks to Docker Desktop's socket (whose VM was wiped), while the images live on colima; the demo's preflight uses the docker **CLI** (context-aware) but the server uses **bollard** (`DOCKER_HOST`-aware). Preflight passed against one daemon, the run failed against another.

**But the demo reported success anyway.** It printed:

```
[  8] state finalizing → failed
[  9] result: failed — None
...
every tool call crossed the server-side gate: 0 decisions
```

…followed by a cheerful next-steps block, and **exited 0**. "Every tool call crossed the server-side gate: 0 decisions" is a self-refuting sentence presented as a security receipt. Teardown was nonetheless correct and complete. This is **P1** (the branch's own reviewer rated the hypothetical P2; I reproduced it via a documented gotcha on this very machine).

**Run 2 — with `DOCKER_HOST` set, fully correct.** 5 gate decisions: 3 policy-allow, 1 policy-deny (`curl`, naming the matched pattern `\bcurl\b`), 1 human-allow after `approved_once by operator`. Real diff: `app.js` repaired **and** `deploy.log` created. `$0.00 · 0 model requests · 5 tool calls`. Total 12 s.

**Teardown verified after both runs:** 0 demo containers, 0 demo volumes, `.demo/` removed, no leftover `fluidbox-net-*`, and the user's dev stack (`deploy-postgres-1`, `deploy-litellm-1`) still 2/2 running with `deploy_fluidbox-pgdata` intact. Ports 19790/19791/15434 never collide with the dev stack's 8787/8788/5433/4000/3000. No `docker system prune`, no bare `volume rm`, no cross-project `down`.

The gate is genuinely real: the replay runner calls the same `requestPermission` → `/internal/sessions/{id}/permission` as the production runners, verdicts are server-authored (`source=policy` / `source=human`), and a deny provably suppresses the side effect (`deploy.log` absent in the deny receipts, present in the approve receipts).

### 5.2 Receipts are authentic

Forensically consistent: gapless `seq` 1→32 in all three sets, one session id per set, UUIDv7 prefixes ordered consistently with wall-clock, identical digests for identical commands across runs, and the TTL arithmetic checks out (`requested_at` + 180 s ≈ `expires_at`). **Independent corroboration:** my own run 2 produced ledger seq numbers **9, 10, 11, 13, 14, 18, 20, 21, 23, 26, 32** — matching the committed receipts and the Demo30 clip exactly.

### 5.3 The film

Five clips, all 30 fps h264, four at 1920×1080 and Vertical at 1080×1920; `SocialLoop` deliberately silent; loop seam clean (PSNR 48.3 dB between first and last frame); no true-black frames at a real threshold. I inspected frames from all five clips personally. Two are honest in exactly the way that matters: the sandbox posture card says **"network: per-run bridge"** — not zero-egress — and every value on it matches the captured `docker inspect`; Demo30 carries a persistent "DETERMINISTIC REPLAY · NO MODEL CALLS" badge.

**The problem is three superlatives.** On-screen text asserts `EVERY TOOL CALL · ONE GATE` (SocialLoop), `SERVER-SIDE POLICY GATE · EVERY TOOL CALL` (Hero45), `POLICY GATE · EVERY TOOL CALL` (Gate15, Vertical) — verified by reading the frames, not just the source. The narration is softer and defensible ("Tool calls answer to a server-side policy gate — allowed, denied, or held for a human"). And the film's own `docs/clips/CLAIMS.md` states the gate gap "was fixed the same day … (fluidbox PR #103)" — **that fix was on an unmerged branch**, so the provenance doc overstates the shipped product.

### 5.4 Verdict

All seven demo commits **ACCEPT** / **ACCEPT WITH FOLLOW-UP** (`4e415b6`, `742992b`, `d14c77e`, `a40639b`, `3c1f5c9`, `007da29`, `5b45838`). The film repo is a **sibling repository and was not integrated** — it is out of this branch's scope, and its clips are **NOT cleared for publication** as-is (§8, §9).

Follow-ups: the exit-0-on-failure receipt (P1); the demo's preflight should validate the daemon **bollard** will use, not the CLI's context; the replay-runner tests run in **no** pipeline (`ci.yml:382` globs `images/runner-lib/*.test.mjs` only); `approve/sandbox-inspect.json` commits defunct session-token values; drills (b) and (c) are pre-fix captures (old ports, the fixed "you denyd" typo).

---

## 6. Branch 4 — prime-time red team (docs only)

`e7db0ae` → `3faaac3` **ACCEPT**. The assessment is unusually rigorous and self-critical, and its central finding is correct: I reproduced it. Two of its conclusions are now stale and one of its self-imposed limits was wrong; `72f572d` adds status addenda rather than rewriting history (§8).

Independently re-verified as **still true**: BLK-03 (`#[default] HostDev` unchanged); BLK-04 verbatim (`8787:8787`, `3000:3000` — both `0.0.0.0` — with `FLUIDBOX_ADMIN_TOKEN` defaulting to the repo-published `fluidbox-eval-only` and `/var/run/docker.sock` bind-mounted, while the sibling dev compose *does* prefix `127.0.0.1:`); BLK-06 (`ci.yml:417` `workflow_dispatch`, release "UNGATED by deliberate choice"); BLK-07's mechanism (no lockfile for either runner, `npm install` not `npm ci`, dependabot npm covers only `/apps/web`).

---

## 7. Integration

Twelve source commits cherry-picked in the mandated order — tool gate → Kubernetes isolation → demo/video → red-team docs — plus two of my own.

| # | Integrated | Source | Subject |
|---|---|---|---|
| 1 | `66e0bb2` | `58b4b02` | fix(runner): gate EVERY Claude tool call via a PreToolUse hook |
| 2 | `92fec3c` | `2bcf66b` | fix(core): register ToolSearch in the canonical tool vocabulary |
| 3 | `95e8459` | `f81aae7` | fix(k8s): close the netpol admission race with a bounded observation protocol |
| 4 | `7904464` | `bd17fa3` | test(k8s): two-environment validation of the netpol admission protocol |
| 5 | `4e415b6` | `d3f18b3` | docs: design for the five-minute first-run demo + launch media |
| 6 | `742992b` | `f15a869` | docs: implementation plan for the five-minute demo + launch clips |
| 7 | `d14c77e` | `dbfeb33` | feat(replay-runner): deterministic replay driver + transcript |
| 8 | `a40639b` | `86483b3` | feat(replay-runner): image + just replay-build |
| 9 | `3c1f5c9` | `55c61a2` | feat(demo): fixture repo + demo compose |
| 10 | `007da29` | `cf31338` | feat(demo): just demo — five-minute no-key first-run + validation drills |
| 11 | `5b45838` | `489941b` | docs: surface just demo as the no-key first-run path |
| 12 | `3faaac3` | `e7db0ae` | docs: independent prime-time red-team assessment (reports only) |
| 13 | `e5cf8da` | *(this review)* | test(runner): close two gate-test mutations that restored the bypass |
| 14 | `72f572d` | *(this review)* | docs: mark the red-team findings superseded by this integration |

### Conflicts — one, resolved deliberately

`.gitignore` at commit 8: both branches append to the same block. Both lines kept; no security property involved. I then corrected `.demo-bin/` → `.demo/` in a **separate** commit rather than silently during conflict resolution, so provenance stays auditable. The committed rule named a path the demo never creates, leaving the real state directory untracked-but-visible — and a kept stack writes `.demo/admin-token`, a live admin credential, into it. Verified fixed via `git check-ignore`.

**Nothing was rejected.** I looked specifically for changes that weakened a security property to make tests pass and found none. Two defects were **corrected rather than rejected** (the ignore path; the test-coverage hole). One cosmetic residue was kept for faithfulness: `.gitignore`'s `data-gate/`, a stray from the tool-gate author's local validation environment (P3).

### Post-integration validation

| Check | Result |
|---|---|
| `cargo fmt --all --check` | **clean** |
| `cargo clippy --workspace --all-targets -- -D warnings` | **clean** (exit 0) |
| `cargo test --workspace` | **856 passed, 0 failed**, 17 suites |
| `node --test images/runner-lib/*.test.mjs` | **18 passed, 0 failed**, 2 skipped (linux-only `/proc` assertions; macOS) |
| `node --test images/replay-runner/runner/test/*.test.mjs` | **8 passed, 0 failed** |
| `pnpm build` (dashboard) | **exit 0** |
| `helm lint deploy/helm/fluidbox` | **0 failed** |
| `scripts/e2e-tool-gate.sh` (Docker provider) | **14 passed, 0 failed** (Phase 1 skipped — no model) |
| `scripts/governance-e2e.sh` (Docker provider) | **47 passed, 0 failed** |
| `scripts/netpol-admission-validation.sh` (kind + Calico) | **12/12 passed**, exit 0 |
| `just demo` end-to-end | **completed**, 5 gate decisions, full teardown |

All test runs kept `DATABASE_URL` pointed at a throwaway database (`fluidbox_gateverify`, dropped afterwards) on the local container Postgres. The user's `fluidbox` database and dev stack were verified intact afterwards.

**Not run, with reasons:** the full `just e2e` — its live-agent phases require model credits the key does not have, and issue #100 records four pre-existing red phases, so its result would not be attributable to this integration. The two suites that actually cover the changed governance path (`e2e-tool-gate`, `governance-e2e`) were run instead. EKS acceptance was not re-run: the mandate forbids creating cloud resources; the branch's EKS evidence was verified circumstantially through the teardown audit (§4.4) and behaviourally through the kind re-run.

---

## 8. Corrections — where the overnight conclusions, or mine, were wrong

**Overnight conclusions disproven:**

1. **"Live reproduction of BLK-01 requires model spend."** False. A mock upstream reproduces it for $0 and more rigorously. The gap was a missing test technique, not a budget. (`prime-time-red-team.md` §2.2/§7; addendum added.)
2. **BLK-01 and BLK-05 are no longer open**, so the NO-GO reasoning that rested on them is stale. (`launch-blockers.md`; addendum added.)
3. **Claims-audit A1 moves CONTRADICTED → PARTIALLY PROVEN** for the Claude harness. (Addendum added; the absolute wording is still unsupportable.)
4. **The subagent residual is misdescribed.** The tool-gate report calls untested subagent nesting its "most important open question" and names `Task`. This CLI version advertises **`Agent`**, not `Task`, so the policy's `Task` rule is inert; `Agent` is unmatched and will pause a supervised run instead.

**My own errors, corrected:**

5. I inferred from two same-context builds returning different digests that the runner images are non-reproducible, calling it live evidence for BLK-07. **Wrong** — `docker build -q` under BuildKit prints a per-build content digest, not a stable image ID. Tested properly: the `:dev` image built a week earlier and a fresh build have **byte-identical** dependency trees (106 packages, same hash). BLK-07's *mechanism* is real and verified statically; its *drift consequence* did not manifest in this window.
6. I flagged `.env` as carrying a live Neon `DATABASE_URL`. **Wrong** — that line is commented out; the active URL was already the local container. I kept `DATABASE_URL` unset or throwaway-scoped throughout anyway, which cost nothing.

---

## 9. Remaining findings

### P0
None open in the integrated code. Both prior P0s (BLK-01, and BLK-02 as its composition) are closed or bounded.

### P1
1. **BLK-04 — the eval quickstart is remotely exploitable by default.** `deploy/docker-compose.eval.yml` publishes `8787` and `3000` on `0.0.0.0` with a repo-published admin token and a bind-mounted docker socket, and an Operator may name any host path as a `local_copy` workspace. Unfixed by every branch, verified verbatim. **This is the single remaining launch blocker.** One-line fix plus a token default.
2. **The tool-vocabulary mismatch (§3.5b).** 23 of 30 advertised tools have no policy rule; with the gate now mandatory they pause every supervised run. This is a *consequence of the fix* and will be the first thing a new user hits.
3. **The demo exits 0 and prints a success-shaped receipt on a failed run (§5.1).** Reproduced.
4. **BLK-03 — `HostDev` is still the Docker default**: full egress plus the host gateway on the recommended quickstart, and `docs/ARCHITECTURE.md:26` / `CLAUDE.md` still say "the sandbox stays egress-free" while `README.md:243` is honest.
5. **BLK-06 — nothing gates the paths the claims depend on.** The only live-agent suite is `workflow_dispatch`-only; publishing is ungated; the replay-runner tests run in no pipeline. AT-01d unmet.
6. **AT-01a was never built.** No server-side detection of a terminal run with a non-empty diff and zero `tool.decision` events. An older pinned `runner_image` on a newer server still bypasses silently. The new runner-side tripwire helps only for images that carry it.

### P2
7. **BLK-07 supply chain** — no lockfile, `npm install`, no dependabot entry for either runner, unsigned/unattested artifacts. Mechanism verified; drift not observed.
8. **Kubernetes test quality (§4.5)** — text-asserting script test, duplicated flag parse, EKS N1/N3-old under-assertion, unasserted teardown audit.
9. **Codex harness unexamined** for the analogous gap.
10. **`docs/hosted/threat-model.md`** still carries the contradicted T1/T2 "Bypass the permission callback" row. Its §1.6 framing *survives* the fix and should be kept: cooperation is now reliably enforced, but it is still a property of a pinned third-party runtime, not a structural one.
11. **BLK-11** — README presents the 2026-07-17/22 EKS acceptances as current evidence; AT-05c unmet.

### P3
`.gitignore`'s stray `data-gate/`; committed defunct session tokens in `approve/sandbox-inspect.json`; drills (b)/(c) pre-fix captures; per-run `fluidbox-net-*` unswept on a hard kill; BLK-12 through BLK-18 unchanged.

---

## 10. Public claims — supported and unsupported

**Supported (verified in this review):** brokered MCP calls cannot execute without a server-side decision; `approved_once` is idempotent by `(session_id, tool_call_id)`; frozen `RunSpec` byte-equality; audience-scoped sandbox tokens; no upstream credential in a sandbox; tenant isolation with an RLS floor; `just check` covers fmt + clippy + tests + web build (856/0 reproduced); the demo is keyless, deterministic, isolated, and cleans up; the demo's posture card values; Kubernetes blocks run admission until enforcement is proven, **now per-sandbox as well as at boot**.

**Now supportable that was not:** on the Claude harness, in-sandbox tool calls are routed to the server-side decision by a `PreToolUse` hook, and a denial provably prevents execution.

**Still unsupported:**

| Claim | Where | Why |
|---|---|---|
| "**EVERY TOOL CALL** · ONE GATE" | SocialLoop clip | Codex unexamined; measured for `Bash`, not all 30 advertised tools; an old pinned image still bypasses |
| "SERVER-SIDE POLICY GATE · **EVERY TOOL CALL**" | Hero45 clip | same |
| "POLICY GATE · **EVERY TOOL CALL**" | Gate15, Vertical clips | same |
| "the gate gap was fixed the same day (PR #103)" | film `docs/clips/CLAIMS.md` | the fix was on an **unmerged** branch until this integration |
| "the sandbox stays egress-free" | `docs/ARCHITECTURE.md:26`, `CLAUDE.md` | false on the Docker `HostDev` default; README is honest |
| "It is for trying the run loop, not for exposing to a network" | `README.md:129` | the compose binds `0.0.0.0` with a published token |
| "The acceptance suites cover … both harnesses" | `README.md:316` | true of content, false of effect — nothing gates them |
| "ZERO EGRESS" beats | older full film (v7) | true only for Kubernetes/`Hardened`; a viewer cannot tell the mode |

The honest replacement for the absolute: *"Brokered MCP calls cannot execute without a server-side decision. On the Claude harness every tool call is routed to that decision by a PreToolUse hook; containment is the control that binds a harness or image that does not route."*

---

## 11. Verdict

### **LIMITED BETA**

Not NO-GO: the finding that made it NO-GO is fixed, and I proved the fix rather than taking it on faith — the vulnerability reproduces on `main` and does not on this branch, with real side effects, a positive control, a measured 8-second ordering proof, and six fail-closed variants. The Kubernetes race is closed at both layers with a bounded observation protocol that contains no blind sleep, weakens no isolation, and left zero cloud residue. The full bar is green: 856 Rust tests, clean fmt and clippy, a passing dashboard build, 14/14 gate acceptance, 47/47 governance, 12/12 kind, and a five-minute demo that runs and tears down cleanly.

Not RELEASE CANDIDATE, for three reasons:

1. **BLK-04 is still open** — the install path the README lists *first* hands full admin authority to any adjacent host by default. It is the smallest fix on the list and it blocks a public launch on its own.
2. **The fix's own blast radius is unresolved** — 23 of 30 advertised tools have no policy rule, so the first supervised run a new user starts will pause on ordinary agent tooling.
3. **The claims still outrun the implementation** — four clips assert a universal guarantee that is not true even post-fix, and the film's provenance doc states the fix shipped when it had not.

Not PUBLIC LAUNCH READY, additionally, because nothing gates the paths these claims depend on (BLK-06), there is still no server-side detection of a bypass (AT-01a), the Codex harness is unexamined, and the artifacts that run beside the workspace are unsigned, unpinned, and unmonitored.

**LIMITED BETA is what the evidence supports:** ship to operators who run it on a trusted network, are told plainly that the Docker default is not an egress boundary, and are given the corrected non-absolute claim. Three changes convert this to a defensible RELEASE CANDIDATE — bind the eval compose to loopback with a generated token, extend the seed policy to the tools the pinned runtime actually advertises, and soften the four absolute claims to the wording in §10.

**Do not publish the clips** until the gate claim is softened or scoped, and `docs/clips/CLAIMS.md` is corrected. That correction is now cheap: with this branch merged the statement becomes true of the Claude harness, which is exactly what the honest wording says.

---

## 12. Reproduction

```bash
# the zero-spend gate proof (13 scenarios; needs docker, no API key)
bash $CLAUDE_JOB_DIR/tmp/gateproof/matrix.sh

# the gate acceptance + governance suites (need a control plane)
bash scripts/e2e-tool-gate.sh
bash scripts/governance-e2e.sh

# kubernetes regression (creates and deletes a local kind cluster)
scripts/netpol-admission-validation.sh

# the demo (export DOCKER_HOST to the daemon holding the images — see §5.1)
FLUIDBOX_DEMO_DECISION=approve just demo

# the full bar
cargo fmt --all --check && cargo clippy --workspace --all-targets -- -D warnings \
  && cargo test --workspace && (cd apps/web && pnpm build)
node --test images/runner-lib/*.test.mjs
node --test images/replay-runner/runner/test/*.test.mjs
```
