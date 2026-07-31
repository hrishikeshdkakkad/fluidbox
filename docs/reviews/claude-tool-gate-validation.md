# The Claude runner executed tools without a fluidbox decision — reproduction, root cause, fix, validation

**Date:** 2026-07-29
**Branch:** `fix/claude-tool-gate`
**Commits:** `58b4b02` (the fix, tests and this report) + `505674b` (register `ToolSearch`
in the canonical vocabulary — see §5.4)
**Severity:** P0 (launch-blocking). fluidbox's central promise — *no sandbox tool call
executes without a control-plane decision* — was false for a large class of calls on the
`claude-agent-sdk` harness.

---

## 1. What was claimed, and what was actually true

The claim (PLAN.md, `CLAUDE.md` "load-bearing invariants") is that the permission gate
in `internal.rs::decide_tool_call` is *the* gate: budget → frozen-set availability →
frozen-schema args → trust tier → policy → approvals, with `tool.requested` and
`tool.decision` written server-authoritatively so audit parity never depends on runner
cooperation.

All of that is true **once the gate is asked**. It was not always asked.

A previously recorded observation (memory `fluidbox-live-agent-gate-bypass`, 2026-07-27)
was that a live agent ran `printf '<nonce>' | sha256sum` and returned the correct digest
while the session ledger held **zero** `tool.requested` / `tool.decision` /
`approval.requested` events, under a policy whose head rule was
`{match:["Bash"], action:"approve"}`. That observation is confirmed here, root-caused,
and fixed.

## 2. Root cause

**`canUseTool` is not an interception point.**

`@anthropic-ai/claude-agent-sdk` does not call `canUseTool` per tool call. It spawns the
Claude Code CLI as a child process and translates the callback into a CLI flag. From the
shipped bundle (`sdk.mjs`, 0.3.205, offset ~529932):

```js
if (lo) {                                   // lo === options.canUseTool
  if (w) throw Error("canUseTool callback cannot be used with permissionPromptToolName…");
  W.push("--permission-prompt-tool", "stdio")
} else if (w) W.push("--permission-prompt-tool", w);
```

The CLI consults that prompt tool **only for calls it decides to ASK about**. Anything it
approves on its own first — its read-only / safe-command classification, an `allowedTools`
entry, a settings allow rule, an auto-accepting `permissionMode` — executes with the
callback never running. The SDK documents this itself (`sdk.mjs` ~592337):

> `canUseTool will not be invoked for: … Bare allowedTools entries auto-approve the whole
> tool before the callback is consulted. **To gate every tool call, use a PreToolUse hook**;
> … Allow rules from settings files can also shadow the callback but are not visible here.`

So the runner was correct in every line a reviewer would look at — `canUseTool` was wired,
`permissionMode: "default"`, `settingSources: []`, no `allowedTools`, never
`bypassPermissions` — and the gate still never ran for a whole class of calls. The bug was
an absent invocation, which no assertion about decision logic can catch.

**Why it survived every acceptance run.** `scripts/e2e-live.sh:113` asserts
`tool_calls >= 1`, and demo A passes: it edits a file and runs `python3 -m unittest`, both
of which the CLI *does* prompt for, so the gate fired for those and the counter was
non-zero. `scripts/governance-e2e.sh` deliberately kills the real runner and drives the
contract itself, so it exercises only the half that always worked. Neither suite could
observe a call the runner never made.

## 3. Reproduction (pre-fix, shipped image, real model)

Run inside the shipped runner image, mirroring `images/sandbox-runner/runner/index.mjs`
option for option (`canUseTool` denies everything and records each consultation):

```
NONCE=fbx-42e01607cb559e84e47e
host-computed sha256 = 5a0cd099c1fb95fe3fbaa5c29d4fc0e34fded49b324828f054dfdd53ff0fce27

{ "cmd": "printf 'fbx-42e01607cb559e84e47e' | sha256sum",
  "tool_uses_emitted": 1,
  "gate_consultations": 0,          ← canUseTool NEVER invoked
  "ungated": ["printf 'fbx-42e01607cb559e84e47e' | sha256sum"],
  "final": "The output is:\n\n```\n5a0cd099c1fb95fe3fbaa5c29d4fc0e34fded49b324828f054dfdd53ff0fce27  -\n```" }
```

The digest is of a nonce minted seconds earlier, so it cannot be guessed, fabricated, or
served from a cache: **the command really executed and the gate really was not consulted.**

**The gap is much wider than one odd command.** An ordinary coding workload — "list the
files, read data.txt, grep for 'beta', run `wc -l data.txt`" — in the same image:

| | Bash | Read | ToolSearch | mcp__wsinfo__* |
|---|---|---|---|---|
| emitted | 3 | 1 | 2 | 1 |
| reached `PreToolUse` | 3 | 1 | 2 | 1 |
| reached `canUseTool` | **0** | **0** | **0** | 1 |

Four tool calls, zero gate consultations. Only MCP tools and mutating shell commands
reliably reached the gate. A control experiment (`printf … > file`, a mutation) *was*
gated, which is exactly why the failure looked intermittent.

## 4. The fix

`PreToolUse` fires for **every** tool call, underneath the CLI's auto-approval
short-circuit. Verified in the same image, same command that bypassed `canUseTool`:

| hook returns | hook fired | `canUseTool` fired | command executed |
|---|---|---|---|
| `{}` (log only) | 1 | 0 | **yes** — digest in `tool_result` |
| `deny` | 1 | 0 | no — `tool_result is_error=true "fluidbox deny"` |
| `ask` | 1 | **1** | follows the gate's verdict |
| `allow` | 1 | 0 | yes |

The shipped fix has the hook answer **`ask`**, which forces the call back onto the
`canUseTool` path where the existing, well-tested gate implementation still makes the
decision:

- `images/runner-lib/contract.mjs` — `forceGateDecision()` (the hook return), plus
  `GateWitness`, `EXIT_UNGOVERNED_TOOL`, and the diagnostic.
- `images/sandbox-runner/runner/index.mjs` — passes
  `hooks: { PreToolUse: [{ hooks: [preToolUseGate] }] }` to `query()`; `canUseTool` is
  otherwise **unchanged**.

**Why `ask` rather than having the hook call `/permission` itself.** A supervised approval
can block for minutes. `requestPermission` already owns the 12-minute timeout and the
forever-retry semantics for that; a hook that never awaits anything cannot time out,
throw, or become a new way to lose a decision. Measured for completeness: a hook that
blocked for 90 s did *not* time out and did *not* fail open, so both designs work — the
I/O-free one is simply the smaller risk, and it leaves the decision logic untouched.

**Second layer — the tripwire.** `GateWitness` pairs the `tool_use` blocks seen on the
message stream with the calls the gate actually decided. A `tool_result` for an
observed-but-undecided call means a tool ran ungoverned; the runner then aborts with
`EXIT_UNGOVERNED_TOOL`, records a `run.error` on the timeline, and posts **no** `/result`
(the heartbeat watchdog terminalizes the run, as for any runner crash). The hook is the
guarantee; the tripwire converts a future silent regression into a loud failure — which is
precisely what this incident lacked.

**Policy change.** With the gate mandatory it now sees tools it never saw before, and
`policies/default.yaml` sets `defaults.tool_action: approve`, so an unmatched tool would
pause every run. `ToolSearch` (schema discovery, executes nothing) joins the read-only
allow rule. This is a **behavioural change for existing deployments**: `seed_policy_if_absent`
never re-applies the seed, so a deployment with a stored policy will start seeing
previously-invisible tools arrive at the gate and fall to its own default — `approve`
(pause) in supervised runs, and `deny` in autonomous ones via `on_approval_rule`.
Operators should add the rule to their policy before deploying this runner image.

## 5. Validation

### 5.1 Hermetic regression tests — `images/runner-lib/gate.test.mjs`

12 tests, run by the existing CI step (`.github/workflows/ci.yml:382`,
`node --test images/runner-lib/*.test.mjs`). They assert the hook's shape and purity, the
tripwire's behaviour (including that it is conservative enough not to fail healthy runs),
and — structurally, against the shipped runner source — that the harness still passes a
`PreToolUse` hook, never an auto-approving `permissionMode`, and no `allowedTools`. The
structural assertions exist because the regression was *an absent call*, not a wrong
decision.

Mutation-verified (a test that cannot fail is worthless):

| mutation | result |
|---|---|
| remove the hook from `query()` (the exact pre-fix state) | 11 pass, **1 fail** |
| remove the tripwire reconciliation | 11 pass, **1 fail** |
| hook returns `allow` instead of `ask` | 11 pass, **1 fail** |
| unmutated | **12 pass, 0 fail** |

### 5.2 Live acceptance — `scripts/e2e-tool-gate.sh`

Phase 1 runs a **real agent on the real Docker provider** and asserts on an unpredictable
nonce. Phases 2–4 drive `/permission` with the sandbox's own tool-audience token after
`silence_runner` kills the runner — deliberately, so they cost no model tokens and cannot
flake on talking a live model into misbehaving.

**The decisive live result** (session `019fac64-d98a-72f3-bc08-678e21af6506`, post-fix
image, Docker provider, `claude-haiku-4-5`, policy `gate-deny`) — the identical scenario
that previously produced zero events:

```
tool.requested {"input_digest":"sha256:2eca02fb70287052",
                "summary":"printf 'fbxgate-acaf9ad75edf15bf9cd21790' | sha256sum",
                "tool":"Bash","tool_call_id":"toolu_013XrkvXtJhGDaXzpk6FDccz"}
tool.decision  {"verdict":"deny","source":"policy",
                "reason":"bash denied for the tool-gate acceptance", …}
run.result     {"outcome":"completed",
                "summary":"I don't have permission to execute that Bash command…"}

digest 0de67b1da13b0648e218950ab465aef26e1ee68b06743d8779bb26c1e42566f4: 0 occurrences
```

The gate saw the call, denied it from the authored policy, and the digest of the fresh
nonce appears **nowhere** — the command did not run.

### 5.3 Suite results

```
PHASE 1 — deny at the gate prevents execution (LIVE agent, Docker provider)
  SKIP: no reachable model (LLM upstream refused a 4-token probe)

PHASE 2 — an approval holds the tool call, then releases it exactly once
  ✓ sandbox tool-audience token extracted (session 019fac8e-df85-78a2-b9b1-4f4c005e9f78)
  ✓ session paused at awaiting_approval
  ✓ the tool call is still blocked — no verdict issued yet
  ✓ a pending approval is queued for a human
  ✓ approval recorded by a human decision
  ✓ after approval the blocked call returns allow
  ✓ approved_once decided exactly once (a faithful replay adopts, 1 intent)

PHASE 3 — the gate fails closed
  ✓ unknown tool → deny (policy default, never an implicit allow)
  ✓ invalid token refused (401) — no verdict issued at all
  ✓ runner-control credential rejected by audience (fatal, not a deny)
  ✓ first use of a tool_call_id decided normally (allow)
  ✓ same tool_call_id replayed with different input → deny
  ✓ after cancellation the session credential is revoked (no verdict issued)

PHASE 4 — an approval that expires denies, never allows
  ✓ expired approval → deny (timeout_action)

RESULT: 14 passed, 0 failed
```

Two notes on what these assertions actually pin:

- **"still blocked — no verdict issued yet"** is the ordering property the P0 was about: at
  the moment the session reads `awaiting_approval`, the runner's `/permission` call has not
  returned, so the tool provably cannot have run. It is asserted by checking the in-flight
  request is still alive, not by inspecting a status field.
- **Cancellation** produces a `401`, not a deny verdict: the terminal transition revokes the
  session's tokens, so no verdict is issued at all. `contract.mjs::requestPermission` maps
  401/403 at that route to a hard deny, so the tool still cannot run — the suite accepts
  either shape and fails only on an `allow`.

### 5.4 Other repository checks

| check | result |
|---|---|
| `cargo test -p fluidbox-core` | **119 passed, 0 failed** |
| `node --test images/runner-lib/*.test.mjs` | **18 passed, 0 failed** |
| `cargo fmt --check -p fluidbox-core` | clean |
| `cargo clippy -p fluidbox-core --all-targets -- -D warnings` | clean |

`cargo test -p fluidbox-core` initially **failed**, which is worth recording because it
caught a real omission rather than a formality:

```
policy matches "ToolSearch", which is neither canonical nor mcp__* —
add it to CANONICAL or fix the policy      (tools.rs:139)
```

The canonical tool vocabulary (`fluidbox-core::tools::CANONICAL`) is a contract: a name the
seed policy governs must be enumerable, or the Governance matrix silently omits a tool the
policy has an opinion about. `ToolSearch` is now registered there (`ToolGroup::Meta`). This
is a second-order consequence of the fix that is easy to miss — making the gate mandatory
does not only change enforcement, it changes *which tool names the control plane ever sees*,
and everything keyed on that vocabulary has to follow.

The DB-backed and full-workspace suites were not run: they need `DATABASE_URL` and, for the
live tiers, model credits.

## 6. Residual risks — stated plainly

1. **Mediation is runner-side, and always will be.** Tools execute inside the sandbox, run
   by the CLI; the control plane cannot intercept in-sandbox execution. The guarantee is
   therefore only as strong as the runner image, which is why images ship in-repo and are
   versioned with the server. An **old pinned `runner_image` on a new server still
   bypasses the gate** exactly as before — `runner_image` is a per-revision API field that
   carries forward across revisions, so this is reachable without a bad deploy. The
   existing `wrong_audience` machinery does not cover it (an old image presents the right
   audience; it simply never asks). There is no server-side detection today.
2. **We depend on upstream continuing to fire `PreToolUse` for every tool.** That is
   upstream's documented remedy for exactly this problem, and it held for every tool class
   measured (`Bash`, `Read`, `ToolSearch`, sandbox MCP). It is not a contract we control.
   The tripwire exists for the day it changes.
3. **The tripwire is deliberately incomplete.** It only trips on calls it watched being
   emitted on the message stream, so it cannot fail a healthy run — but it also cannot see
   tool calls that never surface there. **Subagent (`Task`) nested tool calls were not
   tested** and may not surface as top-level `tool_use`/`tool_result` blocks; if they do
   not, they would be neither gated by our hook nor caught by the tripwire. This is the
   most important open question left.
4. **The tripwire detects, it does not prevent.** By the time a `tool_result` arrives the
   tool has already run. It converts a silent bypass into a stopped run, nothing more.
5. **The Codex harness was not examined.** It uses a different mechanism (the
   sandbox-gate-shim wrapping stdio MCP servers plus codex's own approval flow). Whether it
   has an analogous gap is untested and should be checked before relying on it.
6. **Policy blast radius** — see §4. Existing deployments will see previously-invisible
   tools at the gate.

## 7. Commands

```bash
# hermetic regression tests (also run in CI)
node --test images/runner-lib/*.test.mjs

# rebuild the runner image with the fix (context = images/)
docker build -t fluidbox-sandbox-runner:dev -f images/sandbox-runner/Dockerfile images

# the acceptance suite (needs a control plane; Phase 1 additionally needs a live model,
# and self-skips with a clear notice when the LLM upstream refuses a 4-token probe)
just server                      # or point FLUIDBOX_API_URL at a running one
bash scripts/e2e-tool-gate.sh

# the standalone SDK probes used for root-causing live in the job scratch dir; the
# reproduction is a ~40-line script that mirrors index.mjs and denies in canUseTool.
```

## 8. Cost

All live work used `claude-haiku-4-5`. Roughly 20 short probe/agent runs, each a handful
of tool calls: **well under $1 in model spend**. The session that produced the decisive
evidence above was a single-tool-call run.

The validation was cut short by an external blocker: the `ANTHROPIC_API_KEY` in `.env`
reached **`"Your credit balance is too low to access the Anthropic API"`** partway through
(confirmed against `api.anthropic.com` directly, request id
`req_011CdVrQeuBKgDZPH8HotXwn`). Everything requiring a live model after that point could
not run; the suite's Phase 1 self-skips on it, and §5.3 records what that left unproven.

## 9. Environment notes (and one thing I broke)

- The validation ran against a **dedicated** Postgres (`fbx-gate-pg`, colima,
  `127.0.0.1:5435`, database `fluidbox_gate`) and a **dedicated** LiteLLM
  (`fbx-gate-litellm`, `127.0.0.1:4010`), with the control plane on `:8799` / `:8790`, so
  it touched neither the user's demo database nor their gateway.
- **A sandbox belonging to another running control plane was terminated.** Two fluidbox
  servers sharing one Docker daemon is a footgun: `workers.rs:65` classifies a managed
  container whose session is absent from *its* database as an orphan
  (`Ok(None) => true, // unknown session → orphan`) and terminates it. My server booted
  against an empty database on the shared colima daemon and its boot sweep reaped session
  `019fac5f-590e-7030-9d36-13d57725ccb1`, which belonged to the pre-existing server on
  `:8787`. Worth considering a deployment-scoped label on managed containers so the sweep
  cannot cross deployments.
- Docker Desktop became unresponsive mid-session under disk pressure (the host volume hit
  96% during image builds), taking the compose Postgres on `:5433` with it; colima was
  unaffected. One `cargo build` failed with `No space left on device` for the same reason.
