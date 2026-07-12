# fluidbox — Phase 6: Codex as the second harness (design + settled plan)

**Date:** 2026-07-12
**Status:** APPROVED plan, not yet implemented. Adversarially reviewed by Codex (gpt-5.6-sol @ xhigh) — 2 rounds, REDESIGN → ACCEPT-WITH-CHANGES; all required changes folded in below.
**Relationship to other docs:** `PLAN.md` is authoritative for runtime architecture + milestone invariants; `docs/plans/2026-07-10-agent-workspaces-triggers-integrations-design.md` §12 Phase 6 / §17 is the product roadmap this slice completes; `docs/HANDOVER.md` is current build truth. This doc is the Phase-6 spec + step plan + review record.

## Context

fluidbox has shipped Phases 0–5.6 of the "borrow the agent, on demand" axis on ONE harness (Claude Agent SDK, a Node payload in the sandbox). Phase 6 adds OpenAI **Codex** as the SECOND harness **without modifying the trigger, workspace, policy, capability, or result-delivery model**. The harness seam IS the feature. Directive (user): everything that works with claude-agent-sdk must work with codex and **behave the same way**; the abstraction must make harness #3+ cheap (mechanical, documented, fail-closed).

**§12 acceptance:** a Claude agent and a Codex agent subscribe to the SAME event and run through the SAME fan-out with different runner images — both governed (gate probes pass on both), both ledgered, both publishing attributable results.

**Verified ground truth** (3 exploration agents + spot-checks): the permission gate (`internal.rs::decide_tool_call`), event schema/Redactor, capability freeze + `FLUIDBOX_CAPABILITIES` manifest, broker + `broker-shim.mjs`, and the session-token/heartbeat/result contract are already harness-neutral. Couplings to change: (1) orchestrator's hardcoded `ANTHROPIC_*` env trio (`orchestrator.rs:101-129`) + unvalidated `harness` string defaulting to the claude image (`api.rs:326-329, 424-431`); (2) the Anthropic-only LLM facade (URL/headers/SSE-metering; `gpt-*` has no pricing row → cost budget blind); (3) policy engine expects Claude tool names/shapes (shell classifier wants `input.command` as a string; `extract_paths` wants `file_path`/`edits[].file_path`; `read_only_denial` hardcodes Claude names). The core `Harness` trait (`traits.rs:74-88`) is dead code — zero impls, zero call sites.

**Codex 0.144.1 facts** (from openai/codex `rust-v0.144.1` source + docs + local binary): `wire_api="chat"` REMOVED — Responses API only (LiteLLM supports `/v1/responses` natively incl. cost tracking); `codex exec` + TS SDK have NO approval hooks (disqualified — invariant #6); `codex mcp-server` approval replies are bugged (#18268); **`codex app-server`** is the typed JSON-RPC surface with first-class `execCommandApproval`/`applyPatchApproval` requests answered `{decision}`; `approval_policy=untrusted` auto-runs a trusted read set UNLESS execpolicy rules empty it; MCP approvals are annotation-driven and unreliable; custom `[model_providers]` with `env_key` + `requires_openai_auth=false` needs no login; `CODEX_HOME` relocates all state; update-check phone-home is un-disableable (non-fatal; egress-controlled); `[otel]` off by default; models: gpt-5.4 / **gpt-5.4-mini** (cheapest) / gpt-5.5 / gpt-5.6-{luna,sol,terra}.

## Settled at this boundary (user, 2026-07-11)

1. **Payload: `codex app-server`** (stdio JSON-RPC, typed protocol; pin `@openai/codex@0.144.1` exact — same discipline as the pinned Claude SDK). mcp-server rejected (bugged approvals); exec/TS-SDK disqualified (no approval hooks → invariant #6 violation).
2. **Gate parity: STRICT force-ask-everything.** The runner image ships execpolicy rules emptying codex's trusted command set → EVERY exec escalates → every action crosses `/permission` with the full `tool.requested`/`tool.decision` ledger pair. **(Round-2: post-hoc ledgering is NEVER a releasable mode — if empty execpolicy can't force every exec incl. trusted reads through the gate, interpose another pre-exec mechanism or block the codex release.)**
3. **E2E: 2 tiers** — no-model parity probes + live tier (`OPENAI_API_KEY`, self-skips). The fake-Responses conformance tier was descoped by the user. (Round-1 added a deterministic tier-0 supervisor protocol-replay harness that uses NO model and NO real codex binary — it does not resurrect the descoped tier.)
4. **Default codex model: `gpt-5.4-mini`** @ low reasoning effort (`FLUIDBOX_DEFAULT_CODEX_MODEL`) — the haiku-analog cost directive.

**WORKFLOW DIRECTIVE (user): every implementation step AND review step gets an adversarial review by Codex MCP — model `gpt-5.6-sol`, `config.model_reasoning_effort="xhigh"`, `sandbox=read-only`.** Per step: implement → verify → codex review of the diff → incorporate (record dissents) → next step.

## Preconditions

- **The working tree holds the uncommitted dashboard redesign (~29 files).** The working agreement requires a clean tree before a phase starts, and Step 9 edits files the redesign owns (`HarnessPicker.tsx` is untracked). → **Land (commit) the dashboard redesign first**, or explicitly park it; do not interleave. Steps 1–8 touch no `apps/web` files.
- `.env` gains `OPENAI_API_KEY` (optional — live tier self-skips without it).

## Design essence

**The runner contract over HTTP IS the harness abstraction.** A harness = a runner image implementing: the 4 endpoints (`/permission`, `/events`, `/heartbeat`, `/result` + broker-shim's `/tools/call`), the env contract (`FLUIDBOX_*`), the **canonical tool vocabulary** (now-explicit contract invariant: names/shapes crossing `/permission` MUST be canonical — `Bash{command: string}`, `Edit/Write/MultiEdit{file_path | edits[].file_path}`, `Read/Glob/Grep/LS`, `mcp__<server>__<tool>`; canonicalization is runner-side), and the canonical event dot-names. Server-side harness knowledge is EXACTLY: validate id, default image, default model, per-harness env extras — a plain match (connectors/mod.rs discipline, §17 #8), NOT a trait registry.

**UNCHANGED SEMANTICS, additive hardening only:** `policy.rs` semantics + seed `policies/default.yaml` untouched; the gate ORDER in `internal.rs` unchanged (additive: approval **digest binding** — tool + input_digest columns already exist; only compare-on-conflict is added; no migration); `event.rs` schema untouched (additive Redactor patterns); `run_service.rs` freeze semantics untouched (additive: `create_run` validates `harness` fail-closed at zero spend); `broker.rs`, dashboard timeline, SSE, deliveries, connectors untouched. **NO migrations.**

**Governance parity mechanics under codex:**
- **exec** → app-server `execCommandApproval` → supervisor canonicalizes argv → `tool.requested` → `POST /permission` (tool_call_id = codex `callId`, stable across retries) → reply `{decision:"approved"|"denied"}` — **approved ONCE only, NEVER `approved_for_session`** (session-scope grants are the server's job; a codex-side cached approval would bypass the gate on later calls).
- **argv unwrap rule:** if argv is `[shell, -c|-lc, script]`, canonical `command` = the inner script; else shlex-join. (Naive join makes `bash -lc "git status"` match no allow-prefix → over-escalation + ReadOnly over-deny; unwrap is fail-safe — the metachar screen applies to the unwrapped script.) Dedicated unit fixtures.
- **exec cwd constraint:** the supervisor normalizes every exec `cwd` and requires it inside the frozen workspace (reject outside/missing/symlink-escaping) — a `cat x` verdict is not equivalent if codex runs it from `$CODEX_HOME`.
- **apply_patch** → `applyPatchApproval{fileChanges}` → canonical `MultiEdit{edits:[{file_path},…]}` (moves include BOTH source+dest; `extract_paths` already reads `edits[].file_path`; `MultiEdit` not read-safe → correctly denied under ReadOnly). **Accepted asymmetry:** codex can delete a `/workspace` file via an auto-allowed MultiEdit path rule where Claude needs `rm` (escalates) — within the existing containment envelope (disposable workspace + diff capture); op-type + cwd ride ADDITIVELY in the canonical input (ledger keeps them; policy ignores unknown fields). Supervisor REJECTS exec requests carrying env-mutation/permission-amendment fields outright (fail-closed).
- **MCP: never rely on codex's approval plumbing.** Brokered servers → existing `broker-shim.mjs` VERBATIM (supervisor auto-allow; the broker endpoint re-runs the identical gate server-side). Sandbox servers → NEW `sandbox-gate-shim.mjs`: a gating stdio proxy that serves the FROZEN `tools/list` itself (manifest now carries sandbox tool snapshots too), spawns the real subprocess, on every `tools/call` emits `tool.requested` + preflights `/permission`, forwards only on allow, scrubs the child env. Fallback if it slips: `create_run` refuses codex + sandbox-class servers at zero spend.
- **Tool-surface census + lockdown** (fail-closed: enumerate and disable): `web_search` OFF, `unified_exec`/PTY OFF, js_repl/skills/plugins/view_image/multi-agent/parallel OFF/verified-absent. E2E asserts the materialized config against the REAL pinned binary (effective-config read).
- **Config immutability:** root-owned read-only `config.toml` (entrypoint materializes as root, chmods, drops to the runner uid) + security-critical settings re-asserted as CLI `-c` overrides; `/workspace` is NEVER trusted; project config/`AGENTS.md` discovery disabled (`project_doc_max_bytes=0` + equivalent); system prompt injected via app-server `developer_instructions`, not a repo-discoverable doc.
- **Codex-specific startup egress** (update check) structurally null-routed in the image; e2e network census asserts no unexpected egress succeeds.
- **Autonomy** unchanged (`/permission` resolves instantly server-side in autonomous mode; supervisor is mode-blind; codex NEVER configured `approval_policy=never`). **Trust tier / fork PRs** — gate-side, harness-neutral; canonical names make them bite for codex.
- **Budgets:** tool-call budget now counts UNIQUE PERSISTENT INTENTS server-side (see gate hardening), not runner-posted events; cost/token via the facade OpenAI meter; wall-clock/watchdog unchanged.

**LLM facade — second dialect + enforcement boundary:** keep the single `/internal/llm/{*rest}` route; dispatch inside `facade::messages` on `run_spec.harness`. Both dialects gain: exact suffix ALLOWLIST (claude: `v1/messages` + `v1/messages/count_tokens`; codex: `v1/responses`; reject all else incl. encoded slashes — closes the pre-existing master-key-proxy hole); body validation — `model == RunSpec.model` (422), reject server-executed tool types per dialect, allowlist client-executed tool types from golden fixtures of both pinned SDKs; codex branch forces `store=false` + strips/rejects `previous_response_id`/conversation state, `Authorization: Bearer <master>` only, OpenAI-shaped error bodies, `codex+llm_upstream_is_anthropic` → refuse. Metering: shared INCREMENTAL SSE decoder (partial-line retention across chunks — fixes a latent claude undercount); DRAIN upstream on client disconnect (not abort — the LiteLLM callback stays a stub); OpenAI parser on `response.completed`/`response.incomplete` with `input = input_tokens − cached` (saturating), `cache_read = cached`, reasoning never double-counted; token budget sums ALL categories both dialects; `usage.rs` price entries become per-category rates (uncached-in/cached-in/out/cache-write). Budget stop stays pre-proxy (soft ceiling, honestly documented — one in-flight response can overshoot, true for claude today).

**Gate hardening (digest binding):** approval/decision rows keyed `(session_id, tool_call_id)` COMPARE the stored tool + input_digest on reuse — **mismatch = HARD PROTOCOL REJECT** (deny + security-flavored ledger event), never inherits the old verdict. The server records an intent row per gate decision (all verdict kinds, filtered out of the approvals inbox/API) and emits `tool.requested` exactly once itself; `tool_call_count` counts unique intents; the claude runner's own `tool.requested` emission is removed in the shared-lib refactor (budget parity no longer trusts runner cooperation).

**Supervisor contract compliance:** independent 10s heartbeat (never coupled to approval waits); `/permission` client timeout 12min > server TTL 10min, retry forever reusing the same tool_call_id; token-renew loop (NEW — added to BOTH harnesses via the shared lib; server-side renew hardened: server-capped TTL, terminal-session refusal, token revocation on terminal transition); PID-1 + codex child monitor (unexpected exit → `run.error` + `/result failed` + exit); delta suppression (one `agent.message` per completed `AgentMessage`; drop `*Delta`, `AgentReasoning*`, `TokenCount`); `/result` from the final message; `tool.completed` NOT emitted (claude parity).

## Implementation steps (each: implement → verify → codex gpt-5.6-sol xhigh review → incorporate)

**Step 0 — This design doc** (done: rounds 1–2 folded in).

**Step 1 — Config + harness registry (Rust).** `config.rs`: `codex_sandbox_image` (`FLUIDBOX_CODEX_SANDBOX_IMAGE`, default `fluidbox-codex-runner:dev`), `default_codex_model` (`FLUIDBOX_DEFAULT_CODEX_MODEL`, default `gpt-5.4-mini`). NEW `crates/fluidbox-server/src/harness.rs` (plain match): `is_known`, `default_runner_image`, `default_model`, `runner_env(...)` (claude → `ANTHROPIC_*` trio; codex → empty). DELETE the dead `Harness`/`SessionEnv` from `traits.rs`. *Verify:* unit tests.

**Step 2 — API validation + per-harness defaults.** `api.rs::create_agent` + `add_revision`: unknown harness → 422; per-harness image/model defaults; harness-switch re-defaults runner_image unless explicitly given. *Verify:* unit + e2e tier-1.

**Step 3 — Orchestrator env seam.** `orchestrator.rs:101-129`: keep the generic `FLUIDBOX_*` block; replace the hardcoded Anthropic trio with `env.extend(harness::runner_env(...))`. *Verify:* claude live tier green (regression); codex probe has no `ANTHROPIC_*`.

**Step 4 — Facade: second dialect + enforcement boundary + metering overhaul + gate digest binding.** Per Design. *Verify:* parser fixtures (incl. split-across-chunks, LiteLLM-shaped); allowlist + body-validation unit tests; digest-mismatch reuse denied; pricing; budget stop fires on OpenAI usage.

**Step 5 — Shared runner lib + renew hardening.** NEW `images/runner-lib/` (`contract.mjs` + moved `broker-shim.mjs` + new `sandbox-gate-shim.mjs`); refactor claude `index.mjs` to import it; build context → `images/` with per-image `-f`; `justfile` `sandbox-build`/`codex-build`. Server-side renew hardening. *Verify:* claude image builds; claude live tier green; renew unit tests.

**Step 6 — Codex runner image + supervisor.** NEW `images/codex-runner/{Dockerfile, runner/index.mjs}` per Design (pinned `@openai/codex@0.144.1`, `CODEX_HOME`, config materialization, app-server driver, canonicalization + cwd/field guards, event pump, lockdowns, config immutability, egress null-route, `developer_instructions` system prompt, `model_reasoning_effort="low"`). Redaction additions (`fbx_sess_*`/`sk-proj-*`; scrub summaries/artifacts/delivery payloads; raw diffs stay a protected artifact class). *Verify:* protocol-replay (Step 8) is the real gate; image builds; malicious-repo fixture no-ops; real-binary effective-config asserts lockdowns.

**Step 7 — sandbox-gate-shim** (photograph-preserving, per Design). *Verify:* tier-1 canonical `mcp__ws__*` probes; protocol-replay frozen-list + drifted-tool refusal; live sandbox-tool call if attached.

**Step 8 — E2E phase 10 + protocol-replay + deploy wiring.** NEW `scripts/e2e-codex.sh` wired as PHASE 10: tier-0 deterministic supervisor protocol-replay (fake codex emitting vendored app-server JSON-RPC → the real supervisor against the real control plane: argv canonicalization direct+wrapped, patch add/update/delete/move, denied-not-forwarded, approved-once, env-amendment reject, malicious-config no-op, shim frozen-list); tier-1 no-model parity probes (harness validation, canonical Bash/MultiEdit/mcp verdicts, ReadOnly, approved-id-reuse-with-changed-input denied, facade allowlist/model-mismatch); tier-2 live self-skip (the §12 demo — claude + codex on the same PR event; strict-mode benign-cat-gated; pre-execution patch-approval + denied-command-didn't-run; no-leak canonical-Bash; non-zero usage/cost). `deploy/litellm/config.yaml` += `gpt-5.4-mini → openai/gpt-5.4-mini` + catch-all; compose env += `OPENAI_API_KEY`; `.env.example` += the three vars. *Verify:* `just e2e` fully green with and without `OPENAI_API_KEY`.

**Step 9 — Dashboard (LAST; after the redesign lands).** `HarnessPicker.tsx` codex `available:true`; per-harness MODELS in `agents/new/page.tsx`. Presentation-only; heed `apps/web/AGENTS.md` (modified Next.js). *Verify:* `pnpm build` via `just check`.

**Step 10 — Docs + settlements + memory.** `CLAUDE.md` (harness registry + canonical-tool-vocabulary invariant + two-image note; extension-points rewording, trait removed); this doc's §17 records; `PLAN.md` §6.2 harness bullet (flag to user — user-authored); `docs/HANDOVER.md` rev 10; auto-memory `fluidbox-sequencing` at handback.

## §17-style settlement records (Phase 6)

- Payload = `codex app-server` (pinned 0.144.1); mcp-server/exec/TS-SDK rejected with cause.
- Gate parity = strict force-ask-everything; post-hoc ledgering is never a releasable mode.
- MCP governance = shims (brokered reuses broker-shim; sandbox uses the new gate-shim); codex approval plumbing is bypassed by construction.
- Facade = a real second enforcement boundary for both dialects (suffix allowlist, model pin, server-tool rejection, codex stateless).
- Tool-budget source = unique persistent server-side intents; digest-mismatch on a reused id = hard reject.
- Accepted asymmetries recorded: MultiEdit delete-vs-rm; `AGENTS.md`-style prompt replaced by `developer_instructions`.
- **DISSENT (F9):** declined to teach `policy.rs` patch op-types/cwd/env; compensated by supervisor cwd-in-workspace enforcement + env/permission-field rejection + additive ledger fields.

## Trust model note (pre-existing, follow-up track — NOT Phase 6)

Agent-executed code shares the container with the runner and can read `FLUIDBOX_SESSION_TOKEN` from its own process environment regardless of tool policy; runner-posted narrative events are advisory (authoritative decisions/status/usage are server-emitted). Every run today is `NetworkMode::HostDev` — **Hardened mode is designed-but-NOT-active** in production. Parity-neutral (identical for claude). Follow-up ticket (needs owner + milestone; prerequisite for claiming hardened production isolation): scoped credential split (LLM-only token vs runner-control token), Hardened-as-default in prod, ReadOnly read-path screen (deny `/proc`, `/sys`, home/config, credential files). Also deferred + recorded: LiteLLM callback as a reconciliation meter; atomic budget reservation / per-session model-call serialization.

## Risk register

1. **execpolicy can't fully empty the trusted set** → silent audit/budget/policy gaps. *Mitigation:* exact pin; tier-2 HARD assertion (bare `cat` must gate); else interpose another pre-exec mechanism or block the release.
2. **app-server protocol drift** (`[experimental]`). *Mitigation:* exact pin; vendor `codex generate-json-schema` output at build (drift = build-time diff); centralize the canonicalizer.
3. **argv→Bash canonicalization mismatch.** *Mitigation:* unwrap-then-shlex + fixtures; tier-1 probes; tier-2 asserts benign `git status` auto-allows.
4. **LiteLLM `/v1/responses` usage fidelity.** *Mitigation:* LiteLLM-shaped fixtures; tier-2 asserts non-zero usage+cost; "usage unparsed" telemetry alarms.
5. **Uncommitted dashboard redesign** collides with Step 9 / `just check`. *Mitigation:* precondition — land it first; steps 1–8 don't touch `apps/web`.

## Verification (phase exit bar)

- `just check` green (fmt, clippy -D warnings, unit incl. new harness/facade/pricing tests, web build).
- `just e2e` green: all 10 phases, live tiers included (claude on haiku, codex on gpt-5.4-mini) — the §12 sentence demonstrably true.
- Security spot-checks: codex sandbox env has no real key (session token only); ledger shows no prompts; strict-mode + no-leak + effective-config assertions green.
- Every step's codex (gpt-5.6-sol xhigh) review completed; findings incorporated or dissents recorded here.
- `docs/HANDOVER.md` updated; hand back. **Do NOT start Phase 7.**

## Explicitly out of scope

Phase 7 verticals (Slack); M2 MicroVMs; §17 #4 brokered git-writes; the fake-Responses conformance tier (descoped; tier-0 replay is NOT a resurrection — no model, no codex binary); cross-harness `tool.completed`; CMA/native-loop harnesses; committing the dashboard redesign (separate precondition).
