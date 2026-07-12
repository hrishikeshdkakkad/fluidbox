# Next-session brief — Phase 6: Codex as the second harness (IMPLEMENTATION)

Paste the block below as the next session's goal. The plan is designed, adversarially
reviewed twice by Codex, and APPROVED — this session executes it. Reflects state through
2026-07-12 (Phases 0–5.6 done; `just e2e` = 437 checks / 9 phases green).

---

Continue the fluidbox "borrow the agent, on demand" build — implement Phase 6 (Codex, the
second harness). ultrathink

READ FIRST (in order):
1. CLAUDE.md — commands, invariants (event spine, capability classes, credential inversions), gotchas.
2. docs/plans/2026-07-12-phase6-codex-harness-design.md — THE Phase-6 spec: settled decisions, design essence, the 10 implementation steps, the 2 Codex review rounds folded in, §17 records, trust-model note, risk register. This is authoritative for what to build.
3. docs/HANDOVER.md (rev 9) — current build truth; §6 roadmap.
4. docs/plans/2026-07-10-agent-workspaces-triggers-integrations-design.md §12 Phase 6 + §17 (the product framing this slice completes).
5. PLAN.md §2 invariants (esp. #2 harness-agnostic runner contract, #6 autonomous≠ungoverned) + §6.2 (the seams).

WHERE WE ARE: Phases 0–5.6 shipped & verified live. Phase 6 adds OpenAI Codex as the
SECOND harness with EXACT behavioral parity to the Claude Agent SDK harness, generalizing
the harness seam so #3+ is cheap. The runner contract over HTTP already IS the abstraction;
the design doc's step plan is the build order.

SETTLED (do not re-litigate — see the design doc):
- Payload = `codex app-server` (typed JSON-RPC over stdio), pin `@openai/codex@0.144.1` exact. (exec + TS SDK have no approval hooks → invariant #6; mcp-server approvals bugged, #18268.)
- Gate parity = STRICT force-ask-everything (execpolicy empties codex's trusted set; EVERY exec crosses /permission). Post-hoc ledgering is NEVER a releasable mode — if the knob can't force it, block the codex release.
- MCP governance rides SHIMS, never codex's approval plumbing: brokered → broker-shim.mjs verbatim; sandbox → new sandbox-gate-shim.mjs (photograph-preserving).
- Facade becomes a real 2nd enforcement boundary (suffix allowlist, model==RunSpec.model, server-tool rejection, codex forced stateless store=false); OpenAI Responses metering (incremental SSE decoder, cached-subtract math, per-category pricing); tool-budget source = unique server-side intents (digest-mismatch on a reused id = hard reject).
- Default codex model = gpt-5.4-mini @ low effort (FLUIDBOX_DEFAULT_CODEX_MODEL). Live runs stay cheap (haiku for claude / mini for codex).
- E2E = 3 tiers in scripts/e2e-codex.sh (PHASE 10): tier-0 deterministic supervisor protocol-replay (no model, no real codex binary), tier-1 no-model parity probes, tier-2 live §12 demo (self-skips w/o OPENAI_API_KEY).
- NO migrations; policy.rs semantics + seed policy + gate ORDER untouched (additive hardening only).

PRECONDITION: the working tree currently holds the UNCOMMITTED dashboard redesign (~29 files).
Steps 1–8 touch no apps/web files, but Step 9 (flip HarnessPicker codex available:true) does.
Check `git status` FIRST — either land/commit the dashboard redesign, or confirm with me it's
parked, before starting. Clean + synced expected; if not, ask me.

WORKFLOW DIRECTIVE (locked, user): at EACH implementation step, after verifying, get the
step's diff adversarially reviewed by Codex MCP — model `gpt-5.6-sol`,
config.model_reasoning_effort="xhigh", sandbox=read-only, cwd=repo root. Incorporate
findings; record dissents in the design doc. (Rounds 1–2 already reviewed the plan itself.)

WORKING AGREEMENT (locked, see memory): mechanical, ONE phase; done only when `just check`
AND `just e2e` fully green incl. the NEW phase 10 (live tiers on haiku/gpt-5.4-mini); update
docs/HANDOVER.md (rev 10) + auto-memory; HAND BACK. Do NOT start Phase 7.

OPERATIONAL NOTES: `just e2e` owns the stack (stop :8787 first). Unit + DB tests need the
stack stopped (`set -a; source .env; set +a`). FLUIDBOX_BIND=0.0.0.0:8787. Live runs
AUTONOMOUS. GitHub test seams: FLUIDBOX_GITHUB_API_URL + FLUIDBOX_GITHUB_CLONE_BASE. Fakes
the control plane pools to MUST be ThreadingHTTPServer. `.env` gains OPENAI_API_KEY (optional).
ultrathink

---

## Quick reference — the 10 steps (full detail in the design doc)

0. design doc (done). 1. config + `harness.rs` registry + delete dead trait. 2. api.rs
validation + per-harness defaults. 3. orchestrator env seam. 4. facade 2nd dialect +
enforcement + metering + gate digest-binding. 5. shared `images/runner-lib/` + renew
hardening. 6. `images/codex-runner/` image + supervisor. 7. `sandbox-gate-shim.mjs`.
8. `scripts/e2e-codex.sh` (phase 10) + litellm/compose/.env wiring. 9. dashboard (LAST).
10. docs + settlements + memory.

Approved plan file (working copy): `~/.claude/plans/phase-6-codex-harness-transient-emerson.md`
(mirrors this design doc; the in-repo `docs/plans/2026-07-12-phase6-codex-harness-design.md`
is the durable reference).
