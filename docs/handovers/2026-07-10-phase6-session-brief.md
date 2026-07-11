# Next-session brief — design-doc Phase 6: multi-harness proof (Codex)

Paste the block below as the next session's goal. Reflects everything settled/shipped
through 2026-07-10 (Phases 0–5 done; `just e2e` = 306 checks across 8 phases). Do not
start Phase 6 unprompted.

---

Continue the fluidbox "borrow the agent, on demand" build. ultrathink

READ FIRST (in order):
1. CLAUDE.md — commands, invariants (event spine + capability classes), gotchas
2. docs/HANDOVER.md (rev 7, 2026-07-10) — current state; §6 = roadmap
3. docs/plans/2026-07-10-agent-workspaces-triggers-integrations-design.md — §12 Phase 6, §17 #8
4. PLAN.md §6.2 (Harness trait) + images/sandbox-runner/ (the runner contract as implemented)

WHERE WE ARE: Phases 0–5 shipped & verified — `just check` green (98 tests), `just e2e`
= 306/306 across 8 phases. §17 #1–#3, #5–#7 SETTLED (#7: bundle pins on revisions,
upgrade = append revision); #4 explicitly deferred (brokered git-writes ride the
Phase-5 gateway when settled); #8 (public connector SDK) still waits for n=2 services.

RESEARCH FIRST (web, before any code): survey the CURRENT Codex lane — (a) the Codex
CLI/SDK surface (`codex exec`, the TS SDK, `codex mcp-server` via rmcp) and which is the
right sandbox payload; (b) how Codex consumes MCP servers + permission/approval hooks
(does a canUseTool-equivalent exist, or does governance ride the MCP boundary?);
(c) OpenAI API-key custody through LiteLLM (the facade must stay the only egress);
(d) how Codex reports usage/cost. Bring a findings note; fold it into the runner
contract mapping BEFORE writing the image.

YOUR TASK — design-doc Phase 6, "multi-harness proof":
FRAMING: add the SECOND first-party runner image (Codex) WITHOUT modifying the trigger,
workspace, policy, capability, or result-delivery model — the harness seam is the
feature (PLAN §2: same RunSpec, same internal gateway, same governance). The runner
contract is already harness-agnostic: canUseTool→/permission, events, heartbeats,
/result, fake-key LLM facade, FLUIDBOX_CAPABILITIES manifest + broker-shim.mjs (built
harness-agnostic in Phase 5 — reuse it verbatim).
Mechanics:
- images/codex-runner/ implementing the contract; harness value "codex" on revisions.
- OpenAI key custody: LiteLLM gateway only (same inversion; the facade may need an
  OpenAI-shaped /internal/llm route or LiteLLM model alias — research decides).
- Permission gate parity: every Codex tool call crosses /permission (or is denied by
  construction); capabilities mount via the same frozen manifest + broker shim.
- Registry: harness picker on agents/revisions (API + dashboard); validation that the
  runner_image matches the harness.
Acceptance (§12 Phase 6): a Claude agent and a Codex agent subscribe to the SAME event
and run through the SAME fan-out path with different runner implementations — both
governed (gate probes pass on both), both ledgered, both publish attributable results.
E2E: NEW suite phase (pattern scripts/e2e-capabilities.sh — no-model tier always, live
self-skips; the Codex live tier needs OPENAI_API_KEY in .env + gateway routing).

SETTLE WITH ME BEFORE FREEZING: none pending from §17 for this phase — but bring me the
research note before building the image (payload choice: codex exec vs SDK vs
mcp-server is a real fork).

WORKING AGREEMENT (locked, see memory): mechanical, ONE phase; done only when `just
check` AND `just e2e` fully green incl. the NEW phase; update docs/HANDOVER.md; HAND
BACK. Do not start Phase 7.

OPERATIONAL NOTES: `just e2e` owns the stack (stop :8787). Unit tests need the stack
stopped. DB tests: `set -a; source .env; set +a`. Live runs AUTONOMOUS. Shared-repo e2e
lanes: disable earlier subs before live tiers. GitHub seams: FLUIDBOX_GITHUB_API_URL +
FLUIDBOX_GITHUB_CLONE_BASE. Check `git status` FIRST — clean + synced; else ask me.
ultrathink
