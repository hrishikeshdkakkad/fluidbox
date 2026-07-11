# Next-session brief — design-doc Phase 5: capability & MCP catalog

Paste the block below as the next session's goal (kept ≤4000 chars; the READ FIRST
docs carry the detail). Reflects everything settled/shipped through 2026-07-10
(pushed; code frozen at 390476e, later commits docs-only).

---

Continue the fluidbox "borrow the agent, on demand" build. ultrathink

READ FIRST (in order):
1. CLAUDE.md — commands, invariants (incl. the event spine), gotchas
2. docs/HANDOVER.md (rev 6, 2026-07-10) — current state; §6 = roadmap
3. docs/plans/2026-07-10-agent-workspaces-triggers-integrations-design.md — §3.6, §5.3, §8, §10, §12 Phase 5, §17 #4/#7

WHERE WE ARE: Phases 0–4 shipped & verified — `just check` green (81 tests), `just e2e` = 236/236 across 7 phases. Tree clean & pushed; code frozen at 390476e (later commits docs-only). Phase 4 (GitHub PR fan-out on the connector seam) details in HANDOVER §1; §17 #1–#3 SETTLED: App-only identity; default events opened+reopened (synchronize opt-in); stable results updated in place.

YOUR TASK — design-doc Phase 5, "capability & MCP catalog":
FRAMING THAT GOVERNS EVERYTHING: capabilities are the LAST of the four optional inputs around an agent (workspace/context/capabilities/result — three shipped). EXACTLY two tool classes (§8.3); the split IS the security model: (1) SANDBOX tools — packaged in the runner image/bundle, contained by the sandbox; (2) BROKERED tools — the control plane turns the sealed key server-side (same inversion as the LLM facade and git fetch); a credential NEVER enters a sandbox. No arbitrary lifecycle hooks. Attach ≠ allow: a bundle makes a tool AVAILABLE; the permission gate judges every call. Authority stays an intersection (connection ∩ bundles ∩ subscription ∩ trust tier ∩ policy); narrowing REMOVES, never adds (§3.5).
Mechanics (details in §3.6/§8/§10):
- capability_bundles registry: versioned, append-only like agent revisions; attachment refs on revisions (agent_revisions.capability_bundles column exists, empty).
- RunSpec freezes EXACT bundle versions + discovered MCP tool-schema SNAPSHOTS (photograph rule — silent schema drift is a supply-chain vector). Per §8.2 an MCP attachment records identity/digest, transport, schema snapshot, connection refs, egress, policy defaults, health.
- Every MCP/custom call crosses the SAME permission gateway (policy already matches mcp__*; ReadOnly tier already denies it). Ledger: tool identity, input digest, decision, status, latency, cost — never secrets.
- Brokered-tool gateway on the internal plane (session-token auth): intent → policy verdict → sealed credential used control-plane-side → result + ledger.
- Runner contract extension: mount tools / launch MCP servers from the frozen manifest (images/sandbox-runner is sanctioned Node; `just sandbox-build` after edits).
- Per-run/subscription capability narrowing enforced in the ONE run_service::create_run.
Acceptance (§12): two agents triggered by the SAME event carry different bundles; each uses only its frozen capabilities; every call appears in the governed ledger. E2E: NEW suite phase (pattern scripts/e2e-github.sh — no-model tier always runs, live tier self-skips).

SETTLE WITH ME BEFORE FREEZING THE SCHEMA (§17 #7): bundle versioning/upgrade for existing revisions (rec: revisions PIN exact bundle versions; upgrade = append a new revision — keeps the append-only audit story; "latest" selector only as explicit opt-in). ALSO §17 #4 (first brokered git-write operations) — settle only if a brokered git-write tool is in scope; else defer explicitly.

WORKING AGREEMENT (locked, see memory): implement mechanically, ONE phase; done only when `just check` AND `just e2e` are fully green incl. the NEW e2e phase; update docs/HANDOVER.md; HAND BACK. Do not start Phase 6.

OPERATIONAL NOTES: `just e2e` owns the stack (stop :8787 first). Unit tests also need the stack stopped. DB tests: `set -a; source .env; set +a`. E2E live runs must be AUTONOMOUS. Governance phase inside `just e2e` covers the permission path. Shared-repo e2e lanes: disable earlier subscriptions before live tiers — they fan out too (bit us in Phase 4). GitHub seams: FLUIDBOX_GITHUB_API_URL + FLUIDBOX_GITHUB_CLONE_BASE. Check `git status` FIRST — clean + synced with origin/main; else ask me. ultrathink
