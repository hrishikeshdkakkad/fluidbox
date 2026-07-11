# Next-session brief — design-doc Phase 5: capability & MCP catalog

Paste the block below as the next session's goal (kept ≤4000 chars; the READ FIRST
docs carry the detail). Reflects everything settled/shipped through 2026-07-10
(pushed; code frozen at 390476e, later commits docs-only). Includes a
web-research-first step: the MCP ecosystem must be surveyed fresh, not recalled.

---

Continue the fluidbox "borrow the agent, on demand" build. ultrathink

READ FIRST (in order):
1. CLAUDE.md — commands, invariants (incl. the event spine), gotchas
2. docs/HANDOVER.md (rev 6, 2026-07-10) — current state; §6 = roadmap
3. docs/plans/2026-07-10-agent-workspaces-triggers-integrations-design.md — §3.6, §5.3, §8, §10, §12 Phase 5, §17 #4/#7

WHERE WE ARE: Phases 0–4 shipped & verified — `just check` green (81 tests), `just e2e` = 236/236 across 7 phases. Tree clean & pushed; code frozen at 390476e (later commits docs-only). Phase 4 details in HANDOVER §1; §17 #1–#3 SETTLED: App-only identity; default events opened+reopened (synchronize opt-in); results updated in place.

RESEARCH FIRST (web, before any schema): survey the CURRENT MCP ecosystem — (a) spec revision + transports (streamable HTTP vs stdio; which belong in-sandbox vs brokered); (b) remote-server auth (OAuth/client-credentials — what the broker custodies); (c) how the official MCP Registry + major catalogs identify/version/digest servers (informs attachment identity fields); (d) MCP attack classes (tool poisoning, schema drift/rug-pulls, confused deputy) to pressure-test the snapshot design; (e) commonly attached servers (GitHub, Postgres, Slack…) for realistic e2e fixtures. Bring me a findings note; fold it into the schema BEFORE the §17 settle.

YOUR TASK — design-doc Phase 5, "capability & MCP catalog":
FRAMING: capabilities are the LAST of the four optional run inputs (three shipped). EXACTLY two tool classes (§8.3); the split IS the security model: (1) SANDBOX tools — packaged in the runner image/bundle, contained by the sandbox; (2) BROKERED tools — the control plane turns the sealed key server-side (same inversion as the LLM facade and git fetch); a credential NEVER enters a sandbox. No arbitrary lifecycle hooks. Attach ≠ allow: a bundle makes a tool AVAILABLE; the permission gate judges every call. Authority = intersection (connection ∩ bundles ∩ subscription ∩ trust tier ∩ policy); narrowing REMOVES, never adds (§3.5).
Mechanics (§3.6/§8/§10):
- capability_bundles registry: versioned, append-only; attachment refs on revisions (agent_revisions.capability_bundles exists, empty).
- RunSpec freezes EXACT bundle versions + discovered MCP tool-schema SNAPSHOTS (photograph rule; schema drift = supply chain). §8.2: attachment records identity/digest, transport, schema snapshot, connection refs, egress, policy defaults, health.
- Every MCP/custom call crosses the SAME permission gateway (policy matches mcp__*; ReadOnly tier denies it). Ledger: identity, input digest, decision, status, latency, cost — never secrets.
- Brokered-tool gateway on the internal plane: intent → policy verdict → sealed credential used control-plane-side → result + ledger.
- Runner extension: mount tools / launch MCP servers from the frozen manifest (`just sandbox-build` after edits).
- Narrowing enforced in the ONE run_service::create_run.
Acceptance (§12): two agents on the SAME event carry different bundles; each uses only its frozen capabilities; every call in the ledger. E2E: NEW suite phase (pattern scripts/e2e-github.sh — no-model tier always, live self-skips).

SETTLE WITH ME BEFORE FREEZING THE SCHEMA (§17 #7): bundle upgrade behavior (rec: revisions PIN exact versions; upgrade = append a revision; "latest" only as opt-in). ALSO §17 #4 (first brokered git-write ops) — only if in scope; else defer explicitly.

WORKING AGREEMENT (locked, see memory): mechanical, ONE phase; done only when `just check` AND `just e2e` fully green incl. the NEW phase; update docs/HANDOVER.md; HAND BACK. Do not start Phase 6.

OPERATIONAL NOTES: `just e2e` owns the stack (stop :8787). Unit tests need the stack stopped. DB tests: `set -a; source .env; set +a`. Live runs AUTONOMOUS. Shared-repo e2e lanes: disable earlier subs before live tiers (bit us in Phase 4). GitHub seams: FLUIDBOX_GITHUB_API_URL + FLUIDBOX_GITHUB_CLONE_BASE. Check `git status` FIRST — clean + synced; else ask me. ultrathink
