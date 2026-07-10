# Next-session brief — design-doc Phase 4: GitHub PR-review fan-out

Paste the block below as the next session's goal (kept ≤4000 chars; the READ FIRST
docs carry the detail). Reflects everything settled/shipped through 2026-07-10
(pushed; code frozen at 95177e5, later commits docs-only).

---

Continue the fluidbox "borrow the agent, on demand" build. ultrathink

READ FIRST (in order):
1. CLAUDE.md — commands, invariants (incl. schedules), gotchas
2. docs/HANDOVER.md (rev 5, 2026-07-10) — current state; §6 = roadmap
3. docs/plans/2026-07-10-agent-workspaces-triggers-integrations-design.md — §6.3, §6.4, §7, §10, §12 Phase 4, §17 #1–#3

WHERE WE ARE: Phases 0–3 shipped & verified — `just check` green (65 tests), `just e2e` = 175/175 across 6 phases. Tree clean & pushed; code frozen at 95177e5 (later commits docs-only). Phase 3 (scheduled borrowing) details are in HANDOVER §1; §17 #5 SETTLED: overlap default allow, missed default skip, concurrency_policy enforced in create_run for ALL invocations.

YOUR TASK — design-doc Phase 4, "GitHub PR-review fan-out":
FRAMING THAT GOVERNS EVERYTHING: GitHub is NOT the feature — the CONNECTOR SEAM is; GitHub is its first tenant. Build the generic event spine ONCE (ingress → verify → normalize → match → create_run → publish, plus the dedup ledger); GitHub plugs in through §6.3's five provider-specific duties only. Router/matcher/dedup/fluidbox-core stay provider-ignorant; ALL GitHub knowledge lives in ONE connector module. Seam test: adding Slack (Phase 7) must need only a new connector module + a ResultDestination variant. n=1 discipline: build against the shape, NO abstract SDK yet (§17 #8).
Mechanics (details in §6.3/§6.4/§7/§10):
- Every match → the same run_service::create_run, InvocationContext kind=event (exists in spec.rs).
- Two-level idempotency, DB-unique: trigger_deliveries unique(connection_id, external_event_id); trigger_dispatches unique(delivery_id, subscription_id). Webhook retries never duplicate runs/comments (claim-table pattern).
- GitHub App connection (webhook secret verify, installation tokens); PATs stay for fetch; seal creds via seal.rs. New env vars expected → .env.example + CLAUDE.md.
- Fan-out: one PR event → one run per matching subscription, each isolated at the EXACT head SHA.
- Fork trust tier: fork events downgrade TrustTier (make ReadOnly real: review yes, secrets/writes no); subscriptions cannot override it.
- Publisher: ResultDestination variants (PR comment/Check) beside signed_webhook; stable identity per (subscription, PR) — later events UPDATE, never spam. One agent's failure shows only on its own check.
- E2E needs no public URL: locally-crafted GitHub-shaped payloads signed with the webhook secret; real-GitHub pass manual. E2E also asserts the seam (router/matcher contain no github types).
Acceptance (§12): three differently configured agents on one repo receive one PR-opened event, run in three isolated workspaces, publish three attributable reviews; webhook retry → zero duplicates.

SETTLE WITH ME BEFORE FREEZING THE SCHEMA (§17 #1–#3): (1) result identity: App-only vs user-delegated (rec: App-only now); (2) default events: opened only vs +synchronize/reopened (rec: opened+reopened, synchronize opt-in — cost amplifier); (3) stable comment updated in place vs history (rec: in place; the ledger keeps history).

WORKING AGREEMENT (locked, see memory): implement mechanically, ONE phase; done only when `just check` AND `just e2e` are fully green incl. a NEW e2e phase (pattern: scripts/e2e-schedule.sh — no-model tier always runs, live tier self-skips); update docs/HANDOVER.md; HAND BACK. Do not start Phase 5.

OPERATIONAL NOTES: `just e2e` owns the stack (stop :8787 first). Unit tests also need the stack stopped (db tests seed rows live sweepers would eat). DB tests: `set -a; source .env; set +a`. E2E live runs must be AUTONOMOUS subscriptions (supervised can hang at awaiting_approval — bit us once). Touch the permission path → rerun scripts/governance-e2e.sh. Check `git status` FIRST — clean + synced with origin/main; else ask me. ultrathink
