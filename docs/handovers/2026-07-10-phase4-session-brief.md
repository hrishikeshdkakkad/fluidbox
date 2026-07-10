# Next-session brief — design-doc Phase 4: GitHub PR-review fan-out

Paste the block below (or an edited version) as the next session's goal. It follows the
same shape as the Phase 3 brief and reflects everything settled/shipped through
2026-07-10 (`main` @ 95177e5, pushed).

---

Continue the fluidbox "borrow the agent, on demand" build. ultrathink

READ FIRST (in this order):
1. CLAUDE.md — commands, invariants (incl. the new schedule invariant), gotchas
2. docs/HANDOVER.md (rev 5, 2026-07-10) — current state; §6 tracks the roadmap
3. docs/plans/2026-07-10-agent-workspaces-triggers-integrations-design.md — §6.3 (event trigger), §6.4 (two-level idempotency), §7 (GitHub PR fan-out, the flagship demo), §10 (trigger_deliveries/trigger_dispatches seeds), §12 Phase 4, §17 #1–#3

WHERE WE ARE:
- Phases 0–3 shipped & verified: `just check` green (fmt, clippy -D warnings, 65 tests incl. Neon-gated) and `just e2e` = 175/175 across 6 phases (live demo A, governance, git workspaces, api triggers + signed callbacks, scheduled borrowing, failure paths). Tree clean & pushed at 95177e5.
- Phase 3 delivered: schedules table (migration 0004; explicit IANA tz, DST-correct via fluidbox-core/src/schedule.rs); scheduler.rs tick worker; exactly-once firing via deterministic claim keys (sched:{fire_time}) bound to the session IN THE SAME TRANSACTION (create_session's bind_invocation param); §17 #5 SETTLED: overlap default allow, missed default skip, concurrency_policy enforced in run_service::create_run for ALL invocations (API invokes get 409 + recorded skip); skips are terminal claim rows (trigger_invocations.skip_reason); disabled subscription = clock paused → missed-run path on re-enable; Triggers dashboard shows cron/next/last fire + firings & skips. Plan doc: docs/superpowers/plans/2026-07-10-phase3-scheduled-borrowing.md.

YOUR TASK — design-doc Phase 4, "GitHub PR-review fan-out":
- An event is just another caller: webhook ingress → verify → normalize into InvocationContext (kind=event, already exists in spec.rs) → match subscriptions → the SAME run_service::create_run per match. The trigger router must not know how any harness executes (§6.3).
- TWO-LEVEL idempotency (§6.4, both DB-unique): event receipt dedup unique(connection_id, external_event_id) on trigger_deliveries; dispatch dedup unique(delivery_id, subscription_id) on trigger_dispatches. An accidental webhook retry must never duplicate runs or comments. Reuse the claim-table pattern from Phases 2–3.
- GitHub App connection (webhook secret verification, installation token minting) — the existing PAT-based connections stay for fetch; the App is the new identity for ingress + publishing. Seal all credentials with the existing seal.rs/FLUIDBOX_CREDENTIAL_KEY machinery; new env vars ARE expected this phase (app id / private key / webhook secret).
- Fan-out: one PR-opened event → one run per matching subscription, each with its own agent revision, task template, budgets, isolated workspace at the EXACT head SHA (materialize_git already supports SHA checkout).
- Fork trust tier: events from untrusted forks downgrade TrustTier (ReadOnly exists on RunSpec as frozen intent — make it real: policy may read/review but deny secrets/remote writes; a subscription cannot override the downgrade).
- Publisher: new ResultDestination variants (PR comment and/or Check) alongside signed_webhook in deliveries.rs; stable external result identity per (subscription, PR) so later events UPDATE the same comment/check instead of spamming (result_deliveries.external_id is seeded in §10). One agent's failure shows only on its own comment/check.
- E2E must not require a public URL: drive the ingress endpoint with locally-crafted GitHub-shaped payloads signed with the webhook secret (same receiver pattern as Phases 2–3); a real-GitHub pass can be manual, like Phase 1's.
Acceptance (§12 Phase 4): three differently configured agents subscribed to one repository receive one PR-opened event, execute in three isolated workspaces, and independently publish three attributable reviews. Retrying the webhook creates no duplicate run or comment.

SETTLE WITH ME BEFORE FREEZING THE SCHEMA (design doc §17 #1–#3):
1. GitHub result identity: fluidbox App identity only, or user-delegated identities? (standing recommendation: App-only for Phase 4; user-delegated later)
2. Subscription default events: `opened` only, or also `synchronize`/`reopened`? (standing recommendation: default opened + reopened; synchronize opt-in — every push is a cost amplifier)
3. Later reviews: update a stable comment/check in place, or preserve a history of separate results? (standing recommendation: stable identity updated in place — §7.4; full history lives in fluidbox's ledger regardless)

WORKING AGREEMENT (locked, see memory): implement mechanically, ONE phase at a time; the phase is done only when `just check` AND `just e2e` are fully green including a NEW e2e acceptance phase (pattern: scripts/e2e-schedule.sh — no-model assertions always run, live tier self-skips); update docs/HANDOVER.md; then HAND BACK to me. Do not start Phase 5.

OPERATIONAL NOTES:
- `just e2e` owns the stack: stop any dev server on :8787 first, restart after.
- Unit tests ALSO need the stack stopped — db tests seed past-due schedules/pre-launch sessions that a live scheduler/sweeper would consume mid-assertion.
- DB tests need `set -a; source .env; set +a` (direct Neon URL).
- E2E lesson from Phase 3: live-model runs in e2e must be AUTONOMOUS subscriptions — a supervised run can hang at awaiting_approval if the model reaches for a gated tool (this bit Phase 4's suite once; fixed in e2e-trigger.sh).
- Touching the permission/approval path? Re-run scripts/governance-e2e.sh.
- FLUIDBOX_CREDENTIAL_KEY is already in .env; new GitHub App env vars will need .env.example + CLAUDE.md notes.
- Check `git status` FIRST — the tree should be clean at 95177e5 (pushed); if it isn't, ask me before starting. ultrathink
