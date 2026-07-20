# Phase D (#32) — session handover

**Date:** 2026-07-20 · **State:** implementation COMPLETE, CI fully green, PR open, not merged.

Epic #28 (multi-user MCP control plane). Phases A/B/C merged into `release/multi-user-mcp-control-plane`; **Phase D is PR #83** (branch `feat/mu-phase-D`, head `2e945ab`, 27 commits, 61 files, migrations 0014–0018). Never PR to `main` — the epic lands on the release branch (PR #27).

## Current state

CI **all green** on `2e945ab`: `rust` · `secrets` · `identity` · `bindings` · `deny` · `web` · `chart` · `kind-calico` · `unit`. Local bar: fmt, clippy `-D warnings` 0, **463 tests / 0 failed** with `DATABASE_URL` proven unset, pnpm build, vitest 34/34.

Shipped: KMS envelope encryption (per-tenant DEKs, 13 sealed columns, deployment-KEK claim preventing split-brain) · resumable re-seal with count parity + bidirectional retirement gates · **invariant 20** one-time browser-bound OAuth state rows · reusable OAuth client registrations · per-tenant LiteLLM virtual keys (master key confined to provisioning) · **RLS** on 37 tables with role-posture validation + audited bypass (#75).

Every #32 acceptance bullet maps to a lettered section of `scripts/secrets-e2e.sh`, all passing.

## Owner actions

1. Review + merge **PR #83** (merge commit).
2. **Close #32 and #75 manually** — release-branch base means closing keywords don't fire.
3. On first `just e2e`: `scripts/e2e-connectors.sh` was ported to the new `go_url` + cookie flow this phase — that's the section to watch.
4. Optional features need enabling: KMS (`FLUIDBOX_KMS_MODE` → run `POST /v1/admin/reseal` → drop the legacy key once parity is zero); tenant LLM keys (**requires LiteLLM with its own Postgres — no shipped compose/chart wires this**); RLS role split (`FLUIDBOX_RUNTIME_ROLE`).

## How to resume

Process (unchanged): one phase at a time, branch `feat/mu-phase-<X>` off the release branch, PR into it, per-task spec+quality review, Codex review (gpt-5.6-sol, read-only, **3 parallel scoped rounds** — a single full-branch call times out), then hand back.

**Hard constraints:** never run `just` recipes, `scripts/*e2e*.sh`, or `fluidbox-db` tests locally — the justfile dotenv-loads real Neon and e2e spends real money. Prove `DATABASE_URL` unset before cargo. CI on the PR is the proof for anything DB-backed.

Artifacts: plan `.superpowers/sdd/phase-d-plan.md`, surveys `phase-d-survey-{a,b,c,d}.md`, ledger `progress.md` (**gitignored — the durable record is this doc + git history**).

## Residuals (disclosed, not defects)

- **Transferable `go_url` lure** — an attacker's connect link, completed by a lured victim, seals the victim's grant into the attacker's connection. **Correction to an earlier claim of mine:** a connected-account confirmation closes this *only* if shown to the **external account holder** completing the flow (or it binds an expected subject). Shown to the initiator it closes nothing — the initiator is the attacker. Real closure (designed, not built): put the browser-facing callback on the dashboard origin behind the proxy, set the flow cookie on the authenticated start response, drop `c` from the transferable token.
- **M2M client-credentials** — deferred; SEP-1046 unratified.
- Pre-0018 binaries break on a 0018 database (stop old binary → migrate → deploy). KMS at-rest format and transit-token format both changed (safe: KMS never ran in production; transit tokens are minutes-TTL).
- `__Host-` flow cookie needs HTTPS — non-loopback plain HTTP can't complete a browser connect.
- `MINT_BUDGET` is per-replica, not deployment-wide (documented accurately).

## Follow-ups worth filing

1. Dashboard-origin callback (closes the `go_url` lure).
2. `discover_snapshot` has no reactive-401 retry — `/tools/refresh` fails after AS-side revocation until the cached token expires.
3. "Must hold the lock" on executor-generic `update_connection_oauth` is doc-enforced, not type-enforced.

## Lessons worth carrying

- **False-green assertions** are the dominant defect class here: five found, one *introduced by a fix*. A test passing without exercising its mechanism is worse than a failing one — hunt them explicitly.
- **CI connects as a Postgres superuser**, which silently bypasses RLS. A security control you can't observe working should be assumed inert.

**Next: Phase E (#33) — broker and network hardening. Do not start unprompted.**
