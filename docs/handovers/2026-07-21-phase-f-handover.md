# Phase F (#34) — session handover

**Date:** 2026-07-21 · **State:** IN PROGRESS (this document is written as the phase runs; the closeout section at the bottom is authoritative for what is actually done).

Epic #28 (multi-user MCP control plane), **final phase**. Phases A/B/C/D/E are merged into `release/multi-user-mcp-control-plane`; **Phase F is branch `feat/mu-phase-F`** off `46ffe7f` (the Phase E merge). Never PR to `main` — the epic lands on the release branch (PR #27).

## What Phase F is for

The design's §Phase F is a load-test list and a rollout plan, and issue #34 adds an operational-metrics deliverable. But the phase's real content turned out to be **making the thing those tests would measure actually exist**: three of the four blockers to running more than one replica were still open, and the 300-concurrent target the load tests are supposed to prove was structurally impossible for reasons nobody had written down.

## Task 0 — re-baseline (complete)

All eight Phase E claim families were re-verified **against code**, not against the handover, before anything was built. Two independent read-only passes; the four highest-stakes findings re-checked by hand. Every one is SHIPPED with a real enforcement site. Evidence comment: issues/34#issuecomment-5037787811.

Baseline at `46ffe7f`: `cargo test --workspace` **655 passed / 0 failed**, cargo exit 0, `DATABASE_URL` proven `UNSET`.

**Three documented claims were disproved by the re-baseline** (all doc defects, not code defects; all corrected on this branch):

1. `CLAUDE.md` said the LLM reservation books `declared max output + len/4`. The code books `body_len / BYTES_PER_INPUT_TOKEN` with that constant equal to **1** — one byte per token, a genuine upper bound and **4× more conservative** than documented. The disclosed "aggressive sweeper projection" residual is therefore larger than the Phase E handover's measured figures imply.
2. `CLAUDE.md` said `identity_http` "now carries connector OAuth as well as OIDC". Only discovery does. **Both token legs deliberately ride the no-redirect `egress_http`**, because a 307/308 replays the request *body* — which would forward an authorization code plus PKCE verifier, or a refresh token, to the redirect target. The posture is stronger than documented; a source-grep test pins it.
3. The Phase E handover implied every definitive outcome renders `{ok:true, …}` to the runner. `claim_response` falls back to `{ok:false, …}` when `result_content` is NULL — reachable for a `claimed` row the sweeper flipped to `ambiguous`, so a runner that *did* dispatch can still see `ok:false`.

**And a false green of my own, in the first five minutes.** My initial baseline ran `cargo test --workspace 2>&1 | tail -40`, which reports *tail's* exit code, not cargo's, and truncates the tally. It "passed" while proving nothing. Re-run without the pipe. This is the defect class the phase exists to hunt, committed by the person hunting it.

## The finding that reshaped the phase

A survey of every scale-binding knob found that **the design's 300-concurrent target was not merely untested but structurally impossible**:

- the sqlx pool was hardcoded to `max_connections = 10` with no environment variable — and that 10 was never a decision, it is literally sqlx's own default, as were `min_connections`, `idle_timeout` and `max_lifetime`. Worse, sqlx's default 600 s idle timeout is *longer* than Neon's five-minute autosuspend, so the configuration guaranteed handing out connections Neon had already closed;
- neither axum listener carried a concurrency, body, or request-timeout layer;
- the chart's sandbox `ResourceQuota` capped pods at 20 while a comment claimed an application-level concurrent-run limit existed. **It never did** — the Kubernetes quota is the only admission gate, and it rejects rather than queues, so past the cap a run fails at provisioning.

A load test written before these were fixed would have measured the connection pool, not the system. This became Task 2.

## Method carried forward from Phase E

- **Prove every guard by mutating the code it protects.** Phase E found eleven tests that passed while testing nothing; mutation was the only reliable detector. This phase has found two more so far (see below), and one of them was found by an agent in its *own* work.
- **Verify comments against code before reasoning from them.** Three stale claims were disproved during the re-baseline alone.
- **Two reviewers agreeing is not evidence of mechanism.** A review's headline Critical was overturned by running the thing it claimed had never run.
- **Parallel agents in one working tree never run `git checkout`, `git stash`, or `cargo fmt --all`**, and never whole-file `Write` on a shared file. Per-file formatting and exact-string edits only.

## Shipped

| # | Task | Migration | Commit |
|---|---|---|---|
| 1 | Durable cross-replica egress governance | 0023 | `023c151` |
| 2 | Capacity ceilings for 300 concurrent runs | — | `e7ecb3d` |
| 3 | Cross-replica MCP upstream-session teardown | 0024 | `7007ac5` |
| 4 | Archive object store (fs + S3) | — | `33fefb8` |
| 5 | Workload identity on the internal gateway | 0025 | `33fefb8` |
| 6 | Runner-control token off the process environment | — | `a9a5bea` |
| 7 | *(Operational metrics — NOT BUILT, see below)* | — | — |
| 8 | Load harness + `scripts/scale-e2e.sh` + `scale` CI job | — | `33fefb8`, `75b5495` |
| 9 | Rollout gates, chart wiring, docs | — | `ba5c6b7`, `c1982d7` |

**PR #85** into `release/multi-user-mcp-control-plane`. Final local bar: `cargo test --workspace` **810 passed / 0 failed**, `clippy --workspace --all-targets -D warnings` clean, `cargo deny` clean, `bash -n` + `shellcheck` clean, `helm lint` clean — all with `DATABASE_URL` proven `UNSET`.

## CI state: ALL green — but its first runs earned their keep

All eleven jobs pass on this branch: `rust · hardening · identity · bindings · secrets · kind-calico · unit · web · deny · chart · scale` (coverage/e2e skip by design). It took three fixes to get the two NEW jobs there, and the failures were more informative than the greens:

- **`web` failed first, and the test was wrong, not the code.** The "a closed descriptor" case passed fd 9 on the premise that anything above 2 is closed in a spawned child. A parent can leak descriptors: on the GitHub Linux runner that case died by *signal* (`spawnSync` status `null`) while exiting 4 on macOS. Now uses a descriptor above the process limit — EBADF by definition on every POSIX platform — and asserts `signal` before `status`, because "null !== 4" says nothing about why. **These are Linux-only procfs assertions that self-skip on a developer's Mac, so CI was always going to be their first real run.**
- **`scale` timed out — and the root cause was a script bug, not the gate.** The job forged its 24 sessions, minted 96 tokens, asserted all four audiences, then hung to the 45-minute timeout at a **bare `wait`**. The section fires 24 backgrounded curls and then `wait`s — but it runs with the control plane alive in the background (`boot()` starts the server with `&`), and a bare `wait` blocks on *every* background job, including that immortal server. So the curls all returned and `wait` never did. Fixed by collecting the curl PIDs and waiting on exactly those (`aee65df`); the job now **passes**, which also confirms the harness's fast path works end to end — 24 sessions forged, 96 audience-scoped tokens, all 24 concurrent gate decisions `allow`, zero dropped requests. The gate answers a forged running session, exactly as `hardening-e2e` already implied.

**My first two diagnoses of this were both wrong, and that is the lesson.** I first guessed the gate was blocking on an approval decision (the template's frozen policy answering `RequireApproval`), and added a per-request `--max-time` bound on that theory. The bound was correct hygiene — a load harness must cap every remote-driven request — but aimed at the wrong process: the thing `wait` was stuck on was the server, not a request, so it changed nothing and the job hit 45 minutes again. Only reading the timestamps in the log (last output at `+2s`, then a 43-minute gap, with the burst the very next statement) and then re-reading what `wait` with no arguments actually waits for produced the real answer. A timeout is indistinguishable in the log from a deadlock, and a *plausible* cause is indistinguishable from a *verified* one until you check the mechanism.

## Whole-branch review: DONE (Codex gate still pending)

Three read-only agents reviewed `git diff 46ffe7f..HEAD` in parallel scopes — governance/capacity, the security-sensitive half (MCP teardown, workload identity, auth), and archive/SigV4/loadgen/scripts. Aggregate: **zero Critical, zero Important.** The security half was clean with all twelve mechanisms verified by file:line (header-free identity binding, decision matrix, live credential re-resolution at teardown, both RLS migrations, the M12 false-green guard). Scope C recomputed the SigV4 and RNG vectors independently in Python and they matched.

Findings acted on (`9019a48`): two stale comments, the class this project keeps paying for — the archive store's `error_from`/list read claimed "must not be read into memory" but `resp.text()` buffered the whole body first (now a genuinely bounded chunk-wise read), and `scale-e2e.sh`'s seq check said "max seq 1" while correctly asserting `≤2`. One reported Minor — "`from_config` is untested" — was a **false finding**: the test exists at `governor.rs:1987` with distinct values `11/22/33/44/55/66`, confirmed by grep rather than deferring to the reviewer (checking the mechanism is why it didn't become a phantom fix). The remaining Minors are disclosed limitations or nits (an unused test seam, a loadgen guard docstring that overstates on a malformed-but-unparseable URL) — left as-is.

**The Codex gate (gpt-5.6-sol, 3 scoped rounds) has NOT run.** It is deliberately deferred to a fresh session: in Phase E it found 2 Critical + 17 Important and consumed most of a session to adjudicate and fix across three waves, and cramming it into a nearly-exhausted context window would force the unverified corner-cutting this phase spent its effort catching. It is the one required review step outstanding.

## What is NOT done — read this first

1. **The review gate has not been run on this branch.** No whole-branch review in parallel scopes, and no Codex gate. Phase E's lesson was that an outside model found 2 Critical + 17 Important on a branch that had already survived four internal passes. **Budget for it; it is not redundant.** Only Task 1 got a per-task review (which found the phase's headline false green).
2. **Operational metrics (issue #34's second deliverable) are NOT built.** The design's §Operational metrics list has no `/metrics` endpoint and no registry. A survey identified the exact cheap insertion point for 13 of its 14 bullets (the 14th, sandbox memory/CPU, is provider-side and not reachable from the control plane) — that survey is the input for whoever picks this up. **The rollout gates document depends on these metrics existing**, so Gate 3 cannot be closed without them.
3. **No load test has been run.** The harness is built and CI-proven at small N; 60/150/300 cost real money and provision real infrastructure, and need explicit owner approval with a cost estimate.
4. **Migration 0023 was edited after first landing on this branch.** sqlx refuses a modified applied migration. A dev database that already ran it needs `drop table egress_rate_windows, egress_breakers; delete from _sqlx_migrations where version = 23;` before boot. CI is unaffected — its databases are created fresh per run.

## Residuals (disclosed, not defects)

- **ptrace remains.** The `/proc/<pid>/environ` read is closed, but a same-uid child can still attach to the runner and read the control token from live memory; no pod security control blocks same-uid ptrace. **Invariant 19 is not fully met.** Only a uid split or a separate container (own PID namespace) closes it. The env fallback (entrypoint bypassed) re-opens the original residual in full — deliberate compatibility, asserted by a test.
- **Workload identity is a network-layer binding, not a cryptographic one.** It does not distinguish another process in the same pod, a node-level attacker, a fabric permitting source-address spoofing, or a reused pod IP; and anything unbindable (Docker provider, pre-0025 sessions, adopted orphans) is admitted on the bearer alone. mTLS is the documented stronger follow-up.
- **`host_global` rate tier stays per-replica.** A durable cross-tenant key needs a per-dial RLS bypass on the broker's hottest path — a worse trade than N× looseness on one deliberately loose tier.
- **A brokered dial now pays ~9 extra database round trips** (admit 5, report 4, doubled on the 401 re-mint path), and a tenant's dials serialise on one rate row held across a second round trip.
- **The per-user rate dimension aggregates across a user's runs AND connections**, so the design's own 3-servers-per-run shape regresses from an effective 180/min to 60/min. Disclosed in `.env.example` and the admission policy.
- **A sweeper-retired MCP session is never `DELETE`d upstream** when its credential is unresolvable — invariant 9 forbids sending one. A session slot, not custody; strictly better than Phase E's leak-until-process-exit.
- **`adopt_sandbox_handle` does not write `workload_addrs`**, so an adopted orphan stays unbindable. One-line follow-up.
- **The archive `fs` backend is single-replica only**; multi-replica requires the S3 backend.
- **6 of 10 load scenarios are named gaps**, each refusing with its specific blocker rather than looking covered.

## Lessons worth carrying

- **False green count for this phase: four.** One was mine (`| tail -40` reports tail's exit code, in the first five minutes). One let the entire cross-replica feature be disabled at its real construction site with all 380 server tests green — because the test asserted on a `Default::default()` production never calls. Two were caught by agents in their own work, one because a negative control was too fresh for the predicate under test to matter. **Mutation is still the only detector that has ever worked.**
- **Verify a review's headline before acting on it.** This phase's review opened with a Critical claiming the entire SQL layer had never executed. Running it took ten minutes and disproved it — but its *second* finding was the real one. A wrong Critical does not make the reviewer wrong.
- **A claim about a default is not a claim about production.** Three separate defects this phase came from the same shape: testing a constructor, a `Default`, or a helper's argument rather than the path production takes.
- **Parallel agents in one tree work if — and only if — ownership is by REGION and the tool is exact-string Edit.** Six agents ran concurrently with zero data loss this phase, against two incidents in Phase E. The rules that made the difference: never `git checkout`/`stash`/`restore`, never whole-file `Write` on an existing file, never `cargo fmt --all`. One agent still `rm -rf`'d a shared scratchpad subdirectory — scratchpad paths need per-agent namespacing too.
- **The most valuable finding was not in the plan.** Nothing in the design or the issue said "the pool is 10 and nobody chose it." It came from asking a survey to enumerate every knob that binds under load, before writing the tests that would have measured it.

---

# Session 2 closeout — Codex gate, operational metrics, load plan (2026-07-21, later)

This section is authoritative for what the second session did. It supersedes the "What is NOT done" list above on the two items it names as done.

## Operational metrics (issue #34 deliverable 2) — BUILT, proven, CI-covered

`crates/fluidbox-server/src/metrics.rs`: a hand-rolled, dependency-free registry — atomic `Counter`/`Gauge`, fixed-bucket `Histogram`, and a `Family` (a labelled counter over a COMPILE-TIME-fixed value set with an `_other` catch-all). **Cardinality is a security property here:** tenants are untrusted, so no metric is labelled by `tenant_id`/`connection_id`/upstream host — an unbounded label set would be a memory-exhaustion DoS. Per-tenant attribution stays in the ledger/`usage_entries` (already redacted, already tenant-scoped).

Exposition: `GET /v1/admin/metrics` (admin-token-gated, the same `/v1/admin/*` surface the operator keeps under SSO) plus an OPTIONAL unauth `FLUIDBOX_METRICS_BIND` third listener (off by default; documented private-interface-only). Both render identical Prometheus text; the render does NO database query (pool stats + a registry lock only), so a scrape cannot be turned into DB load.

Insertion points are the funnels where the data already sits, so a decision can't be counted twice or missed:
- `ledger::record` (ONE funnel for every event): gate verdicts + deny sources (`ToolDecision`), brokered latency + outcome (`BrokeredToolCall`), delivery outcomes (`CallbackDelivered`/`Failed`), ledger-write count. Refactored to take `&Metrics` so the event→metric mapping is unit-tested with no DB (mutation-proof: `ledger::tests`).
- `orchestrator::transition_inner` (the single status writer): active-runs gauge (band-edge deltas, `metrics::active_delta` unit-tested), provisioning latency (initializing→running only), terminal-outcome counters.
- `broker.rs`: upstream failure class (from the `CallErr` variants the broker genuinely distinguishes — NOT a fabricated numeric-status split), generation mismatches (metered `recheck_binding` path, DB-test-proven at `broker.rs`), egress rejections (rate/breaker, from the governor's `Throttled.scope`).
- `facade.rs`: reservation lifecycle (booked/released/charged/refused). `connections.rs`: revocations. Governor `degraded_count` + pool + MCP-session count read LIVE at render.

Coverage: `cargo test -p fluidbox-server` metrics/ledger/main tests all green (registry math, `_other` routing, cumulative histogram, deterministic render, exposition-name uniqueness, the route+listener wiring source-guard). The `scale` CI job's new `tool.decision` assertion (below) exercises the ledger funnel end to end.

## The Codex gate — RUN (gpt-5.6-sol), adjudicated by mechanism, fixed

Three scoped rounds over `git diff 46ffe7f..fc3d231`, matching the three whole-branch scopes. **Max reasoning silently exceeded the 30-min MCP idle timeout on the two broad scopes**, so B and C were re-run at `high` and B was split (B1 teardown+workload, B2 token-off-env+audience). Aggregate: **2 Critical + 16 Important + 6 Minor.** Phase E's gate was 2 Critical + 17 Important — the prediction held. Scope B2 (the token-off-env exec chain + the audience mapping — the most security-sensitive surface) came back **completely clean**, all twelve mechanisms verified by an outside model. The SigV4 signer and the SplitMix64 RNG were **independently recomputed in Python and matched exactly** — the hand-rolled crypto is correct.

Every finding was adjudicated against code, not deference (this phase's own review had reported a FALSE "from_config untested" Minor; Codex's own "Verified correct" confirmed that test exists). **FIXED (17):**

| # | Finding | Fix | Test |
|---|---|---|---|
| C1 **Crit** | loadgen production guard bypassable: `host_of` (textual) misses libpq `host=` override + a userinfo/path `@` trick, so it reads loopback while sqlx/reqwest dial prod | `guard.rs`: `effective_db_host` (via `PgConnectOptions::get_host`) + `effective_target_host` (via `reqwest::Url`) reason about the host the connectors ACTUALLY use; present-but-unparseable DB → refuse. (An agent also moved the loadgen DB URL to `FLUIDBOX_LOADGEN_DATABASE_URL` so a `.env` source can't arm it.) | 2 bypass tests, mutation-proof |
| C2 **Crit** | `scale-e2e.sh` had NO production-DB refusal — a `source .env; bash scale-e2e.sh` would seed + forge auth-capable tokens into real Neon | added a python3 host guard (honors `host=` override); refuses non-loopback unless `FLUIDBOX_SCALE_ALLOW_REMOTE_DB=1` | `bash -n` + shellcheck |
| A7 | `FLUIDBOX_DB_MAX_LIFETIME_SECS=0` documented as "no cap" but `pool_options` passed `Some(Duration::ZERO)` → sqlx expires every connection immediately (reconnect storm on Neon) | `disabled_when_zero` maps 0→`None` for lifetime AND idle | `pool_option_tests` asserts the constructed getters |
| A1 | breaker threshold `u32→i32` wrap: a value > `i32::MAX` opened the durable breaker on the first failure | saturating `i32::try_from(...).unwrap_or(i32::MAX)` | — |
| A5 | abandoned open/half-open breaker rows never swept (only `closed AND failures=0`) → unbounded growth; a test PINNED the leak | sweep now collects any row aged past `idle_secs` (≫ `breaker_open_secs`, so a live protection's recent `updated_at` still survives); test flipped + a new `a_recent_open_breaker_is_never_swept` | DB tests |
| A2 | the OAuth 401 retry dial was not re-admitted → a hostile 401-then-200 doubles the governed rate uncounted | re-run `governor_gate_durable` before each retry dial (both broker paths) | — |
| A4 | credential-free legacy bundle keyed the local connection dimension by shared `Uuid::nil()` → cross-tenant collision | key it by the tenant (for a connectionless bundle the per-connection dimension IS per-tenant) | — |
| B1-1 | in `enforce`, a failed `set_workload_addrs` left a k8s run bearer-only for its whole life (indistinguishable from the legit unbindable classes) | in enforce, when the provider reported an address but recording failed, terminate the sandbox + refuse the launch | — |
| C3 | `scale` job counted only `tool.requested` + `max(seq)≤2` → dropping the `tool.decision` append stayed green | added an explicit `tool.decision == FORGE_N` assertion | the job |
| C4 | S3 `ListObjects` parser accumulated every `<Contents>` key across 100 pages unbounded → ~9M keys/>1 GiB | `MAX_LISTED_KEYS` ceiling + warn + break; caller re-lists next sweep | mutation-proof |
| C5 | health/HTTP/auth curls in `scale-e2e.sh` lacked `--max-time` → a hung listener blocks to the 45-min timeout | `--max-time` on all six | `bash -n` |
| C6 | `--facade-calls-per-session>0` could spend real model money with only a warning | new `--allow-model-spend` opt-in (pure `model_spend_gate`), refuses otherwise | unit test |
| C7 | report footer said all limits are "per-replica in-memory" (stale after 0023) | corrected to name both tiers | — |
| C8 | `S3Config` derived `Debug` exposing `secret_access_key`/`session_token` | hand-written redacting `Debug` | mutation-proof |
| A8 | Helm `replicas:3 + archiveStore:s3` still mounted one RWO PVC into every pod + hardcoded `Recreate` | PVC + `Recreate` gated to the node-local `fs` path; `s3` drops the PVC + uses `RollingUpdate`; single-replica render byte-identical | `helm lint` + rendered diff |
| A-min2 / B1-min | stale comments: governor "durable = Phase F" (state.rs, main.rs, CLAUDE.md), orchestrator "a live row causes a re-drive" (false at the last hop), report footer | corrected to the truth | — |
| — | `.env.example` missing every `FLUIDBOX_DB_*`, `MAX_REQUEST_BODY_BYTES`, `WORKLOAD_IDENTITY`, archive-store + `METRICS_BIND` knob | full Phase F section added | — |

**DOCUMENTED, deliberately not fixed this phase (each real, each bounded, each on a best-effort subsystem where a rushed hot-path change is the very false-green class this phase hunts):**

- **A3 — probe/refresh MCP discovery egress is ungoverned.** `probe_tools`/`discover_tools`/`discover_snapshot` send `initialize` + up to 4 `tools/list` pages with no governor admission. Bounded per request, not in aggregate. Mitigating: these are ADMIN/member-authenticated actions, not the unauthenticated abuse the governor primarily guards. FIX: thread `governor_gate_durable` into the three discovery entry points (a new integration into separate paths). Follow-up.
- **A6 — neither listener carries a request-timeout or concurrency layer** (a slowloris on drip-fed sub-2-MiB bodies holds a socket without reaching the DB acquire timeout). The absence is disclosed with rationale (a GLOBAL timeout would cut SSE/LLM/permission-wait routes mid-flight); the reviewer's point is that no ROUTE-SCOPED substitute was added for the short-lived routes. In production this is normally handled at the ingress/LB; app-level route-scoped timeouts on the short routes are the follow-up.
- **B1-2 — cross-replica MCP-session teardown can mark a REPLACEMENT session deleted without deleting it** (replica B snapshots row R/S1, replica A reinits R→S2, B deletes S1 and marks R deleted by UUID → S2's slot leaks). A session SLOT leak, not custody. Broadens the disclosed sweeper residual.
- **B1-3 / B1-4 — the terminal MCP cleanup is fire-and-forget and MCP persistence is best-effort**, so "every registered session is persisted / retryable" overstates: a process death between `delete_finalization` and the spawned cleanup, or a caught `SessionRecorder` DB error, leaves an upstream session slot that the sweeper later retires WITHOUT a DELETE (invariant 9 forbids sending an unresolvable credential). The false comment is corrected; the behavior is a disclosed slot-leak. FIX: a durable, awaited teardown receipt. Follow-up.
- **A-min (governance observability):** the durable-tier preflight runs at first dial, not boot, and `preflight_failed` never clears after a transient recovery. Cosmetic/observability; the degrade path itself is correct and counted.

## Load plan (Gate 3, and the 60/150/300 runs) — PRESENTED, awaiting owner approval + cost sign-off

The harness is built and CI-proven at small N; the real runs spend money and provision infrastructure. Proposed sequence, each gated on the previous holding and on the pool/quota values being RECORDED (Gate 5 extrapolates from them):

1. **Shape the deployment like production first:** multi-replica (≥2), real Postgres sized so `replicas × (FLUIDBOX_DB_MAX_CONNECTIONS + 2)` fits the compute's ceiling (Neon ~112 ⇒ e.g. 3 replicas × 25 + spare), `FLUIDBOX_ARCHIVE_STORE=s3` (fs is single-replica), `FLUIDBOX_EGRESS_DURABLE=1`, `FLUIDBOX_WORKLOAD_IDENTITY=enforce`, runner images rebuilt from this branch, `FLUIDBOX_METRICS_BIND` wired to a scraper (Gate 3 reads these metrics).
2. **60 concurrent (the design's first capacity checkpoint).** Hold every `rollout-gates.md` Gate-3 row: provisioning-latency p95 with no upward trend, pool never sustains 100% checked-out + zero acquire timeouts, gate-decision-latency p95 within a stated factor of idle, ambiguous brokered outcomes a small fraction, no run exceeds budget beyond the sole-claimant bound, durable egress ceiling observed to BIND (not N×), zero orphaned sandboxes after teardown (the k8s epic's audit, repeated under load). **Record the pool/quota/limit values used.** Est. cost: a short (~20–30 min) 60-sandbox run at the haiku default is small; the estimate goes in the approval request.
3. **150, then 300** only if 60 holds and the numbers are recorded. 300 is the full-seat stress case; the harness sustains it or the deployment documents a lower supported ceiling (Gate 5).
4. **Fault injection (Gate 5):** kill a replica mid-run (leases transfer, deliveries re-claim, MCP sessions still torn down), DB failover mid-run (no duplicate side effects), a sustained soak for unbounded memory/connection growth.

6 of 10 load SCENARIOS remain named gaps (each refuses with its blocker, never renders green) — the OAuth-refresh-storm, revocation-during-active-run, upstream-failure-matrix, slow-approval, broker-restart, and reservation-race sections are still to be built; they are not required to run the concurrency gate above but ARE required for Gates 4–5.

## Verification at closeout

`cargo clippy --workspace --all-targets -D warnings` clean (and `-p fluidbox-workspace --features store`); `cargo test` green on every non-DB suite run locally (server 414, loadgen 52, workspace/store 64, plus the new metrics/ledger/guard/pool tests) with `DATABASE_URL` proven `UNSET`. The DB-backed governance/broker tests (the flipped breaker-sweep, the metered generation-mismatch) are CI's to prove. **CI on PR #85 is the proof for everything DB-backed** — that is the final gate.
