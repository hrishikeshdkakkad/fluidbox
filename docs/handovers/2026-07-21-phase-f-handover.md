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

## Closeout

*(Filled in at the end of the phase — see the git log on this branch for the authoritative record until then.)*
