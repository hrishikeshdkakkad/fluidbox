# Phase E (#33) — session handover

**Date:** 2026-07-21 · **State:** implementation + acceptance COMPLETE, **closeout NOT started** — branch never pushed, no PR, CI has never run on it.

Epic #28 (multi-user MCP control plane). Phases A/B/C/D merged into `release/multi-user-mcp-control-plane`; **Phase E is branch `feat/mu-phase-E`** off `825ce56`, 22 commits, 64 files, migrations 0019–0022. Never PR to `main` — the epic lands on the release branch (PR #27).

## Current state

Shipped, all on by default (no feature flags): shared **egress boundary** — two hardened clients, `admit_url` pre-flight at every dial, redirect refusal, save-time admission on connection/callback URLs, git clone-URL admission (Gap 7) · **per-run MCP session manager** + 2025-11-25 conformance, bounded SSE assembler, `-32601`, `outputSchema`/`structuredContent` preserved, SEP-835 terminal (Gap 8) · **server-side frozen-schema argument validation**, dialect by snapshot protocol version (Gap 12) · **durable four-state execution claims** keyed `(session, tool_call_id, input_digest)` (Gap 11) · **audience-scoped sandbox credentials** `llm|tool|control|workspace` (Gap 10) · **multi-replica coordination**: approval single-emission inside the decision CAS + `fluidbox_approvals` `pg_notify`, session lease + epoch fencing, delivery claims (Gap 13) · **durable request-keyed LLM budget reservations** (Gap 14) · per-tenant/connection/host rate limits + per-`(connection, host)` circuit breakers.

Every #33 acceptance bullet maps to a lettered section of `scripts/hardening-e2e.sh` (sections a–j), plus a new `hardening` CI job on its own database. **The script has never been executed** — CI on the PR is its first run, exactly as `secrets`/`identity`/`bindings` were.

The per-task local bar (fmt · clippy `-D warnings` · `cargo test --workspace` with `DATABASE_URL` proven unset) was green at each implementation commit; **this docs task did not re-run it** (docs-only diff). The whole-branch bar has not been re-run since the last fix round.

**Migration deploy order is safe in either direction** — unlike 0018. 0019/0022 create new tables, 0020/0021 add nullable-or-defaulted columns, and a pre-Phase-E binary simply never reads them. **The runner images are the coupled half:** rebuild them (`just sandbox-build`) — a pinned pre-Phase-E image on a new server aborts at the first tool call (see residuals).

## Owner actions

1. Run the closeout that is still outstanding: whole-branch review → fix wave → explicit checks → push → **PR into `release/multi-user-mcp-control-plane`** → CI → Codex (gpt-5.6-sol, read-only, **3 parallel scoped rounds**).
2. **Close #33 manually** on merge — release-branch base means closing keywords don't fire. #32/#75 from Phase D may still be open.
3. Rebuild runner images before any deploy that carries this branch (`just sandbox-build`, `just codex-build`) and check that no agent revision pins an older `runner_image`.
4. Optional knobs, all default-off/default-safe: `FLUIDBOX_EGRESS_ALLOW_CIDRS`, `FLUIDBOX_EGRESS_PROXY`, `FLUIDBOX_EGRESS_RATE_*`, `FLUIDBOX_EGRESS_BREAKER_*`, `FLUIDBOX_LLM_MAX_CONCURRENT_RESERVATIONS`. Every one **fails boot** on a malformed value; the reservation ceiling also refuses `0`, while `0` on a rate/breaker knob means "disable that dimension".
5. On first `just e2e`: nothing in Phase E changed the connector suites, but the broker's runner-facing response shape for a definitive upstream error is now `{ok:true, result:{…, is_error:true}}` — the model-visible tool error is identical, and `ok:false` survives for never-sent/ambiguous/denied.

## How to resume

Process (unchanged): one phase at a time, branch `feat/mu-phase-<X>` off the release branch, PR into it, per-task spec+quality review, Codex review in 3 parallel scoped rounds (a single full-branch call times out), then hand back.

**Hard constraints:** never run `just` recipes, `scripts/*e2e*.sh`, or `fluidbox-db` tests locally — the justfile dotenv-loads real Neon and e2e spends real money. Prove `DATABASE_URL` unset before cargo. CI on the PR is the proof for anything DB-backed.

Artifacts: plan `.superpowers/sdd/phase-e-plan.md` (settled decisions E1–E16), surveys `phase-e-survey-{a,b,c,d}.md`, ledger `progress.md` (**gitignored — the durable record is this doc + git history**).

**Disk:** the machine hit 100% full during this phase. Builds now run `CARGO_INCREMENTAL=0`; `target/` still sits around 25 G.

## Residuals (disclosed, not defects)

- **`/proc/<pid>/environ`** — both runners delete the runner-control token from `process.env` before spawning anything, but a same-uid child can still read the runner's *initial* environ. The invariant-19 acceptance bullet ("agent code cannot reach runner-control endpoints with the LLM or tool-intent credential") is met and server-enforced; true process isolation (uid split or sidecar) is **not built**. Docker `HostDev` is explicitly not a boundary.
- **Gap 6 remainder** — no workload identity, no mTLS on the internal gateway. The bearer alone authenticates; Phase E only narrowed it to four audiences.
- **Rate limits and circuit breakers are per-replica**, in memory: the deployment ceiling is N× the configured value. Same class as the pre-existing per-replica `MINT_BUDGET`. Durable cross-replica limiting is Phase F.
- **Git clone resolve-then-validate (TOCTOU)** — every resolved address is validated before `git` runs, but `git` re-resolves independently out-of-process. `file://` is permitted under the configured clone base or the dev seam.
- **No result-vs-`outputSchema` validation** — both fields are now preserved and digested; results are still not checked against the schema.
- **The upstream MCP session registry is replica-local** — a run finalized on a different replica leaves its entries un-`DELETE`d until process exit. Session affinity is Phase F.
- **Per-tenant destination allowlists: deferred.** Admission is deployment-wide plus the operator CIDR escape hatch; there is no per-tenant allowlist.
- **The LLM reservation sole-claimant carve-out** — with zero active reservations the budget arms are skipped, so one request can proceed over budget. Bounded: total ≤ budget + one request's actual usage (no worse than pre-Gap-14), and the terminal verdict still comes from the accumulated check + sweeper. Without it, a run whose single-request estimate exceeds its remaining budget would 429-livelock with nothing to drain.
- **The sweeper's projection is deliberately aggressive** — counting live reservations can stop a run that would have fit. Measured: an opus-4-class run loses ~$0.82 of a $2.50 default budget (~33%) with a request in flight; haiku ~6.6%.
- **Delivery is at-least-once** (receivers dedup on `x-fluidbox-delivery`); a crashed replica's claimed rows park for up to the claim TTL (300 s, derived from the worst-case single publish attempt).
- **An OLD pinned runner image on a NEW server is UNSUPPORTED.** The current runner-lib aborts loudly at the first tool call with a named diagnostic (`EXIT_AUDIENCE_MISMATCH`, recorded on the timeline, no `/result`), but **that behavior lives in the image** — an image built before this phase still collapses the 403 into a plain deny and runs to completion with every tool denied while model spend continues.
- **Three acceptance properties are documented as uncovered rather than weakly asserted**: MCP session-registry eviction (replica-local map, no read surface — needs an introspection seam), OAuth re-mint on the terminal `DELETE` (no fake authorization server in this suite; a weaker check would pass with a stale token), and circuit-breaker half-open close (needs a >60 s window; covered by `governor.rs`'s injected-clock unit tests).
- **SEP-835 insufficient-scope is terminal AND classified `failed_upstream`**, so after the owner reconnects with more scopes a replay of the same `tool_call_id`+input adopts the stored refusal; a fresh model turn proceeds normally.
- Carried from Phase D and still open: the transferable connector-OAuth `go_url` lure (closure designed, not built) and M2M client credentials (SEP-1046 unratified).

## Follow-ups worth filing

1. **Process-boundary isolation for the runner-control token** (uid split or sidecar) — the only thing that closes the `/proc/<pid>/environ` read.
2. **Gap 6 remainder**: workload identity / mTLS on `:8788`.
3. **Durable cross-replica rate limiting** and **MCP session affinity** (both Phase F prerequisites for 2–3 replicas, alongside moving the archive off the RWO PVC).
4. **An introspection seam for the MCP session registry**, so eviction becomes assertable instead of documented-as-uncovered.
5. **Result validation against `outputSchema`** — the preserved field is currently informational.
6. **Per-tenant egress destination allowlists** on top of the deployment-wide admission rules.

## Lessons worth carrying

- **False-green guards are now the signature defect of this project, and they have moved up a level.** Phase D found five false-green *assertions*; Phase E found **four false-green source guards** — tests written to protect a SQL invariant that passed against the exact mutation they named (one was satisfied by its own doc comment; one anchored on a prefix of the mutant). Three different agents wrote one. Rule that came out of it: **prove a guard by mutating the real statement, and slice statements, not prose.**
- **Writing acceptance assertions from the normative text finds defects reviewers miss.** The terminal MCP `DELETE` shipped with no `Authorization` header — a conforming server would have 401'd it, silently leaking upstream sessions and making an acceptance bullet literally false. Two code reviews passed it; the test author caught it by refusing to encode an assertion it could not honestly make.
- **A comment can be the bug.** The lease-bail path was justified by "Nothing is lost by returning here" — the exact false premise that stalled cancels in the multi-replica mode the lease exists to enable. Elsewhere a doc claimed re-taking our own lapsed lease "deliberately self-fences" (it does not, and must not), and a marker's anti-spoof rationale named the wrong defense. Review comments as claims, not decoration.
- **Promote a disclosure to a fix when the owning task is still open.** Two findings this phase started as "document it in Task 10" and became real fixes in the task that owned the code. A disclosure is what you do when nobody owns the fix.
- **The route→audience mapping is invisible to unit tests.** Deliberately requiring the wrong audience on `/events` left all 303 server tests passing — the e2e route matrix is the mapping's only proof, and shared constants remove only the typo class.

**Next: Phase F — scale, failure, and multi-replica topology. Do not start unprompted.**
