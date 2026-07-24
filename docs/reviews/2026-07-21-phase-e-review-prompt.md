# Phase E — mechanical review prompt

Hand this to a fresh reviewer (model or human) with no context from the session that produced the branch.

---

You are performing a **mechanical, adversarial review** of a completed feature branch in a Rust control plane that runs AI coding agents in sandboxes. The threat model assumes the agent is hostile (prompt injection means the model must be treated as adversarial) and that remote MCP servers are hostile.

**Repository:** `/Users/hrishikeshkakkad/Documents/infra`
**Branch:** `feat/mu-phase-E` · **Base:** `825ce56` · **Range:** `git diff 825ce56..HEAD` (~33 commits) · **PR:** #84 into `release/multi-user-mcp-control-plane`

## Hard constraints — violating these costs real money or corrupts real data

- **READ-ONLY.** Do not modify, create, or delete repository files. Report; do not fix.
- **NEVER** run `just` recipes (the justfile dotenv-loads a real production Neon database), **never** execute `scripts/*e2e*.sh` (they provision servers and spend real API credits), and **never** run `cargo test -p fluidbox-db` with `DATABASE_URL` set.
- Before any cargo command, prove the environment is clean: `echo "[${DATABASE_URL:-UNSET}]"` must print `[UNSET]`.
- If you build, use `CARGO_INCREMENTAL=0` and prefer an isolated tree (`git archive HEAD | tar -x -C <tmpdir>`); disk is tight.
- Scripts may be read and `bash -n` / `shellcheck`'d, never executed.
- If you mutate code to test a guard (encouraged, see below), restore it byte-identically and verify with `git diff --exit-code`.

## Normative sources — the contract the code must satisfy

1. `docs/plans/2026-07-14-multi-user-mcp-control-plane-design.md` — especially the "Security invariants" list (1–22), "Execution semantics", "Network and trust boundaries", the multi-replica statelessness inventory, and Gaps 6–14. **This document is the authority. Where code and design disagree, that is a finding.**
2. `gh issue view 33` — the implement and acceptance bullet lists this branch claims to satisfy.
3. The PR body of #84 — every claim in it is checkable.
4. `CLAUDE.md` — its "load-bearing invariants" section gained seven paragraphs in this branch.
5. `docs/handovers/2026-07-21-phase-e-handover.md` — the residuals list. A residual that turns out to be a *defect* is a finding; a defect quietly omitted from it is a worse one.

## What the branch claims to have built

Verify each claim against code. **A claim with no enforcement site is a finding.**

1. A shared SSRF/egress boundary: address-class blocking, redirect refusal, resolve-then-validate DNS, optional egress proxy — applied to connector OAuth, brokered MCP dials, delivery callbacks, and git clone, with admission at both save time and dial time.
2. A per-run MCP session manager meeting a 2025-11-25 conformance contract: initialize-first, explicit supported-version set, protocol-version headers, a bounded streaming SSE parser, JSON-RPC errors to unsupported server requests, 404 re-init, session DELETE at run end carrying live-resolved authorization, and insufficient-scope challenges terminal rather than auto-escalated.
3. Server-side validation of tool arguments against the run's frozen JSON Schema, dialect selected by the snapshot's protocol version, before trust-tier and policy evaluation.
4. Durable execution claims keyed `(session, tool_call_id, input_digest)` with four terminal outcomes; the claim is conditional on the session being nonterminal and taken in the same lock order as cancellation; duplicates adopt the stored outcome; only a positively-proven never-sent state is re-claimable, and that is capped.
5. Audience-scoped sandbox credentials (`llm` / `tool` / `control` / `workspace`), each accepted only by its own routes, with the control credential removed from the environment before agent-controlled processes spawn.
6. Multi-replica coordination: approval ledger events emitted inside the deciding transaction, a notify channel for cross-replica wakeups, per-session leases with epoch fencing on driver mutations, and delivery row claims re-stamped per attempt.
7. Per-run LLM budget reservations taken atomically before dispatch, reconciled from authoritative usage, released only on positively-proven non-dispatch.
8. Outbound rate limits (tenant / connection / host) and per-(tenant, connection, host) circuit breakers counting transport failures only.

## The mechanical protocol

Work through these as enumerable sweeps, not impressions. For each, produce the **complete list** you examined, not a sample.

### A. Test-to-mechanism (the highest-value check in this codebase)

For every test and source-guard added in the range: identify the production behavior it claims to protect, **mutate that behavior so the test should fail, and run it.** If it still passes, that is a finding.

This branch has already produced **eleven** tests that passed while testing nothing — guards satisfied by their own doc comments, a search string that was a prefix of the very mutation it existed to catch, tests re-implementing the logic they claimed to verify, and assertions comparing empty against empty because a payload was read one nesting level too high. Assume more remain. **Trust no guard you did not personally mutate.**

### B. Coverage sweeps — enumerate, do not sample

- **Every outbound HTTP dial** in the workspace: is it admitted before connecting? List each call site and its admission status.
- **Every new tenant-owned table**: does its own migration carry `ENABLE`+`FORCE` row-level security, a policy, and an *enumerated* DML grant resolving the runtime role from a setting rather than hardcoding it? (A missing grant fails at runtime under RLS, not at migration time — only in deployments that actually enforce it.)
- **Every route on the internal listener**: does it carry an audience guard as its first statement, before any side effect? Which audience, and is it the right one? Unit tests cannot see a wrong constant — check the code.
- **Every early return between acquiring a resource and using it** (execution claims, budget reservations): is the resource settled or released on that path? An unlisted early return leaks.
- **Every swallowed `Result`** on a security-relevant or durability-relevant write (`.ok()`, `let _ =`, `if let Ok`): what breaks if it fails silently?
- **Every `unwrap`/`expect`/panic** reachable from a request path.
- **Every new environment knob**: what happens on a malformed value — boot failure, or silent fallback? Is that documented accurately in `.env.example`?

### C. Cost and resource analysis

Correctness review already passed on this branch; a whole-branch pass then found a parser that was *correct* and quadratic, freezing a worker for 144 seconds on an 8 MiB response. So for every loop, parse, allocation, or retry driven by remote or user input, ask: **what bounds it?** Specifically hunt superlinear behavior, unbounded allocation, unbounded iteration counts, work that can outlive its own timeout budget, and anything that holds a lock or a database connection across network I/O.

### D. Comment-truth audit

Every comment asserting an invariant, a guarantee, or a rationale: **verify it against the code.** This codebase has produced at least four false comments, including one claiming an API was admin-gated that had been wrong for three phases and nearly concealed a real file-disclosure hole. A comment that is wrong is worse than absent, because reviewers reason from it.

### E. Concurrency and ordering

- Lock ordering across all transactions — is there a documented order, is it uniform, and can any two paths cycle?
- Anything held across an `await` or an HTTP call.
- Test isolation: does any test call a cross-tenant or global scan against the shared test database? (Tests run concurrently; this branch already had two such collisions.)
- For each multi-replica mechanism, construct the interleaving that breaks it, or state why none exists.

### F. Migrations

Order, lock duration and blast radius, whether a validating constraint scans under an exclusive lock, back-compat with a pre-branch binary, and the required deploy sequence.

### G. Claims versus evidence

For each acceptance bullet in issue #33, name the test or CI job that proves it. **Any bullet with no real assertion is a finding** — including one that is asserted in a way that cannot fail. Also verify what CI actually covers: which jobs run, which are skipped by design, and which properties are only covered by tests that self-skip locally.

## Empirically observed defect classes in this codebase

Hunt these by name; each has occurred here at least twice:

1. **False-green tests** — passing without exercising the mechanism (eleven instances).
2. **Stale comments asserting the opposite of the code** (four-plus instances, one security-relevant).
3. **Correct-but-costly code** — passes correctness review, unusable under adversarial input.
4. **Writes without a generation/epoch predicate**, allowing a stale actor to overwrite fresh state (three instances across phases).
5. **Test-isolation collisions** against shared global scans (two instances).
6. **A guarantee that stops at the last hop** — durable machinery defeated by the client that consumes it.
7. **Aspirational documentation** — a claim written before the code, never revisited.

## Output format

Findings ranked **Critical / Important / Minor**. Each must carry:

- `file:line`
- a **concrete failure or exploitation scenario** — inputs and state to wrong outcome, not a category name
- **how you established it** — the mutation you ran, the interleaving you constructed, or the code path you traced

Then, separately and explicitly:

- **Verified correct** — properties you checked and found genuinely holding, so they are not re-examined later. Be specific about what you verified, not just that you looked.
- **Claims I could not substantiate** — anything asserted in the PR body, `CLAUDE.md`, or code comments that you could neither confirm nor refute, and what evidence would settle it.
- **Coverage gaps** — properties with no real test, distinguished from properties the branch honestly discloses as untested.

**"No Critical findings" is a valid and useful result.** Do not manufacture severity. Equally, do not soften a real finding because the branch is otherwise thorough — it has already passed per-task review, three whole-branch scopes, and an independent adversarial pass, and each of those still found Criticals the previous ones missed.
