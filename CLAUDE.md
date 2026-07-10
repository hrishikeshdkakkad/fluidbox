# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

**fluidbox** is a control plane that runs AI coding agents in governed, disposable sandboxes. A user registers a versioned **agent definition**; each **run** freezes an immutable `RunSpec`, provisions a fresh sandbox, streams a live event timeline, pauses for human approval (or auto-decides in autonomous mode), and ends with a diff + cost report. `PLAN.md` is the authoritative design doc and roadmap — read it before making architectural changes. It defines convergence invariants (§2) that every change must preserve.

Hard constraints (from PLAN.md, non-negotiable): fluidbox-authored backend is 100% Rust; the Next.js dashboard is presentation-only (all logic in the Rust API); database is Neon Postgres; OSS/MIT.

## Commands

```bash
just dev            # LiteLLM gateway + server + dashboard together
just server         # Rust control plane only (migrations auto-run on boot)
just web            # dashboard only (Next.js, port 3000)
just gateway-up     # start the pinned LiteLLM container (reads .env)
just sandbox-build  # rebuild the sandbox runner image after editing images/sandbox-runner/
just check          # fmt + clippy -D warnings + test + web build (the full bar)

cargo test -p fluidbox-core                              # fast, no DB needed
cargo test -p fluidbox-db                                # needs DATABASE_URL (real Neon)
cargo test -p fluidbox-core policy::tests::               # a single module's tests
cargo run -p fluidbox-cli -- run --task "…" --repo /path # drive a run from the CLI
```

The `fluidbox-db` and workspace-wide test runs hit **real Neon** — `set -a; source .env; set +a` first so `DATABASE_URL` is present, otherwise the DB test self-skips.

## Environment & setup gotchas (these cost real debugging time)

- **`FLUIDBOX_BIND` must be `0.0.0.0:8787`, not loopback.** Sandboxes reach the control plane via `host.docker.internal`, which resolves to the host's gateway IP — a `127.0.0.1` bind is unreachable from a container.
- **`FLUIDBOX_DATA_DIR` is canonicalized to an absolute path at startup** (`config.rs`). Docker bind mounts reject relative paths; don't undo this.
- **Neon: use the DIRECT (non-`-pooler`) connection string.** PgBouncer transaction mode breaks sqlx prepared statements and `LISTEN/NOTIFY` (`PgListener` needs a direct connection). `scripts/neon-setup.sh` enforces this.
- **The Anthropic key lives ONLY in the LiteLLM container**, injected via docker-compose from `.env`. The Rust server never holds it (it authenticates to LiteLLM with `LITELLM_MASTER_KEY`). No server restart is needed after adding the key — just `just gateway-up`.
- **`.env` is gitignored; `apps/web/.env.local` too** (it carries the admin token for the dashboard proxy). Never commit either.
- sqlx needs the `macros` + `derive` features; clap needs `env`; reqwest 0.13 uses the `rustls` feature (not `rustls-tls`). LiteLLM is pinned by **digest** in `.env` (`LITELLM_IMAGE=...@sha256:...`); tag `main-v1.91.1` does not exist as an image — use `main-stable` and re-pin the digest.

## Architecture — how a run flows

The crate dependency order is `fluidbox-core` → `fluidbox-db` / `fluidbox-provider` → `fluidbox-server`; `fluidbox-cli` is a thin reqwest client.

- **`fluidbox-core`** — pure domain, no I/O. The policy engine (`policy.rs`), session state machine (`state.rs`), canonical event schema + redaction (`event.rs`), `RunSpec`/autonomy (`spec.rs`), and the extension traits (`traits.rs`: `ExecutionProvider`, `Harness`). Change domain rules here and the tests here.
- **`fluidbox-server`** is one binary with several planes wired in `main.rs`:
  - **Public `/v1` API** (`api.rs`) — admin-token auth (`auth.rs`); the dashboard + CLI talk only here.
  - **Internal gateway `/internal`** (`internal.rs`) — per-session-token auth; **only the in-sandbox runner talks here**. Houses the permission handler (the heart of the system) and `events`/`heartbeat`/`result`.
  - **LLM facade `/internal/llm`** (`facade.rs`) — the sandbox's fake `ANTHROPIC_API_KEY` **is its session token**; the facade validates it, enforces the budget stop, swaps in the real upstream credential, forwards to LiteLLM, and tees the SSE stream to meter usage.
  - **Orchestrator** (`orchestrator.rs`) — drives lifecycle transitions; the **server is the single status writer**, the runner only reports.
  - **Workers** (`workers.rs`) — heartbeat watchdog, wall-clock budget sweeper, approval expiry, boot-time orphan reap.
  - **SSE** (`sse.rs`) — the event stream.
- **`images/sandbox-runner/runner/index.mjs`** is the **only sanctioned Node payload**: the Claude Agent SDK harness. It implements the runner contract (`canUseTool`→`/permission`, message stream→`/events`, heartbeats, final `/result`). It is sandbox *workload*, not backend Rust — that's why Node here doesn't violate the Rust constraint.

### Load-bearing invariants (violating these breaks the security/audit model)

- **RunSpec is frozen at session creation** and stored as jsonb, including a full policy snapshot. In-flight runs are governed by their snapshot; editing an agent or policy only affects *future* runs. This immutability is what makes the audit trail trustworthy.
- **Agents are append-only.** Editing an agent = appending a `agent_revision` (never mutating one). The model + system prompt live on the revision; a run uses the *current* (latest) revision's values.
- **Two distinct prompts:** the **system prompt** is on the agent revision (who the agent is); the **task** is per-run (what to do this time). The New Run flow only takes the task.
- **The permission callback stays wired in both autonomy modes** — never the SDK's `bypassPermissions`. Autonomous mode rewrites a `RequireApproval` verdict to the policy fallback *inside* `evaluate()`, recording both the original and rewritten verdict in the ledger.
- **Approvals are idempotent by `(session_id, tool_call_id)`.** The DB row is the source of truth; the in-memory `Notify` only wakes a blocked handler early. On restart, the runner's retry re-attaches to the pending row — nothing duplicates or hangs.
- **The ledger only accepts `Redacted<EventEnvelope>`** (`event.rs`) — constructible solely via `Redactor::scrub`. Model prompts never reach the ledger; only digests + usage + cost. `append_event()` (SQL function) assigns a gapless per-session `seq` under a row lock and `pg_notify`s.
- **SSE fanout is hybrid:** NOTIFY is only a wakeup; the `seq` catch-up query is the delivery source of truth (immune to missed notifies and Neon scale-to-zero). Same query powers `Last-Event-ID` resume.
- **Workspace init is control-plane-side.** The credentialed fetch/copy happens in the orchestrator during the `initializing` state (before the agent starts); the agent only ever sees a bind-mounted copy at `/workspace`. The original repo is never touched, and the sandbox stays egress-free.

## Extension points

New execution backend → implement `ExecutionProvider` (the Lambda MicroVM provider is the next planned one; `SandboxHandle` is already serializable jsonb for reattach). New agent harness → a new runner image implementing the runner contract + a `Harness` impl. Neither should leak specifics into `fluidbox-core`. The seams exist precisely so nothing above them changes — see PLAN.md §6.2.

## Testing acceptance

`scripts/governance-e2e.sh` drives the internal gateway over real HTTP (policy verdicts, approval pause/resume, idempotency, autonomous auto-deny) — run it after touching the permission/approval path. The live agent demo (fix a failing test) needs `ANTHROPIC_API_KEY` in `.env` and the gateway up.
