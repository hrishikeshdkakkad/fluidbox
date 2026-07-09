# fluidbox — Validation & MVP Plan

> **Status:** validated & scoped, awaiting build kickoff · **Date:** 2026-07-09 (rev 2: north-star convergence + LiteLLM gateway) · **License target:** MIT (OSS)
> **Source spec:** [`init_prompt.txt`](./init_prompt.txt) — "Agent Execution Platform on AWS Lambda MicroVMs"

## 1. Context

`init_prompt.txt` specifies a **BYOC agent-execution governance platform**: a control plane that lets AI coding agents (Claude, Codex, others) safely run code and tools inside isolated, customer-owned execution environments, with per-action policy, human approvals, append-only audit, and cost controls. The wedge product is "secure event-triggered coding agents for private GitHub repositories."

This document is the result of mechanically validating that spec against reality (2026-07-09) and scoping an MVP under these hard constraints:

- **This directory is the mono-repo** (greenfield; `git init` is step zero)
- **OSS, MIT licensed**
- **Backend: Rust** — all fluidbox-authored backend code is Rust; Next.js is presentation-only. Third-party infrastructure we *deploy but don't author* — Neon Postgres, Docker, the LiteLLM model gateway — doesn't count against this, in the same way the in-sandbox Node runner is workload, not backend.
- **Frontend: Next.js**
- **Database: Neon Postgres, provisioned via the Neon CLI**

## 2. North star & convergence

**The product fluidbox converges to:** a user opens the dashboard and registers an **agent definition** — "built on the Claude Agent SDK" or "built on Codex" — as a versioned recipe: runner image, default prompt, model, allowed tool/MCP **capability bundles**, policy, and budgets. From then on, any person or trigger starts **runs** of that agent. Each run freezes an immutable **RunSpec**, gets a fresh governed sandbox on fluidbox-managed infrastructure, streams a live timeline, and ends with artifacts, a diff, and a cost report. Runs execute in one of two **autonomy modes**: **supervised** (risky actions pause for human approval) or **autonomous** (long-running, no human in the loop — the policy's pre-decided answers apply instantly). Fluidbox never reimplements an agent's reasoning loop; it gives every supported harness the same secure runtime contract.

Core nouns (all present in the schema from M1 onward — the MVP is a thin *instance* of the end state, never a different architecture):

| Noun | Meaning |
|---|---|
| **Agent definition** | Identity + a chain of immutable **revisions** (harness, runner image, default prompt, model, capability bundles, policy ref, default budgets) |
| **Run (session)** | One execution: a frozen **RunSpec** (agent revision + repo + task + **autonomy mode** + effective budgets/policy snapshot) + one disposable sandbox + its ledger |
| **Capability bundle** | A named set of tools / MCP bindings an agent *may* be granted; bound per-session, credential-brokered, policy-gated |
| **Policy** | What a run is *allowed* to do with the capabilities it has (allow / deny / require-approval, egress, budgets) |
| **Execution provider** | Where the sandbox runs (Docker → Lambda MicroVMs → others) behind one trait |

### Convergence invariants — every milestone must preserve these

1. **Definition ≠ run.** An agent is a versioned immutable recipe; every run is a fresh disposable sandbox. No persistent, privileged agent servers — ever.
2. **Harness-agnostic runner contract.** `start(RunSpec)` / `emit(event)` / `request_permission(tool_call)` / usage reporting / `finish(result)`. The Claude runner, the Codex runner, and future customer-built images all implement the same contract; nothing harness-specific leaks into `fluidbox-core`.
3. **Capability ≠ permission ≠ containment.** Bundles say what's *available*, policy says what's *allowed*, the sandbox guarantees what's *impossible*. Three independent layers; weakening one never weakens the others.
4. **Model access flows through the gateway, governance stays in Rust.** Sandboxes hold only a session token. The Rust facade authenticates the session and enforces budget stops; LiteLLM owns provider credentials, routing, and pricing; fluidbox owns identity, policy, approvals, budget *decisions*, and the canonical ledger. The gateway sits **below** the governance plane and is replaceable.
5. **Curated before custom.** M1–M2 ship pinned first-party runner images only; customer-supplied agents arrive in M3, strictly as signed, versioned images implementing the runner contract.
6. **Autonomous ≠ ungoverned.** A run's autonomy mode only changes *who answers* the permission question — a waiting human (supervised) vs the policy's pre-decided fallback (autonomous) — never *whether it is asked*. Every tool call still flows through the policy gateway and lands in the ledger in both modes; the runner keeps its permission callback wired always (never the SDK's `bypassPermissions`, which would skip the callback and blind the audit trail). As autonomy rises, budgets and containment tighten — they never loosen. Long-running agents are first-class citizens of the same lifecycle, not a separate system.

### Convergence map

| Milestone | What of the north star becomes real |
|---|---|
| **M1** | The full vertical slice with one harness: agent definitions w/ revisions, RunSpec freeze, governed sandbox (with its post-startup workspace-init phase), LiteLLM gateway + facade, approvals/ledger/budgets/artifacts, and the "New Run" dashboard flow shaped like the end-state UX |
| **M2** | The execution substrate the product promises: Lambda MicroVMs + BYOC Terraform, behind the same `ExecutionProvider` seam — long-running agents get lease rollover + idle-suspend |
| **M3** | Multi-harness for real: the Codex runner, the tool/MCP capability-bundle catalog + UI, customer-signed runner images — the north star, verbatim |
| **Roadmap** | Runs triggered by the outside world (GitHub App, Slack, Jira…). Descoped 2026-07-09: triggers only *create runs of registered agents*, so nothing about the run model changes — the seams (trigger jsonb, trust tiers) still ship in M1 |

## 3. Validation findings (what's real, what's adjusted)

### ✅ AWS Lambda MicroVMs — REAL, GA
- **GA since 2026-06-22** in us-east-1, us-east-2, us-west-2, ap-northeast-1, eu-west-1. Separate AWS service (`lambda-microvms`, API ver 2025-09-09, SigV4); network connectors under the `lambda-core` namespace.
- Resource model: `MicrovmImage` (S3 zip w/ Dockerfile on managed AL2023 base; snapshot captured after `/ready`) + `Microvm` (`RunMicrovm` → dedicated HTTPS endpoint + `microvmId`). Two IAM roles (build + execution). Sizes 0.5–8 GB baseline with 4× vertical burst (max 32 GB/16 vCPU); suspend/resume preserves memory+disk; suspended = snapshot-storage-only billing.
- **Rust support:** dedicated crate `aws-sdk-lambdamicrovms` (v1.1.0) exists — verify op coverage on first use; SigV4-signed REST via `aws-config` + `aws-sigv4` is the guaranteed fallback.
- Data plane (the MicroVM endpoint) is **not** SigV4: mint a **JWE token** via `CreateMicrovmAuthToken` (max TTL 60 min → refresh loop required), send `X-aws-proxy-auth` + `X-aws-proxy-port` (default 8080).
- **Spec correction #1:** runtime lifecycle hooks (`/run`, `/suspend`, `/resume`, `/terminate`) are fast-notification only (~1–60 s). The spec's plan to restore workspaces inside `/run` won't work — workspace restore must be driven by the control plane calling the in-VM worker after `RunMicrovm` returns. Build-time hooks `/ready`/`/validate` (1–3600 s) are where snapshot prep happens. All six hooks are `POST /aws/lambda-microvms/runtime/v1/<hook>`; traffic only flows after `/run` returns 200; keep `runHookPayload` ≤ 4 KB.
- **Spec correction #2:** the **8-hour cap is a hard ceiling on total RUNNING+SUSPENDED lifetime** (`maximumDurationInSeconds` ≤ 28,800) — suspend does not extend it. Network connectors are fixed at run time (can't switch across suspend/resume).

### ✅ Claude integration — REAL, two Rust-viable paths
1. **Rust-native agentic loop on the Messages API** (GA, low-risk): tool_use/tool_result loop over raw HTTPS `POST /v1/messages` (reqwest + SSE parser; no official Rust SDK — raw HTTP is the sanctioned path). Models: `claude-opus-4-8` ($5/$25 per MTok, Anthropic's recommendation for agentic coding), `claude-sonnet-5`, `claude-haiku-4-5`. Adaptive thinking `{type:"adaptive"}`; `stop_reason` state machine (`tool_use`/`end_turn`/`refusal`/`pause_turn`).
2. **Claude Managed Agents self-hosted sandboxes** (beta `managed-agents-2026-04-01`): Anthropic hosts the loop; env `config:{type:"self_hosted"}`; a worker in our infra long-polls an **outbound-only work queue**. **The full worker wire protocol is documented raw HTTP** — `GET /v1/environments/{env}/work/poll` (`block_ms`, `Anthropic-Worker-ID`) → `ack` → `heartbeat` (optimistic concurrency, 412 on mismatch) → `stop`; tool channel = SSE `GET /v1/sessions/{id}/events/stream` delivering `agent.tool_use`, answered via `POST …/events` with `user.tool_result` (self_hosted-only event). One `ANTHROPIC_ENVIRONMENT_KEY` authorizes both. Docs explicitly bless DIY workers → **a pure-Rust worker is feasible** (implements only `bash/read/write/edit/glob/grep`, `/workspace` + `/mnt/session/outputs` conventions, >100k-token spill-to-file). Gaps: skills-download endpoint undocumented (skip skills initially); memory stores unsupported self-hosted; beta protocol may shift.
- AWS ships a reference for exactly this pattern: one Lambda MicroVM per CMA session (webhook `session.status_run_started` → launcher Lambda → `RunMicrovm`); sample repo `aws-samples/sample-lambda-microvm-claude-managed-agents`.
- **Claude Agent SDK** (a third path — chosen for the MVP, see §4): Claude Code packaged as a TS/Python library; the full harness runs on infra we control, calling the Anthropic API only for inference. Supports `canUseTool`/`PreToolUse` permission callbacks, structured message streams, session resume, and honors `ANTHROPIC_BASE_URL`.
- Cost-ledger inputs confirmed: per-model pricing + `usage` fields (incl. cache tokens) on every API response.

### ✅ Codex — REAL, embeddable
- Codex CLI (`github.com/openai/codex`) is **Rust, Apache-2.0** (v0.143.0). `codex mcp-server` runs it as an MCP server over stdio (JSON-RPC 2.0) exposing `codex` + `codex-reply` tools. **Fully headless with `OPENAI_API_KEY` + `approval-policy:"never"`.** Interface marked experimental → pin the version. Its built-in Landlock/seccomp sandbox may conflict inside our container → run with `sandbox: danger-full-access` (our container/MicroVM is the isolation boundary). The TS Codex SDK is the fallback route (as an in-sandbox runner payload, symmetric with the Claude runner) if the MCP interface proves too limited.

### ✅ LiteLLM as the model gateway — REAL, with known sharp edges (validated 2026-07-09)
- LiteLLM proxy provides Anthropic-native `/v1/messages` (+ `count_tokens`) routes, provider routing, retries/fallbacks, a maintained pricing catalog, virtual keys, spend tracking, and usage callbacks; it documents Claude Code and **Claude Agent SDK** usage via `ANTHROPIC_BASE_URL`.
- **Sharp edges found during validation** (all drive the M1 "gateway gate" test, §7): a documented Agent SDK 403 failure mode through LiteLLM proxies (side-channel calls / auth-token forwarding — [claude-code-action #1089](https://github.com/anthropics/claude-code-action/issues/1089)); spend tracking on native `anthropic_messages`/passthrough call types was silently $0 until fixed ([#24204](https://github.com/BerriAI/litellm/issues/24204) → PR #26248); cache-read tokens were mispriced when streaming ([#11789](https://github.com/BerriAI/litellm/issues/11789)); **PyPI releases 1.82.7/1.82.8 shipped credential-stealing malware** → pin a known-clean release, never float.
- Mitigation is structural: the Rust facade's upstream is a config URL, so direct-Anthropic passthrough (+ facade tee metering, the rev-1 design) remains a one-line fallback if a pinned release fails the gate.

### ✅ Neon — REAL
- CLI: `neonctl` (`npx -y neonctl@latest`; browser OAuth; projects/branches/connection-string subcommands). Branch-per-environment workflow; optional `neon.ts` config-as-code with TTL'd dev branches and scale-to-zero.
- Rust: plain Postgres — sqlx with a rustls TLS feature, `sslmode=require`. **Design rule: use the DIRECT (non `-pooler`) connection string** — PgBouncer transaction mode breaks sqlx prepared statements (`sqlx_s_N already exists`) and `LISTEN/NOTIFY` (`PgListener` requires a direct connection).

### ✅ Rust stack — no blockers (versions verified 2026-07)
axum 0.8.9 (native SSE) · sqlx 0.9.0 · bollard 0.21.0 (Docker Engine API) · octocrab 0.54.0 (GitHub App JWT → installation tokens, Checks, PR review comments) · hmac 0.13 + sha2 0.11 + `subtle` (webhook signatures, constant-time compare) · jsonwebtoken 10.4 · rmcp 2.2.0 (official Rust MCP SDK; stdio client) · cargo-lambda 1.9.1 / lambda_runtime 1.2.1 · Next.js 16.2.6 (App Router + Tailwind default) · shadcn/ui via `shadcn init`.

### Local environment (verified on this machine)
- Present: git 2.50, Rust 1.96, Node 25, pnpm, bun, Docker 29 (daemon running), gh CLI (authed), AWS CLI v2, Terraform 1.14.
- To install during M0: `neonctl` (via npx), `sqlx-cli`, `just`.

## 4. Decisions (locked 2026-07-09)

| Decision | Choice |
|---|---|
| Project name | **fluidbox** (crates `fluidbox-*`; check crates.io/GitHub collisions in M0) |
| Product shape | **Agent-registry platform** (§2 north star) — every milestone is a convergence step; the MVP is a thin instance of the end architecture, never mock scaffolding to be replaced |
| MVP runtime | **Docker first** (bollard) behind an `ExecutionProvider` trait; Lambda MicroVMs = M2 flagship |
| Workspace init | **A formal post-startup init phase** (`initializing`, §6.7): container/VM starts → orchestrator materializes the workspace through provider APIs → agent starts. The credentialed fetch stays **control-plane-side** — an in-container token would be readable by the agent moments later, and MicroVM network connectors are fixed at run time, so "egress only during init" can't exist on the flagship runtime. The sandbox stays egress-free always |
| First harness | **Claude Agent SDK in-sandbox** — the Claude Code harness runs as a Node payload inside the sandbox, governed by (a) `canUseTool`/`PreToolUse` hooks → the Rust policy gateway, (b) model egress through the **session facade → LiteLLM gateway** (the provider key never enters the sandbox), (c) sandbox network isolation as the structural backstop |
| Model gateway | **LiteLLM (pinned release) behind a thin Rust session facade** — LiteLLM owns provider keys, routing, retries, and pricing; fluidbox owns session identity, policy, budget decisions, and the canonical ledger. The facade's upstream is a config URL → the gateway is swappable (equivalent gateways, or direct-Anthropic fallback) without touching fluidbox code |
| Run autonomy | **Both modes from M1** — `autonomy: supervised \| autonomous` on the RunSpec. In autonomous mode, `RequireApproval` verdicts resolve instantly to a policy-configured fallback (**default `deny`**, per-rule `allow` opt-in); a policy may forbid autonomous runs outright. The runner keeps `canUseTool` wired in both modes so every tool intent + verdict is ledgered — the SDK's `bypassPermissions` is never used. Long-running support (token renewal, unbounded wall-clock opt-in) lands with it; idle-suspend/resume rides M2's MicroVM work |
| MVP wedge | **Local-first** (CLI `fluidbox run` + dashboard "New Run"). **GitHub integration descoped 2026-07-09:** "Connect GitHub" is just a stored fetch token in settings, consumed by the workspace-init phase — the GitHub App / webhooks / PR-trigger wedge moves to the roadmap |

> Note on the Rust constraint: fluidbox-authored backend code is 100% Rust. The Agent SDK runner is sandbox **workload** (like the `codex` binary later), and LiteLLM is **deployed third-party infrastructure** (like Postgres) — neither is fluidbox backend code.

## 5. Spec → MVP traceability

| `init_prompt.txt` element | Disposition |
|---|---|
| Control-plane services (api/session/policy/approval/tool-gateway/orchestrator/cost) | **M1** — modules in one `fluidbox-server` binary (mono-binary, not microservices, for OSS simplicity) |
| Agent registry / multi-agent configuration | **M1 (minimal, structural):** `agents` + immutable `agent_revisions` + frozen per-run RunSpec — one curated harness. **M3:** second harness, capability-bundle catalog, customer images |
| Event ingress + trigger router + GitHub App/PR triggers, fork-PR two-phase trust | **Out of MVP scope → roadmap** (user decision 2026-07-09). Seams still built in M1 (`sessions.trigger` jsonb, `trust_tier`, Trigger enum) so triggers later bolt on without run-model changes. MVP repo access = repo URL + stored fetch token, consumed by the workspace-init phase |
| Harness adapters (multi-harness thesis) | `Harness` trait **M1**; ClaudeSdkPayload impl **M1**; Codex runner **M3**; CMA self-hosted Rust worker **M3**; native Rust Messages loop when needed; LangGraph/CrewAI later via the trait |
| Execution Provider API (spec's TS interface) | Rust `ExecutionProvider` trait **M1** (Docker impl); **Lambda MicroVM impl M2**; E2B/Modal/K8s later |
| 8-hour lease rollover | **M2** — orchestrator-owned `Lease` + `Harness::checkpoint()` seam designed now |
| Workspace persistence (spec: S3 + DynamoDB) | **Adjusted:** Neon Postgres ledger + inline artifacts **M1**; S3 workspace/artifact store **M2** |
| Tool catalog / custom tools / MCP gateway | **Capability bundles** — noun + schema seam **M1** (fixed built-in bundle); catalog, MCP bindings, credential brokering + UI **M3** |
| Secrets broker | **Adjusted M1:** session facade + LiteLLM key custody = zero provider secrets in the sandbox; Vault/SM broker **M3** |
| Approval engine (once/session/timeout) | **M1** |
| Audit ledger + replayable timeline | **M1** (append-only canonical events + SSE timeline) |
| Cost ledger | **M1** — LiteLLM usage callbacks → `usage_entries` + cost in the fluidbox ledger (fluidbox stays the source of truth); minimal in-core pricing table retained only for the direct-passthrough fallback |
| Policy engine (YAML, egress modes, budgets) | **M1** (v0 single-layer, first-match-wins; layered deny-wins merge in M3) |
| BYOC Terraform installer, VPC connectors, KMS | **M2** |
| Jira/Slack/Linear triggers, SSO/RBAC, ROI dashboards, rollover autotuning | **Roadmap** — schema is multi-tenant-ready (`tenant_id` everywhere) but the MVP runs single-tenant |
| Product naming section | Resolved: **fluidbox** |

## 6. Architecture

### 6.1 Mono-repo layout

```
infra/                                # this dir = the mono-repo
├── Cargo.toml (workspace)  rust-toolchain.toml  LICENSE (MIT)  README.md  justfile
├── .env.example  .sqlx/ (offline query cache)  .github/workflows/{ci.yml,sandbox-image.yml}
├── crates/
│   ├── fluidbox-core/      # pure domain: IDs, session state machine, canonical EventEnvelope/EventBody,
│   │                       #   Redactor/Redacted<T>, RunSpec, usage/cost types, policy schema + evaluate(),
│   │                       #   ExecutionProvider + Harness + PolicyGateway + LedgerSink TRAITS
│   ├── fluidbox-db/        # sqlx repos, PgListener + polling fallback, migrations runner, seeds
│   ├── fluidbox-provider/  # DockerProvider (bollard): per-session network, workspace, exec, diff, reap
│   ├── fluidbox-server/    # axum bin: public /v1 API + SSE, internal gateway + LLM session facade,
│   │                       #   usage-callback ingestion, orchestrator, approval-wait registry,
│   │                       #   budget sweeper, watchdog
│   └── fluidbox-cli/       # `fluidbox` bin: run / sessions / watch / approve (reqwest client)
├── apps/web/               # Next.js 16 App Router + Tailwind + shadcn; same-origin proxy route injects
│                           #   the admin token server-side (presentation-only; handler = pure forwarding)
├── images/sandbox-runner/  # Dockerfile (node:24-bookworm-slim + git/ripgrep/toolchains + agent-sdk)
│                           #   + runner/index.mjs — the first-party Claude runner (implements the
│                           #   runner contract; the Codex runner joins it in M3)
├── deploy/                 # docker-compose.dev.yml (litellm pinned + fluidbox-server + web)
│                           #   + litellm/config.yaml (Anthropic passthrough, virtual key, usage callback)
├── migrations/  policies/ (seed YAML)  docs/  scripts/neon-setup.sh
```

### 6.2 Key seams (extension-critical; full signatures live in `fluidbox-core`)

- **`ExecutionProvider` trait** — `provision(spec)→SandboxHandle` / `reattach` / `exec→stream` / `read_file`/`write_file` / `expose_endpoint→EndpointHandle` / `snapshot`/`suspend`/`resume` / `terminate(collect)` / `health` + `capabilities()`. **`SandboxHandle` is serializable data persisted as jsonb** (runtime kind, external id, endpoint descriptor, `Lease`, provider attrs) — never a live client → survives restarts and fits MicroVM (`microvmId` + HTTPS endpoint + lease) as well as Docker (`container_id`). `EndpointHandle::auth_headers()` hides JWE minting/refresh (MicroVM) vs nothing (Docker). The 8-hour lease is enforced by the **orchestrator** (provider only reports `lease_remaining`); JWE refresh is **provider-internal** and reconstructible from the persisted handle.
- **`Harness` trait + runner contract** — `start(RunContext) → HarnessHandle{events: EventStream, control}`; `HarnessControl::{interrupt, send_input, checkpoint}`. The adapter **orchestrates** (spawns the payload / polls the vendor queue / drives an MCP child); where the loop runs never leaks into the trait. `RunContext` carries the frozen **RunSpec** and injects `provider`, optional `endpoint`, and `GovernanceCtx{policy, ledger, meter}` — all topologies (loop-in-control-plane, loop-in-sandbox-payload, loop-on-vendor-cloud, loop-via-MCP) funnel tool intents through `PolicyGateway::evaluate` and usage through `ModelMeter`. The in-sandbox side of this is the **runner contract** (north-star invariant #2): env-injected identity, `/permission`, `/events`, `/heartbeat`, `/result` — identical for every harness image.
- **Agent registry & RunSpec** — `agents` are identity; `agent_revisions` are immutable recipes (harness, runner image digest, default prompt, model, capability-bundle refs, policy ref, default budgets). Creating a run **freezes a RunSpec** (revision + repo + task + effective budgets + policy snapshot) into the session row; reproducibility and audit follow from immutability. Editing an agent = appending a revision, never mutating one.
- **Canonical event ledger** — envelope columns (event_id v7, schema_version, tenant_id, session_id, run_id, **seq DB-assigned per session**, ts, occurred_at, actor, harness, causation_id) + stable dot-named `type` strings (explicit serde renames, `Unknown` fallback) + payload jsonb. **Redaction is type-enforced:** `LedgerSink::append` accepts only `Redacted<EventEnvelope>` (constructible solely via `Redactor::scrub`); model prompts are NEVER stored — digests + token usage + cost only.
- **Policy v0 (YAML)** — `match{agents, triggers, trust_tiers}`, `defaults.tool_action: approve` (fail-safe), `egress.mode: none|proxy-only|allowlist`, `budgets{max_wall_clock, max_tokens, max_cost_usd, max_tool_calls}` (wall-clock may be `unlimited` only by explicit opt-in — autonomous runs then lean on token/USD/tool-call caps), `approvals{default_ttl, scope, timeout_action}`, `autonomy{permitted: true|false, on_approval_rule: deny (default) | allow}`, ordered `tools:` rules (tool matchers, path allow/deny globs, shell allow_prefixes + deny_regex, optional per-rule `on_autonomous: allow|deny` override) → `Allow | Deny{reason} | RequireApproval{risk, ttl, scope}`. **Autonomy is resolved inside `evaluate()`:** in autonomous mode a `RequireApproval` verdict is rewritten to the rule's (or policy's) fallback before it ever leaves the engine — the ledger records both the original verdict and the rewrite. M1 = single policy snapshot per session; layered deny-wins merge lands with M3.

### 6.3 Model gateway (LiteLLM + Rust session facade)

```
sandbox runner ──(session token as ANTHROPIC_API_KEY)──▶ Rust session facade   (fluidbox-server /internal/llm)
                                                            │  validates session + token, refuses if budget spent,
                                                            │  stamps tenant/session/policy metadata, streams bytes verbatim
                                                            ▼
                                                         LiteLLM (pinned; private network only; holds provider keys
                                                            │     + virtual key per deployment; native /v1/messages passthrough)
                                                            ▼
                                                         Anthropic  (M3: + OpenAI for Codex, via the same gateway)

LiteLLM usage callback ──▶ POST /internal/llm-usage (fluidbox-server) ──▶ usage_entries + model.response event + cost
```

- The facade is deliberately tiny: session auth, pre-flight budget stop, metadata stamping, verbatim byte streaming. It does **not** parse provider SSE or compute costs — LiteLLM's callback feeds the ledger, and the ledger remains fluidbox's canonical truth (budget sweeper reads `usage_entries`, not LiteLLM's spend tables).
- LiteLLM is reachable **only** on the private compose network; sandboxes can never address it directly. Its own admin UI/DB features are conveniences, never sources of truth for governance.
- **Fallback (designed-in):** the facade upstream is `LLM_UPSTREAM_URL`. If a pinned LiteLLM release fails the gateway gate (§7), point it at `api.anthropic.com`, enable the facade's tee-metering module (kept in-tree), and ship — the sandbox contract and security model are unchanged either way.

### 6.4 Database (Neon Postgres — DIRECT connection, `sslmode=require`)

Tables (all with `tenant_id`): `tenants`, `agents` + **`agent_revisions`** (immutable: harness, runner image digest, default prompt, model, capability-bundle refs jsonb, policy ref, default budgets), `policies` (YAML source + parsed jsonb cache, versioned), `sessions` (status, **`agent_revision_id`**, **frozen `run_spec` jsonb**, task, repo source/ref, `sandbox_handle` jsonb, `trust_tier`, trigger jsonb, budgets snapshot, `event_seq` counter, heartbeat), `events` (**append-only**; `unique(session_id, seq)`; seq assigned by a SQL `append_event()` function that row-locks the session, inserts, and `pg_notify('fluidbox_events', …)`), `approvals` (**unique(session_id, tool_call_id)** for idempotency; statuses incl. approved_once/approved_session/expired), `artifacts` (diff/summary/log; inline content in M1), `usage_entries` (model, token quads incl. cache tokens, USD — fed by the LiteLLM callback), `api_tokens` (sha256 hashes; kinds admin|session), `settings`.

**SSE fanout is hybrid:** NOTIFY is only a wakeup; the seq catch-up query (`where session_id=$1 and seq>$last order by seq`) is the delivery source of truth, with a 2–3 s polling floor and listener keepalive/reconnect → immune to Neon scale-to-zero and missed notifies. The same query powers `Last-Event-ID` resume.

### 6.5 API surface (axum)

- **Public `/v1` (admin token):** sessions CRUD + `cancel` · `GET /sessions/{id}/events` (paged) + `/events/stream` (SSE, Last-Event-ID) · artifacts list/download · `/cost` · approvals inbox + `POST /approvals/{id}/decision` (`approved_once|approved_session|denied|revise`) · **agents CRUD + `POST /agents/{id}/revisions`** (append-only revisions; a run references exactly one) · policies CRUD + `/validate` · settings · `/health`, `/health/ready`.
- **Internal `/internal` (per-session token; sha256-stored; TTL = budget + buffer; long/unbounded runs renew via `POST /internal/token/renew` — old token gets a grace overlap so in-flight calls never race the rotation):** `POST /sessions/{id}/permission` (canUseTool callback — blocks ≤10 min in supervised mode; **answers immediately in autonomous mode** with the policy's pre-resolved verdict; **idempotent by tool_call_id**) · `/events` ingest · `/heartbeat` · `/result` · **`/internal/llm/*` — the session facade** (§6.3): the sandbox's `ANTHROPIC_API_KEY` *is* its session token; the facade validates it, enforces the budget stop, and streams verbatim to LiteLLM, which holds the real provider keys · **`POST /internal/llm-usage`** (shared-secret auth) — LiteLLM's usage callback → `usage_entries` + `model.response` event.

### 6.6 Sandbox contract (M1 Docker)

- **Image:** `node:24-bookworm-slim` + git/ripgrep/curl/python3/build-essential + `@anthropic-ai/claude-agent-sdk` (pinned) + `runner/index.mjs`; non-root user; no published ports; entrypoint = runner.
- **Runner env:** `FLUIDBOX_CONTROL_URL`, `FLUIDBOX_SESSION_ID/TOKEN`, `FLUIDBOX_TASK`, `FLUIDBOX_AUTONOMY=supervised|autonomous`, `FLUIDBOX_WORKSPACE=/workspace/repo`, `ANTHROPIC_BASE_URL=$CONTROL/internal/llm`, `ANTHROPIC_API_KEY=$SESSION_TOKEN` (fake — the facade swaps identity; the real key lives in LiteLLM's env only).
- **Runner behavior:** Agent SDK `query()` with `canUseTool` → `POST /internal/…/permission` (supervised: blocks; retries with the same tool_call_id on socket drop — the server's 10-min bound always wins · autonomous: returns immediately with the pre-resolved verdict). **`canUseTool` stays wired in both modes** — `FLUIDBOX_AUTONOMY` only tunes runner expectations (timeouts, retry cadence), never switches the SDK to `bypassPermissions` (invariant #6). Message stream + hooks → `/events`; 10 s heartbeats; final `/result` with summary. This *is* the runner contract (invariant #2) — the M3 Codex image implements the identical surface.
- **Workspace = the post-startup init phase** (user decision 2026-07-09): after the container starts and *before the agent starts*, the orchestrator runs the sandbox's "post-start hook" — workspace materialization through provider APIs, during the `initializing` state. The credentialed fetch itself executes **control-plane-side**: local repos via `git clone --local` (or copy) into `$DATA_DIR/workspaces/<session>/repo`; remote repos fetched with the stored "Connect GitHub" token (a settings entry, not an integration). Record the base commit, then hand the tree to the sandbox (Docker: bind-mount rw as a provider-internal optimization; MicroVM in M2: archive push via the same provider file APIs). Two reasons the fetch never moves inside the sandbox even though the *phase* runs post-startup: (1) an in-container token is readable by the agent that starts seconds later, and (2) MicroVM network connectors are fixed at run time — "egress only during init" is inexpressible on the flagship runtime, so always-egress-free is the only portable posture. The agent can never touch the original repo. **Diff captured control-plane-side** at session end (`git add -A && git diff --binary <base>` → artifact).
- **Network:** **hardened/compose mode** (per-session bridge with `internal: true`, control-plane container attached → zero external egress; the structural backstop; LiteLLM on a separate private network the sandbox is *not* attached to) and **host-dev mode** (`host.docker.internal` gateway; egress constrained by policy) — provider-selected, both documented.

### 6.7 Session lifecycle & approvals

`created → provisioning → initializing → running ↔ awaiting_approval → completed | failed | cancelled | budget_exceeded`

`initializing` is the post-startup init phase (§6.6): the sandbox is up but the agent hasn't started — the orchestrator materializes the workspace and binds capabilities, then starts the runner. Init failures (bad repo URL, dead token) fail the session *before* any model spend.

Autonomous runs never enter `awaiting_approval` — the same state machine, minus one edge. Long-running autonomous sessions are otherwise ordinary sessions: same heartbeats, same watchdog, same ledger; their guardrails are budgets (token/USD/tool-call caps carry the weight when wall-clock is opted out) plus containment. Idle-suspend/resume for days-long agents arrives with M2's MicroVM snapshot support, behind the same lifecycle.

The **server is the single status writer** (the runner only posts events/heartbeats/result). Watchdog: stale heartbeat (>60 s) + dead container → `failed` + reap; boot-time orphan sweep by the `fluidbox.session` container label; a budget sweeper enforces wall-clock/token/USD/tool-call budgets (reading fluidbox's own `usage_entries`) → graceful stop, and the facade refuses further model calls once a budget is spent.

Approvals: **the DB row is the truth**; an in-memory oneshot + `tokio::select!{decision, 10min timeout → auto-deny}` is a convenience. On server restart the runner's retry re-attaches to the pending row (no duplicates, nothing hangs). `approved_session` scope key = tool name — except Bash, where it is the matched risk pattern (approving `git push` covers `git push`, not all shell).

## 7. Milestones

### M0 — Repo skeleton
1. `git init`; `.gitignore`, MIT `LICENSE`, `README.md`, `rust-toolchain.toml`. ✓ `git status`
2. Workspace `Cargo.toml` + 5 stub crates. ✓ `cargo build --workspace`
3. `justfile` (dev, migrate, server, web, sandbox-build, gateway, neon-setup, fmt, lint, test). ✓ `just --list`
4. `apps/web` via `create-next-app` (TS, Tailwind, App Router) + `shadcn init`. ✓ `pnpm -C apps/web build`
5. `.env.example` + `scripts/neon-setup.sh` (wraps `npx -y neonctl@latest`: auth → `projects create --name fluidbox` → dev branch → prints the **DIRECT** connection string). ✓ dry-run help
6. `deploy/docker-compose.dev.yml` + `deploy/litellm/config.yaml`: LiteLLM pinned to a known-clean release (never PyPI 1.82.7/1.82.8), Anthropic passthrough model config, virtual key, usage callback target, private network. ✓ `docker compose up litellm` + `curl /health`
7. CI: fmt, `clippy -Dwarnings`, test, `cargo sqlx prepare --check`, web build. ✓ local run
8. Provision Neon via the script; DIRECT `DATABASE_URL` into `.env`. ✓ `select 1` over it

Tool installs as needed: `cargo install sqlx-cli --no-default-features --features rustls,postgres`, `brew install just`. Also: check crates.io/GitHub for `fluidbox` name collisions; note the result in the README.

**Converges by:** the repo *is* the end-state shape from the first commit — including the gateway as a first-class deploy component, not a later retrofit.

### M1 — The governed vertical slice (each step individually verifiable)
1. `fluidbox-core`: domain types (incl. **RunSpec** w/ autonomy mode, agent-revision types, capability-bundle refs), state machine, event schema + Redactor, usage/cost types (minimal pricing table for the fallback path only), policy schema + `evaluate()` incl. autonomy resolution. ✓ `cargo test -p fluidbox-core` (allow/deny/approval/path/shell/budget cases + autonomous rewrite: RequireApproval → fallback, both original & rewritten verdicts surfaced)
2. Migration `0001_init.sql` (schema incl. `agent_revisions`, frozen `run_spec`, `append_event()`) + `fluidbox-db` repos + listener + seeds (default tenant, `policies/*.yaml`, one seeded agent definition + revision: the curated Claude runner). ✓ db test: 3 appends → seq 1..3 + NOTIFY received
3. Server skeleton: config, dual-token auth middleware, health routes. ✓ curl 200/401
4. Sessions + agents/revisions + policies CRUD, events page, `policies/validate`; creating a session freezes the RunSpec (incl. autonomy mode) from the chosen revision; autonomous requests against a policy with `autonomy.permitted: false` → 403. ✓ curl create → `created` w/ frozen `run_spec`; editing an agent appends a revision (mutating one → 409); bad YAML → 422
5. SSE stream + hub (notify wakeup + seq catch-up + Last-Event-ID). ✓ two-terminal test
6. `DockerProvider`: network modes, launch/wait/reap, and the workspace-init phase (`initializing` state: materialize + base commit before the runner starts; remote repos fetched control-plane-side with the stored token), diff capture. ✓ stub-image test; patch of a modified file; bad repo URL fails during `initializing` with zero model spend
7. Sandbox runner image (Dockerfile + `index.mjs` implementing the runner contract). ✓ `just sandbox-build`; contract exercised against a stub control endpoint
8. Internal gateway routes (permission w/ policy + approval-wait + idempotency; ingest; heartbeat; result). ✓ curl allow/deny shapes
9. Model gateway wiring: Rust session facade (`/internal/llm/*` — auth, budget stop, verbatim streaming to LiteLLM) + `POST /internal/llm-usage` callback ingestion → `usage_entries` + cost. ✓ **Gateway gate:** an Agent SDK smoke run through the full chain — streaming, tool use, prompt caching, adaptive thinking, `count_tokens` — with usage & cost (incl. cache tokens) landing correctly in the fluidbox ledger. Gate fails on the pinned release → flip `LLM_UPSTREAM_URL` to direct Anthropic + enable facade tee-metering, file the issue, retry LiteLLM at the next pin.
10. Orchestrator end-to-end. ✓ **Acceptance demo A:** `fluidbox run --agent claude-fixer --repo <repo w/ failing test> --task "find and fix the failing test"` → `completed`, diff artifact, cost report
11. Approval path (risky-tool policy). ✓ **Acceptance demo B:** risky tool → `awaiting_approval` → approve from inbox → continues; deny + timeout auto-deny also tested. ✓ **Acceptance demo C (autonomous):** `fluidbox run --autonomous …` against the same risky-tool policy → completes with zero human interaction; the risky tool is auto-denied (policy fallback), the ledger shows the original RequireApproval verdict + the autonomous rewrite, and the agent routes around the denial or finishes degraded — never hangs
12. Budgets + crash/orphan handling. ✓ `max_tool_calls: 2` → `budget_exceeded`; cost budget exhausted mid-run → facade refuses the next model call + graceful stop; kill runner → `failed` + reaped; restart server → orphan reaped on boot
13. Dashboard — shaped like the north-star UX: **agents registry** (definitions + revision history, editor) · **"New Run" flow** (pick agent → repo → task prompt → budgets inherited-or-tightened → run) · sessions list · session detail (live timeline, approval banner, artifacts w/ diff viewer, cost card, cancel) · approvals inbox · policies YAML editor w/ validate · settings. ✓ full demo from the UI
14. `just dev` one-command up (server + web + LiteLLM) + README quickstart + docs (architecture, north star, runner contract, security). ✓ fresh clone → `.env` → `just dev` → demos A & B from CLI **and** dashboard

**Converges by:** M1 *is* the north star with n=1 everywhere — one harness, one curated runner, one built-in capability bundle, Docker as the one provider — but the registry, revisions, RunSpec freeze, gateway, and "New Run" UX are the real, final structures. Later milestones only increase n.

### M2 — Lambda MicroVM provider + BYOC (headline)
`LambdaMicrovmProvider` (aws-sdk-lambdamicrovms or SigV4 REST; image pipeline S3 zip → snapshot; in-VM supervisor serving lifecycle hooks + exec/files API; JWE refresh inside `EndpointHandle`; 8h lease + checkpoint/rollover in the orchestrator), Terraform BYOC module, S3 workspace/artifact store, credential broker. **Long-running autonomous agents get their full substrate here:** lease rollover carries a session past the 8-hour MicroVM cap, and idle-suspend/resume (snapshot billing only while parked) makes days-long agents economical.

**Converges by:** delivers the execution substrate the product promises, strictly behind the M1 `ExecutionProvider` seam — agent definitions gain a "runs on: docker | lambda-microvm" choice; nothing above the trait changes. The M1 autonomy mode + M2 rollover/suspend together are what "deploying long-running agents" means in production. The M1 workspace-init phase ports as-is: same `initializing` state, archive push instead of bind mount.

### M3 — Multi-harness + capability catalog (completes the north star)
- **Codex runner:** second first-party runner image (Codex via `codex mcp-server` driven by rmcp, or the TS Codex SDK as payload — whichever survives its own gateway/contract gate), registered as a selectable harness; OpenAI key custody moves into the same LiteLLM gateway.
- **Capability-bundle catalog:** tool/MCP bundles as first-class registry objects with credential brokering (Vault/SM); UI to attach bundles to agent revisions and narrow them per-run; every MCP call policy-gated like any tool.
- **Customer-built agents:** signed, versioned runner images implementing the runner contract — the "bring your own agent" endgame, gated on image signature + pinned digest.
- CMA self-hosted Rust worker + native Rust Messages-API loop as additional harness adapters; layered deny-wins policy merge.

**Converges by:** this is the milestone where the north star's "select Claude or Codex, pick your tool/MCP bundles, provide a prompt, we run it" sentence is true verbatim.

### Roadmap — integrations & triggers (descoped from MVP, 2026-07-09)
GitHub App (manifest flow) + webhook ingress (octocrab; HMAC via hmac/sha2/subtle; delivery-GUID idempotency), trigger router (PR opened / `/agent` comment / failed check_run), fork-PR read-only trust tier, Checks + PR-comment result writers; then Slack/Jira/Linear triggers, SSO/RBAC. Seams already in place from M1: trigger jsonb, trust_tier, event-ingress module boundary — a trigger only *creates a run of a registered agent*, so nothing about the run model changes when this lands. Until then, "Connect GitHub" = a stored fetch token consumed by the workspace-init phase.

## 8. Verification

- Per-step verifies above; the three acceptance demos (A: agent fixes a failing test, diff+cost delivered; B: supervised approval pause/resume; C: autonomous run — zero human interaction, risky tool auto-denied per policy, full ledger) plus the **gateway gate** (M1 step 9) are the MVP bar — run from CLI and dashboard on a fresh clone via `just dev`.
- `cargo test --workspace` (policy engine, db, state machine, RunSpec freeze immutability), `cargo clippy -Dwarnings`, `pnpm build`; CI green.
- Security spot-checks: the sandbox env contains no real provider key (only the session token); a hardened-mode container cannot reach the internet **or LiteLLM directly** (`curl` fails) but reaches the control plane; the ledger contains no raw prompts or secrets (Redactor tests).
- Convergence check at each milestone close: re-read §2's invariants — any violation (a mutable agent config, a harness detail in core, a sandbox with direct gateway/provider access) blocks the milestone.

## 9. Risks & mitigations

1. **Neon LISTEN/NOTIFY fragility** (scale-to-zero, pooler) → notify = wakeup only, seq query = truth, direct connection, keepalive, polling floor. *(designed in)*
2. **Approval wait vs restarts** → DB-backed rows + idempotent tool_call_id + runner retry + hard timeout. *(designed in)*
3. **Egress lockdown vs control-plane reachability** → two documented network modes; hardened mode for demos. *(designed in)*
4. **LiteLLM fidelity & supply chain** → pin a known-clean release (PyPI 1.82.7/1.82.8 shipped malware — never those); the gateway gate blocks M1 sign-off (Agent SDK has a documented 403 failure mode through proxies; native-route spend tracking was $0 until #26248; cache tokens were mispriced when streaming); LiteLLM reachable only on the private network; `LLM_UPSTREAM_URL` + in-tree tee-metering keep direct-Anthropic passthrough a one-line fallback.
5. **Usage-callback loss** (LiteLLM → fluidbox webhook drops) → callback ingestion is idempotent by LiteLLM call id; a reconciliation sweep flags sessions with model traffic but missing usage entries; budget sweeper treats missing usage as spend-unknown (conservative).
6. **Agent SDK drift** → all SDK coupling confined to the pinned Node runner; the server speaks its own stable internal contract; runner smoke test.
7. Watch-list: bollard/sqlx API churn; `fluidbox` name collision (checked in M0); Anthropic price drift (owned by LiteLLM's catalog; fallback table in `core`); binary diffs (size cap); Codex MCP interface is experimental (pin; TS-SDK runner as fallback).

## 10. Open decision points (deliberately deferred to implementation)

1. `fluidbox-core` policy engine — the shell-command risk classifier (which prefixes/regexes are allow vs approve vs deny): a security-posture judgment call.
2. Approval timeout semantics beyond the MVP default (10 min → deny): escalate? notify? per-policy configurable?
3. Default budget numbers for the seed policy (wall-clock / tokens / USD): a cost-appetite call.
4. LiteLLM callback transport — generic webhook vs a minimal custom callback: decided empirically at M1 step 9, whichever delivers per-call usage (incl. cache tokens) most reliably.
5. Long-run budget semantics for autonomous agents — total caps (M1) vs rolling windows ($/day, tokens/hour): a cost-appetite + safety call once real long-running workloads exist.
