# fluidbox architecture

This is the reader's guide to how fluidbox works: how a run flows, why the security model looks the way it does, and where the system is designed to be extended. The authoritative design document — north star, milestones, and the full rationale — is [`PLAN.md`](../PLAN.md); this document is the distilled tour.

## The shape of the system

fluidbox is a Rust workspace with a strict dependency order:

```
fluidbox-core  →  fluidbox-db / fluidbox-provider  →  fluidbox-server
                                                       ↑
fluidbox-cli (thin reqwest client) ────────────────────┘
```

- **`fluidbox-core`** — pure domain, no I/O. The policy engine, the session state machine, the canonical event schema and redaction types, `RunSpec` and autonomy rules, and the extension traits. Domain rules change here, and the tests live here.
- **`fluidbox-db`** — sqlx repositories against Postgres (Neon), embedded migrations, `LISTEN/NOTIFY`.
- **`fluidbox-provider`** — sandbox lifecycles. Today: `DockerProvider` (bollard). `SandboxHandle` is serializable jsonb, so a control-plane restart can reattach to running sandboxes.
- **`fluidbox-server`** — one binary wiring several planes together (below).
- **`images/`** — the sandbox workloads: runner images for each agent harness. This is the only place non-Rust code is sanctioned; the runner is *payload*, not backend.

The Next.js dashboard (`apps/web`) is presentation-only. Every decision it displays was made by the Rust API.

## How a run flows

1. **Create.** All entry points — dashboard, CLI, API trigger, webhook, schedule — converge on one code path (`run_service::create_run`). It resolves the agent's current revision, intersects sandbox capability pins, resolves each declared connection requirement to a concrete per-run binding, and **freezes an immutable `RunSpec`**: model, system prompt, task, a full policy snapshot, sandbox tool schemas, brokered surfaces (each backed by a frozen connection binding), budgets, and the invocation context. In-flight runs are governed by their snapshot; editing an agent or policy only affects future runs. This immutability is what makes the audit trail trustworthy.
2. **Initialize.** The orchestrator prepares the workspace **control-plane-side**: the credentialed git fetch/copy happens before the agent exists. The sandbox will only ever see a bind-mounted copy at `/workspace` — the original repo is never touched, and the sandbox needs no network egress.
3. **Provision.** A fresh sandbox is created from the harness's runner image. It receives a per-session token — notably disguised as its `ANTHROPIC_API_KEY` — and the address of the control plane. No real credentials.
4. **Execute.** The agent harness runs inside the sandbox and speaks the **runner contract** over HTTP to the internal gateway: every tool call goes to `/permission`, message streams to `/events`, liveness to `/heartbeat`, and the outcome to `/result`. Model calls go to the LLM facade, which meters usage and enforces the budget stop before forwarding upstream.
5. **Decide.** Each tool call passes the single decision gate: budget → frozen capability availability → trust tier → policy → approvals. A `RequireApproval` verdict pauses the tool call until a human decides (idempotent by `(session_id, tool_call_id)`, safe across restarts) — or, in autonomous mode, is rewritten to the policy's fallback *inside* the evaluator, with both verdicts recorded.
6. **Finish.** The **server is the single status writer** — the runner only reports. On terminal entry the orchestrator enqueues result deliveries (HMAC-signed callbacks, GitHub comment/check publishing) in the same transaction funnel, so a dead receiver can never mutate a run. The run ends with a diff, a cost report, and the complete event ledger.

Background workers cover the failure modes: a heartbeat watchdog, a wall-clock budget sweeper, approval expiry, and a boot-time orphan reap.

## The three planes of `fluidbox-server`

| Plane | Auth | Who talks to it |
|-------|------|-----------------|
| **`/v1` public API** | admin bearer token | dashboard, CLI |
| **`/internal` gateway** | per-session token | only the in-sandbox runner |
| **`/internal/llm` facade** | the session token (as the sandbox's API key) | the harness's model client |

Trigger tokens are a fourth, narrower authority: subscription-scoped, sha256-hashed, able to invoke exactly one subscription and poll the runs it created — never the admin API. The admin token, conversely, can never invoke a trigger. Webhook ingress is deliberately unauthenticated as an endpoint; the signature against the connection's sealed secret *is* the authentication, and nothing is stored before it verifies.

Under multi-user mode (`FLUIDBOX_REQUIRE_SSO`, Phase B) the `/v1` public API additionally authenticates browser sessions (`__Host-fbx_web` cookie) and personal API tokens (`fbx_pat_`) with per-organization RBAC, and the admin bearer token is confined to the `/v1/admin/*` break-glass surface; single-admin mode is otherwise unchanged.

## The security model

A few load-bearing invariants explain most of the design:

- **Frozen `RunSpec`s, append-only agents.** Nothing that governed a run can be mutated after the fact. Editing an agent appends a revision; editing a policy bumps a version. Audit is only meaningful because of this.
- **Credentials never enter a sandbox.** The same inversion appears everywhere: the LLM facade swaps in the real provider key (held only by the LiteLLM gateway container); git fetch credentials pass via ephemeral `GIT_CONFIG_*` env vars control-plane-side; brokered MCP tools are executed *by the control plane* with credentials sealed at rest (AEAD, `FLUIDBOX_CREDENTIAL_KEY`).
- **The ledger only accepts redacted events.** The `Redacted<EventEnvelope>` type is constructible solely via the redactor, so model prompts *cannot* reach the database — only digests, usage, and cost. A SQL function assigns a gapless per-session sequence; SSE fanout uses NOTIFY as a wakeup but the sequence catch-up query as the delivery source of truth.
- **Capabilities are exactly two tool classes, and the split is the security model.** *Sandbox* MCP servers are stdio subprocesses packaged in the runner image — credential-free by construction, contained by the container; they ride versioned capability bundles pinned to an agent revision. *Brokered* MCP servers are called by the control plane behind the same decision gate; their credential lives in a **connection** that an agent revision *requires* and a run *binds* to at creation (bundles no longer carry brokered tools). Attach ≠ allow: the frozen set — pinned bundles plus resolved bindings — says what *exists* for a run; the gate decides every call, rechecking each brokered binding's status, authorization generation, and owner membership before touching the credential.
- **One decision gate, shared by both paths.** `/permission` (sandbox-side tools) and the broker endpoint (control-plane tools) run the identical check. The permission callback stays wired in every autonomy mode — never the SDK's bypass.
- **Fork PRs are read-only.** A PR whose head repo differs from the base (or is hidden) freezes `TrustTier::ReadOnly`, enforced above policy and approvals — no approval can escape it.
- **Webhook retries heal, never duplicate.** Two DB-unique dedup levels (per-delivery, per-dispatch) bound to the session insert in one transaction make redelivery idempotent across the whole fan-out.

## Triggers, schedules, and connected services

Connected-service events ride one provider-ignorant spine: ingress → verify → normalize → match → `create_run` → publish. All GitHub-specific knowledge lives in one connector module behind a plain dispatch match — adding a provider means adding a module, not threading a new concept through the core. A schedule is not a new object either: it's a trigger subscription with a clock, fired through the same `create_run` with a deterministic idempotency claim for exactly-once semantics.

## Extension seams

Two seams are designed so that nothing above them changes (`PLAN.md` §6.2):

- **New execution backend** → implement the `ExecutionProvider` trait (`fluidbox-core/src/traits.rs`). The planned AWS Lambda MicroVM provider is the next one; `SandboxHandle`'s serializability exists for exactly this.
- **New agent harness** → a new runner image implementing the HTTP runner contract (`/permission`, `/events`, `/heartbeat`, `/result`, the broker shim, the canonical tool vocabulary) plus one arm in the `harness.rs` registry. Two harnesses exist today — Claude Agent SDK (`images/sandbox-runner`) and Codex (`images/codex-runner`) — sharing `images/runner-lib`. The LLM facade dispatches per-harness between the Anthropic Messages and OpenAI Responses dialects.

Both registries are deliberately plain `match` statements, not trait-object plugin systems: with a handful of variants, greppability beats indirection.

## Verifying the whole thing

`just check` is the unit bar (fmt, clippy `-D warnings`, tests, dashboard build). `scripts/e2e.sh` (`just e2e`) is the acceptance bar: it boots the real stack and drives a live agent demo, governance verdicts, approval pause/resume, git workspaces, API triggers, schedules, a faked GitHub for the full PR fan-out path, the capability catalog, connector OAuth against a local authorization server, and the failure paths. The GitHub test seams (`FLUIDBOX_GITHUB_API_URL`, `FLUIDBOX_GITHUB_CLONE_BASE`) let all of that run with no public URL and no real GitHub.
