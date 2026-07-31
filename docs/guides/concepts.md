# Concepts

The object model, in the order you meet it. Each of these is a real API
object; none of them is decorative. If you only read one page before
integrating, read this one — the most common mistakes are all vocabulary
mistakes.

## Agent → revision

An **agent** is a stable identity: a name and a history. Everything that
defines behavior — harness, model, **system prompt**, policy reference,
budget ceilings, capability pins, connection requirements, default
workspace — lives on a **revision**, and revisions are **append-only**.
"Editing" an agent means appending a revision; nothing is ever mutated, so a
run's record always points at exactly the configuration that governed it.

Two prompts, deliberately distinct:

- the **system prompt** is on the revision — *who the agent is*;
- the **task** arrives per run — *what to do this time*.

Conflating them is the most common modelling mistake. See
[Agents & revisions](./agents.md).

## Policy

A **policy** decides every tool call: `allow`, `deny`, or `approve` (pause
for a human). Policies are versioned and append-only like agents; the
Governance page is the authoring surface, and every publish is an immutable
version with an author and a summary. Budgets on a policy are a **ceiling**
— a revision or a run may only tighten them. See [Policies](./policies.md)
and [the permission gate](./governance.md).

## Run and RunSpec

A **run** (the API calls it a *session*) is one governed execution. At
creation, fluidbox freezes an immutable **RunSpec**: the agent revision's
model and system prompt, a **full policy snapshot**, the resolved workspace,
the effective budgets, the exact tool surface (sandbox schemas and brokered
bindings), and the invocation context. The run is judged against that
snapshot for its whole life — editing the agent or the policy affects only
*future* runs. This is the property that makes the audit trail worth having:
a record cannot be retroactively made to look compliant.

See [Runs & the timeline](./runs.md).

## The timeline (the ledger)

Every run streams an append-only event timeline: tool requests, verdicts,
approvals, usage, lifecycle transitions. Events carry a **gapless
per-session sequence number**, which makes streaming resumable
(`Last-Event-ID`) and polling exact. The ledger only accepts **redacted**
events — model prompts never reach it, only digests, usage, and cost; the
type system enforces this (an unredacted event is unrepresentable at the
storage boundary).

## Approvals

When the verdict is `approve`, the run pauses (`awaiting_approval`) until a
human decides — once, for the session, or deny. Decisions are idempotent by
`(session_id, tool_call_id)`; an unanswered approval expires to **deny**
(human absence narrows permissions, never widens them). Autonomous mode does
not bypass any of this: the `approve` verdict is rewritten to the policy's
fallback *inside* the engine, and both verdicts are recorded. See
[Approvals](./approvals.md).

## Budgets

Cost (USD), tokens, wall-clock, and tool calls, frozen per run. Model usage
is **measured, not estimated** — the LLM facade meters the streamed response
as it passes through and enforces the stop server-side. A run that hits a
budget ends `budget_exceeded`, and the spend that ended it is in the ledger.

## Capabilities and connections

Tools beyond the built-in file/shell vocabulary come in exactly two classes,
and the split *is* the security model:

- **Sandbox** MCP servers: stdio subprocesses packaged in the runner image.
  Credential-free by construction, contained by the container. They ride
  versioned **capability bundles**, pinned `name@version` on the revision.
- **Brokered** MCP servers: called **by the control plane**, never from the
  sandbox. The credential lives in a **connection** (org-owned or personal);
  a revision declares a **connection requirement** (*what* it needs, never
  *whose* credential), and run creation resolves it to a frozen per-run
  **binding**.

Attach ≠ allow: pins and bindings say what *exists* for a run; the
[permission gate](./governance.md) decides every call. See
[Capabilities](./capabilities.md).

## Triggers, schedules, deliveries

A **trigger subscription** lets something other than a human start runs: an
API call with a subscription-scoped token, a **schedule** (a subscription
with a clock — exactly-once firing), or a connected-service **event** (a
GitHub pull request). Results leave through **deliveries**: signed,
retrying webhooks and GitHub comments/checks, decoupled from the run so a
dead receiver can never mutate one. See [Triggers & schedules](./triggers.md).

## Workspaces

A run's working tree. `local_copy` copies a path; `git_repository` fetches
through a connection's credential — **control-plane-side, before the agent
exists**. The sandbox only ever sees a bind-mounted copy at `/workspace`;
the original repository is never touched, and the workload needs no network
egress.

## The four planes

One HTTP surface, four audiences, four credentials — mixing them up is the
most common integration mistake. The [API overview](./api.md) spells them
out; the short version: your code talks to `/v1`, only the in-sandbox runner
talks to `/internal`, `/v1/admin` is break-glass, and `/v1/ingress` is
authenticated by webhook signature.

## Where to go next

- [Getting started](./getting-started.md) — a governed run in five minutes
- [Runs & the timeline](./runs.md) — the lifecycle in detail
- [Security model](./security.md) — why the sandbox holds no secrets
