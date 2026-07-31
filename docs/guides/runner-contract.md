# Building a harness

A **harness** is an agent framework running inside a sandbox. fluidbox ships
two — the Claude Agent SDK and Codex — and adding a third is a first-class
extension point rather than a fork.

You need two things:

1. A **runner image** that implements the HTTP contract below.
2. **One arm** in the server's harness registry (image and model defaults, plus
   any per-harness environment extras).

That registry is deliberately a plain match statement, not a trait registry or
a plugin SDK. There is no `Harness` trait. The seam is small on purpose.

---

## The contract

Five endpoints. All on the `/internal` plane.

| Call | Audience | Purpose |
| --- | --- | --- |
| `POST /internal/sessions/{id}/permission` | `tool` | Ask before every tool call |
| `POST /internal/sessions/{id}/tools/call` | `tool` | Invoke a brokered tool |
| `POST /internal/sessions/{id}/events` | `control` | Report timeline events |
| `POST /internal/sessions/{id}/heartbeat` | `control` | Report liveness |
| `POST /internal/sessions/{id}/result` | `control` | Report the final outcome |
| `GET /internal/sessions/{id}/workspace` | `workspace` | Fetch the workspace archive |
| `POST /internal/llm/{rest}` | `llm` | Model requests, via the facade |

### Four tokens, not one

Your runner receives **four** audience-scoped tokens. Route each to the calls
above. A mismatch returns:

```json
{ "error": "wrong_audience" }
```

with status `403`. **Key your fatal abort on that exact string.** It is the one
deliberately stable machine code in the API, and the reason is instructive: an
older runner that treats a `403` as a generic denial will keep looping while
model spend continues. Abort loudly instead, and put a diagnostic on the
timeline.

On Kubernetes the four tokens arrive as one Secret with four keys, routed per
container — the init container sees only the `workspace` key.

**Delete the token from the environment before spawning any child process.**
Both shipped runners do this. It does not cover a same-uid child reading
`/proc/<pid>/environ` for the runner's *initial* environment; that is a
disclosed limit, not a solved problem.

---

## The permission call

This is the one that matters. Every tool the agent wants to run goes through
it, and the answer is authoritative.

```http
POST /internal/sessions/{id}/permission
Authorization: Bearer <tool-audience token>
Content-Type: application/json

{
  "tool_call_id": "toolu_01ABC",
  "tool": "Bash",
  "input": { "command": "cargo test -p fluidbox-core" }
}
```

The request **blocks** while a human decides. Do not time it out aggressively;
do retry on transport failure. Retries are safe — decisions are idempotent by
`(session_id, tool_call_id)`, so a retry after a restart re-attaches to the
pending row rather than creating a second approval.

### Canonicalization is your job

Names and shapes crossing `/permission` must use the canonical vocabulary:

| Tool | Shape |
| --- | --- |
| `Bash` | `{ command }` |
| `Edit`, `Write`, `MultiEdit` | `{ file_path }` or `{ edits[].file_path }` |
| `Read`, `Glob`, `Grep`, `LS` | — |
| `mcp__<server>__<tool>` | brokered or sandbox MCP |

Whatever your framework calls these natively, translate them **runner-side**.
The gate matches policy rules against these names, so an untranslated name is a
policy that silently does not apply.

### Interception is harder than it looks

A caution learned the expensive way: a framework callback named something like
`canUseTool` is **not necessarily an interception point**. In the Claude Agent
SDK, that callback is turned into a permission-prompt tool that the CLI
consults only for calls it independently decides to *ask* about — so ordinary
tool calls flowed with zero gate consultations.

The fix there was a `PreToolUse` hook that answers "ask" for everything, which
forces every call through the callback.

**Verify empirically.** Run a real workload and count `tool.requested` events
against the tool calls in the transcript. If the numbers disagree, your
interception point is wrong, and the failure mode is silent.

---

## Brokered tools

Auto-allow brokered `mcp__*` calls in your own permission callback and dispatch
them to `/tools/call`. That is not a shortcut — the broker runs the **identical
gate** server-side, so gating them twice would only add latency.

```http
POST /internal/sessions/{id}/tools/call

{ "tool_call_id": "toolu_02XYZ",
  "tool": "mcp__issues__create_issue",
  "input": { "title": "Flaky test" } }
```

The response deliberately splits protocol convention from audit truth: every
definitive outcome renders `ok: true` with any error surfaced inside `result`
(the MCP convention, so the model sees a tool error it can react to), while the
ledger records the real success or failure.

Dispatch is wrapped in a durable execution claim keyed
`(session_id, tool_call_id, input_digest)`. A reused id with *different*
arguments is a new claim, never an adoption. Only a state that carries positive
proof nothing was sent is re-claimable; a definitive upstream response is
terminal.

---

## Model requests

Point your framework's base URL at `/internal/llm` and use the `llm` token as
its API key.

For the Claude Agent SDK that is `ANTHROPIC_BASE_URL` and `ANTHROPIC_API_KEY`.
**The sandbox's API key literally is its session token** — there is no real
provider credential inside a sandbox.

The facade validates the token, enforces the budget stop, swaps in the real
upstream credential, forwards to the gateway, and tees the streamed response to
meter usage. It dispatches on the run's harness, speaking the Anthropic
Messages dialect or the OpenAI Responses dialect as appropriate — so if your
harness speaks a third dialect, that is the file to extend.

Handle `429` (budget exhausted) by stopping cleanly and reporting a result.

---

## Lifecycle

1. Fetch the workspace archive (Kubernetes init container; digest-verified and
   credential-free) or use the bind-mounted copy at `/workspace`.
2. Start the agent loop.
3. Heartbeat throughout. A run that stops heartbeating is reaped by the
   watchdog.
4. Stream events as they happen.
5. `POST /result` exactly once when finished.

**The server is the single status writer.** Your runner reports; it never
writes status. `POST /result` reports an outcome and the server decides the
terminal state from it.

---

## Reuse what exists

`images/runner-lib/` already implements the contract client plus the broker and
sandbox gate shims, and both shipped runners share it. Start there rather than
reimplementing the HTTP layer — the audience routing, retry behaviour, and
abort semantics are exactly the parts that are easy to get subtly wrong.

## Registering the harness

Add one arm to the harness registry in the server: identifier validation, image
and model defaults, and any per-harness environment extras. Nothing about your
harness should leak into the core domain crate — the seams exist precisely so
that nothing above them has to change.
