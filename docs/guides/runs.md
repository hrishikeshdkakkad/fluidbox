# Runs & the timeline

A run is one governed execution of an agent: an immutable specification, a
fresh sandbox, a live event timeline, and a terminal record with a diff and
a cost report. The API calls runs *sessions*; the two words mean the same
object.

## Start a run

```bash
RUN=$(curl -sX POST "$FLUIDBOX_URL/v1/sessions" \
  -H "Authorization: Bearer $FLUIDBOX_ADMIN_TOKEN" \
  -H 'content-type: application/json' \
  -d '{
        "agent": "fixer",
        "task": "Fix the failing test in crates/fluidbox-core.",
        "workspace": { "kind": "local_copy", "path": "'"$PWD"'" }
      }' | jq -r .session.id)
```

- `agent` — name or id; the run uses the agent's **latest revision**.
- `task` — what to do *this time* (the system prompt lives on the revision).
- `workspace` — optional; falls back to the revision's default:
  - `{"kind":"scratch"}` — an empty directory;
  - `{"kind":"local_copy","path":"/abs/path"}` — copies the path. The
    original is never touched;
  - `{"kind":"git_repository","connection_id":"…","repository":"acme/widgets","ref":"main"}`
    — fetched **control-plane-side** through the connection's credential,
    before the agent exists. The sandbox sees a bind-mounted copy at
    `/workspace` and needs no network egress.
- `autonomous: true` — no human in the loop: `approve` verdicts are
  rewritten to the policy's fallback *inside* the engine (both verdicts
  recorded). A policy may forbid autonomy outright.

## What freezes at creation

The **RunSpec**: the revision's model and system prompt, the task, a **full
policy snapshot**, the resolved workspace, the effective budgets (policy ∩
revision ∩ run — tightening only), the exact tool surface (sandbox tool
schemas and brokered bindings with their tool snapshots), and the invocation
context (who or what started this run). Everything the run is judged by is
in that snapshot; nothing that happens later can rewrite it.

## The lifecycle

`initializing` (workspace prepared control-plane-side) → `running` →
`awaiting_approval` (paused on a human decision, possibly repeatedly) → one
of four terminal states: `completed`, `failed`, `cancelled`,
`budget_exceeded`. The **server is the single status writer** — the runner
only reports; a crashed sandbox is noticed by the heartbeat watchdog, a
stuck run by the wall-clock sweeper.

```bash
curl -sX POST "$FLUIDBOX_URL/v1/sessions/$RUN/cancel" \
  -H "Authorization: Bearer $FLUIDBOX_ADMIN_TOKEN"
```

## Follow the timeline

Streaming:

```bash
curl -N "$FLUIDBOX_URL/v1/sessions/$RUN/events/stream" \
  -H "Authorization: Bearer $FLUIDBOX_ADMIN_TOKEN"
```

Every event carries a **gapless per-session `seq`**. The stream is
resumable — reconnect with `Last-Event-ID: <last seq>` and delivery
continues exactly where it stopped. Under the hood a database notification
is only a wakeup; the sequence catch-up query is the delivery source of
truth, so polling and streaming are exact about each other:

```bash
curl -s "$FLUIDBOX_URL/v1/sessions/$RUN/events?after=42" \
  -H "Authorization: Bearer $FLUIDBOX_ADMIN_TOKEN"
```

The vocabulary you will see, in the order a governed tool call produces it:

| Event | Meaning |
| --- | --- |
| `tool.requested` | The agent asked to use a tool (arguments digested, never stored raw). |
| `tool.decision` | The gate's verdict — allow, deny, or "ask a human" — with its source (budget, capability, schema, trust tier, policy, approval). |
| `approval.requested` / `approval.decided` | The pause and the human (or expiry) decision. |
| `tool.brokered` | A control-plane-executed tool call completed: latency and a result digest, never payloads. |
| usage events | Metered model usage as the facade tees the stream. |

Prompts and file contents never appear — the ledger only accepts redacted
events, and that is enforced by construction, not convention.

## Read the outcome

```bash
curl -s "$FLUIDBOX_URL/v1/sessions/$RUN"           -H "Authorization: Bearer $FLUIDBOX_ADMIN_TOKEN" | jq .session.status
curl -s "$FLUIDBOX_URL/v1/sessions/$RUN/cost"      -H "Authorization: Bearer $FLUIDBOX_ADMIN_TOKEN"
curl -s "$FLUIDBOX_URL/v1/sessions/$RUN/artifacts" -H "Authorization: Bearer $FLUIDBOX_ADMIN_TOKEN"
```

Artifacts include the workspace **diff** — what the agent actually changed,
reviewable before anything leaves the machine. Cost is **measured, not
estimated**: usage is teed off the streaming model response by the facade as
it passes through, and the same numbers back the budget stop.

## Runs started by machines

API triggers, schedules, and connected-service events all converge on the
same creation path and freeze the same RunSpec — with the invocation context
recorded (which subscription, which delivery, which actor). See
[Triggers & schedules](./triggers.md). Results can be delivered outward by
signed, retrying webhooks — decoupled from the run, so a dead receiver never
affects one.

## Next

- [Approvals](./approvals.md) — the pause in the middle
- [The permission gate](./governance.md) — how each `tool.decision` is made
- [API overview](./api.md) — credentials, errors, and the full surface
