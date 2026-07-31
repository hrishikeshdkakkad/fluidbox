# Quickstart

Get a governed run — one that actually pauses for your approval — in about five
minutes.

## Prerequisites

- Docker (a container runtime for the sandbox and the local database)
- Rust and pnpm
- An `ANTHROPIC_API_KEY`, if you want a live agent rather than a replay

## 1. Bootstrap

```bash
just setup     # idempotent: .env + secrets, web env, pnpm install, runner image
just doctor    # preflight — validates every environment gotcha and prints the fix
```

`just doctor` is worth reading rather than skimming. It catches the
configuration mistakes that otherwise cost an hour, most notably:

- **`FLUIDBOX_BIND` must be `0.0.0.0:8787`, not loopback.** Sandboxes reach the
  control plane through `host.docker.internal`, which resolves to the host's
  gateway address. A loopback bind is unreachable from inside a container.
- **The model key lives only in the gateway container**, injected from `.env`.
  The control plane never holds it. Adding the key needs no server restart —
  just `just gateway-up`.

## 2. Start the stack

```bash
just db-up      # local Postgres on 127.0.0.1:5433
just gateway-up # the pinned model gateway container
just dev        # gateway + control plane + dashboard
```

Migrations run automatically on boot, so a fresh database volume needs no
provisioning step.

## 3. Register an agent

```bash
curl -sX POST "$FLUIDBOX_URL/v1/agents" \
  -H "Authorization: Bearer $FLUIDBOX_ADMIN_TOKEN" \
  -H 'content-type: application/json' \
  -d '{
        "name": "fixer",
        "system_prompt": "You fix failing tests. Change as little as possible.",
        "model": "claude-haiku-4-5",
        "policy": "default",
        "budgets": { "max_cost_usd": 2.5, "max_wall_clock_secs": 1800 }
      }'
```

Two things to note in that body:

- `system_prompt` is **who the agent is** and lives on the revision. The
  **task** is separate and comes per run.
- `policy: "default"` names the governance rules. The run will freeze a full
  snapshot of that policy, so editing it later will not change this run.

## 4. Start a run

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

`local_copy` copies the path. **The original repository is never touched** —
the credentialed fetch and the copy both happen control-plane-side, and the
agent only ever sees a bind-mounted copy at `/workspace`.

## 5. Watch the timeline

```bash
curl -N "$FLUIDBOX_URL/v1/sessions/$RUN/events/stream" \
  -H "Authorization: Bearer $FLUIDBOX_ADMIN_TOKEN"
```

The stream is resumable: send `Last-Event-ID` with the last `seq` you processed
and delivery continues exactly where it stopped. Under the hood a database
notification is only a wakeup — the `seq` catch-up query is the delivery source
of truth, which is what makes both polling and streaming exact about each
other.

## 6. Approve something

When the agent reaches a tool call the policy will not auto-allow, the run
enters `awaiting_approval` and an `approval.requested` event appears.

```bash
ID=$(curl -s "$FLUIDBOX_URL/v1/approvals" \
  -H "Authorization: Bearer $FLUIDBOX_ADMIN_TOKEN" | jq -r '.approvals[0].id')

curl -sX POST "$FLUIDBOX_URL/v1/approvals/$ID/decision" \
  -H "Authorization: Bearer $FLUIDBOX_ADMIN_TOKEN" \
  -H 'content-type: application/json' \
  -d '{"decision":"approved_once"}'
```

`approved_once` allows this single call; `approved_session` allows that tool
for the rest of the run; `denied` returns a tool error to the model, which
usually causes it to try a different approach rather than give up.

Decisions are idempotent by `(session_id, tool_call_id)` and settled by a
compare-and-swap, so a double-submit produces exactly one decision.

## 7. Read the result

```bash
curl -s "$FLUIDBOX_URL/v1/sessions/$RUN"           -H "Authorization: Bearer $FLUIDBOX_ADMIN_TOKEN" | jq .session.status
curl -s "$FLUIDBOX_URL/v1/sessions/$RUN/cost"      -H "Authorization: Bearer $FLUIDBOX_ADMIN_TOKEN"
curl -s "$FLUIDBOX_URL/v1/sessions/$RUN/artifacts" -H "Authorization: Bearer $FLUIDBOX_ADMIN_TOKEN"
```

Cost is measured, not estimated — usage is teed off the streaming model
response by the facade as it passes through.

---

## The same thing from the CLI

```bash
cargo run -p fluidbox-cli -- run \
  --agent fixer \
  --task "Fix the failing test in crates/fluidbox-core." \
  --repo "$PWD"
```

It reads `FLUIDBOX_API_URL` and `FLUIDBOX_ADMIN_TOKEN` from the environment,
starts the run, and follows the timeline. Other subcommands:

```bash
fluidbox sessions            # recent runs
fluidbox get <id>            # status and usage
fluidbox watch <id>          # follow a live timeline
fluidbox approvals           # pending approvals
fluidbox approve <id>        # add --session to allow for the whole run
fluidbox deny <id>
fluidbox connections
fluidbox agents
```

---

## Next

- [Authentication](./authentication.md) — which of the four credentials you
  actually want
- [The permission gate](./governance.md) — what the agent is allowed to do, and
  in what order that is decided
- [Triggers](./triggers.md) — invoke runs from an API call, a clock, or a pull
  request
