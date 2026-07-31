# API overview

One HTTP surface at `/v1`, JSON in and out, designed so that the credential
you hold determines exactly what you can reach — and so that a record exists
for everything you do with it.

## Base URL and credentials

Local development serves the API at `http://127.0.0.1:8787`. Four planes,
four credentials:

| Plane | Base path | Who calls it | Credential |
| --- | --- | --- | --- |
| Public API | `/v1` | your code, the CLI, the dashboard | admin token, personal token (`fbx_pat_…`), or browser session |
| Runner contract | `/internal` | only the in-sandbox runner | audience-scoped session token |
| Operator | `/v1/admin` | break-glass tooling | admin token only |
| Ingress | `/v1/ingress` | GitHub and other services | webhook signature |

Bearer credentials ride the standard header:

```bash
curl -s "$FLUIDBOX_URL/v1/sessions" \
  -H "Authorization: Bearer $FLUIDBOX_ADMIN_TOKEN"
```

Single-admin deployments use the admin token everywhere. Multi-user
deployments confine it to `/v1/admin/*` and authenticate people via OIDC
browser sessions or personal API tokens — [Authentication](./authentication.md)
walks the decision. **Trigger tokens** are narrower still: scoped to invoke
exactly one subscription and poll the runs it created.

## Errors — one shape, everywhere

```json
{ "error": "agent not found" }
```

Status codes mean what they say (`400` invalid body, `401` missing or bad
credential, `403` authenticated but not allowed, `404`, `409` conflict —
idempotency and concurrency collisions). One deliberately stable machine
code exists: `wrong_audience`, returned when a sandbox token is used outside
its audience; runners key their fatal abort on that exact string.

## A complete exchange

Create an agent once:

```bash
curl -sX POST "$FLUIDBOX_URL/v1/agents" \
  -H "Authorization: Bearer $FLUIDBOX_ADMIN_TOKEN" \
  -H 'content-type: application/json' \
  -d '{
        "name": "reviewer",
        "system_prompt": "You review diffs for correctness and security.",
        "policy": "default"
      }'
```

Start a run and read the response:

```bash
curl -sX POST "$FLUIDBOX_URL/v1/sessions" \
  -H "Authorization: Bearer $FLUIDBOX_ADMIN_TOKEN" \
  -H 'content-type: application/json' \
  -d '{ "agent": "reviewer", "task": "Review the diff on branch fix/timeouts." }'
```

```json
{
  "session": {
    "id": "0198f2…",
    "status": "initializing",
    "agent_id": "0198e1…",
    "task": "Review the diff on branch fix/timeouts.",
    "autonomy": "governed",
    "created_at": "2026-07-30T12:00:00Z"
  }
}
```

Follow it — stream or poll, both exact:

```bash
# Server-sent events; resumable with Last-Event-ID: <seq>
curl -N "$FLUIDBOX_URL/v1/sessions/$RUN/events/stream" \
  -H "Authorization: Bearer $FLUIDBOX_ADMIN_TOKEN"

# The same ledger, by sequence number
curl -s "$FLUIDBOX_URL/v1/sessions/$RUN/events?after=0" \
  -H "Authorization: Bearer $FLUIDBOX_ADMIN_TOKEN"
```

Decide an approval when the run pauses:

```bash
curl -sX POST "$FLUIDBOX_URL/v1/approvals/$ID/decision" \
  -H "Authorization: Bearer $FLUIDBOX_ADMIN_TOKEN" \
  -H 'content-type: application/json' \
  -d '{"decision":"approved_once"}'
```

```json
{ "approval": { "id": "0198f3…", "status": "approved_once" } }
```

Writes are safe to retry: approval decisions are idempotent by
`(session_id, tool_call_id)`, trigger invocations by idempotency key, and
webhook redeliveries heal partial fan-outs instead of duplicating runs.

## The reference

- **[Operation index](/docs/api/reference)** — every endpoint across the
  four planes, generated from the OpenAPI description.
- **[Schemas & examples](/docs/api.html)** — the full Redoc reference with
  request/response schemas.
- **[`openapi.yaml`](/docs/openapi.yaml)** — the raw OpenAPI 3.1 document;
  feed it to a generator or an agent.

The description is linted in CI against the same rules the reference is
built with — when the Rust surface changes, the spec changes in the same
commit or the build goes red.

## Next

- [Authentication](./authentication.md) — choosing and minting credentials
- [Triggers & schedules](./triggers.md) — machine-invoked runs, signed results
- [Runs & the timeline](./runs.md) — the event vocabulary in detail
