# Triggers, schedules & signed results — a cookbook

"Borrow the agent, on demand": any external circumstance — an API call, a cron tick, a webhook — can start a run of a registered agent and get the outcome delivered back, signed. Every entry point converges on the same governed run path (frozen RunSpec, policy gate, budgets); a trigger never widens what an agent may do.

All examples assume `API=http://127.0.0.1:8787` and `H="authorization: Bearer $FLUIDBOX_ADMIN_TOKEN"`.

## 1. Create a subscription

```bash
curl -s -X POST $API/v1/triggers -H "$H" -H "content-type: application/json" -d '{
  "agent": "claude-fixer",
  "name": "incident-investigator",
  "task_template": "Investigate {{ticket}} and write a report.",
  "autonomous": true,
  "callback_url": "https://ops.example.com/fluidbox-callback"
}'
```

The response is the **only** time two secrets appear — store both:

```json
{
  "subscription": { "id": "…", "…": "…" },
  "token": "fbx_trig_…",           // invoke credential, scoped to THIS subscription
  "callback_secret": "fbx_whsec_…" // HMAC key for verifying result deliveries
}
```

Useful create-time fields: `budgets` (tighten below the policy ceiling), `workspace` (a default `git_repository`/`local_path`/`scratch` workspace), `pinned_revision_id` (pin a revision; default = latest at run time), `concurrency_policy` (`allow` default | `skip_if_running` | `replace`), `capabilities` (a remove-only keep-list of the revision's capability bundles). `callback_url` requires `FLUIDBOX_CREDENTIAL_KEY` on the server (the secret is sealed at rest).

**Trigger tokens are subscription-scoped**: they can invoke their one subscription and poll the runs it created — never the admin API. The admin token, conversely, cannot invoke. Rotate with `POST /v1/triggers/{id}/rotate_token` (revokes all live tokens, returns one new one).

## 2. Invoke it

```bash
curl -s -X POST $API/v1/triggers/$SUB_ID/invoke \
  -H "authorization: Bearer fbx_trig_…" -H "content-type: application/json" \
  -H "Idempotency-Key: incident-4711" \
  -d '{"context": {"ticket": "INC-4711"}}'
```

```json
{ "session_id": "…", "status": "queued", "replay": false,
  "poll_url": "/v1/triggers/…/runs/…" }
```

- `context` values (strings/numbers/bools only) fill the `{{key}}` slots in the task template.
- `Idempotency-Key`: same key + same body → the same run is returned (`"replay": true`); same key + different body → `422`. Retry-safe by construction.
- Caller overrides are **opt-in per subscription and off by default**: with `allow_task_override` you may send `task`; with `allow_workspace_override` you may send `workspace: {repository, ref, commit_sha}` — which can only *narrow* within the subscription's authority (never a new connection or clone URL).
- With `concurrency_policy: skip_if_running`, an invoke while a previous run is still active returns **409** (`skipped: run … is still active`).

Poll the outcome with the same trigger token:

```bash
curl -s $API/v1/triggers/$SUB_ID/runs/$SESSION_ID -H "authorization: Bearer fbx_trig_…"
```

## 3. Put it on a clock

A schedule is not a new object — it's the same subscription with a `schedule` block:

```bash
curl -s -X POST $API/v1/triggers -H "$H" -H "content-type: application/json" -d '{
  "agent": "claude-fixer",
  "name": "nightly-deps-audit",
  "task_template": "Audit dependencies and open a report.",
  "autonomous": true,
  "concurrency_policy": "skip_if_running",
  "schedule": { "cron": "0 3 * * *", "timezone": "America/Los_Angeles",
                "missed_run_policy": "skip" }
}'
```

- `cron` is standard 5-field (a 6/7-field form with seconds exists for tests).
- Firing is **exactly-once** — a deterministic claim row per fire time makes restarts and racing workers safe.
- `missed_run_policy`: `skip` (default) records one skip row for a gap (server down, subscription disabled); `catch_up` fires exactly **one** make-up run — never one per missed tick.
- `concurrency_policy` is enforced for ALL invocation paths, not just the scheduler.
- `POST /v1/triggers/{id}/disable` / `/enable` pause and resume; a disabled schedule does not advance, and re-enabling goes through the missed-run policy.

## 4. Verify signed result deliveries

When a run reaches a terminal state, subscriptions with a `callback_url` get a POST:

| Header | Value |
|---|---|
| `x-fluidbox-event` | `run.finished` |
| `x-fluidbox-delivery` | delivery UUID — **dedup on this** (delivery is at-least-once) |
| `x-fluidbox-timestamp` | unix seconds |
| `x-fluidbox-signature` | `v1=<hex hmac-sha256(secret, "{timestamp}.{body}")>` |

Verification (constant-time compare in real code):

```python
import hmac, hashlib
def verify(secret: str, ts: str, body: bytes, header: str) -> bool:
    mac = hmac.new(secret.encode(), f"{ts}.".encode() + body, hashlib.sha256)
    return hmac.compare_digest(f"v1={mac.hexdigest()}", header)
```

Pinned test vector (also asserted in the server's tests): secret `fbx_whsec_test`, timestamp `1752000000`, body `{"a":1}` → `v1=b519ceca5a07a724c2e3aef9decbc4420a5cd7f303bfdf1a28a8c2b63625aa72`. Reject stale timestamps to bound replay.

The body carries `run` (id, status, task, summary, invocation, timestamps), `usage` (tokens, cost_usd, tool_calls), and `artifacts` (including the diff). Failed deliveries retry `5s → 30s → 2m → 10m → 30m → 1h` (6 attempts); a dead receiver can never affect the run itself. Inspect attempts at `GET /v1/sessions/{id}/deliveries`.

## 5. Event-driven runs (GitHub)

Webhook-driven runs ride the same subscription object: pass `connection` (a GitHub connection id) instead of `schedule`, plus optional `repositories` (`["owner/name"]`), `events` (default `opened`+`reopened`; `synchronize` is an explicit opt-in — it fires per push), and `publish` (`["pr_comment"]` default, `"check"` available). The create response then includes the `ingress_path` to configure as the webhook URL; the webhook signature against the connection's sealed secret is the authentication. Fork PRs are frozen to a read-only trust tier with no approval escape. Connect GitHub itself from the dashboard's Integrations page (the seamless GitHub App flow).
