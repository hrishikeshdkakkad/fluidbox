# Approvals

The pause in the middle of a run. When the [permission gate](./governance.md)
resolves a tool call to `approve`, the run enters `awaiting_approval`, an
`approval.requested` event appears on the timeline, and the tool call blocks
until a human decides — or the approval expires.

## Decide

```bash
ID=$(curl -s "$FLUIDBOX_URL/v1/approvals" \
  -H "Authorization: Bearer $FLUIDBOX_ADMIN_TOKEN" | jq -r '.approvals[0].id')

curl -sX POST "$FLUIDBOX_URL/v1/approvals/$ID/decision" \
  -H "Authorization: Bearer $FLUIDBOX_ADMIN_TOKEN" \
  -H 'content-type: application/json' \
  -d '{"decision":"approved_once"}'
```

Three decisions:

| Decision | Effect |
| --- | --- |
| `approved_once` | This single call proceeds. The next matching call asks again. |
| `approved_session` | Calls in this approval's **scope** are allowed for the rest of the run. |
| `denied` | The tool call returns an error to the model — which usually tries a different approach rather than giving up. |

`GET /v1/approvals` lists everything pending;
`GET /v1/sessions/{id}/approvals` scopes to one run. The dashboard's
attention strip is the same data.

## Scope — how far one "yes" reaches

`approved_session` remembers by **scope key**, not blanket tool name where
that would over-grant: for `Bash` the key is the *matched command prefix*
(approving `git push` covers `git push`, not all shell); for other tools it
is the tool name. The policy chooses `once` or `session` as the default
scope per rule, and can override the TTL per rule too — see
[Policies](./policies.md).

## Idempotency — safe to double-click, safe across restarts

Decisions are idempotent by `(session_id, tool_call_id)` and settled by a
compare-and-swap: a double-submit, two reviewers racing, or a retried HTTP
call produce **exactly one** decision, and everyone else sees the settled
answer. The database row is the source of truth — if the control plane
restarts mid-pause, the runner's retry re-attaches to the pending row;
nothing duplicates and nothing hangs.

## Expiry — absence narrows, never widens

An unanswered approval expires after the policy's TTL (per-rule overridable)
and the expiry action is **deny**. There is no configuration in which
nobody-was-watching results in more permission than somebody-said-yes.

## Autonomous runs — rewritten, not bypassed

With `autonomous: true`, a run never waits on a human: an `approve` verdict
is rewritten to the policy's fallback (`autonomy.on_approval_rule`, or the
rule's own `on_autonomous` override) **inside the policy engine**, and the
ledger records *both* the original and the rewritten verdict. The permission
callback stays wired in every mode — there is no bypass flag anywhere in the
system, so the audit trail for an autonomous run reads exactly like a
governed one, minus the human.

## What an approval can never do

Two hard floors sit **above** approvals in the gate:

- **Fork-PR trust tier.** A run triggered by a pull request from a fork is
  frozen read-only. No approval widens it — reads only, no writes, no
  execution, no egress.
- **Frozen tool surface.** A tool that wasn't in the run's frozen
  capability set (or whose brokered binding has gone stale) is denied at the
  availability stage; approval is never consulted.

## Who may decide

Single-admin deployments: the operator. Multi-user deployments
(`FLUIDBOX_REQUIRE_SSO`): role-based — with one deliberate exception. A
brokered call riding a **personal** connection is decidable **only by the
owner who invoked the run** — no role, admin, or operator override, approve
*or* deny. Your credential, your call.

## Next

- [The permission gate](./governance.md) — where `approve` verdicts come from
- [Runs & the timeline](./runs.md) — the events around the pause
- [Triggers & schedules](./triggers.md) — approvals on machine-started runs
