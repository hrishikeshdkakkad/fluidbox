# Agents & revisions

An agent is a stable name with an append-only history. Every property that
shapes behavior lives on a **revision**; a run always uses the *latest*
revision at creation and freezes it into the RunSpec. Nothing here is ever
edited in place — that is what keeps last month's audit trail meaningful.

## What lives on a revision

| Field | Meaning |
| --- | --- |
| `harness` | Which agent runtime executes the run — `claude` (Claude Agent SDK) or `codex`. Each is a separate runner image behind one contract. |
| `model` | The model requests are routed to (via the gateway; the sandbox never holds a provider key). |
| `system_prompt` | Who the agent **is**. The per-run **task** is deliberately not here. |
| `policy` | The governance rules by name. Each run freezes a full snapshot of the policy's latest version. |
| `budgets` | Ceilings for cost, tokens, wall-clock, tool calls. May only tighten the policy's ceilings; a run may tighten further. |
| `capability_bundles` | Sandbox tool bundles, pinned exactly (`name@version`). Naming a bundle without a version pins the newest *as of that moment* — nothing floats afterwards. |
| `connection_requirements` | Brokered tools the agent needs: per slot, a connector, the required tool names, and whether the binding resolves to the invoking user's or the organization's connection. Requirements name *what*, never *whose credential*. |
| `default_workspace` | Where runs check out from when the run doesn't say otherwise. |

## Create an agent

```bash
curl -sX POST "$FLUIDBOX_URL/v1/agents" \
  -H "Authorization: Bearer $FLUIDBOX_ADMIN_TOKEN" \
  -H 'content-type: application/json' \
  -d '{
        "name": "fixer",
        "harness": "claude",
        "model": "claude-haiku-4-5",
        "system_prompt": "You fix failing tests. Change as little as possible.",
        "policy": "default",
        "budgets": { "max_cost_usd": 2.5, "max_wall_clock_secs": 1800 }
      }'
```

This creates the agent *and its first revision*. The response's
`agent.id` and the name are interchangeable in URLs.

## Change an agent — append a revision

`POST /v1/agents/{id}/revisions` is the only way to change behavior.
**Omitted fields inherit from the latest revision**; an explicit empty array
clears a list (that is how you drop every capability pin, and how a bundle
upgrade lands — re-resolving `"name"` pins the newest version as of now).

```bash
# Swap the model; everything else carries over.
curl -sX POST "$FLUIDBOX_URL/v1/agents/fixer/revisions" \
  -H "Authorization: Bearer $FLUIDBOX_ADMIN_TOKEN" \
  -H 'content-type: application/json' \
  -d '{ "model": "claude-sonnet-5" }'
```

In-flight runs are unaffected — they are governed by the snapshot they froze
at creation. The next run picks up the new revision.

## Inspect

```bash
curl -s "$FLUIDBOX_URL/v1/agents" -H "Authorization: Bearer $FLUIDBOX_ADMIN_TOKEN"
curl -s "$FLUIDBOX_URL/v1/agents/fixer" -H "Authorization: Bearer $FLUIDBOX_ADMIN_TOKEN"
```

The detail response carries the agent plus its full revision history —
useful for answering "what configuration did revision 3 actually have?"
without archaeology.

## Declaring brokered tools

A revision that needs a credentialed tool (say, a hosted MCP server)
declares a requirement rather than embedding anything secret:

```json
{
  "connection_requirements": [
    {
      "slot": "issue-tracker",
      "connector": { "url": "https://mcp.example.com/mcp", "slug": "example" },
      "required_tools": ["create_issue", "search"],
      "binding_mode": "organization"
    }
  ]
}
```

At run creation each requirement resolves to a concrete **binding** against
a live connection — fail-closed: every `required_tools` entry must exist in
the connection's photographed tool snapshot, or the run is refused before
any model spend. `binding_mode: "invoking_user"` resolves to the invoking
user's personal connection instead of the organization's.

## Practical notes

- **Name things for the audit trail.** `fixer`, `reviewer`, `triager` read
  well in a ledger; `test-agent-2` does not.
- **The task is not a prompt-engineering surface for identity.** If you find
  yourself re-sending the same instructions in every task, they belong on
  the revision's system prompt.
- Agent names travel in URLs; keep them to the safe set (letters, digits,
  `.`,`_`,`-`).

## Next

- [Runs & the timeline](./runs.md) — starting and observing work
- [Capabilities](./capabilities.md) — sandbox bundles and brokered connections
- [Policies](./policies.md) — authoring the rules a revision names
