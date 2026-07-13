# Capabilities: giving agents MCP tools, safely

A **capability bundle** is a versioned, append-only registry object describing MCP tools an agent may call. There are exactly **two tool classes**, and the split is the security model:

| Class | Runs where | Credentials |
|---|---|---|
| `sandbox` | stdio subprocess **inside** the sandbox, packaged in the runner image | none by construction — contained by the container |
| `brokered` | called **by the control plane** on the sandbox's behalf | a sealed credential that **never enters a sandbox** |

A brokered call is the same inversion as the LLM facade and git fetch: the sandbox asks, the control plane holds the secret and executes. Either way, **every MCP call passes the same permission gate as Bash/Edit** — attaching a bundle makes tools *available*, never *allowed*.

All examples assume `API=http://127.0.0.1:8787` and `H="authorization: Bearer $FLUIDBOX_ADMIN_TOKEN"`.

## The easy path: the connector catalog

`GET /v1/catalog` lists known connectors (Notion, Sentry, …). Connecting auto-registers the bundle:

```bash
# api_key connector: paste the key, get a connection + photographed bundle back
curl -s -X POST $API/v1/catalog/fx-sentry/connect -H "$H" \
  -H "content-type: application/json" -d '{"token": "sntrys_…"}'

# oauth connector: returns {connection, authorize_url} — open the URL, approve,
# the callback completes the connection and photographs the bundle
curl -s -X POST $API/v1/catalog/fx-notion/connect -H "$H" \
  -H "content-type: application/json" -d '{}'
```

A rejected api_key rolls the connection back; nothing half-connected survives. Custom entries can be added with `POST /v1/catalog` (they're forced to `tier=custom` — catalog data is reference data, not trust).

## The explicit path: publish a bundle yourself

**Brokered** — point at a streamable-HTTP MCP server; tools are **discovered** (photographed via `tools/list`), never declared:

```bash
# 1. a connection custodies the credential, audience-bound to base_url
KBCONN=$(curl -s -X POST $API/v1/connections -H "$H" -H "content-type: application/json" -d '{
  "provider": "mcp_http", "base_url": "https://mcp.example.com",
  "token": "secret-upstream-token",
  "header_name": "authorization", "scheme": "Bearer"
}' | jq -r .connection.id)

# 2. publishing photographs the server's tools at THIS moment
curl -s -X POST $API/v1/capabilities -H "$H" -H "content-type: application/json" -d '{
  "name": "knowledge-base",
  "servers": [{ "class": "brokered", "name": "kb",
                "url": "https://mcp.example.com/mcp", "connection_id": "'$KBCONN'" }]
}'
```

(`scheme` also supports `"Basic"` — paste `email:api_token` as the token — and `""` for a bare-token header; `auth_kind: "oauth"` starts the PKCE dance instead of pasting a secret.)

**Sandbox** — a stdio server that ships in the runner image; tools are **declared**, with schemas:

```bash
curl -s -X POST $API/v1/capabilities -H "$H" -H "content-type: application/json" -d '{
  "name": "workspace-tools",
  "servers": [{ "class": "sandbox", "name": "ws",
    "command": "node", "args": ["/opt/fluidbox-runner/servers/workspace-info.mjs"],
    "tools": [{ "name": "workspace_file_count",
                "description": "Count files in the workspace",
                "input_schema": {"type":"object","properties":{},"additionalProperties":false} }]
  }]
}'
```

Re-publishing the same `name` appends the next version — the registry is append-only, like agents.

## Attach, pin, narrow

Bundles attach to **agent revisions** and are **pinned at attach time**:

```bash
curl -s -X POST $API/v1/agents -H "$H" -H "content-type: application/json" -d '{
  "name": "kb-reporter", "policy": "default",
  "capability_bundles": ["knowledge-base", "workspace-tools@1"]
}'
```

- `"name"` resolves to the newest version **at that moment**, then pins it; `"name@N"` pins explicitly. Nothing ever floats — upgrading = appending a new revision.
- On `POST /v1/agents/{id}/revisions`: omit `capability_bundles` to inherit the previous revision's pins; `[]` clears them; a new list re-resolves (the upgrade path).

Narrowing is **remove-only**, by bundle name, via the `capabilities` field in two places — the intersection of revision pins ∩ subscription keep-list ∩ per-run keep-list is what the run gets:

```bash
# a trigger subscription that keeps only one of the revision's bundles
… -d '{ "agent": "kb-reporter", "name": "reporter-sub", "capabilities": ["workspace-tools"] }'
# a single run that strips all MCP tools
curl -s -X POST $API/v1/sessions -H "$H" -H "content-type: application/json" \
  -d '{ "agent": "kb-reporter", "task": "…", "capabilities": [] }'
```

## What the run actually gets (and why drift can't hurt you)

At run creation the RunSpec freezes the pinned versions **plus full tool-schema snapshots and digests**. At the gate, every `mcp__<server>__<tool>` call is checked against that frozen set *before* trust tier and policy — a tool that drifted upstream or was rug-pulled since registration is **denied** (`source=capability`), not silently forwarded. Brokered calls are decided and executed server-side (one decision per call — the sandbox can't self-approve), and the ledger records `tool.requested → tool.decision → tool.brokered` with latency and result digests, never payloads or secrets. Read-only trust tier (fork PRs) strips capabilities entirely.
