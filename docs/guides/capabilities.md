# Capabilities: giving agents MCP tools, safely

There are exactly **two tool classes**, and the split is the security model:

| Class | Runs where | Credentials | Plumbing |
|---|---|---|---|
| `sandbox` | stdio subprocess **inside** the sandbox, packaged in the runner image | none by construction — contained by the container | a **capability bundle** attached to an agent revision |
| `brokered` | called **by the control plane** on the sandbox's behalf | a sealed credential that **never enters a sandbox** | a **connection** (owns the credential + a tool snapshot) that an agent **requires** and a run **binds** |

A brokered call is the same inversion as the LLM facade and git fetch: the sandbox asks, the control plane holds the secret and executes. Either way, **every MCP call passes the same permission gate as Bash/Edit** — making a tool *available* is never making it *allowed*.

Brokered tools used to ride capability bundles too. As of Phase C they don't: a brokered tool now flows through four independent objects — **connector definition** (catalog reference data, no credential) → **connection** (one credential grant, owning an append-only tool snapshot) → agent **connection requirement** (what an agent needs, never whose credential) → per-run **resource binding** (whose connection executes, frozen at run creation). `capability_bundles` survives **only for sandbox tools**. Trying to publish a brokered server into a bundle is refused (see [Sandbox bundles](#sandbox-bundles-the-surviving-role-of-capability_bundles)).

All examples assume `API=http://127.0.0.1:8787` and `H="authorization: Bearer $FLUIDBOX_ADMIN_TOKEN"`.

## The easy path: the connector catalog

`GET /v1/catalog` lists known connectors (Notion, Sentry, …). Connecting creates a **connection** and photographs its tools into an append-only **snapshot** — no bundle:

```bash
# api_key connector: paste the key, get a connection + photographed snapshot back
curl -s -X POST $API/v1/catalog/fx-sentry/connect -H "$H" \
  -H "content-type: application/json" -d '{"token": "sntrys_…"}'

# oauth connector: returns {connection, go_url} — open go_url (a control-plane
# page that binds your browser to the one-time flow, then redirects to the
# provider's consent screen); approve, and the callback completes + photographs
curl -s -X POST $API/v1/catalog/fx-notion/connect -H "$H" \
  -H "content-type: application/json" -d '{}'
# (the raw path POST /v1/connections/{id}/oauth/start likewise returns {go_url})
```

> **An OAuth connect needs an https `FLUIDBOX_PUBLIC_URL`.** The `go_url` page binds
> your browser to the one-time flow with a `__Host-fbx_oauth_flow` cookie, and the
> callback refuses without it. Browsers reject `__Host-` cookies that are not
> `Secure`, so on a stock local deployment (`FLUIDBOX_PUBLIC_URL=http://127.0.0.1:8787`)
> the consent screen completes but the callback fails — in a **real browser**. Put the
> control plane behind https (an ngrok/Cloudflare tunnel is enough locally) and set
> `FLUIDBOX_PUBLIC_URL` to that https origin *before* starting the dance; it is also
> what the provider's `redirect_uri` must match. (`curl` ignores the `__Host-` prefix
> rule, which is why the e2e suites drive the same flow over http.) Two more reasons
> the https origin matters: an authorization server can only fetch the CIMD client
> document over https + non-loopback (local deployments always fall back to DCR), and
> many providers reject an `http://` redirect_uri outright.

A rejected api_key rolls the connection back; nothing half-connected survives. Custom entries can be added with `POST /v1/catalog` (they're forced to `tier=custom`, **tenant-scoped**, and adding one needs admin/owner — catalog data is reference data, not trust; one org's custom row is never visible or bindable to another).

### Ownership

Every connection has an owner. `POST /v1/connections` and the catalog Connect flows take `"owner": "organization"` (the default — visible to every member, mutable by admin/owner) or `"owner": "personal"` (owned by the signed-in user, **visible and mutable only to them** — other members, and admins acting through their own lens, get a 404, never a 403; the admin token has no personal identity and cannot own one). A personal connection's authority is tied to its owner's active membership: deactivating the member is the kill switch — every credentialed use rechecks it live (below).

## Inspect and refresh a connection's tools

The photograph is connection-specific: two users connected to the same URL may legitimately see different tools (accounts, plans, scopes differ). Read the current snapshot, or re-photograph on demand:

```bash
curl -s $API/v1/connections/$CONN/tools -H "$H"            # GET  — latest snapshot (version, tools, digest)
curl -s -X POST $API/v1/connections/$CONN/tools/refresh -H "$H"   # POST — append a new snapshot
```

Snapshots are **append-only** and force a real MCP `initialize`, so each records the negotiated protocol version; a `tools/list` that never finishes paginating **fails** rather than freezing a partial set. A refresh appends a new version — it never mutates an in-flight run's frozen tools.

**Reauthorization bumps the generation.** Reconnecting an OAuth connection that was ever activated increments its `authorization_generation` (a rotation *within* the same account does not; proving a *different* account cannot preserve the generation — fail closed). Runs bound to the old generation then refuse at call time with `connection … was reauthorized after this run started — its binding is stale`. If you see that, the connection was re-consented mid-run: start a new run, which binds the current generation. (GitHub App connections never bump — the installation identity is proven, not re-consented.)

## Declare what an agent needs: connection requirements

An agent revision declares the brokered connections it needs — by **slot**, connector, required tools, and **binding mode** — never by connection id:

```bash
curl -s -X POST $API/v1/agents -H "$H" -H "content-type: application/json" -d '{
  "name": "kb-reporter", "policy": "default",
  "connection_requirements": [{
    "slot": "kb",
    "connector": { "url": "https://mcp.example.com/mcp", "slug": "knowledge-base" },
    "required_tools": ["search_docs", "get_page"],
    "binding_mode": "invoking_user"
  }]
}'
```

- `binding_mode: "invoking_user"` binds the **invoking user's own** active personal connection at run time; `"organization"` binds an org connection (the only mode available to schedules and webhooks — no interactive user exists there).
- **Satisfaction is `all`, fail-closed:** every name in `required_tools` must exist in the selected connection's current snapshot, or binding fails at run creation — *before* model spend or sandbox provisioning. The run surface is exactly the required set; it is never silently narrowed to an intersection.
- On `POST /v1/agents/{id}/revisions`: omit `connection_requirements` to inherit the previous revision's; `[]` clears them. Requirements live on the revision (append-only, like the system prompt); a run uses the current revision's.

## What a run binds

At run creation the binding service resolves **every** requirement to a concrete, authorized, active connection whose snapshot covers the required tools, and freezes one `run_resource_binding` row per slot **before** provisioning. The RunSpec's brokered surfaces reference those binding ids — never a raw connection id. Binding slots are typed `mcp | workspace_fetch | result_publish`, each resolving to a tagged authority: `connection | subscription_secret | none` (`none` is an explicit credentialless decision — e.g. a public repo fetch — never a missing value).

An interactive caller may pin an `mcp` slot explicitly instead of by mode:

```bash
# bind the "kb" slot to a specific connection for this one run
curl -s -X POST $API/v1/sessions -H "$H" -H "content-type: application/json" -d '{
  "agent": "kb-reporter", "task": "…",
  "bindings": { "kb": "'$CONN'" }
}'
```

fluidbox verifies the caller may use that connection (tenant, ownership/visibility, requirement satisfaction, active status, snapshot coverage). Explicit bindings may pin only `mcp` slots — `workspace_fetch` and `result_publish` are server-derived — and a key that names an unknown slot is rejected. Any unresolvable or ambiguous requirement fails the run before it provisions; nothing runs half-bound.

## Sandbox bundles (the surviving role of `capability_bundles`)

A **sandbox** server ships in the runner image; its tools are **declared**, with schemas, into a versioned append-only bundle:

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

Publishing a **brokered** server here is refused — `brokered server '…' can no longer be published in a capability bundle — brokered tools are now connection requirements + snapshots` — that path is the connection/requirement/binding flow above.

Bundles attach to **agent revisions** and are **pinned at attach time**:

```bash
… -d '{ "name": "kb-reporter", "policy": "default",
        "capability_bundles": ["workspace-tools", "other@1"] }'
```

- `"name"` resolves to the newest version **at that moment**, then pins it; `"name@N"` pins explicitly. Nothing floats — upgrading = appending a new revision. Omit `capability_bundles` on a new revision to inherit; `[]` clears.
- Narrowing is **remove-only**, by bundle name, via the `capabilities` field on a subscription or a single run — the intersection of revision pins ∩ subscription keep-list ∩ per-run keep-list is what the run gets. A per-run `"capabilities": []` strips all sandbox bundles.

## What the run actually gets (and why drift can't hurt you)

At run creation the RunSpec freezes the resolved brokered surfaces (each carrying its binding id, snapshot version, tool set, and digest) **plus** the pinned sandbox bundles' full schemas and digests. At the gate, every `mcp__<server>__<tool>` call is checked against that frozen set *before* trust tier and policy — a tool that drifted upstream or was rug-pulled since the photograph is **denied** (`source=capability`/`source=binding`), never silently forwarded. For a brokered call the broker additionally **rechecks the binding immediately before touching the credential**: the connection must still be active, still on the frozen `authorization_generation`, and (for a personal connection) its owner's membership still active — any failure denies the call. The decision and execution happen server-side (the sandbox can't self-approve), and the ledger records `tool.requested → tool.decision → tool.brokered` with latency and result digests, never payloads or secrets.

Two boundaries worth knowing:

- **Approving a brokered call under a personal connection is the owner's alone.** No role — approver, admin, owner, or the operator — may approve or deny a call that executes under another user's personal connection, and only on a run that user invoked. (Unattended personal delegation is omitted in v1.)
- **Legacy revisions are refused after the cutover.** A revision still pinning a bundle that carries a brokered server predates Phase C; creating a run from it fails with `capability server '…' is brokered — this revision predates connection requirements (Phase C); append a new revision`. The 0013 migration converts affected agents automatically (appending a converted revision and repointing pinned subscriptions); this error only reaches an explicitly pinned pre-conversion revision. **After upgrading, refresh each connection's tools once** (`POST /v1/connections/{id}/tools/refresh`) — the migration does not rediscover (that needs network + credentials), so a converted connection has no trustworthy snapshot until you re-photograph it.

Read-only trust tier (fork PRs) strips all MCP tools — brokered and sandbox — from the frozen set entirely.
