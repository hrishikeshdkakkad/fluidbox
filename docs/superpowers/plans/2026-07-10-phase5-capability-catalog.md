# Phase 5 — Capability & MCP catalog (design doc §3.6/§5.3/§8/§10/§12)

**Date:** 2026-07-10 · **Research input:** `docs/research/2026-07-10-mcp-ecosystem-findings.md`
**§17 settles (user, 2026-07-10):** #7 = **pin-only** (attach resolves latest → stores the
exact pin; upgrade = append an agent revision; no floating refs). #4 = **explicitly
deferred** past Phase 5 (the brokered gateway ships now, proven on MCP; the git-write op
list settles at its own boundary).

## Framing (non-negotiable)

Capabilities are the LAST of the four optional run inputs. EXACTLY two tool classes —
the split IS the security model:

1. **Sandbox tools** — stdio MCP servers packaged in the runner image; launched inside
   the sandbox; credential-free by construction; contained by the sandbox.
2. **Brokered tools** — remote (streamable-http) MCP servers executed BY THE CONTROL
   PLANE; the sealed credential turns server-side (fourth instance of the inversion:
   LLM facade, git fetch, webhook verify, now tool broker). A credential never enters a
   sandbox.

No arbitrary lifecycle hooks. **Attach ≠ allow**: a bundle makes a tool AVAILABLE; the
permission gate judges every call. Authority = intersection (connection ∩ bundles ∩
subscription ∩ trust tier ∩ policy); narrowing REMOVES, never adds.

**Photograph rule:** bundle registration photographs tool schemas (brokered: discovered
via `tools/list`; sandbox: declared). `create_run` freezes the stored snapshot + digests
into the RunSpec. Nothing re-discovers mid-run; the gate denies any `mcp__*` call outside
the frozen set (drift/rug-pull = visible deny). Research-driven hardening: snapshot-time
lint (ANSI/zero-width/control chars), server-alias collision rejection, annotations
stored as untrusted display hints, credential audience-binding (connection base_url).

## Decision record (implementation choices)

- **Brokered flow (one decision per call, always server-side):** the runner's
  `canUseTool` auto-allows brokered `mcp__*` tools WITHOUT calling `/permission` — the
  broker endpoint runs the identical gate (same `tool_call_id`, same approvals
  machinery, same ledger events) before executing. A malicious runner skipping
  `canUseTool` changes nothing: the broker gates regardless. Sandbox + built-in tools
  keep the existing `canUseTool → /permission` path. The permission callback stays wired
  (never `bypassPermissions`).
- **Brokered execution is at-least-once** under network failure (like result
  deliveries); the shim does not blind-retry after a request was sent; every attempt is
  ledgered.
- **ReadOnly trust tier strips capabilities at freeze** (fork PRs get zero MCP surface);
  the gate's read-only allowlist denies `mcp__*` anyway (belt + braces).
- **Credentials:** new connection flavor `provider="mcp_http"` (display_name, base_url,
  bearer token → sealed). Broker refuses to send the credential to a URL outside the
  connection's base_url (audience binding). Unauthenticated brokered servers need no
  connection.
- **Runner transport for brokered tools:** a tiny stdio MCP server in the image
  (`broker-shim.mjs`, @modelcontextprotocol/sdk low-level API) advertises the frozen
  tools verbatim and forwards `tools/call` → `POST /internal/sessions/{id}/tools/call`
  with the session token. Harness-agnostic: a future Codex runner reuses it unchanged.
- **Manifest transport:** `FLUIDBOX_CAPABILITIES` env (JSON of frozen servers) — frozen
  at launch like everything else; no new GET endpoint.

## Files

### 1. `migrations/0006_capability_bundles.sql`
```sql
create table capability_bundles (
    id uuid primary key,
    tenant_id uuid not null references tenants(id),
    name text not null,
    version int not null,
    description text,
    definition jsonb not null,        -- CapabilityBundleDef (validated, snapshots inside)
    definition_digest text not null,  -- sha256 over canonical definition
    created_at timestamptz not null default now(),
    unique (tenant_id, name, version) -- append-only: publish = new version row
);
-- Subscription narrowing: optional keep-list of bundle NAMES (null = all attached).
alter table trigger_subscriptions add column capability_bundles jsonb;
```

### 2. `fluidbox-core/src/capability.rs` (new) + `lib.rs` export
Types: `BundleRef{id,name,version}`, `ServerIdentity{name,version,registry_type,identifier,digest}`
(all optional provenance), `ToolSnapshot{name,description,input_schema,annotations}`,
`CapabilityServer` = `Sandbox{name,command,args,identity,tools}` |
`Brokered{name,url,connection_id,identity,tools}` (serde tag `class`),
`CapabilityBundleDef{servers}`, `FrozenBundle{id,name,version,definition_digest,servers}`.
Functions (pure, unit-tested): `validate()` (server alias `^[a-z0-9][a-z0-9-]{0,63}$` —
no underscores so `mcp__srv__tool` parses unambiguously; tool names spec charset
`[A-Za-z0-9_.-]{1,128}`; unique per server; sandbox tools non-empty declared; brokered
url http(s); **lint**: reject ESC/C0 (except \n\t\r)/zero-width chars in names +
descriptions), `tools_digest(&[ToolSnapshot])`, `definition_digest(&def)`,
`parse_mcp_tool("mcp__srv__tool") -> Option<(srv, tool)>`,
`find_tool(&[FrozenBundle], tool_name)`, `capability_denial(&[FrozenBundle], tool) ->
Option<String>` (None for non-mcp tools), `effective_bundles(attached, keep: Option<&[String]>)`
(intersection by name — remove-only), `server_collision(&[FrozenBundle]) -> Option<String>`.

### 3. `fluidbox-core/src/spec.rs`
`RunSpec.capabilities: Vec<FrozenBundle>` with `#[serde(default, skip_serializing_if = "Vec::is_empty")]`.
Test: pre-Phase-5 rows deserialize to empty.

### 4. `fluidbox-core/src/event.rs`
New variants: `capability.frozen` `{bundles: Vec<String>, tools: u64}`;
`tool.brokered` `{tool_call_id, tool, server, ok, latency_ms, result_digest: Option, error: Option}`.

### 5. `fluidbox-db/src/lib.rs`
`CapabilityBundleRow`; `create_capability_bundle` (version = max+1 same-statement, like
revisions), `list_capability_bundles`, `get_capability_bundle`,
`latest_capability_bundle(tenant,name)`, `get_capability_bundle_version(tenant,name,ver)`.
`append_agent_revision(+ capability_bundles: &Value)`;
`create_trigger_subscription(+ capability_bundles: Option<&Value>)` + `SUBSCRIPTION_COLS`
+ row field. DB test: append-only versioning + revision/subscription refs roundtrip.

### 6. `fluidbox-server/src/broker.rs` (new)
Minimal MCP streamable-http client: `initialize` handshake (tolerates missing
`Mcp-Session-Id`; sends `MCP-Protocol-Version` after negotiation), `tools/list`
(discovery at registration), `tools/call` (execution). Handles both `application/json`
and SSE-framed responses (`parse_sse_json` pure fn, tested). Credential resolution:
connection must be active + `mcp_http` + `url_within_base(server.url, base_url)` (pure
fn, tested) → unseal bearer → `Authorization` header. Result content size-capped;
latency measured by caller. 30s timeout.

### 7. `fluidbox-server/src/capabilities.rs` (new)
Admin handlers: `create` (validate def → for each Brokered server discover+photograph
tools via broker (declared tools forbidden for brokered; discovery is the photograph) →
lint → digests → insert version), `list`, `get`. Never echoes connection secrets
(definitions only carry connection_id refs).

### 8. `fluidbox-server/src/internal.rs`
Extract the gate core (budget ceiling → **capability availability** (new; deny
source=`capability`) → trust-tier floor → policy verdict → approvals dance) into a shared
fn used by `/permission` AND the new `POST /internal/sessions/{id}/tools/call`:
parse tool → must be Brokered class in the frozen set (sandbox-class → 400) → gate with
the caller's `tool_call_id` (idempotent approvals) → emit `tool.requested` broker-side →
execute via broker → ledger `tool.brokered` (ok, latency_ms, result digest — never
payloads/secrets) → return `{ok, result}` or `{ok:false, denied, message}`.

### 9. `fluidbox-server/src/run_service.rs`
`CreateRun.capability_selection: Option<Vec<String>>` (manual narrowing). Fetch the
subscription once when `subscription_id` present (reuse for concurrency + narrowing).
Resolve revision pins → load bundle rows (tenant/name/version verified, definition
parsed) → `effective_bundles(sub keep-list)` → `effective_bundles(manual keep-list)` →
collision check → brokered-connection active check (fail-closed before spend) →
ReadOnly-tier strip → freeze `RunSpec.capabilities` → `capability.frozen` ledger event
(when non-empty).

### 10. `fluidbox-server/src/api.rs`
`CreateAgent`/`AddRevision` gain `capability_bundles: Option<Vec<String>>`
(`"name"` = pin latest NOW, `"name@N"` = pin N — §17 #7). Resolution helper validates
existence + attachment-set collisions. AddRevision inheritance: omitted → inherit,
explicit `[]` → clear. `CreateSession` gains `capabilities: Option<Vec<String>>`.

### 11. `fluidbox-server/src/triggers.rs`
`CreateTrigger.capabilities: Option<Vec<String>>` keep-list; validated against the
target revision's attached bundle names (dead config refused); stored on the
subscription; enforced inside `create_run` for ALL invocations.

### 12. `fluidbox-server/src/connections.rs`
`mcp_http` flavor: `{provider:"mcp_http", display_name, base_url, token}` → base_url
http(s) required, token required, sealed; `external_account_id` = host;
`metadata.base_url` pinned for audience binding. No ingress (connector_for → None).

### 13. `fluidbox-server/src/orchestrator.rs`
`FLUIDBOX_CAPABILITIES` env when frozen set non-empty.

### 14. `fluidbox-server/src/main.rs`
Routes: `/v1/capabilities` GET+POST, `/v1/capabilities/{id}` GET, internal
`/sessions/{id}/tools/call` POST; `mod broker; mod capabilities;`.

### 15. Runner image (`just sandbox-build` after)
- `runner/index.mjs`: parse `FLUIDBOX_CAPABILITIES`; `mcpServers[srv.name]` = stdio
  config (sandbox class: command/args) or broker-shim stdio config (brokered class:
  `node broker-shim.mjs` + env `FLUIDBOX_BROKER_SERVER`, `FLUIDBOX_BROKER_TOOLS`,
  control url/session/token); `canUseTool`: brokered tools → immediate allow (broker
  gates server-side), everything else unchanged.
- `runner/broker-shim.mjs` (new): @modelcontextprotocol/sdk stdio server; `tools/list`
  = frozen snapshot verbatim; `tools/call` → POST internal gateway (12-min timeout —
  supervised approvals block); errors → `isError` content.
- `runner/servers/workspace-info.mjs` (new): the packaged sandbox-class demo server —
  `workspace_file_count{}`, `workspace_grep_count{pattern}`; reads `/workspace` only.
- `runner/package.json` += `@modelcontextprotocol/sdk`; Dockerfile COPYs the new files.

### 16. Dashboard (presentation-only)
`app/capabilities/page.tsx` (list bundles: name@version, class chips, tool counts,
digest; create form incl. servers JSON + validate feedback); agents page: attached
bundles on revisions + add-revision picker; triggers form: capabilities keep-list;
session page: frozen-capabilities panel + `tool.brokered`/`capability.frozen` timeline
rendering; nav link.

### 17. `scripts/e2e-capabilities.sh` (new suite phase 7/8; failures becomes 8/8)
Fixtures: fake MCP server (python http.server: JSON-RPC initialize/tools/list/tools/call,
bearer-checked, request log, mutable tool list for the drift probe) + fake GitHub API +
`file://` fixtures (e2e-github pattern). No-model tier (always):
- REGISTRY: create sandbox bundle (declared) + brokered bundle (discovered — fake log
  shows `tools/list` with the sealed bearer); re-POST name → version 2 (append-only);
  invalid defs 400 (empty sandbox tools, bad alias, ANSI-poisoned description, dup tool
  names, declared tools on brokered); digests present; secrets never echoed.
- CONNECTION: `mcp_http` create (sealed, not echoed); bundle referencing a revoked
  connection → 400.
- ATTACH (§17 #7): `"name"` pins the CURRENT latest; publish v2 AFTER attach → new runs
  still freeze v1; `"name@1"` explicit pin; collision across attached set → 400.
- SAME EVENT, DIFFERENT BUNDLES (§12 acceptance): agents A (kb-brokered + ws-sandbox),
  B (ws-sandbox), C (none) subscribed to one repo; one signed PR-opened → three runs;
  each RunSpec freezes its own distinct capability set (exact versions + digests).
- GATE (probe with session tokens, runner killed): A `mcp__kb__kb_search` → allow
  (policy); A `mcp__kb__kb_write` → deny (policy — attach ≠ allow); A `mcp__ghost__x` →
  deny source=capability; B `mcp__kb__kb_search` → deny source=capability (same event,
  different bundles); narrowed subscription (keep-list) → removed bundle's tools denied;
  fork PR → capabilities stripped + `mcp__*` denied.
- BROKER: A's token `POST /internal/…/tools/call kb_search` → result from fake; fake log
  shows `Authorization: Bearer` (server-side credential turn); container env has NO
  secret; RunSpec/ledger have NO secret; `kb_write` → denied AND nothing reached the
  fake; B calling kb → capability deny; sandbox-class tool via broker → 400; DRIFT: fake
  starts advertising `kb_admin` → call → deny (frozen snapshot; rug-pull defense).
- LEDGER: `capability.frozen` + `tool.requested`/`tool.decision`/`tool.brokered` rows
  with digests + latency, never raw secrets.
- SEAM: events.rs/run_service.rs still grep-clean of "github".
Live tier (self-skips): autonomous agent with both bundles + a policy allowing its
tools uses the brokered kb tool AND the sandbox workspace-info tool to answer; every
call ledgered; the co-triggered no-kb agent never calls kb.

### 18. Docs
Design doc §17 #7 SETTLED + #4 deferred note; CLAUDE.md invariant blurb; HANDOVER rev 7;
e2e.sh header + phase count updates.

## Order
migration → core → db → broker/capabilities/internal/run_service/api/triggers/
connections/orchestrator/main → runner + `just sandbox-build` → web → `just check` →
e2e-capabilities.sh → `just e2e` → docs → commit/push.
