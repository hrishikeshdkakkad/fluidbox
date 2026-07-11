# MCP ecosystem findings — input to design-doc Phase 5 (capability & MCP catalog)

**Date:** 2026-07-10 · **Method:** 4 parallel web-research passes (spec/transports/auth ·
registry/catalog identity · attack classes · common servers), synthesized against the
fluidbox design (photograph rule, permission gate, server-side broker, egress-free
sandboxes). Sources inline; ⚠ marks unconfirmed-currency items.

**How to read this:** each section ends with **→ fluidbox** — the concrete schema/design
decision the finding drives. The net effect on the Phase 5 schema is collected in §6.

---

## 1. Spec revision & transports

- **Current ratified revision: `2025-11-25`** (`/specification/latest` resolves there).
  History: 2024-11-05 → 2025-03-26 (OAuth framework + Streamable HTTP) → 2025-06-18
  (structured tool output, RFC 8707 resource binding, batching removed) → **2025-11-25**
  (OIDC discovery, Client ID Metadata Documents, JSON Schema 2020-12 as default dialect,
  experimental Tasks, icons).
- **A locked release candidate dated `2026-07-28` goes final in ~2.5 weeks** and is
  breaking: removes the `initialize` handshake **and protocol-level sessions
  (`Mcp-Session-Id`) entirely** (client info rides `_meta` per request), requires
  `Mcp-Method`/`Mcp-Name` routing headers on Streamable HTTP, and lifts
  `inputSchema`/`outputSchema` to **full JSON Schema 2020-12** (`$ref`/`oneOf`/`allOf`).
  ⚠ RC, not final — re-verify after 2026-07-28.
- **Transports:** `stdio` (local subprocess; newline-delimited JSON-RPC) and
  **Streamable HTTP** (one endpoint; POST returns either `application/json` or an SSE
  stream — clients MUST handle both). The old two-endpoint HTTP+SSE is deprecated with
  hard removal dates landing across vendors. Registry transport strings:
  `"stdio" | "streamable-http" | "sse"`.
- In-practice split (2026): **stdio dominates local**, **Streamable HTTP is the remote
  production transport**.

**→ fluidbox:** the two spec-blessed transports map 1:1 onto our two tool classes —
`stdio` **inside the sandbox** (sandbox class), `streamable-http` **from the control
plane** (brokered class). Store transport with the registry's exact strings. The broker's
MCP client must: accept both JSON and SSE-framed responses; treat the session handshake
as optional (tolerate servers with and without `Mcp-Session-Id` — the 2026-07-28 world
has none); store schema snapshots **verbatim** (never normalize/interpret them) so full
2020-12 schemas freeze without a resolver. An external `$ref` in a snapshot is itself an
egress vector — flag/reject at registration.

## 2. Remote-server auth — what the broker custodies

- Spec auth is **OAuth 2.1**: MCP server = resource server; discovery via **RFC 9728**
  protected-resource metadata; clients MUST send **RFC 8707 `resource=`** (canonical
  server URI) so tokens are **audience-bound to one server**; PKCE S256 mandatory;
  registration via pre-registration > Client ID Metadata Documents (new) > DCR.
  `client_credentials` is the acknowledged headless path.
- **Token passthrough is explicitly forbidden** ("MUST NOT accept tokens not issued for
  the MCP server") — a broker fronting upstreams must authenticate itself, never forward
  the sandbox/agent's token.
- Headless runs have **no browser**: interactive `authorization_code`+consent doesn't
  fit. The workable custody models are (a) static bearer / API key provisioned
  out-of-band, (b) `client_credentials`, (c) an out-of-band OAuth dance whose refresh
  token the broker seals at rest.
- Spec security pages add: SSRF during metadata discovery (block `169.254.169.254`,
  private ranges; egress-proxy recommended), confused-deputy consent rules for OAuth
  proxies, session IDs never used as authentication.

**→ fluidbox:** brokered credentials ride **integration connections** (the existing
sealed-credential object) — a new lightweight flavor `provider = "mcp_http"` holding
`{base_url}` in metadata + a sealed static bearer token. **Audience binding = the
connection pins its `base_url` and the broker refuses to send its credential to any
server URL outside that base** (our RFC-8707-equivalent; prevents a bundle pairing
connection X's token with attacker.com). Full OAuth (client-credentials, refresh
rotation, RFC 9728 discovery) is a later slice — the seam (connection_ref on the server
entry) is already the right one. The broker is structurally not a token-passthrough
proxy: the sandbox holds only its session token; the real credential turns server-side
(same inversion as the LLM facade and git fetch).

## 3. Registry & catalog identity — what an attachment record should carry

- **Official MCP Registry** (registry.modelcontextprotocol.io, still *preview*, API
  frozen v0.1): `server.json` identity = **reverse-DNS `name`**
  (`io.github.owner/server`, `com.example/x` — namespace ownership is auth-verified),
  **`version`** (string ≤255, semver recommended), `packages[]`
  (`registryType ∈ {npm, pypi, oci, nuget, cargo, mcpb}`, `identifier`, `version`,
  `registryBaseUrl`, `transport`, `fileSha256` for mcpb), `remotes[]` (`type`, `url`,
  `headers`).
- **Published `(name, version)` metadata is immutable** (re-publish fails; only `status`
  can change: active → deprecated/deleted; no yank command exists).
- **Critical gap: the registry stores NO content hash for npm/PyPI/NuGet** — it is a
  metadata pointer registry. Only `oci` (digest-pinned ref) and `mcpb` (`fileSha256`)
  are content-addressable, and even `fileSha256` is client-enforced. **`(name, version)`
  alone is not a supply-chain anchor.** Docker's MCP Catalog is the strongest
  supply-chain story (Cosign-signed OCI images, digest-pinned immutable catalogs);
  Anthropic's connectors directory is review-based, not hash-based; VS Code/Cursor
  identity is host-local and inconsistent.
- **No ecosystem standard for tool-list hashing exists** (SEP-1766 — per-tool SHA-256
  digests — is proposed, unsponsored). Client practice (mcp-scan "tool pinning",
  VS Code's startup fingerprint) is exactly: SHA-256 over canonical JSON of each tool's
  `{name, description, inputSchema}`, block/re-approve on drift.

**→ fluidbox:** the attachment identity block mirrors `server.json` — optional
`identity {name (reverse-DNS), version, registry_type, identifier, digest}` — but **the
load-bearing integrity anchor is OUR OWN `tools_digest`**: sha256 over the canonical
JSON of the server's frozen tool list, computed at registration and frozen into the
RunSpec (a private implementation of SEP-1766). Bundle rows also get a
`definition_digest` over the whole definition. Registry-style fields are provenance
metadata; the digest we compute is the guarantee.

## 4. Attack classes — pressure-testing the photograph rule

Control legend: **SNAP** = frozen schema snapshot · **GATE** = permission gate ·
**BROKER** = server-side credential turn · **EGRESS** = sandbox egress denial ·
**ISO** = disposable container.

| Attack class | Example | Defeated by |
|---|---|---|
| **Rug pull / schema drift / `tools/list_changed` abuse** | CVE-2025-54136 "MCPoison" (Cursor name-keyed trust); Claude Code keys MCP trust by server *name* only | **SNAP — clean, categorical win.** Frozen set served/enforced for the life of the run; live drift is simply not consulted. This is Phase 5's strongest story. |
| **Tool poisoning at first sight** (descriptions, and *full-schema* poisoning via parameter names; ANSI/zero-width concealment; "line jumping") | Invariant `add(a,b)` sidenote exfil PoC; CyberArk FSP | **GATE + BROKER + EGRESS — NOT SNAP.** A snapshot photographs the poison in. Registration must **lint at snapshot time** (reject ANSI/zero-width/control chars — objective; deeper mcp-scan-grade lint is follow-up). The backstop is that a convinced model still can't read secrets (none in sandbox) or exfiltrate (no egress; gate denies). |
| **Prompt injection via tool RESULTS / "lethal trifecta"** | GitHub MCP private-repo exfil via public issue (2025-05-26); Supabase ticket-SQL exfil; CyberArk ATPA fake-error | **GATE + approvals + EGRESS only — SNAP and BROKER are irrelevant** (runtime data, not schema). When exfil rides a *legitimately allowed* write tool, even egress doesn't help — this is architecturally open ecosystem-wide. fluidbox posture: results are untrusted context; write/exfil-capable tools stay policy-gated + approval-paused; do **not** claim the snapshot solves this. |
| **Confused deputy / token passthrough / session hijacking** | Spec's own named threats; CVE-2026-26118 (Azure MCP SSRF → managed-identity theft) | **BROKER by construction** (audience-bound sealed creds; sandbox never holds them) + the base-url binding above. If an interactive OAuth proxy ever ships, per-client consent rules apply then. |
| **Cross-server tool shadowing / name collision** | Invariant `send_email` override demo | **SNAP + a collision check**: server aliases must be unique across a run's frozen set — reject at attach/freeze, never first-wins. |
| **RCE-class server bugs** | mcp-remote CVE-2025-6514 (9.6); Anthropic filesystem EscapeRoute CVEs; postgres-MCP SQLi; Postmark-MCP npm exfil typosquat | **ISO** (sandbox class runs inside the disposable container) + registration pinning/digests for supply chain. |
| **Cross-tenant bugs inside a trusted upstream** | Asana MCP leak (~1k orgs) | **None of our controls** — inherited upstream correctness. Recorded as an explicit trust assumption. |

**→ fluidbox:** the photograph rule ships as designed **plus**: (1) snapshot-time lint
(ANSI/zero-width/control-char rejection), (2) server-alias collision rejection across
the frozen set, (3) honest doc language: SNAP kills drift; poisoning-at-attach and
results-injection are the gate's job; annotations like `readOnlyHint` are **spec-declared
untrusted** — stored as display hints, never enforcement (policy classifies
independently).

## 5. Commonly attached servers — catalog seeds & e2e realism

| Server | Distribution / transport | Auth (exact env) | Representative tools | Egress |
|---|---|---|---|---|
| GitHub (`io.github.github/github-mcp-server`, ~31k★) | remote `https://api.githubcopilot.com/mcp/` or local `ghcr.io/github/github-mcp-server` (stdio) | OAuth/PAT bearer (remote); `GITHUB_PERSONAL_ACCESS_TOKEN` (local); `--read-only`, `--toolsets` | `get_file_contents`(R) `search_code`(R) `create_issue`(W) `create_pull_request`(W) | api.github.com |
| Postgres (crystaldba/postgres-mcp; official reference archived) | pipx/Docker, stdio | `DATABASE_URI`; `--access-mode=restricted` (read-only default) | `list_schemas`(R) `execute_sql`(gated) `explain_query`(R) | the DB host |
| Slack (official remote GA; korotovsky self-host) | `https://mcp.slack.com/mcp` (OAuth) / npm stdio | OAuth / `SLACK_MCP_XOXB_TOKEN` | `conversations_history`(R) `conversations_add_message`(W, **off by default**) | slack.com |
| Notion (`com.notion/mcp`) | remote `https://mcp.notion.com/mcp` (only supported mode) | OAuth (hosted); `NOTION_TOKEN` (self-host) | `notion-search`(R) `notion-create-pages`(W) | mcp.notion.com |
| Sentry (`io.github.getsentry/sentry-mcp`) | remote `https://mcp.sentry.dev/mcp` or npm stdio | OAuth / `SENTRY_ACCESS_TOKEN` | `search_issues`(R) `update_issue`(W) | sentry.io |
| Linear / Stripe | remote `https://mcp.linear.app/mcp`, `https://mcp.stripe.com` | OAuth 2.1 / bearer; Stripe local `STRIPE_SECRET_KEY` + `--tools=` | `list_issues`(R) `create_issue`(W); `create_refund`(W) `list_customers`(R) | one host each |
| Playwright (`io.github.microsoft/playwright-mcp`, ~33k★) | npm stdio | none | `browser_navigate` `browser_click`(W) `browser_snapshot`(R) | **arbitrary web** — worst egress fit |
| Reference set (filesystem, git, memory, fetch, time, sequentialthinking, everything; monorepo ~88k★) | npm/PyPI stdio | none | `read_text_file`(R) `git_diff`(R) `create_entities`(W) `fetch`(R) | none (except fetch = open web) |

**→ fluidbox:** the two classes partition the real ecosystem cleanly — credential-free
stdio servers (filesystem/git/memory/time/sequentialthinking; postgres-to-internal-host)
are **sandbox class**; every OAuth/bearer remote (GitHub, Slack, Notion, Sentry, Linear,
Stripe) is **brokered class**; open-web tools (fetch, Playwright) are the ones an
egress-free sandbox correctly forces through an explicit decision. Read-only knobs
(`--read-only`, `--access-mode=restricted`, RAK grants) live *inside* servers — useful
defense-in-depth to record on the bundle, but fluidbox's own gate stays the judge. E2E
fixtures: a fake Streamable-HTTP MCP server (JSON responses, bearer-checked, request log)
mirrors the brokered norm; a tiny stdio server in the runner image mirrors the sandbox
norm.

## 6. Net schema decisions (folded into Phase 5 before the §17 settle)

1. **Two classes, spec-aligned transports:** `sandbox` = stdio in-image (command/args,
   credential-free by construction); `brokered` = streamable-http from the control plane.
2. **Identity fields** on a server entry: local `name` (the `mcp__<name>__…` prefix;
   collision-checked), optional registry-style `identity {name, version, registry_type,
   identifier, digest}` as provenance.
3. **Integrity = our own digests:** per-server `tools_digest` = sha256(canonical JSON of
   frozen `{name, description, input_schema}` list); per-bundle `definition_digest`.
   Both frozen into the RunSpec.
4. **Photograph timing:** brokered tools are **discovered** (tools/list) at bundle
   registration; sandbox tools are **declared** by the registrant. `create_run` freezes
   the stored snapshot; nothing re-discovers mid-run; the gate denies any call outside
   the frozen set (drift = deny, visibly ledgered).
5. **Snapshot-time lint:** reject ANSI/zero-width/control characters in names +
   descriptions at registration (objective poison screen; deep lint later).
6. **Credential custody:** `provider="mcp_http"` connections (sealed bearer +
   `base_url`); broker sends the credential only to URLs under the connection's base
   (audience binding). Schemas/snapshots/ledger never carry secrets.
7. **Annotations untrusted:** `readOnlyHint`/`destructiveHint` etc. stored for display
   only; the policy engine + trust tier decide.
8. **ReadOnly trust tier strips capabilities at freeze** (fork PRs run with zero MCP
   surface) — and the gate's read-only allowlist denies `mcp__*` anyway (belt + braces).
9. **Wire-compat:** RunSpec gains `capabilities: []` with `serde(default)` — every
   pre-Phase-5 frozen row deserializes forever.

### Primary sources
Spec 2025-11-25 (+changelog, transports, authorization, security best practices, tools):
modelcontextprotocol.io/specification/2025-11-25 · 2026-07-28 RC:
blog.modelcontextprotocol.io/posts/2026-07-28-release-candidate ·
Registry & server.json: modelcontextprotocol.io/registry/{about,package-types,authentication},
github.com/modelcontextprotocol/registry · mcpb: github.com/modelcontextprotocol/mcpb ·
Docker MCP Catalog: docs.docker.com/ai/mcp-catalog-and-toolkit · Tool poisoning/line
jumping/FSP/ANSI: invariantlabs.ai (2025-04-01, 2025-05-26), blog.trailofbits.com
(2025-04-21, 2025-04-29), cyberark.com (2025-05-30) · MCPoison CVE-2025-54136:
research.checkpoint.com · mcp-remote CVE-2025-6514: jfrog.com · EscapeRoute
CVE-2025-53109/53110: cymulate.com · Supabase exfil: generalanalysis.com ·
SEP-1766: github.com/modelcontextprotocol/modelcontextprotocol/issues/1766 ·
mcp-scan: invariantlabs-ai.github.io/docs/mcp-scan · Server profiles:
github.com/{github,microsoft,crystaldba,upstash}/…, docs.slack.dev, developers.notion.com,
docs.sentry.io, linear.app/docs/mcp, docs.stripe.com/mcp,
github.com/modelcontextprotocol/servers · Trackers: vulnerablemcp.info,
authzed.com/blog/timeline-mcp-breaches.
