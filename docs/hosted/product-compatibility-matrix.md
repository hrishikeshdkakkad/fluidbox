# Hosted product compatibility matrix

**Date:** 2026-07-17
**Status:** Phase A deliverable of the multi-user MCP control plane epic (#28)
**Authority:** [`../plans/2026-07-14-multi-user-mcp-control-plane-design.md`](../plans/2026-07-14-multi-user-mcp-control-plane-design.md) (v4) and [`../plans/2026-07-17-idp-agnostic-identity-design.md`](../plans/2026-07-17-idp-agnostic-identity-design.md) (v5). This document **states** the supported hosted product boundary; it decides nothing. If it ever disagrees with the design documents, the design documents win and this file has a bug.

This matrix defines what the hosted, multi-user fluidbox deployment (~300 seats) supports, what it explicitly does not, and what happens at each boundary. "Unsupported" always has a defined, fail-closed behavior — nothing degrades silently.

## Reading the matrix

| Status | Meaning |
|---|---|
| **Supported** | Part of the hosted v1 product surface; conformance-tested; fail-closed on violation |
| **Deferred** | Deliberately out of v1; requires its own security/UX design before any support (parent design, Non-goals) |
| **Never** | Permanently outside the product boundary; a design change here is a rewrite of the security model |

Phase labels (B–F) refer to the parent design's implementation sequence; a **shipped** qualifier marks a phase already delivered on `main` (Phase B — identity + tenant enforcement — is shipped; C–F remain target-state).

## MCP protocol surface

### Supported

| Capability | Boundary behavior |
|---|---|
| **Tools** (`tools/call`) over **Streamable HTTP** | The only supported upstream MCP primitive and transport. Every call passes the single decision gate (budget → frozen set → schema → trust tier → policy → approval → execution claim) before the upstream is contacted. |
| Registration-time `tools/list` photograph | Discovery uses its own short-lived client session; names, descriptions, schemas, and annotations are validated (ANSI/zero-width screening, size bounds) and frozen into an append-only snapshot. If `nextCursor` remains after the discovery page cap, discovery **fails** rather than freezing a partial list (Gap 8). |
| Protocol version `2025-11-25` | Offered at initialization; an explicit supported-version set is maintained; unsupported negotiation is rejected. Runtime negotiation must match the snapshot's protocol version unless an explicit compatibility adapter exists. `MCP-Protocol-Version` is sent on subsequent requests. (Gap 8; Phase E — the current broker offers `2025-06-18` and initializes lazily.) |
| Frozen-schema argument validation | Tool arguments are validated server-side against the frozen input schema (depth/size bounds, no external `$ref` resolution) before trust-tier and policy evaluation. The JSON Schema dialect follows the snapshot's protocol version (`2025-11-25` ⇒ JSON Schema 2020-12, SEP-1613). Rejections surface to the model as tool-execution errors (SEP-1303), never protocol errors. (Gap 12; Phase E.) |
| Optional `MCP-Session-Id` | Persisted per run binding; treated as routing state, never authentication. The OAuth/static authorization header is sent on every upstream HTTP request. |
| `outputSchema` / `structuredContent` | Preserved end to end, or the tool is explicitly rejected at registration — never silently dropped (Gap 8; the current snapshot/result path drops both, which Phase E closes). |

### Explicitly unsupported MCP primitives (v1)

Server-side primitives fluidbox never calls:

| Primitive | v1 status | Boundary behavior | What support would require |
|---|---|---|---|
| Resources (`resources/*`, incl. templates and subscriptions) | Deferred | Never requested; a server advertising them is fine — fluidbox simply never calls them | Authorization + data-flow design (what a resource read means under policy/approval) |
| Prompts (`prompts/*`) | Deferred | Never requested | UX + injection-surface design |
| Tasks | Deferred | Never requested | Long-lived-operation lifecycle design |
| Completion (argument autocompletion) | Deferred | Never requested | — |

Client-side capabilities fluidbox never advertises (Gap 9: "advertise no unsupported client capabilities"):

| Capability | v1 status | Boundary behavior |
|---|---|---|
| Sampling (server asks the client to run a model call) | Deferred | Not advertised. A server that sends the request anyway receives a JSON-RPC error response — never silence that could block the server (Gap 8). |
| Elicitation (server asks the client to prompt the user) | Deferred | Not advertised; JSON-RPC error on receipt. |
| Roots | Deferred | Not advertised; JSON-RPC error on receipt. |

Notifications:

| Notification | Behavior |
|---|---|
| `notifications/tools/list_changed` | A signal for an out-of-band **future** snapshot only. It never mutates an in-flight run's frozen tool set (invariant 14). |
| Other server-to-client notifications | Ignored. Server-to-client **requests** for unadvertised capabilities get JSON-RPC errors; notifications (no response expected) are dropped. |

### Transports

| Transport | Status | Notes |
|---|---|---|
| Streamable HTTP | **Supported** | The only hosted upstream transport. HTTPS required in production (see the [connector admission policy](connector-admission-policy.md)). |
| stdio, in the control plane | **Never** | No arbitrary control-plane process execution — no `npx`, no shell, no installation commands, ever. |
| stdio, in the sandbox | **Supported (curated only)** | Sandbox-class MCP servers are stdio subprocesses packaged in the first-party runner images: credential-free by construction, contained by the sandbox. This is the surviving role of `capability_bundles` (settled: bundles persist for sandbox tools only). |
| Legacy HTTP+SSE transport (pre-Streamable-HTTP) | Unsupported | Not offered, not negotiated. |
| A process on a user's laptop | **Never (directly)** | Supported alternatives: expose it as an authenticated remote Streamable HTTP endpoint; package a curated, signed, credential-free stdio server into the runner image; or run a customer-side outbound relay. |

## Connections and binding

The four objects are independent (parent design, "The multi-user connection model"): connector **definition** (no credential, no authority) → **connection** (one authorization grant) → agent **connection requirement** (what an agent needs, never whose credential) → per-run **resource binding** (whose identity executes, frozen at run creation).

### Connection ownership

| Ownership | Status | Use |
|---|---|---|
| Personal connection (`owner_type = user`) | **Supported (Phase C)** | Interactive runs: dashboard, authenticated API. (Today's connections are tenant-owned — Gap 3.) |
| Organization service connection (`owner_type = organization`) | **Supported (Phase C)** | Schedules, webhooks, org-wide agents, GitHub App installations, unattended automation. |
| Unattended **personal** delegation | **Deferred (not in v1)** | A schedule or webhook can never ride a personal connection in v1. Omitted until a concrete customer requirement demands it, with expiry/revocation/membership-loss semantics designed first. |

### Binding modes at run creation

| Mode | Status | Rule |
|---|---|---|
| `invoking_user` | **Supported (Phase C)** | The authenticated invoking user's active personal connection. No unambiguous match ⇒ run creation fails before provisioning — never "latest connection" silently. |
| Organization service | **Supported (Phase C)** | Administrator-managed org connection; the only mode available to schedules/webhooks (no interactive user exists). |
| Explicit | **Supported (Phase C)** | Caller supplies a connection ID; fluidbox verifies tenant, caller authorization, requirement satisfaction, scopes, active status, and snapshot coverage. |
| Delegated personal | **Deferred** | See above. |

### Requirement satisfaction (settled)

- `required_tools`, `satisfaction: all`, **fail closed**: every required tool must exist in the selected connection's current snapshot or binding fails at run creation — before model spend or sandbox provisioning.
- The effective run surface is exactly the required set; silent narrowing to an intersection is prohibited (a shared agent must not behave differently per user without a visible signal).
- Binding slots are typed — `mcp`, `workspace_fetch`, `result_publish` — resolving through one binding service to a tagged authority union: `connection | subscription_secret | none` (`none` is an explicit credentialless decision, never a missing value).
- MCP policy rules are name-only in v1, or require an exact expected schema digest for field-aware rules (schema divergence rule).

## Connector authentication modes

| Mode | Status | Notes |
|---|---|---|
| OAuth authorization-code + PKCE S256 (RFC 9728 protected-resource metadata → RFC 8414/OIDC discovery → RFC 8707 `resource=` on both legs) | **Supported** | Refuses issuers without PKCE S256. Refresh token sealed at rest; access tokens minted at call time, cached in memory only. |
| Static credential (API key; custom `header_name`/`scheme`) | **Supported** | Sealed at rest; audience-bound to the connection's canonical resource URI/base. |
| OAuth client identity | **Supported** | Resolution priority: pre-registered (sealed secret, confidential) → CIMD (only when the public URL is https + non-loopback) → DCR. One client registration serves many user grants; no per-connection dynamic registration unless the AS requires it. |
| Client credentials / M2M (SEP-1046) | **Deferred** | Gated on SEP ratification — it is not part of the ratified `2025-11-25` revision, and this design implements no candidate semantics before ratification. |
| Enterprise-Managed Authorization (SEP-990 ID-JAG) | **Deferred (target state)** | Ratified upstream; adoption is per-connector, gated on each authorization server's support. Nothing in v1 builds it. |

## Identity and login (hosted)

Per-organization, IdP-agnostic OIDC (identity design v5). fluidbox is a generic OIDC relying party; no vendor-specific code paths.

### IdP conformance floor — anything meeting this works

| Requirement |
|---|
| OIDC discovery at `{issuer}/.well-known/openid-configuration` with `authorization_endpoint`, `token_endpoint`, `jwks_uri` |
| Authorization-code flow with PKCE `S256` |
| Token-endpoint client auth among `client_secret_basic`, `client_secret_post`, `none` (public client) |
| ID tokens signed with an asymmetric algorithm in the config's allowlist; stable nonempty `sub` (≤255 bytes); an access token in the token response |
| `email`/`email_verified` claims strongly recommended (required when `require_email_verified` or bootstrap-owner binding is used) |
| A group/role claim only if role mapping is wanted; otherwise every JIT user lands at `default_role` |

### Identity surface

| Capability | Status | Notes |
|---|---|---|
| Per-org OIDC login (`/v1/auth/*`) | **Supported (shipped, Phase B)** | Org-slug URLs; one stable callback; one-time browser-bound `login_flows`; server-side sessions (`__Host-fbx_web` cookie, `fbx_web_` token prefix). |
| JIT provisioning with claim→role mapping | **Supported (shipped, Phase B)** | `sub` is never mappable; `owner` never minted from IdP claims absent explicit operator opt-in. |
| Personal API tokens (`fbx_pat_`) | **Supported (shipped, Phase B)** | Browser-session-minted only; a PAT can never mint/extend/revoke PATs; 90-day default TTL, 1-year max; membership rechecked on every use. |
| Break-glass / bootstrap | **Supported (shipped, Phase B)** | The operator admin token on the explicit `/v1/admin/*` surface; single-winner first-owner claim; fully audited. |
| Single-admin mode (no IdP configured) | **Supported (unchanged)** | Multi-user is derived per organization, but the proxy's credential mode is static per deployment: in a local/dev deployment running `FLUIDBOX_WEB_MODE=admin`, today's admin-token behavior continues exactly. In a hosted `sso` deployment the proxy carries no admin token at all — IdP-less organizations there are reachable only through bearer-authenticated `/v1/admin/*` routes, never the browser. |
| SAML | **Never (directly)** | SAML-only enterprises bridge via Dex/Keycloak on their side. |
| Password store / MFA enforcement / account recovery | **Never** | The IdP owns authentication; fluidbox owns sessions and authorization. `acr`/`amr` are recorded; assurance is derived only from operator-configured mappings. |
| SCIM provisioning; email-domain login routing | Deferred | JIT + slug URLs cover v1. |
| Device-code CLI login | Deferred | PATs cover v1. |
| RP-initiated / back-channel logout | Deferred | `idp_sid` captured informationally; local logout only in v1. |
| Refresh-token custody (login) | **Not in v1** | fluidbox never requests `offline_access` and discards any refresh token an IdP returns. |
| Cross-organization identity linking | **Never (v1 model)** | Users are org-scoped rows keyed `(tenant, idp_config, subject)`; the same human in two orgs is two users. One session = one organization; switching orgs is a new login with an explicit confirmation step. |

## Run invocation surface

All entry points converge on the same governed run path (`run_service::create_run`); a trigger only creates runs of registered agents.

| Entry point | Principal | Status |
|---|---|---|
| Dashboard | User (browser session) | **Supported (shipped, Phase B)** — browser session in `sso` mode; the `admin`-mode proxy injects the admin token for local/single-admin deployments |
| Authenticated API / CLI | User (PAT) | **Supported (shipped, Phase B)** |
| API trigger (`POST /v1/triggers/{id}/invoke`) | Trigger token (subscription-scoped) | **Supported** — a trigger token can poll only the runs it created |
| Webhook (`/v1/ingress/*`) | Webhook (signature-verified) | **Supported** — HMAC is the authentication: against the connection's sealed secret, or the GitHub App registration's sealed secret on the App-level ingress path |
| Schedule | Schedule principal | **Supported** — exactly-once firing via deterministic idempotency claims |

Fork PRs freeze `TrustTier::ReadOnly` (all MCP tools stripped from the frozen set; enforced above policy and approvals — no approval escape).

## Harnesses and runner images

| Harness | Status | Notes |
|---|---|---|
| Claude Agent SDK (`images/sandbox-runner`) | **Supported** | First-party curated image. |
| Codex (`images/codex-runner`) | **Supported** | First-party curated image; same HTTP runner contract, same gate. |
| Customer-built runner images | **Deferred** | Hosted v1 ships first-party images only ("curated before custom", PLAN.md invariant 5). Customer images arrive later strictly as signed, versioned images implementing the same runner contract. |

## Execution providers

| Provider | Status | Role |
|---|---|---|
| Kubernetes (`FLUIDBOX_PROVIDER=kubernetes`) | **Supported — the hosted substrate** | Per-run pods in a sandbox namespace under a default-deny `zeroEgress` NetworkPolicy (only the internal control-plane listener `:8788`; no DNS, no public route); run admission gated on a boot-time probe proving enforcement (`FLUIDBOX_REQUIRE_ENFORCED_NETPOL=true`); optional `runtimeClassName` (gVisor/Kata) isolation tiers. See the [network architecture](network-architecture.md). |
| Docker | **Supported — local development and single-host self-hosting** | Outside the hosted SaaS boundary. Permanent (dual-provider permanence; it is never demoted). The `HostDev` network mode is a local-dev convenience, never a hosted security boundary. |
| Future substrates (e.g. MicroVM fleets) | Deferred | Must provide structural guarantees equivalent to the Kubernetes path before hosting runs (Gap 6). |

## Capability model (settled)

| Decision | Statement |
|---|---|
| Two tool classes | *Sandbox* (in-image stdio, credential-free, contained) and *brokered* (executed by the control plane with sealed credentials). The split **is** the security model. |
| Fate of capability bundles | Bundles survive **only** for sandbox-class tools. Brokered tools move entirely to agent connection requirements + per-connection tool snapshots + per-run resource bindings (Phase C), with an additive migration: legacy deserialization retained, historical RunSpecs never rewritten, legacy connections rediscovered into real snapshots, pinned subscriptions explicitly repointed, unconverted legacy revisions refused after a cutoff. |
| Attach ≠ allow | Availability (frozen set) and permission (policy/approval) remain independent layers; the single gate judges every call. |
| Tenant isolation | Tenant-scoped repository methods are the primary mechanism (`TenantScope` signatures); RLS is defense in depth; composite `(tenant_id, id)` keys/FKs are mandatory for tenant-owned relationships. |

## Scale envelope (planning assumptions)

| Quantity | Value |
|---|---|
| Registered users | ~300 |
| Saved connections | ~1,500 (5/user) |
| Normal concurrent runs | 30–60 |
| Normal active upstream MCP sessions | 90–180 |
| Full-seat stress case | 300 sandboxes / 900 logical MCP sessions |
| Deployment shape, v1 | Single replica + `Recreate` (shipped chart v0.2.0); the `ReadWriteOnce` archive PVC is the first multi-replica blocker. Two-to-three-replica topology is an explicit **Phase F** target behind the statelessness inventory. |

## Related documents

- [Connector admission policy](connector-admission-policy.md) — what endpoints may be admitted, by whom, and what is always refused
- [Hosted network architecture](network-architecture.md) — the planes, listeners, and every edge
- [Threat model](threat-model.md) — adversaries, scenarios, invariant mapping, residuals
