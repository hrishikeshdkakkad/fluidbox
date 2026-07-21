# Connector admission policy

**Date:** 2026-07-21
**Status:** Phase A deliverable of the multi-user MCP control plane epic (#28); **enforced in code as of Phase E** (it was policy-only before)
**Authority:** [`../plans/2026-07-14-multi-user-mcp-control-plane-design.md`](../plans/2026-07-14-multi-user-mcp-control-plane-design.md) (v4). This document states the settled admission boundary for remote MCP connectors in the hosted deployment; it decides nothing new.

Admission answers one question: **which remote MCP endpoints may the fluidbox broker ever contact, and on whose say-so?** It deliberately answers nothing else — an admitted connector still has no credential, no attached agent, and no allowed tool call until the connection, binding, policy, and approval layers each say yes.

## Where the rules below are enforced (shipped, Phase E)

Until Phase E this document described a boundary the code did not yet implement. It now does, at three points:

| Point | What runs | What is refused |
|---|---|---|
| **Connection create** (both `mcp_http` paths, catalog Connect and manual) | Save-time admission of the connector base URL — scheme policy + host-literal address class. DNS is deliberately **not** resolved in a request handler | A non-`http(s)` scheme, an unparsable URL, plain `http` outside the dev-loopback seam, and any URL whose host is a literal in a forbidden class (private, loopback, link-local, multicast, reserved, benchmarking, documentation, IPv6 site-local, cloud metadata) |
| **Subscription callback save** | The same literal + scheme admission on a result-callback URL (`400` on refusal) | Same set. Pre-existing rows are untouched and still checked at dial |
| **Every dial** | `admit_url` pre-flight *plus* an address-filtering DNS resolver on the hardened client. Both are needed: reqwest dials an IP literal without ever consulting a resolver, so the literal check is what stops `https://169.254.169.254/…` | The same set, re-checked at resolution time; **plus** any redirect — the broker client refuses a 3xx outright rather than following it, and never logs the `Location` target |

The same pre-flight fronts the connector-OAuth fetches (protected-resource metadata, authorization-server metadata, dynamic client registration, token exchange, refresh) and the delivery-callback publish. Operator escape hatches: `FLUIDBOX_EGRESS_ALLOW_CIDRS` (opt a deliberately-private endpoint back in; a malformed entry fails boot) and `FLUIDBOX_EGRESS_PROXY` (one waypoint for both hardened clients and the git subprocess — note that a proxy moves DNS resolution to itself, so it must be an allowlisting forward proxy).

## Principles

1. **Admission ≠ authorization.** A connector definition contains no user credential and grants no authority. Catalog data — curated or custom — is untrusted reference data: being displayed, verified, or marked curated bypasses none of connection verification, tool-schema validation, policy evaluation, or approvals. The single decision gate remains the judge of every call.
2. **Fail closed, visibly.** Anything that cannot be positively validated — an unreachable endpoint, a non-conformant discovery document, an unattributable custom row — refuses loudly. An account identity that cannot be proven identical across reauthorization does not refuse the reauthorization — it never *preserves* the authorization generation: the generation bumps and old-generation runs fail closed. Nothing is admitted, bound, or preserved on "probably fine."
3. **The broker is the only MCP egress point.** No other component — and never a sandbox — contacts remote MCP endpoints. Every control below is enforced at that single chokepoint.

## Definition tiers

| Tier | Scope | Admitted by | Notes |
|---|---|---|---|
| **Curated** | Global reference data, visible to all tenants | fluidbox operators (catalog is managed API-only; no seed file, no boot sync) | Curated entries carry the connector's canonical endpoint/template, transport, OAuth discovery expectations, authentication modes, verification tier, display metadata, optional tool hints, and egress classification. |
| **Custom** | **Tenant-scoped** | The owning organization, governed by RBAC (shipped, Phase C: adding an organization custom entry requires admin/owner; a personal-custody Connect is open to any member, mirroring personal connections) | One tenant admitting a custom endpoint must never make it visible or bindable to another tenant. Custom entries are forced to the `custom` verification tier. |

**Migration note (shipped, Phase C):** `connector_catalog` was a global, tenant-less table whose custom rows were admitted by the single boot tenant. The 0013 migration backfills each custom row to its owning tenant when exactly one tenant exists; curated rows stay global; a custom row that cannot be attributed (zero or multiple candidate tenants) is **disabled** (`disabled_at`) — never inherited by every tenant.

## Endpoint admission requirements

Both tiers must satisfy all of the following to be admissible for hosted use. The single sanctioned exception to the **private-address** prohibition is the **specifically approved private-network connector** defined under [Private and enterprise endpoints](#private-and-enterprise-endpoints) — a specific, non-self-service approval; nothing else may target private ranges, and the other forbidden address classes admit no exception at all:

| Requirement | Rule |
|---|---|
| Transport | Streamable HTTP MCP at a canonical resource URI (or endpoint template). |
| TLS | HTTPS required in production. Plaintext HTTP exists only in local development. |
| Address class | The resolved destination must not be private (RFC 1918), loopback, link-local, multicast, reserved, or a cloud-metadata address. Only the specifically approved private-network connector (the sanctioned exception above) may target **private-network** addresses; loopback, link-local, multicast, reserved, and cloud-metadata addresses are unconditionally refused. Enforced at resolution time on **every** fetch, not just at admission (defends time-of-check/time-of-use and DNS-rebinding changes). |
| Redirects | Every redirect target is re-validated against the same rules. Credentials never follow a redirect off the admitted base. |
| OAuth discovery | Where OAuth is used: RFC 9728 protected-resource metadata → RFC 8414/OIDC authorization-server metadata; authorization servers without PKCE S256 are refused; RFC 8707 `resource=` binds both legs. Discovery and metadata fetches obey the same SSRF rules as tool traffic. |
| Headers | Connector-supplied custom headers are restricted: they can never overwrite MCP transport headers or the authorization header the broker manages. |
| Egress path | Hosted broker egress optionally routes through an egress proxy / network firewall (`FLUIDBOX_EGRESS_PROXY`, shipped Phase E). |

The same IP validation applies to **workspace clone URLs**: a credentialless (`authority: none`) fetch of a "public" repo still executes from the control plane and is still egress. The shipped guard resolves the clone host and validates *every* returned address before `git` runs, allows `file://` only under the configured `FLUIDBOX_GITHUB_CLONE_BASE` prefix (or the dev-loopback seam), and hardens the subprocess with `-c http.followRedirects=false`, `GIT_LFS_SKIP_SMUDGE=1`, and `GIT_ALLOW_PROTOCOL=http:https:file`. **Disclosed residual:** because `git` is out-of-process it re-resolves the host independently, so this is resolve-then-validate, not a single atomic check. Cloning an admitted repo is still not authority over arbitrary hosts its metadata points at — submodule and LFS endpoints need their own admission decision and binding.

## Always refused

These are permanent boundary statements, not v1 deferrals:

- **Arbitrary control-plane `stdio` execution — ever.** No user-supplied `npx`, shell, or installation commands run in the control-plane environment, regardless of tier, tenant, or role.
- **Direct reach into a user's machine.** A process on a user's laptop cannot be a hosted connector. Supported alternatives: (1) expose it as an authenticated remote Streamable HTTP endpoint; (2) package a curated, signed, credential-free stdio server into the runner image; (3) run a customer-side outbound relay that brokers a private endpoint.
- **Private-network scanning via custom endpoints.** Arbitrary custom URLs must never turn the hosted broker into a probe of internal address space — the address-class rules admit no self-service exception; private **enterprise** endpoints use only the sanctioned options below.
- **Credential audience escape.** A credential is bound to its connection's canonical resource URI and base path; the broker refuses to send it anywhere else.

## Private and enterprise endpoints

Endpoints that legitimately live on private networks use one of:

1. **Customer-controlled deployment / BYOC** — the customer runs fluidbox where the endpoint is reachable;
2. **A customer-side outbound relay** — the private endpoint dials out; the hosted broker never dials in; or
3. **A specifically approved private-network connector** — approval is specific to the connector, never a general capability; the approval mechanics are deliberately not settled by this document.

## Sandbox stdio class

The stdio tool class exists only **inside the sandbox**: curated, credential-free MCP servers packaged into the first-party runner images, contained by the sandbox boundary. This is the surviving role of `capability_bundles` (settled).

If user-supplied stdio servers inside sandboxes are ever supported, each requires: explicit installation consent; a pinned artifact digest; a signed or verified package policy; minimal filesystem mounts; no default network; resource limits; and full command transparency. None of that is in v1.

## Admission and verification lifecycle

    admit definition ──▶ create connection (one authorization grant)
                              │
                              ▼
                     photograph tools/list
             (validated: ANSI/zero-width screening, size bounds;
              incomplete pagination ⇒ discovery fails)
                              │
                              ▼
                append-only connection tool snapshot
                              │
                              ▼
                          active — bindable

- **Photograph discipline.** Registration-time `tools/list` runs its own short-lived client session under the connection's credential. The photograph is connection-specific: two users connected to the same URL may legitimately see different tools (accounts, plans, scopes, resource selections differ).
- **Snapshots are append-only.** Reauthorization or a deliberate refresh may create a new snapshot; an in-flight run never gains newly advertised tools (invariant 14).
- **Reauthorization is fail-closed on identity.** Deciding "same account" requires a positively proven external account identity. When identity cannot be proven identical, `authorization_generation` bumps and runs bound to the old generation fail closed. "Probably the same account" never preserves a generation.
- **Snapshot staleness.** Binding may enforce an optional per-connector or per-tenant maximum snapshot age; a too-stale snapshot fails binding visibly ("refresh required"). The default is no age limit — staleness is a UX concern, not a safety one, because a vanished tool already fails visibly at call time.
- **Insufficient scope is terminal, never auto-escalated (shipped, Phase E).** An SEP-835 `insufficient_scope` challenge on a 401/403 fails the call with no re-mint and no retry, and evicts the cached token. **For an OAuth connection** it also sets the connection to `status='error'` with the note `insufficient_scope: reconnect with more scopes` (the scopes the server asked for are recorded in the note only), under an `authorization_generation` CAS so a challenge from a superseded generation cannot mark a reconnected connection. **For a STATIC credential (API key / custom header / Basic) the connection is deliberately NOT marked**: there is no scope grant to widen, the reconnect remedy is not actionable, and — since a hostile server chooses its own `WWW-Authenticate` header — marking would hand any upstream a one-header kill switch on an org's connection. The call is terminal either way. The broker never escalates a frozen grant. **Consequence worth knowing:** the refusal is a definitive upstream response, so its execution claim settles `failed_upstream` — terminal and not re-claimable. After the owner reconnects with more scopes, a replay of the *same* `tool_call_id` + arguments adopts the stored refusal; a fresh model turn (new `tool_call_id`) proceeds normally.
- **Revocation is immediate.** Revoking a connection prevents future secret reads and fails active-run calls visibly. Every credentialed use rechecks live status, generation, and (for user-owned connections) the owner's active tenant membership immediately before secret access.

## Abuse controls at the egress plane

- **Rate limits (shipped, Phase E):** three *independent* token buckets — per tenant, per connection, per upstream host — checked before each brokered dial. All three are peeked before any is charged, so a refusal costs nothing; `0` on a dimension disables that dimension (it never means "block everything"). Knobs: `FLUIDBOX_EGRESS_RATE_{TENANT,CONNECTION,HOST}_PER_MIN` (defaults 120 / 60 / 120). **Per-user limiting is not implemented** — the tenant bucket is the coarser stand-in.
- **Circuit breakers (shipped, Phase E):** keyed `(connection, upstream host)` — strictly finer than per-connection. They count *transport* failures only (connect refused, timeout, mid-stream read failure, refused redirect, inadmissible URL, HTTP 5xx); a JSON-RPC error, a 4xx, a 401/SEP-835 challenge, or a tool result that merely reports `isError` all mean the upstream is **healthy** and never trip it. Open for `FLUIDBOX_EGRESS_BREAKER_OPEN_SECS` (default 60) after `FLUIDBOX_EGRESS_BREAKER_THRESHOLD` (default 5) consecutive failures, then one half-open probe carrying a deadline so a lost probe cannot wedge it shut.
- **Both are per-replica, in-memory.** With N replicas the deployment-wide ceiling is N× the configured value — the same class as the pre-existing per-replica `MINT_BUDGET`. They are a fairness/abuse control, not a quota system; durable cross-replica limiting is Phase F.
- A refusal from either lands as a **`failed_before_send` execution claim** (positively never sent, therefore re-claimable) and surfaces to the model as a retryable tool error naming the scope and a retry delay, with the host as a `sha256:` digest — never the raw host.
- Shared upstream HTTP transport carries no ambient state — no cookie jars (the `cookies` feature is off workspace-wide), no cached per-host authentication; every request's authority comes from its binding resolution alone (invariant 22).
- Logs record destination identity and digests — never tokens or payloads.

## What admission never grants

An admitted connector definition, by itself:

- holds no credential and cannot be called;
- appears in no run until an agent revision requires it **and** a run binding resolves a concrete, active, authorized connection for it;
- confers no policy permission — the frozen set says what *exists* for a run; policy and approvals say what is *allowed*; the sandbox boundary says what is *impossible*; and
- is never trusted content: descriptions, annotations, arguments, and results from any connector are untrusted input end to end (invariant 13), and names and schemas are additionally screened and validated at the registration photograph.

## Related documents

- [Product compatibility matrix](product-compatibility-matrix.md) — the supported protocol and product surface
- [Hosted network architecture](network-architecture.md) — where the broker and egress proxy sit
- [Threat model](threat-model.md) — the adversaries these rules exist for
