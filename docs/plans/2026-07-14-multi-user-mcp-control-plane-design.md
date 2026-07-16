# fluidbox — multi-user MCP control plane and brokered sandbox design

**Date:** 2026-07-14  
**Status:** FINALIZED v3 (2026-07-16) — v2 after joint adversarial review by Claude (Fable 5) and Codex (GPT-5.6-sol, max reasoning), v3 after an independent post-finalization review (Claude, Fable 5) re-verifying every current-state claim against the code and the ratified MCP `2025-11-25` changelog; current brokered-MCP foundation exists, multi-user tenancy is not implemented  
**Audience:** fluidbox maintainers, security reviewers, and engineers implementing hosted multi-user support  
**Relationship to other docs:** `PLAN.md` remains authoritative for product invariants and milestone direction. `docs/ARCHITECTURE.md` describes the current run path. `docs/guides/capabilities.md` documents the currently shipped capability-bundle behavior. This document defines the target connection, tenancy, and MCP-session architecture for a hosted deployment with approximately 300 users.

## Executive verdict

The proposed architecture can support 300 users comfortably.

The number of users and MCP connection records is not the difficult scaling problem. The difficult problem is proving, for every tool call, that fluidbox used:

1. the correct tenant,
2. the correct invoking or delegated identity,
3. the correct frozen tool snapshot,
4. the correct policy and approval context, and
5. the correct upstream credential without exposing it to the sandbox.

The current checkout has the correct brokered-MCP skeleton:

- versioned capability bundles,
- registration-time `tools/list` photographs,
- frozen per-run capability schemas,
- a sandbox-local broker shim,
- a single server-side tool gate,
- sealed OAuth/static credentials, and
- control-plane-side `tools/call`.

It is not yet a safe multi-user SaaS. It currently has one admin credential, one boot-selected tenant, tenant-owned rather than user-owned connections, and capability bundles that embed a concrete `connection_id`.

The central architectural change is:

> Separate connector definition, credential-bearing connection, agent connection requirement, and per-run resource binding.

The model may choose a tool from the run's exposed tool set. It must never choose the credential or identity used to execute that tool.

## Goals

This design must support:

- approximately 300 registered users in one or more organizations;
- personal MCP connections owned by individual users;
- organization-managed service connections;
- shared agent definitions that bind to different connections per invocation;
- manual, API, webhook, and scheduled runs through the same governed run path;
- no upstream MCP credentials in sandboxes;
- no direct sandbox-to-external-network path in hosted mode;
- immutable and auditable run-time capability resolution;
- immediate fail-closed revocation;
- horizontally scalable control-plane and broker replicas; and
- remote Streamable HTTP MCP servers chosen from a curated catalog or admitted as custom endpoints.

## Non-goals for the first multi-user release

The initial hosted release should not attempt to support:

- arbitrary user-supplied `stdio` installation commands in the control plane;
- transparent access to an MCP process running on a user's laptop;
- the complete MCP resources, prompts, sampling, elicitation, and tasks surface;
- personal credentials in unattended schedules without explicit offline delegation;
- dynamic mid-run expansion of the tool set; or
- sharing an upstream MCP session between users or runs.

Tools over Streamable HTTP are the initial protocol boundary. Other MCP primitives can be added after their authorization and user-interaction semantics are designed explicitly.

## Terminology and protocol roles

The latest stable MCP specification at the time of this design is `2025-11-25`.

MCP defines:

- **Host:** the AI application coordinating model context and one or more MCP clients.
- **Client:** a protocol participant maintaining a 1:1 logical relationship with an MCP server.
- **Server:** a process exposing tools, resources, prompts, or other MCP primitives.

In fluidbox, the role depends on which hop is being described.

### Sandbox hop

- Host: Claude Agent SDK or Codex.
- Client: the harness's MCP client instance.
- Server: the sandbox-local fluidbox broker shim.
- Transport: `stdio`.

### Upstream hop

- Client: the fluidbox control-plane broker.
- Server: the remote Notion, GitHub, Slack, customer, or other MCP service.
- Transport: Streamable HTTP.

The broker shim is therefore an MCP server façade to the harness. It forwards a normalized intent to fluidbox over an internal HTTP API. The Rust broker then creates the real upstream MCP client interaction.

## High-level architecture

    User / browser
         │
         │ login, connector selection, OAuth consent
         ▼
    ┌──────────────────────────────────────────────────────────────┐
    │ Management control plane                                   │
    │                                                              │
    │  Identity / organizations / memberships / RBAC              │
    │  Connector catalog                                           │
    │  Connection registry + KMS-backed credential custody         │
    │  Agent definitions + connection requirements                 │
    │  Run creation + frozen RunSpec + resource bindings           │
    │  Policy / approvals / audit                                  │
    └──────────────────────────────┬───────────────────────────────┘
                                   │
                                   │ schemas + aliases +
                                   │ audience-scoped run credentials
                                   │ never upstream URL or credential
                                   ▼
    ┌──────────────────────────────────────────────────────────────┐
    │ Per-run sandbox                                             │
    │                                                              │
    │  Claude/Codex host and model                                 │
    │       │                                                       │
    │       │ MCP stdio                                            │
    │       ▼                                                       │
    │  fluidbox broker shim                                        │
    └──────────────────────────────┬───────────────────────────────┘
                                   │
                                   │ internal HTTPS
                                   │ tool-intent credential + tool intent
                                   ▼
    ┌──────────────────────────────────────────────────────────────┐
    │ Governed MCP egress plane                                   │
    │                                                              │
    │  Session authentication                                      │
    │  Intent → budget → frozen set → schema → trust tier →        │
    │  policy → approval → execution claim                          │
    │  Connection status / generation / membership check            │
    │  OAuth access-token mint or static-secret resolution         │
    │  Per-run upstream MCP client/session                          │
    │  Egress proxy, SSRF controls, rate limits, circuit breakers  │
    └──────────────────────────────┬───────────────────────────────┘
                                   │
                                   │ Streamable HTTP + audience-bound token
                                   ▼
                           Remote MCP server

The remote MCP server is normally not deployed by fluidbox. Fluidbox brokers and governs access to an already deployed remote endpoint.

## Current implementation flow

### 1. Create a connection

An `integration_connections` row represents fluidbox's authorized relationship with an external service. It stores:

- tenant,
- provider,
- external account identifier,
- granted scopes,
- selected resources,
- status,
- metadata, and
- an AEAD-sealed credential.

OAuth connections store the rotating refresh token sealed at rest. Access tokens are minted at call time and cached only in memory.

### 2. Photograph the tools

Capability registration calls upstream `tools/list` using the connection credential. The returned names, descriptions, schemas, and annotations are validated and frozen into an append-only capability-bundle version.

This photograph is connection-specific. Two users connected to the same MCP URL may receive different tools because their accounts, scopes, plans, or resource selections differ.

### 3. Freeze the run

At run creation, fluidbox:

- resolves the agent revision's pinned bundles,
- intersects subscription and invocation keep-lists,
- removes all MCP tools for read-only trust,
- verifies each concrete connection is active, and
- freezes full schemas and digests into the immutable `RunSpec`.

### 4. Provision a stripped sandbox manifest

The orchestrator sends the sandbox:

- brokered server alias,
- frozen tool name,
- description,
- input schema, and
- one run-scoped fluidbox session token.

It deliberately strips:

- upstream URL,
- connection ID,
- connection owner,
- OAuth metadata, and
- upstream credential.

### 5. Let the model emit an intent

The model sees tools such as:

    mcp__notion__search
    mcp__github__create_review

Selecting a tool does not authorize it. It only creates a tool-call intent.

### 6. Gate and execute

The local broker shim forwards the intent to:

    POST /internal/sessions/{id}/tools/call

The control plane (order matches `internal.rs::decide_tool_call` — budgets are
enforced BEFORE the capability check, so a budget-exhausted run never leaks
whether a probed tool exists in its frozen set):

1. authenticates the run token and binds the request to its session;
2. registers the tool-call intent (idempotent by `(session, tool_call_id)`,
   digest-bound — a reused ID with different content is a protocol violation);
3. enforces the tool-call budget;
4. checks the frozen capability set;
5. validates arguments against the frozen input schema (target state; see
   Gap 12);
6. checks trust tier;
7. evaluates policy and autonomy;
8. waits for or applies the approval decision;
9. takes the execution claim, conditional on the session still being
   nonterminal (target state; see Gap 11);
10. rechecks the connection's live status (current — the broker fresh-reads
    the row and refuses non-`active`; `broker.rs`), plus its authorization
    generation and owner membership (target state — neither field exists
    yet; Phases B/C);
11. resolves the credential; and
12. calls upstream `tools/call`.

The result returns through the shim to the model. The ledger stores identities, decisions, latency, and digests, not secrets or raw payloads.

## The multi-user connection model

The following objects must be independent.

### Connector definition

Scope: curated definitions are global reference data; **custom definitions
are tenant-scoped** and governed by RBAC. One tenant admitting a custom
endpoint must never make it visible or bindable to another tenant.

Contains:

- canonical MCP endpoint or endpoint template;
- transport;
- OAuth discovery expectations;
- authentication modes;
- verification tier;
- categories, icon, and display copy;
- optional tool hints; and
- egress classification.

It contains no user credential and grants no authority.

Catalog data remains untrusted reference data. A catalog entry being displayed or marked curated does not bypass connection verification, tool-schema validation, policy, or approval.

Migration note: today's `connector_catalog` is a global, tenant-less table
whose custom rows were admitted by the single boot tenant. Hosted bring-up
backfills every existing custom row to a concrete owning tenant (curated
rows stay global); a custom row that cannot be attributed is disabled,
never inherited by every tenant.

### Connection

Scope: one organization or one user inside an organization.

A connection represents one authorization grant and the maximum authority fluidbox may exercise through that grant.

Required ownership fields:

    tenant_id
    owner_type        # organization | user
    owner_user_id     # null for organization-owned connections
    created_by_user_id

Required identity and authority fields:

    connector_definition_id
    canonical_resource_uri
    external_account_id
    external_account_display
    auth_kind
    secret_ref or encrypted credential
    granted_scopes
    resource_selection
    status
    authorization_generation

`authorization_generation` changes when reconnecting would change the logical account, issuer, audience, or grant. Ordinary refresh-token rotation remains inside the same generation.

**Generation determination is fail-closed.** Deciding "same account" requires a positively proven external account identity, and arbitrary MCP servers are not obligated to expose one. When identity cannot be proven identical across a reauthorization, the generation bumps — in-flight runs bound to the old generation fail closed. "Probably the same account" never preserves a generation.

### Connection tool snapshot

Scope: one version of one connection's discovered surface.

Required fields:

    connection_id
    snapshot_version
    authorization_generation
    protocol_version
    tools_json
    tools_digest
    discovered_at

Snapshots are append-only. Reauthorization or a deliberate refresh may create a new snapshot, but an in-flight run never gains newly advertised tools.

Binding may enforce an optional per-connector or per-tenant maximum snapshot
age; a too-stale snapshot fails binding visibly ("refresh required") rather
than resolving against a surface the upstream may long since have changed.
The default is no age limit — staleness is a UX concern, not a safety one,
because a vanished tool already fails visibly at call time.

### Fate of capability bundles (settled)

`capability_bundles` survives **only** for sandbox-class, in-image `stdio`
tools. Brokered tools move completely to:

1. immutable agent connection requirements;
2. per-connection tool snapshots; and
3. per-run resource bindings.

Brokered `name@N` pinning becomes redundant: the immutable agent revision
already pins the required tool names, and the run binding pins the exact
connection snapshot and authorization generation. Keeping connection-neutral
brokered bundles would duplicate `required_tools` and create two competing
sources of authority. The conceptual invariant — capability availability ≠
policy permission — is unchanged; only its persistence model changes.

Migration must be additive:

- Retain legacy `CapabilityServer::Brokered` deserialization for historical
  RunSpecs; never rewrite historical agent revisions or RunSpecs.
- Reject new brokered bundle publication after cutover.
- Rediscover each legacy connection into a real connection tool snapshot —
  do not backfill legacy photographs (they have no trustworthy negotiated
  protocol version).
- Append migrated agent revisions containing sandbox bundle refs plus
  brokered requirements.
- Explicitly repoint pinned subscriptions.
- After a cutoff, refuse new runs from unconverted legacy revisions.

### Agent connection requirement

Scope: immutable agent revision.

An agent declares what it requires, not whose credential should satisfy it.

Example:

    slot: github
    connector: github-mcp
    required_tools:
      - get_pull_request
      - search_code
      - create_review
    binding_mode: invoking_user

The requirement may narrow authority from the connection snapshot but can never widen it.

**Satisfaction semantics (settled): `satisfaction: all`, fail closed.** Every
`required_tools` entry must exist in the selected connection's current tool
snapshot or binding fails at run creation — before model spend or sandbox
provisioning. The connection may advertise additional tools; the effective
run surface is exactly the required set. The field is named `required_tools`
(not `allowed_tools`) because it is a contract, not a maximum. Silent
narrowing to an intersection is prohibited: the same shared agent must not
behave differently per user without a visible signal. A later
`optional_tools` feature may permit declared-optional tools, where a missing
optional tool produces a visible audit event at binding time.

**Schema divergence (settled).** The same tool name may carry different
schemas on different connections (accounts, plans, and scopes differ). The
per-connection schema and digest frozen into the run binding ARE the run
contract:

- Name-only policy rules work across schema variants.
- A policy rule that inspects MCP argument fields must be checked against the
  bound schema at run creation; a missing path or incompatible type fails the
  binding — it never silently makes the rule non-matching.
- For v1, keep MCP policy rules name-only, or require an exact expected
  schema digest for field-aware rules.

### Run resource binding

Scope: exactly one run.

Run creation resolves each requirement to an authorized resource binding — its authority source explicit and frozen — before model spend or sandbox provisioning.

**The binding model is not MCP-only (settled).** The same identity question —
*whose credential executes this?* — exists for the git workspace fetch and
for result publishing (PR comments, checks, callbacks). One binding service
and one normalized `run_resource_bindings` model cover all of them, with
typed slot kinds:

    mcp              # brokered MCP tool calls
    workspace_fetch  # credentialed clone/fetch during workspace init
    result_publish   # comments, checks, and result destinations

Requirements originate from different places — MCP slots from the immutable
agent revision; workspace slots from the revision default, subscription,
trigger, or invocation; publish slots from the subscription/result-destination
configuration — but all resolve through the same service and freeze the same
way. The orchestrator, MCP broker, and delivery worker consume the **binding
ID**, never a `connection_id` embedded in a user-controlled `WorkspaceSpec`
or `ResultDestination`.

A connection may satisfy multiple slots, but each slot gets independent
purpose/resource authorization: GitHub clone access does not automatically
imply comment/check publishing.

The binding's authority source is a tagged union — a nullable
`connection_id` cannot represent all three legitimate cases:

    authority_kind = connection          # an integration_connections grant
                   | subscription_secret # signed-webhook/callback secrets,
                                         #   which stay subscription-owned
                   | none                # explicitly credentialless (public
                                         #   repo, open destination) — never
                                         #   an implicit missing value

`subscription_secret` authorities version too: rotating a subscription's
signing or callback secret bumps its `authority_generation` exactly as a
connection reauthorization does — invariant 7 spans every credential-bearing
authority kind, not only connections.

Required fields:

    tenant_id
    run_id
    requirement_slot
    slot_kind          # mcp | workspace_fetch | result_publish
    authority_kind     # connection | subscription_secret | none
    authority_id       # connection or secret reference; null for none
    authority_generation
    connection_owner_type       # connection kind only
    connection_owner_user_id    # connection kind only
    connection_tool_snapshot_version   # mcp slots only
    effective_tools_json               # mcp slots only
    effective_tools_digest             # mcp slots only
    resource_scope     # frozen repo/ref/target/destination for this slot.
                       #   workspace_fetch / result_publish: mechanically
                       #   enforced on every use. mcp: records the
                       #   connection's frozen resource_selection and is
                       #   enforced by the upstream grant — fluidbox never
                       #   re-derives resources from tool arguments (that
                       #   is the policy layer's job)
    resolved_by_principal_kind  # user | trigger | schedule | webhook | system
    resolved_by_principal_id
    binding_mode
    created_at

These rows are the authoritative answer to:

> Whose identity will execute this tool call, this fetch, or this publish?

### Upstream MCP session

Scope: one run resource binding (`mcp` slot) and one remote MCP server.

Suggested key:

    tenant_id + run_id + run_resource_binding_id + server_id

(`server_id` earns its place only where a connector definition's endpoint
template fans one connection out to multiple concrete servers; for
single-endpoint connectors it is redundant with the binding — harmless, and
kept for the templated case.)

Contains:

- negotiated protocol version;
- optional `MCP-Session-Id`;
- server capabilities;
- creation and expiry timestamps; and
- worker ownership or routing metadata if server-to-client streaming is supported.

An upstream MCP session must never be shared across users or runs. HTTP/TLS connection pools may be shared only because nothing identity-bearing rides them — a requirement (invariant 22), not an observation: shared clients disable cookie stores and any connection-scoped authentication caching. One upstream `Set-Cookie` landing in a shared jar would turn "transport optimization" into cross-tenant session state.

## Binding rules

### Invoking-user binding

Use the active personal connection owned by the authenticated user who starts the run.

Appropriate for:

- dashboard runs;
- authenticated API runs; and
- interactive user workflows.

If the user has no unambiguous matching connection, run creation fails before provisioning. Never choose the latest connection silently.

### Organization-service binding

Use an administrator-managed organization connection.

Appropriate for:

- schedules;
- webhooks;
- organization-wide agents;
- GitHub App installations;
- internal service accounts; and
- other unattended automation.

### Explicit binding

The caller supplies a connection ID, but fluidbox verifies that:

- it belongs to the same tenant;
- the caller may use it;
- it satisfies the requirement;
- its scopes/resources are sufficient;
- its status is active; and
- its current tool snapshot contains the required tools.

### Delegated personal binding

A user may explicitly delegate a personal connection to:

- a named agent;
- a team;
- a trigger subscription; or
- a schedule.

Delegation must include:

- allowed tools;
- allowed resources;
- whether unattended execution is permitted;
- expiry;
- revocation state; and
- behavior when the owner loses organization membership.

The first multi-user release should omit unattended personal delegation unless a concrete customer requirement demands it.

## Identity invariants

The following identities are independent:

1. **Invoking user:** started the run.
2. **Connection owner:** owns the upstream authorization grant.
3. **Approver:** approved a risky action.
4. **Agent author:** created the agent revision.
5. **Trigger principal:** caused an API, webhook, or schedule invocation.

Approval means:

> Permit this proposed action under the credential already frozen into the run.

Approval must never mean:

> Execute this action using the approver's credential.

The model, approval handler, and broker may not dynamically replace a run's resource bindings.

### Approval authorization (v1, settled)

- Every approver must hold an active membership in the run's tenant.
- Members receive `approval.decide_own`: they may approve their own
  invocation when the call is credentialless or uses only their own personal
  connection. Self-approval is allowed within these rules; four-eyes approval
  can later be a policy option.
- `approver`, `admin`, and `owner` roles receive `approval.decide_org`: they
  may approve visible runs whose call authority is an organization-owned
  connection or a `subscription_secret` — every non-personal arm of the
  authority union. `approval.decide_org` implies `runs.read_all`: a role
  whose purpose is deciding approvals can always see the run it must judge.
- No tenant role — including admin — implicitly authorizes positive approval
  under another user's **personal** connection. Since unattended personal
  delegation is omitted in v1, Bob can never approve a call executing under
  Alice's personal connection.
- The API derives `decided_by_user_id`, membership, and role from the
  authenticated principal; request-supplied `decided_by` is removed.
- Session-scoped approval grants are keyed by run binding, authorization
  generation, tool, and policy scope — never a loose tool name.

### Run visibility (v1, settled)

Every session, event, artifact, approval, and SSE query enforces `run.read`:
users can read their own runs; trigger principals only the runs created by
that exact token; holders of `subscriptions.manage` (admin and owner by
default) the runs of subscriptions they manage; and memberships with
`runs.read_all` — which `approval.decide_org` implies — all tenant runs.
Connection ownership and agent authorship alone do not grant timeline
access.

## Personal connection example

Shared agent:

    name: pr-reviewer
    requirement slot: github
    binding mode: invoking_user

Alice starts the agent:

    github → Alice connection 0a12... → snapshot 4 → auth generation 1

Bob starts the same agent:

    github → Bob connection 9f81... → snapshot 2 → auth generation 3

The two sandboxes may receive identical aliases and schemas, but their `RunSpec` bindings point at different connection identities. The broker resolves the connection only from the authenticated session's frozen binding.

A nightly schedule using this agent cannot use an `invoking_user` rule because no interactive user exists. It must bind to an organization-owned GitHub App/service connection or an explicit unattended delegation.

## OAuth and credential lifecycle

### Interactive personal OAuth

1. An authenticated fluidbox user selects Connect.
2. The control plane creates a pending connection with tenant and owner.
3. The control plane probes the MCP endpoint and discovers RFC 9728 protected-resource metadata.
4. It discovers authorization-server metadata through RFC 8414 or OIDC.
5. It resolves a pre-registered, CIMD, or DCR OAuth client identity.
6. It creates authorization-code + PKCE parameters with RFC 8707 `resource=`.
7. The opaque state binds tenant, initiating user, connection, PKCE verifier, redirect URI, nonce, expiry, and the initiating browser session (per-flow cookie; see below).
8. The callback consumes that state exactly once — and only from the browser that initiated the flow.
9. The control plane exchanges the code and seals the rotating refresh token.
10. It initializes an MCP client and photographs `tools/list`.
11. The connection becomes active.

The callback may remain unauthenticated at the HTTP route because browser redirects cannot carry the API token, but the state must authenticate and bind the complete initiating context.

**State binding is stronger than confidentiality (settled).** One-time
consumption must be a server-side row — store a state hash/nonce with
`consumed_at`; an AEAD-sealed but stateless value is replayable. The state
row must bind: expected issuer, authorization/token endpoints (or a metadata
digest), client registration, canonical resource URI, redirect URI, tenant,
initiating user, connection, authorization generation, the PKCE **verifier**
(stored encrypted or by secret reference — the challenge alone cannot
perform the token exchange) plus the `S256` method/challenge for
verification, nonce, and expiry. Binding the discovered endpoints at
start-time closes
authorization-server mix-up attacks and discovery-change races between start
and callback.

**The callback must also prove the completing browser started the flow.**
One-time consumption alone does not stop cross-user grant injection: an
attacker starts Connect on their own pending connection, lures a victim into
consenting on the authorization server, and the victim's browser completes
the attacker's flow — sealing the victim's refresh token into the attacker's
connection. The flow completed exactly once, just by the wrong human. Reuse
the GitHub App flows' defense verbatim: a per-flow `HttpOnly` cookie minted
at start whose hash sits inside the one-time claim predicate — a leaked
authorization URL can then neither complete nor burn the flow — and show the
connected external account for human confirmation before the connection
activates.

### OAuth client identity versus user grant

OAuth client registration and end-user grants are different objects.

One hosted fluidbox OAuth client registration can usually serve many user grants:

    fluidbox OAuth client registration
      ├── Alice refresh-token grant
      ├── Bob refresh-token grant
      └── Carol refresh-token grant

Do not dynamically register a new OAuth client per connection unless the authorization server requires it. Store reusable client registrations separately, keyed by issuer, redirect URI, deployment, and optionally tenant.

Per-tenant OAuth client registrations provide stronger blast-radius isolation but increase operational overhead. Pre-registered or CIMD identities should be the default for curated connectors.

### Machine-to-machine authorization

Organization service connections may use the MCP OAuth client-credentials extension (SEP-1046) where the upstream supports it — noting SEP-1046 is not part of the ratified `2025-11-25` revision, so by this design's own no-candidate-semantics rule (Gap 8) that work is gated on ratification status. Prefer asymmetric JWT assertions when mature and interoperable; support client secrets only as a compatibility path.

### Token rotation

Freeze the logical authorization grant and generation, not access-token bytes.

- Access tokens are short-lived and may be cached.
- Refresh tokens may rotate after every refresh.
- A refresh-token rotation stays within the same authorization generation.
- Reauthorization to a different account, issuer, audience, or resource creates a new generation.
- A run bound to an old generation fails closed rather than silently using the new identity.

### Revocation

Run immutability does not override emergency revocation.

Before **every credentialed use of a run resource binding** — a brokered MCP
call, a workspace fetch, or a result publish — check, immediately before
secret access:

- connection/authority status;
- authorization generation;
- for user-owned connections, **unconditionally** that the owner still holds
  an active tenant membership and any delegation remains valid (never "where
  applicable");
- that the invoking principal — or the triggering subscription/token
  authority — is still valid before new privileged work;
- the exact frozen resource scope for that slot (mechanically for
  `workspace_fetch`/`result_publish`; for `mcp` the scope records the
  frozen resource_selection, enforced by the upstream grant); and
- tenant ownership.

Revoking a connection immediately prevents future secret reads and fails active-run calls visibly.

Git fetch credentials must not follow cross-origin redirects and must not
reach submodule or LFS endpoints without a separate admission decision and
binding — a clone of an admitted repo is not authority over arbitrary hosts
its metadata points at.

## Tenant and application authentication

### Hosted principals

Replace the global admin token with a verified principal. Principals are a
closed set of variants — a trigger token is never modeled as a fake user:

    UserPrincipal    { tenant_id, user_id, membership_id, roles,
                       authentication_strength, session_id }
    TriggerPrincipal { tenant_id, token_id, subscription_id }
    SchedulePrincipal, WebhookPrincipal, SystemWorkerPrincipal — likewise
    distinct, each carrying explicit tenant context.

The Rust control plane derives the principal from OIDC/session
authentication (or token verification for trigger/webhook variants). The
browser must not supply `tenant_id` or `user_id` as trusted request fields.
The exact trigger token ID is stored on each invocation so one token can
poll only the runs it created.

### Database isolation (settled: repository methods primary, RLS as depth)

Every query must scope authorization in SQL rather than fetching globally by UUID and filtering afterward.

**Primary mechanism: tenant-scoped repository methods.** Every normal
`fluidbox-db` method requires a `TenantScope` (or tenant-aware transaction)
in its signature — `get_session(scope, id)`, `get_connection(scope, id)`,
`decide_approval(scope, id, principal)`, `events_after(scope, session, …)`.
Generic UUID-only methods are forbidden outside narrowly named system-worker
repositories. For a sqlx + repository codebase this is easier to review,
test, and use from cross-tenant background workers than making correctness
depend on every pooled connection carrying the right `SET LOCAL` context.

Defense in depth on top:

- Postgres row-level security, enabled with a non-`BYPASSRLS` API role that
  also does **not own the tables** (owners bypass RLS by default) — use a
  non-owner runtime role or `FORCE ROW LEVEL SECURITY`; global workers use
  a separate audited role with explicit tenant resolution;
- composite tenant foreign keys — `(tenant_id, id)` unique keys and FKs are
  **mandatory** for all tenant-owned relationships, not "where practical"
  (today's UUID-only FKs cannot relationally guarantee a session's tenant
  matches its agent's);
- run creation writes the session, invocation claim, resource bindings,
  frozen snapshot references, and run token in ONE transaction — the jsonb
  RunSpec is an audit photograph, not an authorization relation;
- cross-tenant negative tests for every resource family; and
- queue/background-worker messages that carry a signed or database-resolved
  tenant context.

UUID unpredictability is not authorization.

### Cache and lock keys

All distributed caches and locks must be keyed by tenant and connection identity:

    tenant_id + connection_id + authorization_generation

Connection UUIDs are already globally unique, but explicit tenant context prevents future programming errors and makes observability safer.

## Network and trust boundaries

### Hosted sandbox

The hosted sandbox must have no general internet route.

Allow only:

- the internal fluidbox run gateway;
- explicitly designed artifact/workspace channels; and
- substrate control endpoints required by the execution provider.

The sandbox receives:

- task and system prompt;
- workspace;
- frozen tool schemas;
- connection aliases;
- audience-scoped run credentials (LLM, tool-intent, and runner-control,
  each reaching only its own endpoints); and
- tool results.

It never receives:

- remote MCP URL;
- OAuth access or refresh token;
- API key;
- connection ID;
- connection owner identity;
- OAuth client secret; or
- tenant encryption key.

The current local Docker `HostDev` network is not a hosted security boundary because general egress is constrained by policy rather than structurally denied. Hosted execution must use the hardened network path or an equivalent MicroVM/VPC isolation design.

### Broker egress

The broker is the only component allowed to reach arbitrary admitted remote MCP endpoints.

Required controls:

- HTTPS required in production;
- reject private, loopback, link-local, multicast, reserved, and cloud-metadata addresses;
- validate every redirect target;
- defend against DNS rebinding and time-of-check/time-of-use changes;
- route through an egress proxy or network firewall;
- bind credentials to canonical resource URI and base path;
- restrict custom headers so they cannot overwrite MCP transport headers;
- keep shared HTTP clients ambient-state-free — no cookie jar, no cached
  per-host authentication (invariant 22);
- rate-limit per tenant, user, connection, and upstream host;
- circuit-break unhealthy upstreams; and
- log destination identity and digest without tokens or payloads.

Private enterprise MCP endpoints should use:

- customer-controlled deployment/BYOC;
- a customer-side outbound relay; or
- a specifically approved private-network connector.

Do not let arbitrary custom endpoint URLs turn the hosted broker into a private-network scanner.

### Local and `stdio` MCP servers

A process on a user's laptop cannot be reached directly by a hosted service.

Supported options:

1. Expose it as an authenticated remote Streamable HTTP MCP endpoint.
2. Package a curated, signed, credential-free `stdio` server into the runner image.
3. Run an outbound customer connector that brokers a private endpoint.

Never run arbitrary user-supplied `npx`, shell, or installation commands in the control-plane environment.

If user-supplied `stdio` servers are supported inside sandboxes later, require:

- explicit installation consent;
- pinned artifact digest;
- signed or verified package policy;
- minimal filesystem mounts;
- no default network;
- resource limits; and
- full command transparency.

## MCP session model

### Session creation

The production broker should create a logical upstream client session lazily after the tool call passes the fluidbox gate:

1. resolve the run binding;
2. validate live connection status/generation;
3. resolve or mint the access token;
4. send `initialize` as the first MCP interaction;
5. validate the negotiated protocol version and server capabilities;
6. send `notifications/initialized`;
7. call the frozen tool; and
8. persist the optional session ID for later calls in the same run.

Deferring upstream initialization until after policy approval avoids consuming remote resources for denied calls.

Registration-time `tools/list` uses its own short-lived client session and produces a snapshot. A run does not need to call live `tools/list` because the photograph is already frozen.

### Session isolation

Never share an `MCP-Session-Id` across:

- users;
- tenants;
- runs;
- connection authorization generations; or
- differently scoped connections.

Always send the OAuth/static authorization header on every upstream HTTP request. An MCP session ID is routing state, not authentication.

### Session termination and recovery

- Send HTTP DELETE when the run finishes if the upstream supports termination.
- On upstream 404 for an existing session, initialize a new session.
- Do not automatically expand or refresh the run's tool set after reinitialization.
- Treat upstream `notifications/tools/list_changed` as a signal for an out-of-band future snapshot, not as permission to mutate the current run.
- Reject or ignore unadvertised server-to-client capabilities.

### Execution semantics: decision idempotency is not execution idempotency

The intent row makes the *decision* idempotent — a faithful retry re-attaches
to its recorded verdict. That is not enough: after an allow verdict, every
concurrent handler for the same `tool_call_id` could independently call
upstream and execute a write multiple times.

Require a durable execution record keyed by
`(tenant_id, run_id, tool_call_id, input_digest)` with states:

    claimed → succeeded | failed_upstream | failed_before_send | ambiguous

`succeeded` and `failed_upstream` are both completed dispatches with a
definitive upstream outcome — `failed_upstream` is a real response proving
execution was attempted and rejected (an HTTP error status, JSON-RPC error,
or `isError` result). Classifying a definitive upstream failure as
`ambiguous` is wrong (the outcome is proven); as `failed_before_send`,
false (it was sent).

- Only the claim winner may send upstream; duplicates wait for or return the
  stored outcome. Every terminal claim durably stores at least status,
  result digest, and `isError` — the duplicate-return contract depends on
  it; faithful replay of sensitive result bodies may additionally use
  encrypted short-lived storage.
- The guarantee is **at most one fluidbox dispatch attempt** per claim —
  true exactly-once side effects are not achievable over MCP; ambiguity is
  surfaced, never hidden.
- Stale-claim recovery: if a worker dies while `claimed`, the claim moves to
  `ambiguous` unless there is positive proof the request was never sent
  (e.g., a durable pre-send/dispatch boundary). `failed_before_send`
  requires that positive proof; it is never inferred.
- An `ambiguous` outcome is never automatically reclaimed.
- `failed_before_send` IS re-claimable — the positive never-sent proof is
  exactly what makes a fresh dispatch attempt safe. `succeeded` and
  `failed_upstream` are terminal; duplicates adopt the stored outcome,
  never re-execute.
- The claim is taken **conditional on the session still being nonterminal**,
  in the same transaction/row-lock order as cancellation — a run cancelled
  or budget-terminated during a minutes-long approval wait must not execute
  when the approval finally lands. Once a request is in flight, cancellation
  cannot guarantee recall; ledger that case explicitly.

Arguments are validated server-side against the frozen input schema (with
depth/size/resource bounds; external `$ref` resolution rejected — only
self-contained local references) before trust-tier and policy evaluation.
The validator selects its JSON Schema dialect from the snapshot's negotiated
protocol version (`2025-11-25` defaults to JSON Schema 2020-12, SEP-1613); a
`2025-06-18`-era snapshot is never validated under 2020-12 semantics. A
schema rejection is ledgered as a gate denial but surfaces to the model as a
tool-execution-error-shaped result (SEP-1303), so the harness self-corrects
instead of stalling on a protocol error. The sandbox is untrusted;
model-side validation proves nothing.

### Retry semantics

MCP `tools/call` does not generally guarantee exactly-once side effects.

- Never blind-retry a call after an ambiguous network failure.
- A reactive retry after HTTP 401 is safe only because authentication rejection proves the tool did not execute.
- An insufficient-scope challenge (`WWW-Authenticate`, SEP-835 incremental consent) is terminal for the call and marks the connection "reconnect with more scopes" for its owner. The broker never auto-escalates a frozen grant.
- Use upstream idempotency keys when a connector/tool explicitly supports them.
- Ledger ambiguous outcomes as such and let policy, user, or model decide whether to retry.

## Scale model for 300 users

### Assumptions

Planning assumptions, to be replaced with observed pilot data:

- 300 registered users;
- five saved MCP connections per user;
- 10–20% concurrent activity;
- one active run per active user on average;
- three attached MCP servers per active run; and
- single-to-low-tens of brokered calls per second under normal load.

### Derived working set

    Durable connection rows:
      300 users × 5 connections = 1,500

    Normal active sandboxes:
      30–60

    Normal active logical upstream MCP sessions:
      30–60 runs × 3 servers = 90–180

    Full-seat stress case:
      300 sandboxes × 3 servers = 900 logical MCP sessions

The 1,500 connection records and associated snapshots are trivial for Postgres. Active sandbox compute, LLM provider quotas, remote MCP quotas, and audit/event volume will become limiting before the connection table does.

The current Docker provider's 2 GiB per-container cap implies:

    45 concurrent runs → 90 GiB memory-cap envelope
    300 concurrent runs → 600 GiB memory-cap envelope

Actual memory utilization may be lower, but hosted capacity must schedule sandboxes across multiple hosts or a MicroVM provider.

### Recommended deployment shape

For the initial 300-seat deployment:

- two or three stateless Rust API/orchestrator replicas across failure domains;
- a horizontally scalable MCP egress-worker pool with a dedicated secret-access identity;
- shared highly available Postgres;
- Postgres advisory/row locks or Redis for distributed refresh singleflight;
- a multi-host or MicroVM sandbox fleet;
- an egress proxy/firewall;
- per-tenant and per-connection concurrency limits;
- per-upstream circuit breakers;
- centralized audit/metrics/tracing; and
- queue-backed provisioning and terminal delivery work.

The Rust monolith does not need to be split into many microservices merely because there are 300 users. It does need logically separated authority and, ideally, a separately deployable broker worker identity so the dashboard/API surface cannot read every connector secret.

### Multi-replica statelessness inventory

"Two or three stateless replicas" requires making the following
process-local state either DB-authoritative or explicitly coordinated. The
Postgres row is always truth; in-memory structures are latency
optimizations only.

1. **Approval wakeups.** The wait loop already re-reads Postgres on a ≤2 s
   tick (`internal.rs`), so cross-replica approvals are *correct* today with
   ≤2 s added latency; the in-process `Notify` only removes it locally. Ride
   `pg_notify` exactly like SSE: a committed approval transition notifies,
   every replica wakes its local waiters, the polling floor stays as the
   missed-notification backstop. The canonical `approval.decided` ledger
   event is emitted once — by the decision transaction or a uniquely keyed
   transactional outbox — never independently by each awakened waiter.
   (Today each waiter emits its own copy, so two handlers re-attached to
   one pending row already double-ledger inside a single process — a
   current bug the outbox fixes, not merely a multi-replica concern.)
2. **Orchestrator single-status-writer.** Use a claim/lease column —
   `orchestrator_owner_id`, `orchestrator_lease_until`, monotonically
   increasing `orchestrator_epoch` — not a Postgres advisory lock (tied to
   one DB connection; fragile under pool reconnects and Neon scale-to-zero;
   poorly observable). Every lifecycle mutation and external side effect
   carries the epoch as a fencing token. Advisory locks remain acceptable
   for short OAuth-refresh critical sections.
3. **Result deliveries.** The current worker is an explicitly single-process
   sequential loop with no row claim (`deliveries.rs`). Claims must fence
   the external side effect, not merely the final status update. A lease
   prevents concurrent duplicates but not the crash window between remote
   creation and recording the external ID: use provider idempotency where
   available, or reconcile via a deterministic marker before recreating.
4. **Connector-token caches.** Generation-keyed per-replica caches re-mint
   on miss; eviction notification is an optimization — fresh DB
   status/generation validation before serving a cached token is the
   correctness mechanism.
5. **Distributed OAuth refresh serialization** (Gap 4).
6. **Upstream MCP sessions.** Worker ownership/routing metadata so a
   server-to-client stream or session affinity survives replica routing.
7. **Scheduler ticks** — already claim-based via deterministic idempotency
   claims; keep.
8. **Watchdog, budget sweeper, approval expiry** — CAS the terminal verdict
   before performing cleanup/artifact/publication side effects, so a worker
   that lost the transition race never acts.

### Per-tenant LLM quota

Per-run budget stops in the facade do not provide tenant fairness on the
shared gateway. Use **one LiteLLM virtual key per tenant per environment** —
model allowlist, spend/token/rate limits, tenant metadata, rotation — and
have the facade select the key from the authenticated session's tenant. The
LiteLLM master key is used only by a narrow provisioning component, never
for routine model requests. Hosted mode never silently falls back to a
shared direct-provider key. This stays below the replaceable governance
plane (convergence invariant 4); Rust remains authoritative for per-run
budgets and the canonical ledger. A future BYOK model keys quota by billing
principal rather than assuming tenant-wide provider custody.

Separately, the per-run budget check itself is raceable: the facade checks
accumulated usage before forwarding and records usage only after completion,
so concurrent requests can all pass the same remaining budget. Because agent
harnesses legitimately issue parallel model calls (subagents), do NOT
serialize requests per session as the primary fix. Instead:

- take a durable, request-ID-keyed atomic **reservation** of a conservative
  maximum before forwarding, with a finite enforced ceiling on concurrent
  reservations;
- reconcile only from authoritative usage reported by the gateway;
- release a reservation only when non-dispatch is positively proven; and
- on crash/timeout with unknown provider usage, retain the conservative
  charge until reconciliation — never assume zero.

Tenant virtual keys are a backstop, not a fix, for this race.

## Current production gaps

### Gap 1: global admin authentication

Current state:

- one `FLUIDBOX_ADMIN_TOKEN`;
- dashboard proxy injects that token into all requests;
- no user, membership, or role model.

Required:

- OIDC/session authentication;
- organizations and memberships;
- role and connection-use authorization;
- tenant-scoped Rust extractors and DB methods; and
- identity-aware audit fields.

### Gap 2: one boot-selected tenant

Current state:

- `AppState` stores one `tenant_id`;
- handlers use that process-wide tenant.

Required:

- request-derived tenant principal;
- worker jobs that carry explicit tenant context;
- no process-global tenant for hosted mode; and
- cross-tenant DB enforcement.

### Gap 3: capability bundle embeds a concrete connection

Current state:

- `CapabilityServer::Brokered` carries `connection_id`;
- shared agents therefore inherit one fixed connection.

Required:

- connection-neutral agent requirements;
- connection-specific tool snapshots;
- frozen run resource bindings; and
- migration of current attached connections to organization-service requirements.

### Gap 4: process-local OAuth locking

Current state:

- access-token cache is in memory;
- refresh serialization is a Tokio lock inside one process.

Required:

- distributed singleflight or database row locking;
- atomic refresh-token rotation;
- tenant/generation cache keys;
- fresh status checks before serving a cached token; and
- cache eviction on revoke or membership change.

### Gap 5: one deployment credential key

Current state:

- one `FLUIDBOX_CREDENTIAL_KEY` seals all connection credentials.

Required for hosted multi-tenant use:

- KMS-backed envelope encryption;
- per-tenant data-encryption keys or an equivalent isolation boundary;
- key versioning and rotation;
- auditable decrypt permission;
- broker-only decrypt role;
- an explicit re-seal migration off `FLUIDBOX_CREDENTIAL_KEY`: dual-read
  (legacy-unseal, KMS-reseal) over every sealed row — connections, GitHub
  App private keys, webhook and subscription delivery secrets — resumable,
  count-parity verified, the legacy key retired only after 100% re-seal
  (rotating the key without this step orphans every stored credential); and
- tested disaster recovery.

### Gap 6: local-dev network mode

Current state:

- orchestrator provisions `NetworkMode::HostDev`;
- general sandbox egress is not structurally blocked.

Required:

- hardened per-run network;
- internal-only control-plane route;
- no public default route;
- workload identity or mTLS in addition to run bearer tokens; and
- automated negative egress tests.

### Gap 7: SSRF exposure from custom endpoints

Current state:

- URL audience binding protects a credential from being sent outside its configured base;
- OAuth discovery and custom endpoint fetches do not yet constitute a complete SSRF boundary.

Required:

- production HTTPS policy;
- IP/range validation;
- redirect validation;
- DNS rebinding protection;
- egress proxy;
- private-endpoint admission policy;
- the same IP/redirect/DNS validation applied to workspace clone URLs — a
  credentialless (`authority: none`) fetch of a "public" repo still
  executes from the control plane and is still egress; and
- tenant-specific destination allowlists where needed.

### Gap 8: minimal/stateless-first MCP client

Current state:

- the broker attempts `tools/*` directly;
- it initializes only when a server rejects the sessionless call;
- it offers protocol `2025-06-18`;
- it does not own a durable per-run MCP client lifecycle.

Required (the 2025-11-25 conformance contract):

- initialization as the first logical interaction, for discovery and runtime;
- offer `2025-11-25`, maintain an explicit supported-version set, and reject
  unsupported negotiation;
- runtime negotiation must match the snapshot's protocol version unless an
  explicit compatibility adapter exists;
- send `MCP-Protocol-Version` on subsequent requests;
- unique request IDs; serialize/demultiplex concurrent requests within a
  session;
- per-run session manager; shutdown and 404 reinitialization;
- a bounded streaming SSE parser with full event assembly (the current line
  scanner is not one);
- validate HTTP content types, JSON-RPC versions/IDs, and negotiated server
  capabilities;
- select the JSON Schema dialect for all frozen-schema validation from the
  snapshot's protocol version (`2025-11-25` ⇒ JSON Schema 2020-12,
  SEP-1613);
- respond with JSON-RPC errors to unsupported server requests rather than
  silently ignoring requests that may block the server;
- preserve `outputSchema` and `structuredContent`, or explicitly reject
  tools using them (the current snapshot/result path drops both);
- if `nextCursor` remains after the discovery page cap, fail discovery
  rather than freezing a partial list; and
- keep session IDs optional; schedule a pre-GA revalidation checkpoint
  against the next announced protocol revision candidate — do not implement
  candidate semantics before ratification.

### Gap 9: tools-only compatibility boundary is implicit

Current state:

- brokered tools work;
- resources, prompts, sampling, elicitation, notifications, and tasks are not a complete supported product surface.

Required:

- document tools-only support explicitly;
- advertise no unsupported client capabilities;
- conformance-test supported transport and tool behavior; and
- introduce each additional primitive only with a security and UX design.

### Gap 10: one sandbox bearer token holds every audience

Current state:

- the same readable session token reaches the LLM facade, tool gateway,
  events, heartbeat, and result endpoints;
- agent-executed code can read the process environment and impersonate
  runner-control actions.

Required:

- audience-scoped credentials, at minimum separating LLM calls, governed
  tool intents, and runner-control/result/heartbeat operations;
- the runner-control credential protected from agent subprocesses via
  separate OS identities/process boundaries or a sidecar channel — mTLS
  alone does not help when runner and untrusted code share one workload
  identity.

### Gap 11: decision idempotency without execution idempotency

Current state:

- a faithful retry re-attaches to an allowed verdict, after which every
  concurrent handler can independently call upstream;
- session terminality is checked before the approval wait, not before the
  upstream send — a run cancelled during the wait can still execute.

Required: the durable execution claim defined in "Execution semantics"
(claim keyed by tenant/run/tool_call_id/input_digest; nonterminal-session
condition inside the claim; ambiguous outcomes never auto-reclaimed).

### Gap 12: frozen schemas are advertised, not enforced

Current state:

- the gate checks that the tool exists in the frozen set, then passes
  arbitrary JSON to policy and upstream.

Required: server-side argument validation against the frozen schema with
depth/size bounds and no external `$ref` resolution, before trust-tier and
policy evaluation; the dialect selected by the snapshot's protocol version;
rejections surfaced to the model as tool-execution errors (SEP-1303), never
protocol errors.

### Gap 13: process-local lifecycle and delivery workers

Current state:

- the delivery worker is a single sequential loop with no distributed claim;
- watchdog/budget/approval-expiry workers assume one process.

Required: the claims, leases, and epoch fencing defined in the
multi-replica statelessness inventory.

### Gap 14: per-run LLM budget race in the facade

Current state:

- usage is checked before forwarding and recorded after completion;
  concurrent model calls all pass the same remaining budget.

Required: atomic conservative reservation before forwarding with
post-completion reconciliation (parallel subagent calls are legitimate —
do not serialize per session as the primary fix).

## Security invariants

The following are release-blocking invariants:

1. A sandbox never receives an upstream credential.
2. A sandbox never receives the upstream MCP URL or concrete connection ID.
3. A sandbox can reach only the internal fluidbox run gateway in hosted mode.
4. The model chooses only among tools frozen into its run.
5. Model choice never selects or changes a connection.
6. Run creation resolves every requirement to an explicit authority source
   (connection, subscription secret, or none) before model spend.
7. Every credential-bearing slot pins one logical authorization generation;
   `none` slots carry no generation.
8. The approver identity never replaces the credential owner.
9. Every upstream call rechecks live revoke/status state.
10. Every database lookup is tenant-scoped at the query boundary.
11. Upstream MCP sessions are never shared between runs or identities.
12. Credentials are audience/resource-bound and sent only to admitted destinations.
13. Tool descriptions, annotations, arguments, and results are untrusted input.
14. A live upstream tool-list change never mutates an in-flight run.
15. Ambiguous write outcomes are never blindly retried.
16. One execution claim per `(run, tool_call_id, input_digest)` — a decision
    retry never re-executes a write upstream.
17. Tool arguments are validated server-side against the frozen schema
    before policy evaluation.
18. The execution claim is conditional on the session being nonterminal — a
    cancelled run never executes a late-approved call.
19. Sandbox credentials are audience-scoped; the runner-control credential
    is unreachable from agent-executed code.
20. OAuth state is a one-time server-side record bound to issuer, client,
    resource, tenant, user, PKCE context, and the initiating browser
    session (per-flow cookie hash inside the claim predicate) — never a
    stateless sealed value, and never completable by a browser that did
    not start the flow.
21. Workspace fetch and result publishing resolve through run resource
    bindings, never a connection ID carried in user-controlled input.
22. Shared upstream HTTP transport carries no ambient state — no cookie
    jars, no cached per-host authentication; every request's authority
    comes from its binding resolution alone.

## Implementation sequence

### Phase A — define the supported hosted product boundary

Decide and document:

- remote Streamable HTTP tools first;
- curated and admitted custom remote endpoints;
- personal connections for interactive runs;
- organization service connections for schedules/webhooks;
- no arbitrary control-plane `stdio` execution; and
- explicit unsupported MCP primitives.

Deliverables:

- product/compatibility matrix;
- threat model;
- connector admission policy; and
- hosted network diagram.

The following decisions are settled in this document and are Phase A
inputs, not open questions: capability bundles survive for sandbox tools
only (brokered tools move to requirements + snapshots + bindings);
repository methods are the primary tenant-isolation mechanism with RLS as
depth; requirement satisfaction is `all`/fail-closed; binding slots cover
`mcp`, `workspace_fetch`, and `result_publish`.

### Phase B — identity and tenant enforcement

Implement:

- users;
- organizations;
- memberships and roles;
- OIDC/session authentication;
- principal variants (user, trigger, schedule, webhook, system worker) with
  a `Principal` extractor;
- approval RBAC (`approval.decide_own` / `approval.decide_org`) and
  `run.read` visibility;
- tenant/user audit fields;
- tenant-scoped DB methods (`TenantScope` signatures);
- mandatory composite `(tenant_id, id)` keys/FKs plus RLS as depth; and
- dashboard identity/session integration.

Acceptance:

- no global admin token on the hosted browser path;
- cross-tenant negative test matrix passes;
- workers cannot fall back to a default tenant;
- every API/event/artifact route proves tenant ownership;
- approval decisions derive the approver from the principal (no
  request-supplied `decided_by`); and
- a trigger token can poll only runs it created.

### Phase C — connection ownership and run binding

Implement:

- connection `owner_type` and `owner_user_id`;
- authorization generation;
- connection tool snapshots;
- agent connection requirements (`required_tools`, `satisfaction: all`);
- run resource bindings for `mcp`, `workspace_fetch`, and `result_publish`
  slots (orchestrator, broker, and delivery worker consume binding IDs);
- binding resolution service;
- personal/org/explicit binding modes;
- capability-bundle migration (bundles retained for sandbox tools only;
  legacy brokered attachments rediscovered into snapshots; pinned
  subscriptions repointed; historical RunSpecs untouched);
- connector-catalog custom-row tenant backfill (curated rows stay global;
  unattributable custom rows are disabled); and
- connection-use authorization UI.

Acceptance:

- Alice and Bob invoke the same agent and use different connections;
- neither can select or inspect the other's personal connection;
- the model receives identical aliases but the broker resolves the correct binding;
- approval by a third user does not change credential identity;
- missing/ambiguous bindings — including a snapshot missing a required
  tool — fail before sandbox provisioning;
- the workspace clone and result publish use their slot's bound credential,
  never one named in user-controlled input; and
- new runs from unconverted legacy revisions are refused after the cutoff.

### Phase D — OAuth and secret hardening

Implement:

- KMS envelope encryption;
- reusable OAuth client registration objects;
- one-time server-side OAuth state rows binding issuer, endpoints/metadata
  digest, client registration, resource, tenant, user, connection,
  generation, the encrypted PKCE verifier + S256 challenge, nonce, expiry,
  and the initiating browser session (per-flow HttpOnly cookie hash inside
  the claim predicate, exactly as the GitHub App flows already do);
- distributed refresh serialization;
- atomic refresh-token rotation;
- generation-aware token caches;
- revoke and membership-change eviction;
- the legacy-key → KMS re-seal migration (dual-read, resumable,
  count-parity verified);
- per-tenant LiteLLM virtual keys (master key confined to provisioning); and
- machine-to-machine organization connections (gated on SEP-1046
  ratification).

Acceptance:

- concurrent refresh from multiple replicas produces one valid rotation;
- revoke prevents cache hits and secret reads immediately;
- callback cannot activate another user's connection;
- a callback completed by a browser that did not initiate the flow fails
  closed and does not burn the state row;
- connection account change increments generation — as does any
  reauthorization whose account identity cannot be proven identical;
- every legacy-sealed credential is re-sealed under KMS with count parity
  before the legacy key is retired; and
- old-generation active runs fail closed.

### Phase E — broker and network hardening

Implement:

- hosted hardened sandbox networking;
- internal gateway workload authentication and audience-scoped sandbox
  credentials (LLM / tool-intent / runner-control split);
- egress proxy;
- SSRF-safe endpoint validation;
- per-run MCP session manager and the 2025-11-25 conformance contract
  (Gap 8);
- server-side argument-schema enforcement (Gap 12; dialect per snapshot,
  SEP-1303 error surfacing);
- durable execution claims with the nonterminal-session condition and the
  four-state outcome model (Gap 11);
- approval `pg_notify` wakeups, orchestrator leases with epoch fencing, and
  delivery claims (Gap 13);
- per-run LLM budget reservation (Gap 14);
- destination/rate/concurrency policies;
- circuit breakers; and
- safe ambiguous-outcome handling.

Acceptance:

- sandbox cannot reach public internet or metadata endpoints;
- broker cannot reach private/reserved endpoints through direct URLs, redirects, or DNS rebinding;
- session IDs cannot cross run/user boundaries;
- authorization is included on every upstream request;
- denied calls never initialize or contact the upstream server;
- no write call is blindly replayed after timeout;
- a definitive upstream error lands as `failed_upstream`, never `ambiguous`,
  and only `failed_before_send` is ever re-claimed;
- an insufficient-scope challenge fails the call and marks the connection
  for reconnect without automatic scope escalation;
- a duplicated allowed intent results in **at most one fluidbox dispatch
  attempt**, with ambiguity explicit and never silently retried;
- a run cancelled during an approval wait never executes the late-approved
  call;
- agent code cannot reach runner-control endpoints with the LLM or
  tool-intent credential; and
- two replicas deciding/executing concurrently produce at most one dispatch
  per approval/delivery/lifecycle transition, with at-least-once deliveries
  covered by provider idempotency, deterministic-marker reconciliation, or
  receiver dedup.

### Phase F — scale, reliability, and rollout

Load-test:

- 60 concurrent sandboxes;
- 150 concurrent sandboxes;
- 300 concurrent sandboxes;
- 1,500 saved connections;
- OAuth refresh storms;
- connection revocation during active runs;
- upstream 401/404/429/5xx behavior;
- slow approvals;
- broker restart during active sessions;
- parallel model calls across replicas that must not overspend per-run
  budgets (reservation race test);
- database failover; and
- tenant-isolation fuzz/negative cases.

Rollout:

1. internal single-organization environment;
2. 10–25 user pilot;
3. 60-concurrent-run capacity gate;
4. multiple-organization beta;
5. 300-seat production target; and
6. BYOC/private-MCP support after the shared SaaS boundary is proven.

## Operational metrics

At minimum, observe:

- active runs and sandboxes by tenant;
- run provisioning latency;
- active MCP sessions by connection/upstream;
- tool calls allowed, denied, awaiting approval, failed, and ambiguous;
- broker latency by upstream and tool;
- OAuth refresh attempts, races, failures, and invalid grants;
- connection revocations and generation mismatches;
- upstream 401, 404, 429, and 5xx rates;
- egress-policy rejections;
- tool-result truncations;
- queue depth;
- sandbox memory/CPU/runtime;
- database event and ledger write rates; and
- per-tenant/model/MCP cost attribution.

Metrics and traces must use internal IDs and destination identities without recording credentials, authorization codes, full prompts, or raw tool payloads.

## Key trade-offs

### Per-run MCP session versus per-connection session

Decision: use per-run logical sessions.

Benefits:

- strongest identity and state isolation;
- clean run teardown;
- easier audit correlation; and
- no cross-run notification or task leakage.

Cost:

- more initialization calls.

Transport-level HTTP pooling recovers most connection overhead without sharing MCP state.

### Frozen tools versus live `tools/list_changed`

Decision: freeze tools per run.

Benefits:

- reproducibility;
- rug-pull/schema-drift defense;
- stable policy decisions; and
- deterministic model context.

Cost:

- newly added upstream tools require a new snapshot and future run.

### Personal connections versus organization service connections

Decision:

- personal connections for interactive invoking-user workflows;
- organization connections for schedules/webhooks and shared unattended agents;
- personal unattended delegation later.

This keeps the first release understandable and avoids unclear ownership when no user is present.

### Repository methods versus RLS as the primary tenant boundary

Decision: tenant-scoped repository methods primary; RLS as defense in depth.

Repository signatures are reviewable and testable, and background workers
need explicit tenant context anyway; RLS-as-primary makes correctness depend
on every pooled connection carrying `SET LOCAL` state, which is invisible in
code review and fragile under connection pooling.

### Bundles for sandbox tools versus bundles for everything

Decision: capability bundles persist for sandbox (in-image `stdio`) tools
only; brokered tools live in requirements + connection snapshots + run
bindings.

Connection-neutral brokered bundles would duplicate `required_tools` and
create two competing sources of authority for the same tool surface. The
cost is a one-time additive migration of existing brokered attachments.

### Monolith versus service split

Decision: preserve the Rust mono-binary architecture where useful, but establish a separately authorizable broker/worker deployment seam.

Three replicas can handle 300 users without a microservice explosion. Secret decrypt and unrestricted admitted egress should nevertheless belong to a narrow workload identity rather than the entire public API surface.

## Final target lifecycle

    Define agent revision
      + connection requirements
      + required tool subset
              │
              ▼
    User or trigger invokes agent
              │
              ▼
    Authenticate principal and tenant
              │
              ▼
    Resolve each requirement to an authorized resource binding
      (connection, subscription secret, or explicitly credentialless)
              │
              ▼
    Freeze RunSpec, resource bindings, and tool snapshots
              │
              ▼
    Provision fresh sandbox with aliases, schemas, and
      audience-scoped run credentials only
              │
              ▼
    Model emits a tool-call intent
              │
              ▼
    Control plane gates the intent
      (intent → budget → frozen set → schema → trust tier
       → policy → approval)
              │
              ▼
    Execution claim taken, conditional on nonterminal session
              │
              ▼
    Broker rechecks authority status/generation/membership/scope
              │
              ▼
    Broker resolves token and initializes per-run upstream MCP session
              │
              ▼
    Remote MCP executes
              │
              ▼
    Result returns to originating sandbox and decision is audit-ledgered

If any identity, connection, ownership, snapshot, policy, or tenant mapping is missing or ambiguous, the run or call fails closed.

## Acceptance statement

This design is complete when the following sentence is mechanically true:

> A shared fluidbox agent can be invoked by any authorized user or trigger, while every MCP call, workspace fetch, and result publish is executed through the exact personal, delegated, organization, subscription-secret, or explicitly credentialless authority frozen into that run's resource bindings; the sandbox receives only the permitted tool interface and result — never a remote credential, a connection identity, or direct external network authority. Each MCP execution claim causes at most one fluidbox dispatch attempt, with ambiguity surfaced rather than retried; result publishing remains at-least-once, made safe by provider idempotency, deterministic-marker reconciliation, or receiver dedup.

## Revision history

**v3 (2026-07-16)** — independent post-finalization review (Claude, Fable 5).
Every v2 current-state claim was re-verified against the code (all accurate;
one mislabel fixed) and against the ratified MCP `2025-11-25` changelog.
Changes:

- OAuth connect callbacks bind to the initiating browser session — a
  per-flow `HttpOnly` cookie whose hash sits inside the one-time state
  claim predicate, as the GitHub App flows already do — closing cross-user
  grant injection (an attacker-initiated flow completed by a lured victim
  would otherwise seal the victim's refresh token into the attacker's
  connection). Invariant 20 extended; Phase D updated.
- Generation determination made fail-closed: a reauthorization whose
  external account identity cannot be positively proven identical always
  bumps `authorization_generation`.
- Execution claims gained a fourth terminal state (`failed_upstream` — a
  definitive upstream error is a completed dispatch, not ambiguity),
  explicit reclaim semantics (`failed_before_send` re-claimable, terminal
  states never), and a mandatory stored-outcome minimum (status, result
  digest, `isError`).
- Approval RBAC covers `subscription_secret` authorities via
  `approval.decide_org`, which now implies `runs.read_all`; "subscription
  managers" defined as `subscriptions.manage` holders; subscription-secret
  rotation bumps its `authority_generation` (invariant 7 coverage).
- Two missing migrations added: connector-catalog custom-row tenant
  backfill (Phase C) and the legacy-key → KMS re-seal path (Phase D) —
  without the latter, the Phase D cutover orphans every sealed credential.
- Shared upstream HTTP transport must be ambient-state-free (no cookie
  jars, no cached per-host authentication) — new invariant 22.
- `2025-11-25` alignment: JSON Schema dialect selected per snapshot
  protocol version (SEP-1613); schema rejections surface as tool-execution
  errors (SEP-1303); insufficient-scope challenges (SEP-835) are terminal
  reconnect signals, never auto-escalation; M2M client-credentials
  explicitly gated on SEP-1046 ratification (not in the ratified revision).
- `resource_scope` semantics split by slot kind: mechanical enforcement for
  `workspace_fetch`/`result_publish`; a grant-enforced record for `mcp`.
- Current-state fix: gate step 10 rechecks only live connection status
  today; generation and owner-membership rechecks are target state.
- Smaller: optional snapshot max-age at binding, clone-URL egress
  validation for `authority: none` fetches, `server_id` justified for
  templated endpoints only, duplicate `approval.decided` emission noted as
  a current single-process bug the outbox fixes.

**v2 (2026-07-14)** — joint adversarial review by Claude (Fable 5) and Codex
(GPT-5.6-sol, max reasoning). All current-state claims were verified against
the code by both reviewers. Changes:

- Generalized run connection bindings to typed **run resource bindings**
  (`mcp` / `workspace_fetch` / `result_publish`) so the workspace clone and
  result publishing answer the same whose-identity question (invariant 21).
- Settled the fate of capability bundles: sandbox tools only; brokered tools
  move to requirements + snapshots + bindings, with an additive migration.
- Settled requirement satisfaction: `required_tools`, `satisfaction: all`,
  fail closed at run creation; schema-divergence rules for policy.
- Added approval RBAC (v1) and `run.read` visibility rules; principals are
  typed variants (user/trigger/schedule/webhook/system).
- Settled tenant isolation: repository methods primary, RLS as depth,
  composite tenant FKs mandatory, atomic run-creation transaction.
- Corrected the gate-order description to match `decide_tool_call` (budget
  before capability check).
- Corrected the multi-replica approval analysis: the ≤2 s DB polling floor
  already bounds cross-replica latency; `pg_notify` is an optimization.
  Added a full statelessness inventory (approvals, orchestrator leases with
  epoch fencing, delivery claims, token caches, MCP session ownership).
- Added execution semantics: decision idempotency ≠ execution idempotency;
  durable execution claims conditional on nonterminal sessions
  (invariants 16, 18; Gap 11).
- Added server-side argument-schema enforcement (invariant 17; Gap 12),
  audience-scoped sandbox credentials (invariant 19; Gap 10), stronger
  OAuth state binding (invariant 20), per-tenant LiteLLM virtual keys and
  the facade budget-reservation fix (Gap 14), and the full 2025-11-25
  conformance contract (Gap 8).
- Final consistency pass: binding authority became a tagged union
  (`connection | subscription_secret | none`) with principal-typed
  resolvers; live revalidation extended to every binding consumer (incl.
  git redirect/submodule/LFS scoping); PKCE **verifier** custody in the
  state row; "exactly once" replaced with at-most-one-dispatch + stale-claim
  → ambiguous recovery; budget reservations made durable and
  request-ID-keyed; custom connector definitions tenant-scoped; RLS
  requires a non-owner role or `FORCE ROW LEVEL SECURITY`.

**v1 (2026-07-14)** — initial proposal.

## References

### fluidbox

- [PLAN.md](../../PLAN.md)
- [Architecture](../ARCHITECTURE.md)
- [Capabilities guide](../guides/capabilities.md)
- [Capability registry](../../crates/fluidbox-server/src/capabilities.rs)
- [Run capability resolution](../../crates/fluidbox-server/src/run_service.rs)
- [Sandbox capability manifest](../../crates/fluidbox-server/src/orchestrator.rs)
- [Broker shim](../../images/runner-lib/broker-shim.mjs)
- [Server-side tool gate](../../crates/fluidbox-server/src/internal.rs)
- [Remote MCP broker](../../crates/fluidbox-server/src/broker.rs)
- [OAuth custody](../../crates/fluidbox-server/src/oauth.rs)
- [Current authentication](../../crates/fluidbox-server/src/auth.rs)
- [Current network modes](../../crates/fluidbox-core/src/traits.rs)

### MCP

- [MCP architecture](https://modelcontextprotocol.io/specification/2025-11-25/architecture)
- [MCP lifecycle](https://modelcontextprotocol.io/specification/2025-11-25/basic/lifecycle)
- [MCP transports](https://modelcontextprotocol.io/specification/2025-11-25/basic/transports)
- [MCP authorization](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization)
- [MCP tools](https://modelcontextprotocol.io/specification/2025-11-25/server/tools)
- [MCP security best practices](https://modelcontextprotocol.io/docs/tutorials/security/security_best_practices)
- [SEP-1024: local MCP server installation security](https://modelcontextprotocol.io/seps/1024-mcp-client-security-requirements-for-local-server-)
- [SEP-1046: OAuth client credentials](https://modelcontextprotocol.io/seps/1046-support-oauth-client-credentials-flow-in-authoriza)
- [SEP-990: enterprise-managed authorization](https://modelcontextprotocol.io/seps/990-enable-enterprise-idp-policy-controls-during-mcp-o)
