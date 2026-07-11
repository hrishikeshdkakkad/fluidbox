# fluidbox — Agent Workspaces, Triggers, Tools, and Integrations

**Date:** 2026-07-10

**Status:** Product and architecture direction

**Relationship to `PLAN.md`:** This document expands the product direction behind agent configuration, optional workspaces, capability bundles, triggers, and vertical integrations. `PLAN.md` remains authoritative for the runtime architecture and milestone invariants.

## 1. The outcome

fluidbox should let a user define an agent once and then **borrow that agent on demand** from many different circumstances.

An agent definition continues to work as it does today:

1. Select a harness (`claude-agent-sdk` today; more later).
2. Select a model.
3. Set the agent's system prompt.
4. Choose supervised or autonomous behavior through policy and run configuration.

The next product layer adds four optional inputs around that existing agent:

1. **Workspace** — where the agent should work, such as scratch space or a connected Git repository.
2. **Invocation context** — why this run exists, such as an API request, schedule, pull request, Jira issue, or Slack thread.
3. **Capabilities** — custom tools, MCP servers, and connected-service operations available to the agent.
4. **Result destination** — where the outcome should be returned, such as an API callback, pull-request comment, GitHub Check, Jira comment, or Slack reply.

The core product equation is:

```text
Agent Definition + Invocation Context + Optional Workspace = Governed Run
                                                        ↓
                                                 Result + Evidence
```

GitHub is the first rich example, not a special execution architecture. API calls, schedules, GitHub, Slack, Jira, and future integrations must all create ordinary fluidbox runs.

## 2. Product principles

### 2.1 Keep agent creation unchanged

This plan does not introduce a new ownership or agent-sharing model. Users create versioned agents through the existing registry. Every invocation resolves one immutable agent revision and freezes it into a `RunSpec`.

### 2.2 Workspace is optional context

An agent may run with:

- a scratch workspace;
- a copied local repository;
- a repository selected from a connected Git provider;
- a repository and exact commit derived from an event, such as a pull request.

The agent starts in that workspace and uses it as its working directory. An agent is not inherently a “GitHub agent”; GitHub is one possible source of workspace and invocation context.

### 2.3 Triggers borrow agents; they do not own them

A trigger selects an agent, supplies contextual inputs, and requests a run. It must not implement its own execution path.

```text
Manual UI ───────┐
API request ─────┤
Schedule ────────┤
GitHub event ────┼──▶ create_run(agent, context, workspace) ──▶ ordinary RunSpec
Jira event ──────┤
Slack event ─────┘
```

### 2.4 Fan-out is a first-class behavior

One external event may match multiple agent subscriptions. Each match creates an independent run with its own revision, sandbox, policy, budget, ledger, and result delivery.

One agent failing must not block or cancel the other agents triggered by the same event.

### 2.5 Connections never imply authority for every agent

Connecting an external service establishes the maximum authority fluidbox can exercise. Each agent and trigger binding may use only a narrower subset. A connection must never silently grant every agent every operation available through that connection.

### 2.6 External credentials stay out of sandboxes

Product semantics: the sandbox receives a real Git checkout and the agent works from that directory.

Security implementation: fluidbox performs credentialed fetches through the control plane, then mounts or transfers the checkout into the sandbox. The `.git` working tree may be present, but the durable GitHub credential is not.

Local operations such as `git diff`, `git status`, tests, edits, and commits can run normally in the sandbox. Remote operations such as posting a review, creating a branch, pushing, or opening a pull request use governed service capabilities through fluidbox.

## 3. Core product objects

### 3.1 Agent Definition and Agent Revision — existing

An agent is an identity with immutable revisions. A revision defines its default recipe:

```text
AgentRevision
  harness
  runner_image
  model
  system_prompt
  policy_ref
  default_budgets
  default_workspace?       # new, optional
  capability_bundle_refs  # schema seam exists; catalog comes later
```

The agent definition describes **who the specialist is and how it works**. It does not encode every circumstance that may invoke it. Autonomy remains a run/trigger choice bounded by the revision's policy, as it is today.

### 3.2 Integration Connection — new

A connection represents fluidbox's authorized relationship with an external service:

```text
IntegrationConnection
  id
  tenant_id
  provider              # github, gitlab, jira, slack, custom
  external_account_id
  display_name
  credential_ref        # broker reference; never returned to the sandbox/UI
  granted_scopes
  resource_selection    # repositories, projects, workspaces, etc.
  status                # active, expired, revoked, error
  created_at
  updated_at
```

For GitHub, the durable service connection should normally be an installation scoped to selected repositories. “Sign in with Git” is the user-facing connection flow; the stored connection is what workspace resolution and result publishing consume.

### 3.3 Workspace Specification — new first-class shape

`RepoSource` should evolve into a more explicit workspace contract:

```text
WorkspaceSpec =
  Scratch
  | LocalCopy { path }
  | GitRepository {
      connection_id,
      repository_id,
      clone_url,
      ref?,
      commit_sha?,
      checkout_mode       # read_only | writable_copy
    }
```

An agent revision may carry a default workspace, but it remains optional.

Workspace resolution precedence:

```text
event-derived workspace
  > explicit invocation workspace
  > agent revision default workspace
  > scratch workspace
```

The higher-precedence source may narrow or specialize an authorized workspace; it may not escape the repositories available to its connection or trigger binding.

Examples:

- A manually started agent uses the repository selected on its agent revision.
- An API caller supplies a permitted repository and ref.
- A scheduled run uses the agent's default repository.
- A GitHub PR event supplies the event repository plus the exact head and base commits, overriding the default ref.

### 3.4 Invocation Context — new canonical envelope

Every run records why it was created in a provider-neutral envelope:

```text
InvocationContext
  kind                  # manual | api | schedule | event
  provider?             # github | jira | slack | custom
  external_event_id?    # delivery id / issue event id / message id
  actor?                # external user or system identity
  resource              # normalized repo, PR, issue, channel, etc.
  event_type?           # pull_request.opened, issue.updated, ...
  attributes            # provider-specific data retained as structured context
  occurred_at
  received_at
  trust_tier
```

The full envelope is stored with the session, while the agent receives only the fields selected by the trigger's task template and capability policy. Untrusted external text is context, not system instruction.

### 3.5 Trigger Subscription — new

A subscription is the standing instruction that says when an agent should be borrowed:

```text
TriggerSubscription
  id
  tenant_id
  agent_id
  revision_selector       # latest | pinned revision
  enabled
  trigger_kind            # api | schedule | event
  connection_id?          # required for connected-service events
  resource_selector       # repo/project/channel selectors
  event_filter             # pull_request.opened, label=..., branch=...
  task_template
  autonomy_override?      # may narrow; never widen policy
  budget_override?        # may tighten; never widen agent defaults
  capability_overrides    # may remove; never add beyond agent/connection
  workspace_override?
  result_destinations
  concurrency_policy
  created_at
  updated_at
```

Subscriptions create a many-to-many relationship:

- One agent can subscribe to several repositories and event types.
- Several agents can subscribe to the same repository and event.
- One event can therefore create several independent runs.

### 3.6 Capability Bundle — planned schema becomes operational

A capability bundle is a versioned, reusable collection of tools and MCP bindings:

```text
CapabilityBundle
  id
  version
  name
  tools[]
  mcp_servers[]
  connection_refs[]
  credential_requirements[]
  policy_defaults
```

Two broad capability classes are useful:

1. **Sandbox-local capabilities** — read, edit, shell, tests, and tools contained within the workspace.
2. **Brokered service capabilities** — GitHub comments, branch publication, Jira changes, Slack replies, database access, and remote MCP operations using credentials held by fluidbox.

Every tool call remains policy-gated and ledgered. Attaching a bundle makes a tool available; it does not automatically make every invocation permissible.

### 3.7 Result Destination — new

A run may publish to zero or more destinations:

```text
ResultDestination =
  Dashboard
  | SignedWebhook { url, secret_ref }
  | GitHubPullRequestComment { connection_id, repo, pr_number }
  | GitHubCheck { connection_id, repo, commit_sha }
  | JiraComment { connection_id, issue_key }
  | SlackReply { connection_id, channel, thread }
```

The run's canonical artifacts and ledger remain in fluidbox. Result publishers translate that canonical result into the destination-specific representation.

## 4. Run creation and freezing

All entry points must converge on one internal run-creation service:

```text
create_run(
  agent_selector,
  task,
  invocation_context,
  workspace_override?,
  autonomy_override?,
  budget_override?,
  capability_override?,
  result_destinations[]
) -> Session
```

The service resolves and freezes:

1. The selected immutable agent revision.
2. The effective workspace.
3. The effective policy and trust tier.
4. The effective autonomy mode.
5. Tightened budgets.
6. The intersection of available capabilities.
7. The invocation context.
8. Result destinations.

The effective authority is always an intersection:

```text
connection grants
  ∩ agent capabilities
  ∩ subscription overrides
  ∩ event trust tier
  ∩ organization policy
  = frozen RunSpec authority
```

An invocation may narrow an agent's authority but never silently widen it.

## 5. Workspace lifecycle

### 5.1 User-visible behavior

When configuring or starting an agent, the user may select:

- no repository;
- a connected Git provider;
- one of the repositories available through that connection;
- an optional default branch or ref.

When the run starts, the agent is placed in the repository directory and works there. From the user's perspective, the sandbox has cloned the repository.

### 5.2 Secure implementation

```text
Resolve WorkspaceSpec
        ↓
Control plane obtains scoped connection credential
        ↓
Fetch exact repository/ref into per-session workspace
        ↓
Record remote identity + base/head commit
        ↓
Remove credential-bearing remote configuration if necessary
        ↓
Mount/push working copy into fresh sandbox at /workspace/repo
        ↓
Start harness with cwd=/workspace/repo
        ↓
Capture diff/artifacts at completion
```

Required guarantees:

- The original checkout or remote repository is never modified merely by running the agent.
- A PR-triggered run checks out the exact event commit, not a moving branch name.
- The connection credential never appears in the `RunSpec`, sandbox environment, event ledger, or artifacts.
- Workspace creation failure terminates before model spend.
- Cleanup is idempotent.

### 5.3 Remote writes are explicit capabilities

If a user wants an agent to publish changes, the user attaches a capability such as:

- review and comment;
- create a new branch and pull request;
- update a branch owned by that agent/run;
- merge, only as a later explicitly governed capability.

The sandbox can prepare commits locally. A brokered Git capability performs the remote mutation after policy evaluation, avoiding a durable provider credential inside the sandbox.

## 6. Trigger architecture

### 6.1 API trigger — first external proof

A scoped trigger token is bound to one trigger subscription or agent. It can start only the runs allowed by that binding and cannot access the administrative API.

```http
POST /v1/triggers/{trigger_id}/invoke
Authorization: Bearer <scoped-trigger-token>
Idempotency-Key: <caller-stable-key>

{
  "task": "optional task input",
  "context": { "ticket": "INC-42" },
  "workspace": { "repository_id": "optional-authorized-repo", "ref": "main" },
  "callback": { "url": "optional-approved-destination" }
}
```

The response returns the run id immediately. A signed callback or polling endpoint returns the terminal result.

### 6.2 Scheduled trigger

A schedule is a trigger subscription with:

- cron expression and timezone;
- task template;
- optional default workspace;
- concurrency policy (`allow`, `skip_if_running`, or `replace`);
- missed-run policy;
- result destinations.

Each firing creates an ordinary run with `InvocationContext.kind = schedule`.

### 6.3 Connected-service event trigger

Each connector performs only five provider-specific responsibilities:

1. Verify and authenticate the incoming event.
2. Normalize it into `InvocationContext`.
3. Resolve provider resources into a `WorkspaceSpec` when applicable.
4. Let the generic matcher find subscriptions and create runs.
5. Publish canonical results back to the provider.

The trigger router must not know how a Claude, Codex, or custom harness executes.

### 6.4 Delivery and dispatch idempotency

External systems retry webhooks. fluidbox must distinguish two levels:

1. **Event receipt deduplication:** the same external delivery is stored once.
2. **Subscription dispatch deduplication:** the same delivery creates at most one run per matching subscription.

Conceptually:

```text
unique(connection_id, external_event_id)
unique(trigger_delivery_id, subscription_id)
```

Replaying a stored delivery may deliberately create a new replay attempt, but an accidental webhook retry must not duplicate runs or comments.

## 7. GitHub PR review fan-out — flagship integration demo

### 7.1 Configuration

1. A customer connects a GitHub installation and selects repositories.
2. Team member A creates PR Review Agent A as an ordinary agent.
3. Team members B and C create their own agents the same way.
4. Each person creates a trigger subscription for `pull_request.opened` on the same repository.
5. Each subscription selects its own task template, budgets, capabilities, and result behavior.

### 7.2 Event flow

```text
GitHub pull_request.opened
        ↓
Verify signature + store delivery once
        ↓
Normalize repo, PR number, base SHA, head SHA, author, fork status
        ↓
Match three subscriptions
        ↓
Create Run A ──▶ sandbox A ──▶ Review A ──▶ comment/check A
Create Run B ──▶ sandbox B ──▶ Review B ──▶ comment/check B
Create Run C ──▶ sandbox C ──▶ Review C ──▶ comment/check C
```

Each run:

- freezes the agent's current or pinned revision;
- receives the same event context but its own task template;
- checks out the exact PR head commit in its own workspace;
- runs independently and concurrently subject to tenant limits;
- produces its own cost, timeline, artifacts, and status;
- publishes an attributable result containing agent name and run link.

### 7.3 Trust and fork behavior

Events from untrusted forks automatically receive a stricter trust tier. The effective policy may permit reading and reviewing while denying secrets, remote writes, or sensitive capabilities. A trigger cannot override this downgrade.

### 7.4 Result update policy

The publisher should maintain a stable external result identity per agent subscription and PR. On later events such as `pull_request.synchronize`, fluidbox can update the agent's existing comment/check instead of posting unlimited new comments.

One agent's failure is represented on that agent's check/comment only. The other reviews continue.

## 8. Custom tools and MCP

### 8.1 Configuration experience

The agent revision editor gains a Capabilities section where a user can attach versioned bundles. A trigger or individual run may remove capabilities for a narrower context but cannot add capabilities outside the agent revision and connection grants.

### 8.2 MCP requirements

An MCP attachment records:

- server identity and version/digest;
- transport and endpoint;
- discovered tool schema snapshot;
- required connection/secret references;
- egress requirements;
- default policy classifications;
- health status.

Every MCP tool intent crosses the same permission gateway as built-in tools. The ledger records the normalized tool identity, input digest, policy decision, result status, latency, and cost metadata without leaking secrets.

### 8.3 Custom-tool execution modes

Support two deliberate modes rather than an unbounded “hook” mechanism:

1. **Sandbox tool:** packaged in the runner image or capability bundle and constrained by sandbox containment.
2. **Brokered tool:** executed through the control plane or a dedicated tool gateway when it needs a customer connection or secret.

Arbitrary lifecycle shell hooks are not the primary integration model. Typed workspace resolvers, trigger adapters, governed tools, and result publishers provide clearer security and retry semantics.

## 9. Result delivery

The canonical run result should contain:

```text
run_id
agent_id + revision
status
summary
artifacts[]
diff artifact/reference
usage and cost
started_at + finished_at
invocation context reference
```

Result publication is asynchronous and independently retryable. A completed run remains completed even when its external comment or callback temporarily fails.

`result_deliveries` should track:

- destination;
- stable external id when created;
- pending/delivered/failed status;
- attempt count and next retry;
- last error;
- payload digest;
- timestamps.

This separation prevents connector outages from corrupting the run lifecycle.

## 10. Suggested data-model additions

The names may evolve during implementation, but the responsibilities should remain separate:

```text
integration_connections
  id, tenant_id, provider, external_account_id, credential_ref,
  scopes, resource_selection, status, metadata, timestamps

trigger_subscriptions
  id, tenant_id, agent_id, revision_selector, kind, connection_id,
  resource_selector, event_filter, task_template, overrides,
  result_destinations, concurrency_policy, enabled, timestamps

trigger_deliveries
  id, connection_id, external_event_id, event_type, payload,
  payload_digest, occurred_at, received_at

trigger_dispatches
  id, delivery_id, subscription_id, session_id, status, timestamps
  unique(delivery_id, subscription_id)

schedules
  subscription_id, cron, timezone, next_fire_at,
  missed_run_policy, last_fired_at

capability_bundles
  id, tenant_id, name, version, definition, timestamps

result_deliveries
  id, session_id, destination, status, external_id,
  attempts, next_retry_at, last_error, payload_digest, timestamps
```

`agent_revisions` gains an optional default workspace. `sessions.run_spec` freezes resolved workspace, capabilities, invocation context, and result destinations.

## 11. Product experience

The existing agent editor should evolve without becoming a workflow builder:

### Agent configuration

1. **Identity:** name and description.
2. **Brain:** harness, model, and system prompt.
3. **Behavior:** autonomy, policy, and budgets.
4. **Workspace:** optional connected repository and default ref.
5. **Capabilities:** built-in tools, custom tools, and MCP bundles.
6. **Triggers:** API, schedules, and connected-service subscriptions.
7. **Activity:** runs, costs, artifacts, and result-delivery status.

### New Run

The manual flow remains simple:

1. Choose an agent.
2. Confirm or override the workspace.
3. Enter the task.
4. Optionally tighten autonomy/budgets/capabilities.
5. Run.

### Connections

A separate Connections area manages GitHub, GitLab, Jira, Slack, and future services. Agent configuration references connections; it does not own or expose their credentials.

## 12. Delivery roadmap

The phases are ordered to prove one reusable primitive at a time.

### Phase 0 — Finish near-term hardening

Complete `docs/HANDOVER.md` §6.A so later trigger and workspace tests have a reliable acceptance harness.

**Exit:** repeatable E2E, failure-path coverage, cleanup guarantees, and defensible policy/budget defaults.

### Phase 1 — Connected Git workspace

Implement the optional workspace/context concept before event automation:

- GitHub connection flow and repository picker;
- optional default workspace on an agent revision;
- `GitRepository` input on manual/API run creation;
- control-plane-side clone of exact ref/commit;
- sandbox starts in the cloned repository;
- diff capture and cleanup;
- no credential in sandbox or ledger.

**Acceptance demo:** connect GitHub, select a repository on an agent, start it manually, observe it work inside the checkout, and receive a diff while the remote repository remains untouched.

### Phase 2 — Generic API borrowing and result callback

- scoped trigger tokens;
- trigger subscriptions;
- unified internal `create_run` service;
- idempotency keys;
- signed result callbacks;
- trigger and delivery status in the UI.

**Acceptance demo:** an external service invokes one registered agent without an admin token and receives one signed terminal callback containing status, summary, artifacts, and cost.

### Phase 3 — Scheduled borrowing

- scheduler worker;
- cron/timezone configuration;
- missed-run and concurrency policies;
- default workspace/task templates;
- retryable result delivery.

**Acceptance demo:** a repository-maintenance agent runs on schedule, skips or serializes overlapping work according to policy, and publishes its result.

### Phase 4 — GitHub PR-review fan-out

- GitHub webhook verification and delivery deduplication;
- normalized PR context;
- repository/event subscription matching;
- exact-SHA checkout and fork trust tier;
- one run per matching agent subscription;
- PR comment and/or Check result publisher;
- stable comment/check updates on later PR commits.

**Acceptance demo:** three differently configured agents subscribed to one repository receive one PR-opened event, execute in three isolated workspaces, and independently publish three attributable reviews. Retrying the webhook creates no duplicate run or comment.

### Phase 5 — Capability and MCP catalog

- versioned capability bundles;
- custom-tool and MCP registration;
- connection and credential brokering;
- per-agent attachment and per-run narrowing;
- policy, audit, health, and UI coverage.

**Acceptance demo:** two agents triggered by the same event have different tool bundles; each can use only its frozen capabilities, and every call appears in the governed ledger.

### Phase 5.5 — Connector catalog & OAuth custody (user-inserted slice, shipped 2026-07-11)

The user-facing layer over the Phase-5 seams: a curated connector catalog
("select capabilities onto your agent") plus OAuth credential custody for
connectors with no static-key path (Notion-class). RunSpec, the permission
gate, and the photograph rule are untouched — only credential resolution in
`broker::brokered_auth` grew (custom `header_name`/`scheme` for static
secrets; OAuth access-token minting with sealed rotating refresh tokens).

**Settled at the boundary (user, 2026-07-11):**

1. **Both increments in one phase** (catalog + OAuth custody).
2. **API-only catalog** (deviating from the checked-in/boot-synced
   recommendation): `connector_catalog` rows are seeded by migration 0007
   and managed via `/v1/catalog`; there is no seed file and no boot-sync
   code path. The table is global (tenant-less) reference data; custom
   entries are forced tier=custom.
3. **Generic confidential-client support now** (pre-registered client_id +
   sealed client_secret; priority pre-registered → CIMD → DCR); the **Slack
   seed entry is deferred to the Phase-7 Slack vertical** (confidential
   client, no DCR). Notion IS seeded — the OAuth showcase.
4. **Catalog Connect auto-registers the bundle** (photograph with the fresh
   credential; authless immediately, api_key after sealing with rollback on
   refusal, oauth at callback completion).

**Acceptance demo:** a catalog entry is connected end-to-end (401 → PRM →
AS metadata → PKCE S256 + `resource=` both legs → single unauthenticated
callback with AEAD-sealed state → sealed rotating refresh token), the broker
mints/refreshes access tokens server-side (proactive pre-expiry + one
reactive-401 retry), rotation kills the old refresh token, `invalid_grant`
fails new runs closed at zero spend until a reconnect on the same connection
revives it, and no secret ever appears in a response, RunSpec, ledger, or
sandbox.

### Phase 6 — Multi-harness proof

Add the next harness, initially Codex, without modifying the trigger, workspace, policy, or result-delivery model.

**Acceptance demo:** Claude and Codex agents subscribe to the same event and run through the same fan-out path using different runner implementations.

### Phase 7 — Additional vertical integrations

After API, schedules, and GitHub prove the contracts, add Jira, Slack, Linear, GitLab, and custom event sources as adapters:

```text
verify → normalize → match → create ordinary run → publish canonical result
```

Avoid designing a public connector SDK until at least two substantially different connected services have validated the internal adapter boundary.

### Parallel platform track — runtime portability

The existing Lambda MicroVM/BYOC milestone is complementary to this product roadmap. Workspace resolution, trigger dispatch, capability freezing, and result publication should be implemented without Docker-specific assumptions, but the first product slices may be proven on Docker.

**Portability demo:** the same API or GitHub subscription can create a Docker run or Lambda MicroVM run by changing only the selected execution provider; trigger matching and result delivery remain unchanged.

## 13. Current codebase: existing seams and real gaps

### Already present

- Versioned agent definitions.
- Harness, model, system prompt, policy, budgets, and capability refs on revisions.
- Supervised and autonomous runs.
- Frozen `RunSpec`.
- `RepoSource::GitUrl` domain shape.
- `sessions.trigger` and `trust_tier` schema fields.
- Per-run sandbox, workspace initialization, ledger, artifacts, cost, and diff.

### Still required

- `GitUrl`/connected-repository input in the public API and UI.
- Actual remote repository materialization; the orchestrator currently rejects `GitUrl`.
- Connection storage and credential brokering.
- Default workspace on agent revisions.
- Trigger-token authentication and subscriptions.
- Schedule storage and worker.
- Event ingress, normalization, matching, and fan-out.
- Result-delivery persistence and retry workers.
- Capability/MCP catalog and runtime bindings.
- At least one second harness to make harness selection substantive.

## 14. Reliability and security requirements

### Reliability

- At-least-once event ingestion with exactly-once dispatch per subscription through idempotency.
- Independent retry state for event receipt, run dispatch, and result publication.
- Bounded per-tenant and per-connection concurrency.
- Backpressure and rate-limit handling for external APIs.
- Dead-letter visibility and manual replay.
- No connector failure can mutate a completed run back to non-terminal.

### Security

- Verify webhook signatures before storing or dispatching an event.
- Scope trigger tokens to the minimum agent/subscription/resources.
- Keep external credentials in a broker, not `RunSpec` or sandbox environment.
- Treat event payloads, repository contents, and PR text as untrusted input.
- Apply fork/untrusted-source trust downgrades before run creation.
- Freeze effective workspace, capabilities, policies, and budgets into the run.
- Mediate remote mutations through explicit governed capabilities.
- Record every external side effect with actor, agent revision, run id, and destination.

## 15. Success measures

Product and system health should be visible through:

- time from connection to first successful repository-backed run;
- event-to-run dispatch latency;
- percentage of matching subscriptions dispatched successfully;
- duplicate event, run, and external-comment rate;
- result-delivery success and retry latency;
- per-agent/run cost and budget-stop rate;
- workspace initialization failures;
- connector authorization expiry/revocation rate;
- sandbox or ledger credential-exposure incidents — target zero.

## 16. Non-goals

- Replacing the existing agent registry or ownership model.
- Creating provider-specific agent types.
- Building a general-purpose workflow engine.
- Sharing one sandbox between several fan-out agents.
- Giving a GitHub connection automatically to every agent.
- Putting durable external-service credentials inside a sandbox.
- Making triggers responsible for harness execution.
- Blocking the core run result on external comment/callback availability.

## 17. Decisions to make at implementation boundaries

These decisions do not block the overall architecture, but each must be settled before its phase ships:

1. Whether GitHub results appear only under the fluidbox App identity or support user-delegated identities. — **SETTLED 2026-07-10 (Phase 4): App-only.** Comments and checks post under the App installation identity; per-agent attribution lives in the content (agent name + run id in the comment body, check name `fluidbox/<subscription>`). Checks require an App identity anyway; user-delegated identities can layer on later without schema changes.
2. Whether a PR subscription defaults to `opened` only or also `synchronize` and `reopened`. — **SETTLED 2026-07-10 (Phase 4): default `opened` + `reopened`;** `synchronize` is a per-subscription opt-in because it fires on every push to the PR branch — a cost amplifier (pushes × matching subscriptions = runs).
3. Whether subsequent reviews update a stable comment/check or preserve a history of separate results. — **SETTLED 2026-07-10 (Phase 4): update in place.** One stable comment per (subscription, PR), tracked in `external_results` and edited on later events (recreated only if deleted externally); checks get one run per head SHA under the stable subscription name. The ledger and `result_deliveries` keep the full history.
4. Which branch-write operations are allowed through the first brokered Git capability. — **EXPLICITLY DEFERRED past Phase 5 (2026-07-10).** The brokered-tool gateway itself shipped in Phase 5 (proven on MCP); the git-write op list settles at its own boundary, where it rides that gateway unchanged (working recommendation: create_branch / push to run-owned branches / open_pull_request; never merge).
5. Schedule missed-run and overlap defaults. — **SETTLED 2026-07-10 (Phase 3): overlap default `allow`, missed-run default `skip`; `concurrency_policy` enforced in `create_run` for ALL invocations.**
6. Whether API trigger task/workspace overrides are opt-in per subscription. — **SETTLED 2026-07-10 (Phase 2): opt-in per subscription, both default OFF.**
7. Capability-bundle versioning and upgrade behavior for existing agent revisions. — **SETTLED 2026-07-10 (Phase 5): pin-only.** Attaching `"name"` resolves to the newest bundle version AT ATTACH TIME and stores the exact pin (`{id, name, version}`) on the revision; `"name@N"` pins explicitly. Upgrading a bundle = appending a new agent revision — no floating refs exist anywhere, so a bundle publisher can never change what an existing agent runs. The registry itself is append-only ((tenant, name, version) unique; publishing = a new version row), and RunSpecs freeze the pinned definition + digests. Research input: the MCP registry's (name, version) metadata is immutable but carries no content hash for npm/pypi — fluidbox's own snapshot digests are the supply-chain anchor (docs/research/2026-07-10-mcp-ecosystem-findings.md).
8. When the connector boundary is mature enough to expose as a public SDK.

## 18. Definition of the north-star experience

The product direction is achieved when a user can:

1. Create an agent by selecting its harness, model, prompt, autonomy, policy, and budgets.
2. Optionally connect a repository and make it the agent's default workspace.
3. Attach only the tools and MCP capabilities that agent needs.
4. Start it manually, through a scoped API, on a schedule, or from a connected-service event.
5. Have one event independently borrow every matching agent.
6. See every run execute in its own governed workspace.
7. Receive results back in the system that requested the work.
8. Audit exactly which agent revision ran, what it was allowed to do, what it changed, and what it cost.

That is “borrow the agent, on demand”: one reusable agent model, many invocation circumstances, consistent governance, and results returned to the caller.
