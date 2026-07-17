<div align="center">

# fluidbox

### The control plane for AI agents.

**Connect any event on the web to an agent that runs sandboxed, policy-gated, and audited.**

Open source. Written in Rust.

[![Release](https://img.shields.io/github/v/release/hrishikeshdkakkad/fluidbox?display_name=tag&sort=semver)](https://github.com/hrishikeshdkakkad/fluidbox/releases/latest)
[![CI](https://github.com/hrishikeshdkakkad/fluidbox/actions/workflows/ci.yml/badge.svg)](https://github.com/hrishikeshdkakkad/fluidbox/actions/workflows/ci.yml)
[![Kubernetes provider](https://github.com/hrishikeshdkakkad/fluidbox/actions/workflows/k8s.yml/badge.svg)](https://github.com/hrishikeshdkakkad/fluidbox/actions/workflows/k8s.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](./LICENSE)
[![Rust backend](https://img.shields.io/badge/control_plane-Rust-orange.svg)](./crates)

[Try it](#try-fluidbox) · [Connect an event](#connect-an-event) · [How it works](#one-event-one-governed-run) · [Kubernetes](#kubernetes) · [Contributing](#contributing)

</div>

Agents can act. The hard part is deciding **when they may run, what authority they receive, where they execute, and what evidence remains afterward**.

fluidbox is the authority layer between an external event and an AI agent. Register a versioned agent once, then borrow it from a pull request, a schedule, a scoped API call, a webhook, or a manual run. Every invocation becomes the same governed run: its configuration is frozen, its workspace is isolated, its actions meet policy, and its outcome is recorded and delivered.

> **Agent definition + invocation context + optional workspace = governed run.**

```text
 PR opened       cron        API / webhook       Slack or ServiceNow*
     \             |               |                       /
      \____________|_______________|______________________/
                                   |
                         ┌─────────▼─────────┐
                         │     fluidbox      │
                         │ freeze authority  │
                         │ gate actions      │
                         │ audit outcomes    │
                         └─────────┬─────────┘
                                   |
                    fresh Docker container or K8s Pod
                         Claude Agent SDK or Codex
                                   |
                diff · cost · signed callback · PR result · ledger

 * Any service can invoke a subscription-scoped API today. GitHub is the
   first native event adapter; Slack is next, while ServiceNow can use the
   scoped API path today.
```

fluidbox is not another chat UI, and a trigger is not a second execution system. Manual, API, schedule, and event-driven invocations all converge on one Rust control plane and one immutable run contract.

![A completed fluidbox run showing its live timeline, policy decisions, model usage, and frozen RunSpec](./docs/assets/run-detail.png)

*A real run: the agent fixes a failing test in an isolated workspace while fluidbox records tool decisions, model usage, lifecycle events, and the final result.*

## Why fluidbox

| Concern | Ad hoc agent execution | fluidbox |
|---|---|---|
| **Invocation** | A prompt starts an untracked process | An event borrows a registered, versioned agent |
| **Authority** | The agent inherits ambient machine credentials | The sandbox receives a session token; upstream credentials stay control-plane-side |
| **Runtime** | The agent shares a developer machine or long-lived worker | Every run gets a fresh Docker container or Kubernetes Pod |
| **Control** | The model decides what to attempt | Frozen capabilities, policy, trust tier, approvals, and budgets bound the run |
| **Evidence** | Logs explain part of what happened | Frozen `RunSpec`, append-only events, decisions, usage, artifacts, and delivery history |
| **Automation** | Each integration invents its own worker path | UI, CLI, API, cron, webhook, and GitHub all call the same `create_run` path |

## One event, one governed run

1. **Define the agent.** Choose the harness, model, system prompt, policy, budgets, optional workspace, and MCP capability bundles. Changes append a new revision; old revisions remain intact.
2. **Connect the event.** Start it manually, invoke a subscription-scoped endpoint, add a cron schedule, or bind a GitHub App event. Production automations can pin an exact agent revision.
3. **Freeze the authority.** fluidbox resolves the invocation into an immutable `RunSpec`: agent revision, task, policy snapshot, capability schemas, budget ceilings, trust tier, workspace, trigger context, and result destinations.
4. **Prepare the workspace.** Credentialed repository access happens on the control-plane side. The agent receives only a disposable copy; the original repository is never the working tree.
5. **Run and decide.** A fresh sandbox starts the Claude Agent SDK or Codex runner. Canonical tool intents and MCP calls flow through the server-side decision gate for capability, trust, policy, approval, and budget checks.
6. **Finalize and deliver.** fluidbox settles the runner, collects a bounded diff, records cost and audit events, transitions the run, then publishes signed callbacks or GitHub results. Delivery failure never changes the run's outcome.

The same lifecycle holds whether the run came from a button, a PR opening, a Monday-morning schedule, or a ServiceNow automation calling the scoped endpoint.

## What ships today

| Layer | Included |
|---|---|
| **Event sources** | Manual UI/CLI, subscription-scoped API, cron schedules, webhook-style invocation, native GitHub PR events |
| **Agent harnesses** | Claude Agent SDK and Codex behind one runner contract |
| **Execution providers** | Docker for local/self-hosted runs; Kubernetes-native Pods and Helm chart in `v0.2.0` |
| **Capabilities** | Versioned MCP bundles; sandbox-local stdio tools and control-plane-brokered remote tools |
| **Connections** | Sealed static credentials, OAuth with PKCE, GitHub App installation flow, connector catalog, custom MCP servers |
| **Governance** | YAML policies, managed per-tool overrides, human approvals, autonomous fallbacks, budgets, fork-PR read-only trust |
| **Evidence** | Frozen `RunSpec`, live SSE timeline, append-only redacted ledger, model usage and cost, diff artifacts, delivery attempts |
| **Results** | Dashboard/CLI result, HMAC-signed callback, GitHub PR comment, GitHub check |

Native Slack and ServiceNow adapters do not ship yet. Events from either can reach the scoped trigger API today, and a future native adapter only needs to verify and normalize the event before handing it to the existing run path.

## Try fluidbox

### Docker — fastest path

No Rust toolchain, Node installation, or external Postgres required:

```bash
git clone https://github.com/hrishikeshdkakkad/fluidbox.git
cd fluidbox
docker compose -f deploy/docker-compose.eval.yml --profile runners pull
ANTHROPIC_API_KEY=sk-ant-... docker compose -f deploy/docker-compose.eval.yml up -d
```

Open <http://localhost:3000>. The eval stack uses bundled Postgres and a well-known admin token, and leaves credential-backed integrations and webhook ingress disabled. It is for trying the run loop, not for exposing to a network.

### Develop from source

Prerequisites: [Rust](https://rustup.rs), [Docker](https://docs.docker.com/get-docker/), [just](https://github.com/casey/just), Node 24 + [pnpm](https://pnpm.io), and a direct-connection Postgres database. [Neon](https://neon.tech) is the blessed hosted path.

```bash
git clone https://github.com/hrishikeshdkakkad/fluidbox.git
cd fluidbox

just setup          # generate local secrets, install web deps, build the Claude runner
just neon-setup     # provision Neon and write its direct DATABASE_URL
$EDITOR .env        # add ANTHROPIC_API_KEY; add OPENAI_API_KEY for Codex runs
just codex-build    # optional: build the second harness
just dev            # LiteLLM gateway + Rust control plane + dashboard
```

Open <http://localhost:3000>, or start a manual run from the CLI:

```bash
cargo run -p fluidbox-cli -- run \
  --repo /path/to/repository \
  --task "find and fix the failing test"
```

If setup drifts, `just doctor` checks the documented failure points—database mode, bind address, key shape, runner images, dashboard token sync, and web dependencies—and prints the concrete fix.

### Everyday commands

| Command | Purpose |
|---|---|
| `just dev` | Start the gateway, control plane, and dashboard; one Ctrl-C stops them |
| `just doctor` | Validate the local environment and explain failures |
| `just check` | Run format, Clippy with `-D warnings`, Rust tests, and the web build |
| `just e2e` | Drive the full acceptance suite against a real local stack |
| `just sandbox-build` | Rebuild the Claude Agent SDK runner image |
| `just codex-build` | Rebuild the Codex runner image |
| `just k8s-dev` | Prepare the local kind + Calico Kubernetes development path |
| `just policy-sync` | Publish `policies/*.yaml`; active runs keep their frozen snapshot |

## Connect an event

Create an automation in the dashboard or with `POST /v1/triggers`. fluidbox returns a token whose entire authority is one subscription. An external system can then invoke that agent without receiving admin access:

```bash
curl -X POST "$FLUIDBOX_URL/v1/triggers/$SUBSCRIPTION_ID/invoke" \
  -H "authorization: Bearer fbx_trig_..." \
  -H "idempotency-key: servicenow-INC-4711" \
  -H "content-type: application/json" \
  -d '{"context":{"ticket":"INC-4711"}}'
```

The same token may poll only the runs it created. Idempotency keys make retries safe; task and workspace overrides are opt-in and narrowing-only. Add a callback URL to receive the terminal result with an HMAC signature, or attach a schedule to the same subscription.

For the full request shapes and signature-verification recipe, see [Triggers, schedules, and signed results](./docs/guides/triggers.md).

## Architecture

```text
 event sources                                      governed execution
 ─────────────────────────────────────────────────────────────────────────────
 dashboard · CLI · scoped API · cron · webhooks · GitHub App
                            |
                            v
 ┌──────────────────── fluidbox control plane · Rust ────────────────────────┐
 │ ingress / scheduler ──> create_run ──> immutable RunSpec                  │
 │                                      │                                    │
 │ policy + trust + capability + budget gate <──── runner tool intents       │
 │ approvals · SSE · append-only ledger · durable finalizer · deliveries     │
 │                                                                            │
 │ credential boundary: git fetch · LLM facade · OAuth custody · MCP broker  │
 └──────────────────────────────┬───────────────────────────────┬─────────────┘
                                │ session-scoped runner contract│
                    ┌───────────▼────────────┐                  │
                    │ execution provider     │                  ├──> models
                    │ Docker or Kubernetes   │                  ├──> git hosts
                    │                        │                  └──> remote MCP
                    │ fresh sandbox          │
                    │ Claude SDK or Codex    │
                    │ optional workspace     │
                    │ no upstream secrets    │
                    └────────────────────────┘
```

The control plane is the authority; the sandbox is workload-only. Both execution providers implement the same `ExecutionProvider` trait, and both harnesses implement the same HTTP runner contract. Adding an event source does not add a new run type.

### Core objects

| Object | Meaning |
|---|---|
| **Agent revision** | Versioned definition of harness, model, prompt, policy, budgets, workspace default, and capabilities |
| **Trigger subscription** | Standing permission for an event source to borrow an agent |
| **Connection** | Custody for credentials used by git, GitHub, OAuth, or a brokered MCP server |
| **Capability bundle** | Versioned photograph of tools that may exist for an agent; attaching does not allow them |
| **`RunSpec`** | Immutable evidence of the exact agent, authority, context, and limits resolved for one run |
| **Session** | The live lifecycle and audit identity of that run |

## Security boundaries

fluidbox is pre-1.0 security software. Its guarantees come from explicit boundaries, not from the agent behaving well:

- **No real upstream credential is placed in a sandbox.** The runner gets a short-lived session token. Model credentials remain behind the LLM facade, repository credentials are used during control-plane materialization, and brokered MCP credentials are unsealed only for the upstream call.
- **Isolation is provider- and profile-specific.** Kubernetes defaults to a `zeroEgress` sandbox namespace and blocks run admission until a probe proves the cluster's CNI enforces NetworkPolicy. Docker hardened mode uses an internal bridge. Docker's default `host-dev` mode is intentionally convenient and is not a structural zero-egress boundary.
- **Authority is frozen before spend.** Policy, capability schemas, trust tier, budgets, workspace, agent revision, and invocation are stored in the `RunSpec`; later edits affect future runs only.
- **Attach does not mean allow.** A capability must exist in the frozen set and still pass trust, policy, approval, and budget checks at call time. Fork PRs lose their MCP surface and receive a read-only trust floor that approvals cannot widen.
- **Audit is redacted by construction.** The append path accepts only `Redacted<EventEnvelope>` values. The ledger keeps digests, decisions, usage, cost, lifecycle, and artifact metadata—not raw model prompts, secrets, or brokered tool payloads.
- **Finalization is durable.** Terminal intent is persisted before acknowledgement; artifact collection precedes the terminal transition; interrupted finalizations are recovered after restart.

The current deployment model is self-hosted and effectively single-tenant, with one admin bearer token. Tenant-aware tables are not presented as multi-user authentication or RBAC. Read [SECURITY.md](./SECURITY.md) before operating fluidbox outside a local environment.

## Kubernetes

`v0.2.0` adds a Kubernetes-native provider alongside Docker. One run becomes one bare Pod in a dedicated sandbox namespace: workspace init container, unmodified agent runner, and an in-pod collector. Per-run Secrets are owner-referenced for garbage collection, artifact collection uses a pristine git baseline, and reconciliation adopts or terminates resources after control-plane restarts.

The Helm chart is published as an OCI artifact:

```bash
# First create the required `fluidbox-secrets` Secret and a values file.
helm show values oci://ghcr.io/hrishikeshdkakkad/charts/fluidbox \
  --version 0.2.0 > fluidbox-values.yaml

helm install fluidbox oci://ghcr.io/hrishikeshdkakkad/charts/fluidbox \
  --version 0.2.0 \
  --namespace fluidbox \
  --create-namespace \
  --values fluidbox-values.yaml

# Required acceptance check: proves +:8788 internal reachability and
# -:8787 public-plane isolation from the sandbox namespace.
helm test fluidbox --namespace fluidbox
```

Start with the chart's annotated [`values.yaml`](./deploy/helm/fluidbox/values.yaml) and the EKS/GKE/AKS/DOKS/kind presets under [`deploy/helm/fluidbox/values/`](./deploy/helm/fluidbox/values). Production should pin image digests and supply credentials through the existing Secret; the chart never generates credential material.

## Repository map

```text
crates/fluidbox-core          domain types, policy engine, state machine, events
crates/fluidbox-db            sqlx repositories, migrations, LISTEN/NOTIFY
crates/fluidbox-server        axum API, orchestrator, gate, broker, workers
crates/fluidbox-provider      Docker execution provider
crates/fluidbox-provider-k8s  Kubernetes execution provider
crates/fluidbox-workspace     safe workspace archive and diff primitives
crates/workspaced             in-sandbox workspace init and artifact collector
crates/fluidbox-cli           thin command-line client
apps/web                      presentation-only Next.js dashboard
images/sandbox-runner         Claude Agent SDK runner
images/codex-runner           Codex runner
images/runner-lib             shared runner contract and MCP gate shims
deploy/                       Docker Compose, LiteLLM, images, and Helm chart
migrations/                   embedded Postgres schema
policies/                     versioned seed policy YAML
```

## Read next

- [Architecture](./docs/ARCHITECTURE.md) — the run flow, trust boundaries, and extension seams.
- [Authoritative plan](./PLAN.md) — north star, convergence invariants, decisions, and milestones.
- [Roadmap](./ROADMAP.md) and [changelog](./CHANGELOG.md) — what is next and what shipped.
- [Writing policies](./docs/guides/policies.md) — ordered rules, approvals, autonomy, and managed overrides.
- [Triggers and schedules](./docs/guides/triggers.md) — scoped invocation, cron, callbacks, and GitHub events.
- [MCP capabilities](./docs/guides/capabilities.md) — sandbox versus brokered tools, pinning, and connector custody.
- [Kubernetes provider design](./docs/plans/2026-07-15-kubernetes-native-provider-design.md) — Pod lifecycle, network enforcement, archive transport, finalization, and reconciliation.

## Project status

fluidbox is early, usable, and moving quickly. `v0.1.0` shipped the governed vertical slice; `v0.2.0` added Kubernetes-native execution and hardened finalization while keeping Docker fully supported. The acceptance suites cover the Rust control plane, dashboard, both harnesses, event paths, connectors, and provider-specific isolation checks.

Expect breaking changes before `v1.0`. Near-term work includes the native Slack event vertical, AWS Lambda MicroVM/BYOC execution, customer-built signed runner images, and brokered git writes. See the [changelog](./CHANGELOG.md) for release evidence and the [roadmap](./ROADMAP.md) for sequencing.

## Contributing

Contributions are welcome: code, integrations, policies, documentation, bug reports, and security hardening. Start with [CONTRIBUTING.md](./CONTRIBUTING.md), run `just check`, and run `just e2e` for changes that touch a governance path. Architectural changes must preserve the convergence invariants in [`PLAN.md` §2](./PLAN.md).

Please report vulnerabilities privately through [GitHub Security Advisories](https://github.com/hrishikeshdkakkad/fluidbox/security/advisories/new), not a public issue.

## License

[MIT](./LICENSE) © fluidbox contributors.
