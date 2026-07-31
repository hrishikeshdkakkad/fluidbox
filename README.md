<div align="center">

# fluidbox

### The open-source control plane for AI agents

**Connect any event on the web to an agent that runs sandboxed, policy-gated, and audited.**

[![Release](https://img.shields.io/github/v/release/hrishikeshdkakkad/fluidbox?display_name=tag&sort=semver)](https://github.com/hrishikeshdkakkad/fluidbox/releases/latest)
[![CI](https://github.com/hrishikeshdkakkad/fluidbox/actions/workflows/ci.yml/badge.svg)](https://github.com/hrishikeshdkakkad/fluidbox/actions/workflows/ci.yml)
[![Kubernetes provider](https://github.com/hrishikeshdkakkad/fluidbox/actions/workflows/k8s.yml/badge.svg)](https://github.com/hrishikeshdkakkad/fluidbox/actions/workflows/k8s.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](./LICENSE)

[Documentation](./docs) · [Architecture](./docs/ARCHITECTURE.md) · [Kubernetes](./docs/guides/kubernetes.md) · [Issues](https://github.com/hrishikeshdkakkad/fluidbox/issues)

</div>

https://github.com/user-attachments/assets/579df2f1-9c55-4946-988b-952d15feb35d

*The product film (2:56): one incident, followed through frozen authority, a disposable sandbox, the policy gate, and human review to a delivered pull request.*

## What is fluidbox?

fluidbox sits between an external event and an AI agent. Register a versioned agent once, then borrow it from a pull request, a cron schedule, a scoped API call, a webhook, or a manual run — every invocation becomes the same governed run: configuration frozen at start, workspace isolated in a fresh sandbox, every action gated by policy, and the outcome recorded and delivered.

The control plane is written in Rust. It runs the Claude Agent SDK and Codex behind one runner contract, executes on Docker or Kubernetes, and keeps every upstream credential — model keys, git credentials, MCP secrets — out of the sandbox.

## Get started quickly

The fastest path is Docker Compose — no Rust toolchain, Node, or external Postgres required:

```bash
git clone https://github.com/hrishikeshdkakkad/fluidbox.git
cd fluidbox
docker compose -f deploy/docker-compose.eval.yml --profile runners pull
ANTHROPIC_API_KEY=sk-ant-... docker compose -f deploy/docker-compose.eval.yml up -d
```

Open <http://localhost:3000> and start a run. The eval stack is for trying the run loop locally, not for exposing to a network.

- To develop from source, see [Contributing](./CONTRIBUTING.md) — `just setup`, `just dev`, and `just doctor` cover the whole loop.
- To deploy on a cluster, see the [Kubernetes deployment guide](./docs/guides/kubernetes.md) — the Helm chart is published as an OCI artifact.

## When should I use fluidbox?

Use fluidbox when agents need to act on real systems and you need to answer *when they may run, what authority they receive, where they execute, and what evidence remains afterward*. Ad hoc agent execution inherits ambient credentials and leaves logs; a fluidbox run receives only a session token, executes in a disposable sandbox, and leaves an immutable `RunSpec`, an append-only decision ledger, a diff, and a cost report. If you just want a chat UI, fluidbox is not that — it is the authority layer your automations call.

## Features

### Governed runs

- Immutable [`RunSpec`](./docs/ARCHITECTURE.md) frozen at creation — agent revision, policy snapshot, capabilities, budgets, trust tier
- [YAML policies](./docs/guides/policies.md) with human approvals, autonomous fallbacks, and per-tool overrides
- Budget ceilings enforced before model spend; fork PRs get a read-only trust floor approvals cannot widen
- Append-only, redacted audit ledger with a live SSE timeline

### Event sources and delivery

- [Triggers and schedules](./docs/guides/triggers.md): subscription-scoped API tokens, cron, idempotent invocation, HMAC-signed result callbacks
- Native GitHub App events — one stable PR comment and one check per head SHA, updated in place
- Manual runs from the dashboard or CLI; every entry point converges on one `create_run` path

### Sandboxed execution

- Fresh Docker container or Kubernetes Pod per run; the original repository is never the working tree
- No upstream secret enters a sandbox — model, git, and MCP credentials stay control-plane-side
- Two harnesses ([Claude Agent SDK](./images/sandbox-runner) and [Codex](./images/codex-runner)) behind one runner contract
- [MCP capabilities](./docs/guides/capabilities.md): sandbox-local stdio tools and control-plane-brokered remote tools with frozen schemas

### Hosted multi-user and operations

- Opt-in [hosted posture](./docs/hosted/README.md): per-organization OIDC, RBAC, personal API tokens, PostgreSQL RLS, KMS envelope custody
- Organization- and user-owned connections, OAuth with PKCE, GitHub App installation flow, connector catalog
- Prometheus metrics, S3-compatible archives, multi-replica coordination
- Single-admin mode stays the default; nothing changes until `FLUIDBOX_REQUIRE_SSO` is set

## Documentation

Start with the [architecture overview](./docs/ARCHITECTURE.md), the [guides](./docs/guides), and the authoritative [plan](./PLAN.md). Release history lives in the [changelog](./CHANGELOG.md) and sequencing in the [roadmap](./ROADMAP.md).

fluidbox is pre-1.0: usable, moving quickly, and expecting breaking changes. Read [SECURITY.md](./SECURITY.md) and the hosted [threat model](./docs/hosted/threat-model.md) before operating it outside a local environment.

## Community & Support

- [GitHub Issues](https://github.com/hrishikeshdkakkad/fluidbox/issues) — bugs and feature requests
- [GitHub Discussions](https://github.com/hrishikeshdkakkad/fluidbox/discussions) — questions and ideas
- [Security advisories](https://github.com/hrishikeshdkakkad/fluidbox/security/advisories/new) — report vulnerabilities privately, never in a public issue

## Contributing

Contributions are welcome — code, integrations, policies, documentation, and security hardening. Start with [CONTRIBUTING.md](./CONTRIBUTING.md), run `just check`, and run `just e2e` for changes that touch a governance path. Architectural changes must preserve the convergence invariants in [`PLAN.md` §2](./PLAN.md).

## License

[MIT](./LICENSE) © fluidbox contributors.
