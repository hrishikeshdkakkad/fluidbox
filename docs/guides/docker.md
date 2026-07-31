# Docker

Two Docker paths: the **eval stack** (published images, one command, nothing
built locally) and the **from-source stack** (`just` recipes around a local
build). Both run the same control plane; the difference is posture.

## Eval stack — fastest path

No Rust toolchain, no Node, no external Postgres:

```bash
git clone https://github.com/hrishikeshdkakkad/fluidbox.git
cd fluidbox
docker compose -f deploy/docker-compose.eval.yml --profile runners pull
ANTHROPIC_API_KEY=sk-ant-... docker compose -f deploy/docker-compose.eval.yml up -d
```

Open <http://localhost:3000> — the dashboard lives at `/app`, the control
plane API at <http://localhost:8787>.

What that starts:

| Service | Image | Role |
| --- | --- | --- |
| `postgres` | `postgres:16` | bundled database (volume `fluidbox-pg`) |
| `litellm` | pinned gateway image | the **only** container holding provider keys |
| `server` | `ghcr.io/hrishikeshdkakkad/fluidbox-server` | the Rust control plane, `:8787` |
| `web` | `ghcr.io/hrishikeshdkakkad/fluidbox-web` | the dashboard + public site, `:3000` |

The `--profile runners pull` fetches the two **runner images**
(`fluidbox-sandbox-runner`, `fluidbox-codex-runner`) into the host daemon.
They are not services: the server spawns them as sibling containers over the
mounted Docker socket, so they must exist host-side before the first run.

Two quirks worth knowing rather than debugging:

- **The data directory must be the same absolute path on the host and in the
  server container.** Workspace directories under it are bind-mounted into
  sandbox containers by the *host* daemon, which resolves host paths.
- The server binds `0.0.0.0:8787` and publishes the port because sandboxes
  reach the control plane via `host.docker.internal` — a loopback bind is
  unreachable from inside a container.

**Eval only.** Defaults favor zero-setup over hardening: a bundled Postgres,
a well-known admin token, no credential key (so credential-backed
integrations and webhook ingress stay disabled). Try the run loop with it;
do not expose it to a network.

## From source

The developing-and-operating path — real secrets, your database, rebuilt
images:

```bash
just setup          # idempotent: .env + secrets, web env, pnpm install, runner image
just doctor         # preflight — validates every environment gotcha, prints the fix
just db-up          # local Postgres container on 127.0.0.1:5433
just gateway-up     # the pinned LiteLLM gateway (reads .env)
just dev            # gateway + control plane + dashboard together
```

`just sandbox-build` / `just codex-build` rebuild the runner images after
editing `images/`. The [getting started](./getting-started.md) guide walks
the first governed run end to end.

## Where the isolation actually is

Each run gets a **fresh container** from the harness's runner image, with a
bind-mounted workspace copy and a per-session token disguised as its model
API key. The workload needs **no network egress**: model calls terminate at
the control plane's facade, credentialed git happened before the sandbox
existed, and brokered tools execute control-plane-side. Docker here is the
development-grade provider; the same `ExecutionProvider` seam backs the
[Kubernetes provider](./kubernetes.md), where runs are Jobs with
NetworkPolicy-enforced zero egress.

## Published images

Releases publish five images to GHCR (`server`, `web`, `sandbox-runner`,
`codex-runner`, plus the Helm chart as OCI). Pin runner images to the
release you deploy — the runner contract is versioned with the server, and
a mismatched pair refuses loudly rather than degrading silently.

## Next

- [Kubernetes](./kubernetes.md) — the production-shaped deployment
- [Security model](./security.md) — what the sandbox can and cannot reach
- [Getting started](./getting-started.md) — first governed run
