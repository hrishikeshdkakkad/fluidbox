# fluidbox 🧊

**Run AI coding agents in governed, disposable sandboxes — with policy, human approvals, audit, and cost control.**

fluidbox is an open-source (MIT) control plane for agent execution. You register an
**agent definition** (a versioned recipe: harness, model, prompt, policy, budgets),
then start **runs** of it. Each run freezes an immutable RunSpec, gets a fresh
isolated sandbox, streams a live timeline, pauses for human approval on risky
actions (or runs fully autonomous under stricter guardrails), and ends with a
diff, a cost report, and an append-only audit trail.

- **Backend:** 100% Rust (axum, sqlx, bollard)
- **Frontend:** Next.js (presentation-only)
- **Database:** Neon Postgres
- **Model gateway:** LiteLLM (pinned) behind a thin Rust session facade — provider
  keys never enter a sandbox
- **First harness:** Claude Agent SDK running inside the sandbox
- **First runtime:** Docker; AWS Lambda MicroVMs next

See [`PLAN.md`](./PLAN.md) for the full architecture, the north star, and the roadmap.

## Quickstart

```bash
cp .env.example .env       # fill in DATABASE_URL, ANTHROPIC_API_KEY, tokens
just sandbox-build         # build the sandbox runner image
just dev                   # LiteLLM + server + web
```

Then open http://localhost:3000, or use the CLI:

```bash
cargo run -p fluidbox-cli -- run --repo /path/to/repo --task "fix the failing test"
```

## Repository layout

```
crates/fluidbox-core       pure domain: policy engine, events, state machine, traits
crates/fluidbox-db         sqlx repositories, migrations, LISTEN/NOTIFY
crates/fluidbox-provider   DockerProvider (Lambda MicroVMs provider lands in M2)
crates/fluidbox-server     axum API + SSE + orchestrator + LLM session facade
crates/fluidbox-cli        the `fluidbox` command
apps/web                   Next.js dashboard
images/sandbox-runner      the sandbox image + Claude Agent SDK runner payload
deploy/                    docker-compose + LiteLLM config
migrations/                SQL migrations (embedded; run automatically on boot)
policies/                  seed policy YAML
```

## Name

“fluidbox” — package/crate collision check pending in M0 (see PLAN.md).

## License

MIT — see [LICENSE](./LICENSE).
