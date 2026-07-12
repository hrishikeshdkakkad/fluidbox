# Contributing to fluidbox

Thanks for your interest in fluidbox! Contributions of every kind are welcome: bug reports, reproductions, documentation fixes, tests, and code. This document gets you from a fresh clone to a merged PR.

## Ground rules

- Be kind. We follow the [Code of Conduct](./CODE_OF_CONDUCT.md).
- **Security issues go through [SECURITY.md](./SECURITY.md)**, never a public issue.
- [`PLAN.md`](./PLAN.md) is the authoritative design document. Read it before proposing architectural changes — every change must preserve the **convergence invariants in §2** (frozen RunSpecs, append-only agents, the always-wired permission callback, redaction-enforced ledger, credential inversion, and friends).
- For anything larger than a bounded bug fix, **open an issue first** so we can agree on the approach before you invest time.

## Hard constraints (non-negotiable)

These are locked project decisions, not style preferences:

- The fluidbox-authored backend is **100% Rust**. The only sanctioned non-Rust payloads are the runner harnesses inside sandbox images (`images/`).
- The Next.js dashboard is **presentation-only** — all logic lives in the Rust API.
- The database is **Neon Postgres** (any direct-connection Postgres works for development).
- Everything here is MIT-licensed; by contributing you agree your work is too (inbound = outbound).

## Development setup

### Prerequisites

| Tool | Why |
|------|-----|
| [Rust](https://rustup.rs) (stable, pinned by `rust-toolchain.toml`) | the control plane |
| [Docker](https://docs.docker.com/get-docker/) | sandboxes + the LiteLLM gateway |
| [just](https://github.com/casey/just) | task runner (`just --list` shows everything) |
| [pnpm](https://pnpm.io) + Node 24 | the dashboard |
| A [Neon](https://neon.tech) database (free tier is fine) | Postgres with `LISTEN/NOTIFY` |

### First run

```bash
git clone https://github.com/hrishikeshdkakkad/fluidbox.git
cd fluidbox
cp .env.example .env    # every variable is documented inline
just neon-setup         # provisions a Neon project, prints the DIRECT connection string
just sandbox-build      # build the Claude sandbox runner image
just dev                # LiteLLM gateway + Rust server + dashboard
```

Environment gotchas that cost real debugging time are documented in `.env.example` — read the comments before changing values. The two most common traps:

- `DATABASE_URL` must be the **direct** (non-`-pooler`) Neon connection string. PgBouncer transaction mode breaks sqlx prepared statements and `LISTEN/NOTIFY`.
- `FLUIDBOX_BIND` must stay `0.0.0.0:8787` — sandboxes reach the control plane through `host.docker.internal`, which cannot reach a loopback bind.

## Quality bar

All of this runs in CI; save yourself a round trip by running it locally first.

```bash
just check    # cargo fmt + clippy -D warnings + cargo test + web build — must pass on every PR
just e2e      # full acceptance suite — run it if you touched the permission/approval/trigger path
```

Notes:

- `cargo test -p fluidbox-core` is fast and needs no database.
- `cargo test -p fluidbox-db` (and the workspace run) hit a real Postgres via `DATABASE_URL`; the tests **self-skip** when it's absent, so a missing database won't fail you locally — but write DB tests so they keep that property.
- `just e2e` owns the full stack (needs port 8787 free — stop `just dev` first). The live-agent phase self-skips without `ANTHROPIC_API_KEY`.
- Behavior changes need tests. Bug fixes need a regression test that fails without the fix.

## Making changes

1. Fork and create a topic branch from `main`.
2. Keep PRs small and focused — one logical change per PR.
3. Follow [Conventional Commits](https://www.conventionalcommits.org) as used throughout the history: `feat(server): …`, `fix(codex): …`, `docs: …`, `chore(db): …`.
4. Update documentation when behavior changes (`README.md`, `docs/`, `.env.example` comments) and add a line to `CHANGELOG.md` under **Unreleased** for user-visible changes.
5. Open the PR — the template will walk you through the checklist. CI must be green.

### Where things live

| Change | Start here |
|--------|-----------|
| Domain rules (policy, state machine, events, specs) | `crates/fluidbox-core` — pure, no I/O, tests live next to the code |
| API endpoints, orchestration, approvals, SSE | `crates/fluidbox-server` |
| Persistence | `crates/fluidbox-db` + `migrations/` (append a new migration; never edit an applied one) |
| Sandbox lifecycle | `crates/fluidbox-provider` |
| Agent harnesses / runner images | `images/` (this is sandbox workload — Node is allowed here) |
| Dashboard | `apps/web` (presentation only) |
| Feature designs & research notes | `docs/plans/`, `docs/research/` |

### Extension points

The two seams designed for contribution:

- **New execution backend** → implement `ExecutionProvider` (`crates/fluidbox-core/src/traits.rs`).
- **New agent harness** → a new runner image implementing the HTTP runner contract plus one arm in the `harness.rs` registry.

See [`docs/ARCHITECTURE.md`](./docs/ARCHITECTURE.md) and `PLAN.md` §6.2 before starting either.

## Reporting bugs & requesting features

Use the [issue templates](https://github.com/hrishikeshdkakkad/fluidbox/issues/new/choose). For bugs, include your OS, how you're running fluidbox (`just dev`, CLI, …), and relevant log output — the server logs with `tracing`, so `RUST_LOG=debug` output is gold.

## Questions?

Open an issue with the question label. If you're unsure whether an idea fits the project's direction, check `PLAN.md`'s north star first — and when in doubt, ask before building.
