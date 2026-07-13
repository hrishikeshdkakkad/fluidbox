# Roadmap

The distilled version. [`PLAN.md`](./PLAN.md) is the authoritative design document — its §2 convergence invariants govern every change; this page just tells you where the project is and where help is welcome.

## Shipped (v0.1.0)

- **The governed vertical slice** — versioned agents, frozen RunSpecs, disposable Docker sandboxes, live SSE timelines, policy gate + human approvals + autonomous mode, budgets, diff + cost reports, append-only redacted ledger.
- **Two harnesses** behind one runner contract: Claude Agent SDK and Codex.
- **Credential inversion everywhere** — LLM facade, control-plane git fetches, brokered MCP tools, OAuth custody with sealed rotating refresh tokens.
- **Borrow the agent, on demand** — scoped API triggers, cron schedules (exactly-once), signed result webhooks, GitHub App connect + PR fan-out with fork-PR read-only trust.
- **Capability & connector catalogs** — versioned MCP tool bundles pinned at run creation; app-store-style connect.

## Next

| # | What | Why | Status |
|---|------|-----|--------|
| 1 | **Slack vertical** (Phase 7) | second event connector; validates the provider-ignorant event spine before any public connector SDK | next up |
| 2 | **AWS Lambda MicroVM provider + BYOC** (M2) | the production execution substrate: 8h leases with rollover, idle-suspend for days-long autonomous agents, Terraform BYOC | designed (PLAN §7 M2), not started |
| 3 | **Customer-built agents** (M3 remainder) | signed, versioned runner images implementing the runner contract — bring your own agent | after M2 |
| 4 | **Brokered git writes** (design §17 #4) | push/PR-create as brokered operations riding the same broker gateway | explicitly deferred, seam ready |

## Help wanted

Good first contributions are labeled on the [issue tracker](https://github.com/hrishikeshdkakkad/fluidbox/issues) — currently: CI hardening, the codex execpolicy relative-path residual, GitHub App advisory locks, and an architecture diagram. Before picking up anything architectural, read `PLAN.md` §2 (the invariants) and [`CONTRIBUTING.md`](./CONTRIBUTING.md).

Changes land phase-by-phase, fully tested (`just check` + `just e2e`) — see the [changelog](./CHANGELOG.md) for what shipped when.
