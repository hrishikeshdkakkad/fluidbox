# Changelog

All notable, user-visible changes to fluidbox are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow [SemVer](https://semver.org).

## [Unreleased]

### Added

- **Connector-catalog bulk import (schema + tooling)** — the catalog is now import-ready without importing a single row. A `provenance` column (migration 0009) makes every entry auditable and refreshable; curated seeds carry `{"source":"fluidbox"}` and can never be clobbered by an import. A new reference-only transport, `rest_action`, lets an imported entry that has no hosted MCP endpoint to photograph show up as a browsable Store card whose **Connect is refused** (`400`, "reference-only"); `GET /v1/catalog` now derives a `connectable` flag per entry so the dashboard can badge those cards. An offline dev tool, `just catalog-import-registry` (`crates/fluidbox-catalog-import`), imports from **two Apache-2.0 sources**: the official **[MCP Registry](https://github.com/modelcontextprotocol/registry)** (primary — real MCP servers; entries with a `streamable-http` remote import **connectable today** through the existing broker/photograph path) and **[open-connector](https://github.com/oomol-lab/open-connector)** (supplement — REST-only reference cards). It pages the Registry live (or from a pinned snapshot), keeps only `active`/latest servers, merges Registry-wins on slug collision, runs the SAME poison screen as capability registration over every imported string (offenders drop their whole entry), and emits a deterministic, append-only, sorted `INSERT … ON CONFLICT` migration of untrusted **community**-tier rows — each provenance-tagged with its source + pinned snapshot/commit. The tool never runs at boot or request time and is not in the server crate graph; attribution is recorded in `NOTICE`. The actual breadth (the generated import migration) is a separate, legally-gated merge.
- **Bring your own MCP server** — a guided "Add your own server" flow on the Capabilities page: paste a URL, and a non-committing probe (`POST /v1/mcp/probe`) detects whether it needs no auth, an API key, or OAuth and previews its tools without storing anything or sending a secret; one confirm (`POST /v1/mcp/servers`) registers a `tier=custom` catalog entry and connects it in a single call, rolling the entry back if the connect fails so no orphan card survives. Bundle rows now expand to show their photographed tools.
- **Server-authoritative harness/model catalog** — `GET /v1/harnesses` is the single source of truth for the supported harness + model set; the dashboard's pickers fetch it instead of hardcoding models, and `create_agent`/`add_revision` now reject a model that doesn't belong to its harness with a clean **422** at agent-write time instead of a murky failure at the first model call.
- **CI now tells the truth** — the rust job runs against a real Postgres service (the DB tests no longer silently self-skip), an `e2e` job builds both runner images and runs the full no-model acceptance suite (closes the vacuous-green gap of #14), and `cargo deny check` (advisories/licenses/bans/sources, `deny.toml`) gates the supply chain. The `e2e` job is **manual-only** (`workflow_dispatch`) — it costs real Actions minutes, so it never runs on a PR or push; the cheap gates (rust/web/deny) still run on every PR. Live model tiers stay local/manual — CI never spends credits. Coverage (lcov artifact) runs on main pushes.
- **Property tests for the policy engine** — generated-input invariants in `fluidbox-core`: an autonomous run can never surface `RequireApproval`, autonomy rewrites exactly the approval verdicts (original always ledgered), the read-only tier denies any shell metacharacter and any unlisted tool, shell prefixes are token-bounded, first match wins.
- **Try-it-with-Docker distribution** — `deploy/server.Dockerfile` + `deploy/web.Dockerfile` (Next standalone output), a `release` workflow publishing multi-arch images to GHCR on version tags or manual dispatch, and `deploy/docker-compose.eval.yml`: bundled Postgres + LiteLLM + server + dashboard in one `docker compose up`.
- **User guides** (`docs/guides/`) — writing policies, triggers/schedules/signed results (with the HMAC verification recipe and a pinned test vector), and capabilities (sandbox vs brokered MCP tools, pinning, the connector catalog).
- **`ROADMAP.md`** — the public distillation of `PLAN.md` §7.

- **`just setup`** — one-command idempotent bootstrap for a fresh clone: tools check, `.env` with generated secrets (`FLUIDBOX_ADMIN_TOKEN`, `FLUIDBOX_CREDENTIAL_KEY`, `LITELLM_MASTER_KEY`), dashboard env (`apps/web/.env.local`) kept in sync, `pnpm install`, and the sandbox runner image build. Only fills placeholders — never overwrites values you set.
- **`just doctor`** — environment preflight (#13): validates every documented gotcha (pooled vs direct `DATABASE_URL`, loopback `FLUIDBOX_BIND`, credential key shape, missing runner images, dashboard token drift, missing web deps) and prints the exact fix per failure; exits non-zero only on hard failures, never echoes secret values.

### Changed

- `just neon-setup` now writes the DIRECT connection string into `.env` when `DATABASE_URL` is still the placeholder (an existing value is never clobbered).
- README quickstart, CONTRIBUTING dev setup, and the dashboard README (`apps/web/README.md`) rewritten around the `just setup` → `just neon-setup` → `just dev` flow.

## [0.1.0] — 2026-07-12

The first tagged release: the complete governed vertical slice, verified by a 10-phase live-inclusive acceptance suite (468 checks).

### Highlights

- **Governed agent runs end to end** — frozen RunSpecs, fresh sandboxes, live timelines, policy-gated tool calls with human approvals, and a diff + cost report per run.
- **Two harnesses behind one contract** — Claude Agent SDK and Codex, with an in-server LLM facade that meters usage and keeps provider keys out of every sandbox.
- **Borrow the agent, on demand** — API triggers, signed webhooks, cron schedules, and GitHub PR fan-out, all converging on one governed run path.

### Added

- **Governed runs end to end** — versioned agent definitions, immutable per-run `RunSpec` snapshots (model, prompts, policy, capability pins), fresh Docker sandboxes per run, live SSE event timelines with `Last-Event-ID` resume, and a final diff + cost report.
- **Policy engine & human approvals** — YAML policies evaluated on every tool call (allow / deny / require-approval), idempotent restart-safe approvals with expiry, and an autonomous mode that rewrites approval verdicts to a policy fallback while recording both verdicts.
- **Append-only audit ledger** — redaction enforced at the type level; prompts never reach the database, only digests, usage, cost, and decisions, with gapless per-session sequencing.
- **Two agent harnesses** — Claude Agent SDK and Codex runner images behind one HTTP runner contract; the LLM facade speaks both the Anthropic Messages and OpenAI Responses dialects.
- **Credential inversion** — the sandbox's `ANTHROPIC_API_KEY` is a session token; an in-server LLM facade validates it, enforces budget stops, meters streamed usage, and swaps in the real upstream credential held only by the LiteLLM gateway.
- **Git workspaces** — credentialed fetch/copy happens control-plane-side before the agent starts; sandboxes only ever see a bind-mounted copy and stay egress-free.
- **Triggers** — subscription-scoped API tokens, signed webhook ingress with two-level dedup that heals partial fan-outs, cron schedules with exactly-once firing and explicit missed-run/concurrency policies, and HMAC-signed result delivery with retry/backoff.
- **GitHub integration** — seamless GitHub App connect (manifest + install flows), PR fan-out with one stable comment per PR and one check per head SHA, and fork PRs frozen to `ReadOnly` trust with no approval escape.
- **Capability catalog** — append-only versioned MCP tool bundles pinned at run creation; sandbox tools run as contained stdio subprocesses while brokered tools execute on the control plane with sealed credentials the sandbox never sees.
- **Connector catalog + OAuth** — catalog-driven connect flows with PKCE (S256), RFC 8707 resource indicators, DCR/CIMD client identity, sealed refresh tokens with atomic rotation, and fail-closed error states.
- **Dashboard** — Next.js UI (Runs, Agents, Integrations, Automations, Settings); presentation-only, all logic in the Rust API.
- **CLI** — `fluidbox run --repo … --task …` to drive runs from the terminal.
- **Ops** — `just` recipes for the full dev loop, an end-to-end acceptance suite (`just e2e`), Neon setup and DB-cleanup scripts, and CI (fmt, clippy `-D warnings`, tests, dashboard build).

### Changed

- Dependency refresh: `sha2` 0.11, `hmac` 0.13, `chacha20poly1305` 0.11, `jsonwebtoken` 10 (pinned to the pure-Rust `rust_crypto` provider), React 19.2.7, TypeScript 6, and current GitHub Actions. The sealed-credential wire format (`nonce ‖ ciphertext`) is unchanged — existing sealed credentials open fine.
