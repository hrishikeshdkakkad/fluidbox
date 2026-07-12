# Changelog

All notable, user-visible changes to fluidbox are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow [SemVer](https://semver.org) once tagged releases begin. Until then, everything lives under **Unreleased**.

## [Unreleased]

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
