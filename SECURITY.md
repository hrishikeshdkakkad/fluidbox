# Security Policy

fluidbox's core promise is **containment and accountability** for AI coding agents. Security reports are not an inconvenience here — they are exactly the contributions we value most.

## Reporting a vulnerability

**Please do not open a public issue for security problems.**

Preferred: use GitHub's private vulnerability reporting — [**Report a vulnerability**](https://github.com/hrishikeshdkakkad/fluidbox/security/advisories/new) — which opens a private thread with the maintainer.

Alternatively, email **hrishidkakkad@gmail.com** with `[fluidbox security]` in the subject.

You can expect an acknowledgement within **72 hours** and an assessment (confirmed / not a vulnerability / need more info) within a week. Please give us a reasonable window to ship a fix before public disclosure; we will credit you in the advisory and changelog unless you prefer otherwise.

## What counts as a vulnerability

Anything that breaks the security model described in [`docs/ARCHITECTURE.md`](./docs/ARCHITECTURE.md) and `PLAN.md`. High-interest areas:

- **Sandbox escape or egress** — an agent workload reaching the network, host filesystem, or credentials it shouldn't.
- **Credential exposure** — provider API keys, git credentials, OAuth/refresh tokens, or webhook secrets reaching a sandbox, a log, the ledger, or an API response. (Credentials are supposed to be sealed at rest and only ever used control-plane-side.)
- **Policy/approval bypass** — executing a tool call without the permission gate deciding it, escalating a fork PR's read-only trust tier, or replaying/forging an approval.
- **Audit-trail integrity** — writing unredacted prompts to the ledger, mutating a frozen `RunSpec` or policy snapshot, gaps or forgeries in the per-session event sequence.
- **Ingress authentication** — webhook signature bypass, trigger tokens reaching admin surfaces, OAuth `state`/PKCE weaknesses in the connector flow, forged GitHub App installation handling.
- **Budget/metering bypass** — driving model usage past a run's budget stop.

Also in scope: the usual suspects (SQL injection, authz gaps between the `/v1` admin API and the `/internal` session-token gateway, SSRF from the control plane, dependency vulnerabilities with a demonstrated impact).

Out of scope: vulnerabilities in upstream projects themselves (LiteLLM, Docker, Neon, the agent SDKs) — report those upstream, though we appreciate a heads-up if fluidbox's default configuration makes one exploitable.

## Supported versions

fluidbox is pre-1.0; only the latest `main` receives security fixes. There is no bug bounty — just fast fixes and public credit.

## Hardening notes for operators

- Keep `.env` out of version control (already gitignored) and rotate `FLUIDBOX_ADMIN_TOKEN` and `FLUIDBOX_CREDENTIAL_KEY` if a machine is compromised. Rotating `FLUIDBOX_CREDENTIAL_KEY` orphans sealed credentials — reconnect integrations afterwards.
- The Anthropic key belongs **only** in the LiteLLM container environment, never in the Rust server's.
- Run the dashboard and API behind TLS in any non-local deployment; `FLUIDBOX_PUBLIC_URL` must be HTTPS for OAuth client-ID metadata to be used.
