# Security Policy

fluidbox's core promise is **containment and accountability** for AI coding agents. Security reports are not an inconvenience here — they are exactly the contributions we value most.

## ⚠ Read this before you deploy anything

Three properties of the shipped defaults, stated up front because each one has
surprised a reviewer:

1. **Two different strengths of "gated".** A **brokered MCP** call cannot execute
   without a server-side decision *structurally* — the control plane executes it.
   An **in-sandbox** call (`Bash`, `Edit`, `Read`, sandbox stdio MCP) is executed
   by the sandbox, and the gate binds it because the runner **routes** every call
   there (on the Claude harness, a mandatory `PreToolUse` hook; proven by
   `scripts/gate-proof.sh`, which needs no API key). That is a real control
   against a prompt-injected model. It is **not** a control against a workload
   already executing arbitrary code, and an older pinned `runner_image` routes
   nothing and is not detected server-side. For those, **containment** — not the
   gate — is the binding control.
2. **The Docker default is not an egress boundary.** `NetworkMode::HostDev` is
   the default: general internet egress **plus** `host.docker.internal`, i.e. the
   host's network position. Kubernetes `zeroEgress` and Docker `Hardened` are the
   modes that close it. Combined with (1), the default Docker profile is
   convenient rather than contained.
3. **The eval Docker profile publishes its API on all interfaces**, because
   sandboxes reach the control plane over the host gateway and a loopback publish
   would break every run. Its admin token is now **required** rather than
   defaulted (the old default was published in this repository), so the token is
   what protects it — not your network position. Run it on a trusted network.

Full detail: [`docs/release/claims-matrix.md`](./docs/release/claims-matrix.md)
lists every material claim with the command that checks it, and
[`docs/hosted/threat-model.md`](./docs/hosted/threat-model.md) carries the
adversary model and the accepted residuals.

## Reporting a vulnerability

**Please do not open a public issue for security problems.**

Preferred: use GitHub's private vulnerability reporting — [**Report a vulnerability**](https://github.com/hrishikeshdkakkad/fluidbox/security/advisories/new) — which opens a private thread with the maintainer.

Alternatively, email **hrishidkakkad@gmail.com** with `[fluidbox security]` in the subject.

You can expect an acknowledgement within **72 hours** and an assessment (confirmed / not a vulnerability / need more info) within a week. Please give us a reasonable window to ship a fix before public disclosure; we will credit you in the advisory and changelog unless you prefer otherwise.

## What counts as a vulnerability

Anything that breaks the security model described in [`docs/ARCHITECTURE.md`](./docs/ARCHITECTURE.md) and `PLAN.md`. High-interest areas:

- **Sandbox escape or egress** — an agent workload reaching the network, host filesystem, or credentials it shouldn't.
- **Credential exposure** — provider API keys, git credentials, OAuth/refresh tokens, or webhook secrets reaching a sandbox, a log, the ledger, or an API response. (Credentials are supposed to be sealed at rest and only ever used control-plane-side.)
- **Policy/approval bypass** — executing a tool call without the permission gate deciding it, escalating a fork PR's read-only trust tier, or replaying/forging an approval. **Especially valuable:** a tool call that reaches execution without a `tool.decision` in the ledger. That is the shape of the defect fixed in `v0.4.0-rc.1`, where the Claude Code CLI auto-approved its read-only classification beneath the SDK's permission callback. If you can make `scripts/gate-proof.sh` produce a side effect under a `deny` verdict, that is a report we want. Nested sub-execution (`Agent`, `Task`, `Workflow`, `Skill`, `TaskCreate`) is the known-untested case — the seed policy denies it rather than claiming to mediate it.
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
