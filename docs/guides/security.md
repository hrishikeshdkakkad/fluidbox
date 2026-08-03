# Security model

fluidbox's promise is **containment and accountability**: hand an agent a
repository and a credential, and still be able to answer, afterwards,
exactly what it did and why it was allowed to. This page is the map of how
that promise is enforced; the [threat model](https://github.com/hrishikeshdkakkad/fluidbox/blob/main/docs/hosted/threat-model.md)
and [`PLAN.md`](https://github.com/hrishikeshdkakkad/fluidbox/blob/main/PLAN.md)
carry the full rationale.

## Credentials never enter a sandbox

The same inversion, three times:

- **Model access** — the sandbox's `ANTHROPIC_API_KEY` *is its session
  token*. The LLM facade validates it, enforces the budget stop, swaps in
  the real upstream credential (held only by the gateway container), and
  meters the streamed response as it forwards.
- **Git** — the credentialed fetch happens **control-plane-side, before the
  agent exists**, with credentials passed to git via ephemeral environment
  configuration — never argv, never on-disk config. The sandbox sees a
  bind-mounted copy at `/workspace`.
- **Brokered tools** — credentialed MCP servers are called **by the control
  plane**. The sandbox sends intent; the broker re-verifies the binding
  (status, authorization generation, owner membership) before touching the
  sealed credential, then returns a governed result.

At rest, every credential is sealed with authenticated encryption —
versioned envelope encryption with per-tenant data keys under a KMS-wrapped
key-encryption key in hosted deployments — and bound to its tenant and
column, so a stolen blob is untransplantable.

## One gate decides every tool call

There is exactly one place where "can this happen?" is answered, and it runs
a fixed sequence: **budget → frozen tool surface → frozen argument schema →
trust tier → policy → approvals.** Both tool paths — sandbox-side tools and
control-plane-brokered tools — pass the identical gate. The permission
callback stays wired in every autonomy mode; there is no bypass flag in the
system. Two floors sit above policy and cannot be approved away: a run out
of budget, and the **read-only trust tier** frozen onto runs from fork pull
requests.

## The audit trail cannot be quietly wrong

- **RunSpecs are frozen** at creation — model, prompts, policy snapshot,
  tool surface, budgets. Nothing that governed a run is mutable afterwards.
- **Agents and policies are append-only** — changes create revisions and
  versions, never edits.
- **The ledger only accepts redacted events** — the redaction type is the
  only constructor, so prompts and payloads *cannot* reach the database;
  digests, verdicts, usage, and cost can. Events carry a gapless
  per-session sequence, so a gap is evidence, not noise.

## The workload goes only where it was granted

A sandbox's network is **default-deny, and anything wider is an explicit,
frozen, auditable grant** — never an ambient capability.

By default a run is `offline`: on Kubernetes a deny-all NetworkPolicy,
admission-gated before the untrusted payload starts, and on Docker a
per-session internal bridge under the `hardened` profile. (The Docker
`host-dev` default is a local-development posture and has never been a hosted
boundary — it deliberately injects a host gateway.)

A run may instead be granted `approved` (exactly the FQDN/CIDR targets its
agent declared, capped by policy) or `public` (everything the deployment's deny
wall permits). Both are resolved BEFORE any sandbox exists, frozen into the
immutable RunSpec, and enforced at L3/L4 in the datapath — so there is no
application shim to bypass and nothing for the workload to opt into. A
deployment with no enforcer refuses a wider grant at create time rather than
running it unenforced, and `public` is refused outright for a run that also
holds brokered tool results unless policy explicitly opts in: the dangerous
pairing is credentials plus reach.

Policy may require a human to authorize a grant, which parks the run BEFORE
provisioning — no pod, no tokens, no model spend until someone consents to a
specific digest. See [network grants](../hosted/network-grants-operations.md). Separately, the **control plane's own egress** rides one hardened
boundary: destination admission that blocks private, loopback, link-local,
and cloud-metadata address classes at every dial site; redirect refusal on
the clients that carry credentials; and per-tenant/host rate limits with a
circuit breaker.

## Identity and tenancy (multi-user deployments)

Hosted mode adds per-organization OIDC login, server-side browser sessions,
personal API tokens, and RBAC — with the admin token confined to a
break-glass surface. Tenant isolation is a **signature requirement** in the
data layer (every tenant-owned query carries a verified tenant scope) with a
**database floor** underneath: PostgreSQL row-level security, forced even
for the table owner, keyed on a transaction-local tenant setting. The
dashboard is presentation-only; every decision it displays was made by the
Rust API.

## Scope honesty

fluidbox is pre-1.0. The security model above is implemented and tested
(unit suites plus end-to-end acceptance that drives real sandboxes,
approvals, OAuth against a local authorization server, and the failure
paths), but there are **no compliance certifications and no formal
third-party audit yet**. Known residual risks are documented in the
[threat model](https://github.com/hrishikeshdkakkad/fluidbox/blob/main/docs/hosted/threat-model.md)
rather than rounded away.

## Reporting a vulnerability

**Please do not open a public issue.** Use GitHub's private vulnerability
reporting — [report a vulnerability](https://github.com/hrishikeshdkakkad/fluidbox/security/advisories/new)
— or email the maintainer with `[fluidbox security]` in the subject
(addresses in [`SECURITY.md`](https://github.com/hrishikeshdkakkad/fluidbox/blob/main/SECURITY.md)).
Acknowledgement within 72 hours, an assessment within a week, and credit in
the advisory and changelog unless you prefer otherwise. Sandbox escape,
credential exposure, policy/approval bypass, audit-trail integrity, ingress
authentication, and budget bypass are exactly the reports we value most.

## Next

- [The permission gate](./governance.md) — the decision sequence in detail
- [Capabilities](./capabilities.md) — why brokered vs sandbox is the split
- [Kubernetes](./kubernetes.md) — the hardened deployment shape
