# Hosted product boundary

These documents define the supported product boundary for the hosted, multi-user fluidbox deployment (~300 seats). They are the Phase A deliverable of the multi-user MCP control plane epic (#28).

| Document | Question it answers |
|---|---|
| [Product compatibility matrix](product-compatibility-matrix.md) | What is supported, deferred, or permanently out — MCP primitives, transports, connections, auth modes, identity, harnesses, providers — and what happens at each boundary |
| [Connector admission policy](connector-admission-policy.md) | Which remote MCP endpoints may ever be contacted, by whose decision, and what is always refused |
| [Hosted network architecture](network-architecture.md) | The planes, listeners, and every network edge — initiator, authentication, cargo, and what must never cross |
| [Threat model](threat-model.md) | Assets, adversaries, trust boundaries, scenario→control mapping with honest status, accepted residuals, and the gap register |

**Operator runbook.** [KMS operations](kms-operations.md) — the Phase D custody layer: envelope sealing (DEK/KEK, the `FLUIDBOX_KMS_MODE` boot matrix), the resumable re-seal + legacy-key retirement procedure, disaster recovery, per-tenant LiteLLM virtual keys, and Row-Level Security operations.

**Authority.** These documents *state* settled decisions; they make none. The normative sources are:

- [`../plans/2026-07-14-multi-user-mcp-control-plane-design.md`](../plans/2026-07-14-multi-user-mcp-control-plane-design.md) (v4) — the multi-user architecture, security invariants 1–22, Gaps 1–14, Phases A–F
- [`../plans/2026-07-17-idp-agnostic-identity-design.md`](../plans/2026-07-17-idp-agnostic-identity-design.md) (v5) — the Phase B identity layer, identity invariants 1–12
- [`../../PLAN.md`](../../PLAN.md) — product convergence invariants

If a statement here disagrees with those documents, the design documents win and the file here has a bug. Changes to the boundary go through the design documents first.
