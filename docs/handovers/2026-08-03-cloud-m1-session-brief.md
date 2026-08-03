# Session brief — Fluidbox Cloud M1 (Managed Private Beta)

Paste-ready handover prompt for the session that executes M1. Authoritative scope: `docs/plans/2026-08-03-fluidbox-cloud-m1-brief.md`. Parent strategy: `docs/plans/2026-08-03-fluidbox-cloud-plan.md` (PLAN rev 3).

---

You are picking up **Fluidbox Cloud M1 — Managed Private Beta**: operate today's self-hosted Fluidbox as a managed service on AWS for ~5–10 manually onboarded organizations. Two documents govern this work — read both before doing anything:

1. `docs/plans/2026-08-03-fluidbox-cloud-m1-brief.md` — the M1 implementation brief (scope, phases M1.0–M1.3, hard acceptance criteria §9). This is your contract for THIS milestone.
2. `docs/plans/2026-08-03-fluidbox-cloud-plan.md` — the full Fluidbox Cloud plan (rev 3, externally reviewed). Read it for the ownership model, edge/network decisions, identity corrections, and what is deliberately deferred to M2/M3/M4.

Also read `CLAUDE.md` (invariants + env gotchas) and skim `docs/reviews/2026-07-22-eks-acceptance-phase-f.md` (the proven EKS recipe and its two recurring teardown leaks).

## Non-negotiable constraints

- **Zero Fluidbox Core code changes and zero Helm chart changes.** M1 is release artifacts + automation around them. If something appears to require a core change, STOP and hand back — it's an M3 proposal, not an M1 task.
- **No Lambda cloud API, no DynamoDB, no provisioning saga, no automated WorkOS provisioning** — all M2. Onboarding is manual, by operator runbook.
- **Public signup stays off.** Trusted private beta only; quota gaps (no per-tenant run caps/credits) are documented, not fixed.
- **M1.0 gates everything**: no EKS deployment until the scoped IAM role (root key retired), two budgets (tag-filtered fluidbox + account-wide breaker), CloudTrail/root alarms, Terraform state hygiene, the OIDC login proof, the Vercel SSE/cookie probe, and the cost re-verification are recorded as PASSING.
- **Terraform applies are per-action approved by the user.** Never apply without an explicit go.
- **Standing agreement:** never run live-Neon/live-key suites or anything spending model money unprompted (`justfile` auto-loads `.env` — use explicit cargo/pnpm and prove `DATABASE_URL` unset). Live model runs use haiku (`FLUIDBOX_DEFAULT_MODEL=claude-haiku-4-5`) and are user-triggered.
- Local docker is **colima** (Docker Desktop VM deleted) — see memory `fluidbox-local-docker-colima` before touching a daemon.

## Execution order

Work the M1 brief's phases in order, handing back at each gate:

- **M1.0 Guardrails + proofs** → gate: all proofs pass, recorded in the docs.
- **M1.1 Managed EKS platform** → encode the known EKS recipe (VPC CNI netpol *standard* mode, avoid us-east-1a, gp3, arm64/t4g, LiteLLM 2Gi, t4g.medium system node, sandbox nodegroup scale-from-zero); chart unchanged with `web.enabled=false`; ALB controller + chart Ingress (`target-type: ip`, never a hand-built ALB to pod IPs); CloudFront → ALB locked by prefix list + rotating origin header; Pod Identity → KMS. Gate: healthy core, edge locked (direct-ALB refused), no-cost replay run completes on-cluster.
- **M1.2 Operator onboarding + beta access** → Vercel dashboard in sso/proxy mode (`FLUIDBOX_PUBLIC_URL` = the Vercel origin; core cookie lands there via the rewrites — see memory `fluidbox-web-auth-gate` for the local-SSO trio + proxy.ts trap), first org onboarded manually, checklist another operator can follow. Gate: invited user signs in unaided; cross-tenant entry impossible.
- **M1.3 Acceptance + handoff** → run every §9 criterion (18 items) with recorded evidence; publish threat model, network doc, operator runbooks (§8 list, containment explicitly labeled incomplete), validation report; reconcile the ~$130–140/mo idle cost.

## Decisions to collect from the user before execution (M1 brief §12)

Account-wide budget number; AWS account/region; IAM bootstrap approval; WorkOS-Connect-vs-other-OIDC for M1 identity; Vercel project link; first beta org + owner; approval for any real-model run.

## Verification bar

Per phase: `just check` green + existing hermetic suites untouched and green + that phase's terraform apply (with approval) + hand back. `just demo`-style replay is the no-cost acceptance vehicle. Evidence beats assertion: every gate produces a recorded artifact (doc, screenshot, command output) under `docs/reviews/` or the design doc.
