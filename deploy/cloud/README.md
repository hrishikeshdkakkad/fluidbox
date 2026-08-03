# Fluidbox Cloud M1 — deployment kit

Everything here operates **today's released Fluidbox** (chart `0.4.0`, GHCR
multi-arch images) as a managed AWS service for the invited private beta.
**Zero core code changes, zero chart changes** — the M1 contract
(`docs/plans/2026-08-03-fluidbox-cloud-m1-brief.md`); the parent strategy is
PLAN rev 3 (`docs/plans/2026-08-03-fluidbox-cloud-plan.md`).

## Stacks (apply order; every apply is per-action user-approved)

| # | stack | identity | what |
|---|---|---|---|
| 0 | `terraform/bootstrap` | **root, once** | state hygiene, operator user + scoped deployer role, two budgets, owned CloudTrail, root-activity alarm → then the root key is retired (README ceremony) |
| 1 | `terraform/platform` | deployer | VPC (10.42/16, public subnets, **no NAT**), EKS 1.35 (restricted endpoint, logs, netpol standard mode), t4g system NG + scale-from-zero sandbox NG, gp3, KMS KEK, Pod Identity ×4, ALB controller, cluster-autoscaler, ALB frontend SG (CloudFront prefix list), replay ECR |
| 2 | `terraform/app` | deployer | namespace, composed DB-backed LiteLLM, the **unchanged chart** (`web.enabled=false`, ingress → ALB, tenant LLM keys, staged SSO flags) — via `scripts/cloud/deploy-app.sh` (enforces make-secrets first) |
| 3 | `terraform/edge` | deployer | CloudFront → ALB (http-only origin, streaming-friendly), placeholder origin header — **must** be followed by `scripts/cloud/rotate-origin-secret.sh` |

Secrets NEVER transit Terraform: `scripts/cloud/make-secrets.sh` creates the
two Kubernetes Secrets out-of-band (and backs custody values into SSM
SecureString); the CloudFront origin header lives in SSM + the live config
only. State therefore stays secret-free (PLAN §P0 requirement).

## Scripts (`scripts/cloud/`)

| script | role |
|---|---|
| `verify-bootstrap.sh` | M1.0 gate evidence: guardrails live, root path retired |
| `make-secrets.sh` | out-of-band Secrets + SSM custody |
| `deploy-app.sh` | order-enforcing app apply wrapper |
| `rotate-origin-secret.sh` | CloudFront↔ALB origin-header rotation (both sides + SSM) |
| `direct-alb-check.sh` | §9-12 evidence: direct ALB refused, CloudFront serves |
| `replay-on-cluster.sh` | the NO-COST acceptance journey (real gate, real sandbox, real approval — no model key) |
| `idle-scaledown-watch.sh` | §9-15 evidence: sandbox capacity → 0 |
| `cloud-m1-acceptance.sh` | the §9 harness (18 criteria → one evidence ledger) |
| `teardown.sh` | reverse-order destroy + the two documented EKS leak sweeps |

## The staged flags (all helm values, never chart edits)

M1.1 platform gate runs **single-user** (`require_sso=false`) so the admin
token can drive the replay acceptance; the M1.2 onboarding apply flips
`require_sso=true` + `public_url=https://<vercel-origin>` — from then on the
admin token reaches only `/v1/admin/*` (the operator onboarding surface) and
browsers authenticate through each org's OIDC.

## Documentation

- `docs/hosted/cloud-architecture.md` — topology, edge lock, network posture, SSE path + fallback
- `docs/hosted/cloud-threat-model-m1.md` — M1 delta threat model (edge, Vercel processor, operator custody, IAM residuals)
- `docs/hosted/cloud-operator-runbook.md` — the §8 procedures (containment explicitly incomplete)
- `docs/hosted/cloud-onboarding-checklist.md` — provision a beta org end to end
- `docs/hosted/cloud-cost-model.md` — the re-verified ~$131/mo idle floor
- `docs/plans/2026-08-03-cloud-m1-decisions.md` — the §12 decision sheet
