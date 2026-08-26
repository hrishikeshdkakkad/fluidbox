# Fluidbox Cloud — fully managed hosted platform (PLAN, rev 4)

Status: **rev 4 (2026-08-26) — split at the repository boundary; body below is the rev-3 historical record.**

Rev 3 → rev 4 change ledger (owner decisions, 2026-08-26):

- **The commercial and managed-service design moved to the private
  `fluidbox-cloud` repository.** This repository keeps no billing-domain code,
  schema, or design content; the dependency arrow is one-way (`fluidbox-cloud`
  consumes fluidbox's public APIs and published artifacts; fluidbox never
  knows the managed layer exists).
- **The OSS-side authority is now
  [`2026-08-26-cloud-boundary-design.md`](./2026-08-26-cloud-boundary-design.md)** —
  the boundary contract, the upstream-gateway seam, the ranked capability
  gaps, the M3 generic-capability interface specs, the rollout-gate
  re-scoring, and the disposition of this plan's P0–P7 phases. That document
  satisfies the OSS half of this plan's P0 design-doc deliverable; the
  commercial half lives in the private repository.
- **Substrate:** the EKS estate this revision describes was torn down
  2026-08-15; the live deployment is GCP/GKE (`deploy/cloud/gcp/`,
  `docs/hosted/gcp-*.md`). **Identity:** the per-org WorkOS Connect assumption
  was disproven and re-decided as bring-your-own IdP per org, with Auth0 as
  the operated default (see `2026-08-03-cloud-m1-decisions.md` and the
  2026-08-25 evidence).
- **Unchanged and still binding:** the ownership deciding test and rules
  (below), zero core changes outside separately-approved generic
  capabilities, and public self-serve gated on the quota-enforcement
  capability set (boundary design §6(a)/(b)/(d)).

The body below is retained verbatim as the rev-3 record. Where it conflicts
with the change ledger above or the boundary design, the newer documents win.

---

Rev-3 status was: **DRAFT — architecture conditionally approved by external review; P0 kill-switch proofs gate implementation.** Rev 3 incorporates the full external review of rev 2 (4 blockers + corrections) and the Core-vs-Cloud ownership model settled in follow-up discussion.

## Context

Fluidbox is a self-host product (Rust control plane governing AI-agent runs; GHCR images + Helm chart; k8s provider proven on EKS twice with zeroEgress netpol). **Fluidbox Cloud** hosts it: sign up (WorkOS) → create org → tenant provisioned → submit runs → watch/inspect — no infrastructure knowledge. The multi-user epic already built the hosted engine (org==tenant + RLS, per-org OIDC, sealed custody, per-tenant LLM keys, REQUIRE_SSO). Missing: self-serve identity/provisioning, a hosted deployment (no IaC exists), product wrap (onboarding, org management, usage), metering presentation.

Locked user decisions: **EKS with the chart unchanged; zero core-code changes in M1/M2** (generic core capabilities are M3, each separately approved); real AWS applies as phases land; web on Vercel; budget guardrails from day 0.

## Milestones

- **M1 — Managed Fluidbox on Kubernetes (private beta):** existing release artifacts on EKS, operator-grade automation around them. Zero core changes.
- **M2 — Self-serve cloud management:** signup, WorkOS org mapping, provisioning saga, hosted org management, usage — all composed over existing `/v1` + `/v1/admin/*`. Zero core changes.
- **M3 — Hosted-grade generic core capabilities (each separately approved, own design/PR):** atomic per-tenant run caps + monthly compute credits (capacity-scheduling design), tenant suspend/reactivate, membership preauthorization (invite-only JIT), usage export API, purge. **Public self-serve launch is gated on M3 quota enforcement** — M1/M2 serve a trusted private beta only.
- **M4 — Execution economics (optional, later):** scale-to-zero core / alternative providers. The rev-1 Lambda+Fargate analysis is preserved as a design-doc appendix; nothing from it is built now.

## Ownership model (the deciding test: *if Core were called directly, bypassing the cloud layer, must the rule still hold? If yes → it lives in Core*)

| Information | Authority | Cloud DB (DynamoDB) holds |
|---|---|---|
| Tenants, memberships, roles, sessions/PATs | Core | references only — never copied authorization state |
| Agents, policies, runs, approvals, credentials | Core | nothing (run traffic goes browser→proxy→Core directly) |
| Raw usage entries | Core (Postgres) | recomputable monthly aggregates (display cache) |
| WorkOS org/user ↔ core tenant/user links | **Cloud** | `workos_org_id↔core_tenant_id/slug`, `workos_sub↔core_user_id`, `connect_app_id↔core_idp_config_id` |
| Provisioning sagas, idempotency ledger | **Cloud** | full step ledger, versioned/conditional transitions |
| Hosted plan / billing refs / hosted status / placement | **Cloud** | plan id, `provisioning|ready|needs_operator|offboarded` |
| Operator token | AWS SSM | never DynamoDB |
| Per-org OIDC client secret | Core sealed custody | passed once during provisioning; no plaintext retained |

Rules: no shared database; the cloud layer never writes Core's Postgres; Cloud DB is rebuildable by reconciliation (losing it disrupts provisioning/billing, never tenants/permissions/runs); a stale mapping never grants access — Core is re-consulted for authority on every mutation. Nothing WorkOS/Stripe/AWS-shaped ever enters Core.

## Architecture

```
Product        Vercel: apps/web — marketing /, docs, /app dashboard
               ├─ /api/fluidbox/* + /v1/* rewrites (sso mode) → Core; core cookie
               │    lives on the VERCEL origin (login dance rides these rewrites)
               └─ /api/cloud/* → Cloud API (forwards WorkOS token + core cookie)
Managed cloud  Rust Lambda (lambda_http + axum — NOT LWA; that's only for wrapping
(NEW)          existing servers): signup/saga/org-mgmt/usage. DynamoDB per ownership
               table. EventBridge: hourly rollup + 15-min saga sweep. SSM secrets.
Core platform  EKS persistent dev cluster, chart UNCHANGED (web.enabled=false):
(EXISTING)     fluidbox-server + LiteLLM pods; Neon (+small LiteLLM DB); REQUIRE_SSO=1,
               runtime-role RLS, FLUIDBOX_KMS_MODE=aws via EKS Pod Identity
Execution      existing k8s provider: sandbox pods, zeroEgress netpol + admission gate
(EXISTING)     preserved exactly; sandbox nodegroup scales 0↔N (Cluster Autoscaler)
```

**Edge/network (concrete, per review):** system nodegroup (t4g.medium on-demand) in a public subnet with public IP, no inbound, tight SGs, **no NAT ever** (nodes need egress to Neon/WorkOS/GHCR/model APIs; sandbox *pods* stay zeroEgress-constrained regardless of node egress). Sandbox nodegroup: managed, Cluster Autoscaler scale-from-zero (Karpenter deferred). Ingress = AWS Load Balancer Controller + the **chart's existing Ingress** (`target-type: ip`) — Terraform must not hand-build an ALB against pod IPs. CloudFront (default cert, no domain needed) → ALB, origin locked by the CF prefix list **plus a rotating secret origin header** enforced by an ALB listener rule. ALB idle timeout > SSE keepalive (15s). KMS access via **EKS Pod Identity** association (no SA annotations). EKS control-plane logs on; API endpoint access restricted.

**Hosts:** `FLUIDBOX_PUBLIC_URL` = the **Vercel dashboard origin** (browser-facing: login callback, `/v1/oauth/go|callback`, CIMD all ride the sso rewrites so `__Host-fbx_web` lands on the Vercel host — the review's callback-host trap). CLI/PAT + programmatic traffic uses the CloudFront API host directly (bearer, no cookies). Sandboxes keep the in-cluster control URL (existing k8s behavior).

## Identity (review-corrected)

1. **Per-org WorkOS Connect app** created by the saga via the WorkOS API — WorkOS supports `organization_id` restriction on Connect applications, which makes IdP-side org binding the zero-core-change path. Each org's `org_idp_configs` row gets that app's issuer/client_id/secret (sealed by Core). **P0 spike proves:** nonce echoed into the id_token, PKCE tolerated on a confidential client, `organization_id` restriction actually enforced at authorize time, organizations `external_id` support. *Fallback if restriction fails:* invite-only JIT preauth = an M3 core proposal (flag-gated), not assumed; interim = closed beta with WorkOS sign-ups disabled, residual risk documented.
2. **Login UX:** AuthKit signs the browser into the Vercel app first → user picks/creates an org (`GET /me/orgs` from cloud mappings) → browser navigates the proxied core login (`/v1/auth/login/{slug}/start` on the Vercel origin) → AuthKit (already-authenticated SSO hop) → core callback via rewrite → `__Host-fbx_web` set on the Vercel origin. **Dual-session state machine is explicit:** logout clears both (core `/v1/auth/logout` + WorkOS signout); org switch uses core's existing switch interstitial; adversarial tests cover WorkOS-only, core-only, mismatched-org, one-expired, one-sided-logout. This supplies the lifecycle whose absence is *why* `sso+workos` refuses boot today — the unblock ships with the state machine, not instead of it.
3. **Cloud API authorization (no email matching — WorkOS access tokens carry `sub/sid/org_id/role`, not email):** pre-provisioning ops (create org, saga status, org discovery) authorize on the verified WorkOS JWT (`sub`, `org_id`). Org-scoped mutations derive authority from **Core**: the proxy forwards the core session cookie; the cloud Lambda calls `GET /v1/auth/me` and requires the caller's core roles (admin/owner) for that org. The `workos_sub↔core_user_id` link is recorded at first bind; email is never the durable join key.

## Provisioning saga (review-corrected idempotency)

DynamoDB step-ledger (PK `saga#{slug}`, versioned conditional transitions so two sweepers can't advance the same step), driven synchronously by the signup Lambda, resumed by status polls + 15-min sweep. Steps: reserve slug (conditional put; core regex + reserved list) → WorkOS org create with **deterministic `external_id = fluidbox:{slug}`** (lookup-by-external_id before create) → WorkOS membership → per-org Connect app create → core `POST /v1/admin/orgs` — **a 409 is accepted as success ONLY if this saga previously persisted a successful core response; otherwise `needs_operator`** (never adopt an unverified pre-existing tenant) → `POST .../idp` (per-org app issuer/client/secret + `bootstrap_owner_email` = signup email; live discovery) → activate → verify tenant LLM key (auto-minted) → ready → redirect into login. Secrets pass once into core custody; no plaintext retained in DDB. Failures after core-org-create flag `needs_operator`; never auto-rollback.

## Hosted management (M2, all composition)

Cloud API endpoints: `POST /signup/orgs`, `GET /signup/orgs/{slug}/status`, `GET /me/orgs`, `GET /orgs/{slug}` (plan/status), `GET /orgs/{slug}/members`, `POST /orgs/{slug}/invitations` (WorkOS invitation; + preauth iff M3 lands), `PUT /orgs/{slug}/members/{id}/roles`, `POST /orgs/{slug}/members/{id}/deactivate`, `GET /orgs/{slug}/usage?month=`. **Suspend is REMOVED from scope** (review: composed suspend is an irreversible soft-lockout that doesn't stop in-flight sandbox tokens or runs, and no reactivation API exists). M1 emergency containment = documented **manual operator runbook**: deactivate memberships + disable subscriptions + cancel each active run via existing endpoints, explicitly labeled incomplete/irreversible; real suspend/reactivate = M3 core proposal.

## Quotas & metering

- M1/M2 enforcement (existing, core-side): per-tenant LLM budgets via tenant-key knobs (`FLUIDBOX_LLM_TENANT_MAX_BUDGET=5`, rolling 30d — labeled as rolling, not calendar-month), per-run policy budgets ($2.50 / 1800s), global sandbox ResourceQuota, per-tenant egress rates. **Documented gap: no per-tenant concurrent-run cap or compute credits — private trusted beta only; public launch blocked on M3** (capacity-design atomic claims + run-minute credits + start-rate caps + admission kill switch).
- Plans live in Cloud DB as *commercial entitlement*; enforcement values are core-side settings — Cloud never becomes a shadow authorization DB.
- Usage rollup Lambda (hourly): **recompute the current month per tenant from Postgres and overwrite** the DDB aggregate (idempotent by construction; no additive watermark double-counting; late entries included). Read-only Neon access is an explicit transitional adapter; a generic core usage-export API is an M3 candidate.

## Phases (each: `just check` + existing hermetic suites green + that phase's terraform apply + hand back)

- **P0 — Guardrails + kill-switch proofs** *(first hand-back; implementation gated on these passing)*: design doc (delivered 2026-08-26 as [`2026-08-26-cloud-boundary-design.md`](./2026-08-26-cloud-boundary-design.md) — the OSS half: assessment, API inventory, ownership/boundary, gate re-scoring; the commercial half lives in the private `fluidbox-cloud` repository). Guardrail IaC applied first: scoped IAM deploy role (retire root-key use; scoped `iam:PassRole`), **two budgets** (tag-filtered $50 fluidbox + account-wide kept as second circuit-breaker — user sets its number), CloudTrail/root-activity alarms, log retention, ECR/S3 lifecycle, Terraform state encrypted/versioned/locked with no secret values in state. **Proofs:** WorkOS Connect spike (nonce, PKCE, organization_id restriction, external_id, invitations) against Staging; dual-session login flow demonstrated against a local core through a dev Vercel deployment (cookie lands on the right host, dual logout works); Vercel SSE pass-through probe (duration cap measured; Last-Event-ID resume UX acceptable); cost model re-verified incl. IPv4 + ALB LCUs. *(Moot on this substrate, recorded as such: CloudFront-OAC/bearer collision, Lambda starvation, artifact payload limits, RunTask idempotency — Fargate/Lambda-core findings; oauth advisory lock already exists in core.)*
- **P1 — Cloud scaffold + hermetic saga**: `crates/fluidbox-cloud` (axum + `lambda_http`), DDB tables per ownership model, SSM wiring, CI job, `scripts/cloud-e2e.sh` (identity-e2e style; dynamodb-local + Dex-as-AuthKit + fake WorkOS behind `FLUIDBOX_CLOUD_WORKOS_API_URL`); saga e2e vs LOCAL core: cross-tenant denial, duplicate-request no-dup, kill-mid-step resume, 409-adoption-refusal, sweeper-race (versioned transitions). Apply: skeleton + DDB live.
- **P2 — EKS dev environment**: Terraform cluster + addons (encode the recipe: VPC CNI netpol standard mode, off us-east-1a, gp3, arm64/t4g, LiteLLM 2Gi; single t4g.medium + RWO PVC explicitly labeled dev/private-beta availability tier); `helm_release` of the unchanged chart (`web.enabled=false`); Pod Identity → KMS; ALB controller + chart Ingress; CloudFront + rotating origin header (direct-ALB requests refused — tested); Neon + LiteLLM DB. Prove on-cluster: replay run (`just demo`-style, no key), governance pause/approve smoke, **edge SSE long-stream + resume through CloudFront** (the P2 gate). Apply: core platform live.
- **P3 — Live provisioning** (reordered after EKS per review — a deployed Lambda cannot call a laptop): saga against the deployed core + WorkOS Staging, per-org Connect apps, `needs_operator` drill. Apply: signup path live end-to-end.
- **P4 — Web cloud mode (Vercel)**: AuthKit-first onboarding + org create/select, dual-session bridge + dual logout + adversarial session tests, org switcher, run submission + SSE watch through the proxy, usage page (stub). Playwright e2e signup→onboard→run(replay)→watch.
- **P5 — Metering + plans**: rollup (recompute-and-overwrite) + real usage page; plan records; LLM budget envs set on cluster; cost-abuse tests (budget-stop, egress rates) in cloud-e2e §B.
- **P6 — Acceptance + docs**: full 10-step journey twice — replay (~$0.25) and real haiku (user-triggered, <$0.50); 24h idle scale-down measurement (sandbox nodes → 0); `docs/hosted/*` updates (threat model incl. edge + operator-token custody + Vercel processor; network architecture; cloud runbook incl. manual containment + teardown-leak notes); consolidated validation report; self-hosted compat proof (suites + kind chart CI unchanged); modeled-vs-measured cost reconciliation.
- **P7 — Public-readiness gate + M3 proposals**: load test on the long-lived route mix; WAF decision resolved; kill-switch drill; purge/retention design; then the M3 core-capability proposals (atomic caps/credits via capacity design, suspend/reactivate, preauth-if-needed, usage export) — each its own design + approval. **Public self-serve stays off until M3 enforcement lands.**

Completion criteria (10-step journey): steps 1–5 → P3/P4; 6–8 → P2/P4; 9 → P5; 10 → P6. All within a private beta; public signup = post-M3.

## Cost (honest floor, per review)

Idle ≈ **$130–140/mo**: EKS $73 + t4g.medium ~$24.5 + ALB ~$16.5 + ~3 public IPv4 ~$11 + EBS/KMS/logs/CloudFront ~$5–15. Sandbox compute at idle: $0. 10 orgs light ≈ $140–155. External: Neon $0–19, WorkOS $0, Vercel $0–20. Justification: the fixed cost is the price of "current primitives unchanged" (user-selected over the ~$13-idle Lambda-core path, now the M4 appendix). Guardrails: two-level budgets, DDB on-demand caps, Lambda reserved-concurrency ceiling on the (short-request-only) cloud API, log retention, LLM tenant budgets, ResourceQuota. Denial-of-wallet: documented per route class; sandbox egress remains zeroEgress (k8s posture unchanged — the rev-1 open-egress concern was Fargate-specific).

## Core-change ledger

**M1/M2: zero core changes. Zero.** apps/web changes only (presentation): sso+workos unblock shipped together with the dual-session lifecycle, onboarding/org/usage pages, `/api/cloud` proxy. M3 candidates (generic, self-hosted-valuable, each separately approved): capacity claims + credits, suspend/reactivate, membership preauth, usage export, purge. Never enters core: WorkOS/Stripe/AWS-placement concepts.

## Risks

1. WorkOS Connect specifics (nonce/PKCE/organization_id/external_id) → P0 spike gates everything; fallback pre-defined.
2. Vercel SSE duration caps → P0 probe; resume-on-cap UX; fallback = dedicated stream path via CloudFront host.
3. Dual-session lifecycle bugs → explicit state machine + adversarial tests (P0 flow proof, P4 suite).
4. Saga/WorkOS/core consistency → external_id correlation + versioned ledger + needs_operator + kill-mid-step tests.
5. Quota gap abused in beta → trusted cohort + global ResourceQuota + budgets; public launch gated on M3.
6. Single-node/RWO availability tier → labeled dev/private-beta; scheduling + peak-memory gate in P2 (LiteLLM 2Gi headroom).
7. Cost drift → P0 verified model, P6 reconciliation, two-level budgets from day 0.
8. Root-key account → P0 IAM bootstrap precedes all other applies.

## User setup checklist

WorkOS (fennec, Staging): approve spike + per-org Connect app creation via API; dashboard AuthKit app (redirect = **Vercel origin** `/callback`); `WORKOS_API_KEY`/`WORKOS_CLIENT_ID`/`WORKOS_COOKIE_PASSWORD` into SSM. AWS: approve P0 IAM bootstrap; pick the account-wide budget number (kept as second breaker). Vercel: create/link the apps/web project (env: `NEXT_PUBLIC_WORKOS_REDIRECT_URI` is build-time). Later: product domain; WorkOS prod environment; Neon plan.

## Contribution points (learning mode)

Reserved-slug list (P1); plan names + free-tier values (P5); onboarding/provisioning-state copy (P4); account-wide budget number (P0).

## Verification

Per phase: `just check` + existing hermetic suites + new cloud-e2e sections; live-Neon/live-key suites and anything spending model money stay user-triggered (standing agreement); `just demo` replay is the no-cost acceptance vehicle (local P1, on-cluster P2/P6). Terraform applies per phase with per-action approval. P0's proofs are pass/fail gates recorded in the design doc before any P1 code.
