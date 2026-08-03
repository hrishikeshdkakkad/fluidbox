# Fluidbox Cloud M1 — threat-model delta

Delta over `docs/hosted/threat-model.md` (the product threat model, which
still governs core: gate, custody, RLS, sandbox planes). This file covers
what the MANAGED deployment adds: the AWS account boundary, the public edge,
the Vercel processor, and operator custody. Written 2026-08-03 for the M1
private beta; every accepted residual is listed with its planned closure.

## Trust boundaries added by M1

```
[browser] ─ B1 ─ [Vercel] ─ B2 ─ [CloudFront] ─ B3 ─ [ALB] ─ B4 ─ [EKS: core]
                                                            ├─ B5 ─ [sandbox pods]
[operator laptop] ─ B6 ─ [AWS control plane / SSM / Terraform state]
[core] ─ B7 ─ [Neon ×2] · [WorkOS/IdP] · [Anthropic via LiteLLM]
```

## Assets (new or newly-placed)

| asset | where | custody control |
|---|---|---|
| AWS root | console-only after M1.0 | key RETIRED; MFA; any use alarms (EventBridge→SNS) |
| Deployer authority | IAM role | operator-user-only trust; path/tag/name-scoped policies; CloudTrail |
| Terraform state | S3 (versioned, TLS-only, locked) | **no secret values by design** (out-of-band secrets; placeholder origin header) |
| Admin token, credential key, LiteLLM master key, origin header | SSM SecureString + K8s Secrets | created by `make-secrets.sh`; never in git/state; K8s Secret RBAC = cluster-admins only |
| KMS KEK | KMS | Pod-Identity-scoped to the server SA; deletion-unrecoverable warning carried on the resource |
| Per-org IdP client secrets | core sealed custody (v2 envelope) | pass once through the admin API over TLS |
| Anthropic key | LiteLLM pod env only | unchanged product posture (server never holds it) |

## Edge threats (B1–B4)

| threat | control | residual |
|---|---|---|
| Direct-to-ALB bypass of the edge | SG admits only CloudFront origin-facing prefix list | none for internet clients |
| Foreign CloudFront distribution fronts our ALB | rotating `x-fluidbox-origin-auth` header enforced by ALB rule | window between edge-apply and first rotation (minutes, documented as a MANDATORY step); rotation script closes |
| CloudFront→ALB leg is HTTP | AWS-backbone leg between two AWS endpoints + both locks above | **ACCEPTED (M1)**: no product domain ⇒ no ALB cert possible. Closure: domain + ACM in M2 |
| SSE stream truncation at a hop | seq catch-up + Last-Event-ID resume are the delivery truth (core invariant) | UX degradation only; measured by the M1.0 probe |
| Header secret leak via SSM read | SSM SecureString; deployer/operator only | operator laptop compromise ⇒ rotate (runbook §9) |

## Vercel as a processor (B1)

The dashboard (presentation-only by hard constraint) runs on Vercel; in sso
mode its proxy forwards ONLY the allow-listed cookies (`__Host-fbx_web`,
login/switch families) + the CSRF header, and the `/v1/*` rewrite carries the
login dance so the session cookie lives on the Vercel origin. Consequences:

- Vercel infrastructure can observe session cookies and API payloads in
  transit (it terminates TLS for the dashboard origin). **ACCEPTED (M1)** for
  a trusted beta; noted to beta customers. Closure path: first-party edge in
  front of core for the dashboard origin (M3+aws-native web) or contractual
  (Vercel BAA-grade posture) — decision deferred.
- A Vercel account compromise = dashboard-origin compromise (serve modified
  JS). Mitigation: Vercel account MFA (operator action, checklist), no
  secrets in Vercel env beyond the PUBLIC API host name (`FLUIDBOX_API_URL`
  is not a secret; sso mode carries NO admin token — enforced by
  `web-auth.ts`'s mode matrix, and `admin`+`REQUIRE_SSO` cannot even render).
- Build-time rewrite pinning (`FLUIDBOX_API_URL` baked at build) means a
  poisoned build persists until redeploy — treat Vercel deploy rights as
  production-change rights.

## Identity (B7, M1-specific shape)

Per-org OIDC (core's existing flow) with MANUALLY configured apps. The M1.0
proof must show, per configured app: nonce round-trip, PKCE tolerance on a
confidential client, and whether the IdP enforces the org restriction at
authorize time. If IdP-side restriction is NOT enforced, the enforced floor
remains core's armed-membership model (an unarmed subject bounces even after
authenticating) — record which layer refuses in the onboarding checklist
(§E's wrong-org probe). No dual sessions in M1: `sso`+`workos` web tier is
refused by the app, deferred with the M2 state machine.

## Operator plane (B6)

| threat | control | residual |
|---|---|---|
| Root key abuse | key retired; alarm on any root use | root CONSOLE remains (MFA'd) as sanctioned break-glass — alarm announces it |
| Deployer over-reach in the SHARED account | IAM path/name/tag scoping; PassRole condition; enumerated SLRs | **ACCEPTED**: `ec2:*`/`eks:*`/`elbv2:*`/`autoscaling:*` are region-locked but not resource-scoped (EKS lifecycle needs unnameable ARNs) — within us-east-1 the deployer could affect other projects' EC2-plane resources. Compensations: single trusted operator, CloudTrail owned + validated, root alarm, per-action apply approvals |
| Terraform state tamper | versioned bucket, TLS-only, lockfile, no secrets | state bucket policy is IAM-scoped, not KMS-CMK — SSE-S3 accepted for secret-free state |
| Laptop compromise | operator user is AssumeRole-only + self-service; MFA hardening variable (`require_deployer_mfa`) | enable MFA condition promptly (ceremony step 7) |

## Sandbox plane (B5) — unchanged, restated for the audit

The product controls carry verbatim: zeroEgress default-deny NetworkPolicy
(control-plane :8788 only), boot-time enforcement probe + per-run netpol-gate
init (containing the VPC-CNI standard-mode async window), tainted sandbox
nodegroup, no Pod Identity association for sandbox SAs, per-run four-audience
tokens, the single permission gate. New in the managed context: nodes hold
public IPs (no NAT) — node egress is NOT the sandbox boundary (pods are
policy-constrained regardless); IMDS/link-local is inside the sandbox
deny-all. Known residuals inherited from the product threat model (e.g.
`/proc/<pid>/environ` same-uid reads) remain as documented there.

## Multi-tenant beta gaps (documented, not fixed — the reason the beta is invited-only)

- No per-tenant concurrent-run cap (global ResourceQuota only) → one tenant
  can consume the sandbox tier. M3: atomic claims.
- No calendar-month credits (rolling LLM budgets only). M3.
- Containment is the manual multi-step runbook §7 — labeled incomplete;
  suspend/reactivate is an M3 core proposal.
- No purge/offboarding workflow (disable-only). M3.

## Kill switches (fastest first)

1. Disable an org's login: `POST /v1/admin/orgs/{slug}/idp/{id}/disable`.
2. Cancel runs / contain tenant: runbook §7.
3. Stop the world: `kubectl scale deploy/fluidbox-server --replicas=0 -n fluidbox`
   (DB-durable; replay-safe restart).
4. Close the edge: disable the CloudFront distribution (direct ALB is already
   SG-refused).
5. Model spend: rotate the tenant LLM key (invalidates), or scale LiteLLM to 0.
