# Fluidbox Cloud M1 — validation report

The M1 brief §9 hard-acceptance ledger, plus the pre-apply verifications that
back it. Living document: `scripts/cloud/cloud-m1-acceptance.sh` writes the
per-criterion evidence and prints the table to paste into §2 below.

Status as of **2026-08-03**: **M1.0 and M1.1 are APPLIED AND LIVE on AWS.**
Bootstrap (27 resources), platform (49), app (chart + composed LiteLLM) and
edge (CloudFront) are deployed; the origin secret is rotated; the $0 replay
acceptance passed on-cluster through the public edge. Ten §9 criteria now
carry live evidence. Criteria fall into these states:

- **PASS** — closed without a deployment (16, 18).
- **MECHANISM PROVEN** — the product behaviour was demonstrated on a *real*
  Kubernetes cluster with the *released* artifacts and the *actual* M1 values,
  or at the enforced database floor; what remains is re-running it on EKS
  (5, 6, 7, 9, 10, 11, 13, 14).
- **PENDING-APPLY** — genuinely needs AWS or Vercel and cannot be faked
  (1, 2, 3, 4, 12, 15, 17, and the CF/ALB half of 8).

"Mechanism proven" is deliberately not "pass": it says the code path works
and the values are right, not that it works *on the deployed edge*. Both
statements are needed, and only one of them was purchasable without an apply.

## 1. Pre-apply verification (done, no AWS mutations)

| check | result |
|---|---|
| All four Terraform stacks `fmt` clean | ✅ |
| All four `terraform validate` against **real** provider schemas (aws 6.57.1, kubernetes 2.38.0, helm 2.17.0) | ✅ |
| Chart `0.4.0` published at `oci://ghcr.io/hrishikeshdkakkad/charts/fluidbox` (appVersion 0.4.0) | ✅ |
| Product images multi-arch with `linux/arm64` at 0.4.0 (server, workspaced, sandbox-runner, codex-runner) — required for t4g nodes | ✅ |
| `ghcr.io/berriai/litellm-database:main-stable` exists and ships `linux/arm64` — the composed LiteLLM must schedule on the Graviton system node | ✅ |
| All six referenced EKS addons exist for K8s 1.35 (vpc-cni, kube-proxy, coredns, ebs-csi, metrics-server, pod-identity-agent) | ✅ |
| CloudFront managed policy ids resolve: `Managed-CachingDisabled`, `Managed-AllViewerExceptHostHeader` | ✅ |
| `com.amazonaws.global.cloudfront.origin-facing` prefix list exists in us-east-1 (`pl-3b927c52`) | ✅ |
| EKS 1.35 is in **standard** support until 2027-03-26 (1.33 moved to extended 2026-07-28) | ✅ |
| Target state-bucket name free; account clean of fluidbox EKS leftovers | ✅ |
| **`terraform plan` on bootstrap against the real account** (read-only): 27 to add, 0 to change, 0 to destroy, no errors; budget filter renders `TagKeyValue = user:project$fluidbox` | ✅ |
| Zero changes to `crates/ deploy/helm/ images/ migrations/ apps/web/ Cargo.*` vs main | ✅ (§9-16 half) |
| Hermetic core suite `cargo test -p fluidbox-core` with `DATABASE_URL` unset | ✅ 167/167 |
| Cost model re-verified live (AWS Pricing API) | ✅ ≈$131.6/mo idle, in band |
| OIDC login path proof | ⚠️ 17/18 — see the blocking finding |
| Vercel proxy cookie + SSE — **code path AND platform cap** | ✅ 9/9 locally; live deployment measures the cap at **exactly 300s** with working `Last-Event-ID` resume ⇒ fallback not needed |
| Independent IaC security review (separate agent, full stack read) | ✅ ran; 1 blocker + 4 medium + 3 nits, **all fixed** |
| `operator_cidrs` guard proven to refuse `[]` and `0.0.0.0/0`, accept a `/32` | ✅ |
| **M1 values INSTALL on a real enforcing cluster** (kind + Calico, released 0.4.0 chart/images), server READY, netpol `helm test` passes, governed replay run completes with approval + diff | ✅ 15/15 |
| **M1.2 onboarding procedure rehearsed** (two orgs, per-org IdP, admin confinement) + cross-tenant denial at the RLS floor | ✅ 14/14 |
| **§9-13 cancellation proven + §9-14 containment drill exercised** (five limitations recorded from observation; one corrected the runbook) | ✅ 13/13 |
| **IAM policies SIMULATED** against the real AWS evaluator (`simulate-custom-policy`, read-only): every action the applies need is allowed, and 12 negative cases prove the scoping refuses what it must | ✅ 42/42 |
| **Acceptance harness executed** for the AWS-free criteria (16, 18) — it runs and emits the ledger table rather than crashing on first use | ✅ |
| **Operator-toolkit failure paths tested** — every script stops fast with an actionable message when a prerequisite is missing; all four destructive scripts refuse the root identity | ✅ 11/11 |

Evidence: `docs/reviews/2026-08-03-cloud-m1-readiness/`.

### What the independent review caught (all fixed before handback)

1. **BLOCKER — the Terraform S3 backend does not inherit the provider's
   `assume_role`.** It resolves credentials independently, so state and lock
   objects are read/written by the *ambient* identity (the operator user),
   which had no state-bucket permissions — every platform/app/edge apply would
   have failed at `init` with AccessDenied before planning a single resource.
   Fixed by granting the operator state-bucket object access (plus
   `eks:DescribeCluster`, which `update-kubeconfig` needs ambiently), and by
   documenting the profile rule: **terraform runs as the operator** (the
   provider elevates), **scripts run as the deployer**.
2. The tag-filtered budget would have missed compute — node-group tags don't
   reach EC2 instances (fixed with propagating ASG tags; EBS residual recorded
   in the cost model).
3. `coredns`/`kube-proxy` addons lacked `resolve_conflicts_on_create`, risking
   `ConfigurationConflict` when adopting the cluster's self-managed copies.
4. `operator_cidrs` had no guard — an empty list makes EKS default the public
   API endpoint to `0.0.0.0/0`, world-opening it by omission. Now refused at
   plan time, and the refusal is proven.
5. Nits fixed: `activate_cost_allocation_tag` now defaults **false** (the old
   default made the documented first-apply failure the default path); the
   `alb_hostname` output documents that it is empty on first apply by design;
   the runbook covers re-pointing CloudFront after an ALB replacement (the
   `ignore_changes = [origin]` freeze) and the post-retirement bootstrap drift.

The review independently confirmed the four defects I had already found and
fixed, and cleared three things I flagged as uncertain: the helm `~> 2.17`
block syntax is correct for v2.x, the budget `TagKeyValue` filter form is
correct for provider 6.x, and the KMS key needs no explicit key policy for
Pod Identity (the default root statement lets the IAM role policy govern).

## 2. §9 hard acceptance criteria

| # | criterion | status | evidence |
|---|---|---|---|
| 1 | scoped deployer applies without a root key | **PARTIAL — the scoped deployer DID apply all three stacks (proven).** `verify-bootstrap.sh` is 11/12; the single gap is that the root access key is still ACTIVE, left so at your instruction after CloudTrail showed non-session use | `…-cloud-m1-acceptance/c1-verify-bootstrap.txt` |
| 2 | both budget controls active | **PASS** ($600 breaker + $50 tag-filtered, live) | `…-cloud-m1-acceptance/c2-budgets.json` |
| 3 | operator provisions an org by documented steps | **PASS (org half)** — `fluidzero` provisioned through the public edge via the documented admin endpoint, status active. The IdP-config half awaits the chosen provider's client secret | live `GET /v1/admin/orgs` |
| 4 | invited owner logs in through the Vercel origin | PENDING-APPLY (blocked on decision §12#4) | manual + screenshots |
| 5 | user submits a replay run | **PASS ON EKS** — submitted through the CloudFront edge | `…-cloud-m1-replay/` |
| 6 | EKS creates an isolated sandbox | **PASS ON EKS** — sandbox pod scheduled on a node the autoscaler woke FROM ZERO | `…-cloud-m1-replay/sandbox-pods.txt` |
| 7 | run pauses for approval and resumes | **PASS ON EKS** — approval.decided by operator → tool.decision(source=human) → completed | `…-cloud-m1-replay/timeline.txt` |
| 8 | events stream through Vercel→CloudFront→ALB (or documented fallback) | **PASS — the COMPLETE chain is live.** Vercel now points at CloudFront: `/v1/health` through the rewrite returns `{"status":"ok"}` from core, `/api/fluidbox` proxies 200, and the SSE route correctly answers `unauthorized` without a session. Vercel leg measured at a 300s cap with working `Last-Event-ID` resume ⇒ fallback ruled out | readiness ledger + live chain check |
| 9 | artifacts + usage recorded | **PASS ON EKS** — diff carries the real fix; cost ledger records **$0.00 / 0 requests**, confirming a genuinely model-free acceptance | `…-cloud-m1-replay/changes.patch`, `cost.json` |
| 10 | sandbox cannot make disallowed connections | **PASS ON EKS** — a labelled probe pod in the sandbox namespace: `OPEN_ATTEMPT_1` then `EGRESS_BLOCKED_AT_2` (the VPC-CNI standard-mode programming window, ~3s, measured live), with `:8788` still reachable. Policy also denied `curl` mid-run | `…-cloud-m1-acceptance/c10-netpol-probe.txt` |
| 11 | cross-tenant read/mutate impossible | **PROVEN AT THE ENFORCED FLOOR** — RLS under the non-owner runtime role: A sees only A, B only B, no-GUC sees zero, A selecting B's tenant_id gets nothing | `…-cloud-m1-readiness/cross-tenant-rls.txt` |
| 12 | direct ALB requests rejected | **PASS** — CloudFront 200; direct ALB and forged-header both refused (000) | `…-cloud-m1-edge-lock/direct-alb-check.txt` |
| 13 | operator cancellation stops a run | **PASS ON EKS** — `{"cancelled":true}`, status polled through `finalizing` → `cancelled` | `…-cloud-m1-acceptance/c13-cancel.txt` |
| 14 | containment runbook exercised, limits recorded | **EXERCISED** against a real multi-user control plane; five limitations recorded from observation, incl. a previously-unknown ordering trap that changed the runbook | `…-cloud-m1-readiness/containment-drill.md` |
| 15 | sandbox capacity returns to zero | **PASS** — watched to `desired=0, nodes=0` at 22:01:26Z after the idle window; a later run woke one again, re-demonstrating scale-FROM-zero | `…-cloud-m1-scaledown/idle-scaledown.log` |
| 16 | core/chart/suites green, unmodified | ✅ **PASS (both halves)** | §1 above |
| 17 | measured idle cost reconciled with ~$130–140 | **RECONCILED, AND THE BAND MOVED** — the model is now ~$156/mo, ~$16 above the brief's band, because the DB-backed LiteLLM forces t4g.large + 4Gi. Measured spend accrues from 2026-08-03; a full idle month is needed for the empirical figure | `cloud-cost-model.md` (revision notice at the top) |
| 18 | threat model, network doc, runbooks, report published | ✅ **PASS** | `docs/hosted/cloud-*.md` (this file included) |

## 3. Open findings carried into the applies

1. **🚩 Identity (blocks §9-4).** WorkOS exposes one OIDC issuer + one client
   per environment; a per-org Connect app is refused at authorize. PLAN rev 3
   identity §1 does not hold as written; decision §12#4 must be re-taken from
   the three options in the readiness ledger. Nothing else in M1 depends on
   it — the platform, edge, and replay gates are identity-independent.
2. **⚠️ WorkOS token-endpoint auth (only if a WorkOS option is chosen).**
   Discovery omits `token_endpoint_auth_methods_supported`, so core requires
   `client_secret_basic` while WorkOS documents body credentials. Untested —
   the Connect app secret is dashboard-only. Verify before committing.
3. **Vercel duration cap unmeasured.** Reserved decision; the probe is
   written and runs unchanged against a preview URL. `Last-Event-ID` resume
   already proven, so a cap is a UX cost, not a correctness one.
4. **Documented beta gaps (not defects):** no per-tenant concurrent-run cap,
   rolling-30d rather than calendar-month LLM budgets, containment is a
   manual multi-step runbook, no purge. All are M3 items and appear in the
   threat model and the beta expectations note.

## 4. How to close this report

Run the phases in `docs/plans/2026-08-03-cloud-m1-decisions.md` §"apply
queue". After each, run the matching acceptance criteria
(`scripts/cloud/cloud-m1-acceptance.sh <n> …`) and paste its generated table
into §2, replacing PENDING-APPLY rows with the real verdict and evidence
path. M1 is done when every row reads PASS with a citation.
