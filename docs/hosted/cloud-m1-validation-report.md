# Fluidbox Cloud M1 — validation report

The M1 brief §9 hard-acceptance ledger, plus the pre-apply verifications that
back it. Living document: `scripts/cloud/cloud-m1-acceptance.sh` writes the
per-criterion evidence and prints the table to paste into §2 below.

Status as of **2026-08-03**: M1.0 proofs run; nothing applied to AWS
(applies are per-action user-approved). §9 criteria 1–18 are therefore
`PENDING-APPLY` except where a criterion could be honestly closed without a
deployment.

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
| **`terraform plan` on bootstrap against the real account** (read-only): 28 to add, 0 to change, 0 to destroy, no errors; budget filter renders `TagKeyValue = user:project$fluidbox` | ✅ |
| Zero changes to `crates/ deploy/helm/ images/ migrations/ apps/web/ Cargo.*` vs main | ✅ (§9-16 half) |
| Hermetic core suite `cargo test -p fluidbox-core` with `DATABASE_URL` unset | ✅ 167/167 |
| Cost model re-verified live (AWS Pricing API) | ✅ ≈$131.6/mo idle, in band |
| OIDC login path proof | ⚠️ 17/18 — see the blocking finding |
| Vercel proxy cookie + SSE code path | ✅ 9/9 (platform cap pending project link) |
| Independent IaC security review (separate agent, full stack read) | ✅ ran; 1 blocker + 4 medium + 3 nits, **all fixed** |
| `operator_cidrs` guard proven to refuse `[]` and `0.0.0.0/0`, accept a `/32` | ✅ |

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
| 1 | scoped deployer applies without a root key | PENDING-APPLY | `verify-bootstrap.sh` after the ceremony |
| 2 | both budget controls active | PENDING-APPLY | acceptance harness c2 |
| 3 | operator provisions an org by documented steps | PENDING-APPLY | `cloud-onboarding-checklist.md`, filled |
| 4 | invited owner logs in through the Vercel origin | PENDING-APPLY (blocked on decision §12#4) | manual + screenshots |
| 5 | user submits a replay run | PENDING-APPLY | `replay-on-cluster.sh` |
| 6 | EKS creates an isolated sandbox | PENDING-APPLY | `sandbox-pods.txt` |
| 7 | run pauses for approval and resumes | PENDING-APPLY | replay timeline |
| 8 | events stream through Vercel→CloudFront→ALB (or documented fallback) | PARTIAL — proxy code path ✅, CF/ALB legs pending apply | readiness ledger proof 2 |
| 9 | artifacts + usage recorded | PENDING-APPLY | `changes.patch`, `cost.json` |
| 10 | sandbox cannot make disallowed connections | PENDING-APPLY | harness c10 netpol probe |
| 11 | cross-tenant read/mutate impossible | PENDING-APPLY | harness c11 (two-PAT probe) |
| 12 | direct ALB requests rejected | PENDING-APPLY | `direct-alb-check.sh` |
| 13 | operator cancellation stops a run | PENDING-APPLY | harness c13 |
| 14 | containment runbook exercised, limits recorded | PENDING-APPLY | runbook §7 drill |
| 15 | sandbox capacity returns to zero | PENDING-APPLY | `idle-scaledown-watch.sh` |
| 16 | core/chart/suites green, unmodified | ✅ **PASS (both halves)** | §1 above |
| 17 | measured idle cost reconciled with ~$130–140 | MODEL ✅ / MEASURED pending | `cloud-cost-model.md` + harness c17 |
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
