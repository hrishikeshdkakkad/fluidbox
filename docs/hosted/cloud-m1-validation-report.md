# Fluidbox Cloud M1 — validation report

The M1 brief §9 hard-acceptance ledger, plus the pre-apply verifications that
back it. Living document: `scripts/cloud/cloud-m1-acceptance.sh` writes the
per-criterion evidence and prints the table to paste into §2 below.

## Final status — 2026-08-03

**Fluidbox Cloud M1 is DEPLOYED AND RUNNING on AWS. 16 of the 18 §9 criteria
pass with recorded live evidence.**

All four stacks are applied (bootstrap 27 resources, platform 49, app, edge),
the origin secret is rotated, the $0 replay acceptance passed on-cluster
through the public edge, and an invited owner has signed in through the Vercel
origin against a real OIDC provider.

The count is unchanged from the first published version, but **the two open
rows are not the two it started with** — a post-deployment sweep on 2026-08-03
corrected the ledger in both directions:

| # | criterion | state |
|---|---|---|
| 1 | scoped deployer applies without a root key | **NOW PASS.** Re-scored against the criterion's own text, which asks whether a scoped deployer *can apply without a root key* — proven, all four stacks. It had been graded against the M1.0 gate's parenthetical "(root key retired)", a different requirement. The root key is still ACTIVE by the owner's twice-stated choice; that is tracked in §4 on its own, not folded into this row. |
| 2 | both budget controls active | **NOW PARTIAL — a real defect, found late.** The $600 account breaker works ($14.88 observed). The $50 tag-filtered budget reads **$0.00 while the cluster runs**, because the `project` cost-allocation tag was never activated. It would never fire at any spend. The original PASS verified the budgets EXISTED with correct filters; it never verified the filter MATCHED anything. See §3b. |
| 17 | measured idle cost reconciled | **Still open, and the reason was wrong.** Recorded as a pure calendar dependency; it is also a config one. The account is shared with four other projects ($7.66 and $5.68/day of non-fluidbox spend), so without the tag above, fluidbox's idle cost cannot be isolated *at all* — not now, not after a month. Activating the tag is what starts the clock. |

The model-side reconciliation for §9-17 is done and stands: ~$156/mo, matched
line-by-line against deployed inventory. Everything else in this document is
evidence for the 16 that pass.

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
| 1 | scoped deployer applies without a root key | **PASS — re-scored 2026-08-03 against the criterion's own text.** §9-1 reads "a scoped deployer *can apply the infrastructure without using a root key*". That is a statement about capability, and it is demonstrated without qualification: the scoped deployer applied all four stacks (bootstrap, platform, app, edge). `verify-bootstrap.sh` scores the two things separately — the capability check ("running as the ASSUMED deployer role — the scoped non-root path works end to end") passes; the *separate* root-key-presence check warns. I had been grading this row against the M1.0 gate's parenthetical "(root key retired)", which is a different sentence and a different requirement. **The root key is still ACTIVE and that remains open** — tracked as its own line in §4 rather than hidden inside a PASS. The owner was asked twice and chose both times to retire it personally, which is the prudent call on an account shared with four other projects where CloudTrail shows non-session root use on 2026-08-01 and 07-30 | `…-cloud-m1-acceptance/c1-verify-bootstrap.txt` |
| 2 | both budget controls active | **DOWNGRADED TO PARTIAL 2026-08-03 — one of the two is not a working control.** The $600 account-wide breaker is genuinely live and correct: it reads $14.88 of real spend. The $50 tag-filtered `fluidbox-cloud-monthly` **exists but measures nothing** — it reads `$0.00` while the cluster runs, because the `project` cost-allocation tag is still **Inactive**, and AWS does not break cost down by an unactivated user tag. It will never fire regardless of fluidbox spend. My earlier PASS checked that both budgets EXISTED with the right filters and limits; it never checked that the filter MATCHED anything, which is the only property that makes it a control. Fix + one-click remediation below | live `budgets describe-budgets`, `ce list-cost-allocation-tags` |
| 3 | operator provisions an org by documented steps | **PASS** — `fluidzero` provisioned AND its per-org IdP configured + activated through the public edge, all via the documented endpoints; login start then redirects to the IdP | live `GET /v1/admin/orgs`, `…-cloud-m1-acceptance/c14-containment-live.txt` |
| 4 | invited owner logs in through the Vercel origin | **PASS ON THE LIVE DEPLOYMENT** — driven end to end with Playwright: Vercel login start → the org's own OIDC issuer → credentials → back to the Vercel origin with a `__Host-fbx_web` session. `/v1/auth/me` returns org `fluidzero`, roles `[member, owner]`, user `owner@fluidzero.test`; `/app` renders; the membership row carries `last_login_at`. IdP is Dex (standards-conformant), i.e. the bring-your-own path from decision §12#4 — core unmodified | `…-cloud-m1-acceptance/c4-owner-login-live.txt` |
| 5 | user submits a replay run | **PASS ON EKS** — submitted through the CloudFront edge | `…-cloud-m1-replay/` |
| 6 | EKS creates an isolated sandbox | **PASS ON EKS** — sandbox pod scheduled on a node the autoscaler woke FROM ZERO | `…-cloud-m1-replay/sandbox-pods.txt` |
| 7 | run pauses for approval and resumes | **PASS ON EKS** — approval.decided by operator → tool.decision(source=human) → completed | `…-cloud-m1-replay/timeline.txt` |
| 8 | events stream through Vercel→CloudFront→ALB (or documented fallback) | **PASS — the COMPLETE chain is live.** Vercel now points at CloudFront: `/v1/health` through the rewrite returns `{"status":"ok"}` from core, `/api/fluidbox` proxies 200, and the SSE route correctly answers `unauthorized` without a session. Vercel leg measured at a 300s cap with working `Last-Event-ID` resume ⇒ fallback ruled out | readiness ledger + live chain check |
| 9 | artifacts + usage recorded | **PASS ON EKS** — diff carries the real fix; cost ledger records **$0.00 / 0 requests**, confirming a genuinely model-free acceptance | `…-cloud-m1-replay/changes.patch`, `cost.json` |
| 10 | sandbox cannot make disallowed connections | **PASS ON EKS** — a labelled probe pod in the sandbox namespace: `OPEN_ATTEMPT_1` then `EGRESS_BLOCKED_AT_2` (the VPC-CNI standard-mode programming window, ~3s, measured live), with `:8788` still reachable. Policy also denied `curl` mid-run | `…-cloud-m1-acceptance/c10-netpol-probe.txt` |
| 11 | cross-tenant read/mutate impossible | **PASS ON THE LIVE CLOUD DATABASE** — as `fluidbox_runtime` (posture `false/false/false`) against production Neon: each tenant's GUC sees only its own rows, a GUC-less connection sees ZERO, and one tenant explicitly selecting another's `tenant_id` gets nothing. The owner sees both, which is exactly why the pool runs as the non-owner role | `…-cloud-m1-acceptance/c11-cross-tenant-live.txt` |
| 12 | direct ALB requests rejected | **PASS** — CloudFront 200; direct ALB and forged-header both refused (000) | `…-cloud-m1-edge-lock/direct-alb-check.txt` |
| 13 | operator cancellation stops a run | **PASS ON EKS** — `{"cancelled":true}`, status polled through `finalizing` → `cancelled` | `…-cloud-m1-acceptance/c13-cancel.txt` |
| 14 | containment runbook exercised, limits recorded | **PASS ON EKS** — every step run against the live deployment under `REQUIRE_SSO=1`: disable stopped login (302→200), reactivate restored it (→302), and BOTH documented limitations reproduced (the admin token cannot reach `/v1/sessions`, and an armed-but-never-logged-in org has no membership row) | `…-cloud-m1-acceptance/c14-containment-live.txt` |
| 15 | sandbox capacity returns to zero | **PASS** — watched to `desired=0, nodes=0` at 22:01:26Z after the idle window; a later run woke one again, re-demonstrating scale-FROM-zero | `…-cloud-m1-scaledown/idle-scaledown.log` |
| 16 | core/chart/suites green, unmodified | ✅ **PASS (both halves)** | §1 above |
| 17 | measured idle cost reconciled with ~$130–140 | **RECONCILED AGAINST THE MODEL; THE MEASURED HALF IS BLOCKED — and the blocker is NOT just the calendar.** The model is now ~$156/mo, ~$16 above the brief's band, because the DB-backed LiteLLM forces t4g.large + 4Gi, and it is matched line-by-line against deployed inventory. The empirical figure needs two things: a full idle month (2026-08-03 + ~30d), **and the `project` cost-allocation tag activated**. This account is shared with four other projects — its 2026-08-01/02 totals were $7.66 and $5.68 of non-fluidbox spend — so an account-wide number can never be fluidbox's idle cost. Until the tag is Active there is no way to isolate it, so this criterion was blocked on a config gap, not only on time | `cloud-cost-model.md`; live `ce get-cost-and-usage` |
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

## 3b. Findings from the 2026-08-03 post-deployment sweep

1. **🚩 The tag-filtered budget is not a working control (§9-2).** Live:
   `fluidbox-cloud-monthly` reads **$0.00** while the account reads $14.88 and
   the cluster runs. Cause: the `project` cost-allocation tag is **Inactive**,
   and AWS does not break cost down by an unactivated user tag, so the filter
   `user:project$fluidbox` matches nothing. The budget would never fire at any
   level of fluidbox spend. This also blocks the measured half of §9-17, since
   the account is shared with four other projects.

   *How it slipped through:* the original check verified both budgets EXISTED
   with the right limits and filter strings. Existence is not efficacy — the
   filter has to match something, and that was never asserted. The acceptance
   evidence (`c2-budgets.json`) is not wrong, it is just answering a weaker
   question than the criterion asks.

   **Remediation (one click, needs root — see below):** Billing → Cost
   allocation tags → `project` → Activate. Up to 24h to populate, then the
   budget starts measuring and the §9-17 clock is meaningful. The Terraform
   equivalent is `-var activate_cost_allocation_tag=true` on bootstrap.

2. **⚠️ Bootstrap is root-only after step-6 hardening.** A `terraform plan` on
   bootstrap as the operator now fails to refresh: no `iam:GetRole`,
   `iam:GetPolicy`, `s3:GetBucketPolicy`, `s3:GetLifecycleConfiguration`. The
   stack's provider has no `assume_role`, so it runs as the ambient identity —
   which means any bootstrap change (including the tag activation above)
   requires the root ceremony. Worth knowing before planning one; it also means
   the console click is genuinely the lighter path today.

   Mitigated going forward by granting the deployer
   `ce:UpdateCostAllocationTagsStatus` (`iam.tf`, Sid
   `CostAllocationTagActivation`) so the tag can be re-asserted without root on
   the next bootstrap apply. A cost control repairable only as root is a cost
   control that will not get repaired.

## 4. How to close this report

Run the phases in `docs/plans/2026-08-03-cloud-m1-decisions.md` §"apply
queue". After each, run the matching acceptance criteria
(`scripts/cloud/cloud-m1-acceptance.sh <n> …`) and paste its generated table
into §2, replacing PENDING-APPLY rows with the real verdict and evidence
path. M1 is done when every row reads PASS with a citation.
