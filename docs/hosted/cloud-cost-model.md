# Fluidbox Cloud M1 — Idle & Light-Use Cost Model (re-verification)

**Milestone:** M1.0 gate proof — "Re-verify the idle and light-use cost model, including public IPv4 and ALB costs" (brief §6 M1.0, §9 criterion 17).
**Date:** 2026-08-03 · **Region:** us-east-1 · **Pricing source:** AWS Price List API, pulled live this date.
**Claimed floor (brief §11):** ≈ **$130–140 / month**.

Unit prices in the "live?" = yes rows were fetched live from the AWS Pricing API (publication dates 2025-08 through 2026-08-03; the CloudWatch Logs list was published today). Rows marked "no" are AWS free-tier/policy facts or minor storage rates not separately re-queried — flagged inline. Quantities (LCU count, log GB, transfer GB) are operator estimates regardless of whether the unit price was verified.

## 1. Idle floor (no runs in flight; sandbox nodegroup at zero)

| Component | Unit price (live?) | Monthly math | Monthly $ |
|---|---|---|---|
| EKS control plane, standard support | $0.10 /cluster-hr — **yes** | 0.10 × 730 | **73.00** |
| System node — 1× t4g.medium, Linux on-demand | $0.0336 /hr — **yes** | 0.0336 × 730 | **24.53** |
| ALB — load-balancer hours | $0.0225 /hr — **yes** | 0.0225 × 730 | **16.43** |
| ALB — LCU (near-idle, ~0.05 LCU avg) | $0.008 /LCU-hr — **yes** (rate) | 0.008 × 730 × 0.05 | **0.30** |
| Public IPv4, in-use × 3 (1 node + 2 ALB AZ) | $0.005 /hr — **yes** | 0.005 × 730 × 3 | **10.95** |
| EBS gp3 — 30 GiB root + 10 GiB archive PVC | $0.08 /GB-mo — **yes** | 0.08 × 40 | **3.20** |
| KMS — 1 customer-managed key | $1.00 /key-mo — **yes** | 1 key (+ ~$0.03/10k req, trivial) | **1.00** |
| CloudWatch Logs — ingestion (EKS control plane) | $0.50 /GB — **yes** | ~2 GB (first 5 GB/mo free) | **1.00** |
| CloudWatch Logs — archived storage | $0.03 /GB-mo — no (not re-queried) | ~few GB | **0.10** |
| S3 — state + trail buckets | $0.023 /GB-mo — **yes** | ~4 GB × 0.023 | **0.10** |
| CloudFront | $0.085 /GB — **yes** (rate) | <1 TB, covered by 1 TB/mo always-free | **0.00** |
| CloudTrail — fluidbox-owned trail (SECOND management-events copy: the account's pre-existing `serverless_trail` consumes the free first copy) | $2.00 /100k events — no (policy rate) | light account activity, ~50k/mo | **~1.00** |
| Regional data transfer out to internet | $0.09 /GB — no (not re-queried) | <5 GB, covered by 100 GB/mo free | **0.00** |
| Sandbox nodegroup (idle) | — | scale-to-zero by design | **0.00** |
| **Idle-floor total** | | | **≈ 131.6** |

**Verdict: PASS.** Computed idle floor ≈ **$131.6/mo** (incl. ~$1 for the fluidbox-owned second CloudTrail copy — see `deploy/cloud/terraform/bootstrap/cloudtrail.tf` for why an owned trail was chosen over adopting another project's), at the **low end of the claimed $130–140 band** (in the range, not over). If the CloudWatch Logs ingestion and ALB LCU fall entirely into free tier / round to zero, the floor is ~$129; if logs run a little heavier, ~$131. No line item moved materially versus the brief's §11 numbers:

- EKS $73.00 (claim $73), node $24.53 (claim $24.50), public IPv4 $10.95 (claim $11) — all within pennies.
- ALB is **$16.43 hours + ~$0.30 idle LCU ≈ $16.7** (claim $16.50); at true idle the LCU is negligible, so ALB alone is ~$16.4, slightly **below** the bundled claim.
- The brief's "EBS + KMS + logs + CloudFront ≈ $5–15" bucket lands at its **low end (~$5.4)**: EBS $3.20 + KMS $1.00 + logs ~$1.10 + S3 $0.10, with CloudFront, CloudTrail, and regional egress all $0 under always-on free tiers.

## 2. Light use (5–10 orgs) scenario

Add usage-driven deltas on top of the idle floor (sandbox nodegroup wakes for runs, more edge/LCU traffic, more logs):

| Delta | Math | Monthly $ |
|---|---|---|
| Sandbox node — ~2 hr/day of 1× t4g.medium (+transient EBS) | 0.0336 × 2 × 30 (+~0.05) | **~2.05** |
| ALB LCU bump (bursty run traffic, ~0.5–1 LCU active) | ~+3 | **~3.00** |
| CloudWatch Logs bump (container + audit, +2–3 GB) | ~+1.25 | **~1.25** |
| CloudFront / regional egress | still inside 1 TB & 100 GB free tiers | **0.00** |
| **Light-use total** | idle 130.6 + ~6.3 | **≈ 137 / mo** |

Still **within the $130–140 band**. Sandbox delta ~$2 matches the brief's $1.50–2.50 estimate.

## 3. Cost levers / denial-of-wallet notes

All of these already exist in the product or the AWS setup; they are the mitigations that bound spend for an invited, trusted cohort (brief §7):

- **Two-level AWS budgets** — a tag-filtered Fluidbox budget plus an account-wide budget as a second circuit breaker (brief §6 M1.0).
- **Per-tenant rolling LLM budget + per-run monetary and wall-clock budgets** — Core-side, cap the largest variable cost (model spend) before it happens.
- **Global sandbox ResourceQuota + scale-from-zero nodegroup** — sandbox compute is $0 while idle and cannot exceed the cluster quota.
- **Per-tenant egress-rate controls** — bound outbound abuse (denial-of-wallet via egress) per tenant/user/connection/host.
- **Log retention + ECR/S3 lifecycle rules** — keep CloudWatch Logs ingestion/storage and image/object storage from creeping (brief §6 M1.0).
- **Operator run cancellation + manual tenant containment** — stop active runs and deactivate access (with the documented limitation that containment is not yet a durable suspend).

## 4. Honest note on the fixed floor

The ~$130 idle floor is the deliberate price of running the **unchanged Kubernetes and Core primitives** in M1 (PLAN rev 3, brief §11): a standard EKS control plane ($73), one always-on system node, and an always-on ALB with its public IPv4 addresses together account for ~$125 of the ~$130 and are fixed whether or not any customer is active. M1's contract is "deploy today's Fluidbox safely," so none of these are optimized away here. The **~$13-idle serverless-core alternative** (scale-to-zero Core, no persistent EKS/ALB floor) is explicitly **deferred to M4** (brief §3 "Explicitly deferred"; §13). M1 accepts the fixed floor in exchange for zero Core/chart changes.

## 5. Caveats and non-AWS costs

- **NAT gateway is assumed absent.** This model puts the system/sandbox nodes in **public subnets** (the node carries a public IP — that is the 3rd billed IPv4). A private-subnet topology instead would drop the node's public IP (−$3.65/mo) but add a **NAT gateway ≈ $0.045/hr = ~$32.85/mo + $0.045/GB** processing — a material ~**+$30/mo**. Hold the public-subnet topology to keep the floor as modeled.
- **Not live-verified (flagged above):** CloudWatch Logs archived-storage rate ($0.03/GB-mo), regional data-transfer-out rate ($0.09/GB), CloudTrail first-trail-free and the CloudFront 1 TB / regional 100 GB always-free allowances — these are AWS free-tier/policy facts, not Pricing-API line items, and drive several $0 rows.
- **External (informational, not AWS, not from the Pricing API):** Neon $0–19/mo, WorkOS $0 (under 1M MAU), Vercel Hobby/Pro $0–20/mo. Not included in the AWS floor above.
