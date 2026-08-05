# M1 §9 acceptance — evidence ledger (2026-08-04)

| # | criterion | verdict | evidence |
|---|---|---|---|
| 1 | scoped deployer applies without a root key | **PASS** | c1-verify-bootstrap.txt |
| 2 | tag-filtered budget measures nothing (tag inactive) | **FAIL** | c2-cost-allocation-tag.json |
| 5 | replay run submitted | **PASS** | docs/reviews/2026-08-03-cloud-m1-replay/ |
| 6 | isolated EKS sandbox created | **PASS** | docs/reviews/2026-08-03-cloud-m1-replay/sandbox-pods.txt |
| 7 | pause + resume on approval | **PASS** | docs/reviews/2026-08-03-cloud-m1-replay/timeline.txt |
| 8 | events streamed through the public route (CF/ALB leg) | **PASS** | docs/reviews/2026-08-03-cloud-m1-replay/timeline.txt (Vercel leg: criterion 4/8 manual + SSE probe evidence) |
| 9 | artifacts + usage recorded | **PASS** | docs/reviews/2026-08-03-cloud-m1-replay/changes.patch, docs/reviews/2026-08-03-cloud-m1-replay/cost.json |
| 10 | sandbox egress denied (external blocked once policy programmed, :8788 allowed) | **PASS** | c10-netpol-probe.txt |
| 12 | direct ALB refused | **PASS** | c12-direct-alb.log + …-cloud-m1-edge-lock/ |
| 17 | measured cost not isolable (tag inactive; EKS-only floor $0.0) | **FAIL** | c17-exclusive.json + c17-tag-status.json |
