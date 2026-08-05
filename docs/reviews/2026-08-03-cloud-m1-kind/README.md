# M1 substrate-independent validation — real cluster, released artifacts, $0

`scripts/cloud/m1-kind-validation.sh`, 2026-08-03. **15/15 after one harness
fix** (below). No AWS, no model calls, no live Neon.

## Why this exists

The M1.1/M1.3 criteria split into two kinds of claim. One kind is genuinely
AWS-specific — the ALB/CloudFront edge lock, Pod Identity → KMS,
scale-from-zero, EKS addons — and only an EKS apply can prove it. The other
kind is about the **product and the values file**, and is true or false
regardless of substrate: do the M1 values install, does the released 0.4.0
server boot in the M1 posture, does the zero-egress NetworkPolicy actually
enforce, does a governed run pause for approval and produce a diff.

This run proves the second kind on **kind + Calico** (a real enforcing CNI),
against the **real published 0.4.0 chart and images** M1 deploys — the same
recipe the repo's k8s CI tier uses, pointed at `deploy/cloud/values/eks-m1.yaml`
instead of the CI values.

## Results

| # | claim | result |
|---|---|---|
| 1 | cluster + Calico enforcing | ✅ |
| 2 | throwaway in-cluster Postgres; **server migrates on boot** | ✅ |
| 3 | credential Secret created out-of-band (as `make-secrets.sh` does) | ✅ |
| 4 | **`helm install` with `deploy/cloud/values/eks-m1.yaml` succeeds**, server READY (the readiness probe gated `--wait`, so a red install could not pass) | ✅ |
| 5 | Ingress object accepted by the API server (`alb` class, empty host) | ✅ |
| 6 | sandbox `ResourceQuota` present — the only concurrent-run admission gate | ✅ |
| 7 | kubernetes execution provider active | ✅ |
| 8 | **`helm test` netpol probe PASSES**: `:8788` reachable, `:8787` blocked | ✅ |
| 9 | replay-runner image built + loaded | ✅ |
| 10 | fixture staged in the server pod (`local_copy` workspace path, via `kubectl cp` — the same mechanism the EKS script uses) | ✅ |
| 11 | policy + agent seeded through the admin API | ✅ |
| 12 | **governed replay run COMPLETED on-cluster** | ✅ |
| 13 | **approval requested → operator approved → resumed via a `source=human` allow** | ✅ |
| 14 | **policy denied `curl`** (1 denial) while allowing the edit/test tools | ✅ |
| 15 | diff artifact carries the canonical fix | ✅ |

Final replay assertion:
`{"status":"completed","approval_requested":true,"approved":true,"resumed_via_human_allow":true,"policy_denials":1}`

Sandbox plane as installed:

```
networkpolicy/fluidbox-sandbox-default-deny   <none>
networkpolicy/fluidbox-sandbox-egress         fluidbox.dev/managed=true
resourcequota/fluidbox-sandbox-quota          pods: 1/20, requests.cpu: 550m/10, requests.memory: 1088Mi/20Gi
limitrange/fluidbox-sandbox-limits
```

## Two harness bugs this run found (both mine, both fixed)

1. **`sandbox.nodeSelector: {}` in an overlay does nothing.** Helm
   **deep-merges maps** across `-f` files (it replaces lists), so the EKS
   `fluidbox.dev/role: sandbox` selector survived, every sandbox pod became
   unschedulable on kind's single untainted node, and it surfaced minutes
   later as an inscrutable `Pending`. Fixed with `--set sandbox.nodeSelector=null`
   plus an assertion that fails immediately and says why. The same trap
   applies to any map override against `values/eks-m1.yaml` on the real
   deploy — recorded in `deploy/cloud/README.md`.
2. **The approval pause does not surface as an `awaiting_approval` status.**
   The first assertion required that transition and so failed a run that had
   in fact completed perfectly. The session stays `running` while the
   permission handler blocks; the real evidence for §9-7 is the chain
   `approval.requested` → `approval.decided` → `tool.decision(source=human,
   verdict=allow)` → `completed`. Observed transitions were exactly
   `created → provisioning → initializing → running → finalizing → completed`.
   The assertion now keys on the chain, and the corrected version was
   re-proven against the same live cluster (`timeline-verified.txt`).

The second one matters beyond this script: **an acceptance harness that
asserts on the wrong signal reports a false failure**, and on a different day
that costs an operator an afternoon chasing a healthy system.
`scripts/cloud/cloud-m1-acceptance.sh` already keys criterion 7 on
`approval.decided`, so it was correct — but this is why the harness was run
rather than assumed.

## What this does NOT prove

The AWS-specific half: ALB + CloudFront origin lock and direct-ALB refusal
(§9-12), Pod Identity → KMS custody, sandbox nodegroup scale-from-zero
(§9-15), EKS addon behaviour, and the VPC-CNI standard-mode async enforcement
window (Calico programs policy synchronously; the boot-gate race documented in
the runbook is EKS-specific). Those need the M1.1 apply.

## Files

`run.log` (full transcript), `timeline.txt` + `timeline-verified.txt` (both
replay runs), `replay-result.json`, `changes.patch`, `artifacts.json`,
`cost.json`, `server-boot.log`, `installed-objects.txt`, `sandbox-plane.txt`.
