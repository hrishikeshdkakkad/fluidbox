# Live EKS re-acceptance — Phase F branch on the Kubernetes provider

The 2026-07-17 acceptance ([`2026-07-17-eks-acceptance.md`](./2026-07-17-eks-acceptance.md))
closed epic #48 with the released v0.2.0 chart and images. **This run re-certifies the
CURRENT branch** — `feat/mu-phase-F` (54df7e0 plus the uncommitted PR-#27 review fixes) —
live on EKS: current-branch images, the working-tree chart with the `runtimeRole` RLS
pool split active, against real Neon at migration 0025. Demo A and governance
pause/resume, unchanged, on `FLUIDBOX_PROVIDER=kubernetes`.

- **Cloud:** AWS EKS, region `us-east-1`, account `471112572248`
- **Chart:** `deploy/helm/fluidbox` from the working tree (NOT the OCI v0.2.0 release)
- **Images:** ECR `fluidbox-server` / `fluidbox-workspaced` / `fluidbox-sandbox-runner`, tag `eks-run`, arm64
- **Model:** `claude-haiku-4-5` only (cost discipline)
- **Date:** 2026-07-22/23 (UTC)

## 1. Deltas from the 2026-07-17 acceptance

| Delta | This run | Why |
|---|---|---|
| Nodegroup | `t4g.medium` (arm64/Graviton), same 2 vCPU/4GiB envelope | current-branch images built natively on an arm64 Mac (amd64-under-QEMU impractical); `scripts/eks-cluster.yaml` edited accordingly (uncommitted) |
| Images | ECR, tag `eks-run`, current branch | NOT GHCR v0.2.0; node instance role pulls ECR without imagePullSecrets |
| Chart | working tree, Phase F values (`runtimeRole=fluidbox_runtime` default, uncommitted `web.mode` change; `web.enabled=false` this run) | exercise the branch's chart, not the release |
| LiteLLM | bundled, **2Gi limit set at install** | the 2026-07-17 finding; the chart's 1Gi default still OOMKills |
| Database | real Neon at migrations **0025** | this is WHY v0.2.0 images could not be used — a pre-Phase-B binary cannot run against the migrated schema |

## 2. Cluster create

`eksctl create -f scripts/eks-cluster.yaml`: K8s 1.33, AZs us-east-1b/1c (1a excluded
per the epic recipe), addons `vpc-cni` (`enableNetworkPolicy=true`, **standard** mode) /
`kube-proxy` / `coredns` / `aws-ebs-csi-driver` / `metrics-server` all ACTIVE. 2 nodes
Ready (AL2023 arm64, v1.33.13-eks). Control-plane create took ~50 min this run (prior
run: 18 — AWS-side variance, not a config change). gp3 default StorageClass applied;
archive PVC **Bound** 10Gi gp3. `scripts/k8s-doctor.sh`: all four checks green
(apiserver, default SC, enforcing-capable CNI, Secret present).

## 3. Server boot — RLS runtime-role split active in-cluster

The current-branch binary booted with the Phase D/F posture the local suites exercise,
now live on EKS:

- `app pool runs under non-owner role 'fluidbox_runtime' (RLS role split enabled; posture verified: NOLOGIN, no SUPERUSER/BYPASSRLS, no inherited or foreign memberships)`
- `row-level security is ENFORCED for this pool`
- Public `:8787` + internal `:8788` listeners up; access via `kubectl port-forward` only (no Ingress/LB created).

## 4. Certification — NetworkPolicy enforcement, three ways

1. **Boot gate:** initial probes NOT verified (`Unschedulable`, then `NotEnforced`
   during eBPF programming) — run admission correctly **blocked**; verified at
   `22:41:01Z`: `netpol gate: enforcement verified (+:8788 -:8787)`. The gate held
   runs closed until enforcement was real, exactly its job.
2. **Policies materialized:** `fluidbox-sandbox-default-deny` + `fluidbox-sandbox-egress`
   present, `PolicyEndpoints` on both.
3. **`helm test`:** 6 resolver/target suites Succeeded; the one-shot netpol-probe suite
   **Failed** — the DOCUMENTED standard-mode false negative (fail-open before eBPF
   programming; the boot gate is the authoritative proof). Reproduced exactly as on
   2026-07-17; the chart follow-up (a retrying probe) remains open.

## 5. Acceptance — demo A on FLUIDBOX_PROVIDER=kubernetes

**First attempt failed fast with `ErrImagePull` — expected.** The seeded `claude-fixer`
agent's revision pins its creation-time runner image (`fluidbox-sandbox-runner:dev`, a
local-dev ref no node can pull). The 2026-07-17 run created a dedicated agent for the
same reason; the "seeded agents pin their creation-time image" gotcha resurfaced on cue.
$0 spend (provider error before model start); GC clean.

**Run `019f8ce1-e9cf-79b3-ba35-e1b98911dcd8` (agent `eks-fixer`, runner image = ECR
`eks-run`, model `claude-haiku-4-5`) — completed.**

- Sandbox pod **2/2** Running (runner + collector, both ECR images) in `fluidbox-sandboxes`.
- Lifecycle `created → provisioning → initializing → running → finalizing → completed`;
  base_commit `8e2213fb…`; 33 timeline events.
- Diff artifact `changes.patch`: `-    return a + b` / `+    return a * b` on
  `multiply()` — the canonical fix.
- **Cost ledgered:** `$0.0664`, 8 requests, 609 in / 861 out, cache read 184,058 /
  write 34,500.
- **Isolation:** `/tmp/demoa` in the server pod untouched (`git status` clean; both
  `return a + b` lines still present).
- **GC:** sandbox namespace empty of pods AND per-run Secrets after terminal (ownerRef reclaim).
- **P1-1 regression note:** the `local_copy` workspace ran under the ADMIN token
  (operator authority) — the review fix's allowed path, exercised live in-cluster.

**Governance pause/resume (`019f8ce6-beb5-7541-98f9-7a897e251bb2`) — completed.** A
`Write` to `/tmp/…` (outside `/workspace`) paused the session at `awaiting_approval`;
`POST /v1/approvals/019f8ce7-1e05-7333-8256-7f7654528376/decision {"decision":"approve"}`
(`decided_by: operator`) → resumed → `completed`.

## 6. Cost envelope

Model spend ~$0.07 (demo A) + the governance run (haiku). Infra: ~1.5h of
cluster + NAT + 2× t4g.medium ≈ $0.40.

## 7. Baseline + teardown audit

Baseline captured 2026-07-22T22:01:35Z — honestly flagged in the capture itself as
**~28s AFTER** the eksctl stack entered CREATE_IN_PROGRESS (22:01:07Z), so every
eksctl/fluidbox-ephemeral artifact it lists belongs to the in-flight creation, and an
**effective pre-creation baseline was derived** (capture minus the in-flight resources).
All 9 prior `eksctl-fluidbox-eks` stack sets are `DELETE_COMPLETE`, zero
`DELETE_FAILED` — no evidence of an unclean prior teardown. Pre-existing and NOT ours:
NAT `nat-1d0c58bf66f36fed7`, 3 VPCs, 7 CFN stacks, 2 OIDC providers.

- **Zero-orphan verdict:** **PASS — ZERO ORPHANS** (2026-07-23T03:53Z): teardown required manual remediation of two EKS-lifecycle leaks — the VPC-CNI leaked-ENI GC race (`eni-05e2674cdec16ca8b` held the public subnet, DELETE_FAILED on retry #1) and the EKS-created cluster SG outside the CFN resource set (`sg-012d3f9abde2a9c68`, `eks-cluster-sg-fluidbox-eks-283595647`, blocked retry #2) — after which retry #3 deleted the stack clean; all 13 audit categories match the effective pre-creation baseline exactly (0 orphans; the 7 fluidbox-ephemeral tag-index entries are verified NotFound/terminated/deleted eventual-consistency ghosts), and the 3 run-created ECR repos were already swept by the teardown script (no manual deletes needed).

## 8. Verdict (product)

No new product findings. The Phase F branch passes the live EKS acceptance end to end:
boot-gated zero-egress enforcement, the RLS runtime-role split, demo A with a governed
pause/resume — with both known issues (helm-test standard-mode false negative; seeded
agents pinning their creation-time image) reproduced as documented, not regressed.
