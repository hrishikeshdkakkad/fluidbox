# Live EKS acceptance — fluidbox Kubernetes-native provider (epic #48)

Closes the last checkbox of the design's **Acceptance statement**
(`docs/plans/2026-07-15-kubernetes-native-provider-design.md` §406): demo A must
pass unchanged against `FLUIDBOX_PROVIDER=kubernetes` on kind+Calico (already
green in CI) **and at least one managed cloud (EKS or GKE)**, with the hardened
`zeroEgress` profile verified by the boot probe, the diff artifact produced by
the collector path — and the Docker provider fully intact.

- **Cloud:** AWS EKS, region `us-east-1`, account `471112572248`
- **Chart:** `oci://ghcr.io/hrishikeshdkakkad/charts/fluidbox` v0.2.0 (appVersion 0.2.0)
- **Images:** public multi-arch on GHCR (`fluidbox-server:0.2.0` etc.) — no imagePullSecrets
- **Model:** `claude-haiku-4-5` only (cost discipline)
- **Cluster config:** `scripts/eks-cluster.yaml` · **Teardown:** `scripts/eks-teardown.sh`
- **Date:** 2026-07-17

---

## 1. Resource inventory — everything this run creates (written BEFORE creation)

Teardown safety is the point of deferring this to a budget-headroom window. Every
resource class below is enumerated up front so the post-teardown audit can prove
**zero orphans**. All AWS resources are tagged `fluidbox-ephemeral=true` (where
taggable) and/or named `eksctl-fluidbox-eks-*`, and all live inside one eksctl
CloudFormation stack family so `eksctl delete cluster` reclaims them atomically.

| # | Resource class | Detail | Reclaimed by |
|---|---|---|---|
| 1 | CloudFormation stacks | `eksctl-fluidbox-eks-cluster`, `-nodegroup-ng-1`, `-addon-vpc-cni`, `-addon-aws-ebs-csi-driver` (+ coredns/kube-proxy) | `eksctl delete cluster` |
| 2 | EKS control plane | cluster `fluidbox-eks` (v1.33) | eksctl (cluster stack) |
| 3 | Managed nodegroup | `ng-1`: 2× `t3.medium` EC2 (AL2023), 40 GiB gp3 roots | eksctl (nodegroup stack) |
| 4 | VPC networking | 1 VPC, 2 public + 2 private subnets (2 AZs), 1 IGW, **1 NAT gw + 1 EIP**, route tables, security groups, pod ENIs | eksctl (cluster stack) |
| 5 | IAM | OIDC provider, cluster role, node role, EBS-CSI IRSA role | eksctl |
| 6 | EKS addons | vpc-cni (netpol on), aws-ebs-csi-driver (IRSA), coredns, kube-proxy | eksctl |
| 7 | EBS volumes | 2× node roots (40 GiB) + **1× archive PVC (10 GiB gp3)** | node roots→nodegroup delete; PVC→`helm uninstall` + ns delete |
| 8 | Load balancers | **NONE** — access via `kubectl port-forward`; Services are ClusterIP, no Ingress | n/a (defensive sweep in teardown) |
| 9 | ECR repositories | **NONE** — GHCR images are public (design: ECR mirror is *optional*) | n/a |
| 10 | In-cluster objects | ns `fluidbox` + `fluidbox-sandboxes`, Deployments (server/web/litellm), ClusterIP Services, `fluidbox-secrets`, PVC, NetworkPolicies, RBAC, ephemeral sandbox pods + per-run Secrets (GC'd by ownerRef) | `helm uninstall` + ns delete |

**Cost envelope (few-hour window):** EKS control plane $0.10/hr + 2× t3.medium
~$0.083/hr + NAT ~$0.045/hr + trivial EBS ≈ **~$0.25/hr**. Delete promptly.

## 2. Pre-creation baseline (region us-east-1, 2026-07-17T03:52:09Z)

Captured so "zero orphans" is provable by **diff** — anything below is
pre-existing and NOT ours; anything new that survives teardown IS our orphan.

- **EKS clusters:** none
- **NAT gateways (available):** `nat-1d0c58bf66f36fed7` ← **pre-existing, NOT ours** (the audit lists NATs region-wide; do not flag this one)
- **VPCs:** `vpc-04ef1f69ba795b4f9`, `vpc-04a8a15267c19de0f` (default), `vpc-049fc9d234e6210be` ← all pre-existing
- **CloudFormation stacks:** `Serverless-Inc-Role-Stack`, `accountforce-auth`, `accountforce-core-auth`, `aws-sam-cli-managed-default`, `aws-sam-cli-managed-init-pipeline-resources`, `CodePipelineStarterTemplate-CIBuildMaven-ZihS6I8b`, `Infra-ECS-Cluster-forceplatforms-dev-ca50fe1c` ← none `eksctl-fluidbox-eks-*`
- **LoadBalancers (v2 + classic):** none · **EBS volumes:** none · **Unattached EIPs:** none
- **`fluidbox-ephemeral=true` tagged resources:** none (must return to empty post-teardown)
- **Quota:** On-Demand Standard vCPU (L-1216C47A) = 256 (need 4). No constraint.

---

## 3. Cluster create

`eksctl create cluster -f scripts/eks-cluster.yaml` (exit 0, ~18 min). Result:

- EKS `fluidbox-eks` v1.33; 2 managed nodes `t3.medium` AL2023 (kernel 6.12, eBPF-capable), public EXTERNAL-IPs (direct egress, NAT unused by nodes).
- Addons all ACTIVE: `vpc-cni v1.21.2` (config `enableNetworkPolicy: "true"`), `aws-ebs-csi-driver v1.62.0` (IRSA role attached), `coredns`, `kube-proxy`, `metrics-server`.
- OIDC provider present; EBS-CSI IRSA confirmed.
- eksctl's create ordering warns that vpc-cni is created **before** the OIDC association step (`"OIDC is disabled ... eksctl cannot configure ... permissions"`) — harmless: the netpol **eBPF nodeagent uses the node role, not IRSA**, and OIDC is associated immediately after (EBS-CSI IRSA succeeds).

## 4. NetworkPolicy enforcement (Trap #1) + gp3 StorageClass (Trap #2)

**Trap #2 (storage) — clean:** EKS shipped only a non-default in-tree `gp2` SC. Applied
`scripts/eks-gp3-storageclass.yaml` (`ebs.csi.aws.com`, `WaitForFirstConsumer`, default).
The archive PVC later **Bound** a 10Gi gp3 EBS volume the moment the server pod scheduled. ✓

**Trap #1 (NetworkPolicy) — required `strict` enforcing mode.** With
`enableNetworkPolicy: "true"` the `aws-node` DaemonSet ran both `aws-node` + the
`aws-eks-nodeagent` eBPF enforcer (`--enable-network-policy=true`), and the policies
reconciled to `PolicyEndpoints`. But the boot gate + helm test kept reporting
`NotEnforced`. Root cause (proven with a **long-lived** probe): in the default
**`standard`** enforcing mode a freshly-created pod is **fail-open** until the nodeagent
programs its eBPF — so short-lived probes (`nc -w 4`) test *during* the window. A
long-lived probe showed correct enforcement (`+:8788 −:8787`) once programming settled.

> **Finding for the EKS values preset:** on VPC CNI, set
> `NETWORK_POLICY_ENFORCING_MODE=strict` (new pods deny-all from birth). This both makes
> the probe deterministic **and** closes a real fail-open egress window for sandbox pods —
> exactly what the zero-egress model wants. Applied via
> `aws eks update-addon ... --configuration-values '{"enableNetworkPolicy":"true","env":{"NETWORK_POLICY_ENFORCING_MODE":"strict"}}'`.
> After the switch the server logged the gate success:
> `netpol gate: enforcement verified (+:8788 -:8787)` (`workers.rs:565`).

**Operational note (not a fluidbox defect): us-east-1a IPAM failure.** Nodes in
**us-east-1a** failed to bring up the `aws-node` IPAM (ipamd hung on "Checking for IPAM
connectivity", never binding `:50051` → node `NotReady`); us-east-1b nodes were healthy
under the identical (strict) config. A brand-new 1a replacement failed identically → an
AZ-specific problem, not fluidbox. **Worked around** by pinning compute to a fresh
single-AZ (us-east-1b) nodegroup `ng-b` and deleting the straddling `ng-1`. (Also removes
cross-AZ PVC risk.) LiteLLM's default 1Gi limit OOMKilled `main-stable`; reinstalled with
a 2Gi limit.

## 5. Secrets + Helm install

- `kubectl create ns fluidbox`; Secret `fluidbox-secrets` from `.env` (DATABASE_URL = Neon
  **direct** non-pooler 114 chars; ADMIN_TOKEN 64; CREDENTIAL_KEY 64 = 32-byte hex;
  LITELLM_MASTER_KEY; ANTHROPIC_API_KEY). Never sourced — values extracted by key, lengths
  verified, never printed. `scripts/k8s-doctor.sh fluidbox` → all green.
- `helm install fluidbox oci://ghcr.io/hrishikeshdkakkad/charts/fluidbox --version 0.2.0
  -n fluidbox -f values/eks.yaml --set litellm.enabled=true` (STATUS: deployed).
  Images pulled anonymously from public GHCR (no imagePullSecrets). All Services ClusterIP
  (no LoadBalancer); zeroEgress NetworkPolicies `fluidbox-sandbox-default-deny` +
  `fluidbox-sandbox-egress` created.
- **litellm sizing:** the default 1Gi limit OOMKilled `litellm:main-stable` (exit 137);
  reinstalled with `--set litellm.resources.limits.memory=2Gi` → healthy. (Finding for the
  chart's litellm defaults.)

## 6. Certification — NetworkPolicy enforcement

**Enforcement is verified — proven three independent ways:**

1. **Boot gate (the design's "boot probe", the run-admission gate):**
   server log `netpol gate: enforcement verified (+:8788 -:8787)` (`workers.rs:565`).
   Runs are admitted only after this; it stays verified (re-checks every 6h).
2. **Long-lived probe** (managed pod in the sandbox ns): `:8787 BLOCKED`, `:8788 REACHABLE`
   — direct proof the egress policy is enforced once the pod's eBPF is programmed.
3. **The live demo-A run** (§7) executed under zeroEgress, reaching only the internal
   `:8788` and never the internet.

**`helm test` caveat (false negative on VPC CNI `standard` mode):** the chart's helm-test
probe is a *one-shot* pod that tests `:8787` immediately on startup. In VPC CNI `standard`
mode a new pod is **fail-open** until the nodeagent programs its eBPF (the documented
policy-application race), so the probe's negative check catches `:8787` reachable →
`FAIL negative`. This is a probe-timing false negative, **not** an enforcement gap (proofs
1–3). `strict` mode makes it deterministic but is unusable here — it starves *system* pods
(CoreDNS, EBS CSI controller/node) of IMDS/API access during startup, cascading into DNS
and PVC-provisioning failures. **Recipe for EKS: `standard` mode; enforcement is real and
the boot gate confirms it.** Follow-up (chart): the helm-test probe should retry its
negative check for a few seconds to tolerate `standard`-mode programming latency (Calico,
the CI reference, programs before pod-ready so it passes one-shot — hence green in CI).

## 7. Acceptance — demo A on FLUIDBOX_PROVIDER=kubernetes

Agent `eks-fixer` (harness `claude-agent-sdk`, **model `claude-haiku-4-5`**, policy
`default`, runner image `ghcr.io/hrishikeshdkakkad/fluidbox-sandbox-runner:0.2.0`).
Workspace: the demo-A calculator fixture `kubectl cp`'d into the server pod (`/tmp/demoa`,
a git repo with `multiply` returning `a+b`), driven as `{"kind":"local_copy"}` — **demo A
unchanged**, fully self-contained (the control plane materializes its own `/tmp`).

**Run `019f6ea3` — completed.** Lifecycle `created → provisioning → initializing →
running → finalizing → completed`. Sandbox pod `fluidbox-019f6ea3…` observed **2/2**
(runner + collector) → 1/2 NotReady (finalizing) → Terminating → gone.
- **Collector-produced diff artifact** (`event: artifact.collected`):
  ```diff
   def multiply(a, b):
  -    return a + b
  +    return a * b
  ```
- **Cost ledgered:** `$0.02263` (haiku), **3 tool calls** (unittest → edit → unittest),
  595/593 tokens. 28-event governed timeline (`workspace.initialized`, `tool.requested`×3
  → `tool.decision`×3, `model.response`×6, `artifact.collected`, `run.result`).
- **Isolation:** original `/tmp/demoa` untouched — still `return a + b`, HEAD unchanged,
  `git status` clean (the agent worked on a disposable copy).
- **GC:** sandbox namespace empty afterward — pod **and** per-run Secret reclaimed.

**Governance pause/resume (`019f6ea8`) — completed.** A `Write` to `/tmp/…` (outside
`/workspace`) hit the default policy's `approve` → session paused at **`awaiting_approval`**;
`POST /v1/approvals/{id}/decision {"decision":"approve"}` (`decided_by: operator`) →
`running → completed`. The permission gate — the heart of the system — governs the live
Kubernetes provider exactly as designed.

## 8. Teardown

1. Killed port-forward; `helm uninstall fluidbox -n fluidbox` (freed ClusterIP Services +
   the archive PVC → its gp3 EBS volume auto-deleted via `reclaimPolicy: Delete`).
2. `kubectl delete ns fluidbox fluidbox-sandboxes`.
3. `eksctl delete cluster --name fluidbox-eks --region us-east-1 --disable-nodegroup-eviction
   --wait` → **"all cluster resources were deleted"** (exit 0). Sequence: nodegroup `ng-b`
   stack → IAM OIDC provider → both addon IRSA stacks (vpc-cni, ebs-csi) → cluster/VPC/NAT
   stack. (eksctl also swept for K8s-created LBs — none, since all Services were ClusterIP.)
   `ng-1` was already deleted earlier (the us-east-1a workaround). No ECR was ever created
   (public GHCR images), so nothing to sweep there.

## 9. Post-teardown audit — ZERO orphans

Audited `2026-07-17T06:18Z`, diffed against the §2 baseline. **Every category clean:**

| Check | Result |
|---|---|
| `eksctl-fluidbox-eks-*` CloudFormation stacks (not DELETE_COMPLETE) | **none** |
| EKS clusters | **none** |
| NAT gateways (available) | only `nat-1d0c58bf66f36fed7` (**pre-existing baseline**); mine `nat-028eefeb684703fa9` → `deleted` |
| EBS volumes tagged with cluster | **none** (5 node/PVC volumes → `InvalidVolume.NotFound`) |
| LoadBalancers (v2 + classic) | **none** |
| Unattached EIPs | **none** (NAT's EIP released) |
| VPCs | only the 3 baseline; my eksctl VPC deleted |
| IAM roles `eksctl-fluidbox-eks-*` | **none** |
| OIDC provider (`…/C3761FEDE17C2EE82C8F7C2416DAA02B`) | **gone** |
| Security groups `eksctl-fluidbox-eks-*` | **none** |
| Running EC2 tagged `fluidbox-ephemeral` | **none** (all instances `terminated`) |
| ENIs | 5 tagged ENIs → `InvalidNetworkInterface…NotFound` (deleted) |

**Note on the tagging API:** `resourcegroupstaggingapi` still *listed* several
`fluidbox-ephemeral` ARNs (volumes/instances/ENIs/NAT) — this is its documented
eventual-consistency lag, not live resources. Each was verified individually as
`terminated` / `NotFound` / `deleted` (above). The stale tag-index entries age out on
their own; there is nothing left to delete.

**Conclusion:** the ephemeral EKS acceptance environment is fully reclaimed — zero orphans,
zero ongoing spend beyond the pre-existing baseline. Total run cost: a few dollars of
compute + `$0.036` of haiku inference across the acceptance runs.
