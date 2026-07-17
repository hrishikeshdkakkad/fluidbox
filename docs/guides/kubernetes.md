# Kubernetes deployment guide

fluidbox runs on any conformant Kubernetes cluster with an **enforcing CNI** — kind, AWS EKS, Google GKE, Azure AKS, DigitalOcean DOKS, or anything else in its support window. `v0.2.0` ships the Kubernetes-native execution provider and an OCI Helm chart. This guide takes you from zero to a **certified, run-serving cluster**, with the real-world gotchas and costs from a live cloud acceptance.

> **Just want to try fluidbox?** Kubernetes is one of two execution providers. For a single machine, the [Docker path](../../README.md#try-fluidbox) is faster and cheaper. See [Which provider?](#which-provider) to choose.

---

## Contents

- [How the Kubernetes provider works](#how-the-kubernetes-provider-works)
- [Which provider? Docker vs Kubernetes](#which-provider)
- [Prerequisites](#prerequisites)
- [Local: kind + Calico](#local-kind--calico)
- [Managed cloud: the generic recipe](#managed-cloud-the-generic-recipe)
- [AWS EKS — step by step](#aws-eks--step-by-step)
- [Other clouds: GKE, AKS, DOKS](#other-clouds-gke-aks-doks)
- [Secrets](#secrets)
- [Certifying network enforcement](#certifying-network-enforcement)
- [Verifying a run end to end](#verifying-a-run-end-to-end)
- [Sizing and cost (AWS example)](#sizing-and-cost-aws-example)
- [Teardown — do it safely](#teardown--do-it-safely)
- [Troubleshooting](#troubleshooting)
- [Reference](#reference)

---

## How the Kubernetes provider works

One run becomes **one bare Pod** in a dedicated sandbox namespace (default `fluidbox-sandboxes`). The Pod has three parts:

```text
  ┌─────────────────────── sandbox Pod (per run) ───────────────────────┐
  │  initContainer: workspace          collector container (long-lived)  │
  │  pulls the credential-free   ───▶  runner container       ───▶       │
  │  workspace archive from the        (Claude SDK or Codex)   computes  │
  │  control plane's PVC                the agent runs here     a diff    │
  └──────────────────────────────────────────────────────────────────────┘
        ▲ session token only                    ▲ egress: internal :8788 ONLY
        │ (no upstream credentials)              │ (zeroEgress NetworkPolicy)
```

- **The control plane is the authority; the Pod is workload-only.** The runner gets a short-lived session token — never a real model, git, or MCP credential.
- **Workspace materialization is control-plane-side.** fluidbox fetches the repo with credentials, archives it, and the Pod pulls a disposable copy. The original repo is never the working tree.
- **`zeroEgress` by default.** A NetworkPolicy allows the sandbox to reach only the internal control-plane service (`:8788`) and nothing else — not the internet, not the LLM gateway, not the public API (`:8787`).
- **Run admission is gated on proven enforcement.** At boot, fluidbox runs a probe and refuses to admit runs until it confirms the cluster's CNI actually enforces NetworkPolicy (`FLUIDBOX_REQUIRE_ENFORCED_NETPOL=true`). A cluster that silently ignores policy is **fail-closed**, not fail-open.
- **Per-run Secrets are owner-referenced** for automatic garbage collection; the Pod and its Secret disappear on terminal.
- **Finalization is durable** — the diff is collected before the terminal transition, and interrupted finalizations are recovered after a control-plane restart.

The Docker provider stays the default (`FLUIDBOX_PROVIDER=docker`) and is never demoted; Kubernetes lands **beside** it via the same `ExecutionProvider` trait and the same HTTP runner contract.

---

## Which provider?

| | **Docker** (default) | **Kubernetes** |
|---|---|---|
| Best for | Local dev, single-host self-hosting, trying the loop | Fleets, autoscaling, cluster-grade isolation |
| Deploy | `docker compose` on one host | Helm chart on any conformant cluster |
| Sandbox | sibling container | bare Pod in a sandbox namespace |
| Zero-egress boundary | hardened bridge mode | `zeroEgress` NetworkPolicy (probe-verified) |
| Infra cost floor | one VM | control plane + nodes (see [cost](#sizing-and-cost-aws-example)) |
| Scale-to-zero | n/a | control plane always on |

**Rule of thumb:** use Docker until you actually need a cluster (multi-node capacity, K8s-native isolation, or you already run on Kubernetes). Docker on a single VM is roughly a **third** of the cost of a managed-cloud Kubernetes cluster.

---

## Prerequisites

| Requirement | Notes |
|---|---|
| `kubectl` ≥ 1.27 | matched to your cluster version |
| `helm` ≥ 3.8 | OCI registry support |
| **An enforcing CNI** | Calico, Cilium, or a cloud CNI **with NetworkPolicy enforcement turned on**. kind's default kindnet does **not** enforce. |
| A default `RWO` StorageClass | for the workspace-archive PVC |
| A **direct** Postgres URL | Neon (blessed) — use the non-pooler connection string (`LISTEN/NOTIFY` needs a direct connection) |
| Container images | public multi-arch on GHCR — **no pull secret needed** unless you mirror privately |

Verify a candidate cluster before installing:

```bash
bash scripts/k8s-doctor.sh fluidbox
# checks: kube context, apiserver, default StorageClass, an enforcing-capable CNI, the fluidbox-secrets Secret
```

---

## Local: kind + Calico

The fastest way to exercise the Kubernetes provider without a cloud account. kindnet doesn't enforce NetworkPolicy, so `just k8s-dev` provisions kind **with Calico**:

```bash
just k8s-dev          # kind + Calico + build/load images + print next steps
just k8s-doctor       # preflight: context, StorageClass, CNI, Secret

# create the credential Secret (see Secrets below), then:
helm upgrade --install fluidbox deploy/helm/fluidbox \
  -n fluidbox --create-namespace \
  -f deploy/helm/fluidbox/values/kind.yaml

helm test fluidbox -n fluidbox                 # must PASS (+:8788  -:8787)
kubectl -n fluidbox port-forward svc/fluidbox-fluidbox-server 8787:8787
```

This kind flow is exactly what CI runs, so "works in `just k8s-dev`" ≈ "works in CI."

---

## Managed cloud: the generic recipe

Every managed cloud follows the same five steps; only the **CNI enforcement** and **StorageClass** differ (covered per-cloud below).

1. **Provision a cluster with an enforcing CNI.**
2. **Create the namespace and the `fluidbox-secrets` Secret** ([Secrets](#secrets)).
3. **`helm install` from the OCI registry** with the cloud's values preset:
   ```bash
   helm install fluidbox oci://ghcr.io/hrishikeshdkakkad/charts/fluidbox \
     --version 0.2.0 \
     -n fluidbox --create-namespace \
     -f deploy/helm/fluidbox/values/<cloud>.yaml
   ```
   Presets ship for `eks`, `gke`, `aks`, `doks`, and `kind` under
   [`deploy/helm/fluidbox/values/`](../../deploy/helm/fluidbox/values).
4. **Certify enforcement** — `helm test` passes and the server log confirms the boot gate ([Certifying enforcement](#certifying-network-enforcement)).
5. **Point DNS/Ingress and set `FLUIDBOX_PUBLIC_URL`** to your https origin — this lights up OAuth callbacks, CIMD, and GitHub App webhooks with no code change.

> Images ship **public** on GHCR, so no imagePullSecret is needed unless you mirror to a private registry. For production, **pin image digests** and supply all credentials through the existing Secret — the chart never generates credential material.

---

## AWS EKS — step by step

EKS has **two traps** that will silently break a fresh install. Both are handled by the shipped preset [`values/eks.yaml`](../../deploy/helm/fluidbox/values/eks.yaml) plus the steps below. The reproducible cluster config is [`scripts/eks-cluster.yaml`](../../scripts/eks-cluster.yaml); teardown is [`scripts/eks-teardown.sh`](../../scripts/eks-teardown.sh).

> These steps and the [field notes](#field-notes-from-a-live-eks-acceptance) come from a live EKS acceptance run (evidence: [`docs/reviews/2026-07-17-eks-acceptance.md`](../reviews/2026-07-17-eks-acceptance.md)).

### 1. Create the cluster

```bash
eksctl create cluster -f scripts/eks-cluster.yaml
```

Key pieces of that config:

- **OIDC enabled** (`iam.withOIDC: true`) — required for the EBS CSI IRSA role.
- **Trap #1 — NetworkPolicy is NOT enforced by default.** The AWS VPC CNI is an IPAM plugin; it installs no policy enforcement. Turn on the eBPF nodeagent via the addon config, and **keep the default `standard` enforcing mode** (see the warning below):
  ```yaml
  addons:
    - name: vpc-cni
      configurationValues: |-
        enableNetworkPolicy: "true"
  ```
- **Trap #2 — no default StorageClass / EBS CSI not preinstalled.** Install the driver as an addon with IRSA:
  ```yaml
    - name: aws-ebs-csi-driver
      wellKnownPolicies:
        ebsCSIController: true
  ```
- **Nodes:** AmazonLinux2023 (supports the netpol eBPF agent), `t3.medium` minimum. See [sizing](#sizing-and-cost-aws-example) — for a single-node cluster prefer `t3.large`.

> ⚠️ **Do NOT set `NETWORK_POLICY_ENFORCING_MODE=strict` on EKS.** Strict mode makes every new Pod deny-all until the nodeagent programs its eBPF — which starves *system* pods (CoreDNS, the EBS CSI controller/node) of IMDS and API-server access during startup. They crashloop, DNS dies, EBS can't reach STS, and PVCs never provision. **`standard` mode enforces correctly** for fluidbox — the boot gate confirms it — and leaves system pods alone.

### 2. Add the gp3 StorageClass

`values/eks.yaml` pins `server.archivePvc.storageClass: gp3`, and EKS ships no default class, so create one:

```bash
kubectl apply -f scripts/eks-gp3-storageclass.yaml
# gp3, ebs.csi.aws.com, WaitForFirstConsumer, default, encrypted
```

`WaitForFirstConsumer` binds the volume in the AZ where the Pod lands, avoiding cross-AZ bind failures.

### 3. Secrets, install, certify

```bash
kubectl create namespace fluidbox
# ...create fluidbox-secrets (see Secrets)...

helm install fluidbox oci://ghcr.io/hrishikeshdkakkad/charts/fluidbox \
  --version 0.2.0 -n fluidbox \
  -f deploy/helm/fluidbox/values/eks.yaml \
  --set litellm.enabled=true \
  --set litellm.resources.limits.memory=2Gi   # see field notes

helm test fluidbox -n fluidbox
kubectl -n fluidbox logs deploy/fluidbox-fluidbox-server | grep 'netpol gate'
# expect: netpol gate: enforcement verified (+:8788 -:8787)
```

### Field notes from a live EKS acceptance

Real gotchas observed bringing this up on EKS in `us-east-1`. The durable lessons are baked into the configs above; keep these in mind:

| Symptom | Cause | Fix |
|---|---|---|
| `helm test` fails `negative: :8787 REACHABLE` but the **boot gate passes** | The chart's one-shot probe races VPC CNI **standard-mode fail-open** (a new Pod is briefly allowed until eBPF programs). | Enforcement is real — trust the boot gate + a long-lived probe. This is a probe-timing false negative (chart follow-up: retry the negative check). |
| System pods (CoreDNS, EBS CSI) crashloop; PVC stuck `Pending` | You set **`strict`** enforcing mode. | Revert to `standard` and restart the affected system pods so they re-init with clean networking. |
| A node stays `NotReady`; `aws-node` shows `1/2`, ipamd hangs on "Checking for IPAM connectivity" | **AZ-specific** IPAM failure (observed only in `us-east-1a` at the time; not a fluidbox issue). | Pin the nodegroup to a healthy AZ (`availabilityZones: [us-east-1b]` in the nodegroup). |
| `litellm` `OOMKilled` (exit 137) | `litellm:main-stable` needs more than the chart's default 1Gi. | `--set litellm.resources.limits.memory=2Gi`. |
| A service unreachable after toggling netpol modes | Pods that started under strict keep stale eBPF deny rules after reverting. | `kubectl rollout restart` the affected deployment. |

---

## Other clouds: GKE, AKS, DOKS

| Cloud | NetworkPolicy enforcement | PVC storage | Preset |
|---|---|---|---|
| **GKE** | Dataplane V2 (Cilium) enforces natively — the recommended mode; Autopilot always has it. Classic dataplane needs `--enable-network-policy`. | default `standard-rwo` works | `values/gke.yaml` |
| **AKS** | Choose a policy engine **at cluster creation** (Azure NPM, Cilium dataplane, or Calico) — it can't be added later. | default `managed-csi` works | `values/aks.yaml` |
| **DOKS** | Cilium is the default CNI — enforced out of the box, zero extra setup. The simplest managed-cloud story. | default `do-block-storage` works | `values/doks.yaml` |
| **Anything conformant** | any enforcing CNI — the boot probe is the arbiter, not the vendor list | any default RWO class | generic recipe |

The probe-fails-closed design makes the vendor list *advisory*: fluidbox proves enforcement at boot rather than trusting a cloud to have it, so on-prem RKE2/k3s, OVH, Hetzner, etc. are supported by construction.

---

## Secrets

The chart reads — never writes — a single existing Secret named `fluidbox-secrets` in the release namespace:

| Key | Value |
|---|---|
| `DATABASE_URL` | Neon **direct** (non-pooler) connection string |
| `FLUIDBOX_ADMIN_TOKEN` | admin bearer for the `/v1` API + dashboard |
| `FLUIDBOX_CREDENTIAL_KEY` | 32-byte hex (seals connections + gates event ingress) |
| `LITELLM_MASTER_KEY` | facade ↔ gateway auth |
| `ANTHROPIC_API_KEY` | only if `litellm.enabled=true` (bundled gateway) |

```bash
kubectl -n fluidbox create secret generic fluidbox-secrets \
  --from-literal=DATABASE_URL='postgresql://...neon.tech/neondb?sslmode=require' \
  --from-literal=FLUIDBOX_ADMIN_TOKEN="$(openssl rand -hex 32)" \
  --from-literal=FLUIDBOX_CREDENTIAL_KEY="$(openssl rand -hex 32)" \
  --from-literal=LITELLM_MASTER_KEY="sk-$(openssl rand -hex 16)" \
  --from-literal=ANTHROPIC_API_KEY='sk-ant-...'
```

> Production LiteLLM is external by default. Set `llm.upstreamUrl` to your gateway and omit `litellm.enabled`; the bundled gateway is a convenience for isolated setups.

---

## Certifying network enforcement

fluidbox proves the sandbox is actually contained — two independent checks:

**1. `helm test` (release certification).** A probe Pod in the sandbox namespace, under the `zeroEgress` policy, must reach the **internal** service `:8788` (positive) and must **not** reach the **public** service `:8787` (negative). Both services back the same healthy pod, so reachability is known independently of policy — no external-IP false pass.

```bash
helm test fluidbox -n fluidbox
# PASS: NetworkPolicy enforced (+:8788 -:8787)
```

**2. The boot gate (the real run-admission gate).** The server periodically probes and admits runs only after:

```text
netpol gate: enforcement verified (+:8788 -:8787)
```

With `FLUIDBOX_REQUIRE_ENFORCED_NETPOL=true` (default), a cluster that doesn't enforce keeps runs **blocked** — never silently unprotected.

> On VPC CNI standard mode the one-shot `helm test` probe can false-negative on the fail-open window even though enforcement is real. The **boot gate** (which retries) and a long-lived probe are the authoritative signals. See the [EKS field notes](#field-notes-from-a-live-eks-acceptance).

---

## Verifying a run end to end

With `helm test` green and the boot gate verified, drive a run (the classic "fix a failing test"):

```bash
kubectl -n fluidbox port-forward svc/fluidbox-fluidbox-server 8787:8787 &
AT=<your FLUIDBOX_ADMIN_TOKEN>

# 1. Create an agent (haiku keeps it cheap)
curl -s -XPOST -H "authorization: Bearer $AT" -H 'content-type: application/json' \
  -d '{"name":"fixer","harness":"claude-agent-sdk","model":"claude-haiku-4-5","policy":"default"}' \
  http://127.0.0.1:8787/v1/agents

# 2. Start a run against a git workspace (or a local_copy path the server can read)
curl -s -XPOST -H "authorization: Bearer $AT" -H 'content-type: application/json' \
  -d '{"agent":"fixer","task":"Run the tests, fix the failing one, re-run to confirm.",
       "workspace":{"kind":"git_repository","repository":"owner/name"}}' \
  http://127.0.0.1:8787/v1/sessions
```

Watch the lifecycle — you should see the full arc and clean GC:

```bash
kubectl -n fluidbox-sandboxes get pods -w
# fluidbox-<id>  0/2 Pending → 2/2 Running (runner + collector) → 1/2 (finalizing) → gone

curl -s -H "authorization: Bearer $AT" http://127.0.0.1:8787/v1/sessions/<id>/artifacts   # diff artifact
curl -s -H "authorization: Bearer $AT" http://127.0.0.1:8787/v1/sessions/<id>/cost        # usage + cost
kubectl -n fluidbox-sandboxes get pods,secrets   # empty after terminal — Pod + per-run Secret GC'd
```

A completed run leaves a **collector-produced diff**, a **cost/usage record**, an append-only event timeline, and **no leftover Pod or Secret**. Governed tool calls appear as `tool.requested → tool.decision`; a non-allowlisted action pauses at `awaiting_approval` until you `POST /v1/approvals/{id}/decision`.

---

## Sizing and cost (AWS example)

**Node sizing — can all services fit on one host?** Core services request roughly:

| Pod | CPU req | Mem req |
|---|---|---|
| server | 250m | 512Mi |
| web | 100m | 256Mi |
| litellm (bundled) | 250m | ~1Gi |
| one sandbox run | 500m | 1Gi |
| system DaemonSets (aws-node, kube-proxy, ebs-csi, coredns) | ~350m | ~350Mi |

On a **t3.medium** (2 vCPU / 4 GiB, ~1.93 vCPU / ~3.4 GiB allocatable) that fits by *requests* but leaves almost no headroom — under real load litellm plus a running agent will OOM (observed live). **Recommendations:**

- **Single-host cluster → `t3.large` (8 GiB).** Comfortably runs server + web + litellm + a couple concurrent sandbox pods.
- **Fleet → 2× t3.medium** (or larger), letting sandbox pods spread across nodes.

**Monthly cost — the acceptance cluster** (us-east-1 on-demand, 730 h, verified against the AWS Pricing API):

| Line | Rate | Monthly |
|---|---|---|
| EKS control plane | $0.10/hr | $73.00 |
| 2× t3.medium | $0.0416/hr ea | $60.74 |
| NAT gateway | $0.045/hr | $32.85 |
| Public IPv4 × 3 | $0.005/hr ea | $10.95 |
| EBS gp3, 90 GiB | $0.08/GB-mo | $7.20 |
| Data transfer (idle) | — | ~$1–3 |
| **Total (idle)** | | **≈ $186 / mo** |

**Cheaper variants:**

- **Single-node EKS** (1 node, NAT disabled): **≈ $145/mo** — you still pay the $73 control-plane tax for one node.
- **Docker provider on one VM** (`deploy/docker-compose.eval.yml`, no EKS, no NAT): a single t3.large ≈ **$69/mo** — about a third of the EKS bill. The natural single-host deployment.
- Spot nodes cut the compute line ~70%; the biggest fixed costs are the control plane and the NAT (disable it if your nodes are public-subnet).

> These are AWS infrastructure figures only. Actual agent runs add Anthropic API spend (the acceptance runs were ~$0.02 each on haiku); your Neon database is separate.

---

## Teardown — do it safely

The control plane and NAT bill by the hour, so tear down ephemeral clusters promptly — and **audit for orphans**, because a partial teardown quietly bleeds money.

```bash
# 1. Release-level resources (frees Services + the PVC's EBS volume)
helm uninstall fluidbox -n fluidbox
kubectl delete ns fluidbox fluidbox-sandboxes

# 2. The whole cluster (nodegroups, control plane, VPC, NAT, IRSA, OIDC)
eksctl delete cluster --name fluidbox-eks --region us-east-1 --wait

# 3. AUDIT — every line MUST be empty (or only pre-existing baseline resources)
scripts/eks-teardown.sh   # helm uninstall + sweeps + audit in one shot
```

Then confirm zero orphans directly:

```bash
aws eks list-clusters --region us-east-1                       # empty
aws cloudformation list-stacks --region us-east-1 \
  --query "StackSummaries[?contains(StackName,'fluidbox-eks') && StackStatus!='DELETE_COMPLETE'].StackName" --output text   # empty
aws ec2 describe-instances --region us-east-1 \
  --filters Name=tag:fluidbox-ephemeral,Values=true Name=instance-state-name,Values=running \
  --query 'Reservations[].Instances[].InstanceId' --output text  # empty
```

> The `resourcegroupstaggingapi` tag index **lags** — it lists recently-deleted resources for a while. Verify suspect resources individually (`describe-instances`/`describe-volumes` → `terminated`/`NotFound`), not by the tag index alone.

---

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| Runs stay blocked; log shows `netpol gate: NOT verified (NotEnforced)` | CNI isn't enforcing NetworkPolicy | Enable enforcement (VPC CNI netpol agent / Calico / Cilium). Never lower `FLUIDBOX_REQUIRE_ENFORCED_NETPOL`. |
| `helm test` probe fails the negative check but the boot gate passes | VPC CNI standard-mode fail-open race (probe timing) | Enforcement is real — trust the boot gate; re-run the test. |
| Archive PVC stuck `Pending` | No default/`gp3` StorageClass, or EBS CSI driver/IRSA missing | Install the EBS CSI addon with IRSA and apply the gp3 StorageClass. |
| Sandbox Pod stuck `ContainerCreating`, `FailedCreatePodSandBox` (`50051 connection refused`) | `aws-node` IPAM briefly down (DaemonSet re-roll) or strict-mode Pod-startup hold | Wait out the re-roll; avoid strict mode; if a node's IPAM won't recover, replace the node. |
| System pods (CoreDNS/EBS CSI) crashloop, DNS/PVC failures | VPC CNI `strict` enforcing mode | Revert to `standard`; restart the affected system pods. |
| `litellm` `CrashLoopBackOff` / OOMKilled (137) | 1Gi memory limit too small | `--set litellm.resources.limits.memory=2Gi`. |
| Run fails `502 ... litellm:4000` although litellm is Running | stale eBPF state on a pod that started under strict mode | `kubectl rollout restart deploy/<release>-litellm`. |
| Node `NotReady` in one AZ, IPAM hangs on "Checking for IPAM connectivity" | AZ-specific IPAM/infra problem | Pin the nodegroup to a healthy AZ. |
| A `just` command hits a real Neon DB unexpectedly | `justfile` loads `.env` for every recipe | For K8s ops use the plain scripts (`bash scripts/k8s-doctor.sh`), not `just`, unless you intend `.env`. |

---

## Reference

- [Kubernetes provider design](../plans/2026-07-15-kubernetes-native-provider-design.md) — Pod lifecycle, network enforcement, archive transport, finalization, reconciliation, and the 16 settled design questions.
- [Live EKS acceptance report](../reviews/2026-07-17-eks-acceptance.md) — the end-to-end evidence and audited teardown these notes come from.
- [Chart values](../../deploy/helm/fluidbox/values.yaml) and [per-cloud presets](../../deploy/helm/fluidbox/values) — every knob, annotated.
- Repro scripts: [`scripts/eks-cluster.yaml`](../../scripts/eks-cluster.yaml), [`scripts/eks-gp3-storageclass.yaml`](../../scripts/eks-gp3-storageclass.yaml), [`scripts/eks-teardown.sh`](../../scripts/eks-teardown.sh), [`scripts/k8s-doctor.sh`](../../scripts/k8s-doctor.sh).
- [Architecture](../ARCHITECTURE.md) · [Security](../../SECURITY.md) · [main README](../../README.md).
