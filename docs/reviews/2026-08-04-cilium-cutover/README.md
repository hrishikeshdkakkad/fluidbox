# Cilium cutover on Fluidbox Cloud — what it took, and what it found

**Date:** 2026-08-04 · **Cluster:** `fluidbox-cloud` (EKS 1.35, us-east-1,
account 471112572248) · **Cilium:** 1.19.6, ENI IPAM + native routing

Goal: make governed sandbox network access *possible* on the live deployment.
It was inert — the feature lowers to CiliumNetworkPolicy and the cluster ran the
AWS VPC CNI, whose plain NetworkPolicy cannot express an FQDN allow at all.

This is the substrate + control-plane half. **No tenant has been granted
egress**; see "Where this stops" below.

---

## 1. Substrate — Cilium as the primary CNI

Terraform, not `kubectl`: `deploy/cloud/terraform/platform/cilium.tf`, selected
by `var.cni` so the vpc-cni addon is count-gated off and the two are mutually
exclusive by construction.

### The deliberate deviation from the runbook

`docs/hosted/network-grants-eks-acceptance-runbook.md` §1 prescribes
overlay/VXLAN on a **fresh** cluster. This is a **live** cluster, and overlay
pod IPs are not VPC-routable — which breaks the ALB's `target-type: ip`, i.e.
the entire CloudFront → ALB → server chain, and would force a NodePort
recomposition plus CloudFront origin surgery.

ENI IPAM + native routing keeps pod IPs VPC-routable, so ingress, edge, and the
chart stayed byte-identical. Everything the grants design rests on — identity-
vs-CIDR selector semantics, cross-object deny precedence, the FQDN proxy — is
policy-engine behaviour, independent of routing mode. kube-proxy was kept:
kube-proxy replacement is only required by the egress gateway, which stays off.

### Three things the cutover forced, none of them predicted

| Symptom | Cause | Fix |
|---|---|---|
| EBS CSI + ALB controllers timing out to EC2/ELB APIs; pods on one ENI fine, pods on another dark | This VPC has **no NAT** by design; only the **primary** ENI's primary address carries a public mapping. Cilium allocated a second ENI and SNAT'd those pods to an address the IGW drops. | `eni.awsEnablePrefixDelegation: true` — ~176 addresses on the primary ENI of a t4g.large, far past kubelet's max-pods, so a second ENI is never needed. |
| Every pod internet-dark after install | The chart **defaults IPv4 masquerade OFF** in ENI mode, assuming a NAT gateway. Pod traffic left with its pod source IP and died at the IGW. Visible as `enable-ipv4-masquerade: "false"` in the live `cilium-config`. | `enableIPv4Masquerade: true` |
| `cilium-agent` panics at boot, node `NotReady` with `cni plugin not initialized` | With ENI IPAM + masquerade, `egressMasqueradeInterfaces` is **mandatory**: *"Egress masquerading interfaces cannot be empty when IP masquerading is enabled with IPAM mode other than ClusterPool or Kubernetes"* | `ens+`. The upstream example `eth+` is AL2-era naming; AL2023/Nitro names ENIs `ens5` (verified on the node). |

### The step Terraform cannot express

Each node must be **recycled** after the apply. `aws-node`'s warm secondary ENIs
stay attached to the running instance and a t4g.large has only three ENI slots,
so a fresh instance is the clean way to hand Cilium the ENI budget *and* restart
every pod onto a Cilium-managed endpoint at once. Recorded in `cilium.tf`.

### Verified after the cutover

- `cilium status --brief` → `OK`; agent + operator healthy on every node
- CloudFront `/v1/health` → **200** through the unchanged ALB
- The product's own boot gate: `netpol gate: enforcement verified (+:8788 -:8787, observed within 60s)`
- A sandbox pod scheduled and the sandbox nodegroup autoscaled 0→1

Note the third bullet: the pre-existing `zeroEgress` k8s NetworkPolicies still
enforce under Cilium. They are kept on purpose — Cilium unions allows across
NetworkPolicy and CiliumNetworkPolicy, so `:8788`-only remains a second,
CNI-independent floor while per-run CNPs add granted targets on top.

---

## 2. Two bugs this found in the feature itself

### 2.1 The enforcer was never wired (fixed upstream by #126)

`main` at `d491bc1` (PR #122) shipped `CiliumNetworkEnforcer` and a
`connect_with_enforcer()` that resolves it — **with zero callers anywhere in the
repo**. `build_provider` still called plain `connect()`, so `enforcer` was
always `None`.

Consequence, observed live: with `FLUIDBOX_NETWORK_ENFORCER=cilium` set on a
cluster that genuinely runs Cilium, the server logged

```
sandbox network grants: NO enforcer resolved (requested: cilium) — runs are
offline-only and any wider grant is refused at create time
```

That is precisely the silent downgrade #122's own description claimed to have
closed, and the "boot refusal on a Cilium-less cluster" could never fire either.

**PR #126 fixes it** — and better than a fresh caller would have: it collapses
the mode into `connect()` itself, so the dead-code trap cannot reappear. It also
picks `netpol_wait_secs` as the verify timeout, which is the same knob this
investigation had independently concluded was right.

### 2.2 The controlled resolver could not exec (PR #128)

Enabling `networkGrants` kills the sandbox DNS resolver instantly:

```
exec /coredns: operation not permitted
```

CrashLoopBackOff on every replica, and `helm upgrade --wait` hangs to its
timeout. CoreDNS binds `:53` as uid 65532, which the image supports by shipping
`/coredns` with the `cap_net_bind_service` **file capability**; the pod dropped
`ALL` capabilities while `allowPrivilegeEscalation: false` sets `NO_NEW_PRIVS`,
and the kernel refuses to exec a binary carrying file capabilities under that
combination. It never reached a bind failure — the process could not start.

Fixed by adding `NET_BIND_SERVICE` (what upstream CoreDNS manifests do), guarded
by a render assertion in `chart-assertions.sh` because the kind job does not
reproduce the exec refusal. The assertion was verified to fail on removal.

---

## 3. Where this stops, and why

**No tenant can obtain egress today, and that is the correct state.**

The last mile is two tenant-data edits: a policy raising `network.max_mode`
above `offline` with a target catalog, and an agent revision declaring a
`NetworkRequest`. Both are deliberately gated behind an authenticated
**owner** — the design's words are that enabling sandbox egress must be "a
deliberate, auditable policy edit".

There is no non-subverting automation path from here: under
`FLUIDBOX_REQUIRE_SSO=1` the admin token is confined to `/v1/admin/*` (verified:
`GET /v1/agents` → 401), PAT minting requires a browser session, and the
dashboard exposes neither a PAT UI nor a network-grant UI. The remaining ways in
would be forging a credential or writing tenant rows directly — either of which
would defeat exactly the property the feature exists to provide.

**Order matters on the last mile:** PR #126 carries ten security fixes for this
feature, including a policy-deny bypass and a DNS exfiltration channel. Nothing
should raise a policy ceiling on a deployment whose running image predates it.

---

## 4. Residuals recorded

- **`deploymentPublicCIDRs` can go stale.** It carries the ALB's current public
  IPs, which are AWS-managed and change when the load balancer scales or is
  replaced, and it is a static file. It is also incomplete for the real front
  door, CloudFront (a large managed prefix list, not enumerable here).
  Consequence: **`public` mode is not certified on this deployment.** `approved`
  mode, where every target is named, does not depend on this.
- **`dnsClusterIP` is pinned** (`172.20.0.53`, mirroring kube-dns at
  `172.20.0.10`). A Service's `clusterIP` is immutable, so a release that once
  allocated it dynamically needs the Service deleted before the pinning upgrade.
- **The 0.5.0 deployment's resolver runs only because of a manual `kubectl`
  patch.** It is reverted by any helm upgrade until the #128 fix ships in a
  release.
