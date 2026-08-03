# EKS acceptance runbook — governed sandbox network access

The Phase 6 gate. **Unit tests and rendered YAML do not count**, and an
unverified CNI or a skipped assertion fails acceptance. This runbook lands with
the plan; the acceptance itself is executed on request and written up at
`docs/reviews/<date>-eks-cilium-network-acceptance.md`.

Follows the shape of the two prior acceptances
([2026-07-17](../reviews/2026-07-17-eks-acceptance.md),
[2026-07-22 Phase F](../reviews/2026-07-22-eks-acceptance-phase-f.md)) and
carries their hard-won recipe forward.

---

## §1 Cluster — Cilium as the PRIMARY CNI

This differs from both prior acceptances, which ran the AWS VPC CNI. Cilium must
be the primary CNI in overlay mode, which means **VPC CNI removed before any
workload pod is scheduled**.

```bash
eksctl create cluster -f scripts/eks-cluster-cilium.yaml   # nodegroups WITHOUT the CNI addon
kubectl -n kube-system delete ds aws-node                  # before scheduling anything
helm install cilium cilium/cilium --version 1.19.6 -n kube-system \
  --set kubeProxyReplacement=true \
  --set k8sServiceHost=<apiserver-endpoint> --set k8sServicePort=443 \
  --set routingMode=tunnel --set tunnelProtocol=vxlan \
  --set bpf.masquerade=true --set egressGateway.enabled=true \
  --set l7Proxy=true --set hubble.enabled=true --set hubble.relay.enabled=true
kubectl -n kube-system rollout restart ds/cilium && kubectl delete pod -A --field-selector spec.nodeName!=""
```

Carry forward from the epic recipe, all still live constraints:

- **Pin the nodegroup off `us-east-1a`** — IPAM init fails there.
- **LiteLLM needs 2Gi**; the chart's 1Gi default OOMKills.
- **Seeded agents pin their creation-time runner image ref**, so a cloud run
  needs a dedicated agent with an explicit `runner_image` or it ErrImagePulls.
- **t4g/arm64 nodes are fine** when images are built on the arm64 Mac.
- A **dedicated egress-gateway nodegroup**, labelled
  `fluidbox.dev/egress-gateway=true`, with an EIP so the egress address is
  stable and attributable.

## §2 What must be proven

Every row is a **live** assertion, with the command and its redacted output in
the report. A row that cannot be executed fails acceptance; it is not deferred.

| # | Claim | How |
|---|---|---|
| 1 | Allowed traffic genuinely works for real toolchains | `curl`, `pip install`, `git clone`, and a raw TCP/TLS client against a non-HTTP service, all under one `approved` grant |
| 2 | A real workload runs end to end | A microservice installs dependencies and opens external connections **while the agent tests, edits, reruns, and returns artifacts** — the whole point of the feature, not a synthetic probe |
| 3 | Every bypass is denied | The full Phase 4 matrix, re-run on EKS: direct-IP, alternate DNS, DoH, IPv6, UDP/QUIC, proxy env vars, in-cluster service discovery, apiserver, kubelet, metadata |
| 4 | Enforcement precedes user code | The in-netns `netpol-gate` init container's own evidence, plus a run whose policy is deliberately withheld failing closed |
| 5 | Failures close | CoreDNS down and gateway node down, each leaving `:8788` alive and the run able to report |
| 6 | Two concurrent runs with different grants cannot reach each other's targets | Both resolve their own name first (so the shared DNS cache is populated), then cross-probe by name AND by raw IP |
| 7 | Secrets never appear in API, logs, or artifacts | grep the run's events, artifacts, and pod logs for the session tokens and any credential material |
| 8 | Zero network objects or credentials survive teardown | Per-run CNP residual check + the AWS-side audit below |

Live agent legs are pinned to `claude-haiku`; the ≥100-run churn uses the no-key
`images/replay-runner`.

## §3 Teardown — and the leaks it must sweep

The two recurring EKS-lifecycle leaks from the Phase F acceptance are **not**
swept by `eks-teardown.sh` and must be handled explicitly:

- **A detached VPC-CNI ENI** (a GC race) holds a subnet → `DELETE_FAILED`.
- **The EKS-created cluster SG** `eks-cluster-sg-<cluster>-*` is created outside
  CloudFormation and holds the VPC.

Sweep both before or with `eksctl delete`. This acceptance adds two more:

- **Release the egress-gateway EIP** — an unreleased Elastic IP bills silently.
- **Per-run CNP residuals**: `kubectl get cnp -A` must show zero
  `fluidbox-*` policies before teardown. A survivor is not cosmetic — Cilium
  allow rules are additive, so a policy outliving its pod could match a
  re-created pod for the same session and silently reopen traffic.

Tagging-API ghosts after deletion are normal (documented in the epic recipe).

## §4 Report skeleton

```
# Live EKS acceptance — governed sandbox network access

- Cloud / region / account
- Cilium version + image digest, routing mode, kube-proxy replacement
- Chart values (networkGrants block, verbatim)
- Images + tag, model pinned
- Date

## 1. Cluster and CNI — with the evidence Cilium is PRIMARY
## 2. Boot posture — the enforcer the server resolved, from its own log
## 3. The eight claims of §2, one section each, commands + redacted output
## 4. Deviations and residuals found
## 5. Teardown — including the four sweeps of §3, with the AWS-side audit
## Verdict
```

State deviations plainly. The prior acceptances' value came from recording what
did **not** work (VPC CNI strict mode starving CoreDNS; LiteLLM OOM; the netpol
probe's fail-open false negative), and this one is held to the same standard.
