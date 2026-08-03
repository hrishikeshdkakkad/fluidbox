# Platform — M1.1 managed EKS (deployer-role apply)

The EKS platform encoding the proven recipe (2026-07-17 + 2026-07-22
acceptances) with the deltas M1 requires:

| Recipe element | Here |
|---|---|
| VPC CNI NetworkPolicy agent ON, **standard** mode (never strict) | `eks.tf` vpc-cni addon `configuration_values` |
| Avoid us-east-1a | `azs` default `[us-east-1b, us-east-1c]`, node subnets pinned to 1b |
| gp3 default StorageClass (WaitForFirstConsumer, encrypted) | `k8s.tf` (+ gp2 demoted) |
| arm64 / t4g (GHCR images are multi-arch) | both node groups `AL2023_ARM_64_STANDARD` |
| LiteLLM 2Gi headroom | app stack values (this stack just sizes the node) |
| t4g.medium on-demand system node | `system` node group 1/1/2 |
| Sandbox scale-from-zero | `sandbox` node group 0/0/4, tainted, CA discovery tags |
| **Delta:** K8s 1.35, not the proven 1.33 | 1.33 entered EXTENDED support 2026-07-28 (6× billing); `upgrade_policy=STANDARD` refuses silent extended billing forever |
| **Delta:** no NAT, public-subnet nodes | PLAN rev 3 edge/network decision; keeps the ~$131 floor honest |

Also here: the ALB frontend SG (CloudFront origin-facing prefix list only),
KMS KEK + Pod Identity for the server / EBS CSI / ALB controller /
cluster-autoscaler, the two controllers (helm, pinned), control-plane logs with
retention (log group precreated so it is never retain-forever), and the
replay-runner ECR repo with a keep-5 lifecycle.

## Apply

```bash
cd deploy/cloud/terraform/platform
cp terraform.auto.tfvars.example terraform.auto.tfvars   # set operator_cidrs
AWS_PROFILE=fluidbox-operator terraform init
AWS_PROFILE=fluidbox-operator terraform plan             # per-action user approval required
AWS_PROFILE=fluidbox-operator terraform apply
```

The provider assumes `fluidbox-cloud-deployer` itself — a root-credential
apply fails by construction. Expect ~15–25 min (EKS control plane dominates;
the 2026-07-22 run saw 50 min of AWS-side variance once).

After apply: `terraform output kubeconfig_hint` prints the kubeconfig command.

## Order notes

- coredns / ebs-csi / metrics-server addons intentionally depend on the system
  node group (they cannot reach ACTIVE with zero nodes).
- The sandbox node group sits at 0 until the app stack's first run schedules a
  sandbox pod with the matching toleration; `ignore_changes` on desired_size
  leaves runtime scaling to the autoscaler.
- Destroy ORDER MATTERS: destroy the app stack first (the ALB controller must
  delete the ALB the Ingress created before the VPC can go) —
  `scripts/cloud/teardown.sh` encodes it plus the two known EKS leak sweeps.
