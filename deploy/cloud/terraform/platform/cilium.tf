# Cilium as the PRIMARY CNI — the substrate for governed sandbox network
# grants (PR #121 machinery + PR #122 enforcer). Gated by var.cni so the
# vpc-cni recipe remains expressible; the two are mutually exclusive by
# construction (the vpc-cni addon gets count = 0 when cilium is selected).
#
# DELIBERATE DEVIATION from docs/hosted/network-grants-eks-acceptance-runbook.md
# (which prescribes overlay/VXLAN on a FRESH cluster and was never executed):
# this deployment runs ENI IPAM + native routing instead, recorded 2026-08-04.
#
#   * Overlay pod IPs are not VPC-routable, which breaks the live ALB's
#     `target-type: ip` — the entire CloudFront → ALB → server chain — and
#     would force a NodePort/instance-target recomposition (the chart's
#     Services are ClusterIP, hardcoded) plus CloudFront origin surgery (the
#     edge stack pins `ignore_changes = [origin]`). ENI mode keeps pod IPs
#     VPC-routable, so ingress, edge, and chart stay byte-identical.
#   * Everything the grants design actually rests on — identity-vs-CIDR
#     selector semantics, cross-object deny precedence, the FQDN proxy — is
#     policy-engine behavior, independent of the datapath's routing mode
#     (spike: docs/reviews/2026-08-01-cilium-substrate-spike.md).
#   * kube-proxy is KEPT (kubeProxyReplacement=false): KPR is only required by
#     the egress-gateway feature, which the chart treats as SNAT/attribution
#     only ("never the security boundary") and which stays disabled until a
#     dedicated gateway nodegroup + EIP is deliberately added.
#
# IAM: cilium-operator runs hostNetwork on the node, so ENI create/attach
# rides the node role's AmazonEKS_CNI_Policy (already attached as `node_cni`)
# via IMDS — no extra principal.
#
# Rollout on a LIVE cluster (the order matters, and terraform cannot express
# the last step): apply (installs Cilium, removes the vpc-cni addon; cni
# exclusive=true deletes 10-aws.conflist so kubelet pivots), then RECYCLE the
# system node — aws-node's warm secondary ENIs stay attached to the old
# instance and t4g.large has only 3 ENI slots, so a fresh instance is the
# clean way to hand Cilium the ENI budget AND restart every pod onto
# Cilium-managed endpoints in one stroke.

resource "helm_release" "cilium" {
  count      = var.cni == "cilium" ? 1 : 0
  name       = "cilium"
  repository = "https://helm.cilium.io"
  chart      = "cilium"
  version    = var.cilium_chart_version
  namespace  = "kube-system"

  values = [
    yamlencode({
      eni = {
        enabled = true
        # Every pod IP must live on the PRIMARY ENI: this VPC has NO NAT (by
        # design — nodes sit in public subnets and only the primary ENI's
        # primary IP carries a public mapping), so egress SNAT'd to a
        # Cilium-created secondary ENI's IP blackholes at the IGW. Observed
        # live 2026-08-04: pods split across two ENIs, everything on the
        # second ENI timing out to EC2/ELB APIs. Prefix delegation gives the
        # primary ENI ~176 addresses on t4g.large — far past kubelet's
        # max-pods — so Cilium never allocates a second ENI at all.
        awsEnablePrefixDelegation = true
      }
      ipam = {
        mode = "eni"
      }
      routingMode = "native"
      # The chart DEFAULTS IPv4 masquerade OFF in ENI mode (nil → false),
      # assuming a NAT gateway will handle the public leg. Without NAT, pod
      # traffic left the node with its pod source IP and died at the IGW —
      # `enable-ipv4-masquerade: "false"` observed in the live cilium-config,
      # every pod internet-dark. Forcing it ON restores the VPC-CNI-equivalent
      # behavior: SNAT to the outgoing ENI's primary IP (public-mapped on the
      # primary ENI, which prefix delegation above makes the only ENI).
      enableIPv4Masquerade = true
      # REQUIRED with ENI IPAM + masquerade — the agent PANICS at boot without
      # it ("Egress masquerading interfaces cannot be empty when IP
      # masquerading is enabled with IPAM mode other than ClusterPool or
      # Kubernetes", observed live 2026-08-04). The docs' example `eth+` is
      # AL2-era naming; AL2023/Nitro names ENIs `ens5`, `ens6`, … — verified
      # on the node — so the selector is `ens+`.
      egressMasqueradeInterfaces = "ens+"
      kubeProxyReplacement       = "false"
      l7Proxy              = true

      # kube-system's own view of the API server; agents resolve it via the
      # in-cluster Service since kube-proxy remains.

      # One schedulable node (system) — the default 2 operator replicas
      # anti-affine and one would sit Pending forever.
      operator = {
        replicas = 1
      }

      hubble = {
        enabled = true
        relay = {
          enabled = true
        }
      }
    }),
  ]

  # The agent DaemonSet needs a node to land on, and the operator needs a
  # schedulable one.
  depends_on = [aws_eks_node_group.system]
}
