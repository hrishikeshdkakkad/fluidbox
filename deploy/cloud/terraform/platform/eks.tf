# EKS cluster + node groups, raw resources (no wrapper module): every recipe
# element is explicit and auditable — netpol standard mode, AZ pin, arm64,
# gp3, scale-from-zero, restricted endpoint, adopted log group with retention.

# Precreated so EKS adopts a log group that HAS a retention policy (the account
# survey found two old EKS log groups retaining forever — this is the fix).
resource "aws_cloudwatch_log_group" "cluster" {
  name              = "/aws/eks/${var.cluster_name}/cluster"
  retention_in_days = var.eks_log_retention_days
}

# ── IAM ─────────────────────────────────────────────────────────────────────

resource "aws_iam_role" "cluster" {
  name = "fluidbox-eks-cluster"
  path = "/fluidbox-cloud/"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "eks.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy_attachment" "cluster_policy" {
  role       = aws_iam_role.cluster.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"
}

resource "aws_iam_role" "node" {
  name = "fluidbox-eks-node"
  path = "/fluidbox-cloud/"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy_attachment" "node_worker" {
  role       = aws_iam_role.node.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy"
}

resource "aws_iam_role_policy_attachment" "node_cni" {
  role       = aws_iam_role.node.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy"
}

resource "aws_iam_role_policy_attachment" "node_ecr" {
  role       = aws_iam_role.node.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly"
}

# ── Cluster ─────────────────────────────────────────────────────────────────

resource "aws_eks_cluster" "this" {
  name     = var.cluster_name
  version  = var.kubernetes_version
  role_arn = aws_iam_role.cluster.arn

  vpc_config {
    subnet_ids              = aws_subnet.public[*].id
    endpoint_public_access  = true
    public_access_cidrs     = var.operator_cidrs
    endpoint_private_access = true
  }

  access_config {
    authentication_mode                         = "API"
    bootstrap_cluster_creator_admin_permissions = true
  }

  # Refuse to age into EXTENDED support billing ($0.60/hr vs $0.10/hr): at end
  # of standard support AWS auto-upgrades instead of auto-charging 6x.
  upgrade_policy {
    support_type = "STANDARD"
  }

  enabled_cluster_log_types = ["api", "audit", "authenticator", "controllerManager", "scheduler"]

  depends_on = [
    aws_iam_role_policy_attachment.cluster_policy,
    aws_cloudwatch_log_group.cluster,
  ]
}

# ── Addons ──────────────────────────────────────────────────────────────────
# vpc-cni FIRST and node-independent, with the network-policy agent ON in the
# DEFAULT "standard" enforcing mode. Trap from the acceptances, kept verbatim:
# do NOT set NETWORK_POLICY_ENFORCING_MODE=strict — strict starves CoreDNS and
# the EBS CSI controller during startup and cascades into DNS + PVC failures.
# Standard mode enforces asynchronously (~1-20s window); the chart's netpol
# boot gate + per-sandbox netpol-gate init container hold runs closed until
# enforcement is OBSERVED, so the async window is contained by the product.

resource "aws_eks_addon" "vpc_cni" {
  cluster_name = aws_eks_cluster.this.name
  addon_name   = "vpc-cni"

  configuration_values        = jsonencode({ enableNetworkPolicy = "true" })
  resolve_conflicts_on_create = "OVERWRITE"
  resolve_conflicts_on_update = "OVERWRITE"
}

resource "aws_eks_addon" "kube_proxy" {
  cluster_name = aws_eks_cluster.this.name
  addon_name   = "kube-proxy"
  # A fresh cluster ships self-managed coredns/kube-proxy; adopting them with
  # the default NONE conflict policy can fail with ConfigurationConflict.
  # These two pass no configuration_values, so adoption is normally clean —
  # OVERWRITE just removes the failure mode (and the asymmetry with vpc-cni).
  resolve_conflicts_on_create = "OVERWRITE"
  resolve_conflicts_on_update = "OVERWRITE"
}

resource "aws_eks_addon" "pod_identity_agent" {
  cluster_name = aws_eks_cluster.this.name
  addon_name   = "eks-pod-identity-agent"
}

# These three only reach ACTIVE once pods can schedule → after the system NG.
resource "aws_eks_addon" "coredns" {
  cluster_name                = aws_eks_cluster.this.name
  addon_name                  = "coredns"
  resolve_conflicts_on_create = "OVERWRITE"
  resolve_conflicts_on_update = "OVERWRITE"
  depends_on                  = [aws_eks_node_group.system]
}

resource "aws_eks_addon" "ebs_csi" {
  cluster_name = aws_eks_cluster.this.name
  addon_name   = "aws-ebs-csi-driver"
  depends_on = [
    aws_eks_node_group.system,
    aws_eks_pod_identity_association.ebs_csi,
  ]
}

resource "aws_eks_addon" "metrics_server" {
  cluster_name = aws_eks_cluster.this.name
  addon_name   = "metrics-server"
  depends_on   = [aws_eks_node_group.system]
}

# ── Node groups ─────────────────────────────────────────────────────────────

# System: Core + LiteLLM + platform controllers. One t4g.medium on-demand is
# the declared beta availability tier (max 2 covers replace-during-drain).
resource "aws_eks_node_group" "system" {
  cluster_name    = aws_eks_cluster.this.name
  node_group_name = "system"
  node_role_arn   = aws_iam_role.node.arn
  subnet_ids      = local.node_subnet_ids

  instance_types = [var.system_instance_type]
  ami_type       = "AL2023_ARM_64_STANDARD"
  capacity_type  = "ON_DEMAND"
  disk_size      = 40

  scaling_config {
    desired_size = 1
    min_size     = 1
    max_size     = var.system_nodes_max
  }

  update_config {
    max_unavailable = 1
  }

  labels = { "fluidbox.dev/role" = "system" }

  depends_on = [
    aws_iam_role_policy_attachment.node_worker,
    aws_iam_role_policy_attachment.node_cni,
    aws_iam_role_policy_attachment.node_ecr,
    aws_eks_addon.vpc_cni,
  ]
}

# Sandbox: scale-from-zero, tainted so ONLY sandbox pods (which the chart's
# values give the matching toleration + nodeSelector) land here. Cluster
# Autoscaler reads labels/taints straight from the managed-nodegroup API for
# scale-from-zero decisions.
resource "aws_eks_node_group" "sandbox" {
  cluster_name    = aws_eks_cluster.this.name
  node_group_name = "sandbox"
  node_role_arn   = aws_iam_role.node.arn
  subnet_ids      = local.node_subnet_ids

  instance_types = [var.sandbox_instance_type]
  ami_type       = "AL2023_ARM_64_STANDARD"
  capacity_type  = "ON_DEMAND"
  disk_size      = 40

  scaling_config {
    desired_size = 0
    min_size     = 0
    max_size     = var.sandbox_nodes_max
  }

  update_config {
    max_unavailable = 1
  }

  labels = { "fluidbox.dev/role" = "sandbox" }

  taint {
    key    = "fluidbox.dev/sandbox"
    value  = "true"
    effect = "NO_SCHEDULE"
  }

  lifecycle {
    # The autoscaler owns desired_size at runtime.
    ignore_changes = [scaling_config[0].desired_size]
  }

  depends_on = [
    aws_iam_role_policy_attachment.node_worker,
    aws_iam_role_policy_attachment.node_cni,
    aws_iam_role_policy_attachment.node_ecr,
    aws_eks_addon.vpc_cni,
  ]
}

# Cluster Autoscaler ASG discovery tags. Managed node groups usually get these
# from EKS already; applying them explicitly is idempotent and makes the
# dependency visible (the autoscaler helm_release depends on them).
#
# Deliberately TWO resources rather than one for_each/count: the ASG name is
# only known after apply, and Terraform requires for_each keys AND count
# values to be known at PLAN time — deriving either from
# `aws_eks_node_group.sandbox.resources[…]` fails the first apply with
# "Invalid for_each argument". Passing that unknown as a plain ARGUMENT (as
# below) is fine.
locals {
  system_asg_name  = aws_eks_node_group.system.resources[0].autoscaling_groups[0].name
  sandbox_asg_name = aws_eks_node_group.sandbox.resources[0].autoscaling_groups[0].name
}

# Cost-allocation tags that actually reach the EC2 INSTANCES.
#
# `default_tags` and node-group `tags` land on the node group API object —
# EKS does NOT propagate them to the instances or their volumes. Without
# these, the biggest single line item in the cost model (the always-on
# t4g.medium, ~$24.50/mo) carries no `project` tag and falls OUTSIDE the
# tag-filtered fluidbox budget, which would then quietly report a fraction of
# real spend. `propagate_at_launch` is what fixes that.
#
# Residual, recorded in docs/hosted/cloud-cost-model.md: EBS volumes are
# tagged from the launch template's TagSpecifications, which the EKS-managed
# launch template does not carry, so gp3 storage (~$3.20/mo) can still fall
# outside the filter. The account-wide breaker covers everything regardless —
# it is, deliberately, the unfiltered control.
resource "aws_autoscaling_group_tag" "system_project" {
  autoscaling_group_name = local.system_asg_name

  tag {
    key                 = "project"
    value               = "fluidbox"
    propagate_at_launch = true
  }
}

resource "aws_autoscaling_group_tag" "sandbox_project" {
  autoscaling_group_name = local.sandbox_asg_name

  tag {
    key                 = "project"
    value               = "fluidbox"
    propagate_at_launch = true
  }
}

resource "aws_autoscaling_group_tag" "sandbox_ca_enabled" {
  autoscaling_group_name = local.sandbox_asg_name

  tag {
    key                 = "k8s.io/cluster-autoscaler/enabled"
    value               = "true"
    propagate_at_launch = false
  }
}

resource "aws_autoscaling_group_tag" "sandbox_ca_cluster" {
  autoscaling_group_name = local.sandbox_asg_name

  tag {
    key                 = "k8s.io/cluster-autoscaler/${var.cluster_name}"
    value               = "owned"
    propagate_at_launch = false
  }
}
