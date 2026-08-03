# EKS Pod Identity (per PLAN rev 3: associations, NOT IRSA SA annotations —
# there is no OIDC provider to manage). Four workload identities:
#
#   fluidbox/fluidbox-server            → KMS (envelope sealing KEK)
#   kube-system/ebs-csi-controller-sa   → EBS volumes
#   kube-system/aws-load-balancer-controller → ALB lifecycle
#   kube-system/cluster-autoscaler      → sandbox ASG scale 0↔N
#
# Sandbox pods get NO association: the Pod Identity agent answers only for
# associated service accounts, and the sandbox NetworkPolicy denies the
# link-local agent address anyway (defense in depth).

locals {
  pod_identity_trust = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "pods.eks.amazonaws.com" }
      Action    = ["sts:AssumeRole", "sts:TagSession"]
    }]
  })
}

# ── KMS KEK + the server's identity ─────────────────────────────────────────

resource "aws_kms_key" "kek" {
  description         = "fluidbox-cloud custody KEK (FLUIDBOX_KMS_MODE=aws envelope sealing). LOSING THIS KEY IS UNRECOVERABLE for sealed credentials — see docs/hosted/kms-operations.md."
  enable_key_rotation = true
}

resource "aws_kms_alias" "kek" {
  name          = "alias/fluidbox-cloud-kek"
  target_key_id = aws_kms_key.kek.key_id
}

resource "aws_iam_role" "server" {
  name               = "fluidbox-server"
  path               = "/fluidbox-cloud/"
  assume_role_policy = local.pod_identity_trust
}

resource "aws_iam_role_policy" "server_kms" {
  name = "kek-envelope"
  role = aws_iam_role.server.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid    = "EnvelopeSealing"
      Effect = "Allow"
      Action = [
        "kms:Encrypt",
        "kms:Decrypt",
        "kms:ReEncrypt*",
        "kms:GenerateDataKey",
        "kms:GenerateDataKeyWithoutPlaintext",
        "kms:DescribeKey",
      ]
      Resource = aws_kms_key.kek.arn
    }]
  })
}

resource "aws_eks_pod_identity_association" "server" {
  cluster_name    = aws_eks_cluster.this.name
  namespace       = "fluidbox"
  service_account = "fluidbox-server"
  role_arn        = aws_iam_role.server.arn
}

# ── EBS CSI ─────────────────────────────────────────────────────────────────

resource "aws_iam_role" "ebs_csi" {
  name               = "fluidbox-ebs-csi"
  path               = "/fluidbox-cloud/"
  assume_role_policy = local.pod_identity_trust
}

resource "aws_iam_role_policy_attachment" "ebs_csi" {
  role       = aws_iam_role.ebs_csi.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonEBSCSIDriverPolicy"
}

resource "aws_eks_pod_identity_association" "ebs_csi" {
  cluster_name    = aws_eks_cluster.this.name
  namespace       = "kube-system"
  service_account = "ebs-csi-controller-sa"
  role_arn        = aws_iam_role.ebs_csi.arn
}

# ── AWS Load Balancer Controller ────────────────────────────────────────────
# Policy vendored from the controller's official iam_policy.json
# (files/iam_policy_alb_controller.json, fetched 2026-08-03) so applies never
# depend on GitHub availability and the diff is reviewable.

resource "aws_iam_role" "alb_controller" {
  name               = "fluidbox-alb-controller"
  path               = "/fluidbox-cloud/"
  assume_role_policy = local.pod_identity_trust
}

resource "aws_iam_role_policy" "alb_controller" {
  name   = "alb-controller"
  role   = aws_iam_role.alb_controller.id
  policy = file("${path.module}/files/iam_policy_alb_controller.json")
}

resource "aws_eks_pod_identity_association" "alb_controller" {
  cluster_name    = aws_eks_cluster.this.name
  namespace       = "kube-system"
  service_account = "aws-load-balancer-controller"
  role_arn        = aws_iam_role.alb_controller.arn
}

# ── Cluster Autoscaler ──────────────────────────────────────────────────────

resource "aws_iam_role" "cluster_autoscaler" {
  name               = "fluidbox-cluster-autoscaler"
  path               = "/fluidbox-cloud/"
  assume_role_policy = local.pod_identity_trust
}

resource "aws_iam_role_policy" "cluster_autoscaler" {
  name = "cluster-autoscaler"
  role = aws_iam_role.cluster_autoscaler.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "Describe"
        Effect = "Allow"
        Action = [
          "autoscaling:DescribeAutoScalingGroups",
          "autoscaling:DescribeAutoScalingInstances",
          "autoscaling:DescribeLaunchConfigurations",
          "autoscaling:DescribeScalingActivities",
          "autoscaling:DescribeTags",
          "ec2:DescribeInstanceTypes",
          "ec2:DescribeLaunchTemplateVersions",
          "ec2:DescribeImages",
          "ec2:GetInstanceTypesFromInstanceRequirements",
          "eks:DescribeNodegroup",
        ]
        Resource = "*"
      },
      {
        Sid    = "ScaleTaggedAsgsOnly"
        Effect = "Allow"
        Action = [
          "autoscaling:SetDesiredCapacity",
          "autoscaling:TerminateInstanceInAutoScalingGroup",
        ]
        Resource = "*"
        Condition = {
          StringEquals = {
            "autoscaling:ResourceTag/k8s.io/cluster-autoscaler/${var.cluster_name}" = "owned"
          }
        }
      },
    ]
  })
}

resource "aws_eks_pod_identity_association" "cluster_autoscaler" {
  cluster_name    = aws_eks_cluster.this.name
  namespace       = "kube-system"
  service_account = "cluster-autoscaler"
  role_arn        = aws_iam_role.cluster_autoscaler.arn
}
