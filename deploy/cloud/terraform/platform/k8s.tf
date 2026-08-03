# In-cluster platform pieces: storage classes + the two controllers.

# gp3 default StorageClass — parameters mirror scripts/eks-gp3-storageclass.yaml
# byte-for-byte in spirit: WaitForFirstConsumer avoids the cross-AZ bind trap,
# encrypted gp3, expansion allowed. Must be NAMED gp3 (values/eks.yaml pins
# server.archivePvc.storageClass: gp3).
resource "kubernetes_storage_class_v1" "gp3" {
  metadata {
    name        = "gp3"
    annotations = { "storageclass.kubernetes.io/is-default-class" = "true" }
  }
  storage_provisioner    = "ebs.csi.aws.com"
  volume_binding_mode    = "WaitForFirstConsumer"
  allow_volume_expansion = true
  reclaim_policy         = "Delete"
  parameters = {
    type      = "gp3"
    encrypted = "true"
  }

  depends_on = [aws_eks_addon.ebs_csi]
}

# EKS ships a default-annotated gp2 class; two defaults make PVC binding
# ambiguous — demote it.
resource "kubernetes_annotations" "gp2_not_default" {
  api_version = "storage.k8s.io/v1"
  kind        = "StorageClass"
  metadata {
    name = "gp2"
  }
  annotations = {
    "storageclass.kubernetes.io/is-default-class" = "false"
  }
  force = true

  depends_on = [aws_eks_addon.ebs_csi]
}

# AWS Load Balancer Controller — the chart's existing Ingress (app stack) does
# the rest; Terraform never hand-builds an ALB against pod IPs (PLAN rev 3).
resource "helm_release" "alb_controller" {
  name       = "aws-load-balancer-controller"
  repository = "https://aws.github.io/eks-charts"
  chart      = "aws-load-balancer-controller"
  version    = var.alb_controller_chart_version
  namespace  = "kube-system"

  set {
    name  = "clusterName"
    value = aws_eks_cluster.this.name
  }
  set {
    name  = "region"
    value = var.region
  }
  set {
    name  = "vpcId"
    value = aws_vpc.this.id
  }
  set {
    name  = "serviceAccount.create"
    value = "true"
  }
  set {
    name  = "serviceAccount.name"
    value = "aws-load-balancer-controller"
  }
  # One replica: leader election makes the second replica pure standby, and the
  # single t4g.medium system node is the declared beta tier.
  set {
    name  = "replicaCount"
    value = "1"
  }

  depends_on = [
    aws_eks_node_group.system,
    aws_eks_pod_identity_association.alb_controller,
    aws_eks_addon.coredns,
  ]
}

# Cluster Autoscaler — sandbox nodegroup 0↔N. Chart app version matches the
# cluster minor (variables.tf).
resource "helm_release" "cluster_autoscaler" {
  name       = "cluster-autoscaler"
  repository = "https://kubernetes.github.io/autoscaler"
  chart      = "cluster-autoscaler"
  version    = var.cluster_autoscaler_chart_version
  namespace  = "kube-system"

  set {
    name  = "cloudProvider"
    value = "aws"
  }
  set {
    name  = "awsRegion"
    value = var.region
  }
  set {
    name  = "autoDiscovery.clusterName"
    value = aws_eks_cluster.this.name
  }
  set {
    name  = "rbac.serviceAccount.create"
    value = "true"
  }
  set {
    name  = "rbac.serviceAccount.name"
    value = "cluster-autoscaler"
  }
  set {
    name  = "extraArgs.balance-similar-node-groups"
    value = "true"
  }
  # Sandbox nodes must drain to zero: un-ready sandbox pods never block
  # scale-down of a node that only ever hosts terminated runs.
  set {
    name  = "extraArgs.skip-nodes-with-local-storage"
    value = "false"
  }

  depends_on = [
    aws_eks_node_group.system,
    aws_eks_pod_identity_association.cluster_autoscaler,
    aws_eks_addon.coredns,
    aws_autoscaling_group_tag.sandbox_ca,
  ]
}
