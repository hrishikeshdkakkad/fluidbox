provider "aws" {
  region = var.region

  # Pinned assumption: this stack CANNOT be applied as root or as any other
  # identity — the credentials in the environment must be allowed to assume
  # the scoped deployer (i.e. the fluidbox-operator user).
  assume_role {
    role_arn     = var.deployer_role_arn
    session_name = "fluidbox-platform-apply"
  }

  default_tags {
    tags = {
      project          = "fluidbox"
      "fluidbox-cloud" = "m1"
      "managed-by"     = "terraform"
      stack            = "platform"
    }
  }
}

data "aws_caller_identity" "current" {}

locals {
  account_id = data.aws_caller_identity.current.account_id
  # The single-AZ pin for node subnets (recipe: off us-east-1a, one AZ).
  node_subnet_ids = [aws_subnet.public[var.node_az_index].id]
}

# Kubernetes + Helm providers authenticate via the SAME deployer role the AWS
# provider assumes; the cluster's creator-admin access entry makes that role
# cluster-admin. exec re-derives a fresh token per operation.
provider "kubernetes" {
  host                   = aws_eks_cluster.this.endpoint
  cluster_ca_certificate = base64decode(aws_eks_cluster.this.certificate_authority[0].data)
  exec {
    api_version = "client.authentication.k8s.io/v1beta1"
    command     = "aws"
    args = [
      "eks", "get-token",
      "--cluster-name", aws_eks_cluster.this.name,
      "--region", var.region,
      "--role-arn", var.deployer_role_arn,
    ]
  }
}

provider "helm" {
  kubernetes {
    host                   = aws_eks_cluster.this.endpoint
    cluster_ca_certificate = base64decode(aws_eks_cluster.this.certificate_authority[0].data)
    exec {
      api_version = "client.authentication.k8s.io/v1beta1"
      command     = "aws"
      args = [
        "eks", "get-token",
        "--cluster-name", aws_eks_cluster.this.name,
        "--region", var.region,
        "--role-arn", var.deployer_role_arn,
      ]
    }
  }
}
