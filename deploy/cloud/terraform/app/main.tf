provider "aws" {
  region = var.region

  assume_role {
    role_arn     = var.deployer_role_arn
    session_name = "fluidbox-app-apply"
  }

  default_tags {
    tags = {
      project          = "fluidbox"
      "fluidbox-cloud" = "m1"
      "managed-by"     = "terraform"
      stack            = "app"
    }
  }
}

data "terraform_remote_state" "platform" {
  backend = "s3"
  config = {
    bucket = "fluidbox-cloud-tfstate-471112572248"
    key    = "platform.tfstate"
    region = var.region
  }
}

locals {
  cluster_name = data.terraform_remote_state.platform.outputs.cluster_name
  alb_sg_id    = data.terraform_remote_state.platform.outputs.alb_frontend_sg_id
  kms_kek_arn  = data.terraform_remote_state.platform.outputs.kms_kek_arn
}

data "aws_eks_cluster" "this" {
  name = local.cluster_name
}

provider "kubernetes" {
  host                   = data.aws_eks_cluster.this.endpoint
  cluster_ca_certificate = base64decode(data.aws_eks_cluster.this.certificate_authority[0].data)
  exec {
    api_version = "client.authentication.k8s.io/v1beta1"
    command     = "aws"
    args = [
      "eks", "get-token",
      "--cluster-name", local.cluster_name,
      "--region", var.region,
      "--role-arn", var.deployer_role_arn,
    ]
  }
}

provider "helm" {
  kubernetes {
    host                   = data.aws_eks_cluster.this.endpoint
    cluster_ca_certificate = base64decode(data.aws_eks_cluster.this.certificate_authority[0].data)
    exec {
      api_version = "client.authentication.k8s.io/v1beta1"
      command     = "aws"
      args = [
        "eks", "get-token",
        "--cluster-name", local.cluster_name,
        "--region", var.region,
        "--role-arn", var.deployer_role_arn,
      ]
    }
  }
}

# The namespace is created OUT OF BAND by scripts/cloud/make-secrets.sh — it
# has to be, because the Secrets live in it and they must exist before the
# chart installs. Terraform therefore does not own it: managing it here forced
# a first-run `terraform import`, and the imported object then tripped the
# kubernetes provider with "Unexpected Identity Change" on every subsequent
# read. A constant is simpler and matches who actually creates it.
locals {
  namespace = "fluidbox"
}
