# Fluidbox Cloud M1 — platform stack: VPC + EKS + node groups + addons +
# Pod Identity + in-cluster platform services (ALB controller, autoscaler,
# storage classes). Applied with the DEPLOYER role (never root) — the provider
# pins the assumption so a stray root/other-profile apply fails loudly.

terraform {
  required_version = ">= 1.10"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = "~> 2.33"
    }
    helm = {
      source  = "hashicorp/helm"
      version = "~> 2.17"
    }
  }

  backend "s3" {
    bucket       = "fluidbox-cloud-tfstate-471112572248"
    key          = "platform.tfstate"
    region       = "us-east-1"
    encrypt      = true
    use_lockfile = true
  }
}
