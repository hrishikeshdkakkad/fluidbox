# Fluidbox Cloud M1 — app stack: the UNCHANGED fluidbox chart (OCI, release
# version) + the composed external LiteLLM (DB-backed, for tenant virtual
# keys) in the fluidbox namespace.
#
# NO SECRET VALUES IN STATE: Kubernetes Secrets are created out-of-band by
# scripts/cloud/make-secrets.sh BEFORE this stack applies (the deploy wrapper
# scripts/cloud/deploy-app.sh enforces the order). This stack only references
# them by name.

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
    key          = "app.tfstate"
    region       = "us-east-1"
    encrypt      = true
    use_lockfile = true
  }
}
