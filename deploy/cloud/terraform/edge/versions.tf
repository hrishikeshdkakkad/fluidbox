# Fluidbox Cloud M1 — edge stack: CloudFront in front of the chart's
# Ingress-created ALB. Applies AFTER the app stack (the ALB must exist to be
# an origin).

terraform {
  required_version = ">= 1.10"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
  }

  backend "s3" {
    bucket       = "fluidbox-cloud-tfstate-471112572248"
    key          = "edge.tfstate"
    region       = "us-east-1"
    encrypt      = true
    use_lockfile = true
  }
}
