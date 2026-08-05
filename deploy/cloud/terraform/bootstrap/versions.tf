# Fluidbox Cloud M1 — bootstrap (guardrails) stack.
# Applied ONCE with the account root credentials, then never again: it creates
# the scoped deployer role every other stack assumes, and the ceremony in
# README.md ends with the root access key retired.

terraform {
  # >= 1.10 for S3-native state locking (use_lockfile) — no DynamoDB table.
  required_version = ">= 1.10"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
  }
}
