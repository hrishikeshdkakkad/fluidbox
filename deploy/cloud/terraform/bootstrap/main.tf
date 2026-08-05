# Bootstrap is the ONE stack applied with root credentials (see README.md for
# the full ceremony, which ends with the root access key retired). Everything
# it creates is a guardrail: state hygiene, the scoped deployer identity, two
# budgets, an owned CloudTrail, and the root-activity alarm.

provider "aws" {
  region = var.region

  default_tags {
    tags = {
      project          = "fluidbox"
      "fluidbox-cloud" = "m1"
      "managed-by"     = "terraform"
      stack            = "bootstrap"
    }
  }
}

data "aws_caller_identity" "current" {}

locals {
  account_id   = data.aws_caller_identity.current.account_id
  state_bucket = var.state_bucket_name != "" ? var.state_bucket_name : "fluidbox-cloud-tfstate-${local.account_id}"
  trail_bucket = var.trail_bucket_name != "" ? var.trail_bucket_name : "fluidbox-cloud-trail-${local.account_id}"
}
