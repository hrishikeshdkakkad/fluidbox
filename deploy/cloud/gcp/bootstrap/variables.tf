variable "project_id" {
  description = "The GCP project. Pinned by validation: this repo deploys to exactly one project, and a typo here would silently build a parallel estate somewhere else."
  type        = string
  default     = "fluidbox-506603"

  validation {
    condition     = var.project_id == "fluidbox-506603"
    error_message = "This repository deploys only to fluidbox-506603. Change the default deliberately (and the validation with it) if that ever moves."
  }
}

variable "region" {
  description = "Primary region for regional resources (state bucket, Artifact Registry)."
  type        = string
  default     = "us-central1"
}

variable "github_repository" {
  description = "owner/repo allowed to impersonate the CI deployer through Workload Identity Federation. The attribute condition below pins tokens to THIS repository - without it, any GitHub Actions workflow on GitHub.com could mint a token for this pool."
  type        = string
  default     = "hrishikeshdkakkad/fluidbox"

  validation {
    condition     = can(regex("^[A-Za-z0-9._-]+/[A-Za-z0-9._-]+$", var.github_repository))
    error_message = "github_repository must be in owner/repo form."
  }
}

variable "deploy_branch" {
  description = "The only git ref whose workflow runs may impersonate the deployer. Production deploys come from main and nowhere else; pull-request runs get a plan-only identity (see iam.tf)."
  type        = string
  default     = "main"
}

variable "billing_account" {
  description = "Billing account id (XXXXXX-XXXXXX-XXXXXX) that owns this project, used for the budget. Empty disables the budget resources - useful when the caller lacks billing.budgets permissions, which are granted on the BILLING ACCOUNT and not the project."
  type        = string
  default     = ""
}

variable "budget_amount_usd" {
  description = "Monthly budget threshold in USD. Alerts fire at 50/90/100 percent of this; it never caps spend (GCP budgets are advisory, not enforcing)."
  type        = number
  default     = 300
}

variable "budget_alert_emails" {
  description = "Addresses that receive budget and monitoring alerts."
  type        = list(string)
  default     = []
}

variable "state_bucket_name" {
  description = "Remote-state bucket. Defaults to <project>-tfstate."
  type        = string
  default     = ""
}

variable "labels" {
  description = "Labels stamped on every resource that supports them."
  type        = map(string)
  default = {
    app        = "fluidbox"
    managed-by = "terraform"
    stack      = "bootstrap"
  }
}
