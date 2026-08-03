variable "region" {
  description = "AWS region for all regional guardrail resources. Both EKS acceptances ran us-east-1; the platform stack pins its subnets off us-east-1a."
  type        = string
  default     = "us-east-1"
}

variable "account_budget_limit" {
  description = <<-EOT
    USER DECISION (M1 brief §12): the account-wide monthly budget in USD — the
    second circuit breaker. Context from the 2026-08-03 account survey: this is
    a SHARED account (forceplatforms) whose OTHER projects already forecast
    ~$179/mo, and the fluidbox idle floor is ~$131/mo — so anything below ~$320
    alerts constantly. 400 is the recommended starting number.
  EOT
  type        = number
  default     = 400
}

variable "fluidbox_budget_limit" {
  description = <<-EOT
    Tag-filtered fluidbox budget (matches cost-allocation tag project=fluidbox)
    in USD/month. 50 is the pre-platform guardrail value from PLAN rev 3 §P0;
    raise to ~175 in the same apply that deploys the M1.1 platform (idle floor
    is ~$131/mo — docs/hosted/cloud-cost-model.md), otherwise the 100% alert
    fires on day one of the cluster. That first alert IS a useful test of the
    notification path — just don't leave the limit there.
  EOT
  type        = number
  default     = 50
}

variable "operator_email" {
  description = "Email for budget + root-activity alerts. SNS emails a confirmation link on first apply — the subscription is dead until it is clicked."
  type        = string
  default     = "hrishidkakkad@gmail.com"
}

variable "operator_user_name" {
  description = "IAM user the human operator uses AFTER root retirement. It can only assume the deployer role and self-manage its own credentials."
  type        = string
  default     = "fluidbox-operator"
}

variable "deployer_role_name" {
  description = "The scoped deployment role every non-bootstrap stack assumes."
  type        = string
  default     = "fluidbox-cloud-deployer"
}

variable "state_bucket_name" {
  description = "Terraform state bucket name. Empty = fluidbox-cloud-tfstate-<account-id> (verified free in the 2026-08-03 survey)."
  type        = string
  default     = ""
}

variable "trail_bucket_name" {
  description = "CloudTrail bucket name. Empty = fluidbox-cloud-trail-<account-id>."
  type        = string
  default     = ""
}

variable "trail_retention_days" {
  description = "Days to keep CloudTrail log objects before expiry (M1.0 'log retention and lifecycle rules')."
  type        = number
  default     = 90
}

variable "require_deployer_mfa" {
  description = <<-EOT
    Require MFA on sts:AssumeRole into the deployer role. Default false so the
    first assume-role works before the operator user has enrolled MFA; flip to
    true (and add mfa_serial to the AWS profile) as soon as MFA is enrolled —
    the README ceremony includes this step. Root retirement does NOT wait on it.
  EOT
  type        = bool
  default     = false
}

variable "activate_cost_allocation_tag" {
  description = <<-EOT
    Activate the `project` user cost-allocation tag so the tag-filtered budget
    can actually see fluidbox spend. AWS only allows activating a tag AFTER it
    has been seen on billed usage (up to 24h of lag) — if the first apply fails
    on aws_ce_cost_allocation_tag, set this false, apply, then flip it true a
    day later. Until activation the fluidbox budget filter matches nothing and
    the ACCOUNT-WIDE budget is the working breaker (by design, it always is).
  EOT
  type        = bool
  default     = true
}

variable "extra_deployer_principal_arns" {
  description = "Additional IAM principal ARNs allowed to assume the deployer role (e.g. a future CI role). Empty for M1 — applies are operator-run by agreement."
  type        = list(string)
  default     = []
}
