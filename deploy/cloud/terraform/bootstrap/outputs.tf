output "deployer_role_arn" {
  description = "Assume this for every platform/app/edge apply."
  value       = aws_iam_role.deployer.arn
}

output "operator_user" {
  description = "The human operator IAM user (create its access key from the root console once, then self-service)."
  value       = aws_iam_user.operator.name
}

output "state_bucket" {
  description = "Terraform state bucket — uncomment backend.tf and `terraform init -migrate-state` right after the first apply."
  value       = aws_s3_bucket.tfstate.bucket
}

output "trail_bucket" {
  value = aws_s3_bucket.trail.bucket
}

output "alerts_topic_arn" {
  description = "Budget + root-activity notifications land here (email subscription must be confirmed by clicking the link SNS sends)."
  value       = aws_sns_topic.alerts.arn
}

output "next_steps" {
  value = <<-EOT
    1. Confirm the SNS email subscription (check ${var.operator_email}).
    2. Uncomment backend.tf, run: terraform init -migrate-state   (then delete local terraform.tfstate*)
    3. Root console -> IAM -> users -> ${var.operator_user_name}: create access key; configure the
       fluidbox-operator + fluidbox-deployer AWS profiles (README.md step 4).
    4. Verify: AWS_PROFILE=fluidbox-deployer aws sts get-caller-identity  (must show the assumed role)
    5. RETIRE THE ROOT ACCESS KEY (root console -> security credentials -> deactivate, verify nothing
       broke, delete). The fluidbox-root-activity alarm now announces any future root use.
    6. Optional hardening once operator MFA is enrolled: set require_deployer_mfa=true and re-apply.
  EOT
}
