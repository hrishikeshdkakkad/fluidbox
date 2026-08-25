output "project_id" {
  description = "The project every stack targets."
  value       = var.project_id
}

output "project_number" {
  description = "Numeric project id - needed to build principalSet:// members by hand."
  value       = data.google_project.this.number
}

output "state_bucket" {
  description = "Remote-state bucket. Later stacks point their gcs backend here with -backend-config."
  value       = google_storage_bucket.tfstate.name
}

output "workload_identity_provider" {
  description = "Full provider resource name for google-github-actions/auth. Set as the repo variable GCP_WORKLOAD_IDENTITY_PROVIDER."
  value       = google_iam_workload_identity_pool_provider.github.name
}

output "deployer_service_account" {
  description = "Write identity for main-branch deploys. Set as the repo variable GCP_DEPLOYER_SA."
  value       = google_service_account.deployer.email
}

output "planner_service_account" {
  description = "Read-only identity for pull-request plans. Set as the repo variable GCP_PLANNER_SA."
  value       = google_service_account.planner.email
}

output "github_actions_variables" {
  description = "Copy-paste block for `gh variable set`. No secrets here - WIF means there is no key to store."
  value = join("\n", [
    "GCP_PROJECT_ID=${var.project_id}",
    "GCP_WORKLOAD_IDENTITY_PROVIDER=${google_iam_workload_identity_pool_provider.github.name}",
    "GCP_DEPLOYER_SA=${google_service_account.deployer.email}",
    "GCP_PLANNER_SA=${google_service_account.planner.email}",
    "GCP_TF_STATE_BUCKET=${google_storage_bucket.tfstate.name}",
  ])
}
