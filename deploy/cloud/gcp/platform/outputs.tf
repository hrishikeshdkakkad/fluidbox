output "cluster_name" {
  value = google_container_cluster.fluidbox.name
}

output "cluster_location" {
  description = "Zone, not region - this is a zonal cluster. `gcloud container clusters get-credentials` needs --zone, not --region."
  value       = google_container_cluster.fluidbox.location
}

output "cluster_endpoint" {
  value     = google_container_cluster.fluidbox.endpoint
  sensitive = true
}

output "ingress_ip" {
  description = "Static GCLB address. This is the A record for control_plane_host in Route 53."
  value       = google_compute_global_address.ingress.address
}

output "nat_ip" {
  description = "Stable egress address for everything in the cluster. Give this to upstreams that allowlist by IP."
  value       = google_compute_address.nat.address
}

output "control_plane_host" {
  value = var.control_plane_host
}

output "dashboard_host" {
  value = var.dashboard_host
}

output "sql_instance" {
  value = google_sql_database_instance.fluidbox.name
}

output "sql_private_ip" {
  description = "Reachable only from inside the VPC - there is no public address."
  value       = google_sql_database_instance.fluidbox.private_ip_address
}

output "sql_connection_name" {
  description = "For `gcloud sql connect` and the Cloud SQL proxy."
  value       = google_sql_database_instance.fluidbox.connection_name
}

output "artifact_registry" {
  description = "Docker repository host/path for mirrored images."
  value       = "${var.region}-docker.pkg.dev/${var.project_id}/${google_artifact_registry_repository.fluidbox.repository_id}"
}

output "external_secrets_service_account" {
  value = google_service_account.external_secrets.email
}

output "kms_key_secrets" {
  value = google_kms_crypto_key.secrets.id
}

output "secret_ids" {
  description = "Secret Manager secret ids the app stack materialises into the chart's existingSecret."
  value       = sort(concat(keys(local.generated_secrets), keys(local.external_secrets)))
}

# Deliberately NOT output: database_url, admin_token, credential_key, kek.
# They are in state (unavoidable - Terraform generated them) but an output
# republishes them into every `terraform output` and every CI log that runs
# one. Read them from Secret Manager instead:
#   gcloud secrets versions access latest --secret=fluidbox-admin-token

output "archive_bucket" {
  description = "Workspace-archive bucket for the chart's server.archiveS3.bucket. Empty unless enable_gcs_archive_store is on."
  value       = try(google_storage_bucket.archives[0].name, "")
}

output "archive_endpoint" {
  description = "GCS XML API endpoint. Path-style addressing (the chart defaults to it whenever an endpoint is set)."
  value       = "https://storage.googleapis.com"
}
