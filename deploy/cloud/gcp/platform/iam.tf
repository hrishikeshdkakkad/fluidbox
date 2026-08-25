data "google_project" "this" {
  project_id = var.project_id
}

# ── Node identity ────────────────────────────────────────────────────────────
#
# GKE defaults nodes to the Compute Engine DEFAULT service account, which holds
# project Editor. Every pod on a node without Workload Identity would inherit
# that. This replaces it with an account that can do four things and nothing
# else.

resource "google_service_account" "node" {
  project      = var.project_id
  account_id   = "fbx-gke-node"
  display_name = "Fluidbox GKE nodes"
  description  = "Node-level identity. Pods use Workload Identity instead; this only covers logging, metrics and image pulls."
}

resource "google_project_iam_member" "node" {
  for_each = toset([
    "roles/logging.logWriter",
    "roles/monitoring.metricWriter",
    "roles/monitoring.viewer",
    "roles/stackdriver.resourceMetadata.writer",
    "roles/artifactregistry.reader",
  ])

  project = var.project_id
  role    = each.value
  member  = google_service_account.node.member
}

# ── Control-plane identity: deliberately NONE ────────────────────────────────
#
# There is no service account for the fluidbox-server pod, and that is the
# secure choice rather than an omission.
#
# The control plane needs no Google API at all: it reaches Cloud SQL over
# private IP with password authentication, and it receives every secret as an
# environment variable from a Kubernetes Secret that External Secrets
# materialises. Nothing it does requires a Google credential.
#
# Because the node pools run workload_metadata_config mode GKE_METADATA, a pod
# whose ServiceAccount carries no Workload Identity binding gets NO cloud
# credential - it cannot even read the legacy metadata endpoint. Binding an
# unused service account here would replace "no credentials" with "some
# credentials", which is strictly worse.
#
# If Cloud SQL IAM database authentication is adopted later, this is where the
# account goes, together with roles/cloudsql.instanceUser and an annotation on
# the chart's server ServiceAccount (server.serviceAccount.annotations).

# ── External Secrets operator identity ───────────────────────────────────────
#
# Materialises Secret Manager values into Kubernetes Secrets so the chart's
# existingSecret contract is satisfied WITHOUT a human pasting credentials into
# kubectl, and without Terraform holding them in a Kubernetes resource.

resource "google_service_account" "external_secrets" {
  project      = var.project_id
  account_id   = "fbx-external-secrets"
  display_name = "Fluidbox External Secrets"
  description  = "Syncs Secret Manager -> Kubernetes Secrets for the chart's existingSecret."
}

resource "google_service_account_iam_member" "external_secrets_workload_identity" {
  service_account_id = google_service_account.external_secrets.name
  role               = "roles/iam.workloadIdentityUser"
  member             = "serviceAccount:${var.project_id}.svc.id.goog[external-secrets/external-secrets]"

  # The identity pool "<project>.svc.id.goog" does not exist until a cluster in
  # this project enables Workload Identity. Without this the binding races the
  # cluster and fails with "Identity Pool does not exist", which reads like a
  # configuration error rather than an ordering one.
  depends_on = [google_container_cluster.fluidbox]
}
