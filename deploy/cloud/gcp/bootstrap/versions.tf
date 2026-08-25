# Bootstrap runs ONCE, by a project Owner, and creates the things every later
# stack depends on: the remote-state bucket, the CI identity, and the spend
# guardrails.
#
# It is the only stack with a LOCAL backend at first apply — it cannot store
# state in a bucket it has not created yet. The documented ceremony (README)
# migrates it into that bucket immediately afterwards, so no state stays on a
# laptop. Nothing here is secret: the bucket name, the service-account emails
# and the Workload Identity pool are all public-safe identifiers.

terraform {
  required_version = ">= 1.9.0"

  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 6.12"
    }
  }

  # Filled in by the README's `terraform init -migrate-state` step. Kept as a
  # partial config so the FIRST apply can run with a local backend.
  backend "gcs" {}
}


# user_project_override + billing_project: some APIs (billingbudgets in
# particular) refuse a user-ADC caller that carries no quota project, with a
# confusing "SERVICE_DISABLED" naming Google's own client project rather than
# ours. These two send X-Goog-User-Project on every request, which is the
# reproducible fix - `gcloud auth application-default set-quota-project` fixes
# only the machine it is run on, and CI would hit the same wall.
provider "google" {
  project               = var.project_id
  region                = var.region
  user_project_override = true
  billing_project       = var.project_id
}
