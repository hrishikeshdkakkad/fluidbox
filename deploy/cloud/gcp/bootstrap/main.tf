locals {
  state_bucket = coalesce(var.state_bucket_name, "${var.project_id}-tfstate")

  # Every API the three stacks touch. Enabling them here - once, in the stack
  # that runs as Owner - is what lets the CI deployer hold a role set that does
  # NOT include serviceusage.serviceUsageAdmin. Enabling an API is effectively
  # granting a whole product surface, so it stays an Owner-only act.
  services = [
    "cloudresourcemanager.googleapis.com",
    "iam.googleapis.com",
    "iamcredentials.googleapis.com",
    "sts.googleapis.com",
    "serviceusage.googleapis.com",
    "compute.googleapis.com",
    "container.googleapis.com",
    "artifactregistry.googleapis.com",
    "sqladmin.googleapis.com",
    "servicenetworking.googleapis.com",
    "secretmanager.googleapis.com",
    "cloudkms.googleapis.com",
    "logging.googleapis.com",
    "monitoring.googleapis.com",
    "cloudbilling.googleapis.com",
    "billingbudgets.googleapis.com",
    "certificatemanager.googleapis.com",
  ]
}

data "google_project" "this" {
  project_id = var.project_id
}

resource "google_project_service" "enabled" {
  for_each = toset(local.services)

  project = var.project_id
  service = each.value

  # Never turn an API off on `terraform destroy`. Disabling a service can
  # cascade-delete the resources that depend on it, which would make a routine
  # teardown of THIS stack destructive to stacks it does not own.
  disable_on_destroy         = false
  disable_dependent_services = false
}

# ── Remote state ─────────────────────────────────────────────────────────────
#
# Versioned so a corrupted or truncated state can be rolled back to the
# previous generation; uniform access so object ACLs cannot re-open it
# per-object behind IAM's back; public access prevention belt-and-braces.
# State carries generated secrets (the Cloud SQL password) - it is treated as
# a credential store, which is why it is never on a laptop and never in git.
resource "google_storage_bucket" "tfstate" {
  name     = local.state_bucket
  project  = var.project_id
  location = var.region
  labels   = var.labels

  uniform_bucket_level_access = true
  public_access_prevention    = "enforced"
  force_destroy               = false

  versioning {
    enabled = true
  }

  # Keep 10 generations of history, then age them out. Without this, a busy
  # pipeline accumulates every state version forever.
  lifecycle_rule {
    condition {
      num_newer_versions = 10
    }
    action {
      type = "Delete"
    }
  }

  lifecycle_rule {
    condition {
      age                = 90
      with_state         = "ARCHIVED"
      num_newer_versions = 3
    }
    action {
      type = "Delete"
    }
  }

  depends_on = [google_project_service.enabled]
}
