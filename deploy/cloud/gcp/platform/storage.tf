# ── Workspace archive store ──────────────────────────────────────────────────
#
# The chart's archiveStore "s3" backend speaks the S3 REST API, and GCS exposes
# one: the XML API at storage.googleapis.com, authenticated with HMAC keys and
# SigV4. That combination is what unlocks server replicas > 1, and therefore:
#
#   * a RollingUpdate strategy instead of Recreate - deploys stop being a
#     visible outage;
#   * PodDisruptionBudgets that mean something;
#   * a working HorizontalPodAutoscaler.
#
# The node-local alternative is one ReadWriteOnce PVC, which structurally pins
# the control plane to a single replica.
#
# THE COST, stated plainly: an HMAC key is a long-lived static credential. The
# chart is explicit that this backend does not support workload identity or STS
# ("IRSA, instance roles and STS auto-refresh are NOT supported"), because the
# point of the backend is that MinIO and R2 work identically. So this trades a
# credential-free PVC for a static key in Secret Manager. The key belongs to a
# service account whose ONLY permission is objectAdmin on this one bucket.

resource "google_storage_bucket" "archives" {
  name     = "${var.project_id}-archives"
  project  = var.project_id
  location = var.region
  labels   = var.labels

  uniform_bucket_level_access = true
  public_access_prevention    = "enforced"

  # Workspace archives are a CACHE for the sandbox init container, not a record
  # of anything. The ledger is the audit trail. Ageing them out keeps the
  # storage line near zero and shrinks the window in which a leaked HMAC key
  # could read anything interesting.
  lifecycle_rule {
    condition {
      age = 14
    }
    action {
      type = "Delete"
    }
  }

  # Abandoned multipart uploads otherwise accumulate invisibly and are billed.
  lifecycle_rule {
    condition {
      age                        = 1
      days_since_noncurrent_time = 1
    }
    action {
      type = "AbortIncompleteMultipartUpload"
    }
  }

  versioning {
    enabled = false
  }
}

resource "google_service_account" "archives" {
  project      = var.project_id
  account_id   = "fbx-archives"
  display_name = "Fluidbox workspace archives (S3/XML)"
  description  = "Owns the HMAC key the control plane uses against the GCS XML API. Scoped to one bucket."
}

resource "google_storage_bucket_iam_member" "archives" {
  bucket = google_storage_bucket.archives.name
  role   = "roles/storage.objectAdmin"
  member = google_service_account.archives.member
}

# The HMAC key IS the credential. It lands in Secret Manager (secrets.tf) and
# nowhere else.
resource "google_storage_hmac_key" "archives" {
  project               = var.project_id
  service_account_email = google_service_account.archives.email

  depends_on = [google_storage_bucket_iam_member.archives]
}
