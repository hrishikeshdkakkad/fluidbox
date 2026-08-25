# ── Cloud KMS ────────────────────────────────────────────────────────────────
#
# Two keys, two jobs:
#
#   gke-etcd     application-layer encryption of Kubernetes Secret objects in
#                etcd. Google already encrypts etcd at rest; this adds a key WE
#                can rotate and revoke.
#   secrets      CMEK for Secret Manager. This is the root of custody for the
#                fluidbox sealing keys - see secrets.tf for why that matters
#                more here than the name suggests.
#
# Key rings and keys are permanent by design: `terraform destroy` cannot remove
# them, and a destroyed key VERSION makes everything sealed under it
# unrecoverable. Both carry prevent_destroy for that reason.

resource "google_kms_key_ring" "fluidbox" {
  project  = var.project_id
  name     = "fluidbox"
  location = var.region

  lifecycle {
    prevent_destroy = true
  }
}

resource "google_kms_crypto_key" "gke_etcd" {
  name     = "gke-etcd"
  key_ring = google_kms_key_ring.fluidbox.id
  purpose  = "ENCRYPT_DECRYPT"

  rotation_period = "7776000s" # 90 days

  lifecycle {
    prevent_destroy = true
  }
}

resource "google_kms_crypto_key" "secrets" {
  name     = "secrets"
  key_ring = google_kms_key_ring.fluidbox.id
  purpose  = "ENCRYPT_DECRYPT"

  # NOT rotated automatically. Secret Manager re-encrypts on write, not on
  # rotation, so an automatic schedule would leave old versions on old key
  # versions and create exactly the split-key state the fluidbox sealing gates
  # exist to refuse. Rotate deliberately, then rewrite every secret version.
  lifecycle {
    prevent_destroy = true
  }
}

# Service agents that must be able to use the keys. These are Google-managed
# identities; the members are constructed from the project NUMBER.
resource "google_kms_crypto_key_iam_member" "gke_etcd" {
  crypto_key_id = google_kms_crypto_key.gke_etcd.id
  role          = "roles/cloudkms.cryptoKeyEncrypterDecrypter"
  member        = "serviceAccount:service-${data.google_project.this.number}@container-engine-robot.iam.gserviceaccount.com"
}

resource "google_kms_crypto_key_iam_member" "secretmanager" {
  crypto_key_id = google_kms_crypto_key.secrets.id
  role          = "roles/cloudkms.cryptoKeyEncrypterDecrypter"
  member        = "serviceAccount:service-${data.google_project.this.number}@gcp-sa-secretmanager.iam.gserviceaccount.com"

  depends_on = [google_project_service_identity.secretmanager]
}

# Secret Manager's service agent does not exist until something asks for it.
resource "google_project_service_identity" "secretmanager" {
  provider = google-beta
  project  = var.project_id
  service  = "secretmanager.googleapis.com"
}
