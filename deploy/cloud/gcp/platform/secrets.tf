# ── Secret Manager ───────────────────────────────────────────────────────────
#
# Two classes of secret, handled differently on purpose.
#
# GENERATED (below, with values): the database URL, the admin token, the
# sealing keys. Terraform mints these because they have no external source and
# because a human generating them by hand is a step that gets skipped, done
# wrong, or done twice. They land in Terraform state - which is why state lives
# in a private, versioned, uniform-access bucket and never on a laptop or in
# git.
#
# EXTERNAL (bottom, containers only): the Anthropic key, the Auth0 client
# secret. These come from another system. Terraform creates the CONTAINER so
# IAM and CMEK are declared as code, and the VALUE is added out-of-band by
# scripts/cloud/gcp-secrets.sh. A value Terraform never sees is a value
# Terraform state cannot leak.
#
# EVERY secret here is a permanent object. Losing the credential key orphans
# stored integration credentials; losing the KEK is unrecoverable from the
# moment any v2 row exists. prevent_destroy + ignore_changes are what stop a
# routine re-apply from silently rotating either one.

locals {
  # A DIRECT connection string. Not a pooler: sqlx prepared statements and the
  # SSE fanout's LISTEN/NOTIFY both break under transaction pooling.
  database_url = format(
    "postgres://%s:%s@%s:5432/%s?sslmode=require",
    google_sql_user.fluidbox.name,
    random_password.sql.result,
    google_sql_database_instance.fluidbox.private_ip_address,
    google_sql_database.fluidbox.name,
  )

  # LiteLLM's OWN database - same instance, different database and user.
  # LiteLLM applies its prisma schema to whatever DATABASE_URL it is handed, so
  # it must never receive the fluidbox one.
  litellm_database_url = format(
    "postgresql://%s:%s@%s:5432/%s?sslmode=require",
    google_sql_user.litellm.name,
    random_password.litellm_sql.result,
    google_sql_database_instance.fluidbox.private_ip_address,
    google_sql_database.litellm.name,
  )

  generated_secrets = {
    "fluidbox-database-url"   = local.database_url
    "fluidbox-admin-token"    = random_password.admin_token.result
    "fluidbox-credential-key" = random_bytes.credential_key.hex
    "fluidbox-kms-static-kek" = random_bytes.kms_kek.hex
    "litellm-master-key"      = "sk-${random_password.litellm_master_key.result}"
    "litellm-database-url"    = local.litellm_database_url
  }

  # GCS XML API (S3-compatible) credentials for the workspace archive store.
  # Present ONLY when that backend is provisioned - see
  # var.enable_gcs_archive_store for why it is off by default (the org policy
  # constraints/iam.disableServiceAccountKeyCreation forbids the static HMAC key
  # it requires). Merged rather than inlined so the map stays a known-key set.
  archive_secrets = var.enable_gcs_archive_store ? {
    "fluidbox-archive-access-key-id"     = google_storage_hmac_key.archives[0].access_id
    "fluidbox-archive-secret-access-key" = google_storage_hmac_key.archives[0].secret
  } : {}

  all_generated_secrets = merge(local.generated_secrets, local.archive_secrets)

  external_secrets = {
    "anthropic-api-key"   = "Anthropic key for the LiteLLM gateway. The control plane never holds it."
    "auth0-client-secret" = "OIDC client secret for the org IdP. Held by the control plane's own custody, not by the chart."
  }
}

resource "random_password" "admin_token" {
  length  = 48
  special = false
}

resource "random_password" "litellm_master_key" {
  length  = 40
  special = false
}

# 32 bytes -> 64 hex chars, which is exactly what both key readers accept
# (crates/fluidbox-server/src/seal.rs LegacyKey::from_key_string and
# kms.rs StaticKek::from_key_string: "64 hex chars or standard base64").
resource "random_bytes" "credential_key" {
  length = 32
}

resource "random_bytes" "kms_kek" {
  length = 32
}

resource "google_secret_manager_secret" "generated" {
  for_each = local.all_generated_secrets

  project   = var.project_id
  secret_id = each.key
  labels    = var.labels

  replication {
    user_managed {
      replicas {
        location = var.region
        customer_managed_encryption {
          kms_key_name = google_kms_crypto_key.secrets.id
        }
      }
    }
  }

  lifecycle {
    prevent_destroy = true
  }

  depends_on = [google_kms_crypto_key_iam_member.secretmanager]
}

resource "google_secret_manager_secret_version" "generated" {
  for_each = local.all_generated_secrets

  secret      = google_secret_manager_secret.generated[each.key].id
  secret_data = each.value

  lifecycle {
    prevent_destroy = true
    # Re-applying must NEVER mint a new sealing key. Rotation is a deliberate,
    # documented procedure (docs/hosted/kms-operations.md), not a side effect
    # of a plan that happened to see a different random value.
    ignore_changes = [secret_data]
  }
}

resource "google_secret_manager_secret" "external" {
  for_each = local.external_secrets

  project   = var.project_id
  secret_id = each.key
  labels    = var.labels

  annotations = {
    description = each.value
  }

  replication {
    user_managed {
      replicas {
        location = var.region
        customer_managed_encryption {
          kms_key_name = google_kms_crypto_key.secrets.id
        }
      }
    }
  }

  lifecycle {
    prevent_destroy = true
  }

  depends_on = [google_kms_crypto_key_iam_member.secretmanager]
}

# ── Who may read them ────────────────────────────────────────────────────────
#
# Per-secret, never project-wide. External Secrets reads all of them (that is
# its whole job); the control plane's own account is granted nothing here,
# because it receives these values as environment variables from the
# Kubernetes Secret rather than by calling Secret Manager itself.

# for_each over the static LOCAL, not over google_secret_manager_secret.generated.
# A for_each keyed on a resource map is unknown at plan time until those
# resources exist, and Terraform refuses any for_each over an unknown value -
# which breaks `terraform import` for EVERY resource in the stack, not just this
# one. The keys are the secret ids either way, so nothing is lost.
resource "google_secret_manager_secret_iam_member" "external_secrets_generated" {
  for_each = local.all_generated_secrets

  project   = var.project_id
  secret_id = google_secret_manager_secret.generated[each.key].secret_id
  role      = "roles/secretmanager.secretAccessor"
  member    = google_service_account.external_secrets.member
}

resource "google_secret_manager_secret_iam_member" "external_secrets_external" {
  for_each = local.external_secrets

  project   = var.project_id
  secret_id = google_secret_manager_secret.external[each.key].secret_id
  role      = "roles/secretmanager.secretAccessor"
  member    = google_service_account.external_secrets.member
}
