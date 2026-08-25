# ── Cloud SQL for PostgreSQL ─────────────────────────────────────────────────
#
# Private IP ONLY. There is no authorized-network list to get wrong because
# there is no public address at all; reachability comes from the VPC peering.
#
# Why not a pooler: fluidbox needs DIRECT connections. sqlx uses prepared
# statements and the SSE fanout uses LISTEN/NOTIFY, both of which a
# transaction-mode pooler breaks. Cloud SQL private IP is a direct connection,
# which is exactly what the app contract asks for.

resource "random_password" "sql" {
  length = 32
  # Alphanumeric only, deliberately. This password is embedded in a
  # postgres:// URL; a generator that emits '/', '@', '#' or '?' produces a URL
  # that parses wrong in ways that surface as an authentication failure hours
  # later. 32 alphanumeric characters is ~190 bits - the entropy lost is
  # irrelevant, the class of bug avoided is not.
  special = false
}

resource "google_sql_database_instance" "fluidbox" {
  project          = var.project_id
  name             = "fluidbox-pg"
  region           = var.region
  database_version = "POSTGRES_16"

  # Two separate switches, both required. The provider-level flag stops
  # Terraform issuing the delete; the settings-level flag stops the API
  # accepting one from any source.
  deletion_protection = true

  settings {
    tier              = var.sql_tier
    availability_type = var.sql_availability_type
    disk_type         = "PD_SSD"
    disk_size         = var.sql_disk_size_gb
    disk_autoresize   = true
    edition           = "ENTERPRISE"

    deletion_protection_enabled = true

    user_labels = var.labels

    ip_configuration {
      ipv4_enabled                                  = false
      private_network                               = google_compute_network.vpc.id
      enable_private_path_for_google_cloud_services = true
      ssl_mode                                      = "ENCRYPTED_ONLY"
    }

    backup_configuration {
      enabled    = true
      start_time = "07:00" # UTC, inside the maintenance-quiet window
      location   = var.region

      # WAL archiving. Without it, recovery granularity is the nightly backup -
      # i.e. up to 24h of runs, approvals and audit rows lost.
      point_in_time_recovery_enabled = true
      transaction_log_retention_days = 7

      backup_retention_settings {
        retained_backups = var.sql_backup_retention_days
        retention_unit   = "COUNT"
      }
    }

    maintenance_window {
      day          = 7 # Sunday
      hour         = 9 # UTC - after the GKE window opens, so both land together
      update_track = "stable"
    }

    database_flags {
      # See var.sql_max_connections: the tier default leaves no headroom for
      # `replicas x (pool + 2)` plus migrations plus a psql session.
      name  = "max_connections"
      value = tostring(var.sql_max_connections)
    }

    database_flags {
      # Surface slow queries. 1s is high enough not to spam the log with the
      # per-run pollers and low enough to catch a missing index.
      name  = "log_min_duration_statement"
      value = "1000"
    }

    insights_config {
      query_insights_enabled  = true
      record_application_tags = true
      record_client_address   = false # client addresses are pod IPs; no value, some PII risk
    }
  }

  depends_on = [google_service_networking_connection.sql]

  lifecycle {
    ignore_changes = [settings[0].disk_size] # disk_autoresize moves this
  }
}

resource "google_sql_database" "fluidbox" {
  project  = var.project_id
  name     = "fluidbox"
  instance = google_sql_database_instance.fluidbox.name

  # Server-side collation matters for index ordering; pin it rather than
  # inheriting whatever the image default happens to be.
  charset   = "UTF8"
  collation = "en_US.UTF8"
}

resource "google_sql_user" "fluidbox" {
  project  = var.project_id
  name     = "fluidbox"
  instance = google_sql_database_instance.fluidbox.name
  password = random_password.sql.result
}

# ── LiteLLM's own database ───────────────────────────────────────────────────
#
# SEPARATE database, SEPARATE user, same instance.
#
# Separate because LiteLLM applies its own prisma schema to whatever DATABASE_URL
# it is given - pointing it at the fluidbox database would let it create and
# alter tables inside the schema fluidbox's migrations own. Same instance
# because a second Cloud SQL instance would roughly double the database line for
# a workload that stores a few dozen virtual-key rows.
#
# This is not optional in a hosted deployment: FLUIDBOX_REQUIRE_SSO=1 with the
# default shared key mode makes the LLM facade answer 503 on every model call,
# and per-tenant virtual keys are a database-backed LiteLLM feature.

resource "random_password" "litellm_sql" {
  length  = 32
  special = false
}

resource "google_sql_database" "litellm" {
  project  = var.project_id
  name     = "litellm"
  instance = google_sql_database_instance.fluidbox.name

  charset   = "UTF8"
  collation = "en_US.UTF8"
}

resource "google_sql_user" "litellm" {
  project  = var.project_id
  name     = "litellm"
  instance = google_sql_database_instance.fluidbox.name
  password = random_password.litellm_sql.result
}
