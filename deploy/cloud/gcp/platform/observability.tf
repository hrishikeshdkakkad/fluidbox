# ── Observability ────────────────────────────────────────────────────────────
#
# The bar is "an operator finds out from the platform, not from a user". Four
# things earn an alert here: the public endpoint is down, the database is about
# to run out of something, the control plane is crash-looping, and the control
# plane REFUSED TO BOOT.
#
# That last one deserves its own metric. Fluidbox fails closed on
# misconfiguration by design - an RLS-bypassing pool role under REQUIRE_SSO, a
# KEK that cannot unwrap a stored DEK, a queue knob set without its cap. Those
# are the highest-signal lines the process ever emits, and without a log-based
# metric they are invisible to alerting: the pod simply restarts forever and
# looks like any other CrashLoopBackOff.

resource "google_monitoring_notification_channel" "email" {
  for_each = toset(var.alert_emails)

  project      = var.project_id
  display_name = "fluidbox - ${each.value}"
  type         = "email"

  labels = {
    email_address = each.value
  }
}

locals {
  channels = [for c in google_monitoring_notification_channel.email : c.id]
}

# ── Uptime ───────────────────────────────────────────────────────────────────

resource "google_monitoring_uptime_check_config" "control_plane" {
  project      = var.project_id
  display_name = "fluidbox control plane"
  timeout      = "10s"
  period       = "60s"

  http_check {
    path           = "/v1/health"
    port           = 443
    use_ssl        = true
    validate_ssl   = true
    request_method = "GET"

    accepted_response_status_codes {
      status_class = "STATUS_CLASS_2XX"
    }
  }

  monitored_resource {
    type = "uptime_url"
    labels = {
      project_id = var.project_id
      host       = var.control_plane_host
    }
  }

  # Probe from several regions so one region's network trouble does not page.
  selected_regions = ["USA_OREGON", "USA_IOWA", "EUROPE"]
}

resource "google_monitoring_alert_policy" "uptime" {
  project      = var.project_id
  display_name = "fluidbox: control plane unreachable"
  combiner     = "OR"

  documentation {
    content   = "https://${var.control_plane_host}/v1/health stopped answering 2xx from multiple probe regions. Runbook: docs/hosted/gcp-operations.md#control-plane-unreachable"
    mime_type = "text/markdown"
  }

  conditions {
    display_name = "uptime check failing"
    condition_threshold {
      filter          = "metric.type=\"monitoring.googleapis.com/uptime_check/check_passed\" AND resource.type=\"uptime_url\" AND metric.label.check_id=\"${google_monitoring_uptime_check_config.control_plane.uptime_check_id}\""
      comparison      = "COMPARISON_LT"
      threshold_value = 1
      duration        = "300s"

      aggregations {
        alignment_period     = "300s"
        per_series_aligner   = "ALIGN_FRACTION_TRUE"
        cross_series_reducer = "REDUCE_MEAN"
        group_by_fields      = ["resource.label.host"]
      }

      trigger {
        count = 1
      }
    }
  }

  notification_channels = local.channels
}

# ── Boot refusals ────────────────────────────────────────────────────────────

resource "google_logging_metric" "boot_refusal" {
  project = var.project_id
  name    = "fluidbox/boot_refusal"

  description = "Counts control-plane fail-closed boot refusals. Fluidbox refuses to serve on a misconfiguration rather than degrading silently; without this metric those refusals look like an ordinary crash loop."

  filter = <<-EOT
    resource.type="k8s_container"
    resource.labels.cluster_name="${google_container_cluster.fluidbox.name}"
    resource.labels.container_name="server"
    (textPayload:"REFUSING TO BOOT" OR jsonPayload.message:"REFUSING TO BOOT")
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
    unit        = "1"
  }
}

resource "google_monitoring_alert_policy" "boot_refusal" {
  project      = var.project_id
  display_name = "fluidbox: control plane REFUSED TO BOOT"
  combiner     = "OR"

  documentation {
    content   = "The server hit a fail-closed boot gate (RLS posture, KEK identity, sealing retirement, queue configuration). Read the pod log - the refusal line names the exact cause. Runbook: docs/hosted/gcp-operations.md#refusing-to-boot"
    mime_type = "text/markdown"
  }

  conditions {
    display_name = "any boot refusal"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.boot_refusal.name}\" AND resource.type=\"k8s_container\""
      comparison      = "COMPARISON_GT"
      threshold_value = 0
      duration        = "0s"

      aggregations {
        alignment_period   = "60s"
        per_series_aligner = "ALIGN_DELTA"
      }
    }
  }

  notification_channels = local.channels
}

# ── Database ─────────────────────────────────────────────────────────────────

resource "google_monitoring_alert_policy" "sql_disk" {
  project      = var.project_id
  display_name = "fluidbox: Cloud SQL disk above 85 percent"
  combiner     = "OR"

  documentation {
    content   = "disk_autoresize is on, so this is a warning that growth is faster than expected rather than an imminent outage. Runbook: docs/hosted/gcp-operations.md#database"
    mime_type = "text/markdown"
  }

  conditions {
    display_name = "disk utilization > 85%"
    condition_threshold {
      filter          = "metric.type=\"cloudsql.googleapis.com/database/disk/utilization\" AND resource.type=\"cloudsql_database\""
      comparison      = "COMPARISON_GT"
      threshold_value = 0.85
      duration        = "600s"

      aggregations {
        alignment_period   = "300s"
        per_series_aligner = "ALIGN_MEAN"
      }
    }
  }

  notification_channels = local.channels
}

resource "google_monitoring_alert_policy" "sql_connections" {
  project      = var.project_id
  display_name = "fluidbox: Cloud SQL connections near max"
  combiner     = "OR"

  documentation {
    content   = "The app holds `replicas x (FLUIDBOX_DB_MAX_CONNECTIONS + 2)`. Hitting the ceiling shows up as acquire timeouts, not as a database error, so alert before it happens. Either lower the pool or raise sql_max_connections (which needs a restart). Runbook: docs/hosted/gcp-operations.md#database"
    mime_type = "text/markdown"
  }

  conditions {
    display_name = "connections > 80% of max"
    condition_threshold {
      filter          = "metric.type=\"cloudsql.googleapis.com/database/postgresql/num_backends\" AND resource.type=\"cloudsql_database\""
      comparison      = "COMPARISON_GT"
      threshold_value = var.sql_max_connections * 0.8
      duration        = "300s"

      aggregations {
        alignment_period   = "300s"
        per_series_aligner = "ALIGN_MEAN"
      }
    }
  }

  notification_channels = local.channels
}

# ── Workload health ──────────────────────────────────────────────────────────

resource "google_monitoring_alert_policy" "pod_restarts" {
  project      = var.project_id
  display_name = "fluidbox: container restarting repeatedly"
  combiner     = "OR"

  documentation {
    content   = "More than 3 restarts in 15 minutes. If the boot-refusal alert also fired, that one names the cause. Runbook: docs/hosted/gcp-operations.md#crashloop"
    mime_type = "text/markdown"
  }

  conditions {
    display_name = "restart count climbing"
    condition_threshold {
      filter          = "metric.type=\"kubernetes.io/container/restart_count\" AND resource.type=\"k8s_container\" AND resource.label.cluster_name=\"${google_container_cluster.fluidbox.name}\""
      comparison      = "COMPARISON_GT"
      threshold_value = 3
      duration        = "0s"

      aggregations {
        alignment_period     = "900s"
        per_series_aligner   = "ALIGN_DELTA"
        cross_series_reducer = "REDUCE_SUM"
        group_by_fields      = ["resource.label.container_name"]
      }
    }
  }

  notification_channels = local.channels
}
