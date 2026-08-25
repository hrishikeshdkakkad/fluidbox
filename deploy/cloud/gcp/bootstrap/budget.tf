# ── Spend guardrails ─────────────────────────────────────────────────────────
#
# GCP budgets ALERT, they do not CAP. Nothing here can stop a runaway bill; it
# can only make one visible early. The real cost controls are structural and
# live in the platform stack: a zonal cluster, a fixed-size system pool, and a
# sandbox pool whose minimum is zero.
#
# Budget resources are created on the BILLING ACCOUNT, not the project, so they
# need billing.budgets.* which a project Owner does not automatically hold.
# Leave billing_account empty to skip them and create the budget by hand; the
# README documents that path.

resource "google_monitoring_notification_channel" "email" {
  for_each = toset(var.budget_alert_emails)

  project      = var.project_id
  display_name = "fluidbox alerts - ${each.value}"
  type         = "email"

  labels = {
    email_address = each.value
  }

  depends_on = [google_project_service.enabled]
}

resource "google_billing_budget" "monthly" {
  count = var.billing_account == "" ? 0 : 1

  billing_account = var.billing_account
  display_name    = "fluidbox ${var.project_id} monthly"

  budget_filter {
    projects               = ["projects/${data.google_project.this.number}"]
    calendar_period        = "MONTH"
    credit_types_treatment = "INCLUDE_ALL_CREDITS"
  }

  amount {
    specified_amount {
      currency_code = "USD"
      units         = tostring(var.budget_amount_usd)
    }
  }

  # 50/90/100 of actual, plus a FORECAST rule at 100. The forecast rule is the
  # one that matters: it fires while there is still a month left to react,
  # rather than after the money is already spent.
  dynamic "threshold_rules" {
    for_each = [0.5, 0.9, 1.0]
    content {
      threshold_percent = threshold_rules.value
      spend_basis       = "CURRENT_SPEND"
    }
  }

  threshold_rules {
    threshold_percent = 1.0
    spend_basis       = "FORECASTED_SPEND"
  }

  dynamic "all_updates_rule" {
    for_each = length(var.budget_alert_emails) > 0 ? [1] : []
    content {
      monitoring_notification_channels = [for c in google_monitoring_notification_channel.email : c.id]
      disable_default_iam_recipients   = false
    }
  }

  depends_on = [google_project_service.enabled]
}
