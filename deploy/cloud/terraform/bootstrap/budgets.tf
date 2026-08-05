# Two budgets, per PLAN rev 3 §P0: a tag-filtered fluidbox budget (what THIS
# project spends) and an account-wide budget kept as the second circuit
# breaker (this is a shared account — the breaker also covers everything else).
#
# Both notify the operator email directly AND the fluidbox-cloud-alerts SNS
# topic (which the root-activity rule also publishes to).

resource "aws_sns_topic" "alerts" {
  name = "fluidbox-cloud-alerts"
}

resource "aws_sns_topic_policy" "alerts" {
  arn = aws_sns_topic.alerts.arn
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AllowBudgets"
        Effect    = "Allow"
        Principal = { Service = "budgets.amazonaws.com" }
        Action    = "SNS:Publish"
        Resource  = aws_sns_topic.alerts.arn
        Condition = { StringEquals = { "aws:SourceAccount" = local.account_id } }
      },
      {
        Sid       = "AllowEventBridge"
        Effect    = "Allow"
        Principal = { Service = "events.amazonaws.com" }
        Action    = "SNS:Publish"
        Resource  = aws_sns_topic.alerts.arn
        Condition = { StringEquals = { "aws:SourceAccount" = local.account_id } }
      },
    ]
  })
}

# Emails require the recipient to click the confirmation link once.
resource "aws_sns_topic_subscription" "alerts_email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.operator_email
}

locals {
  budget_thresholds = [
    { threshold = 50, type = "ACTUAL" },
    { threshold = 80, type = "ACTUAL" },
    { threshold = 100, type = "ACTUAL" },
    { threshold = 100, type = "FORECASTED" },
  ]
}

# Tag-filtered fluidbox budget. Matches the cost-allocation tag
# project=fluidbox — which only starts matching once the tag is ACTIVATED (see
# aws_ce_cost_allocation_tag below and its variable's 24h caveat).
resource "aws_budgets_budget" "fluidbox" {
  name         = "fluidbox-cloud-monthly"
  budget_type  = "COST"
  limit_amount = tostring(var.fluidbox_budget_limit)
  limit_unit   = "USD"
  time_unit    = "MONTHLY"

  cost_filter {
    name   = "TagKeyValue"
    values = ["user:project$fluidbox"]
  }

  dynamic "notification" {
    for_each = local.budget_thresholds
    content {
      comparison_operator        = "GREATER_THAN"
      threshold                  = notification.value.threshold
      threshold_type             = "PERCENTAGE"
      notification_type          = notification.value.type
      subscriber_email_addresses = [var.operator_email]
      subscriber_sns_topic_arns  = [aws_sns_topic.alerts.arn]
    }
  }

  depends_on = [aws_sns_topic_policy.alerts]
}

# Account-wide second circuit breaker. Unfiltered ON PURPOSE: it is the number
# at which the human investigates the whole account, fluidbox or not.
resource "aws_budgets_budget" "account_breaker" {
  name         = "fluidbox-account-breaker"
  budget_type  = "COST"
  limit_amount = tostring(var.account_budget_limit)
  limit_unit   = "USD"
  time_unit    = "MONTHLY"

  dynamic "notification" {
    for_each = local.budget_thresholds
    content {
      comparison_operator        = "GREATER_THAN"
      threshold                  = notification.value.threshold
      threshold_type             = "PERCENTAGE"
      notification_type          = notification.value.type
      subscriber_email_addresses = [var.operator_email]
      subscriber_sns_topic_arns  = [aws_sns_topic.alerts.arn]
    }
  }

  depends_on = [aws_sns_topic_policy.alerts]
}

# Activate the `project` user tag for cost allocation so the tag-filtered
# budget can see fluidbox usage. AWS refuses to activate a tag it has never
# seen on billed usage (up to 24h lag) — variables.tf documents the retry.
resource "aws_ce_cost_allocation_tag" "project" {
  count   = var.activate_cost_allocation_tag ? 1 : 0
  tag_key = "project"
  status  = "Active"
}
