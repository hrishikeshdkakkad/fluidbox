# Root-activity alarm: after retirement, ANY root usage is an event worth a
# human's attention. CloudTrail management events reach EventBridge in the
# trail home region at no extra charge; the rule matches every API call or
# console sign-in made by the root identity and publishes to the alerts topic
# (email-subscribed).
#
# This is also the audit trail for the sanctioned break-glass path: bootstrap
# IAM changes after retirement are done from a root CONSOLE session (no key),
# and this rule announces each one.

resource "aws_cloudwatch_event_rule" "root_activity" {
  name        = "fluidbox-root-activity"
  description = "Any AWS API call or console sign-in by the account root user"

  event_pattern = jsonencode({
    detail-type = [
      "AWS API Call via CloudTrail",
      "AWS Console Sign In via CloudTrail",
    ]
    detail = {
      userIdentity = {
        type = ["Root"]
      }
    }
  })
}

resource "aws_cloudwatch_event_target" "root_activity_sns" {
  rule      = aws_cloudwatch_event_rule.root_activity.name
  target_id = "fluidbox-cloud-alerts"
  arn       = aws_sns_topic.alerts.arn

  input_transformer {
    input_paths = {
      event  = "$.detail.eventName"
      source = "$.detail.eventSource"
      time   = "$.detail.eventTime"
      ip     = "$.detail.sourceIPAddress"
    }
    input_template = <<-EOT
      "ROOT ACTIVITY on the fluidbox AWS account: <event> (<source>) at <time> from <ip>. If this was not a sanctioned break-glass session, rotate credentials NOW (docs/hosted/cloud-operator-runbook.md)."
    EOT
  }
}
