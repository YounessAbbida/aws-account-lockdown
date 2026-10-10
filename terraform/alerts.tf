# Security alerts by email: CloudWatch metric filters on the CloudTrail log
# group (CIS monitoring controls) plus high-severity GuardDuty findings.
resource "aws_sns_topic" "alerts" {
  name              = "${var.project_name}-security-alerts"
  kms_master_key_id = aws_kms_key.security.id
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

data "aws_iam_policy_document" "alerts_topic" {
  statement {
    sid       = "AlarmAndEventPublish"
    actions   = ["sns:Publish"]
    resources = [aws_sns_topic.alerts.arn]

    principals {
      type        = "Service"
      identifiers = ["cloudwatch.amazonaws.com", "events.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [local.account_id]
    }
  }
}

resource "aws_sns_topic_policy" "alerts" {
  arn    = aws_sns_topic.alerts.arn
  policy = data.aws_iam_policy_document.alerts_topic.json
}

locals {
  metric_namespace = "${var.project_name}/CloudTrail"

  # Patterns from the CIS AWS Foundations Benchmark monitoring section.
  trail_alarms = {
    "root-account-usage" = {
      description = "The root user was used"
      pattern     = "{ $.userIdentity.type = \"Root\" && $.userIdentity.invokedBy NOT EXISTS && $.eventType != \"AwsServiceEvent\" }"
    }
    "console-login-without-mfa" = {
      description = "An IAM user signed in to the console without MFA"
      pattern     = "{ ($.eventName = \"ConsoleLogin\") && ($.additionalEventData.MFAUsed != \"Yes\") && ($.userIdentity.type = \"IAMUser\") && ($.responseElements.ConsoleLogin = \"Success\") }"
    }
    "access-key-created" = {
      description = "A new IAM access key was created"
      pattern     = "{ ($.eventSource = \"iam.amazonaws.com\") && ($.eventName = \"CreateAccessKey\") }"
    }
    "iam-policy-changes" = {
      description = "An IAM policy was created, changed, attached or detached"
      pattern     = "{ ($.eventSource = \"iam.amazonaws.com\") && (($.eventName = \"DeleteGroupPolicy\") || ($.eventName = \"DeleteRolePolicy\") || ($.eventName = \"DeleteUserPolicy\") || ($.eventName = \"PutGroupPolicy\") || ($.eventName = \"PutRolePolicy\") || ($.eventName = \"PutUserPolicy\") || ($.eventName = \"CreatePolicy\") || ($.eventName = \"DeletePolicy\") || ($.eventName = \"CreatePolicyVersion\") || ($.eventName = \"DeletePolicyVersion\") || ($.eventName = \"AttachRolePolicy\") || ($.eventName = \"DetachRolePolicy\") || ($.eventName = \"AttachUserPolicy\") || ($.eventName = \"DetachUserPolicy\") || ($.eventName = \"AttachGroupPolicy\") || ($.eventName = \"DetachGroupPolicy\")) }"
    }
    "cloudtrail-config-changes" = {
      description = "A CloudTrail trail was created, changed, stopped or deleted"
      pattern     = "{ ($.eventName = \"CreateTrail\") || ($.eventName = \"UpdateTrail\") || ($.eventName = \"DeleteTrail\") || ($.eventName = \"StartLogging\") || ($.eventName = \"StopLogging\") }"
    }
  }
}

resource "aws_cloudwatch_log_metric_filter" "trail" {
  for_each = local.trail_alarms

  name           = "${var.project_name}-${each.key}"
  log_group_name = aws_cloudwatch_log_group.trail.name
  pattern        = each.value.pattern

  metric_transformation {
    name      = each.key
    namespace = local.metric_namespace
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "trail" {
  for_each = local.trail_alarms

  alarm_name          = "${var.project_name}-${each.key}"
  alarm_description   = each.value.description
  namespace           = local.metric_namespace
  metric_name         = each.key
  statistic           = "Sum"
  period              = 300
  evaluation_periods  = 1
  threshold           = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.alerts.arn]

  depends_on = [aws_cloudwatch_log_metric_filter.trail]
}

resource "aws_cloudwatch_event_rule" "guardduty" {
  name        = "${var.project_name}-guardduty-findings"
  description = "GuardDuty findings at or above severity ${var.guardduty_alert_min_severity}"

  event_pattern = jsonencode({
    source      = ["aws.guardduty"]
    detail-type = ["GuardDuty Finding"]
    detail = {
      severity = [{ numeric = [">=", var.guardduty_alert_min_severity] }]
    }
  })
}

resource "aws_cloudwatch_event_target" "guardduty" {
  rule = aws_cloudwatch_event_rule.guardduty.name
  arn  = aws_sns_topic.alerts.arn
}
