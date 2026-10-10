locals {
  trail_log_group = "/aws/cloudtrail/${local.trail_name}"
}

# Multi-region trail with log file validation, encrypted with the security key.
# Management events from every region also go to CloudWatch Logs, where the
# metric filters in alerts.tf watch for root use and risky changes.
resource "aws_cloudtrail" "this" {
  #checkov:skip=CKV_AWS_252:Alerts come from CloudWatch metric filters (alerts.tf), not per-log-file SNS notifications.
  name                          = local.trail_name
  s3_bucket_name                = aws_s3_bucket.logs.id
  s3_key_prefix                 = "cloudtrail"
  is_multi_region_trail         = true
  include_global_service_events = true
  enable_log_file_validation    = true
  kms_key_id                    = aws_kms_key.security.arn

  cloud_watch_logs_group_arn = "${aws_cloudwatch_log_group.trail.arn}:*"
  cloud_watch_logs_role_arn  = aws_iam_role.trail_to_logs.arn

  depends_on = [aws_s3_bucket_policy.logs]
}

resource "aws_cloudwatch_log_group" "trail" {
  name              = local.trail_log_group
  retention_in_days = var.log_retention_days
  kms_key_id        = aws_kms_key.security.arn
}

data "aws_iam_policy_document" "cloudtrail_assume" {
  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "aws:SourceArn"
      values   = [local.trail_arn]
    }
  }
}

resource "aws_iam_role" "trail_to_logs" {
  name               = "${var.project_name}-cloudtrail-to-logs"
  assume_role_policy = data.aws_iam_policy_document.cloudtrail_assume.json
}

data "aws_iam_policy_document" "trail_to_logs" {
  statement {
    actions   = ["logs:CreateLogStream", "logs:PutLogEvents"]
    resources = ["${aws_cloudwatch_log_group.trail.arn}:log-stream:*"]
  }
}

resource "aws_iam_role_policy" "trail_to_logs" {
  name   = "write-trail-log-group"
  role   = aws_iam_role.trail_to_logs.id
  policy = data.aws_iam_policy_document.trail_to_logs.json
}
