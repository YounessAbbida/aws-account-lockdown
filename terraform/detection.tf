# GuardDuty: threat detection from CloudTrail, VPC flow logs and DNS logs.
resource "aws_guardduty_detector" "this" {
  #checkov:skip=CKV2_AWS_3:Single-account baseline in the home region; the multi-region and Organizations setup is listed under production additions.
  enable                       = true
  finding_publishing_frequency = "FIFTEEN_MINUTES"
}

resource "aws_guardduty_detector_feature" "s3_data_events" {
  detector_id = aws_guardduty_detector.this.id
  name        = "S3_DATA_EVENTS"
  status      = "ENABLED"
}

# Security Hub: scores the account against AWS Foundational Security Best
# Practices and the CIS AWS Foundations Benchmark. Relies on AWS Config below.
resource "aws_securityhub_account" "this" {
  enable_default_standards  = false
  control_finding_generator = "SECURITY_CONTROL"
  auto_enable_controls      = true
}

resource "aws_securityhub_standards_subscription" "fsbp" {
  standards_arn = "arn:${local.partition}:securityhub:${local.region}::standards/aws-foundational-security-best-practices/v/1.0.0"
  depends_on    = [aws_securityhub_account.this]
}

resource "aws_securityhub_standards_subscription" "cis" {
  standards_arn = "arn:${local.partition}:securityhub:${local.region}::standards/cis-aws-foundations-benchmark/v/3.0.0"
  depends_on    = [aws_securityhub_account.this]
}

# AWS Config: resource inventory and the rules Security Hub controls run on.
data "aws_iam_policy_document" "config_assume" {
  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["config.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [local.account_id]
    }
  }
}

resource "aws_iam_role" "config" {
  name               = "${var.project_name}-config"
  assume_role_policy = data.aws_iam_policy_document.config_assume.json
}

resource "aws_iam_role_policy_attachment" "config" {
  role       = aws_iam_role.config.name
  policy_arn = "arn:${local.partition}:iam::aws:policy/service-role/AWS_ConfigRole"
}

data "aws_iam_policy_document" "config_delivery" {
  statement {
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.logs.arn}/config/AWSLogs/${local.account_id}/Config/*"]

    condition {
      test     = "StringEquals"
      variable = "s3:x-amz-acl"
      values   = ["bucket-owner-full-control"]
    }
  }

  statement {
    actions   = ["s3:GetBucketAcl"]
    resources = [aws_s3_bucket.logs.arn]
  }

  statement {
    actions   = ["kms:GenerateDataKey", "kms:Decrypt"]
    resources = [aws_kms_key.security.arn]
  }
}

resource "aws_iam_role_policy" "config_delivery" {
  name   = "deliver-to-log-bucket"
  role   = aws_iam_role.config.id
  policy = data.aws_iam_policy_document.config_delivery.json
}

resource "aws_config_configuration_recorder" "this" {
  name     = "default"
  role_arn = aws_iam_role.config.arn

  recording_group {
    all_supported                 = true
    include_global_resource_types = true
  }
}

resource "aws_config_delivery_channel" "this" {
  name           = "default"
  s3_bucket_name = aws_s3_bucket.logs.id
  s3_key_prefix  = "config"
  s3_kms_key_arn = aws_kms_key.security.arn

  depends_on = [aws_config_configuration_recorder.this, aws_s3_bucket_policy.logs]
}

resource "aws_config_configuration_recorder_status" "this" {
  name       = aws_config_configuration_recorder.this.name
  is_enabled = true

  depends_on = [aws_config_delivery_channel.this]
}

# Identity checks: root MFA, root access keys, key rotation, unused
# credentials, console users without MFA. scripts/access-key-audit.sh gives
# the same picture on demand, per user and per key.
locals {
  config_rules = {
    "root-account-mfa-enabled" = {
      identifier = "ROOT_ACCOUNT_MFA_ENABLED"
      params     = null
    }
    "iam-root-access-key-check" = {
      identifier = "IAM_ROOT_ACCESS_KEY_CHECK"
      params     = null
    }
    "access-keys-rotated" = {
      identifier = "ACCESS_KEYS_ROTATED"
      params     = { maxAccessKeyAge = tostring(var.max_access_key_age_days) }
    }
    "iam-user-unused-credentials-check" = {
      identifier = "IAM_USER_UNUSED_CREDENTIALS_CHECK"
      params     = { maxCredentialUsageAge = tostring(var.max_unused_credential_days) }
    }
    "mfa-enabled-for-iam-console-access" = {
      identifier = "MFA_ENABLED_FOR_IAM_CONSOLE_ACCESS"
      params     = null
    }
  }
}

resource "aws_config_config_rule" "identity" {
  for_each = local.config_rules

  name             = "${var.project_name}-${each.key}"
  input_parameters = each.value.params == null ? null : jsonencode(each.value.params)

  source {
    owner             = "AWS"
    source_identifier = each.value.identifier
  }

  depends_on = [aws_config_configuration_recorder_status.this]
}
