output "cloudtrail_arn" {
  description = "Multi-region trail."
  value       = aws_cloudtrail.this.arn
}

output "log_bucket" {
  description = "Bucket holding CloudTrail (cloudtrail/) and Config (config/) logs."
  value       = aws_s3_bucket.logs.bucket
}

output "kms_key_arn" {
  description = "Customer managed key for security logs and alerts."
  value       = aws_kms_key.security.arn
}

output "alerts_topic_arn" {
  description = "SNS topic for security alerts. Confirm the email subscription."
  value       = aws_sns_topic.alerts.arn
}

output "guardduty_detector_id" {
  description = "GuardDuty detector in the home region."
  value       = aws_guardduty_detector.this.id
}

output "mfa_required_group" {
  description = "Add human IAM users to this group to enforce MFA."
  value       = aws_iam_group.mfa_required.name
}
