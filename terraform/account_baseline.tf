# Account-wide settings that cost nothing and close common findings.

# No bucket in the account can be made public, whatever its own settings say.
resource "aws_s3_account_public_access_block" "this" {
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# New EBS volumes and snapshots in the home region are encrypted by default.
resource "aws_ebs_encryption_by_default" "this" {
  enabled = true
}

# CIS password policy for any remaining IAM users with console access.
resource "aws_iam_account_password_policy" "this" {
  #checkov:skip=CKV_AWS_9:No forced expiry, following NIST SP 800-63B; MFA and the unused-credential rule cover stale passwords.
  minimum_password_length        = 14
  require_lowercase_characters   = true
  require_uppercase_characters   = true
  require_numbers                = true
  require_symbols                = true
  password_reuse_prevention      = 24
  allow_users_to_change_password = true
}

# Flags resources (buckets, roles, keys...) shared outside the account.
resource "aws_accessanalyzer_analyzer" "account" {
  analyzer_name = "${var.project_name}-account"
  type          = "ACCOUNT"
}
