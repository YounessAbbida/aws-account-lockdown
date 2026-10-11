# IAM clean-up guardrails.
#
# 1. IAM Access Analyzer unused-access findings: roles, users, keys and
#    permissions not used for unused_access_days.
# 2. An MFA enforcement policy, attached to a group: members can manage their
#    own MFA device and nothing else until they sign in with MFA.
#
# The credential report side is scripts/access-key-audit.sh; the before/after
# write-up is docs/iam-report-template.md.

resource "aws_accessanalyzer_analyzer" "unused_access" {
  analyzer_name = "${var.project_name}-unused-access"
  type          = "ACCOUNT_UNUSED_ACCESS"

  configuration {
    unused_access {
      unused_access_age = var.unused_access_days
    }
  }
}

# Based on the AWS documented "allow MFA-authenticated IAM users to manage
# their own credentials" policy.
data "aws_iam_policy_document" "require_mfa" {
  statement {
    sid = "AllowViewAccountInfo"
    actions = [
      "iam:GetAccountPasswordPolicy",
      "iam:ListVirtualMFADevices",
    ]
    resources = ["*"]
  }

  statement {
    sid = "AllowManageOwnPasswordAndMFA"
    actions = [
      "iam:ChangePassword",
      "iam:GetUser",
      "iam:CreateVirtualMFADevice",
      "iam:DeleteVirtualMFADevice",
      "iam:EnableMFADevice",
      "iam:ListMFADevices",
      "iam:ResyncMFADevice",
    ]
    resources = [
      "arn:${local.partition}:iam::${local.account_id}:user/$${aws:username}",
      "arn:${local.partition}:iam::${local.account_id}:mfa/*",
    ]
  }

  statement {
    sid    = "DenyAllExceptMFASetupWithoutMFA"
    effect = "Deny"
    not_actions = [
      "iam:ChangePassword",
      "iam:CreateVirtualMFADevice",
      "iam:EnableMFADevice",
      "iam:GetUser",
      "iam:ListMFADevices",
      "iam:ListVirtualMFADevices",
      "iam:ResyncMFADevice",
      "sts:GetSessionToken",
    ]
    resources = ["*"]

    condition {
      test     = "BoolIfExists"
      variable = "aws:MultiFactorAuthPresent"
      values   = ["false"]
    }
  }
}

resource "aws_iam_policy" "require_mfa" {
  name        = "${var.project_name}-require-mfa"
  description = "Denies everything except MFA self-setup until the user signs in with MFA."
  policy      = data.aws_iam_policy_document.require_mfa.json
}

# Add every human IAM user to this group. Workload identities should be roles,
# not users; the audit script and Access Analyzer find the ones that are not.
resource "aws_iam_group" "mfa_required" {
  name = "${var.project_name}-mfa-required"
}

resource "aws_iam_group_policy_attachment" "require_mfa" {
  group      = aws_iam_group.mfa_required.name
  policy_arn = aws_iam_policy.require_mfa.arn
}
