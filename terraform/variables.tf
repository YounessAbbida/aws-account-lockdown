variable "aws_region" {
  description = "Home region: CloudTrail, the log bucket, GuardDuty, Security Hub and Config are created here."
  type        = string
  default     = "eu-west-3"
}

variable "project_name" {
  description = "Prefix for resource names."
  type        = string
  default     = "lockdown"

  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{1,24}$", var.project_name))
    error_message = "project_name must be lowercase letters, digits and hyphens, starting with a letter."
  }
}

variable "alert_email" {
  description = "Email subscribed to security alerts (root activity, CloudTrail or IAM changes, high-severity GuardDuty findings). AWS sends a confirmation link."
  type        = string
}

variable "budget_email" {
  description = "Email that receives budget alerts."
  type        = string
}

variable "budget_limit_usd" {
  description = "Monthly budget in USD. Alerts at 50% and 80% actual, and 100% forecasted."
  type        = number
  default     = 50
}

variable "log_retention_days" {
  description = "Days CloudTrail and Config logs are kept in S3 and CloudWatch Logs. CIS recommends at least 365."
  type        = number
  default     = 365

  validation {
    condition     = contains([365, 400, 545, 731, 1096, 1827, 2192, 2557, 2922, 3288, 3653], var.log_retention_days)
    error_message = "log_retention_days must be a CloudWatch Logs retention value of at least 365."
  }
}

variable "max_access_key_age_days" {
  description = "Access keys older than this are flagged by AWS Config (ACCESS_KEYS_ROTATED)."
  type        = number
  default     = 90
}

variable "max_unused_credential_days" {
  description = "Passwords or access keys unused for longer than this are flagged by AWS Config."
  type        = number
  default     = 45
}

variable "guardduty_alert_min_severity" {
  description = "GuardDuty findings at or above this severity are emailed. 7 = High, 4 = Medium."
  type        = number
  default     = 7
}
