# AWS account lockdown: before/after report

> **TEMPLATE. This is not a real report and contains no results.**
> Every `<placeholder>` is filled in from a real engagement's Prowler scans
> (see [prowler.md](prowler.md)). Copy this file outside the repository for
> each client; filled-in reports name real resources and are never committed.

| | |
|---|---|
| Client | `<client name>` |
| AWS account | `<account alias>` (account ID shared privately, not in this document) |
| Regions in scope | `<regions>` |
| Baseline scan | `<date>`, Prowler `<version>` |
| Re-scan | `<date>`, Prowler `<version>` |
| Frameworks | CIS AWS Foundations Benchmark `<version>`, AWS Foundational Security Best Practices |
| Prepared by | `<name>` |

## 1. Summary

`<Two or three sentences in plain language: what the main risks were, what was
fixed, and what still needs a decision from the client.>`

Paste the **Summary** table from `scripts/prowler_compare.py` here:

| | Before | After |
|---|---|---|
| Pass rate | `<n>%` | `<n>%` |
| Failed checks | `<n>` | `<n>` |
| Critical | `<n>` | `<n>` |
| High | `<n>` | `<n>` |
| Medium | `<n>` | `<n>` |
| Low | `<n>` | `<n>` |
| Informational | `<n>` | `<n>` |

## 2. What was changed

| Area | Before | After | How |
|---|---|---|---|
| Root user | `<MFA state, access keys>` | `<state>` | Manual, [root-account.md](root-account.md) |
| IAM users and keys | `<findings from access-key-audit.sh>` | `<state>` | `<rotated / deleted / moved to roles>` |
| Audit logging | `<CloudTrail state>` | Multi-region trail, log validation, KMS, 365-day retention | Terraform `cloudtrail.tf` |
| Threat detection | `<GuardDuty state>` | GuardDuty on, high-severity findings emailed | Terraform `detection.tf`, `alerts.tf` |
| Posture scoring | `<Security Hub / Config state>` | Security Hub (FSBP + CIS), AWS Config recording | Terraform `detection.tf` |
| S3 public access | `<state>` | Blocked at account level | Terraform `account_baseline.tf` |
| Cost guardrail | `<state>` | Monthly budget with alerts | Terraform `budget.tf` |
| `<other>` | | | |

## 3. Fixed findings

Paste the **Fixed** table from `prowler_compare.py`.

## 4. Remaining critical and high findings

Paste the **Remaining critical and high** table. For each row, one of:

| Check | Resource | Decision | Owner | Due |
|---|---|---|---|---|
| `<check id>` | `<resource>` | `<fix planned / accepted risk / false positive>` | `<who>` | `<date>` |

## 5. Accepted risks

Findings muted in Prowler, with the reason and who accepted them.

| Check | Resource | Reason | Accepted by | Review date |
|---|---|---|---|---|
| `<check id>` | `<resource>` | `<reason>` | `<name>` | `<date>` |

## 6. New since baseline

Paste the **New since baseline** table. New findings usually mean resources
were created between the scans; explain each one.

## 7. Recommended next steps

- `<for example: move CI from IAM user keys to OIDC roles>`
- `<for example: AWS Organizations with SCPs and a delegated security account>`
- `<for example: re-run this scan quarterly>`

## Appendix: evidence

- Prowler HTML reports: `<where they were shared>`
- `access-key-audit.sh` output before and after: `<where>`
- Security Hub score screenshot after 24 hours: `<where>`
