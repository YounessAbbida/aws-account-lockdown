# IAM clean-up: before/after report

> **TEMPLATE. This is not a real report and contains no results.**
> Every `<placeholder>` is filled in from a real engagement. Copy this file
> outside the repository for each client; filled-in reports name real users
> and are never committed.

| | |
|---|---|
| Client | `<client name>` |
| AWS account | `<account alias>` (account ID shared privately, not in this document) |
| Before | `<date>`: credential report + IAM Access Analyzer unused-access findings |
| After | `<date>`: same sources, after clean-up |
| Prepared by | `<name>` |

## 1. Summary

`<Two or three sentences: how many identities had access they did not need,
what was removed, and what still needs a decision from the client.>`

| | Before | After |
|---|---|---|
| IAM users | `<n>` | `<n>` |
| Human users without MFA | `<n>` | `<n>` |
| Root user MFA | `<on/off>` | `<on/off>` |
| Root access keys | `<n>` | `<n>` |
| Active access keys | `<n>` | `<n>` |
| Keys older than 90 days | `<n>` | `<n>` |
| Keys or passwords unused for 45+ days | `<n>` | `<n>` |
| Unused roles (Access Analyzer) | `<n>` | `<n>` |
| Unused permissions findings (Access Analyzer) | `<n>` | `<n>` |
| Resources shared outside the account (Access Analyzer) | `<n>` | `<n>` |

## 2. How the numbers were collected

- `scripts/access-key-audit.sh` (IAM credential report): users, MFA, key age
  and last use. Save its output before and after.
- IAM Access Analyzer, unused-access analyzer (`terraform/iam.tf`): unused
  roles, users, keys and permissions over `<n>` days.
- IAM Access Analyzer, external-access analyzer: resources shared outside the
  account.

## 3. Changes made

| Identity | Finding | Action | Approved by |
|---|---|---|---|
| `<user or role>` | `<for example: key 400 days old, last used 200 days ago>` | `<deleted / rotated / moved to role / permissions reduced>` | `<name>` |

## 4. MFA enforcement

- Group `<project>-mfa-required` created with the MFA enforcement policy.
- Human users added: `<n>` of `<n>`.
- Exceptions: `<user, reason>`.

## 5. Remaining items

| Identity | Finding | Decision | Owner | Due |
|---|---|---|---|---|
| `<identity>` | `<finding>` | `<fix planned / accepted risk>` | `<who>` | `<date>` |

## 6. Recommended next steps

- `<for example: replace remaining IAM users with IAM Identity Center>`
- `<for example: move CI keys to OIDC roles>`
- `<for example: review Access Analyzer findings monthly>`
