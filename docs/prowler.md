# Running Prowler: baseline and re-scan

[Prowler](https://github.com/prowler-cloud/prowler) is an open-source AWS
security scanner. This guide produces the two scans the before/after report is
built from: one **before** any change, one **after** the Terraform baseline
and the manual root-account steps.

Commands are written for Prowler 5.44.0 (September 2026) and checked against
its CLI options. Check
`prowler --version` and `prowler aws --list-compliance` if you use a newer
release; framework names change as new CIS versions are added.

## 1. Read-only access

Prowler only reads. Give it a dedicated role or user with the two AWS managed
policies Prowler documents:

- `arn:aws:iam::aws:policy/SecurityAudit`
- `arn:aws:iam::aws:policy/job-function/ViewOnlyAccess`

Prowler's repository also ships an extra read-only policy
(`permissions/prowler-additions-policy.json`) for a few checks those two do not
cover. Never scan with the root user or with long-lived admin keys; use AWS
IAM Identity Center or `aws sts assume-role` and a short session.

## 2. Install

AWS CloudShell or any machine with Python 3.10 to 3.13:

```bash
python3 -m venv ~/.venvs/prowler
~/.venvs/prowler/bin/pip install prowler==5.44.0
~/.venvs/prowler/bin/prowler --version
```

Alternative without Python: `docker run --rm -it prowlercloud/prowler:5.44.0 ...`
with your AWS credentials passed as environment variables.

## 3. Baseline scan (before)

```bash
prowler aws \
  --compliance cis_6.0_aws aws_foundational_security_best_practices_aws \
  --output-formats csv html json-ocsf \
  --output-directory prowler-output/before \
  --output-filename before
```

- Scans every enabled region by default. Add `--region eu-west-3 us-east-1`
  to limit it (IAM and other global checks run regardless).
- Takes 10 to 40 minutes depending on how many resources the account has.
- `prowler-output/` is gitignored: reports name real resources and account IDs,
  so they stay out of the repository and are shared with the client directly.

Open `before.html` for a browsable view, and keep `before.csv` for the
comparison.

To focus on what matters first:

```bash
prowler aws --severity critical high --output-formats csv \
  --output-directory prowler-output/before --output-filename before-critical-high
```

## 4. Remediate

1. Root account steps in [root-account.md](root-account.md).
2. `scripts/access-key-audit.sh` and the fixes it lists.
3. `terraform apply` (see [RUNBOOK.md](RUNBOOK.md)).
4. Anything workload-specific from the baseline that the baseline does not
   cover (public buckets, open security groups, unencrypted volumes): fix or
   record as an accepted risk with a reason.

Security Hub and AWS Config need up to 24 hours to evaluate every control
after they are enabled. Wait at least that long before the re-scan.

## 5. Re-scan (after)

Same command, different output names:

```bash
prowler aws \
  --compliance cis_6.0_aws aws_foundational_security_best_practices_aws \
  --output-formats csv html json-ocsf \
  --output-directory prowler-output/after \
  --output-filename after
```

## 6. Compare

```bash
python3 scripts/prowler_compare.py \
  prowler-output/before/before.csv \
  prowler-output/after/after.csv > prowler-output/comparison.md
```

The output has the summary table (pass rate, failed checks by severity), the
fixed findings, anything new, and the critical/high findings that remain.
Paste it into a copy of [report-template.md](report-template.md).

Prowler appends a timestamp to file names in some versions; use the actual
CSV paths under each output directory.

## Accepted risks and muting

Findings that are deliberate (for example a public website bucket) can be
muted with a mutelist so they stop counting as failures:

```bash
prowler aws --mutelist-file mutelist.yaml ...
```

`prowler_compare.py` ignores muted findings. List every muted item with its
reason in the report's "Accepted risks" section, so nothing is hidden.
