# Runbook

Order matters: scan first, so the "before" picture is real.

Requirements: Terraform >= 1.10, AWS CLI v2, admin credentials for the target
account through a short session (IAM Identity Center or `assume-role`), not
long-lived keys.

## 1. Baseline scan

Follow [prowler.md](prowler.md) steps 1 to 3, and save the access-key audit:

```bash
scripts/access-key-audit.sh | tee prowler-output/before/access-key-audit.txt
```

## 2. Root account

Follow [root-account.md](root-account.md). Do this before Terraform so the
`root-account-usage` alarm does not fire on your own setup work.

## 3. Check for existing services

Each of these can exist only once per account and region. If one is already
enabled, import it instead of creating a duplicate:

```bash
aws guardduty list-detectors --region eu-west-3
aws securityhub describe-hub --region eu-west-3
aws configservice describe-configuration-recorders --region eu-west-3
aws configservice describe-delivery-channels --region eu-west-3
```

Import examples (after `terraform init`):

```bash
terraform -chdir=terraform import aws_guardduty_detector.this <detector-id>
terraform -chdir=terraform import aws_securityhub_account.this <account-id>
terraform -chdir=terraform import aws_config_configuration_recorder.this <recorder-name>
terraform -chdir=terraform import aws_config_delivery_channel.this <channel-name>
```

An existing recorder or channel with a name other than `default` must be
renamed in `detection.tf` to match before importing.

## 4. Apply

```bash
cd terraform
cp terraform.tfvars.example terraform.tfvars   # alert_email, budget_email
cp backend.hcl.example backend.hcl             # your state bucket
terraform init -backend-config=backend.hcl
terraform plan
terraform apply
```

Then:

1. Confirm the SNS subscription email ("AWS Notification - Subscription
   Confirmation"); no alert is delivered until you do.
2. Fix what `access-key-audit.sh` reported: delete unused keys, rotate old ones,
   enforce MFA for console users, and move workloads to IAM roles.
3. Wait 24 hours for Config and Security Hub to evaluate every control.

## 5. Re-scan and report

Follow [prowler.md](prowler.md) steps 5 and 6, run the access-key audit again,
and fill in a copy of [report-template.md](report-template.md) outside the
repository.

## 6. Verify the alert path

- Sign in as root and sign out: the `root-account-usage` alarm emails within
  about 10 minutes.
- GuardDuty sample findings (severity 8 included):

  ```bash
  aws guardduty create-sample-findings --region eu-west-3 \
    --detector-id "$(terraform -chdir=terraform output -raw guardduty_detector_id)" \
    --finding-types 'Backdoor:EC2/C&CActivity.B!DNS'
  ```

## 7. Removing the baseline

This is a baseline meant to stay. If it must be removed:

```bash
terraform -chdir=terraform destroy
```

The log bucket is versioned and holds the audit trail; `destroy` fails while it
has objects. Keep the logs for your retention period, and decide with the
account owner before deleting them. The KMS key enters a 30-day pending
deletion window, during which encrypted logs can still be recovered by
cancelling the deletion.
