# Root account steps (manual)

Terraform cannot sign in as root, so these are done by hand in the console,
signed in as the root user. AWS Config (`root-account-mfa-enabled`,
`iam-root-access-key-check`) and the `root-account-usage` alarm then keep
watching them.

1. **Enable MFA on root.** Security credentials → Multi-factor authentication →
   Assign MFA device. Prefer a hardware security key or passkey; register a
   second device as a backup and store it separately.
2. **Delete root access keys.** Security credentials → Access keys. There should
   be none. If one exists, check CloudTrail for its last use, move whatever used
   it to an IAM role, then delete it.
3. **Strong, unique root password** stored in a password manager or vault that
   more than one trusted person can reach.
4. **Root email** should be a group alias the company controls (for example
   `aws-root@company.com`), not a person's mailbox.
5. **Alternate contacts.** Account → Alternate contacts: set billing, operations
   and security contacts so AWS reaches the right people.
6. **Stop using root.** Create an admin through IAM Identity Center (or, for a
   single account without Identity Center, an IAM user with MFA) and use that
   from now on. Root is only for the
   [tasks that require it](https://docs.aws.amazon.com/IAM/latest/UserGuide/root-user-tasks.html).
7. **Sign out**, then confirm the `root-account-usage` alarm email arrives
   within about 10 minutes. That proves the alert path works.

Check the result with:

```bash
scripts/access-key-audit.sh
```

The `<root_account>` line must show `MFA true` and no active keys.
