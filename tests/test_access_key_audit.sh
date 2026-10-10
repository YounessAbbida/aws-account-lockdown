#!/usr/bin/env bash
# Runs access-key-audit.sh on the synthetic credential report and checks each flag.
set -euo pipefail
cd "$(dirname "$0")/.."

status=0
output=$(AUDIT_NOW=$(date -u -d 2026-10-10T00:00:00Z +%s) \
  scripts/access-key-audit.sh --file tests/fixtures/credential-report.csv) || status=$?

fail() {
  echo "FAIL: $1"
  echo "$output"
  exit 1
}

[[ $status -eq 2 ]] || fail "expected exit code 2, got $status"

expect() {
  grep -Eq "$1" <<<"$output" || fail "missing: $1"
}
expect 'ROOT_NO_MFA +<root_account>'
expect 'ROOT_ACCESS_KEY +<root_account>'
expect 'KEY_NOT_ROTATED +ci-legacy +key 1 is 588 days old'
expect 'KEY_UNUSED +ci-legacy +key 1 last used 131 days ago'
expect 'KEY_NOT_ROTATED +ci-legacy +key 2 is 101 days old'
expect 'KEY_NEVER_USED +ci-legacy +key 2'
expect 'CONSOLE_NO_MFA +bob'
expect 'PASSWORD_NEVER_USED +bob'
expect 'Findings \(8\)'

if grep -Eq '^ +[A-Z_]+ +alice ' <<<"$output"; then
  fail "alice should have no findings"
fi

echo "access-key-audit: all checks passed"
