#!/usr/bin/env bash
# Access-key and MFA audit from the IAM credential report.
#
# Lists the root user and every IAM user with MFA, password and access-key
# status, then flags what needs fixing. Read-only: needs
# iam:GenerateCredentialReport and iam:GetCredentialReport (both in the
# SecurityAudit managed policy). Needs GNU date: run it in AWS CloudShell or
# on Linux.
#
# Usage:
#   scripts/access-key-audit.sh                         # fetch a fresh report
#   scripts/access-key-audit.sh --file report.csv       # use a saved report
#
# Exit codes: 0 no findings, 2 findings, 1 error.
set -euo pipefail

MAX_KEY_AGE_DAYS=${MAX_KEY_AGE_DAYS:-90}
MAX_UNUSED_DAYS=${MAX_UNUSED_DAYS:-45}
NOW=${AUDIT_NOW:-$(date -u +%s)}

usage() {
  sed -n '2,15p' "$0" | sed 's/^# \{0,1\}//'
}

report=""
while (($#)); do
  case $1 in
    --file)
      report=${2:?--file needs a path}
      shift 2
      ;;
    -h | --help)
      usage
      exit 0
      ;;
    *)
      usage >&2
      exit 1
      ;;
  esac
done

if [[ -z $report ]]; then
  report=$(mktemp)
  trap 'rm -f "$report"' EXIT
  for _ in $(seq 1 15); do
    state=$(aws iam generate-credential-report --query State --output text)
    [[ $state == COMPLETE ]] && break
    sleep 2
  done
  aws iam get-credential-report --query Content --output text | base64 --decode >"$report"
fi

# Days since an ISO 8601 timestamp; empty for N/A, no_information, not_supported.
days_since() {
  case $1 in
    N/A | no_information | not_supported | "") echo "" ;;
    *) echo $(((NOW - $(date -u -d "$1" +%s)) / 86400)) ;;
  esac
}

declare -A col
IFS=, read -r -a header <"$report"
for i in "${!header[@]}"; do
  col[${header[$i]//$'\r'/}]=$i
done

findings=()
flag() {
  findings+=("$(printf '%-28s %-20s %s' "$1" "$2" "$3")")
}

key_summary() {
  local active=$1 rotated=$2 used=$3
  if [[ $active != true ]]; then
    echo "-"
  elif [[ -z $used ]]; then
    echo "${rotated}d old, never used"
  else
    echo "${rotated}d old, used ${used}d ago"
  fi
}

printf '%-28s %-5s %-9s %-26s %-26s\n' USER MFA PASSWORD ACCESS_KEY_1 ACCESS_KEY_2
# Field of the current row, by column name.
get() {
  echo "${row[${col[$1]}]}"
}

while IFS=, read -r -a row; do
  row=("${row[@]//$'\r'/}")

  user=$(get user)
  mfa=$(get mfa_active)
  password=$(get password_enabled)
  summaries=()

  for k in 1 2; do
    active=$(get "access_key_${k}_active")
    rotated=$(days_since "$(get "access_key_${k}_last_rotated")")
    used=$(days_since "$(get "access_key_${k}_last_used_date")")
    summaries+=("$(key_summary "$active" "$rotated" "$used")")

    [[ $active == true ]] || continue
    if [[ $user == "<root_account>" ]]; then
      flag ROOT_ACCESS_KEY "$user" "root has active access key $k: delete it"
      continue
    fi
    if ((rotated > MAX_KEY_AGE_DAYS)); then
      flag KEY_NOT_ROTATED "$user" "key $k is ${rotated} days old (max ${MAX_KEY_AGE_DAYS})"
    fi
    if [[ -z $used ]] && ((rotated > MAX_UNUSED_DAYS)); then
      flag KEY_NEVER_USED "$user" "key $k created ${rotated} days ago and never used"
    elif [[ -n $used ]] && ((used > MAX_UNUSED_DAYS)); then
      flag KEY_UNUSED "$user" "key $k last used ${used} days ago (max ${MAX_UNUSED_DAYS})"
    fi
  done

  if [[ $user == "<root_account>" ]]; then
    [[ $mfa == true ]] || flag ROOT_NO_MFA "$user" "enable MFA on the root user"
  elif [[ $password == true ]]; then
    [[ $mfa == true ]] || flag CONSOLE_NO_MFA "$user" "console password without MFA"
    pw_used=$(days_since "$(get password_last_used)")
    created=$(days_since "$(get user_creation_time)")
    if [[ -z $pw_used ]] && ((created > MAX_UNUSED_DAYS)); then
      flag PASSWORD_NEVER_USED "$user" "console password never used, user created ${created} days ago"
    elif [[ -n $pw_used ]] && ((pw_used > MAX_UNUSED_DAYS)); then
      flag PASSWORD_UNUSED "$user" "console password last used ${pw_used} days ago"
    fi
  fi

  printf '%-28s %-5s %-9s %-26s %-26s\n' "$user" "$mfa" "$password" "${summaries[0]}" "${summaries[1]}"
done < <(tail -n +2 "$report")

echo
if ((${#findings[@]} == 0)); then
  echo "No findings."
  exit 0
fi
echo "Findings (${#findings[@]}):"
printf '  %s\n' "${findings[@]}"
exit 2
