#!/usr/bin/env bash
set -euo pipefail

repo="$HOME/readinessops-connected-a"
package_root="$(cd "$(dirname "$0")/../.." && pwd)"
expected_account="538522204923"
application_id="application-84ed051249524be2adc7d0d46f0503c5"
connector_report="$HOME/readinessops-connected-transfer/customer-connector-result.json"

actual_account="$(aws sts get-caller-identity --query Account --output text --no-cli-pager)"
if [[ "$actual_account" != "$expected_account" ]]; then
  echo "ERROR: Run this in account A ($expected_account). Current account: $actual_account" >&2
  exit 1
fi
if [[ ! -d "$repo/.git" || ! -f "$connector_report" ]]; then
  echo "ERROR: The account-A repository or connector report is missing." >&2
  exit 1
fi
cd "$repo"
if ! git diff --quiet || ! git diff --cached --quiet; then
  echo "ERROR: The repository has uncommitted changes. Preserve them before running again." >&2
  exit 1
fi
git merge-base --is-ancestor c89c269aaa2a14d17ec8e6e53997a63e0dd4be39 HEAD || {
  echo "ERROR: This is not the expected ReadinessOps history." >&2
  exit 1
}

while IFS= read -r relative; do
  install -D -m 0644 "$package_root/overlay/$relative" "$repo/$relative"
done < "$package_root/overlay-files.txt"
python3 scripts/build_customer_publisher_template.py >/dev/null
git diff --check
git add -- $(cat "$package_root/overlay-files.txt")
if ! git diff --cached --quiet; then
  git -c user.name='ReadinessOps Recovery' \
      -c user.email='readinessops-recovery@solifan.local' \
      commit -m 'Recover the canary result identity contract safely'
fi

ad_app_table="$(aws cloudformation describe-stacks \
  --stack-name authority-delta-business \
  --region ap-northeast-1 \
  --query "Stacks[0].Outputs[?OutputKey=='AppTable'].OutputValue | [0]" \
  --output text --no-cli-pager)"

read_state() {
  aws dynamodb scan --table-name "$ad_app_table" \
    --region ap-northeast-1 --consistent-read \
    --filter-expression 'sk = :application' \
    --expression-attribute-values \
    "{\":application\":{\"S\":\"APPLICATION#$application_id\"}}" \
    --projection-expression '#payload' \
    --expression-attribute-names '{"#payload":"data"}' \
    --query 'Items[0].data.S' --output text --no-cli-pager
}

raw="$(read_state)"
status="$(python3 -c 'import json,sys; print(json.load(sys.stdin).get("status"))' <<<"$raw")"
if [[ "$status" == "VERIFIED" ]]; then
  python3 -m json.tool <<<"$raw"
  echo "READY_TO_CONTINUE_RO07_LIVE_ACCEPTANCE"
  exit 0
fi

python3 scripts/launch_customer_wiring.py \
  --connector-report "$connector_report" \
  --recovery-application-id "$application_id"

for step in $(seq 1 60); do
  raw="$(read_state)"
  status="$(python3 -c 'import json,sys; print(json.load(sys.stdin).get("status"))' <<<"$raw")"
  attempt="$(python3 -c 'import json,sys; print(json.load(sys.stdin).get("attempt"))' <<<"$raw")"
  if [[ "$status" == "VERIFIED" ]]; then
    python3 -m json.tool <<<"$raw"
    echo "READY_TO_CONTINUE_RO07_LIVE_ACCEPTANCE"
    exit 0
  fi
  if [[ "$status" == "RECOVERED_CLOSED" || "$status" == "CANCELLED" ]]; then
    python3 -m json.tool <<<"$raw"
    echo "SAFE_CLOSED_RECOVERY_CONFIRMED"
    exit 0
  fi
  if (( step % 3 == 0 )); then
    echo "Recovering: status=$status attempt=$attempt elapsed=$((step * 10)) seconds" >&2
  fi
  sleep 10
done

python3 -m json.tool <<<"$raw"
echo "NEXT_REMOTE_ROOT_CAUSE_CAPTURED_RETRY_PARKED" >&2
exit 2
