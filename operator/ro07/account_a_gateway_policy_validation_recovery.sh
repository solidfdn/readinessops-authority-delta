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
      commit -m 'Recover exact Gateway Policy validation failure'
fi

ad_app_table="$(aws cloudformation describe-stacks \
  --stack-name authority-delta-business \
  --region ap-northeast-1 \
  --query "Stacks[0].Outputs[?OutputKey=='AppTable'].OutputValue | [0]" \
  --output text --no-cli-pager)"

read_state() {
  aws dynamodb get-item --table-name "$ad_app_table" \
    --region ap-northeast-1 --consistent-read \
    --key '{"pk":{"S":"o-8b018b1fb182496ea6749f12c78a65b8"},"sk":{"S":"APPLICATION#application-84ed051249524be2adc7d0d46f0503c5"}}' \
    --projection-expression '#payload' \
    --expression-attribute-names '{"#payload":"data"}' \
    --query 'Item.data.S' --output text --no-cli-pager
}

before="$(read_state)"
before_status="$(python3 -c 'import json,sys; print(json.load(sys.stdin).get("status"))' <<<"$before")"
before_attempt="$(python3 -c 'import json,sys; print(json.load(sys.stdin).get("attempt",0))' <<<"$before")"
before_updated="$(python3 -c 'import json,sys; print(json.load(sys.stdin).get("updated_at"))' <<<"$before")"
if [[ "$before_status" == "VERIFIED" ]]; then
  python3 -m json.tool <<<"$before"
  echo "READY_TO_CONTINUE_RO07_LIVE_ACCEPTANCE"
  exit 0
fi

python3 scripts/launch_customer_wiring.py \
  --connector-report "$connector_report" \
  --recovery-application-id "$application_id"

for step in $(seq 1 9); do
  raw="$(read_state)"
  status="$(python3 -c 'import json,sys; print(json.load(sys.stdin).get("status"))' <<<"$raw")"
  attempt="$(python3 -c 'import json,sys; print(json.load(sys.stdin).get("attempt",0))' <<<"$raw")"
  updated="$(python3 -c 'import json,sys; print(json.load(sys.stdin).get("updated_at"))' <<<"$raw")"
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
  if [[ "$status" == "UNKNOWN" && ( "$attempt" -gt "$before_attempt" || "$updated" != "$before_updated" ) ]]; then
    python3 -m json.tool <<<"$raw"
    echo "NEXT_REMOTE_ROOT_CAUSE_CAPTURED_RETRY_PARKED" >&2
    exit 2
  fi
  echo "Checking recovery: status=$status attempt=$attempt elapsed=$((step * 10)) seconds" >&2
  sleep 10
done

python3 -m json.tool <<<"$raw"
echo "NO_STATE_TRANSITION_WITHIN_90_SECONDS_RETRY_PARKED" >&2
exit 2
