#!/usr/bin/env bash
set -euo pipefail

repo="$HOME/readinessops-account-b"
package_root="$(cd "$(dirname "$0")/../.." && pwd)"
expected_account="062788795311"

actual_account="$(aws sts get-caller-identity --query Account --output text --no-cli-pager)"
if [[ "$actual_account" != "$expected_account" ]]; then
  echo "ERROR: Run this in account B ($expected_account). Current account: $actual_account" >&2
  exit 1
fi
if [[ ! -d "$repo/.git" ]]; then
  echo "ERROR: $repo is missing." >&2
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
      commit -m 'Honor AgentCore Policy delete acceptance contract'
fi

python3 scripts/launch_customer_connector.py

python3 - <<'PY'
import boto3

model = boto3.client(
    'bedrock-agentcore-control', region_name='ap-northeast-1').meta.service_model
operation = model.operation_model('DeletePolicy')
status = operation.output_shape.members['status']
if (operation.http.get('method') != 'DELETE'
        or operation.http.get('responseCode') != 202
        or 'DELETING' not in status.enum):
    raise SystemExit('ERROR: The pinned SDK DeletePolicy contract does not match.')
print('ACCOUNT_B_POLICY_DELETE_CONTRACT_FIX_PASS')
PY
