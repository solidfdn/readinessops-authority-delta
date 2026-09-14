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
for required in scripts/build_customer_publisher_template.py \
                scripts/launch_customer_connector.py \
                src/authority_delta/business/customer_publisher.py; do
  if [[ ! -f "$required" ]]; then
    echo "ERROR: The existing account-B ReadinessOps deployment is missing: $required" >&2
    exit 1
  fi
done

while IFS= read -r relative; do
  install -D -m 0644 "$package_root/overlay/$relative" "$repo/$relative"
done < "$package_root/overlay-files.txt"
python3 scripts/build_customer_publisher_template.py >/dev/null
git diff --check
git add -- $(cat "$package_root/overlay-files.txt")
if ! git diff --cached --quiet; then
  git -c user.name='ReadinessOps Recovery' \
      -c user.email='readinessops-recovery@solifan.local' \
      commit -m 'Honor AgentCore Policy create acceptance contract'
fi

python3 scripts/launch_customer_connector.py

python3 - <<'PY'
import boto3

model = boto3.client(
    'bedrock-agentcore-control', region_name='ap-northeast-1').meta.service_model
operation = model.operation_model('CreatePolicy')
read = model.operation_model('GetPolicy')
listed = model.operation_model('ListPolicies')
status = operation.output_shape.members['status']
if (operation.http.get('method') != 'POST'
        or operation.http.get('responseCode') != 202
        or read.http.get('method') != 'GET'
        or read.http.get('responseCode') != 200
        or listed.http.get('method') != 'GET'
        or listed.http.get('responseCode') != 200
        or not {'policyId', 'name', 'policyEngineId', 'status', 'definition'}
            <= set(operation.output_shape.required_members)
        or 'enforcementMode' not in operation.output_shape.members
        or not {'CREATING', 'ACTIVE'} <= set(status.enum)):
    raise SystemExit('ERROR: The pinned SDK CreatePolicy contract does not match.')
print('ACCOUNT_B_POLICY_CREATE_CONTRACT_FIX_PASS')
PY
