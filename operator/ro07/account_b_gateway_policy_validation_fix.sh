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
      commit -m 'Permit exact Gateway validation for Policy creation'
fi

python3 scripts/launch_customer_connector.py

ad_gateway_arn="$(aws cloudformation describe-stacks \
  --stack-name authority-delta-customer-baseline \
  --region ap-northeast-1 \
  --query "Stacks[0].Outputs[?OutputKey=='GatewayArn'].OutputValue | [0]" \
  --output text --no-cli-pager)"
AD_GATEWAY_ARN="$ad_gateway_arn" python3 - <<'PY'
import json
import os
import subprocess

response = json.loads(subprocess.check_output([
    'aws', 'iam', 'get-role-policy',
    '--role-name', 'authority-delta-customer-publisher',
    '--policy-name', 'BoundedCustomerApplication',
    '--output', 'json', '--no-cli-pager'], text=True))
gateway = os.environ['AD_GATEWAY_ARN']
manage, validation, admin = [], [], []
for statement in response['PolicyDocument']['Statement']:
    actions = statement.get('Action', [])
    actions = [actions] if isinstance(actions, str) else actions
    resources = statement.get('Resource', [])
    resources = [resources] if isinstance(resources, str) else resources
    if 'bedrock-agentcore:ManageAdminPolicy' in actions:
        admin.append(statement)
    if statement.get('Effect') != 'Allow' or gateway not in resources:
        continue
    if any(action.startswith('bedrock-agentcore:Manage') for action in actions):
        manage.append(set(actions))
    if any(action in {'bedrock-agentcore:GetGateway',
                      'bedrock-agentcore:InvokeGateway'} for action in actions):
        validation.append(set(actions))
if (manage != [{'bedrock-agentcore:ManageResourceScopedPolicy'}]
        or validation != [{'bedrock-agentcore:GetGateway',
                            'bedrock-agentcore:InvokeGateway'}]
        or admin):
    raise SystemExit('ERROR: The Publisher Gateway permissions do not match the minimum boundary.')
print('ACCOUNT_B_GATEWAY_POLICY_VALIDATION_FIX_PASS')
PY
