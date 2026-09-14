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
      commit -m 'Permit and verify publisher fence release'
fi

python3 scripts/launch_customer_connector.py

ad_journal="$(aws cloudformation describe-stacks \
  --stack-name authority-delta-customer-publisher \
  --region ap-northeast-1 \
  --query "Stacks[0].Outputs[?OutputKey=='PublisherJournalTable'].OutputValue | [0]" \
  --output text --no-cli-pager)"
AD_JOURNAL="$ad_journal" python3 - <<'PY'
import json, os, subprocess

response = json.loads(subprocess.check_output([
    'aws', 'iam', 'get-role-policy',
    '--role-name', 'authority-delta-customer-publisher',
    '--policy-name', 'BoundedCustomerApplication',
    '--output', 'json', '--no-cli-pager'], text=True))
expected = {
    'dynamodb:GetItem', 'dynamodb:PutItem', 'dynamodb:DeleteItem',
    'dynamodb:TransactWriteItems'}
resource = ('arn:aws:dynamodb:ap-northeast-1:062788795311:table/'
            + os.environ['AD_JOURNAL'])
matches = []
for statement in response['PolicyDocument']['Statement']:
    actions = statement.get('Action', [])
    actions = [actions] if isinstance(actions, str) else actions
    resources = statement.get('Resource', [])
    resources = [resources] if isinstance(resources, str) else resources
    if statement.get('Effect') == 'Allow' and resource in resources:
        if any(action.startswith('dynamodb:') for action in actions):
            matches.append(set(actions))
if matches != [expected]:
    raise SystemExit('ERROR: The AWS readback for Publisher journal permissions does not match.')
print('ACCOUNT_B_PUBLISHER_DELETE_ITEM_FIX_PASS')
PY
