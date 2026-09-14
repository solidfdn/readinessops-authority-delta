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
      commit -m 'Restore the canary result request identity contract'
fi

python3 scripts/launch_customer_connector.py

AD_REPO="$repo" python3 - <<'PY'
import json
import os
import subprocess
from pathlib import Path

repo = Path(os.environ['AD_REPO'])
report = json.loads((Path.home() / 'customer-connector-result.json').read_text())
if report.get('result') != 'PASS' or report.get('account') != '062788795311':
    raise SystemExit('ERROR: The account-B connector PASS report could not be verified.')
source = (repo / 'src/authority_delta/business/customer_publisher.py').read_text()
if "common = {'request_id': request_id," not in source:
    raise SystemExit('ERROR: The canary request ID requirement is missing from the source.')
for key in ('PublisherFunctionArn', 'CanaryFunctionArn', 'InvocationFunctionArn'):
    arn = report['connector_outputs'][key]
    value = json.loads(subprocess.check_output([
        'aws', 'lambda', 'get-function-configuration', '--function-name', arn,
        '--region', 'ap-northeast-1', '--output', 'json', '--no-cli-pager'], text=True))
    if (value.get('State') != 'Active'
            or value.get('LastUpdateStatus') != 'Successful'
            or value.get('FunctionArn') != arn
            or not value.get('CodeSha256')):
        raise SystemExit('ERROR: ' + key + ' has incomplete updated AWS readback.')
print('ACCOUNT_B_CANARY_REQUEST_ID_FIX_PASS')
PY
