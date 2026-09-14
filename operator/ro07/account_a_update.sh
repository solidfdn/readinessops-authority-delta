#!/usr/bin/env bash
set -euo pipefail

package_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
bundle="$package_dir/ReadinessOps_RO07_Authority_Lifecycle.bundle"
expected_commit=$(git bundle list-heads "$bundle" refs/heads/main | awk 'NR==1 {print $1}')
if [ -z "$expected_commit" ]; then
  echo "STOP: The release bundle main commit could not be verified." >&2
  exit 1
fi
account=$(aws sts get-caller-identity --query Account --output text --no-cli-pager)
if [ "$account" != "538522204923" ]; then
  echo "STOP: Run this in account A (538522204923). Current account: $account" >&2
  exit 1
fi

repo_dir="$HOME/readinessops-connected-a"
transfer="$HOME/ReadinessOps_RO07_AccountB_Transfer.zip"
transfer_dir="$HOME/readinessops-connected-transfer"
if [ ! -d "$repo_dir/.git" ]; then
  echo "STOP: $repo_dir is missing. Use the existing account-A clone." >&2
  exit 1
fi
if [ ! -s "$transfer" ]; then
  echo "STOP: Upload $transfer downloaded from account B to this CloudShell." >&2
  exit 1
fi

mkdir -p "$transfer_dir"
unzip -j -o "$transfer" \
  customer-foundation-latest-launch.json customer-foundation-result.json \
  customer-connector-latest-launch.json customer-connector-result.json \
  -d "$transfer_dir"

git -C "$repo_dir" fetch "$bundle" main
git -C "$repo_dir" merge --ff-only FETCH_HEAD
actual_commit=$(git -C "$repo_dir" rev-parse HEAD)
if [ "$actual_commit" != "$expected_commit" ]; then
  echo "STOP: The release commit does not match. expected=$expected_commit actual=$actual_commit" >&2
  exit 1
fi

cd "$repo_dir"
python3 scripts/launch_customer_wiring.py \
  --connector-report "$transfer_dir/customer-connector-result.json"
python3 scripts/check_connected_acceptance_readiness.py \
  --foundation-launch "$transfer_dir/customer-foundation-latest-launch.json" \
  --foundation-report "$transfer_dir/customer-foundation-result.json" \
  --connector-launch "$transfer_dir/customer-connector-latest-launch.json" \
  --connector-report "$transfer_dir/customer-connector-result.json" \
  --wiring-launch "$HOME/customer-wiring-latest-launch.json" \
  --wiring-report "$HOME/customer-wiring-result.json" \
  --runtime-transition evidence/aws/20260912-customer-runtime-versions-user-reported.json \
  --output "$HOME/connected-acceptance-readiness.json"

echo "ACCOUNT_A_UPDATE_PASS"
echo "Expected:  READY_FOR_AUTHENTICATED_ACCEPTANCE"
echo "Next: follow operator/ro07/live_acceptance.md in the browser."
