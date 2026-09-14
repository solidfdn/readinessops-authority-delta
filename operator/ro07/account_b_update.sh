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
if [ "$account" != "062788795311" ]; then
  echo "STOP: Run this in account B (062788795311). Current account: $account" >&2
  exit 1
fi

repo_dir="$HOME/readinessops-account-b"
if [ ! -d "$repo_dir/.git" ]; then
  echo "STOP: $repo_dir is missing. Use the existing account-B clone." >&2
  exit 1
fi

git -C "$repo_dir" fetch "$bundle" main
git -C "$repo_dir" merge --ff-only FETCH_HEAD
actual_commit=$(git -C "$repo_dir" rev-parse HEAD)
if [ "$actual_commit" != "$expected_commit" ]; then
  echo "STOP: The release commit does not match. expected=$expected_commit actual=$actual_commit" >&2
  exit 1
fi

cd "$repo_dir"
python3 scripts/launch_customer_connector.py

for name in customer-foundation-latest-launch.json customer-foundation-result.json customer-connector-latest-launch.json customer-connector-result.json; do
  if [ ! -s "$HOME/$name" ]; then
    echo "STOP: The collected file $HOME/$name is missing." >&2
    exit 1
  fi
done

transfer="$HOME/ReadinessOps_RO07_AccountB_Transfer.zip"
python3 - "$transfer" "$HOME" <<'PY'
from pathlib import Path
import sys
from zipfile import ZIP_DEFLATED, ZipFile

output, root = Path(sys.argv[1]), Path(sys.argv[2])
names = (
    'customer-foundation-latest-launch.json',
    'customer-foundation-result.json',
    'customer-connector-latest-launch.json',
    'customer-connector-result.json',
)
with ZipFile(output, 'w', ZIP_DEFLATED) as archive:
    for name in names:
        archive.write(root / name, name)
print(output)
PY

echo "ACCOUNT_B_UPDATE_PASS"
echo "Next file to download: $transfer"
