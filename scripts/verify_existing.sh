#!/usr/bin/env bash
set -euo pipefail
ad_source_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ad_source_dir"
exec python3 scripts/launch_verification.py "$@"
