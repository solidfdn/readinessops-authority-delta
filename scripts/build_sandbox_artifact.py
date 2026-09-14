#!/usr/bin/env python3
"""Build the dependency-free Lambda zip and report its SHA-256."""

from __future__ import annotations

import argparse
import hashlib
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile, ZipInfo


ROOT = Path(__file__).resolve().parents[1]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", default="dist/authority-delta-sandbox.zip")
    args = parser.parse_args()
    output = ROOT / args.output
    output.parent.mkdir(parents=True, exist_ok=True)
    source = ROOT / "services/sandbox/handler.py"
    with ZipFile(output, "w", compression=ZIP_DEFLATED) as bundle:
        entry = ZipInfo("handler.py", date_time=(2026, 9, 8, 0, 0, 0))
        entry.compress_type = ZIP_DEFLATED
        entry.external_attr = 0o100644 << 16
        bundle.writestr(entry, source.read_bytes())
    digest = hashlib.sha256(output.read_bytes()).hexdigest()
    print(f"{output.relative_to(ROOT)} sha256={digest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
