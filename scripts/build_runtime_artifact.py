#!/usr/bin/env python3
"""Build deterministic AgentCore code ZIPs using the verified pure-Python wheels."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
from zipfile import ZIP_DEFLATED, ZipFile, ZipInfo

from authority_delta.canonical import canonicalize, sha256_json
from authority_delta.registry import FixtureBundle


ROOT = Path(__file__).resolve().parents[1]
STAMP = (2026, 9, 9, 0, 0, 0)


def release_document(fixtures, release_id):
    if release_id not in fixtures.releases:
        raise ValueError("Unknown fixed release")
    definition = fixtures.releases[release_id].as_contract()
    return {"schema_version": "1.0", "release_id": release_id, "definition": definition,
        "release_definition_hash": sha256_json(definition),
        "request_registry_snapshot_hash": fixtures.request_registry_snapshot_hash}


def dependency_files(root=ROOT):
    files = {}
    lock = (root / "requirements-deploy.lock").read_text(encoding="utf-8")
    for line in lock.splitlines():
        if not line.strip() or line.startswith("#"):
            continue
        match = re.fullmatch(r"([A-Za-z0-9_-]+)==([^ ]+) --hash=sha256:([0-9a-f]{64})", line)
        if not match:
            raise ValueError("Deployment dependency lock is not fully pinned")
        package, version, digest = match.groups()
        candidates = sorted((root / "vendor/wheels").glob(package.replace("-", "_") + "-" + version + "-*.whl"))
        if len(candidates) != 1:
            raise ValueError("Missing or ambiguous locked deployment wheel")
        wheel = candidates[0]
        if hashlib.sha256(wheel.read_bytes()).hexdigest() != digest:
            raise ValueError("Locked deployment wheel digest mismatch")
        if not wheel.name.endswith("-none-any.whl"):
            raise ValueError("Runtime ZIP requires pure Python or independently verified ARM64 wheels")
        with ZipFile(wheel) as archive:
            for item in archive.infolist():
                if item.is_dir():
                    continue
                path = PurePosixPath(item.filename)
                if path.is_absolute() or ".." in path.parts or ".data" in path.parts:
                    raise ValueError("Unexpected wheel layout")
                if "__pycache__" in path.parts or item.filename.endswith((".pyc", ".pyo")):
                    continue
                if item.filename in files:
                    raise ValueError("Overlapping dependency files")
                files[item.filename] = archive.read(item)
    return files


def build(fixtures, release_id, output_path, *, root=ROOT):
    """Return artifact identity; no fixture answers or AWS credentials enter ZIP."""
    if not isinstance(fixtures, FixtureBundle):
        fixtures = FixtureBundle.load(fixtures)
    root = Path(root)
    output_path = Path(output_path)
    document = release_document(fixtures, release_id)
    files = dependency_files(root)
    app_files = {
        "runtime.py": root / "services/vendor_agent/runtime.py",
        "services/vendor_agent/evaluator.py": root / "services/vendor_agent/evaluator.py",
        "authority_delta/__init__.py": root / "src/authority_delta/__init__.py",
        "authority_delta/canonical.py": root / "src/authority_delta/canonical.py",
        "authority_delta/domain.py": root / "src/authority_delta/domain.py",
        "authority_delta/decisions.py": root / "src/authority_delta/decisions.py",
        "authority_delta/adapters/__init__.py": root / "src/authority_delta/adapters/__init__.py",
        "authority_delta/adapters/vendor_payment.py": root / "src/authority_delta/adapters/vendor_payment.py",
        "authority_delta/gateway_probe.py": root / "src/authority_delta/gateway_probe.py",
    }
    for name, source in app_files.items():
        if name in files:
            raise ValueError("Application and dependency file collision")
        files[name] = source.read_bytes()
    files["services/__init__.py"] = b""
    files["services/vendor_agent/__init__.py"] = b""
    files["release.json"] = canonicalize(document)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with ZipFile(output_path, "w", compression=ZIP_DEFLATED, compresslevel=9) as bundle:
        directories = {str(parent) + "/" for name in files for parent in PurePosixPath(name).parents if str(parent) != "."}
        for name in sorted(directories):
            entry = ZipInfo(name, date_time=STAMP)
            entry.create_system = 3
            entry.external_attr = (0o40755 << 16) | 0x10
            bundle.writestr(entry, b"")
        for name in sorted(files):
            entry = ZipInfo(name, date_time=STAMP)
            entry.create_system = 3
            entry.compress_type = ZIP_DEFLATED
            entry.external_attr = 0o100644 << 16
            bundle.writestr(entry, files[name])
    encoded = output_path.read_bytes()
    return {"path": str(output_path), "sha256": hashlib.sha256(encoded).hexdigest(),
        "size_bytes": len(encoded), "release_id": release_id,
        "release_definition_hash": document["release_definition_hash"],
        "request_registry_snapshot_hash": document["request_registry_snapshot_hash"]}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--release", required=True, choices=["V1", "V2", "V1-BENIGN"])
    parser.add_argument("--output", required=True)
    parser.add_argument("--fixtures", default=str(ROOT / "fixtures/decision_cases.json"))
    args = parser.parse_args()
    print(json.dumps(build(args.fixtures, args.release, args.output), indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
