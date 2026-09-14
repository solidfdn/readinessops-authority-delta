#!/usr/bin/env python3
"""Generated delivery embeds the V3 delta; reuses the operator's verified V2 ZIP."""
import base64
import hashlib
import json
from pathlib import Path, PurePosixPath
import stat
import subprocess
import sys
import tempfile
import zipfile
import zlib

BASE_ARCHIVE_SHA256 = "__BASE_ARCHIVE_SHA256__"
PATCH_DATA = "__PATCH_DATA__"
PATCH_SHA256 = "__PATCH_SHA256__"


def prepare_source(archive_path, destination):
    archive_bytes = archive_path.read_bytes()
    if hashlib.sha256(archive_bytes).hexdigest() != BASE_ARCHIVE_SHA256:
        raise ValueError("V2 ZIP differs from the tested source. Existing files were not modified.")
    with zipfile.ZipFile(archive_path) as archive:
        items = archive.infolist()
        if len(items) > 3000 or sum(item.file_size for item in items) > 100_000_000:
            raise ValueError("Unexpected V2 archive size.")
        seen = set()
        for item in items:
            path = PurePosixPath(item.filename)
            if path.is_absolute() or ".." in path.parts or "\\" in item.filename or item.filename in seen or stat.S_ISLNK(item.external_attr >> 16):
                raise ValueError("Unexpected archive entry.")
            seen.add(item.filename)
        archive.extractall(destination)
    raw_patch = zlib.decompress(base64.b64decode(PATCH_DATA, validate=True))
    if hashlib.sha256(raw_patch).hexdigest() != PATCH_SHA256:
        raise ValueError("Repair payload checksum mismatch.")
    patch = json.loads(raw_patch)
    for name, data in patch["files"].items():
        relative = PurePosixPath(name)
        if relative.is_absolute() or ".." in relative.parts or "\\" in name:
            raise ValueError("Unexpected repair path.")
        target = destination / name
        target.parent.mkdir(parents=True, exist_ok=True)
        decoded = base64.b64decode(data["base64"], validate=True)
        if hashlib.sha256(decoded).hexdigest() != data["sha256"]:
            raise ValueError("Repair file checksum mismatch.")
        target.write_bytes(decoded)
    return patch["source_commit"]


def main():
    archive = Path.home() / "ReadinessOps_Authority_Delta_AWS_Verification_V2.zip"
    if not archive.is_file():
        print("ERROR: The previously used V2 ZIP is missing from CloudShell home. No AWS operations started.")
        return 1
    try:
        directory = Path(tempfile.mkdtemp(prefix="authority-delta-v3-"))
        commit = prepare_source(archive, directory)
        print(f"Authority Delta V3 repair prepared. Source: {commit}", flush=True)
        print(f"Local evidence directory: {directory / 'evidence/aws'}", flush=True)
        # subprocess argv avoids shell expansion. Original V2 ZIP/directories remain untouched.
        return subprocess.run([sys.executable, str(directory / "scripts/repair_and_verify.py")], cwd=directory).returncode
    except (OSError, ValueError, KeyError, zipfile.BadZipFile, zlib.error) as exc:
        print(f"ERROR: {exc}", flush=True)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
