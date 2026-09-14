#!/usr/bin/env python3
"""Generated stdlib Gate B delivery; reuse the operator's unchanged V2 ZIP."""
import base64
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
import sys
import tempfile
import zipfile
import zlib


BASE_ARCHIVE_SHA256 = "__BASE_ARCHIVE_SHA256__"
PATCH_DATA = "__PATCH_DATA__"
PATCH_SHA256 = "__PATCH_SHA256__"


def _safe_path(name):
    if not isinstance(name, str) or not name or "\\" in name or "\x00" in name:
        raise ValueError("Unexpected Gate B payload path.")
    path = PurePosixPath(name)
    if not path.parts or path.is_absolute() or ".." in path.parts or path.as_posix() != name:
        raise ValueError("Unexpected Gate B payload path.")
    return path


def _decode_patch():
    raw = zlib.decompress(base64.b64decode(PATCH_DATA, validate=True))
    if hashlib.sha256(raw).hexdigest() != PATCH_SHA256:
        raise ValueError("Gate B payload checksum mismatch.")
    patch = json.loads(raw)
    if set(patch) != {"schema_version", "base_commit", "source_commit", "files", "deleted_paths"}:
        raise ValueError("Unexpected Gate B payload fields.")
    if patch["schema_version"] != "1.0" or patch["base_commit"] != "00f07d7":
        raise ValueError("Unsupported Gate B patch baseline.")
    if not isinstance(patch["source_commit"], str) or re.fullmatch(r"[0-9a-f]{40}", patch["source_commit"]) is None:
        raise ValueError("Invalid committed source identity.")
    if not isinstance(patch["files"], dict) or not isinstance(patch["deleted_paths"], list):
        raise ValueError("Invalid Gate B patch entries.")
    decoded = {}
    for name, data in patch["files"].items():
        _safe_path(name)
        if not isinstance(data, dict) or set(data) != {"base64", "sha256", "mode"}:
            raise ValueError("Invalid Gate B file metadata.")
        if data["mode"] not in (0o644, 0o755):
            raise ValueError("Unsupported Gate B file mode.")
        content = base64.b64decode(data["base64"], validate=True)
        if hashlib.sha256(content).hexdigest() != data["sha256"]:
            raise ValueError("Gate B file checksum mismatch.")
        decoded[name] = (content, data["mode"])
    deleted = set()
    for name in patch["deleted_paths"]:
        _safe_path(name)
        if name in decoded or name in deleted:
            raise ValueError("Conflicting Gate B patch paths.")
        deleted.add(name)
    if len(decoded) + len(deleted) > 3000 or sum(len(v[0]) for v in decoded.values()) > 100_000_000:
        raise ValueError("Unexpected Gate B patch size.")
    return patch["source_commit"], decoded, deleted


def prepare_source(archive_path, destination):
    """Validate the immutable base and complete patch before touching files."""
    archive_path, destination = Path(archive_path), Path(destination)
    if hashlib.sha256(archive_path.read_bytes()).hexdigest() != BASE_ARCHIVE_SHA256:
        raise ValueError("V2 ZIP differs from the tested source. No AWS operations started.")
    commit, patched_files, deleted_paths = _decode_patch()
    if destination.is_symlink() or (destination.exists() and (not destination.is_dir() or any(destination.iterdir()))):
        raise ValueError("Gate B extraction requires a new empty directory.")
    with zipfile.ZipFile(archive_path) as archive:
        items = archive.infolist()
        if len(items) > 3000 or sum(item.file_size for item in items) > 100_000_000:
            raise ValueError("Unexpected V2 archive size.")
        seen = set()
        for item in items:
            name = item.filename[:-1] if item.is_dir() else item.filename
            _safe_path(name)
            if name in seen or stat.S_ISLNK(item.external_attr >> 16):
                raise ValueError("Duplicate or symbolic V2 archive entry.")
            if stat.S_IFMT(item.external_attr >> 16) not in (0, stat.S_IFREG, stat.S_IFDIR):
                raise ValueError("Unsupported V2 archive entry type.")
            seen.add(name)
        destination.mkdir(parents=True, exist_ok=True)
        archive.extractall(destination)
    for name in sorted(deleted_paths):
        target = destination / name
        if target.is_dir():
            raise ValueError("A deleted source file unexpectedly names a directory.")
        target.unlink(missing_ok=True)
    for name, (content, mode) in patched_files.items():
        target = destination / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(content)
        target.chmod(mode)
    if not (destination / "scripts/launch_gate_b.py").is_file():
        raise ValueError("Gate B launcher is missing from committed source.")
    dependency_path = Path.home() / 'Authority_Delta_Analysis_Dependencies.zip'
    if hashlib.sha256(dependency_path.read_bytes()).hexdigest() != '51563470e31e77d2324deb2cfe08fdbbb498a2975cd9b506f97ebce35b3d64dd':
        raise ValueError('Dependency ZIP differs from the tested file')
    with zipfile.ZipFile(dependency_path) as dep:
        manifest=json.loads(dep.read('manifest.json'))
        for arch,items in manifest['wheels'].items():
            if arch not in ('x86_64','aarch64'):raise ValueError('Unexpected dependency architecture')
            for item in items:
                _safe_path(item['file'])
                if '/' in item['file']:raise ValueError('Unexpected wheel path')
                content=dep.read(arch+'/'+item['file'])
                if hashlib.sha256(content).hexdigest()!=item['sha256']:raise ValueError('Dependency checksum mismatch')
                target=destination/'vendor/analysis'/arch/item['file'];target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(content)
    return commit


def main(argv=None):
    arguments = sys.argv[1:] if argv is None else argv
    if arguments:
        print("ERROR: This entrypoint accepts no arguments. For an existing build, use the resume command printed by its launcher.", flush=True)
        return 1
    archive = Path.home() / "ReadinessOps_Authority_Delta_AWS_Verification_V2.zip"
    if not archive.is_file():
        print("ERROR: The previously used V2 ZIP is missing from CloudShell home. No AWS operations started.", flush=True)
        return 1
    try:
        directory = Path(tempfile.mkdtemp(prefix="authority-delta-gate-b-"))
        commit = prepare_source(archive, directory)
        print(f"Authority Delta Gate B prepared. Source: {commit}", flush=True)
        print(f"Prepared directory: {directory}", flush=True)
        print("If the connection is interrupted, use the resume command printed by the launcher. Keep this prepared directory.", flush=True)
        return subprocess.run([sys.executable, str(directory / "scripts/launch_gate_b.py")], cwd=directory).returncode
    except (OSError, ValueError, TypeError, KeyError, zipfile.BadZipFile, zlib.error) as exc:
        print(f"ERROR: {exc}", flush=True)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
