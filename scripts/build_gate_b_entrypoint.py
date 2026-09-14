#!/usr/bin/env python3
"""Build a stdlib-only Gate B entrypoint from committed changes to the V2 base."""
import base64
import hashlib
import json
from pathlib import Path
import subprocess
import zlib


ROOT = Path(__file__).resolve().parents[1]
BASE_COMMIT = "00f07d7"
V2_ARCHIVE_SHA256 = "7271a5eb7f3039ccc78efdcbba81b3de3b08f0232f7ab735be95cda0c676d496"


def _git(*arguments):
    return subprocess.check_output(["git", *arguments], cwd=ROOT)


def build(archive_path, destination):
    archive_path, destination = Path(archive_path), Path(destination)
    archive_hash = hashlib.sha256(archive_path.read_bytes()).hexdigest()
    if archive_hash != V2_ARCHIVE_SHA256:
        raise ValueError("Builder requires the exact previously delivered V2 archive.")
    commit = _git("rev-parse", "HEAD").decode().strip()
    entries = _git("diff", "--name-status", "-z", "--no-renames", BASE_COMMIT, commit).split(b"\0")
    entries = entries[:-1] if entries and entries[-1] == b"" else entries
    if len(entries) % 2:
        raise ValueError("Unexpected committed diff format.")
    modes = {}
    for record in _git("ls-tree", "-r", "-z", commit).split(b"\0"):
        if record:
            metadata, name = record.split(b"\t", 1)
            mode, kind, _ = metadata.split()
            modes[name.decode()] = (mode, kind)
    files, deleted = {}, []
    for status, encoded_name in zip(entries[::2], entries[1::2]):
        name = encoded_name.decode()
        if name.startswith("vendor/analysis/") and name.endswith(".whl"):
            continue
        if status == b"D":
            deleted.append(name)
            continue
        if status not in (b"A", b"C", b"M", b"T"):
            raise ValueError("Unsupported committed change type.")
        mode, kind = modes[name]
        if kind != b"blob" or mode not in (b"100644", b"100755"):
            raise ValueError("Gate B payload supports regular committed files only.")
        content = _git("show", f"{commit}:{name}")
        files[name] = {"base64": base64.b64encode(content).decode(),
                       "sha256": hashlib.sha256(content).hexdigest(),
                       "mode": 0o755 if mode == b"100755" else 0o644}
    # Source and template both come from HEAD, not an uncommitted workspace.
    _git("cat-file", "-e", f"{commit}:scripts/launch_gate_b.py")
    template = _git("show", f"{commit}:scripts/gate_b_entrypoint.py").decode()
    raw = json.dumps({"schema_version": "1.0", "base_commit": BASE_COMMIT,
                      "source_commit": commit, "files": files,
                      "deleted_paths": sorted(deleted)}, separators=(",", ":")).encode()
    generated = template.replace("__BASE_ARCHIVE_SHA256__", archive_hash)
    generated = generated.replace("__PATCH_DATA__", base64.b64encode(zlib.compress(raw, 9)).decode())
    generated = generated.replace("__PATCH_SHA256__", hashlib.sha256(raw).hexdigest())
    compile(generated, str(destination), "exec")
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(generated, encoding="utf-8")
    return {"source_commit": commit, "base_archive_sha256": archive_hash,
            "file_count": len(files), "deleted_file_count": len(deleted),
            "size": destination.stat().st_size,
            "sha256": hashlib.sha256(destination.read_bytes()).hexdigest()}


if __name__ == "__main__":
    print(build(ROOT.parent / "outputs/ReadinessOps_Authority_Delta_AWS_Verification_V2.zip",
                ROOT.parent / "outputs/Authority_Delta_Gate_B.py"))
