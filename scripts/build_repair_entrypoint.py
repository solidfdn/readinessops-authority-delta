#!/usr/bin/env python3
"""Package the committed diff as a small, stdlib-only CloudShell repair script."""
import base64
import hashlib
import json
from pathlib import Path
import subprocess
import zlib

ROOT = Path(__file__).resolve().parents[1]
BASE_COMMIT = "00f07d7"


def build(archive_path, destination):
    commit = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    names = subprocess.check_output(["git", "diff", "--name-only", "--diff-filter=ACMR", BASE_COMMIT, commit], cwd=ROOT, text=True).splitlines()
    files = {}
    for name in names:
        content = subprocess.check_output(["git", "show", f"{commit}:{name}"], cwd=ROOT)
        files[name] = {"base64": base64.b64encode(content).decode(), "sha256": hashlib.sha256(content).hexdigest()}
    raw = json.dumps({"source_commit": commit, "files": files}, separators=(",", ":")).encode()
    template = (ROOT / "scripts/repair_entrypoint.py").read_text()
    generated = template.replace("__BASE_ARCHIVE_SHA256__", hashlib.sha256(archive_path.read_bytes()).hexdigest())
    generated = generated.replace("__PATCH_DATA__", base64.b64encode(zlib.compress(raw, 9)).decode())
    generated = generated.replace("__PATCH_SHA256__", hashlib.sha256(raw).hexdigest())
    compile(generated, str(destination), "exec")
    destination.write_text(generated)
    return {"source_commit": commit, "file_count": len(files), "size": destination.stat().st_size}


if __name__ == "__main__":
    print(build(ROOT.parent / "outputs/ReadinessOps_Authority_Delta_AWS_Verification_V2.zip",
        ROOT.parent / "outputs/Authority_Delta_Repair_V3.py"))
