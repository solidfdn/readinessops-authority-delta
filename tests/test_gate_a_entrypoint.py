from __future__ import annotations

import base64
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import zipfile
import zlib


ROOT = Path(__file__).resolve().parents[1]


def load_script(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class GateAEntrypointTests(unittest.TestCase):
    def setUp(self):
        self.module = load_script("gate_a_entrypoint")
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.archive = self.root / "ReadinessOps_Authority_Delta_AWS_Verification_V2.zip"
        self.make_archive()
        self.payload = {"schema_version": "1.0", "base_commit": "00f07d7", "source_commit": "a" * 40,
                        "files": {"scripts/launch_gate_a.py": self.file_entry(b"print('gate a')\n")},
                        "deleted_paths": ["obsolete.py"]}
        self.set_payload()

    def file_entry(self, content):
        return {"base64": base64.b64encode(content).decode(), "sha256": hashlib.sha256(content).hexdigest(), "mode": 0o644}

    def make_archive(self, extra=None):
        with zipfile.ZipFile(self.archive, "w") as archive:
            archive.writestr("obsolete.py", "old source")
            archive.writestr("kept.py", "unchanged source")
            if extra is not None:
                archive.writestr(*extra)
        self.module.BASE_ARCHIVE_SHA256 = hashlib.sha256(self.archive.read_bytes()).hexdigest()

    def set_payload(self):
        raw = json.dumps(self.payload).encode()
        self.module.PATCH_DATA = base64.b64encode(zlib.compress(raw)).decode()
        self.module.PATCH_SHA256 = hashlib.sha256(raw).hexdigest()

    def test_exact_base_apply_addition_deletion_and_original_unchanged(self):
        original_hash = hashlib.sha256(self.archive.read_bytes()).hexdigest()
        destination = self.root / "prepared"
        self.assertEqual(self.module.prepare_source(self.archive, destination), "a" * 40)
        self.assertEqual((destination / "scripts/launch_gate_a.py").read_bytes(), b"print('gate a')\n")
        self.assertFalse((destination / "obsolete.py").exists())
        self.assertEqual((destination / "kept.py").read_text(), "unchanged source")
        self.assertEqual(original_hash, hashlib.sha256(self.archive.read_bytes()).hexdigest())

    def test_all_checksums_fail_before_source_extraction(self):
        for mode in ("archive", "payload", "file"):
            with self.subTest(mode=mode):
                self.make_archive()
                self.payload["files"]["scripts/launch_gate_a.py"] = self.file_entry(b"good")
                self.set_payload()
                if mode == "archive":
                    self.module.BASE_ARCHIVE_SHA256 = "f" * 64
                elif mode == "payload":
                    self.module.PATCH_SHA256 = "f" * 64
                else:
                    self.payload["files"]["scripts/launch_gate_a.py"]["sha256"] = "f" * 64
                    self.set_payload()
                destination = self.root / mode
                with self.assertRaises(ValueError):
                    self.module.prepare_source(self.archive, destination)
                self.assertFalse(destination.exists())

    def test_archive_and_patch_paths_cannot_escape_or_follow_links(self):
        for name in (".", "../escape.py", "/absolute.py", "dir\\escape.py", "a//b.py", "a/./b.py"):
            with self.subTest(archive=name):
                self.make_archive((name, "bad"))
                with self.assertRaises(ValueError):
                    self.module.prepare_source(self.archive, self.root / "prepared")
            self.make_archive()
            with self.subTest(patch=name):
                self.payload["deleted_paths"] = [name]
                self.set_payload()
                with self.assertRaises(ValueError):
                    self.module.prepare_source(self.archive, self.root / "prepared")
            self.payload["deleted_paths"] = ["obsolete.py"]
            self.set_payload()
        linked = zipfile.ZipInfo("link")
        linked.create_system = 3
        linked.external_attr = (stat.S_IFLNK | 0o777) << 16
        self.make_archive((linked, "../outside"))
        with self.assertRaises(ValueError):
            self.module.prepare_source(self.archive, self.root / "prepared")

    def test_main_invokes_only_gate_a_launcher_and_propagates_return_code(self):
        directory = self.root / "prepared"
        directory.mkdir()
        output = io.StringIO()
        with patch.object(self.module.Path, "home", return_value=self.root), \
             patch.object(self.module.tempfile, "mkdtemp", return_value=str(directory)) as mktemp, \
             patch.object(self.module.subprocess, "run", return_value=SimpleNamespace(returncode=2)) as run, \
             patch("sys.stdout", output):
            self.assertEqual(self.module.main([]), 2)
        mktemp.assert_called_once_with(prefix="authority-delta-gate-a-")
        run.assert_called_once_with([sys.executable, str(directory / "scripts/launch_gate_a.py")], cwd=directory)
        self.assertIn("Gate A prepared", output.getvalue())
        self.assertIn(str(directory), output.getvalue())
        self.assertIn("resume", output.getvalue())

    def test_missing_base_or_resume_argument_never_starts_subprocess(self):
        self.archive.unlink()
        with patch.object(self.module.Path, "home", return_value=self.root), \
             patch.object(self.module.subprocess, "run") as run, patch("sys.stdout", io.StringIO()):
            self.assertEqual(self.module.main([]), 1)
            self.assertEqual(self.module.main(["--resume", "launch.json"]), 1)
        run.assert_not_called()

    def test_builder_uses_committed_source_and_encodes_deleted_paths(self):
        builder = load_script("build_gate_a_entrypoint")
        repository = self.root / "repository"
        repository.mkdir()
        def git(*args):
            return subprocess.check_output(["git", *args], cwd=repository, stderr=subprocess.DEVNULL).decode().strip()
        git("init", "-q")
        git("config", "user.email", "test@example.invalid")
        git("config", "user.name", "Gate A Test")
        (repository / "obsolete.py").write_text("old source")
        git("add", "obsolete.py")
        git("commit", "-qm", "base")
        base_commit = git("rev-parse", "HEAD")
        (repository / "scripts").mkdir()
        (repository / "scripts/gate_a_entrypoint.py").write_text((ROOT / "scripts/gate_a_entrypoint.py").read_text())
        (repository / "scripts/launch_gate_a.py").write_text("print('committed')\n")
        (repository / "obsolete.py").unlink()
        git("add", "-A")
        git("commit", "-qm", "gate a")
        expected_commit = git("rev-parse", "HEAD")
        (repository / "scripts/launch_gate_a.py").write_text("print('uncommitted must not leak')\n")
        with patch.object(builder, "ROOT", repository), patch.object(builder, "BASE_COMMIT", base_commit), \
             patch.object(builder, "V2_ARCHIVE_SHA256", hashlib.sha256(self.archive.read_bytes()).hexdigest()):
            report = builder.build(self.archive, self.root / "Gate_A.py")
        self.assertEqual(report["source_commit"], expected_commit)
        self.assertEqual(report["deleted_file_count"], 1)
        namespace = {"__name__": "generated_test"}
        exec((self.root / "Gate_A.py").read_text(), namespace)
        raw = zlib.decompress(base64.b64decode(namespace["PATCH_DATA"]))
        payload = json.loads(raw)
        self.assertEqual(payload["deleted_paths"], ["obsolete.py"])
        self.assertEqual(base64.b64decode(payload["files"]["scripts/launch_gate_a.py"]["base64"]), b"print('committed')\n")
        self.assertEqual(hashlib.sha256(raw).hexdigest(), namespace["PATCH_SHA256"])


if __name__ == "__main__":
    unittest.main()
