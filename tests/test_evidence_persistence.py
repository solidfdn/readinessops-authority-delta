from contextlib import redirect_stdout
from datetime import datetime, timezone, timedelta
import io
import json
from pathlib import Path
import tempfile
import unittest

from authority_delta.evidence_json import encode_evidence
from scripts import verify_aws as worker


class StoredSession:
    def __init__(self, fail=False):
        self.objects = {}
        self.fail = fail
    def client(self, name):
        if name != "s3":
            raise AssertionError("Unexpected AWS request")
        return self
    def put_object(self, **kwargs):
        if self.fail:
            raise OSError("simulated storage failure")
        self.objects[kwargs["Key"]] = kwargs["Body"]
        return {"VersionId": "saved-version"}


class EvidencePersistenceTests(unittest.TestCase):
    def env(self):
        return {"CODEBUILD_BUILD_ID": "authority-delta-deploy:test", "AD_SOURCE_SHA256": "source-test", "AD_ARTIFACT_BUCKET": "owned-evidence", "AD_REPORT_KEY": "evidence/test/result.json"}

    def test_nested_sdk_timestamps_normalize_to_utc_without_changing_values(self):
        value = {"catalog_observed": {"modelLifecycle": {"startOfLifeTime": datetime(2026, 9, 8, 15, 9, tzinfo=timezone(timedelta(hours=9)))}}}
        result = json.loads(encode_evidence(value))
        self.assertEqual(result["catalog_observed"]["modelLifecycle"]["startOfLifeTime"], "2026-09-08T06:09:00Z")
        with self.assertRaises(ValueError):
            encode_evidence({"invalid": float("nan")})

    def test_unsupported_object_cannot_leak_repr_or_erase_gateway_checkpoint(self):
        class SecretObject:
            def __str__(self):
                return "SECRET-MUST-NOT-LEAK"
        session = StoredSession()
        def verify(session, environment, report, checkpoint):
            report["gateway_default_deny"] = {"status": "PASS", "state_unchanged": True}
            checkpoint(report, "gateway")
            report.update(result="PASS", model_invocation={"unexpected": SecretObject()})
        with tempfile.TemporaryDirectory() as d, redirect_stdout(io.StringIO()) as stdout:
            exit_code = worker.run_worker(session, self.env(), root=Path(d), verify_fn=verify)
            report = json.loads((Path(d) / "evidence/aws/verification-result.json").read_text())
        self.assertEqual(exit_code, 1)
        self.assertEqual(report["result"], "FAIL")
        self.assertEqual(report["gateway_default_deny"]["status"], "PASS")
        self.assertEqual(report["evidence_serialization_error"]["excluded_sections"], ["model_invocation"])
        self.assertIn("evidence/test/result-gateway.json", session.objects)
        self.assertNotIn("SECRET-MUST-NOT-LEAK", stdout.getvalue())
        self.assertNotIn("SECRET-MUST-NOT-LEAK", session.objects["evidence/test/result.json"].decode())

    def test_external_blocker_persists_as_blocked_while_storage_failure_exits_failed(self):
        def verify(session, environment, report, checkpoint):
            report.update(result="BLOCKED", gate_0="BLOCKED", model_invocation={"status": "BLOCKED", "timestamp": datetime.now(timezone.utc)})
        for failed in (False, True):
            with self.subTest(storage_failed=failed), tempfile.TemporaryDirectory() as d, redirect_stdout(io.StringIO()):
                session = StoredSession(fail=failed)
                result = worker.run_worker(session, self.env(), root=Path(d), verify_fn=verify)
                report = json.loads((Path(d) / "evidence/aws/verification-result.json").read_text())
                self.assertEqual(result, 1 if failed else 0)
                self.assertEqual(report["result"], "BLOCKED")
                self.assertEqual(report["gate_a"], "NOT_RUN")
