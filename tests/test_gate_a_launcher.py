from __future__ import annotations

from contextlib import contextmanager, redirect_stdout
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from zipfile import ZipFile

from scripts import launch_gate_a as launcher

ROOT = Path(__file__).resolve().parents[1]
BINDING = json.loads((ROOT / "infra/environments/development.json").read_text())
BUILD_ID = BINDING["project"] + ":11111111-2222-3333-4444-555555555555"


class GateACliDouble:
    def __init__(self, root, *, final_missing=False, partial_mismatch=False,
            cleanup="PASS", build_status="SUCCEEDED", result="PASS", active=False,
            report_version="final-object-version"):
        self.root, self.calls = root, []
        self.final_missing, self.partial_mismatch = final_missing, partial_mismatch
        self.cleanup, self.build_status, self.result = cleanup, build_status, result
        self.active, self.report_version = active, report_version
        self.source_hash = None
        self.source_entries = []
        self.start_parameters = None

    def run(self, *args, **kwargs):
        self.calls.append(args)
        action = args[:2]
        arg = lambda name: args[args.index(name) + 1]
        if action == ("sts", "get-caller-identity"):
            return {"Account": BINDING["account"], "Arn": f"arn:aws:iam::{BINDING['account']}:root"}
        if action == ("cloudformation", "describe-stacks"):
            if arg("--stack-name") == BINDING["bootstrap_stack"]:
                outputs = {"ArtifactBucketName": BINDING["artifact_bucket"], "BuildProjectName": BINDING["project"]}
            elif arg("--stack-name") == BINDING["application_stack"]:
                outputs = BINDING["resources"]
            else:
                raise AssertionError("Unexpected stack read")
            return {"Stacks": [{"StackStatus": "CREATE_COMPLETE", "Outputs": [
                {"OutputKey": k, "OutputValue": v} for k, v in outputs.items()]}]}
        if action == ("codebuild", "list-builds-for-project"):
            return {"ids": [BUILD_ID] if self.active else []}
        if action == ("s3api", "put-object"):
            self.source_hash = arg("--metadata").split("=", 1)[1]
            with ZipFile(arg("--body")) as source:
                self.source_entries = source.namelist()
            return {"VersionId": "fixed-source-version"}
        if action == ("codebuild", "start-build"):
            self.start_parameters = args
            return {"build": {"id": BUILD_ID}}
        if action == ("codebuild", "batch-get-builds"):
            if not self.active:
                records = list((self.root / "evidence/aws").glob("*/launch.json"))
                if len(records) != 1:
                    raise AssertionError("Launch record was not saved before polling")
                record = json.loads(records[0].read_text())
                if record["build_id"] != BUILD_ID or record["source_sha256"] != self.source_hash:
                    raise AssertionError("Launch record binding differs before polling")
            return {"builds": [{"id": BUILD_ID, "currentPhase": "BUILD" if self.active else "COMPLETED",
                "buildStatus": "IN_PROGRESS" if self.active else self.build_status,
                "logs": {"groupName": "/aws/codebuild/authority-delta-deploy", "streamName": "observed-stream"}}]}
        if action == ("s3api", "get-object"):
            partial = arg("--key").endswith("-latest.json")
            if self.final_missing and not partial:
                raise launcher.DeploymentError("Final report not found")
            result = {"scope": launcher.SCOPE, "result": self.result, "gate_a": "PASS",
                "cleanup": {"status": self.cleanup}, "build_id": BUILD_ID,
                "source_sha256": "f" * 64 if partial and self.partial_mismatch else self.source_hash}
            Path(args[-1]).write_text(json.dumps(result))
            return {"VersionId": "partial-object-version" if partial else self.report_version}
        if action == ("logs", "get-log-events"):
            return {"events": [{"message": "Recovered worker log"}]}
        raise AssertionError("Unapproved CloudShell action: " + repr(action))


class GateALauncherTests(unittest.TestCase):
    @contextmanager
    def run_context(self, **kwargs):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = root / "infra/environments/development.json"
            config.parent.mkdir(parents=True)
            config.write_text(json.dumps(BINDING))
            cli = GateACliDouble(root, **kwargs)
            with patch.object(launcher, "ROOT", root), redirect_stdout(io.StringIO()) as output:
                yield root, cli, output

    def test_actual_source_contains_runtime_worker_and_buildspec_with_fixed_start_overrides(self):
        with self.run_context() as (root, cli, output):
            self.assertEqual(launcher.launch(cli), 0)
            self.assertTrue({"buildspec.gate-a.yml", "scripts/gate_a.py", "scripts/launch_gate_a.py",
                "scripts/build_runtime_artifact.py", "services/vendor_agent/runtime.py",
                "infra/vendor-runtimes/template.json", "requirements-deploy.lock"} <= set(cli.source_entries))
            self.assertFalse(any(name.startswith("evidence/") for name in cli.source_entries))
            args = cli.start_parameters
            value = lambda name: args[args.index(name) + 1]
            self.assertEqual(value("--buildspec-override"), "buildspec.gate-a.yml")
            self.assertEqual(value("--timeout-in-minutes-override"), "25")
            self.assertEqual(value("--source-version"), "fixed-source-version")
            variables = {x["name"]: x["value"] for x in json.loads(value("--environment-variables-override"))}
            self.assertEqual(variables["AD_SOURCE_SHA256"], cli.source_hash)
            self.assertTrue(variables["AD_REPORT_KEY"].endswith("/gate-a-result.json"))
            record_path = next((root / "evidence/aws").glob("*/launch.json"))
            self.assertEqual(json.loads(record_path.read_text())["report_version_id"], "final-object-version")
            self.assertLess(output.getvalue().index("Resume this build:"), output.getvalue().index("CodeBuild:"))
            actions = {x[:2] for x in cli.calls}
            self.assertNotIn(("cloudformation", "deploy"), actions)
            self.assertNotIn(("iam", "get-account-summary"), actions)
            self.assertFalse(any(x[0] == "budgets" for x in cli.calls))

    def test_resume_via_cli_main_only_collects_existing_build(self):
        with self.run_context() as (root, cli, output):
            self.assertEqual(launcher.launch(cli), 0)
            record_path = next((root / "evidence/aws").glob("*/launch.json"))
            cli.calls.clear()
            with patch.object(launcher, "AwsCli", return_value=cli):
                self.assertEqual(launcher.main(["--resume", str(record_path)]), 0)
            self.assertEqual([x[:2] for x in cli.calls], [
                ("sts", "get-caller-identity"), ("codebuild", "batch-get-builds"), ("s3api", "get-object")])

    def test_final_missing_recovers_versioned_checkpoint_but_never_passes(self):
        with self.run_context(final_missing=True, build_status="FAILED") as (root, cli, output):
            with self.assertRaises(launcher.DeploymentError):
                launcher.launch(cli)
            self.assertIn("AUTHORITY_DELTA_PARTIAL_GATE_A_EVIDENCE", output.getvalue())
            self.assertIn('"gate_a": "NOT_CONFIRMED"', output.getvalue())
            self.assertIn("Recovered worker log", output.getvalue())
            self.assertNotIn("AUTHORITY_DELTA_GATE_A_RESULT", output.getvalue())
            record = json.loads(next((root / "evidence/aws").glob("*/launch.json")).read_text())
            self.assertEqual(record["checkpoint_version_id"], "partial-object-version")
            self.assertEqual(record["collection_result"], "INCOMPLETE")

    def test_mismatched_partial_or_unversioned_final_is_not_accepted(self):
        for settings in ({"final_missing": True, "partial_mismatch": True}, {"report_version": "null"}):
            with self.subTest(settings=settings), self.run_context(**settings) as (root, cli, output):
                with self.assertRaises(launcher.DeploymentError):
                    launcher.launch(cli)
                self.assertNotIn("AUTHORITY_DELTA_PARTIAL_GATE_A_EVIDENCE", output.getvalue())
                self.assertNotIn("AUTHORITY_DELTA_GATE_A_RESULT", output.getvalue())

    def test_cleanup_worker_or_build_failure_is_not_success(self):
        for settings in ({"cleanup": "UNKNOWN"}, {"result": "FAIL"}, {"build_status": "FAILED"}):
            with self.subTest(settings=settings), self.run_context(**settings) as (root, cli, output):
                with patch.object(launcher, "AwsCli", return_value=cli):
                    self.assertEqual(launcher.main([]), 1)
                self.assertIn("ERROR:", output.getvalue())

    def test_running_build_prevents_new_upload_and_start(self):
        with self.run_context(active=True) as (root, cli, output):
            with self.assertRaises(launcher.DeploymentError):
                launcher.launch(cli)
            actions = [x[:2] for x in cli.calls]
            self.assertNotIn(("s3api", "put-object"), actions)
            self.assertNotIn(("codebuild", "start-build"), actions)

    def test_polling_uses_35_minute_bound_and_retains_resume_record_on_timeout(self):
        with self.run_context() as (root, cli, output):
            def timeout(cli, build_id, *, limit):
                self.assertEqual(limit, 210)
                self.assertEqual(build_id, BUILD_ID)
                self.assertEqual(len(list((root / "evidence/aws").glob("*/launch.json"))), 1)
                raise launcher.DeploymentError("Polling timed out")
            with patch.object(launcher, "wait_terminal", side_effect=timeout):
                with self.assertRaises(launcher.DeploymentError):
                    launcher.launch(cli)
            self.assertIn("--resume", output.getvalue())
            self.assertEqual(sum(x[:2] == ("codebuild", "start-build") for x in cli.calls), 1)

    def test_buildspec_is_offline_and_invokes_worker_in_the_installed_environment(self):
        source = (ROOT / "buildspec.gate-a.yml").read_text()
        self.assertIn("--no-index --find-links vendor/wheels --require-hashes -r requirements-deploy.lock", source)
        self.assertIn("PYTHONPATH=src /tmp/authority-delta-gate-a-env/bin/python scripts/gate_a.py", source)
        self.assertNotIn("pip install --upgrade", source)

    def test_summary_counts_full_evidence_without_printing_it_or_promoting_checkpoints(self):
        full = {"result": "PASS", "gate_a": "PASS", "auth_01": "PASS", "auth_02": "PASS",
            "cleanup": {"status": "PASS", "policy_count": 0}, "checkpoint_phase": "complete",
            "baseline_before": {"stable": {"ledger_count": 0}},
            "baseline_after": {"stable": {"ledger_count": 5}},
            "runtime_calls": [{"large_details": "detail" * 10000}] * 28,
            "replay_observations": [{}] * 14,
            "runtime_bindings": {"V1": {"RuntimeId": "v1", "RuntimeVersion": "1"}},
            "previous_gate_0": {"model_invocation": {"status": "PASS", "strands_invocation": "PASS", "raw_response": "unneeded"}}}
        summary = launcher.compact_report(full, build_status="SUCCEEDED")
        self.assertEqual((summary["runtime_calls_count"], summary["replay_observation_count"]), (28, 14))
        self.assertEqual((summary["baseline_ledger_before_count"], summary["baseline_ledger_after_count"]), (0, 5))
        self.assertEqual(summary["policy_count"], 0)
        self.assertNotIn("runtime_calls", summary)
        self.assertNotIn("raw_response", summary["previous_gate_0"]["model_invocation"])
        self.assertLess(len(json.dumps(summary)), 2000)
        partial = launcher.compact_report(full, build_status="FAILED", partial=True)
        self.assertEqual((partial["result"], partial["gate_a"], partial["checkpoint_phase"]), ("INCOMPLETE", "NOT_CONFIRMED", "complete"))
        full.update(result="FAIL", error={"type": "ValueError", "message": "reason" * 1000, "request_headers": "never print"})
        failed = launcher.compact_report(full, build_status="FAILED")
        self.assertEqual(len(failed["error"]["message"]), 600)
        self.assertNotIn("request_headers", failed["error"])


if __name__ == "__main__":
    unittest.main()
