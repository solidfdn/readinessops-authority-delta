#!/usr/bin/env python3
"""Check the delivered Gate A entrypoint and recovery paths without live AWS."""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time
import zipfile

ROOT = Path(__file__).resolve().parents[1]
SCOPE = "GATE_A_FIXED_RUNTIMES_AND_SCOPED_GATEWAY_PROOF"


def run(command, cwd, env=None, timeout=90):
    result = subprocess.run(command, cwd=cwd, env=env, text=True, capture_output=True, timeout=timeout)
    if result.returncode:
        raise RuntimeError(f"Command failed ({result.returncode}): {command[:3]}\n"
            + result.stderr[-4500:] + "\n" + result.stdout[-1500:])
    return result


def load(path):
    spec = importlib.util.spec_from_file_location("delivered_authority_delta_gate_a", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def recorded_calls(directory):
    path = directory / "calls.jsonl"
    return [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []


def check(entrypoint, base_zip, expected_source_commit):
    started = time.monotonic()
    report = {"scope": "LOCAL_GATE_A_OPERATOR_DELIVERY_REVIEW_NO_LIVE_AWS", "result": "FAIL",
        "observed_at": datetime.now(timezone.utc).isoformat(), "aws_execution": "NOT_RUN",
        "entrypoint_sha256": hashlib.sha256(entrypoint.read_bytes()).hexdigest(),
        "base_zip_sha256": hashlib.sha256(base_zip.read_bytes()).hexdigest(), "checks": []}

    def passed(name, **details):
        report["checks"].append(dict(name=name, status="PASS", **details))
        print(f"[local Gate A delivery] {name}: PASS", flush=True)

    try:
        with tempfile.TemporaryDirectory(prefix="ad-gate-a-delivery-review-") as temporary:
            stage = Path(temporary)
            restored = stage / "restored"
            restored.mkdir()
            commit = load(entrypoint).prepare_source(base_zip, restored)
            intended = run(["git", "rev-parse", expected_source_commit], ROOT).stdout.strip()
            report["delivered_source_commit"] = commit
            if commit != intended:
                raise ValueError("Delivered entrypoint does not contain the intended source commit")
            tracked = run(["git", "ls-tree", "-r", "--name-only", commit], ROOT).stdout.splitlines()
            for name in tracked:
                expected = subprocess.check_output(["git", "show", f"{commit}:{name}"], cwd=ROOT)
                if not (restored / name).is_file() or (restored / name).read_bytes() != expected:
                    raise ValueError(f"Delivered source differs from committed file: {name}")
            deleted = run(["git", "diff", "--diff-filter=D", "--name-only", "00f07d7", commit], ROOT).stdout.splitlines()
            if any((restored / name).exists() for name in deleted):
                raise ValueError("A deleted source file survived delivery restoration")
            passed("restored_delivery_matches_committed_source", tracked_files=len(tracked), removed_files=len(deleted))

            cli_bin = stage / "bin"
            cli_bin.mkdir()
            fake_cli = cli_bin / "aws"
            fake_cli.write_text(f"#!{sys.executable}\n" + (ROOT / "tests/support/gate_a_cli_double.py").read_text())
            fake_cli.chmod(0o700)
            scenarios = [("PASS", 0), ("FAIL", 1), ("FINAL_MISSING", 1),
                ("WRONG_ACCOUNT", 1), ("ACTIVE_BUILD", 1), ("CLEANUP_UNCONFIRMED", 1)]
            for scenario, expected_exit in scenarios:
                scenario_dir = stage / scenario
                scenario_dir.mkdir()
                operator_home = scenario_dir / "operator"
                operator_home.mkdir()
                shutil.copy2(base_zip, operator_home / "ReadinessOps_Authority_Delta_AWS_Verification_V2.zip")
                # Substitute Path.home only inside the isolated test process.
                # The real HOME and credential environment are never used or changed.
                harness = ('import runpy,sys,tempfile; from pathlib import Path; from unittest.mock import patch; '
                    'delivery,operator_home,temporary=sys.argv[1:]; tempfile.tempdir=temporary; '
                    'sys.argv=[delivery];\n'
                    'with patch.object(Path,"home",return_value=Path(operator_home)): '
                    'runpy.run_path(delivery,run_name="__main__")')
                environment = {"PATH": str(cli_bin) + os.pathsep + os.defpath, "LANG": "C.UTF-8",
                    "AD_TEST_SCENARIO": scenario, "AD_TEST_STATE": str(scenario_dir),
                    "AWS_EC2_METADATA_DISABLED": "true"}
                result = subprocess.run([sys.executable, "-c", harness, str(entrypoint), str(operator_home),
                    str(scenario_dir)], cwd=operator_home, env=environment, text=True, capture_output=True, timeout=60)
                if result.returncode != expected_exit:
                    raise ValueError(f"{scenario}: exit {result.returncode}, expected {expected_exit}\n"
                        + result.stderr[-2500:] + "\n" + result.stdout[-2500:])
                calls = recorded_calls(scenario_dir)
                if ["sts", "get-caller-identity"] not in calls or "Traceback (most recent call last)" in result.stderr:
                    raise ValueError(f"{scenario}: operator process did not reach its intended check")
                starts = calls.count(["codebuild", "start-build"])
                uploads = calls.count(["s3api", "put-object"])
                should_start = scenario not in ("WRONG_ACCOUNT", "ACTIVE_BUILD")
                if starts != int(should_start) or uploads != int(should_start):
                    raise ValueError(f"{scenario}: unexpected build starts or source uploads")
                forbidden = [["sts", "assume-role"], ["cloudformation", "deploy"],
                    ["iam", "get-account-summary"], ["budgets", "describe-budget"]]
                if any(action in calls for action in forbidden):
                    raise ValueError("Operator repeated bootstrap, MFA/budget checks or root AssumeRole")
                marker = {"WRONG_ACCOUNT": "Wrong account.", "ACTIVE_BUILD": "already running",
                    "FAIL": "Gate A is incomplete", "CLEANUP_UNCONFIRMED": "cleanup is unconfirmed",
                    "FINAL_MISSING": "AUTHORITY_DELTA_PARTIAL_GATE_A_EVIDENCE",
                    "PASS": "AUTHORITY_DELTA_GATE_A_RESULT"}[scenario]
                if marker not in result.stdout:
                    raise ValueError(f"{scenario}: required diagnostic or result marker missing")
                records = [path for path in scenario_dir.glob("authority-delta-gate-a-*/evidence/aws/*/launch.json")
                    if json.loads(path.read_text()).get("scope") == SCOPE]
                if len(records) != int(should_start):
                    raise ValueError(f"{scenario}: launch record was not retained exactly once")
                if should_start:
                    record_path = records[0]
                    record = json.loads(record_path.read_text())
                    if scenario == "FINAL_MISSING":
                        partial_path = record_path.with_name("gate-a-result-latest.json")
                        if not partial_path.is_file() or record.get("collection_result") != "INCOMPLETE":
                            raise ValueError("Missing final report did not retain its checkpoint and incomplete launch state")
                        if '"gate_a": "NOT_CONFIRMED"' not in result.stdout:
                            raise ValueError("A checkpoint was promoted without final Gate A proof")
                    else:
                        recovered = json.loads(record_path.with_name("gate-a-result.json").read_text())
                        if recovered.get("scope") != SCOPE or recovered.get("build_id") != record["build_id"]:
                            raise ValueError(f"{scenario}: incorrect evidence recovered at operator endpoint")
                        if record.get("report_version_id") != "offline-report-version":
                            raise ValueError(f"{scenario}: report version was not retained")
                passed("operator_process_" + scenario.lower(), exit_status=result.returncode,
                    build_starts=starts, source_uploads=uploads,
                    boundary="Actual generated Python entrypoint, launcher, source archive and AwsCli processes; AWS responses are local doubles")

                if scenario in ("PASS", "FINAL_MISSING"):
                    # The second collection of the same launch record must not
                    # upload code, read/redeploy baseline or start another build.
                    resumed_env = dict(environment, AD_TEST_SCENARIO="PASS")
                    prepared = record_path.parents[3]
                    resumed = subprocess.run([sys.executable, str(prepared / "scripts/launch_gate_a.py"),
                        "--resume", str(record_path)], cwd=prepared, env=resumed_env,
                        text=True, capture_output=True, timeout=30)
                    if resumed.returncode != 0 or "AUTHORITY_DELTA_GATE_A_RESULT" not in resumed.stdout:
                        raise ValueError(f"{scenario}: existing build collection failed on resume\n"
                            + resumed.stderr[-1500:] + "\n" + resumed.stdout[-2000:])
                    additional = recorded_calls(scenario_dir)[len(calls):]
                    allowed = [["sts", "get-caller-identity"], ["codebuild", "batch-get-builds"], ["s3api", "get-object"]]
                    if not additional or any(action not in allowed for action in additional):
                        raise ValueError("Resume performed work beyond identity, existing build polling and evidence retrieval")
                    after = json.loads(record_path.read_text())
                    if after["build_id"] != record["build_id"] or after["source_sha256"] != record["source_sha256"]:
                        raise ValueError("Resume changed build or source identity")
                    passed("resume_same_build_after_" + scenario.lower(), exit_status=0,
                        additional_build_starts=0, additional_source_uploads=0)

            # Build precisely the subset uploaded to CodeBuild, then install its
            # locked wheels into a new environment without package-index access.
            archive = stage / "codebuild-source.zip"
            env = dict(os.environ, PYTHONPATH=str(restored / "src"), AWS_EC2_METADATA_DISABLED="true")
            run([sys.executable, "-c", 'from pathlib import Path; from scripts.launch_deployment import source_archive; '
                'source_archive(Path(__import__("sys").argv[1]))', str(archive)], restored, env)
            cloud_source = stage / "cloud-source"
            cloud_source.mkdir()
            with zipfile.ZipFile(archive) as source:
                source.extractall(cloud_source)
            fresh = stage / "worker-env"
            run([sys.executable, "-m", "venv", str(fresh)], cloud_source)
            python = fresh / "bin/python"
            run([str(python), "-m", "pip", "install", "--no-index", "--find-links", "vendor/wheels",
                "--require-hashes", "-r", "requirements-deploy.lock"], cloud_source)
            cloud_env = {"PATH": os.defpath, "LANG": "C.UTF-8", "PYTHONPATH": str(cloud_source / "src"),
                "AWS_EC2_METADATA_DISABLED": "true"}
            run([str(python), "-c", 'from scripts import gate_a; from authority_delta.registry import FixtureBundle; '
                'from pathlib import Path; assert len(FixtureBundle.load(Path("fixtures/decision_cases.json")).all_cases)==7'],
                cloud_source, cloud_env)
            passed("codebuild_source_imports_with_fresh_offline_locked_dependencies",
                python_version=run([str(python), "--version"], cloud_source).stdout.strip(),
                boundary="Fresh virtual environment and actual source subset; not a live CodeBuild image")

            artifacts = []
            for release in ("V1", "V2"):
                artifact = stage / (release.lower() + ".zip")
                output = run([str(python), "scripts/build_runtime_artifact.py", "--release", release,
                    "--output", str(artifact)], cloud_source, cloud_env)
                identity = json.loads(output.stdout)
                if identity["release_id"] != release or identity["sha256"] != hashlib.sha256(artifact.read_bytes()).hexdigest():
                    raise ValueError("Built Runtime artifact identity mismatch")
                unpacked = stage / (release.lower() + "-runtime")
                unpacked.mkdir()
                with zipfile.ZipFile(artifact) as source:
                    source.extractall(unpacked)
                # Isolated interpreter imports only the produced Runtime ZIP's
                # extracted dependencies, not the repository or worker venv.
                run([sys.executable, "-I", "-S", "-c", 'import sys; from pathlib import Path; '
                    'sys.path.insert(0,sys.argv[1]); import runtime; '
                    'value,definition=runtime.load_release(Path(sys.argv[1])/"release.json"); '
                    'assert value["release_id"]==sys.argv[2]; '
                    'assert runtime.make_server and definition', str(unpacked), release], unpacked,
                    {"PATH": os.defpath, "LANG": "C.UTF-8", "AWS_EC2_METADATA_DISABLED": "true"})
                artifacts.append({key: identity[key] for key in ("release_id", "sha256", "size_bytes", "release_definition_hash")})
            if artifacts[0]["sha256"] == artifacts[1]["sha256"]:
                raise ValueError("Fixed release artifacts are unexpectedly identical")
            passed("delivered_source_builds_independent_runtime_zips", artifacts=artifacts,
                boundary="Actual packaged wheels and application imports; no live AgentCore invocation")
            report["result"] = "PASS"
    except Exception as exc:
        report["error"] = {"type": type(exc).__name__, "message": str(exc)[:7000]}
    report["elapsed_seconds"] = round(time.monotonic() - started, 3)
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--entrypoint", type=Path, required=True)
    parser.add_argument("--base-zip", type=Path, required=True)
    parser.add_argument("--expected-source-commit", required=True)
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    report = check(args.entrypoint.resolve(), args.base_zip.resolve(), args.expected_source_commit)
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n")
    print(json.dumps({"result": report["result"], "scope": report["scope"], "error": report.get("error")}), flush=True)
    return 0 if report["result"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
