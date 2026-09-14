#!/usr/bin/env python3
"""Launch the bounded Gate A worker or resume collection of the same build."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import shlex
import sys
import tempfile
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from launch_deployment import AwsCli, DeploymentError, source_archive, stack_outputs, show_failure_details
from launch_verification import wait_terminal

BUNDLE_VERSION = "20260909-gate-a-v2"
SCOPE = "GATE_A_FIXED_RUNTIMES_AND_SCOPED_GATEWAY_PROOF"


def write_record(path, record):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    pending = path.with_name(path.name + ".pending")
    pending.write_text(json.dumps(record, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    os.replace(pending, path)


def validate_record(record, binding):
    if not isinstance(record, dict) or record.get("scope") != SCOPE:
        raise DeploymentError("Not a Gate A launch record.")
    for name, expected in (("bucket", binding["artifact_bucket"]), ("project", binding["project"]),
            ("account", binding["account"]), ("region", binding["region"])):
        if record.get(name) != expected:
            raise DeploymentError("Launch record does not match the existing account and project bindings.")
    if not isinstance(record.get("build_id"), str) or not re.fullmatch(re.escape(binding["project"]) + r":[A-Za-z0-9_-]+", record["build_id"]):
        raise DeploymentError("Invalid Gate A build identity.")
    if not isinstance(record.get("report_key"), str) or not re.fullmatch(r"evidence/[0-9a-f]{32}/gate-a-result\.json", record["report_key"]):
        raise DeploymentError("Invalid Gate A evidence key.")
    if not isinstance(record.get("source_sha256"), str) or not re.fullmatch(r"[0-9a-f]{64}", record["source_sha256"]):
        raise DeploymentError("Invalid Gate A source digest.")
    if not isinstance(record.get("source_version"), str) or record["source_version"] in ("", "null"):
        raise DeploymentError("Gate A source has no immutable version.")


def validate_report(result, record, downloaded):
    if not isinstance(result, dict) or any(result.get(key) != record[key] for key in ("build_id", "source_sha256", "scope")):
        raise DeploymentError("Gate A evidence belongs to another build, source or scope.")
    version = downloaded.get("VersionId")
    if not isinstance(version, str) or version in ("", "null"):
        raise DeploymentError("Gate A evidence has no immutable S3 version.")
    return version


def compact_report(report, *, build_status, partial=False):
    """Operator summary only; the downloaded JSON remains the complete evidence."""
    def mapping(value):
        return value if isinstance(value, dict) else {}

    cleanup = mapping(report.get("cleanup"))
    before = mapping(mapping(report.get("baseline_before")).get("stable"))
    after = mapping(mapping(report.get("baseline_after")).get("stable"))
    bindings = mapping(report.get("runtime_bindings"))
    model = mapping(mapping(report.get("previous_gate_0")).get("model_invocation"))
    model_summary = {key: model[key] for key in ("status", "model_id", "strands_invocation") if key in model}
    if isinstance(model.get("attempts"), list):
        model_summary["attempts"] = [{key: attempt[key] for key in ("model_id", "status") if key in attempt}
            for attempt in model["attempts"][:4] if isinstance(attempt, dict)]
    summary = {
        "result": "INCOMPLETE" if partial else report.get("result"),
        "gate_a": "NOT_CONFIRMED" if partial else report.get("gate_a"),
        "auth_01": report.get("auth_01", "NOT_RUN"),
        "auth_02": report.get("auth_02", "NOT_RUN"),
        "cleanup": {"status": cleanup.get("status", "NOT_CONFIRMED")},
        "policy_count": cleanup.get("policy_count", after.get("policy_count")),
        "replay_observation_count": len(report["replay_observations"]) if isinstance(report.get("replay_observations"), list) else None,
        "runtime_calls_count": len(report["runtime_calls"]) if isinstance(report.get("runtime_calls"), list) else None,
        "baseline_ledger_before_count": before.get("ledger_count"),
        "baseline_ledger_after_count": after.get("ledger_count"),
        "build_id": report.get("build_id"),
        "build_status": build_status,
        "source_sha256": report.get("source_sha256"),
        "runtime_bindings": {release: {key: mapping(bindings[release])[key] for key in (
            "RuntimeArn", "RuntimeId", "RuntimeVersion", "EndpointArn", "EndpointName", "ExecutionRoleArn")
            if key in mapping(bindings[release])} for release in ("V1", "V2") if release in bindings},
        "previous_gate_0": {"model_invocation": model_summary or None},
    }
    if partial:
        summary.update(collection_result="INCOMPLETE", checkpoint_phase=report.get("checkpoint_phase", "UNKNOWN"))
    if partial or report.get("result") != "PASS" or build_status != "SUCCEEDED" or cleanup.get("status") != "PASS":
        error = mapping(report.get("error")) or mapping(cleanup.get("error"))
        if error:
            summary["error"] = {key: value[:600] if isinstance(value, str) else value
                for key, value in error.items() if key in ("type", "code", "message", "request_id", "http_status")
                and isinstance(value, (str, int, float, bool, type(None)))}
    return summary


def collect(cli, record, record_path):
    print("Build ID: " + record["build_id"], flush=True)
    resume_command = ["python3", str(ROOT / "scripts/launch_gate_a.py"), "--resume", str(record_path)]
    print("Resume this build: " + shlex.join(resume_command), flush=True)
    print("[Gate A] Wait for fixed Runtime and Gateway proof", flush=True)
    build = wait_terminal(cli, record["build_id"], limit=210)
    evidence = record_path.parent
    report_path = evidence / "gate-a-result.json"
    try:
        downloaded = cli.run("s3api", "get-object", "--bucket", record["bucket"],
            "--key", record["report_key"], str(report_path))
    except DeploymentError:
        checkpoint_key = record["report_key"].removesuffix(".json") + "-latest.json"
        try:
            checkpoint_path = evidence / "gate-a-result-latest.json"
            partial_object = cli.run("s3api", "get-object", "--bucket", record["bucket"],
                "--key", checkpoint_key, str(checkpoint_path))
            partial = json.loads(checkpoint_path.read_text(encoding="utf-8"))
            version = validate_report(partial, record, partial_object)
            record.update(checkpoint_version_id=version, build_status=build.get("buildStatus"), collection_result="INCOMPLETE")
            write_record(record_path, record)
            print("AUTHORITY_DELTA_PARTIAL_GATE_A_EVIDENCE", flush=True)
            print(json.dumps(compact_report(partial, build_status=build.get("buildStatus"), partial=True),
                ensure_ascii=False, indent=2), flush=True)
            print(f"Full checkpoint: {checkpoint_path}", flush=True)
            print(f"Checkpoint: s3://{record['bucket']}/{checkpoint_key} (version {version}); final Gate A proof is incomplete.", flush=True)
        except (DeploymentError, OSError, ValueError):
            print("No matching, versioned Gate A checkpoint could be recovered.", flush=True)
        show_failure_details(cli, build)
        raise DeploymentError(f"No final Gate A report. Build status: {build.get('buildStatus')}; resume build {record['build_id']} instead of starting another.")
    try:
        result = json.loads(report_path.read_text(encoding="utf-8"))
        version = validate_report(result, record, downloaded)
    except (DeploymentError, OSError, ValueError):
        show_failure_details(cli, build)
        raise
    record.update(report_version_id=version, build_status=build.get("buildStatus"), collection_result="COLLECTED")
    write_record(record_path, record)
    print("AUTHORITY_DELTA_GATE_A_RESULT", flush=True)
    print(json.dumps(compact_report(result, build_status=build.get("buildStatus")), ensure_ascii=False, indent=2), flush=True)
    print(f"Full report: {report_path}", flush=True)
    print(f"Evidence: s3://{record['bucket']}/{record['report_key']} (version {version})", flush=True)
    cleanup = result.get("cleanup")
    if build.get("buildStatus") != "SUCCEEDED" or result.get("result") != "PASS" or result.get("gate_a") != "PASS" or not isinstance(cleanup, dict) or cleanup.get("status") != "PASS":
        show_failure_details(cli, build)
        raise DeploymentError("Gate A is incomplete or cleanup is unconfirmed. Preserve the evidence; no gate is promoted.")
    return 0


def launch(cli, resume=None):
    binding = json.loads((ROOT / "infra/environments/development.json").read_text(encoding="utf-8"))
    print(f"Authority Delta Gate A {BUNDLE_VERSION}", flush=True)
    if cli.run("sts", "get-caller-identity").get("Account") != binding["account"]:
        raise DeploymentError("Wrong account. No Gate A operation started.")
    if resume:
        record_path = Path(resume).expanduser().resolve()
        record = json.loads(record_path.read_text(encoding="utf-8"))
        validate_record(record, binding)
        return collect(cli, record, record_path)

    print("[Gate A] Read existing deployment bindings", flush=True)
    bootstrap = stack_outputs(cli, binding["bootstrap_stack"])
    current = stack_outputs(cli, binding["application_stack"])
    if any(current.get(key) != value for key, value in binding["resources"].items()):
        raise DeploymentError("Existing baseline bindings changed. No Gate A build started.")
    bucket, project = bootstrap["ArtifactBucketName"], bootstrap["BuildProjectName"]
    if bucket != binding["artifact_bucket"] or project != binding["project"]:
        raise DeploymentError("Unexpected artifact bucket or CodeBuild project.")
    active = cli.run("codebuild", "list-builds-for-project", "--project-name", project,
        "--sort-order", "DESCENDING", "--max-items", "5").get("ids", [])
    if active:
        builds = cli.run("codebuild", "batch-get-builds", "--ids", *active).get("builds", [])
        if any(build.get("buildStatus") == "IN_PROGRESS" for build in builds):
            raise DeploymentError("A project build is already running. Use its launch record to resume collection.")
    run_id = uuid.uuid4().hex
    report_key = f"evidence/{run_id}/gate-a-result.json"
    print("[Gate A] Upload source and start the existing deployment service", flush=True)
    with tempfile.TemporaryDirectory(prefix="authority-delta-gate-a-source-") as directory:
        archive = Path(directory) / "source.zip"
        digest = source_archive(archive)
        key = f"source/{digest}.zip"
        uploaded = cli.run("s3api", "put-object", "--bucket", bucket, "--key", key,
            "--body", str(archive), "--metadata", f"sha256={digest}")
    version = uploaded.get("VersionId")
    if not isinstance(version, str) or version in ("", "null"):
        raise DeploymentError("Source upload lacks an immutable VersionId.")
    variables = [
        {"name": "AD_REPORT_KEY", "value": report_key, "type": "PLAINTEXT"},
        {"name": "AD_SOURCE_SHA256", "value": digest, "type": "PLAINTEXT"},
    ]
    started = cli.run("codebuild", "start-build", "--project-name", project,
        "--source-location-override", f"{bucket}/{key}", "--source-version", version,
        "--buildspec-override", "buildspec.gate-a.yml", "--timeout-in-minutes-override", "25",
        "--environment-variables-override", json.dumps(variables), "--idempotency-token", run_id)
    record = {"schema_version": "1.0", "scope": SCOPE, "build_id": started["build"]["id"],
        "account": binding["account"], "region": binding["region"], "project": project,
        "bucket": bucket, "report_key": report_key, "source_sha256": digest,
        "source_version": version, "bundle_version": BUNDLE_VERSION}
    validate_record(record, binding)
    record_path = ROOT / "evidence/aws" / run_id / "launch.json"
    write_record(record_path, record)
    return collect(cli, record, record_path)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--resume", metavar="LAUNCH_RECORD", help="Collect the same existing build without uploading or starting another")
    args = parser.parse_args(argv)
    try:
        return launch(AwsCli(), resume=args.resume)
    except (DeploymentError, OSError, KeyError, ValueError, TypeError) as exc:
        print(f"ERROR: {exc}", flush=True)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
