#!/usr/bin/env python3
"""Launch the bounded Gate B worker or resume collection of the same build."""
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
from gate_b_diagnostics import semantic_diagnostics

BUNDLE_VERSION = "20260909-gate-b-v3"
SCOPE = "GATE_B_LIVE_SEMANTIC_PROOF_UI_NOT_INCLUDED"


def write_record(path, record):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    pending = path.with_name(path.name + ".pending")
    pending.write_text(json.dumps(record, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    os.replace(pending, path)


def validate_record(record, binding):
    if not isinstance(record, dict) or record.get("scope") != SCOPE:
        raise DeploymentError("Not a Gate B launch record.")
    for name, expected in (("bucket", binding["artifact_bucket"]), ("project", binding["project"]),
            ("account", binding["account"]), ("region", binding["region"])):
        if record.get(name) != expected:
            raise DeploymentError("Launch record does not match the existing account and project bindings.")
    if not isinstance(record.get("build_id"), str) or not re.fullmatch(re.escape(binding["project"]) + r":[A-Za-z0-9_-]+", record["build_id"]):
        raise DeploymentError("Invalid Gate B build identity.")
    if not isinstance(record.get("report_key"), str) or not re.fullmatch(r"evidence/[0-9a-f]{32}/gate-b-result\.json", record["report_key"]):
        raise DeploymentError("Invalid Gate B evidence key.")
    if not isinstance(record.get("source_sha256"), str) or not re.fullmatch(r"[0-9a-f]{64}", record["source_sha256"]):
        raise DeploymentError("Invalid Gate B source digest.")
    if not isinstance(record.get("source_version"), str) or record["source_version"] in ("", "null"):
        raise DeploymentError("Gate B source has no immutable version.")


def validate_report(result, record, downloaded):
    if not isinstance(result, dict) or any(result.get(key) != record[key] for key in ("build_id", "source_sha256", "scope")):
        raise DeploymentError("Gate B evidence belongs to another build, source or scope.")
    version = downloaded.get("VersionId")
    if not isinstance(version, str) or version in ("", "null"):
        raise DeploymentError("Gate B evidence has no immutable S3 version.")
    return version


def compact_report(report, *, build_status, partial=False):
    """Operator summary only; the downloaded JSON remains the complete evidence."""
    summary = {key:report.get(key) for key in ('result','semantic_runtime_proof','gate_b','sem_01','sem_02','state_unchanged','error','build_id','source_sha256')}
    summary['analysis_model_id']=(report.get('analysis_model') or {}).get('model_id')
    summary.update(build_status=build_status, partial=partial,
                   analysis_diagnostics=semantic_diagnostics(report))
    return summary


def collect(cli, record, record_path):
    print("Build ID: " + record["build_id"], flush=True)
    resume_command = ["python3", str(ROOT / "scripts/launch_gate_b.py"), "--resume", str(record_path)]
    print("Resume this build: " + shlex.join(resume_command), flush=True)
    print("[Gate B] Wait for fixed Runtime replay and Strands analysis", flush=True)
    build = wait_terminal(cli, record["build_id"], limit=210)
    evidence = record_path.parent
    report_path = evidence / "gate-b-result.json"
    try:
        downloaded = cli.run("s3api", "get-object", "--bucket", record["bucket"],
            "--key", record["report_key"], str(report_path))
    except DeploymentError:
        checkpoint_key = record["report_key"].removesuffix(".json") + "-latest.json"
        try:
            checkpoint_path = evidence / "gate-b-result-latest.json"
            partial_object = cli.run("s3api", "get-object", "--bucket", record["bucket"],
                "--key", checkpoint_key, str(checkpoint_path))
            partial = json.loads(checkpoint_path.read_text(encoding="utf-8"))
            version = validate_report(partial, record, partial_object)
            record.update(checkpoint_version_id=version, build_status=build.get("buildStatus"), collection_result="INCOMPLETE")
            write_record(record_path, record)
            print("AUTHORITY_DELTA_PARTIAL_GATE_B_EVIDENCE", flush=True)
            print(json.dumps(compact_report(partial, build_status=build.get("buildStatus"), partial=True),
                ensure_ascii=False, indent=2), flush=True)
            print(f"Full checkpoint: {checkpoint_path}", flush=True)
            print(f"Checkpoint: s3://{record['bucket']}/{checkpoint_key} (version {version}); final Gate B proof is incomplete.", flush=True)
        except (DeploymentError, OSError, ValueError):
            print("No matching, versioned Gate B checkpoint could be recovered.", flush=True)
        show_failure_details(cli, build)
        raise DeploymentError(f"No final Gate B report. Build status: {build.get('buildStatus')}; resume build {record['build_id']} instead of starting another.")
    try:
        result = json.loads(report_path.read_text(encoding="utf-8"))
        version = validate_report(result, record, downloaded)
    except (DeploymentError, OSError, ValueError):
        show_failure_details(cli, build)
        raise
    record.update(report_version_id=version, build_status=build.get("buildStatus"), collection_result="COLLECTED")
    write_record(record_path, record)
    print("AUTHORITY_DELTA_GATE_B_RESULT", flush=True)
    print(json.dumps(compact_report(result, build_status=build.get("buildStatus")), ensure_ascii=False, indent=2), flush=True)
    print(f"Full report: {report_path}", flush=True)
    print(f"Evidence: s3://{record['bucket']}/{record['report_key']} (version {version})", flush=True)
    proof = result.get("semantic_runtime_proof")
    if build.get("buildStatus") != "SUCCEEDED" or result.get("result") != "PASS" or proof != "PASS" or result.get("state_unchanged") is not True:
        show_failure_details(cli, build)
        raise DeploymentError("Semantic proof is incomplete. Preserve evidence; Gate B UI acceptance remains separate.")
    return 0


def launch(cli, resume=None):
    binding = json.loads((ROOT / "infra/environments/development.json").read_text(encoding="utf-8"))
    print(f"Authority Delta Gate B {BUNDLE_VERSION}", flush=True)
    if cli.run("sts", "get-caller-identity").get("Account") != binding["account"]:
        raise DeploymentError("Wrong account. No Gate B operation started.")
    if resume:
        record_path = Path(resume).expanduser().resolve()
        record = json.loads(record_path.read_text(encoding="utf-8"))
        validate_record(record, binding)
        return collect(cli, record, record_path)

    print("[Gate B] Read existing deployment bindings", flush=True)
    bootstrap = stack_outputs(cli, binding["bootstrap_stack"])
    current = stack_outputs(cli, binding["application_stack"])
    if any(current.get(key) != value for key, value in binding["resources"].items()):
        raise DeploymentError("Existing baseline bindings changed. No Gate B build started.")
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
    report_key = f"evidence/{run_id}/gate-b-result.json"
    print("[Gate B] Upload source and start the existing deployment service", flush=True)
    with tempfile.TemporaryDirectory(prefix="authority-delta-gate-b-source-") as directory:
        archive = Path(directory) / "source.zip"
        digest = source_archive(archive)
        key = f"source/{digest}.zip"
        uploaded = cli.run("s3api", "put-object", "--bucket", bucket, "--key", key,
            "--body", str(archive), "--metadata", f"sha256={digest}")
    version = uploaded.get("VersionId")
    if not isinstance(version, str) or version in ("", "null"):
        raise DeploymentError("Source upload lacks an immutable VersionId.")
    variables = [
        {"name": "AD_REUSE_GATE_B", "value": "authority-delta-deploy:4186d536-a5f8-4bf9-9015-2b697b32fcdb", "type": "PLAINTEXT"},
        {"name": "AD_REPORT_KEY", "value": report_key, "type": "PLAINTEXT"},
        {"name": "AD_SOURCE_SHA256", "value": digest, "type": "PLAINTEXT"},
    ]
    started = cli.run("codebuild", "start-build", "--project-name", project,
        "--source-location-override", f"{bucket}/{key}", "--source-version", version,
        "--buildspec-override", "buildspec.gate-b.yml", "--timeout-in-minutes-override", "25",
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
