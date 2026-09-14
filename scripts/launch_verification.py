#!/usr/bin/env python3
"""Run verification on the existing CodeBuild project, without stack changes."""
from __future__ import annotations

import json
from pathlib import Path
import sys
import tempfile
import time
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from launch_deployment import AwsCli, DeploymentError, source_archive, stack_outputs, show_failure_details

BUNDLE_VERSION = "20260908-v3"


def wait_terminal(cli, build_id, delay=time.sleep, limit=100):
    previous = None
    for _ in range(limit):
        builds = cli.run("codebuild", "batch-get-builds", "--ids", build_id).get("builds", [])
        if len(builds) != 1 or builds[0].get("id") != build_id:
            raise DeploymentError("Verification build identity missing or mismatched.")
        build = builds[0]
        current = (build.get("currentPhase"), build.get("buildStatus"))
        if current != previous:
            print(f"CodeBuild: {current[0]} / {current[1]}", flush=True)
            previous = current
        if build.get("buildStatus") != "IN_PROGRESS":
            return build
        delay(10)
    raise DeploymentError(f"Verification polling timed out. Existing build: {build_id}. Do not start a duplicate.")


def launch(cli):
    binding = json.loads((ROOT / "infra/environments/development.json").read_text())
    print(f"Authority Delta live verification {BUNDLE_VERSION}", flush=True)
    print("[1/3] Read existing account and deployment bindings", flush=True)
    if cli.run("sts", "get-caller-identity").get("Account") != binding["account"]:
        raise DeploymentError("Wrong account. No verification started.")
    bootstrap = stack_outputs(cli, binding["bootstrap_stack"])
    current = stack_outputs(cli, binding["application_stack"])
    if any(current.get(key) != value for key, value in binding["resources"].items()):
        raise DeploymentError("Deployed resources changed since the successful baseline. No tool calls started.")
    bucket, project = bootstrap["ArtifactBucketName"], bootstrap["BuildProjectName"]
    if bucket != binding["artifact_bucket"] or project != binding["project"]:
        raise DeploymentError("Unexpected artifact bucket or CodeBuild project.")
    active = cli.run("codebuild", "list-builds-for-project", "--project-name", project, "--sort-order", "DESCENDING", "--max-items", "5").get("ids", [])
    if active:
        builds = cli.run("codebuild", "batch-get-builds", "--ids", *active).get("builds", [])
        if any(b.get("buildStatus") == "IN_PROGRESS" for b in builds):
            raise DeploymentError("A project build is already running. Preserve it; do not start another.")
    print("[2/3] Upload verification source and start the existing service role", flush=True)
    run_id = uuid.uuid4().hex
    report_key = f"evidence/{run_id}/verification-result.json"
    with tempfile.TemporaryDirectory(prefix="authority-delta-verify-") as directory:
        archive = Path(directory) / "source.zip"
        digest = source_archive(archive)
        key = f"source/{digest}.zip"
        uploaded = cli.run("s3api", "put-object", "--bucket", bucket, "--key", key, "--body", str(archive), "--metadata", f"sha256={digest}")
    version = uploaded.get("VersionId")
    if not version or version == "null":
        raise DeploymentError("Source upload lacks an immutable VersionId.")
    variables = [
        {"name": "AD_REPORT_KEY", "value": report_key, "type": "PLAINTEXT"},
        {"name": "AD_SOURCE_SHA256", "value": digest, "type": "PLAINTEXT"},
    ]
    started = cli.run("codebuild", "start-build", "--project-name", project,
        "--source-location-override", f"{bucket}/{key}", "--source-version", version,
        "--buildspec-override", "buildspec.verify.yml", "--timeout-in-minutes-override", "10",
        "--environment-variables-override", json.dumps(variables), "--idempotency-token", run_id)
    build_id = started["build"]["id"]
    if not build_id.startswith(project + ":"):
        raise DeploymentError("Unexpected build identity returned.")
    evidence = ROOT / "evidence/aws" / run_id
    evidence.mkdir(parents=True, exist_ok=True)
    record = {"build_id": build_id, "bucket": bucket, "report_key": report_key,
        "source_sha256": digest, "source_version": version, "bundle_version": BUNDLE_VERSION}
    (evidence / "launch.json").write_text(json.dumps(record, indent=2) + "\n")
    print(f"Build ID: {build_id}", flush=True)
    print("[3/3] Wait for Gateway/ledger/model evidence", flush=True)
    build = wait_terminal(cli, build_id)
    report_path = evidence / "verification-result.json"
    try:
        downloaded = cli.run("s3api", "get-object", "--bucket", bucket, "--key", report_key, str(report_path))
    except DeploymentError:
        checkpoint_key = report_key.removesuffix(".json") + "-gateway.json"
        try:
            partial_path = evidence / "checkpoint-gateway.json"
            partial_object = cli.run("s3api", "get-object", "--bucket", bucket, "--key", checkpoint_key, str(partial_path))
            partial = json.loads(partial_path.read_text())
            if partial.get("build_id") != build_id or partial.get("source_sha256") != digest or partial.get("checkpoint_phase") != "gateway" or not partial_object.get("VersionId") or partial_object["VersionId"] == "null":
                raise DeploymentError("Gateway checkpoint identity/version mismatch.")
            print("AUTHORITY_DELTA_PARTIAL_GATEWAY_EVIDENCE", flush=True)
            print(json.dumps(partial, ensure_ascii=False, indent=2), flush=True)
            print(f"Checkpoint version: {partial_object['VersionId']}; final verification remains incomplete.", flush=True)
        except (DeploymentError, OSError, ValueError):
            print("No valid Gateway checkpoint could be recovered.", flush=True)
        show_failure_details(cli, build)
        raise DeploymentError(f"No verification report. Build status: {build.get('buildStatus')}; build: {build_id}")
    result = json.loads(report_path.read_text())
    if result.get("build_id") != build_id or result.get("source_sha256") != digest or result.get("scope") != "LIVE_BASELINE_VERIFICATION_NOT_FULL_GATE_A":
        raise DeploymentError("Verification evidence belongs to a different build or source.")
    version_id = downloaded.get("VersionId")
    if not version_id or version_id == "null":
        raise DeploymentError("Verification evidence has no immutable S3 version.")
    record.update({"report_version_id": version_id, "build_status": build.get("buildStatus")})
    (evidence / "launch.json").write_text(json.dumps(record, indent=2) + "\n")
    print("AUTHORITY_DELTA_VERIFICATION", flush=True)
    print(json.dumps(result, ensure_ascii=False, indent=2), flush=True)
    print(f"Evidence: s3://{bucket}/{report_key} (version {version_id})", flush=True)
    if build.get("buildStatus") == "SUCCEEDED" and result.get("result") == "BLOCKED":
        print("BLOCKED: AWS account verification prevents model access. Gateway evidence is retained; continue model-independent implementation. Gate 0/A have not passed.", flush=True)
        return 2
    if build.get("buildStatus") != "SUCCEEDED" or result.get("result") != "PASS":
        raise DeploymentError("Verification is incomplete; the report above preserves observed results. No gate promoted.")
    return 0


def main():
    try:
        return launch(AwsCli())
    except (DeploymentError, OSError, KeyError, ValueError) as exc:
        print(f"ERROR: {exc}", flush=True)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
