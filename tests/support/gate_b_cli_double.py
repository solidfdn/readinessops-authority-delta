#!/usr/bin/env python3
"""Local operator-process double. No live requests and no AWS gate evidence."""
import hashlib
import json
import os
from pathlib import Path
import re
import sys
import zipfile

args = sys.argv[1:]
state = Path(os.environ["AD_TEST_STATE"])
mode = os.environ["AD_TEST_SCENARIO"]
binding = json.loads((Path.cwd() / "infra/environments/development.json").read_text())
action = args[:2]
BUILD_ID = "authority-delta-deploy:offline-gate-b"
SCOPE = "GATE_B_LIVE_SEMANTIC_PROOF_UI_NOT_INCLUDED"


def value(flag):
    return args[args.index(flag) + 1]


def emit(data):
    print(json.dumps(data))
    raise SystemExit(0)


def fail(message):
    print(message, file=sys.stderr)
    raise SystemExit(1)


assert value("--region") == binding["region"]
assert value("--output") == "json"
assert "--no-cli-pager" in args
with (state / "calls.jsonl").open("a") as stream:
    stream.write(json.dumps(action) + "\n")

if action == ["sts", "get-caller-identity"]:
    account = "111122223333" if mode == "WRONG_ACCOUNT" else binding["account"]
    emit({"Account": account, "Arn": f"arn:aws:iam::{account}:root"})
if action == ["cloudformation", "describe-stacks"]:
    name = value("--stack-name")
    assert name in (binding["application_stack"], binding["bootstrap_stack"])
    outputs = binding["resources"] if name == binding["application_stack"] else {
        "ArtifactBucketName": binding["artifact_bucket"], "BuildProjectName": binding["project"]}
    emit({"Stacks": [{"StackStatus": "CREATE_COMPLETE", "Outputs": [
        {"OutputKey": key, "OutputValue": item} for key, item in outputs.items()]}]})
if action == ["codebuild", "list-builds-for-project"]:
    assert value("--project-name") == binding["project"]
    emit({"ids": ["authority-delta-deploy:active"]} if mode == "ACTIVE_BUILD" else {"ids": []})
if action == ["codebuild", "batch-get-builds"]:
    build_id = value("--ids")
    assert build_id in (BUILD_ID, "authority-delta-deploy:active")
    status = "IN_PROGRESS" if build_id.endswith(":active") else ("FAILED" if mode == "FAIL" else "SUCCEEDED")
    emit({"builds": [{"id": build_id, "projectName": binding["project"],
        "currentPhase": "BUILD" if status == "IN_PROGRESS" else "COMPLETED", "buildStatus": status,
        "logs": {"groupName": "/aws/codebuild/authority-delta-deploy", "streamName": "offline-only"}}]})
if action == ["logs", "get-log-events"]:
    assert value("--log-group-name") == "/aws/codebuild/authority-delta-deploy"
    emit({"events": [{"timestamp": 1, "message": "[Gate B] offline diagnostic retained"}], "nextForwardToken": "end"})
if action == ["s3api", "put-object"]:
    assert value("--bucket") == binding["artifact_bucket"]
    archive = Path(value("--body"))
    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    assert value("--metadata") == f"sha256={digest}"
    assert value("--key") == f"source/{digest}.zip"
    with zipfile.ZipFile(archive) as source:
        names = set(source.namelist())
        assert {"scripts/gate_b.py", "scripts/gate_a_state.py", "scripts/build_runtime_artifact.py",
            "services/vendor_agent/runtime.py", "src/authority_delta/cedar.py",
            "src/authority_delta/execution_evidence.py", "infra/vendor-runtimes/template.json",
            "buildspec.gate-b.yml", "requirements-deploy.lock"} <= names
        assert any(name.startswith("vendor/wheels/") for name in names)
        assert not any(name.startswith(("evidence/", "tests/", ".git/")) for name in names)
        assert b"scripts/gate_b.py" in source.read("buildspec.gate-b.yml")
    (state / "source.json").write_text(json.dumps({"hash": digest, "key": value("--key")}))
    emit({"VersionId": "offline-source-version"})
if action == ["codebuild", "start-build"]:
    source = json.loads((state / "source.json").read_text())
    assert value("--project-name") == binding["project"]
    assert value("--source-location-override") == f"{binding['artifact_bucket']}/{source['key']}"
    assert value("--source-version") == "offline-source-version"
    assert value("--buildspec-override") == "buildspec.gate-b.yml"
    assert value("--timeout-in-minutes-override") == "25"
    variables = {item["name"]: item["value"] for item in json.loads(value("--environment-variables-override"))}
    assert set(variables) == {"AD_REPORT_KEY", "AD_SOURCE_SHA256", "AD_REUSE_GATE_B"}
    assert variables["AD_REUSE_GATE_B"] == "authority-delta-deploy:4186d536-a5f8-4bf9-9015-2b697b32fcdb"
    assert variables["AD_SOURCE_SHA256"] == source["hash"]
    assert re.fullmatch(r"evidence/[0-9a-f]{32}/gate-b-result\.json", variables["AD_REPORT_KEY"])
    assert value("--idempotency-token") == variables["AD_REPORT_KEY"].split("/")[1]
    (state / "build.json").write_text(json.dumps(variables))
    emit({"build": {"id": BUILD_ID}})
if action == ["s3api", "get-object"]:
    variables = json.loads((state / "build.json").read_text())
    assert value("--bucket") == binding["artifact_bucket"]
    key = value("--key")
    partial = key.endswith("-latest.json")
    assert key == (variables["AD_REPORT_KEY"].removesuffix(".json") + "-latest.json"
        if partial else variables["AD_REPORT_KEY"])
    if mode == "FINAL_MISSING" and not partial:
        fail("NoSuchKey (injected local collection failure)")
    report = {"scope": SCOPE, "build_id": BUILD_ID, "source_sha256": variables["AD_SOURCE_SHA256"],
        "result": "IN_PROGRESS" if partial else ("FAIL" if mode == "FAIL" else "PASS"),
        "gate_b": "NOT_PASSED" if mode == "FAIL" else "PASS",
        "cleanup": {"status": "UNCONFIRMED" if mode == "CLEANUP_UNCONFIRMED" else "PASS"},
        "semantic_runtime_proof":"PASS", "state_unchanged":mode != "CLEANUP_UNCONFIRMED", "_offline_test": True}
    if partial:
        report["checkpoint_phase"] = "complete"
    if mode == "FAIL":
        report['patches']={'semantic':{'analysis_status':'REJECTED','analysis_error':'Recommendation disagrees with observed changes'}}
    # AwsCli appends its global flags after the positional destination.
    Path(args[args.index("--key") + 2]).write_text(json.dumps(report))
    emit({"VersionId": "offline-checkpoint-version" if partial else "offline-report-version"})

fail("Unexpected operator operation in local double: " + " ".join(action))
