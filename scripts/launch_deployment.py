#!/usr/bin/env python3
"""CloudShell entry point. Root bootstraps and launches CodeBuild; it never assumes a role."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time
import uuid
import zipfile

ROOT = Path(__file__).resolve().parents[1]
ACCOUNT = "538522204923"
REGION = "ap-northeast-1"
BOOTSTRAP_STACK = "authority-delta-bootstrap"
APPLICATION_STACK = "authority-delta-customer-baseline"
BUNDLE_VERSION = "20260908-r1"


class DeploymentError(RuntimeError):
    pass


class AwsCli:
    def __init__(self):
        self.env = dict(os.environ, AWS_PAGER="", AWS_DEFAULT_REGION=REGION, AWS_MAX_ATTEMPTS="3")

    def run(self, *args, json_output=True, stream=False):
        command = ["aws", *args, "--region", REGION, "--no-cli-pager", "--cli-connect-timeout", "10", "--cli-read-timeout", "45"]
        if json_output:
            command += ["--output", "json"]
        result = subprocess.run(command, cwd=ROOT, env=self.env, text=True, capture_output=not stream)
        if result.returncode:
            raise DeploymentError(f"{' '.join(args[:2])}: {(result.stderr or 'See output above.').strip()}")
        if stream:
            return None
        return json.loads(result.stdout or "{}") if json_output else result.stdout

    def budgets(self, operation):
        args = ["aws", "budgets", operation, "--account-id", ACCOUNT, "--budget-name", "ReadinessOps-Authority-Delta", "--region", "us-east-1", "--output", "json", "--no-cli-pager", "--cli-connect-timeout", "10", "--cli-read-timeout", "30"]
        result = subprocess.run(args, cwd=ROOT, env=self.env, text=True, capture_output=True)
        if result.returncode:
            raise DeploymentError(result.stderr.strip())
        return json.loads(result.stdout)


def validate_guard(identity, mfa, budget, notifications):
    if identity.get("Account") != ACCOUNT:
        raise DeploymentError("Wrong account. No resources changed.")
    if mfa.get("SummaryMap", {}).get("AccountMFAEnabled") != 1:
        raise DeploymentError("Account root MFA is not enabled. No resources changed.")
    value = budget["Budget"]
    if (value.get("BudgetType"), value.get("TimeUnit"), value.get("BudgetLimit", {}).get("Unit")) != ("COST", "MONTHLY", "USD") or float(value["BudgetLimit"]["Amount"]) != 50.0:
        raise DeploymentError("Expected USD 50 monthly cost budget. No resources changed.")
    observed = {(n["NotificationType"], float(n["Threshold"])) for n in notifications.get("Notifications", [])}
    if observed != {("ACTUAL", 20.0), ("ACTUAL", 50.0), ("ACTUAL", 100.0), ("FORECASTED", 80.0)}:
        raise DeploymentError("Budget notifications do not match the four configured thresholds.")
    if any(n.get("ThresholdType") not in (None, "PERCENTAGE") for n in notifications.get("Notifications", [])):
        raise DeploymentError("Budget thresholds must be percentages.")


def source_archive(destination):
    """Allowlist project input; do not transfer CloudShell files or credentials."""
    files = []
    for directory in ("src", "services", "scripts", "infra", "fixtures", "vendor", "packages/contracts"):
        files += [p for p in (ROOT / directory).rglob("*") if p.is_file() and not p.is_symlink() and "__pycache__" not in p.parts and p.suffix != ".pyc"]
    required = ("buildspec.deploy.yml", "buildspec.verify.yml", "buildspec.gate-a.yml", "buildspec.gate-b.yml", "buildspec.workbench.yml", "buildspec.business.yml", "buildspec.customer-foundation.yml", "buildspec.customer-connector.yml", "buildspec.customer-wiring.yml", "buildspec.ui-only.yml", "requirements-analysis-x86_64.lock", "requirements-analysis-aarch64.lock", "requirements-deploy.lock", "LICENSE")
    missing = [name for name in required if not (ROOT / name).is_file()]
    if missing:
        raise DeploymentError("Required CodeBuild source is missing: " + ", ".join(missing))
    files += [ROOT / name for name in required]
    with zipfile.ZipFile(destination, "w", zipfile.ZIP_DEFLATED) as archive:
        for path in sorted(files):
            archive.write(path, path.relative_to(ROOT))
    return hashlib.sha256(destination.read_bytes()).hexdigest()


def stack_outputs(cli, name):
    stacks = cli.run("cloudformation", "describe-stacks", "--stack-name", name)["Stacks"]
    if stacks[0]["StackStatus"] not in ("CREATE_COMPLETE", "UPDATE_COMPLETE"):
        raise DeploymentError(f"{name}: {stacks[0]['StackStatus']}")
    return {item["OutputKey"]: item["OutputValue"] for item in stacks[0].get("Outputs", [])}


def show_failure_details(cli, build):
    for phase in build.get("phases", []):
        for context in phase.get("contexts", []):
            if context.get("message"):
                print(context["message"], flush=True)
    logs = build.get("logs", {})
    if logs.get("groupName") and logs.get("streamName"):
        try:
            response = cli.run("logs", "get-log-events", "--log-group-name", logs["groupName"], "--log-stream-name", logs["streamName"], "--limit", "60")
            for event in response.get("events", []):
                print(event["message"].rstrip(), flush=True)
        except DeploymentError as exc:
            print(f"Log retrieval: {exc}", flush=True)


def wait_build(cli, build_id, delay=time.sleep, limit=210):
    previous = None
    for _ in range(limit):
        response = cli.run("codebuild", "batch-get-builds", "--ids", build_id)
        builds = response.get("builds", [])
        if len(builds) != 1 or builds[0].get("id") != build_id:
            raise DeploymentError("Build identity missing or mismatched.")
        build = builds[0]
        current = (build.get("currentPhase"), build["buildStatus"])
        if current != previous:
            print(f"CodeBuild: {current[0]} / {current[1]}", flush=True)
            previous = current
        if build["buildStatus"] == "SUCCEEDED":
            return build
        if build["buildStatus"] != "IN_PROGRESS":
            show_failure_details(cli, build)
            raise DeploymentError(f"CodeBuild {build['buildStatus']}: {build_id}")
        delay(10)
    raise DeploymentError(f"Polling timed out; inspect build {build_id}. The build itself has a 25-minute limit.")


def launch(cli):
    print(f"Authority Delta recovery {BUNDLE_VERSION}", flush=True)
    print("[1/4] Verify account, MFA and the existing budget", flush=True)
    validate_guard(cli.run("sts", "get-caller-identity"), cli.run("iam", "get-account-summary"), cli.budgets("describe-budget"), cli.budgets("describe-notifications-for-budget"))
    print("[2/4] Update the existing bootstrap stack for CodeBuild", flush=True)
    cli.run("cloudformation", "validate-template", "--template-body", "file://infra/bootstrap/template.json")
    try:
        cli.run("cloudformation", "deploy", "--template-file", "infra/bootstrap/template.json", "--stack-name", BOOTSTRAP_STACK, "--capabilities", "CAPABILITY_NAMED_IAM", "--no-fail-on-empty-changeset", "--tags", "Project=ReadinessOpsAuthorityDelta", "Baseline=AD-BASELINE-1.0", json_output=False, stream=True)
    except DeploymentError:
        try:
            events = cli.run("cloudformation", "describe-stack-events", "--stack-name", BOOTSTRAP_STACK).get("StackEvents", [])
            failed = [{k: e.get(k) for k in ("LogicalResourceId", "ResourceStatus", "ResourceStatusReason")} for e in events if e.get("ResourceStatus", "").endswith("FAILED")][:8]
            print(json.dumps(failed, indent=2), flush=True)
        except DeploymentError:
            pass
        raise
    outputs = stack_outputs(cli, BOOTSTRAP_STACK)
    bucket = outputs["ArtifactBucketName"]
    project = outputs["BuildProjectName"]
    print("[3/4] Upload fixed source and start the deployment service", flush=True)
    run_id = uuid.uuid4().hex
    with tempfile.TemporaryDirectory(prefix="authority-delta-source-") as temp:
        archive = Path(temp) / "source.zip"
        source_hash = source_archive(archive)
        key = f"source/{source_hash}.zip"
        uploaded = cli.run("s3api", "put-object", "--bucket", bucket, "--key", key, "--body", str(archive), "--metadata", f"sha256={source_hash}")
    version = uploaded.get("VersionId")
    if not version or version == "null":
        raise DeploymentError("Source upload has no immutable S3 VersionId.")
    report_key = f"evidence/{run_id}/deployment-result.json"
    variables = [{"name": "AD_REPORT_KEY", "value": report_key, "type": "PLAINTEXT"}, {"name": "AD_SOURCE_SHA256", "value": source_hash, "type": "PLAINTEXT"}]
    started = cli.run("codebuild", "start-build", "--project-name", project, "--source-location-override", f"{bucket}/{key}", "--source-version", version, "--environment-variables-override", json.dumps(variables), "--idempotency-token", run_id)
    build_id = started["build"]["id"]
    evidence_dir = ROOT / "evidence/aws"
    evidence_dir.mkdir(parents=True, exist_ok=True)
    launch_record = {"build_id": build_id, "bucket": bucket, "report_key": report_key, "source_sha256": source_hash, "source_version": version, "bundle_version": BUNDLE_VERSION}
    (evidence_dir / "latest-build.json").write_text(json.dumps(launch_record, indent=2) + "\n", encoding="utf-8")
    print(f"Build ID: {build_id}", flush=True)
    print("[4/4] Wait for deployment and download the result", flush=True)
    wait_build(cli, build_id)
    report_path = evidence_dir / "deployment-result.json"
    cli.run("s3api", "get-object", "--bucket", bucket, "--key", report_key, str(report_path))
    result = json.loads(report_path.read_text(encoding="utf-8"))
    if result.get("result") != "PASS" or result.get("build_id") != build_id or result.get("source_sha256") != source_hash:
        raise DeploymentError("Deployment report is failed, missing or belongs to a different build.")
    print("AUTHORITY_DELTA_RESULT", flush=True)
    print(json.dumps(result, ensure_ascii=False, indent=2), flush=True)


def main():
    try:
        launch(AwsCli())
        return 0
    except (DeploymentError, OSError, KeyError, ValueError) as exc:
        print(f"ERROR: {exc}", flush=True)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
