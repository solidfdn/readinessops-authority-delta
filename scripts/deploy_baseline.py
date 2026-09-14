#!/usr/bin/env python3
"""Run the baseline deployment inside CodeBuild using its service credentials."""
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "scripts"))

ACCOUNT = "538522204923"
REGION = "ap-northeast-1"
STACK = "authority-delta-customer-baseline"


def require_worker_identity(identity, environment):
    if identity.get("Account") != ACCOUNT or environment.get("AD_EXPECTED_ACCOUNT") != ACCOUNT:
        raise ValueError("Deployment account mismatch.")
    if environment.get("AD_REGION") != REGION:
        raise ValueError("Deployment Region mismatch.")
    if not re.fullmatch(r"arn:aws:sts::538522204923:assumed-role/ReadinessOpsAuthorityDeltaDeployer/[^/]+", identity.get("Arn", "")):
        raise ValueError("Application deployment requires the CodeBuild service role, never root.")
    if not environment.get("CODEBUILD_BUILD_ID", "").startswith("authority-delta-deploy:"):
        raise ValueError("Expected the owned CodeBuild deployment project.")


def all_records(client, table):
    records = []
    request = {"TableName": table, "ConsistentRead": True}
    while True:
        response = client.scan(**request)
        records += response.get("Items", [])
        if not response.get("LastEvaluatedKey"):
            return records
        request["ExclusiveStartKey"] = response["LastEvaluatedKey"]


def validate_observed(gateway, engine, targets, policies, registry, ledger, expected_items):
    if gateway.get("status") != "READY" or gateway.get("authorizerType") != "AWS_IAM":
        raise ValueError("Gateway is not READY with AWS_IAM authentication.")
    if engine.get("status") != "ACTIVE":
        raise ValueError("Policy Engine is not ACTIVE.")
    config = gateway.get("policyEngineConfiguration", {})
    if config.get("mode") != "ENFORCE" or config.get("arn") != engine.get("policyEngineArn"):
        raise ValueError("Gateway is not bound to the expected ENFORCE Policy Engine.")
    if len(targets) != 1 or targets[0].get("name") != "VendorPaymentTools" or targets[0].get("status") != "READY":
        raise ValueError("The expected tool target is missing, ambiguous or not READY.")
    if policies:
        raise ValueError("The initial Policy Engine already contains policies; preserve them and stop baseline initialization.")
    expected = {item["request_id"]["S"]: item for item in expected_items}
    observed = {item["request_id"]["S"]: item for item in registry}
    if observed != expected:
        raise ValueError("Deployed request registry does not exactly match the seven immutable fixture records.")
    if ledger:
        raise ValueError("Sandbox ledger is not empty; existing execution evidence was preserved.")


def deploy(session, environment, run=subprocess.run):
    from authority_delta.registry import FixtureBundle
    from build_registry_seed import build_transaction

    identity = session.client("sts").get_caller_identity()
    require_worker_identity(identity, environment)
    print("[worker 1/5] CodeBuild service identity verified; validate local input", flush=True)
    fixtures = FixtureBundle.load(ROOT / "fixtures/decision_cases.json")
    # Exercise the complete seed builder before the first application mutation.
    build_transaction(fixtures, "preflight-registry")
    run([sys.executable, "scripts/build_sandbox_artifact.py"], cwd=ROOT, check=True)
    artifact = ROOT / "dist/authority-delta-sandbox.zip"
    digest = hashlib.sha256(artifact.read_bytes()).hexdigest()
    bucket = environment["AD_ARTIFACT_BUCKET"]
    key = f"lambda/{digest}/authority-delta-sandbox.zip"
    s3 = session.client("s3", region_name=REGION)
    print("[worker 2/5] Publish a versioned Lambda artifact", flush=True)
    with artifact.open("rb") as data:
        uploaded = s3.put_object(Bucket=bucket, Key=key, Body=data, Metadata={"sha256": digest})
    version = uploaded.get("VersionId")
    if not version or version == "null":
        raise ValueError("Artifact upload did not return an immutable VersionId.")
    cfn = session.client("cloudformation", region_name=REGION)
    template = ROOT / "infra/customer-baseline/template.json"
    cfn.validate_template(TemplateBody=template.read_text(encoding="utf-8"))
    print("[worker 3/5] Deploy Lambda, DynamoDB, Gateway, Policy Engine and target", flush=True)
    run([
        "aws", "cloudformation", "deploy", "--region", REGION, "--no-cli-pager",
        "--template-file", str(template), "--stack-name", STACK,
        "--capabilities", "CAPABILITY_IAM", "--no-fail-on-empty-changeset",
        "--parameter-overrides", "ConnectionId=conn-demo",
        f"SandboxArtifactBucket={bucket}", f"SandboxArtifactKey={key}", f"SandboxArtifactVersion={version}",
        "--tags", "Project=ReadinessOpsAuthorityDelta", "Baseline=AD-BASELINE-1.0", "DataClass=SyntheticOnly",
    ], cwd=ROOT, check=True)
    stack = cfn.describe_stacks(StackName=STACK)["Stacks"][0]
    if stack["StackStatus"] not in ("CREATE_COMPLETE", "UPDATE_COMPLETE"):
        raise ValueError(f"Application stack state is {stack['StackStatus']}.")
    output = {item["OutputKey"]: item["OutputValue"] for item in stack["Outputs"]}
    control = session.client("bedrock-agentcore-control", region_name=REGION)
    gateway = control.get_gateway(gatewayIdentifier=output["GatewayIdentifier"])
    engine = control.get_policy_engine(policyEngineId=output["PolicyEngineId"])
    policy_page = control.list_policies(policyEngineId=output["PolicyEngineId"])
    policies = list(policy_page.get("policies", []))
    if policies or policy_page.get("nextToken"):
        raise ValueError("Existing policies found; preserve them and stop baseline initialization.")
    target_page = control.list_gateway_targets(gatewayIdentifier=output["GatewayIdentifier"])
    if target_page.get("nextToken"):
        raise ValueError("Unexpected additional Gateway targets.")
    target_items = target_page.get("items", [])
    ddb = session.client("dynamodb", region_name=REGION)
    ledger = all_records(ddb, output["SandboxLedgerTableName"])
    if ledger:
        raise ValueError("Existing ledger evidence found; preserve it and stop initialization.")
    print("[worker 4/5] Seed and reread seven immutable synthetic requests", flush=True)
    transaction = build_transaction(fixtures, output["RequestRegistryTableName"])
    ddb.transact_write_items(TransactItems=transaction)
    registry = all_records(ddb, output["RequestRegistryTableName"])
    ledger = all_records(ddb, output["SandboxLedgerTableName"])
    validate_observed(gateway, engine, target_items, policies, registry, ledger, [t["Put"]["Item"] for t in transaction])
    function = session.client("lambda", region_name=REGION).get_function_configuration(FunctionName=output["SandboxToolFunctionArn"])
    if function.get("State") != "Active" or function.get("LastUpdateStatus") != "Successful":
        raise ValueError("Sandbox Lambda is not active with a successful last update.")
    print("[worker 5/5] Write observed deployment evidence", flush=True)
    return {
        "schema_version": "1.1", "baseline_id": "AD-BASELINE-1.0", "result": "PASS",
        "scope": "AWS_BASELINE_DEPLOYMENT_ONLY_GATE_A_NOT_RUN",
        "observed_at": datetime.now(timezone.utc).isoformat(),
        "build_id": environment["CODEBUILD_BUILD_ID"], "source_sha256": environment["AD_SOURCE_SHA256"],
        "account": ACCOUNT, "region": REGION, "deployment_arn": identity["Arn"],
        "artifact": {"bucket": bucket, "key": key, "version_id": version, "sha256": digest},
        "resources": output,
        "postconditions": {"gateway_status": gateway["status"], "policy_engine_status": engine["status"],
            "policy_mode": gateway["policyEngineConfiguration"]["mode"], "policy_count": len(policies),
            "target_count": len(target_items), "request_registry_count": len(registry), "ledger_count": len(ledger)},
        "gate_a": "NOT_RUN", "model_invocation": "NOT_RUN", "credentials_recorded": False,
    }


def main():
    import boto3
    import botocore
    session = boto3.Session(region_name=REGION)
    result = {"result": "FAIL", "baseline_id": "AD-BASELINE-1.0", "build_id": os.environ.get("CODEBUILD_BUILD_ID"), "source_sha256": os.environ.get("AD_SOURCE_SHA256"), "gate_a": "NOT_RUN", "credentials_recorded": False}
    try:
        result = deploy(session, os.environ)
    except Exception as exc:
        result["error"] = str(exc)
        print(f"ERROR: {exc}", flush=True)
        try:
            events = session.client("cloudformation").describe_stack_events(StackName=STACK)["StackEvents"]
            result["failed_stack_events"] = [{k: e.get(k) for k in ("LogicalResourceId", "ResourceStatus", "ResourceStatusReason")} for e in events if e.get("ResourceStatus", "").endswith("FAILED")][:8]
            print(json.dumps(result["failed_stack_events"], indent=2), flush=True)
        except Exception:
            pass
    result["sdk_versions"] = {"boto3": boto3.__version__, "botocore": botocore.__version__}
    data = json.dumps(result, ensure_ascii=False, indent=2) + "\n"
    output = ROOT / "evidence/aws/deployment-result.json"
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(data, encoding="utf-8")
    try:
        session.client("s3").put_object(Bucket=os.environ["AD_ARTIFACT_BUCKET"], Key=os.environ["AD_REPORT_KEY"], Body=data.encode("utf-8"), ContentType="application/json")
    except Exception as exc:
        print(f"ERROR saving deployment evidence: {exc}", flush=True)
        return 1
    print(data, flush=True)
    return 0 if result["result"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
