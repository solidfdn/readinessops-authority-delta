#!/usr/bin/env python3
"""Observe real Gateway enforcement and bounded model access on the live baseline."""
from __future__ import annotations

import base64
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import sys
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "scripts"))
from authority_delta.canonical import sha256_json
from authority_delta.gateway_probe import GatewayProbe, policy_denial, validate_endpoint
from authority_delta.evidence_json import encode_evidence, recover_serializable_report
from authority_delta.registry import FixtureBundle
from build_registry_seed import build_transaction
from deploy_baseline import ACCOUNT, REGION, all_records, require_worker_identity, validate_observed

TOOL_ARGUMENTS = {"prepare_vendor_payment": "payment_request_id",
    "update_vendor_bank": "change_request_id", "export_credentials": "export_request_id"}


def observed_at():
    return datetime.now(timezone.utc).isoformat()


def sdk_evidence(response):
    metadata = response.get("ResponseMetadata", {})
    return {"request_id": metadata.get("RequestId"), "http_status": metadata.get("HTTPStatusCode")}


def safe_error(exc):
    from botocore.exceptions import ClientError
    if isinstance(exc, ClientError):
        error = exc.response.get("Error", {})
        return {"type": type(exc).__name__, "code": error.get("Code"),
            "message": error.get("Message", "")[:2000], **sdk_evidence(exc.response)}
    if isinstance(exc, (ValueError, KeyError)):
        return {"type": type(exc).__name__, "message": str(exc)[:2000]}
    # Network exception repr may contain request internals; report its class only.
    return {"type": type(exc).__name__, "message": "Operation failed; no credentials or request headers recorded."}


def snapshot(session, binding, fixtures):
    output = binding["resources"]
    cfn = session.client("cloudformation")
    stack = cfn.describe_stacks(StackName=binding["application_stack"])["Stacks"][0]
    if stack["StackStatus"] not in ("CREATE_COMPLETE", "UPDATE_COMPLETE"):
        raise ValueError("Application stack is not stable.")
    current = {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}
    if any(current.get(k) != v for k, v in output.items()):
        raise ValueError("Application bindings differ from the successful baseline.")
    control = session.client("bedrock-agentcore-control")
    gateway = control.get_gateway(gatewayIdentifier=output["GatewayIdentifier"])
    engine = control.get_policy_engine(policyEngineId=output["PolicyEngineId"])
    policies = control.list_policies(policyEngineId=output["PolicyEngineId"])
    targets = control.list_gateway_targets(gatewayIdentifier=output["GatewayIdentifier"])
    if policies.get("nextToken") or targets.get("nextToken"):
        raise ValueError("Unexpected additional policies or targets; preserve environment and stop.")
    if gateway.get("gatewayArn") != output["GatewayArn"] or gateway.get("gatewayUrl") != output["GatewayUrl"] or engine.get("policyEngineArn") != output["PolicyEngineArn"]:
        raise ValueError("Gateway or engine identity changed.")
    validate_endpoint(gateway["gatewayUrl"], output["GatewayIdentifier"], REGION)
    ddb = session.client("dynamodb")
    registry = all_records(ddb, output["RequestRegistryTableName"])
    ledger = all_records(ddb, output["SandboxLedgerTableName"])
    expected_items = [t["Put"]["Item"] for t in build_transaction(fixtures, output["RequestRegistryTableName"])]
    validate_observed(gateway, engine, targets.get("items", []), policies.get("policies", []), registry, ledger, expected_items)
    target = control.get_gateway_target(gatewayIdentifier=output["GatewayIdentifier"], targetId=targets["items"][0]["targetId"])
    if target.get("status") != "READY" or target.get("name") != "VendorPaymentTools" or target.get("gatewayArn") != output["GatewayArn"]:
        raise ValueError("Tool target is not READY on the expected Gateway.")
    config = target.get("targetConfiguration", {}).get("mcp", {}).get("lambda", {})
    if config.get("lambdaArn") != output["SandboxToolFunctionArn"]:
        raise ValueError("Tool target is not bound to the synthetic Lambda.")
    tools = config.get("toolSchema", {}).get("inlinePayload", [])
    if len(tools) != 3 or {t.get("name") for t in tools} != set(TOOL_ARGUMENTS):
        raise ValueError("The three protected tools are not actually registered.")
    for tool in tools:
        schema = tool.get("inputSchema", {})
        parameter = TOOL_ARGUMENTS[tool["name"]]
        if schema.get("type") != "object" or schema.get("required") != [parameter] or set(schema.get("properties", {})) != {parameter} or schema["properties"][parameter].get("type") != "string":
            raise ValueError("Registered tool input is not the immutable request-ID contract.")
    function = session.client("lambda").get_function_configuration(FunctionName=output["SandboxToolFunctionArn"])
    if function.get("State") != "Active" or function.get("LastUpdateStatus") != "Successful":
        raise ValueError("Synthetic tool Lambda is not active.")
    if base64.b64decode(function.get("CodeSha256", ""), validate=True).hex() != binding["sandbox_code_sha256"]:
        raise ValueError("Synthetic Lambda code differs from the deployed artifact.")
    expected_env = {"CONNECTION_ID": "conn-demo", "REQUEST_REGISTRY_TABLE": output["RequestRegistryTableName"], "SANDBOX_LEDGER_TABLE": output["SandboxLedgerTableName"]}
    if function.get("Environment", {}).get("Variables") != expected_env:
        raise ValueError("Synthetic Lambda is not bound to the expected registry and ledger.")
    stable = {"gateway_arn": gateway["gatewayArn"], "policy_engine_arn": engine["policyEngineArn"],
        "policy_mode": "ENFORCE", "policy_count": 0, "target_id": target["targetId"],
        "target_schema_hash": sha256_json(config), "sandbox_code_sha256": binding["sandbox_code_sha256"],
        "registry_hash": sha256_json(sorted(registry, key=lambda v: v["request_id"]["S"])), "ledger_hash": sha256_json(ledger),
        "registry_count": len(registry), "ledger_count": len(ledger)}
    return {"stable": stable, "api_evidence": {"gateway": sdk_evidence(gateway), "policy_engine": sdk_evidence(engine), "target": sdk_evidence(target)}}


def probe_model(session, candidates):
    from botocore.exceptions import ClientError
    attempts = []
    if candidates != ["openai.gpt-5.6-terra", "amazon.nova-lite-v1:0"]:
        raise ValueError("Unexpected model probe candidates.")
    for model_id in candidates:
        print(f"[model] Bounded Converse probe: {model_id}", flush=True)
        attempt = {"model_id": model_id, "max_output_tokens": 128, "status": "FAIL"}
        attempts.append(attempt)
        try:
            description = session.client("bedrock").get_foundation_model(modelIdentifier=model_id)
            details = description["modelDetails"]
            attempt["catalog_evidence"] = sdk_evidence(description)
            attempt["catalog_observed"] = {k: details.get(k) for k in ("modelId", "modelLifecycle", "outputModalities", "inferenceTypesSupported")}
            checks = {"model_id_matches": details.get("modelId") == model_id,
                "active": details.get("modelLifecycle", {}).get("status") == "ACTIVE",
                "text_output": "TEXT" in details.get("outputModalities", []),
                "on_demand": "ON_DEMAND" in details.get("inferenceTypesSupported", [])}
            if not all(checks.values()):
                attempt["status"] = "NOT_RUN"
                attempt["failed_catalog_checks"] = [name for name, ok in checks.items() if not ok]
                attempt["reason"] = "Catalog requirements not met; no invocation attempted. No conclusion about other inference modes."
                continue
            response = session.client("bedrock-runtime").converse(modelId=model_id,
                messages=[{"role": "user", "content": [{"text": "Reply with a short greeting. This is a synthetic connectivity test."}]}],
                inferenceConfig={"maxTokens": 128})
            attempt.update(sdk_evidence(response))
            message = response.get("output", {}).get("message", {})
            text = "\n".join(c["text"] for c in message.get("content", []) if isinstance(c.get("text"), str))
            attempt.update({"usage": response.get("usage", {}), "stop_reason": response.get("stopReason"),
                "response_text": text[:1000], "response_sha256": hashlib.sha256(text.encode()).hexdigest()})
            if not text.strip() or not attempt.get("request_id") or attempt.get("http_status") != 200:
                attempt["reason"] = "No nonempty correlated model text response. Model quality is not assessed here."
                continue
            attempt["status"] = "PASS"
            return {"status": "PASS", "selected_model_id": model_id, "fallback_used": model_id != candidates[0],
                "attempts": attempts, "strands_invocation": "NOT_RUN"}
        except ClientError as exc:
            attempt["error"] = safe_error(exc)
            if account_verification_pending(exc.response):
                attempt["status"] = "BLOCKED"
                return {"status": "BLOCKED", "blocker": "AWS_ACCOUNT_VERIFICATION_PENDING",
                    "attempts": attempts, "strands_invocation": "NOT_RUN",
                    "action": "Continue model-independent work. Retry model access after AWS verification; do not change IAM or resubscribe."}
            if exc.response.get("Error", {}).get("Code") not in ("ValidationException", "ResourceNotFoundException", "AccessDeniedException", "ModelNotReadyException"):
                break
        except Exception as exc:
            attempt["error"] = safe_error(exc)
            break
    return {"status": "FAIL", "attempts": attempts, "strands_invocation": "NOT_RUN"}


def account_verification_pending(response):
    error = response.get("Error", {})
    return error.get("Code") == "AccessDeniedException" and "your account is currently being verified" in error.get("Message", "").lower()


def finish_verification(report):
    gateway = report.get("gateway_default_deny", {}).get("status")
    model = report.get("model_invocation", {}).get("status")
    if gateway == "PASS" and model == "PASS":
        report.update(result="PASS", gate_0="PASS")
    elif gateway == "PASS" and model == "BLOCKED":
        report.update(result="BLOCKED", gate_0="BLOCKED")
    else:
        report.update(result="FAIL", gate_0="NOT_PASSED")
    report["model_independent_work_ready"] = gateway == "PASS"


def verify(session, environment, report, probe_factory=GatewayProbe, checkpoint=None):
    binding = json.loads((ROOT / "infra/environments/development.json").read_text())
    identity = session.client("sts").get_caller_identity()
    require_worker_identity(identity, environment)
    if environment.get("AD_ARTIFACT_BUCKET") != binding["artifact_bucket"]:
        raise ValueError("Unexpected evidence bucket.")
    report.update({"account": ACCOUNT, "region": REGION, "caller_arn": identity["Arn"], "identity_evidence": sdk_evidence(identity)})
    fixtures = FixtureBundle.load(ROOT / "fixtures/decision_cases.json")
    print("[verify 1/3] Read and validate live target, code, policy and registry", flush=True)
    before = snapshot(session, binding, fixtures)
    report["before"] = before
    report["fixture_snapshot_hash"] = fixtures.request_registry_snapshot_hash
    output = binding["resources"]
    probe = probe_factory(session, output["GatewayUrl"], output["GatewayIdentifier"], REGION)
    report["gateway_calls"] = []
    print("[verify 2/3] Call protected tools and require actual Policy rejection", flush=True)
    for case in fixtures.all_cases:
        action = case.request["action"]
        mcp_id = "ad-verify-" + uuid.uuid4().hex
        call = {"case_id": case.case_id, "request_id": case.request_id, "mcp_id": mcp_id,
            "tool": "VendorPaymentTools___" + action, "observed_at": observed_at(), "status": "FAIL"}
        report["gateway_calls"].append(call)
        try:
            call["response"] = probe.call(call["tool"], {TOOL_ARGUMENTS[action]: case.request_id}, mcp_id)
            call["status"] = "PASS" if policy_denial(call["response"], mcp_id) else "FAIL"
        except Exception as exc:
            call["error"] = safe_error(exc)
        print(f"[gateway] {case.case_id}: {call['status']}", flush=True)
        if call["status"] != "PASS":
            # Do not issue further calls after an unexpected permit or unclassified error.
            break
    report["gateway_default_deny"] = {"status": "FAIL", "required_calls": len(fixtures.all_cases), "observed_calls": len(report["gateway_calls"])}
    try:
        after = snapshot(session, binding, fixtures)
        report["after"] = after
        unchanged = after["stable"] == before["stable"]
        report["gateway_default_deny"]["state_unchanged"] = unchanged
        if unchanged and len(report["gateway_calls"]) == len(fixtures.all_cases) and all(c["status"] == "PASS" for c in report["gateway_calls"]):
            report["gateway_default_deny"]["status"] = "PASS"
    except Exception as exc:
        report["gateway_default_deny"]["error"] = safe_error(exc)
        # Preserve actual post-call ledger, even if snapshot's empty-ledger invariant failed.
        try:
            ledger = all_records(session.client("dynamodb"), output["SandboxLedgerTableName"])
            report["unexpected_ledger"] = ledger
        except Exception as read_exc:
            report["ledger_read_error"] = safe_error(read_exc)
    if checkpoint is not None:
        checkpoint(report, "gateway")
    print("[verify 3/3] Invoke Bedrock with at most two small model attempts", flush=True)
    report["model_invocation"] = probe_model(session, binding["model_candidates"])
    finish_verification(report)
    # A deployment-role probe cannot prove V2 identity, scoped permit or role isolation.
    report["gate_a"] = "NOT_RUN"
    report["remaining_gate_a"] = ["Immutable V1/V2 runtimes and distinct caller principals", "AUTH-01 unapproved V2 denial", "AUTH-02 scoped permit and other-principal/input/tool denial"]


def save_evidence(session, environment, encoded, destination, key):
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_bytes(encoded)
    stored = session.client("s3").put_object(Bucket=environment["AD_ARTIFACT_BUCKET"], Key=key,
        Body=encoded, ContentType="application/json", Metadata={"sha256": hashlib.sha256(encoded).hexdigest()})
    if not stored.get("VersionId") or stored["VersionId"] == "null":
        raise ValueError("Evidence object has no immutable S3 version.")
    return {"bucket": environment["AD_ARTIFACT_BUCKET"], "key": key,
        "version_id": stored["VersionId"], "sha256": hashlib.sha256(encoded).hexdigest()}


def run_worker(session, environment, root=ROOT, verify_fn=verify):
    import boto3
    import botocore
    report = {"schema_version": "1.2", "baseline_id": "AD-BASELINE-1.0", "result": "FAIL",
        "scope": "LIVE_BASELINE_VERIFICATION_NOT_FULL_GATE_A", "started_at": observed_at(),
        "build_id": environment.get("CODEBUILD_BUILD_ID"), "source_sha256": environment.get("AD_SOURCE_SHA256"),
        "gate_a": "NOT_RUN", "model_invocation": {"status": "NOT_RUN"}, "credentials_recorded": False,
        "sdk_versions": {"boto3": boto3.__version__, "botocore": botocore.__version__}}
    def checkpoint(current, phase):
        partial = dict(current, checkpoint_phase=phase, result="IN_PROGRESS", checkpoint_at=observed_at())
        encoded = encode_evidence(partial)
        key = environment["AD_REPORT_KEY"].removesuffix(".json") + f"-{phase}.json"
        location = save_evidence(session, environment, encoded, root / f"evidence/aws/checkpoint-{phase}.json", key)
        current.setdefault("checkpoints", {})[phase] = location
        print("AUTHORITY_DELTA_CHECKPOINT " + json.dumps(location), flush=True)
    try:
        verify_fn(session, environment, report, checkpoint=checkpoint)
    except Exception as exc:
        report["result"] = "FAIL"
        report["error"] = safe_error(exc)
    report["completed_at"] = observed_at()
    try:
        encoded = encode_evidence(report)
    except (TypeError, ValueError, OverflowError, RecursionError):
        report = recover_serializable_report(report)
        encoded = encode_evidence(report)
    print("AUTHORITY_DELTA_VERIFICATION", flush=True)
    print(encoded.decode(), flush=True)
    try:
        save_evidence(session, environment, encoded, root / "evidence/aws/verification-result.json", environment["AD_REPORT_KEY"])
    except Exception as exc:
        print("Evidence save failed: " + json.dumps(safe_error(exc)), flush=True)
        return 1
    # A completed probe with an explicit external blocker is not a crashed build.
    # Its result/gates remain BLOCKED, never PASS.
    return 0 if report["result"] in ("PASS", "BLOCKED") else 1


def main():
    import boto3
    from botocore.config import Config
    session = boto3.Session(region_name=REGION)
    original_client = session.client
    session.client = lambda service, **kw: original_client(service, config=Config(connect_timeout=10, read_timeout=90, retries={"total_max_attempts": 1}), **kw)
    return run_worker(session, os.environ)


if __name__ == "__main__":
    raise SystemExit(main())
