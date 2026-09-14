from contextlib import ExitStack, redirect_stdout
from datetime import datetime, timezone
import base64
import copy
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import boto3
from botocore.stub import ANY, Stubber

from authority_delta.registry import FixtureBundle
from scripts.build_registry_seed import build_transaction
from scripts import launch_deployment as deployment
from scripts import launch_verification as launcher
from scripts import verify_aws as worker
from test_gateway_probe import denied_response

ROOT = Path(__file__).resolve().parents[1]
BINDING = json.loads((ROOT / "infra/environments/development.json").read_text())
META = {"RequestId": "sdk-request-1", "HTTPStatusCode": 200}


class VerificationTests(unittest.TestCase):
    def test_account_verification_is_blocked_and_not_generic_iam_denial(self):
        original = json.loads((ROOT / "evidence/aws/20260908-055108-verification-v1-user-reported.json").read_text())
        observed = original["model_invocation"]["attempts"][1]["error"]
        response = {"Error": {"Code": observed["code"], "Message": observed["message"]}}
        self.assertTrue(worker.account_verification_pending(response))
        self.assertFalse(worker.account_verification_pending({"Error": {"Code": "AccessDeniedException", "Message": "Missing bedrock:InvokeModel permission"}}))
        for gateway, model, expected in [("PASS", "BLOCKED", "BLOCKED"), ("FAIL", "BLOCKED", "FAIL"), ("PASS", "FAIL", "FAIL"), ("PASS", "PASS", "PASS")]:
            report = {"gateway_default_deny": {"status": gateway}, "model_invocation": {"status": model}, "gate_a": "NOT_RUN"}
            worker.finish_verification(report)
            self.assertEqual(report["result"], expected)
            self.assertEqual(report["gate_a"], "NOT_RUN")

    def test_model_probe_records_catalog_fields_and_stops_on_account_block(self):
        session = boto3.Session(aws_access_key_id="unit-test", aws_secret_access_key="unit-test", region_name=worker.REGION)
        catalog, runtime = session.client("bedrock"), session.client("bedrock-runtime")
        a, b = Stubber(catalog), Stubber(runtime)
        first, second = BINDING["model_candidates"]
        for model, modes in [(first, ["PROVISIONED"]), (second, ["ON_DEMAND"])]:
            a.add_response("get_foundation_model", {"modelDetails": {"modelArn": f"arn:aws:bedrock:{worker.REGION}::foundation-model/{model}", "modelId": model, "modelLifecycle": {"status": "ACTIVE"}, "outputModalities": ["TEXT"], "inferenceTypesSupported": modes}, "ResponseMetadata": META}, {"modelIdentifier": model})
        b.add_client_error("converse", service_error_code="AccessDeniedException", service_message="Your account is currently being verified. Verification normally takes less than 2 hours.", http_status_code=403, expected_params={"modelId": second, "messages": ANY, "inferenceConfig": {"maxTokens": 128}})
        class BoundSession:
            def client(self, name):
                return {"bedrock": catalog, "bedrock-runtime": runtime}[name]
        with a, b, redirect_stdout(io.StringIO()):
            result = worker.probe_model(BoundSession(), BINDING["model_candidates"])
            a.assert_no_pending_responses()
            b.assert_no_pending_responses()
        self.assertEqual(result["status"], "BLOCKED")
        self.assertEqual(result["attempts"][0]["failed_catalog_checks"], ["on_demand"])
        self.assertEqual(result["attempts"][0]["catalog_observed"]["modelLifecycle"], {"status": "ACTIVE"})
        self.assertEqual(result["attempts"][0]["status"], "NOT_RUN")
        self.assertEqual(result["attempts"][1]["status"], "BLOCKED")

    def test_complete_worker_with_real_sdk_shapes_and_signed_gateway_transport(self):
        session = boto3.Session(aws_access_key_id="unit-test-key", aws_secret_access_key="unit-test-secret", region_name=worker.REGION)
        clients = {n: session.client(n) for n in ("sts", "cloudformation", "bedrock-agentcore-control", "dynamodb", "lambda", "bedrock", "bedrock-runtime", "s3")}
        stubs = {n: Stubber(c) for n, c in clients.items()}
        identity = {"Account": worker.ACCOUNT, "Arn": f"arn:aws:sts::{worker.ACCOUNT}:assumed-role/ReadinessOpsAuthorityDeltaDeployer/AWSCodeBuild-test", "UserId": "test-principal", "ResponseMetadata": META}
        environment = {"AD_EXPECTED_ACCOUNT": worker.ACCOUNT, "AD_REGION": worker.REGION, "CODEBUILD_BUILD_ID": "authority-delta-deploy:test", "AD_ARTIFACT_BUCKET": BINDING["artifact_bucket"], "AD_REPORT_KEY": "evidence/test/verification-result.json", "AD_SOURCE_SHA256": "source-test"}
        stubs["sts"].add_response("get_caller_identity", identity, {})
        output = BINDING["resources"]
        now = datetime.now(timezone.utc)
        fixtures = FixtureBundle.load(ROOT / "fixtures/decision_cases.json")
        for _ in range(2):
            stubs["cloudformation"].add_response("describe_stacks", {"Stacks": [{"StackName": BINDING["application_stack"], "StackStatus": "CREATE_COMPLETE", "CreationTime": now, "Outputs": [{"OutputKey": k, "OutputValue": v} for k, v in output.items()]}]}, {"StackName": BINDING["application_stack"]})
            control = stubs["bedrock-agentcore-control"]
            control.add_response("get_gateway", {"gatewayArn": output["GatewayArn"], "gatewayId": output["GatewayIdentifier"], "gatewayUrl": output["GatewayUrl"], "createdAt": now, "updatedAt": now, "status": "READY", "name": "authority-delta-gateway", "authorizerType": "AWS_IAM", "policyEngineConfiguration": {"arn": output["PolicyEngineArn"], "mode": "ENFORCE"}, "ResponseMetadata": META}, {"gatewayIdentifier": output["GatewayIdentifier"]})
            control.add_response("get_policy_engine", {"policyEngineId": output["PolicyEngineId"], "name": "AuthorityDeltaEngine", "createdAt": now, "updatedAt": now, "policyEngineArn": output["PolicyEngineArn"], "status": "ACTIVE", "statusReasons": [], "ResponseMetadata": META}, {"policyEngineId": output["PolicyEngineId"]})
            control.add_response("list_policies", {"policies": []}, {"policyEngineId": output["PolicyEngineId"]})
            control.add_response("list_gateway_targets", {"items": [{"targetId": "target-0123456789", "name": "VendorPaymentTools", "status": "READY", "createdAt": now, "updatedAt": now}]}, {"gatewayIdentifier": output["GatewayIdentifier"]})
            config = {"lambdaArn": output["SandboxToolFunctionArn"], "toolSchema": {"inlinePayload": [{"name": t, "description": "Synthetic test", "inputSchema": {"type": "object", "properties": {p: {"type": "string"}}, "required": [p]}} for t, p in worker.TOOL_ARGUMENTS.items()]}}
            control.add_response("get_gateway_target", {"gatewayArn": output["GatewayArn"], "targetId": "target-0123456789", "createdAt": now, "updatedAt": now, "status": "READY", "name": "VendorPaymentTools", "targetConfiguration": {"mcp": {"lambda": config}}, "credentialProviderConfigurations": [{"credentialProviderType": "GATEWAY_IAM_ROLE"}], "ResponseMetadata": META}, {"gatewayIdentifier": output["GatewayIdentifier"], "targetId": "target-0123456789"})
            items = [t["Put"]["Item"] for t in build_transaction(fixtures, output["RequestRegistryTableName"])]
            stubs["dynamodb"].add_response("scan", {"Items": items}, {"TableName": output["RequestRegistryTableName"], "ConsistentRead": True})
            stubs["dynamodb"].add_response("scan", {"Items": []}, {"TableName": output["SandboxLedgerTableName"], "ConsistentRead": True})
            stubs["lambda"].add_response("get_function_configuration", {"State": "Active", "LastUpdateStatus": "Successful", "CodeSha256": base64.b64encode(bytes.fromhex(BINDING["sandbox_code_sha256"])).decode(), "Environment": {"Variables": {"CONNECTION_ID": "conn-demo", "REQUEST_REGISTRY_TABLE": output["RequestRegistryTableName"], "SANDBOX_LEDGER_TABLE": output["SandboxLedgerTableName"]}}}, {"FunctionName": output["SandboxToolFunctionArn"]})
        model = BINDING["model_candidates"][0]
        lifecycle = {"status": "ACTIVE", "startOfLifeTime": now, "endOfLifeTime": now, "legacyTime": now, "publicExtendedAccessTime": now}
        with self.assertRaises(TypeError):
            json.dumps(lifecycle)  # Reproduces the actual V2 failure with SDK timestamp types.
        stubs["bedrock"].add_response("get_foundation_model", {"modelDetails": {"modelArn": f"arn:aws:bedrock:{worker.REGION}::foundation-model/{model}", "modelId": model, "outputModalities": ["TEXT"], "inferenceTypesSupported": ["ON_DEMAND"], "modelLifecycle": lifecycle}, "ResponseMetadata": META}, {"modelIdentifier": model})
        stubs["bedrock-runtime"].add_response("converse", {"output": {"message": {"role": "assistant", "content": [{"text": "Hello!"}]}}, "stopReason": "end_turn", "usage": {"inputTokens": 15, "outputTokens": 2, "totalTokens": 17}, "metrics": {"latencyMs": 30}, "ResponseMetadata": META}, {"modelId": model, "messages": ANY, "inferenceConfig": {"maxTokens": 128}})
        written = {}
        original_put = clients["s3"].put_object
        def captured_put(**kwargs):
            written[kwargs["Key"]] = kwargs["Body"]
            return original_put(**kwargs)
        clients["s3"].put_object = captured_put
        for suffix in ("-gateway", ""):
            stubs["s3"].add_response("put_object", {"VersionId": "immutable" + suffix},
                {"Bucket": BINDING["artifact_bucket"], "Key": f"evidence/test/verification-result{suffix}.json", "Body": ANY, "ContentType": "application/json", "Metadata": ANY})
        class BoundSession:
            def client(self, name, **kwargs):
                return clients[name]
            def get_credentials(self):
                return session.get_credentials()
        calls = []
        class Http:
            def request(self, *args, **kwargs):
                payload = json.loads(kwargs["body"])
                calls.append(payload)
                response = denied_response(payload["id"])
                class Response:
                    status = 200
                    headers = {"content-type": "application/json", **response["headers"]}
                    def read(self, n):
                        return json.dumps(response["body"]).encode()
                    def close(self):
                        pass
                return Response()
        with ExitStack() as stack, redirect_stdout(io.StringIO()), tempfile.TemporaryDirectory() as directory:
            for stub in stubs.values():
                stack.enter_context(stub)
            status = worker.run_worker(BoundSession(), environment, root=Path(directory),
                verify_fn=lambda *a, **kw: worker.verify(*a, **kw, probe_factory=lambda *args: worker.GatewayProbe(*args, http=Http())))
            report = json.loads((Path(directory) / "evidence/aws/verification-result.json").read_text())
            self.assertEqual(status, 0)
            self.assertEqual(report, json.loads(written[environment["AD_REPORT_KEY"]]))
            checkpoint = json.loads(written["evidence/test/verification-result-gateway.json"])
            self.assertEqual(checkpoint["gateway_default_deny"]["status"], "PASS")
            self.assertEqual(checkpoint["model_invocation"]["status"], "NOT_RUN")
            self.assertEqual(checkpoint["result"], "IN_PROGRESS")
            self.assertTrue(report["model_invocation"]["attempts"][0]["catalog_observed"]["modelLifecycle"]["startOfLifeTime"].endswith("Z"))
            for stub in stubs.values():
                stub.assert_no_pending_responses()
        self.assertEqual(report["result"], "PASS")
        self.assertEqual(report["gate_a"], "NOT_RUN")
        self.assertEqual(report["model_invocation"]["strands_invocation"], "NOT_RUN")
        self.assertEqual(len(calls), 7)
        self.assertEqual({c["params"]["name"] for c in calls}, {"VendorPaymentTools___" + t for t in worker.TOOL_ARGUMENTS})
        self.assertNotIn("unit-test-secret", json.dumps(report))

    def test_unexpected_permit_stops_calls_and_keeps_gate_unpassed(self):
        class Sts:
            def get_caller_identity(self):
                return {"Account": worker.ACCOUNT, "Arn": f"arn:aws:sts::{worker.ACCOUNT}:assumed-role/ReadinessOpsAuthorityDeltaDeployer/test"}
        class Session:
            def client(self, *a):
                return Sts()
        class Probe:
            calls = []
            def __init__(self, *a):
                pass
            def call(self, tool, args, mcp_id):
                self.calls.append(tool)
                return {"http_status": 200, "headers": {"x-amzn-requestid": "aws-req"}, "body": {"jsonrpc": "2.0", "id": mcp_id, "result": {"isError": False, "content": []}}}
        environment = {"AD_EXPECTED_ACCOUNT": worker.ACCOUNT, "AD_REGION": worker.REGION, "CODEBUILD_BUILD_ID": "authority-delta-deploy:test", "AD_ARTIFACT_BUCKET": BINDING["artifact_bucket"]}
        report = {}
        with patch.object(worker, "snapshot", side_effect=[{"stable": {"ledger_count": 0}}, {"stable": {"ledger_count": 1}}]), patch.object(worker, "probe_model", return_value={"status": "PASS"}), redirect_stdout(io.StringIO()):
            worker.verify(Session(), environment, report, probe_factory=Probe)
        self.assertEqual(len(Probe.calls), 1)
        self.assertEqual(report["result"], "FAIL")
        self.assertFalse(report["gateway_default_deny"]["state_unchanged"])
        self.assertEqual(report["gate_a"], "NOT_RUN")

    def test_root_launcher_never_redeploys_and_retrieves_failed_evidence(self):
        class Cli:
            def __init__(self):
                self.calls = []
            def run(self, *args, **kw):
                self.calls.append(args)
                action = args[:2]
                if action == ("sts", "get-caller-identity"):
                    return {"Account": BINDING["account"], "Arn": f"arn:aws:iam::{BINDING['account']}:root"}
                if action == ("cloudformation", "describe-stacks"):
                    values = BINDING["resources"] if args[-1] == BINDING["application_stack"] else {"BuildProjectName": BINDING["project"], "ArtifactBucketName": BINDING["artifact_bucket"]}
                    return {"Stacks": [{"StackStatus": "CREATE_COMPLETE", "Outputs": [{"OutputKey": k, "OutputValue": v} for k,v in values.items()]}]}
                if action == ("codebuild", "list-builds-for-project"):
                    return {"ids": []}
                if action == ("s3api", "put-object"):
                    return {"VersionId": "immutable-version"}
                if action == ("codebuild", "start-build"):
                    if args[args.index("--buildspec-override")+1] != "buildspec.verify.yml":
                        raise AssertionError("Wrong buildspec would redeploy baseline.")
                    return {"build": {"id": "authority-delta-deploy:test"}}
                if action == ("codebuild", "batch-get-builds"):
                    return {"builds": [{"id": "authority-delta-deploy:test", "currentPhase": "COMPLETED", "buildStatus": "FAILED"}]}
                if action == ("s3api", "get-object"):
                    Path(args[-1]).write_text(json.dumps({"result": "FAIL", "scope": "LIVE_BASELINE_VERIFICATION_NOT_FULL_GATE_A", "build_id": "authority-delta-deploy:test", "source_sha256": "source-hash", "gateway_default_deny": {"status": "PASS"}, "model_invocation": {"status": "FAIL"}}))
                    return {"VersionId": "evidence-version"}
                raise AssertionError(f"Unexpected operation {action}")
        cli = Cli()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "infra/environments").mkdir(parents=True)
            (root / "infra/environments/development.json").write_text(json.dumps(BINDING))
            with patch.object(launcher, "ROOT", root), patch.object(launcher, "source_archive", side_effect=lambda p: (p.write_bytes(b"source"), "source-hash")[1]), redirect_stdout(io.StringIO()) as printed:
                with self.assertRaises(launcher.DeploymentError):
                    launcher.launch(cli)
                self.assertIn("AUTHORITY_DELTA_VERIFICATION", printed.getvalue())
                saved = list((root / "evidence/aws").glob("*/launch.json"))
                self.assertEqual(json.loads(saved[0].read_text())["report_version_id"], "evidence-version")
        self.assertNotIn(("sts", "assume-role"), [c[:2] for c in cli.calls])
        self.assertNotIn(("cloudformation", "deploy"), [c[:2] for c in cli.calls])

    def test_missing_final_report_recovers_checkpoint_but_never_passes(self):
        class Cli:
            def run(self, *args, **kw):
                action = args[:2]
                if action == ("sts", "get-caller-identity"):
                    return {"Account": BINDING["account"]}
                if action == ("codebuild", "list-builds-for-project"):
                    return {"ids": []}
                if action == ("s3api", "put-object"):
                    return {"VersionId": "source-version"}
                if action == ("codebuild", "start-build"):
                    return {"build": {"id": "authority-delta-deploy:test"}}
                if action == ("s3api", "get-object"):
                    if not args[args.index("--key") + 1].endswith("-gateway.json"):
                        raise launcher.DeploymentError("NoSuchKey")
                    Path(args[-1]).write_text(json.dumps({"result": "IN_PROGRESS", "build_id": "authority-delta-deploy:test", "source_sha256": "source-hash", "checkpoint_phase": "gateway", "gate_a": "NOT_RUN", "gateway_default_deny": {"status": "PASS"}}))
                    return {"VersionId": "checkpoint-version"}
                raise AssertionError(action)
        with tempfile.TemporaryDirectory() as directory, ExitStack() as stack:
            root = Path(directory)
            (root / "infra/environments").mkdir(parents=True)
            (root / "infra/environments/development.json").write_text(json.dumps(BINDING))
            stack.enter_context(patch.object(launcher, "ROOT", root))
            stack.enter_context(patch.object(launcher, "stack_outputs", side_effect=[{"ArtifactBucketName": BINDING["artifact_bucket"], "BuildProjectName": BINDING["project"]}, BINDING["resources"]]))
            stack.enter_context(patch.object(launcher, "source_archive", side_effect=lambda p: (p.write_bytes(b"source"), "source-hash")[1]))
            stack.enter_context(patch.object(launcher, "wait_terminal", return_value={"buildStatus": "FAILED"}))
            details = stack.enter_context(patch.object(launcher, "show_failure_details"))
            printed = stack.enter_context(redirect_stdout(io.StringIO()))
            with self.assertRaisesRegex(launcher.DeploymentError, "No verification report"):
                launcher.launch(Cli())
            self.assertIn("AUTHORITY_DELTA_PARTIAL_GATEWAY_EVIDENCE", printed.getvalue())
            self.assertIn("final verification remains incomplete", printed.getvalue())
            recovered = json.loads(next((root / "evidence/aws").glob("*/checkpoint-gateway.json")).read_text())
            self.assertEqual(recovered["result"], "IN_PROGRESS")
            self.assertEqual(recovered["gate_a"], "NOT_RUN")
            details.assert_called_once()
