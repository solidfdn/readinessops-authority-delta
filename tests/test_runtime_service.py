from __future__ import annotations

from contextlib import contextmanager
import copy
import hashlib
import http.client
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import unittest
from zipfile import ZipFile

import boto3
from botocore.stub import Stubber
from botocore.validate import validate_parameters

from authority_delta.gateway_probe import GatewayProbe, policy_denial
from authority_delta.registry import FixtureBundle
from scripts.build_registry_seed import build_transaction
from scripts.build_runtime_artifact import build, release_document
from services.vendor_agent.runtime import VendorRuntimeService, make_server


ROOT = Path(__file__).resolve().parents[1]
ACCOUNT = "538522204923"
REGION = "ap-northeast-1"
GATEWAY = "authority-delta-gateway-rvplvkk1t7"
GATEWAY_URL = f"https://{GATEWAY}.gateway.bedrock-agentcore.{REGION}.amazonaws.com/mcp"


class GatewayHTTPDouble:
    def __init__(self):
        self.calls = []

    def request(self, method, url, **kwargs):
        assert method == "POST" and url == GATEWAY_URL
        assert kwargs["retries"] is False and kwargs["redirect"] is False
        envelope = json.loads(kwargs["body"])
        self.calls.append(envelope)
        content = json.dumps({"jsonrpc": "2.0", "id": envelope["id"], "error": {
            "code": -32002,
            "message": "Tool Execution Denied: Tool call not allowed due to policy enforcement [No policy applies to the request (denied by default).]"
        }}).encode()

        class Response:
            status = 200
            headers = {"Content-Type": "application/json", "x-amzn-requestid": "gateway-live-shape-request",
                "Authorization": "must-never-be-returned"}
            def read(self, limit):
                return content[:limit]
            def close(self):
                pass
        return Response()


class SessionClients:
    def __init__(self, session, clients):
        self.session, self.clients = session, clients
    def client(self, service_name, **kwargs):
        return self.clients[service_name]
    def get_credentials(self):
        return self.session.get_credentials()


class RuntimeServiceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fixtures = FixtureBundle.load(ROOT / "fixtures/decision_cases.json")
        cls.items = {x["Put"]["Item"]["request_id"]["S"]: x["Put"]["Item"]
            for x in build_transaction(cls.fixtures, "registry-test")}

    @contextmanager
    def app(self, release="V1", identity_arn=None):
        with tempfile.TemporaryDirectory() as temporary:
            release_path = Path(temporary) / "release.json"
            release_path.write_text(json.dumps(release_document(self.fixtures, release)))
            env = {"AD_ACCOUNT_ID": ACCOUNT, "AD_REGION": REGION,
                "AD_EXPECTED_ROLE_NAME": f"authority-delta-vendor-{release.lower()}-runtime",
                "AD_GATEWAY_URL": GATEWAY_URL, "AD_GATEWAY_ID": GATEWAY,
                "AD_REGISTRY_TABLE": "registry-test"}
            session = boto3.Session(region_name=REGION, aws_access_key_id="unit-test-key",
                aws_secret_access_key="unit-test-secret", aws_session_token="unit-test-session-token")
            clients = {name: session.client(name) for name in ("sts", "dynamodb")}
            wrapped = SessionClients(session, clients)
            gateway = GatewayHTTPDouble()
            service = VendorRuntimeService(release_path=release_path, environment=env,
                session=wrapped, gateway_probe=GatewayProbe(wrapped, GATEWAY_URL, GATEWAY, REGION, http=gateway))
            with Stubber(clients["sts"]) as sts, Stubber(clients["dynamodb"]) as ddb:
                def queue_identity():
                    sts.add_response("get_caller_identity", {
                        "Account": ACCOUNT,
                        "Arn": identity_arn or f"arn:aws:sts::{ACCOUNT}:assumed-role/{env['AD_EXPECTED_ROLE_NAME']}/runtime-session",
                        "UserId": "RUNTIME:session", "ResponseMetadata": {"RequestId": "sts-observed-request", "HTTPStatusCode": 200}}, {})
                yield service, queue_identity, ddb, gateway
                sts.assert_no_pending_responses()
                ddb.assert_no_pending_responses()

    @contextmanager
    def http_server(self, service):
        with make_server(service, host="127.0.0.1", port=0) as server:
            worker = threading.Thread(target=lambda: server.serve_forever(poll_interval=0.01), daemon=True)
            worker.start()
            try:
                yield server.server_address[1]
            finally:
                server.shutdown()
                worker.join(timeout=2)

    def request(self, port, payload=None, *, path="/invocations", method="POST", raw=None, headers=None):
        connection = http.client.HTTPConnection("127.0.0.1", port, timeout=3)
        encoded = raw if raw is not None else (json.dumps(payload).encode() if payload is not None else None)
        connection.request(method, path, body=encoded, headers=headers or {"Content-Type": "application/json"})
        response = connection.getresponse()
        content = response.read()
        status = response.status
        connection.close()
        self.assertEqual(response.getheader("Content-Type"), "application/json")
        return status, json.loads(content), content

    def test_actual_http_entry_replays_each_release_without_tool_execution(self):
        observations = {}
        for release in ("V1", "V2"):
            with self.app(release) as (service, identity, ddb, gateway), self.http_server(service) as port:
                self.assertEqual(self.request(port, method="GET", path="/ping")[:2], (200, {"status": "Healthy"}))
                observations[release] = {}
                for case in self.fixtures.all_cases:
                    identity()
                    ddb.add_response("get_item", {"Item": self.items[case.request_id],
                        "ResponseMetadata": {"RequestId": "registry-" + case.case_id}}, {
                        "TableName": "registry-test", "Key": {"request_id": {"S": case.request_id}}, "ConsistentRead": True})
                    status, value, encoded = self.request(port, {"operation": "evaluate", "request_id": case.request_id})
                    self.assertEqual(status, 200)
                    self.assertEqual(value["identity"]["request_id"], "sts-observed-request")
                    self.assertEqual(value["release_id"], release)
                    self.assertEqual(value["evaluation"]["gateway_outcome"], "NOT_RUN")
                    self.assertNotIn(b"unit-test-secret", encoded)
                    observations[release][case.case_id] = value["evaluation"]["judgment"]
                self.assertEqual(gateway.calls, [])
        self.assertEqual([key for key in observations["V1"] if observations["V1"][key] != observations["V2"][key]], ["P-002"])

    def test_real_http_and_sigv4_probe_preserve_policy_response_for_all_three_tools_and_unknown_id(self):
        unknown = "req-" + "0" * 64
        with self.app("V2") as (service, identity, ddb, gateway), self.http_server(service) as port:
            for tool in ("prepare_vendor_payment", "update_vendor_bank", "export_credentials"):
                identity()
                status, value, encoded = self.request(port, {"operation": "invoke_tool", "tool": tool, "request_id": unknown})
                self.assertEqual(status, 200)
                self.assertTrue(policy_denial(value["gateway_response"], value["mcp_id"]))
                self.assertEqual(value["request_id"], unknown)
                self.assertEqual(value["tool"], "VendorPaymentTools___" + tool)
                for secret in (b"unit-test-key", b"unit-test-secret", b"unit-test-session-token", b"must-never-be-returned", b"Authorization"):
                    self.assertNotIn(secret, encoded)
            self.assertEqual(len(gateway.calls), 3)
            self.assertEqual(gateway.calls[0]["params"]["arguments"], {"payment_request_id": unknown})
            self.assertEqual(gateway.calls[1]["params"]["arguments"], {"change_request_id": unknown})
            self.assertEqual(gateway.calls[2]["params"]["arguments"], {"export_request_id": unknown})

    def test_http_rejects_overrides_bad_framing_unknown_tools_and_duplicate_json_without_aws(self):
        good = {"operation": "evaluate", "request_id": self.fixtures.cases[0].request_id}
        with self.app() as (service, identity, ddb, gateway), self.http_server(service) as port:
            for field in ("release_id", "verified", "role_arn", "gateway_url"):
                self.assertEqual(self.request(port, {**good, field: "injected"})[0], 400)
            for payload in ([good], {**good, "operation": []}, {**good, "request_id": 3},
                {**good, "operation": "invoke_tool", "tool": "missing_tool"}):
                self.assertEqual(self.request(port, payload)[0], 400)
            self.assertEqual(self.request(port, raw=b'{"operation":"evaluate","operation":"invoke_tool"}')[0], 400)
            self.assertEqual(self.request(port, raw=b'{"operation":NaN}')[0], 400)
            self.assertEqual(self.request(port, raw=b"{" * 4097)[0], 413)
            self.assertEqual(self.request(port, good, headers={"Content-Type": "text/plain"})[0], 415)
            self.assertEqual(self.request(port, good, path="/invocations?release=V2")[0], 404)
            self.assertEqual(gateway.calls, [])

    def test_wrong_execution_identity_fails_before_registry_and_gateway(self):
        with self.app(identity_arn=f"arn:aws:iam::{ACCOUNT}:root") as (service, identity, ddb, gateway), self.http_server(service) as port:
            identity()
            status, value, encoded = self.request(port, {"operation": "invoke_tool", "tool": "prepare_vendor_payment", "request_id": "req-" + "0" * 64})
            self.assertEqual(status, 500)
            self.assertEqual(value["result"], "ERROR")
            self.assertEqual(value["identity"]["arn"], f"arn:aws:iam::{ACCOUNT}:root")
            self.assertEqual(gateway.calls, [])

    def test_upstream_exception_does_not_disclose_secret_or_claim_deny(self):
        class BrokenGateway:
            def call(self, *args):
                raise RuntimeError("Authorization=secret-should-not-leak")
        with self.app() as (service, identity, ddb, gateway), self.http_server(service) as port:
            service.gateway = BrokenGateway()
            identity()
            status, value, encoded = self.request(port, {"operation": "invoke_tool", "tool": "prepare_vendor_payment", "request_id": "req-" + "0" * 64})
            self.assertEqual(status, 500)
            self.assertEqual(value["error"]["type"], "RuntimeError")
            self.assertNotIn(b"secret-should-not-leak", encoded)
            self.assertNotIn("gateway_response", value)

    def test_built_artifact_is_deterministic_and_imports_without_local_site_packages(self):
        with tempfile.TemporaryDirectory() as temporary:
            temp = Path(temporary)
            first = build(self.fixtures, "V1", temp / "a.zip")
            second = build(self.fixtures, "V1", temp / "b.zip")
            candidate = build(self.fixtures, "V2", temp / "c.zip")
            self.assertEqual(first["sha256"], second["sha256"])
            self.assertNotEqual(first["sha256"], candidate["sha256"])
            self.assertLess(first["size_bytes"], 250 * 1024 * 1024)
            extracted = temp / "extracted"
            with ZipFile(temp / "a.zip") as archive:
                names = archive.namelist()
                self.assertIn("runtime.py", names)
                self.assertNotIn("fixtures/decision_cases.json", names)
                self.assertFalse(any("__pycache__" in name for name in names))
                self.assertFalse(any(name.endswith((".so", ".dll", ".dylib")) for name in names))
                document = json.loads(archive.read("release.json"))
                self.assertEqual(document["release_definition_hash"], first["release_definition_hash"])
                self.assertEqual(document["release_id"], "V1")
                self.assertNotIn("expected", document)
                self.assertEqual((archive.getinfo("runtime.py").external_attr >> 16) & 0o777, 0o644)
                self.assertEqual((archive.getinfo("authority_delta/").external_attr >> 16) & 0o777, 0o755)
                archive.extractall(extracted)
            result = subprocess.run([sys.executable, "-S", "-c",
                "import runtime,boto3,botocore,urllib3,rfc8785; print(runtime.load_release('release.json')[1].release_id, boto3.__version__, botocore.__version__)"],
                cwd=extracted, capture_output=True, text=True, timeout=30)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout.strip(), "V1 1.43.89 1.43.89")

    def test_template_runtime_shapes_match_pinned_sdk_and_external_resources_are_not_recreated(self):
        template = json.loads((ROOT / "infra/vendor-runtimes/template.json").read_text())
        resources = template["Resources"]
        self.assertEqual({x["Type"] for x in resources.values()}, {
            "AWS::IAM::Role", "AWS::BedrockAgentCore::Runtime", "AWS::BedrockAgentCore::RuntimeEndpoint",
            "AWS::BedrockAgentCore::ResourcePolicy"})
        control = boto3.client("bedrock-agentcore-control", region_name=REGION,
            aws_access_key_id="unit-test", aws_secret_access_key="unit-test")
        create_shape = control.meta.service_model.operation_model("CreateAgentRuntime").input_shape
        endpoint_shape = control.meta.service_model.operation_model("CreateAgentRuntimeEndpoint").input_shape
        for label in ("V1", "V2"):
            properties = resources[label + "Runtime"]["Properties"]
            code = properties["AgentRuntimeArtifact"]["CodeConfiguration"]
            self.assertEqual(properties["ProtocolConfiguration"], "HTTP")
            self.assertEqual(code["Code"]["S3"]["VersionId"], {"Ref": label + "ArtifactVersionId"})
            self.assertEqual(properties["RoleArn"], {"Fn::GetAtt": [label + "ExecutionRole", "Arn"]})
            converted = {"agentRuntimeName": properties["AgentRuntimeName"],
                "agentRuntimeArtifact": {"codeConfiguration": {"code": {"s3": {
                    "bucket": "artifact-bucket-test", "prefix": "runtime/test.zip", "versionId": "fixed-version"}},
                    "runtime": code["Runtime"], "entryPoint": code["EntryPoint"]}},
                "roleArn": f"arn:aws:iam::{ACCOUNT}:role/authority-delta-test",
                "networkConfiguration": {"networkMode": properties["NetworkConfiguration"]["NetworkMode"]},
                "protocolConfiguration": {"serverProtocol": properties["ProtocolConfiguration"]},
                "lifecycleConfiguration": {"idleRuntimeSessionTimeout": properties["LifecycleConfiguration"]["IdleRuntimeSessionTimeout"],
                    "maxLifetime": properties["LifecycleConfiguration"]["MaxLifetime"]}}
            validate_parameters(converted, create_shape)
            endpoint = resources[label + "Endpoint"]["Properties"]
            validate_parameters({"agentRuntimeId": properties["AgentRuntimeName"] + "-abcdefghij",
                "name": endpoint["Name"], "agentRuntimeVersion": "1"}, endpoint_shape)
            self.assertEqual(endpoint["AgentRuntimeId"], {"Fn::GetAtt": [label + "Runtime", "AgentRuntimeId"]})
            resource_policy = resources[label + "RuntimeResourcePolicy"]["Properties"]
            policy = json.loads(resource_policy["Policy"]["Fn::Sub"])
            deny = next(x for x in policy["Statement"] if x["Effect"] == "Deny")
            expected_principals = (["${DeployerRoleArn}", "${ApplicationCanaryRoleArn}",
                                    "${NormalInvocationRoleArn}"]
                if label == "V2" else "${DeployerRoleArn}")
            self.assertEqual(deny["Condition"], {
                "ArnNotEquals": {"aws:PrincipalArn": expected_principals}})
            self.assertEqual(deny["Resource"], "${" + label + "Runtime.AgentRuntimeArn}")
            role = resources[label + "ExecutionRole"]["Properties"]
            self.assertTrue(role["RoleName"].startswith("authority-delta-"))
            grants = role["Policies"][0]["PolicyDocument"]["Statement"]
            actions = {a for grant in grants for a in (grant["Action"] if isinstance(grant["Action"], list) else [grant["Action"]])}
            self.assertTrue({"dynamodb:GetItem", "bedrock-agentcore:InvokeGateway", "s3:GetObjectVersion"} <= actions)
            self.assertFalse({"lambda:InvokeFunction", "dynamodb:PutItem", "bedrock:InvokeModel", "bedrock-agentcore:CreatePolicy"} & actions)
        self.assertNotEqual(resources["V1ExecutionRole"]["Properties"]["RoleName"], resources["V2ExecutionRole"]["Properties"]["RoleName"])


if __name__ == "__main__":
    unittest.main()
