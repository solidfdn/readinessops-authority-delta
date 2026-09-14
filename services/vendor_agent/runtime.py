"""Fixed-release AgentCore HTTP service; the deployed artifact owns all bindings.

The invoke_tool operation is a bounded canary operation. Its caller is restricted
by the Runtime resource policy; Gateway Policy remains the tool authorizer.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import re
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import uuid

from authority_delta.canonical import sha256_json
from authority_delta.domain import ContractError, ReleaseDefinition
from authority_delta.gateway_probe import GatewayProbe, validate_endpoint
from services.vendor_agent.evaluator import VendorRuntimeEvaluator


MAX_REQUEST_BYTES = 4096
MAX_RESPONSE_BYTES = 131072
TOOL_ARGUMENTS = {
    "prepare_vendor_payment": "payment_request_id",
    "update_vendor_bank": "change_request_id",
    "export_credentials": "export_request_id",
}
TARGET_NAME = "VendorPaymentTools"


def unique_object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ContractError("Duplicate JSON keys are not accepted")
        value[key] = item
    return value


def reject_constant(value):
    raise ContractError("Non-finite JSON numbers are not accepted")


def load_release(path):
    source = Path(path).read_bytes()
    if len(source) > 65536:
        raise ContractError("Invalid deployed release document")
    value = json.loads(source, object_pairs_hook=unique_object, parse_constant=reject_constant)
    required = {"schema_version", "release_id", "definition", "release_definition_hash",
                "request_registry_snapshot_hash"}
    if not isinstance(value, dict) or set(value) != required or value["schema_version"] != "1.0":
        raise ContractError("Invalid deployed release document")
    definition = dict(value["definition"])
    if definition.pop("release_id", None) != value["release_id"]:
        raise ContractError("Invalid deployed release identity")
    release = ReleaseDefinition.from_mapping(value["release_id"], definition)
    if sha256_json(release.as_contract()) != value["release_definition_hash"]:
        raise ContractError("Invalid deployed release digest")
    if not re.fullmatch(r"[0-9a-f]{64}", value["request_registry_snapshot_hash"]):
        raise ContractError("Invalid deployed registry digest")
    return value, release


class VendorRuntimeService:
    def __init__(self, *, release_path, environment, session, gateway_probe=None):
        document, release = load_release(release_path)
        self.fixed = {k: document[k] for k in ("schema_version", "release_id",
            "release_definition_hash", "request_registry_snapshot_hash")}
        self.account = environment["AD_ACCOUNT_ID"]
        self.region = environment["AD_REGION"]
        self.role_name = environment["AD_EXPECTED_ROLE_NAME"]
        if not re.fullmatch(r"[0-9]{12}", self.account):
            raise ContractError("Invalid account binding")
        if not re.fullmatch(r"[A-Za-z0-9+=,.@_-]{1,64}", self.role_name):
            raise ContractError("Invalid execution role binding")
        validate_endpoint(environment["AD_GATEWAY_URL"], environment["AD_GATEWAY_ID"], self.region)
        self.sts = session.client("sts", region_name=self.region)
        self.evaluator = VendorRuntimeEvaluator(release=release,
            definition_hash=document["release_definition_hash"],
            fixture_snapshot_hash=document["request_registry_snapshot_hash"],
            registry_table=environment["AD_REGISTRY_TABLE"],
            dynamodb=session.client("dynamodb", region_name=self.region))
        self.gateway = gateway_probe or GatewayProbe(session, environment["AD_GATEWAY_URL"],
            environment["AD_GATEWAY_ID"], self.region)

    def error(self, error_type="ContractError", *, identity=None):
        return {**self.fixed, "result": "ERROR", "identity": identity,
            "error": {"type": error_type, "message": "Runtime request could not be completed."}}

    def invoke(self, payload):
        if not isinstance(payload, dict):
            return 400, self.error()
        operation = payload.get("operation")
        keys = {"operation", "request_id"} if operation == "evaluate" else {"operation", "request_id", "tool"}
        if not isinstance(operation, str) or operation not in {"evaluate", "invoke_tool"} or set(payload) != keys:
            return 400, self.error()
        request_id = payload["request_id"]
        if not isinstance(request_id, str) or not re.fullmatch(r"req-[0-9a-f]{64}", request_id):
            return 400, self.error()
        if operation == "invoke_tool" and (not isinstance(payload["tool"], str) or payload["tool"] not in TOOL_ARGUMENTS):
            return 400, self.error()
        identity = None
        try:
            caller = self.sts.get_caller_identity()
            identity = {"account": caller["Account"], "arn": caller["Arn"],
                "request_id": caller.get("ResponseMetadata", {}).get("RequestId")}
            expected = "arn:aws:sts::" + self.account + ":assumed-role/" + self.role_name + "/"
            if identity["account"] != self.account or not identity["arn"].startswith(expected) or not identity["request_id"]:
                raise ContractError("Runtime execution identity mismatch")
            result = {**self.fixed, "result": "OBSERVED", "operation": operation,
                "request_id": request_id, "identity": identity}
            if operation == "evaluate":
                result["evaluation"] = self.evaluator.evaluate({"request_id": request_id})
            else:
                tool = payload["tool"]
                result["tool"] = TARGET_NAME + "___" + tool
                result["mcp_id"] = "ad-runtime-" + uuid.uuid4().hex
                # Unknown immutable IDs and mismatched known tool/ID pairs reach
                # Gateway, so the canary proves Policy denial, not local refusal.
                result["gateway_response"] = self.gateway.call(result["tool"],
                    {TOOL_ARGUMENTS[tool]: request_id}, result["mcp_id"])
            return 200, result
        except Exception as exc:
            return 500, self.error(type(exc).__name__, identity=identity)


class RuntimeRequestHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "AuthorityDeltaRuntime"
    sys_version = ""

    def setup(self):
        super().setup()
        self.connection.settimeout(10)

    def log_message(self, format, *args):
        # Paths, bodies and headers are never recorded by the HTTP server.
        return

    def send_json(self, status, value):
        try:
            encoded = json.dumps(value, ensure_ascii=False, allow_nan=False,
                separators=(",", ":")).encode("utf-8")
            if len(encoded) > MAX_RESPONSE_BYTES:
                raise ValueError("Response limit exceeded")
        except (ValueError, TypeError):
            status = 500
            encoded = json.dumps(self.server.application.error("SerializationError"),
                separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(encoded)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(encoded)
        self.close_connection = True

    def do_GET(self):
        if self.path == "/ping":
            self.send_json(200, {"status": "Healthy"})
        else:
            self.send_json(404, self.server.application.error())

    def do_POST(self):
        if self.path != "/invocations":
            self.send_json(404, self.server.application.error())
            return
        try:
            lengths = self.headers.get_all("Content-Length", [])
            if len(lengths) != 1 or self.headers.get("Transfer-Encoding"):
                raise ContractError("Invalid request framing")
            length = int(lengths[0])
            if length < 1 or length > MAX_REQUEST_BYTES:
                self.send_json(413, self.server.application.error())
                return
            if self.headers.get_content_type() != "application/json":
                self.send_json(415, self.server.application.error())
                return
            raw = self.rfile.read(length)
            if len(raw) != length:
                raise ContractError("Incomplete request")
            payload = json.loads(raw.decode("utf-8"), object_pairs_hook=unique_object,
                parse_constant=reject_constant)
            status, value = self.server.application.invoke(payload)
        except (ValueError, UnicodeError, OSError):
            status, value = 400, self.server.application.error()
        except Exception as exc:
            status, value = 500, self.server.application.error(type(exc).__name__)
        self.send_json(status, value)


def make_server(application, host="0.0.0.0", port=8080):
    server = ThreadingHTTPServer((host, port), RuntimeRequestHandler)
    server.daemon_threads = True
    server.application = application
    return server


def main():
    import boto3
    from botocore.config import Config
    session = boto3.Session(region_name=os.environ["AD_REGION"])
    # Configure all clients created by this isolated application. Tool HTTP calls
    # independently disable retries to avoid duplicate sandbox side effects.
    session._session.set_default_client_config(Config(connect_timeout=10, read_timeout=45,
        retries={"total_max_attempts": 1}))
    application = VendorRuntimeService(release_path=Path(__file__).resolve().with_name("release.json"),
        environment=os.environ, session=session)
    with make_server(application) as server:
        server.serve_forever()


if __name__ == "__main__":
    main()
