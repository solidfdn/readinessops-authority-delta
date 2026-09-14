"""Signed MCP calls with strict policy-denial evidence classification."""
from __future__ import annotations

import json
import re

SAFE_HEADERS = {"x-amzn-requestid", "x-amzn-request-id", "x-amz-request-id",
    "x-amzn-trace-id", "x-amzn-bedrock-agentcore-gateway-request-id"}
REQUEST_HEADERS = SAFE_HEADERS - {"x-amzn-trace-id"}


def validate_endpoint(url, gateway_id, region):
    if not re.fullmatch(r"[a-z0-9-]+", gateway_id) or not re.fullmatch(r"[a-z0-9-]+", region):
        raise ValueError("Invalid Gateway or Region identifier.")
    expected = f"https://{gateway_id}.gateway.bedrock-agentcore.{region}.amazonaws.com/mcp"
    if url != expected:
        raise ValueError("Refusing to send AWS credentials to an unbound endpoint.")


def decode_mcp(body, content_type):
    text = body.decode("utf-8")
    if "text/event-stream" not in content_type.lower():
        return json.loads(text)
    # Streamable HTTP can return a JSON-RPC envelope in SSE data fields.
    messages = []
    for block in text.replace("\r\n", "\n").split("\n\n"):
        data = "\n".join(line[5:].lstrip(" ") for line in block.splitlines() if line.startswith("data:"))
        if data and data != "[DONE]":
            messages.append(json.loads(data))
    envelopes = [m for m in messages if isinstance(m, dict) and ("result" in m or "error" in m)]
    if len(envelopes) != 1:
        raise ValueError("Expected exactly one MCP response envelope.")
    return envelopes[0]


def policy_denial(response, mcp_id):
    """403/IAM failure, missing tool, transport error and LLM refusal never pass."""
    body = response.get("body")
    if response.get("http_status") not in (200, 403) or not isinstance(body, dict):
        return False
    if body.get("jsonrpc") != "2.0" or body.get("id") != mcp_id:
        return False
    correlated = any(response.get("headers", {}).get(h) for h in REQUEST_HEADERS)
    if not correlated or ("error" in body and "result" in body):
        return False
    prefix = "Tool Execution Denied: Tool call not allowed due to policy enforcement"
    if "error" in body:
        # Live Tokyo response, 2026-09-08, request 9194ab47-cda4-4738-be28-0c52f1a43ac7.
        # -32002 alone is not enough: IAM/schema/unknown-tool errors are not Policy DENY.
        error = body["error"]
        return bool(isinstance(error, dict) and type(error.get("code")) is int
            and error["code"] == -32002 and isinstance(error.get("message"), str)
            and error["message"].startswith(prefix))
    result = body.get("result")
    if not isinstance(result, dict) or result.get("isError") is not True:
        return False
    content = result.get("content", [])
    if not isinstance(content, list):
        return False
    texts = [c.get("text", "") for c in content if isinstance(c, dict) and c.get("type") == "text"]
    recognized = any(isinstance(t, str) and t.startswith("AuthorizeActionException - " + prefix) for t in texts)
    return bool(recognized)


class GatewayProbe:
    def __init__(self, session, url, gateway_id, region, http=None):
        import urllib3
        validate_endpoint(url, gateway_id, region)
        self.session, self.url, self.region = session, url, region
        self.http = http or urllib3.PoolManager(cert_reqs="CERT_REQUIRED")

    def call(self, tool, arguments, mcp_id):
        from botocore.auth import SigV4Auth
        from botocore.awsrequest import AWSRequest
        import urllib3
        payload = {"jsonrpc": "2.0", "id": mcp_id, "method": "tools/call",
            "params": {"name": tool, "arguments": arguments}}
        encoded = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        request = AWSRequest(method="POST", url=self.url, data=encoded,
            headers={"Content-Type": "application/json", "Accept": "application/json, text/event-stream"})
        credentials = self.session.get_credentials()
        if credentials is None:
            raise ValueError("CodeBuild service credentials unavailable.")
        SigV4Auth(credentials.get_frozen_credentials(), "bedrock-agentcore", self.region).add_auth(request)
        # Never log signed headers; never follow redirects or retry tool calls.
        response = self.http.request("POST", self.url, body=encoded, headers=dict(request.headers),
            timeout=urllib3.Timeout(connect=10, read=45), retries=False, redirect=False, preload_content=False)
        try:
            body = response.read(65537)
            if len(body) > 65536:
                raise ValueError("Gateway evidence response exceeds 64 KiB.")
            headers = {k.lower(): v for k, v in response.headers.items() if k.lower() in SAFE_HEADERS}
            evidence = {"http_status": response.status, "headers": headers}
            try:
                evidence["body"] = decode_mcp(body, response.headers.get("content-type", ""))
            except (ValueError, UnicodeError):
                # Tool inputs are synthetic; retain diagnostic response text, never request headers.
                evidence["body_text"] = body.decode("utf-8", errors="replace")[:4000]
            return evidence
        finally:
            response.close()
