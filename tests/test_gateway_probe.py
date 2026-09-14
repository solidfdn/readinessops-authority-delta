import copy
import io
import json
from pathlib import Path
import unittest

import boto3

from authority_delta.gateway_probe import GatewayProbe, decode_mcp, policy_denial, validate_endpoint


def denied_response(mcp_id="probe-1"):
    return {"http_status": 200, "headers": {"x-amzn-requestid": "aws-request-1"}, "body": {
        "jsonrpc": "2.0", "id": mcp_id, "result": {"isError": True, "content": [{"type": "text",
        "text": "AuthorizeActionException - Tool Execution Denied: Tool call not allowed due to policy enforcement [No policy applies to the request (denied by default).]"}]}}}


class GatewayProbeTests(unittest.TestCase):
    def test_actual_tokyo_jsonrpc_error_and_negative_variants(self):
        path = Path(__file__).resolve().parents[1] / "evidence/aws/20260908-055108-verification-v1-user-reported.json"
        report = json.loads(path.read_text())
        call = report["gateway_calls"][0]
        self.assertEqual(call["status"], "FAIL")  # Preserve the original faulty result.
        self.assertTrue(policy_denial(call["response"], call["mcp_id"]))
        self.assertEqual(report["before"]["stable"], report["after"]["stable"])
        self.assertEqual(len(report["gateway_calls"]), 1)  # Not seven completed tests.
        for key, value in [("code", -32602), ("code", "-32002"), ("message", "AccessDeniedException"), ("message", "Tool not found")]:
            bad = copy.deepcopy(call["response"])
            bad["body"]["error"][key] = value
            with self.subTest(key=key, value=value):
                self.assertFalse(policy_denial(bad, call["mcp_id"]))
        for mutate in (lambda r: r["body"].update(id="other"), lambda r: r.update(headers={}),
                lambda r: r["body"].update(result={"isError": False}), lambda r: r.update(http_status=404)):
            bad = copy.deepcopy(call["response"])
            mutate(bad)
            self.assertFalse(policy_denial(bad, call["mcp_id"]))

    def test_only_correlated_policy_rejection_counts_as_deny(self):
        good = denied_response()
        self.assertTrue(policy_denial(good, "probe-1"))
        variants = [dict(good, http_status=404), dict(good, headers={}), dict(good, body=None),
            dict(good, body={"message": "User is not authorized to invoke this gateway"}),
            dict(good, http_status=403, body={"message": "AccessDeniedException"})]
        for body in [
            {"jsonrpc": "2.0", "id": "other", "result": good["body"]["result"]},
            {"jsonrpc": "2.0", "id": "probe-1", "error": {"code": -32602, "message": "Unknown tool"}},
            {"jsonrpc": "2.0", "id": "probe-1", "result": {"isError": False, "content": [{"type": "text", "text": "DENY"}]}},
            {"jsonrpc": "2.0", "id": "probe-1", "result": {"isError": True, "content": [{"type": "text", "text": "AccessDeniedException: missing IAM permission"}]}}]:
            variants.append(dict(good, body=body))
        for response in variants:
            with self.subTest(response=response):
                self.assertFalse(policy_denial(response, "probe-1"))

    def test_json_and_sse_envelopes_and_ambiguous_stream(self):
        body = denied_response()["body"]
        encoded = json.dumps(body)
        self.assertEqual(decode_mcp(encoded.encode(), "application/json"), body)
        self.assertEqual(decode_mcp((": ping\n\nevent: message\ndata: " + encoded + "\n\n").encode(), "text/event-stream"), body)
        with self.assertRaises(ValueError):
            decode_mcp(("data: " + encoded + "\n\n") .encode() * 2, "text/event-stream")

    def test_credentials_are_signed_only_for_bound_endpoint_and_not_saved(self):
        session = boto3.Session(aws_access_key_id="unit-test-key", aws_secret_access_key="unit-test-secret", aws_session_token="unit-test-token", region_name="ap-northeast-1")
        class Response:
            status = 200
            headers = {"content-type": "application/json", "x-amzn-requestid": "aws-request-1", "set-cookie": "not-evidence"}
            def read(self, n):
                return json.dumps(denied_response()["body"]).encode()
            def close(self):
                pass
        class Http:
            calls = []
            def request(self, *args, **kwargs):
                self.calls.append((args, kwargs))
                return Response()
        http = Http()
        url = "https://gateway-test.gateway.bedrock-agentcore.ap-northeast-1.amazonaws.com/mcp"
        probe = GatewayProbe(session, url, "gateway-test", "ap-northeast-1", http=http)
        result = probe.call("Tools___pay", {"payment_request_id": "req-1"}, "probe-1")
        args, sent = http.calls[0]
        self.assertEqual(args, ("POST", url))
        self.assertFalse(sent["retries"])
        self.assertFalse(sent["redirect"])
        self.assertIn("/ap-northeast-1/bedrock-agentcore/aws4_request", sent["headers"]["Authorization"])
        self.assertEqual(sent["headers"]["X-Amz-Security-Token"], "unit-test-token")
        self.assertTrue(policy_denial(result, "probe-1"))
        for excluded in ("unit-test-key", "unit-test-secret", "unit-test-token", "Authorization", "set-cookie"):
            self.assertNotIn(excluded, json.dumps(result))
        for bad_url in (url + "?redirect=elsewhere", url.replace("https", "http"), url.replace("amazonaws.com", "amazonaws.com.evil.example")):
            with self.assertRaises(ValueError):
                GatewayProbe(session, bad_url, "gateway-test", "ap-northeast-1", http=http)
        self.assertEqual(len(http.calls), 1)
