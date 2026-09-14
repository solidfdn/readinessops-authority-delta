from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
import unittest

from services.sandbox.handler import ToolInvocationError, invoke


ROOT = Path(__file__).resolve().parents[1]


class MemoryBackend:
    def __init__(self, requests: dict[str, dict[str, object]]) -> None:
        self.requests = requests
        self.ledger: dict[str, dict[str, object]] = {}

    def get_request(self, request_id: str) -> dict[str, object] | None:
        return self.requests.get(request_id)

    def put_execution_if_absent(self, business_key: str, record: dict[str, object]) -> bool:
        if business_key in self.ledger:
            return False
        self.ledger[business_key] = dict(record)
        return True

    def get_execution(self, business_key: str) -> dict[str, object] | None:
        return self.ledger.get(business_key)


def context(tool_name: str) -> SimpleNamespace:
    return SimpleNamespace(client_context=SimpleNamespace(custom={
        "bedrockAgentCoreToolName": f"VendorPaymentTools___{tool_name}",
        "bedrockAgentCoreAwsRequestId": "aws-request-1",
        "bedrockAgentCoreMcpMessageId": "mcp-message-1",
        "bedrockAgentCoreGatewayId": "gateway-1",
        "bedrockAgentCoreTargetId": "target-1",
    }))


class SandboxHandlerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        fixture = json.loads((ROOT / "fixtures/decision_cases.json").read_text(encoding="utf-8"))
        cls.cases = {item["case_id"]: item for item in fixture["cases"] + fixture["auxiliary_cases"]}

    def backend(self) -> MemoryBackend:
        return MemoryBackend({item["request_id"]: item["request"] for item in self.cases.values()})

    def test_prepare_payment_is_idempotent_by_business_key(self) -> None:
        backend = self.backend()
        request_id = self.cases["P-001"]["request_id"]
        first = invoke({"payment_request_id": request_id}, context("prepare_vendor_payment"), backend)
        second = invoke({"payment_request_id": request_id}, context("prepare_vendor_payment"), backend)
        self.assertFalse(first["idempotent_replay"])
        self.assertTrue(second["idempotent_replay"])
        self.assertEqual(len(backend.ledger), 1)

    def test_tool_never_accepts_caller_supplied_business_facts(self) -> None:
        backend = self.backend()
        request_id = self.cases["P-001"]["request_id"]
        with self.assertRaises(ToolInvocationError):
            invoke(
                {"payment_request_id": request_id, "amount_minor": 1},
                context("prepare_vendor_payment"),
                backend,
            )
        self.assertEqual(backend.ledger, {})

    def test_unknown_and_mutated_registry_requests_never_reach_ledger(self) -> None:
        backend = self.backend()
        with self.assertRaises(ToolInvocationError):
            invoke({"payment_request_id": "req-unknown"}, context("prepare_vendor_payment"), backend)
        request_id = self.cases["P-001"]["request_id"]
        backend.requests[request_id] = dict(backend.requests[request_id], amount_minor=1)
        with self.assertRaises(ToolInvocationError):
            invoke({"payment_request_id": request_id}, context("prepare_vendor_payment"), backend)
        self.assertEqual(backend.ledger, {})

    def test_forbidden_tool_would_leave_a_detectable_marker_if_policy_failed(self) -> None:
        backend = self.backend()
        request_id = self.cases["P-005"]["request_id"]
        result = invoke({"change_request_id": request_id}, context("update_vendor_bank"), backend)
        self.assertEqual(result["status"], "SANDBOX_FORBIDDEN_ACTION_REACHED")
        self.assertEqual(len(backend.ledger), 1)

    def test_direct_lambda_invocation_without_gateway_context_is_rejected(self) -> None:
        backend = self.backend()
        request_id = self.cases["P-001"]["request_id"]
        with self.assertRaises(ToolInvocationError):
            invoke({"payment_request_id": request_id}, SimpleNamespace(), backend)
        self.assertEqual(backend.ledger, {})


if __name__ == "__main__":
    unittest.main()
