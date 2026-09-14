"""Exercise result/ledger correlation using the actual deployed handler logic."""
import copy
import json
from pathlib import Path
from types import SimpleNamespace
import unittest

from authority_delta.execution_evidence import (
    ExecutionEvidenceError, decode_ledger_items, validate_execution_evidence,
)
from services.sandbox.handler import invoke


class MemoryLedger:
    def __init__(self, request_id, request):
        self.requests = {request_id: request}
        self.records = {}

    def get_request(self, request_id):
        return self.requests.get(request_id)

    def put_execution_if_absent(self, key, record):
        if key in self.records:
            return False
        self.records[key] = copy.deepcopy(record)
        return True

    def get_execution(self, key):
        return self.records.get(key)

    def items(self):
        return [{"business_key": {"S": key}, "payload": {"S": json.dumps(record)}}
            for key, record in self.records.items()]


class ExecutionEvidenceTests(unittest.TestCase):
    def setUp(self):
        bundle = json.loads((Path(__file__).resolve().parents[1] / "fixtures/decision_cases.json").read_text())
        case = bundle["cases"][0]
        self.request_id, request = case["request_id"], case["request"]
        self.ledger = MemoryLedger(self.request_id, request)
        self.key = "conn-demo#" + request["fixture_dataset_id"] + "#" + self.request_id

    def call_handler(self, mcp="mcp-1", aws="aws-1"):
        context = SimpleNamespace(client_context=SimpleNamespace(custom={
            "bedrockAgentCoreToolName": "VendorPaymentTools___prepare_vendor_payment",
            "bedrockAgentCoreAwsRequestId": aws, "bedrockAgentCoreMcpMessageId": mcp,
            "bedrockAgentCoreGatewayId": "gateway-1", "bedrockAgentCoreTargetId": "target-1"}))
        return invoke({"payment_request_id": self.request_id}, context, self.ledger)

    def response(self, value, *, mcp="mcp-1", aws="aws-1", representation="text"):
        result = {"isError": False}
        if representation in ("text", "both"):
            result["content"] = [{"type": "text", "text": json.dumps(value)}]
        if representation in ("structured", "both"):
            result["structuredContent"] = copy.deepcopy(value)
        return {"http_status": 200, "headers": {"x-amzn-requestid": aws},
            "body": {"jsonrpc": "2.0", "id": mcp, "result": result}}

    def validate(self, response, before, after, mcp="mcp-1"):
        return validate_execution_evidence(response, mcp_id=mcp, request_id=self.request_id,
            business_key=self.key, gateway_id="gateway-1", target_id="target-1",
            before_items=before, after_items=after)

    def test_actual_handler_insert_then_cross_call_replay_keep_first_record(self):
        first = self.call_handler()
        after = self.ledger.items()
        for representation in ("text", "structured", "both"):
            with self.subTest(representation=representation):
                observed = self.validate(self.response(first, representation=representation), [], after)
                self.assertTrue(observed["created"])
                self.assertEqual(observed["outcome"], "ALLOW")
        replay = self.call_handler(mcp="mcp-2", aws="aws-2")
        observed = self.validate(self.response(replay, mcp="mcp-2", aws="aws-2"),
            after, self.ledger.items(), mcp="mcp-2")
        self.assertFalse(observed["created"])
        self.assertEqual(observed["aws_request_id"], "aws-2")
        self.assertEqual(observed["ledger_record"]["aws_request_id"], "aws-1")
        self.assertEqual(observed["ledger_record"]["mcp_message_id"], "mcp-1")

    def test_http_success_unstructured_text_and_conflicting_envelopes_do_not_pass(self):
        first = self.call_handler()
        good, after = self.response(first), self.ledger.items()
        mutations = [
            lambda r: r.update(http_status=403),
            lambda r: r.update(headers={}),
            lambda r: r["headers"].update({"x-amz-request-id": "other-aws"}),
            lambda r: r["body"].update(id="other-mcp"),
            lambda r: r["body"].update(error={"code": -32002, "message": "failure"}),
            lambda r: r["body"]["result"].update(isError=True),
            lambda r: r["body"]["result"].update(isError=0),
            lambda r: r["body"]["result"].update(content=[{"type": "text", "text": "Payment prepared successfully"}]),
            lambda r: r["body"]["result"].update(content=[]),
            lambda r: r["body"]["result"].update(structuredContent=dict(first, request_id="other")),
            lambda r: r["body"]["result"].update(content=r["body"]["result"]["content"] * 2),
        ]
        for index, mutate in enumerate(mutations):
            bad = copy.deepcopy(good)
            mutate(bad)
            with self.subTest(index=index), self.assertRaises(ExecutionEvidenceError):
                self.validate(bad, [], after)
        with self.assertRaises(ExecutionEvidenceError):
            self.validate(good, [], [])
        alternate = self.response(first, representation="both")
        alternate["body"]["result"]["content"][0]["text"] = json.dumps(dict(first, idempotent_replay=0))
        with self.assertRaises(ExecutionEvidenceError):
            self.validate(alternate, [], after)

    def test_all_execution_bindings_and_finite_contract_are_required(self):
        first = self.call_handler()
        good, after = self.response(first), self.ledger.items()
        for field in ("request_id", "business_key", "status", "idempotent_replay"):
            for replacement in (None, "not-the-current-value"):
                bad = dict(first, **{field: replacement})
                with self.subTest(field=field, replacement=replacement), self.assertRaises(ExecutionEvidenceError):
                    self.validate(self.response(bad), [], after)
        for field in ("request_id", "business_key", "gateway_id", "target_id", "action", "execution_status",
                "mcp_message_id", "aws_request_id", "connection_id", "fixture_dataset_id"):
            bad = copy.deepcopy(after)
            record = json.loads(bad[0]["payload"]["S"])
            record[field] = "changed"
            bad[0]["payload"]["S"] = json.dumps(record)
            with self.subTest(field=field), self.assertRaises(ExecutionEvidenceError):
                self.validate(good, [], bad)

    def test_unrelated_insert_mutation_deletion_or_false_replay_rejects(self):
        prior = {"business_key": "prior", "preserved": "yes"}
        before = [{"business_key": {"S": "prior"}, "payload": {"S": json.dumps(prior)}}]
        first = self.call_handler()
        after = self.ledger.items() + before
        self.validate(self.response(first), before, after)
        for altered in (self.ledger.items(), self.ledger.items() + [{"business_key": {"S": "prior"},
                "payload": {"S": json.dumps(dict(prior, preserved="no"))}}]):
            with self.assertRaises(ExecutionEvidenceError):
                self.validate(self.response(first), before, altered)
        with self.assertRaises(ExecutionEvidenceError):
            self.validate(self.response(first), [], after)
        with self.assertRaises(ExecutionEvidenceError):
            self.validate(self.response(dict(first, idempotent_replay=True)), [], self.ledger.items())
        with self.assertRaises(ExecutionEvidenceError):
            self.validate(self.response(first), self.ledger.items(), self.ledger.items())
        replay = self.call_handler(mcp="mcp-2", aws="aws-2")
        mutated = copy.deepcopy(self.ledger.items())
        record = json.loads(mutated[0]["payload"]["S"])
        record["mcp_message_id"] = "mcp-2"
        mutated[0]["payload"]["S"] = json.dumps(record)
        with self.assertRaises(ExecutionEvidenceError):
            self.validate(self.response(replay, mcp="mcp-2", aws="aws-2"),
                self.ledger.items(), mutated, mcp="mcp-2")

    def test_duplicate_and_noncanonical_ledger_records_are_rejected(self):
        self.call_handler()
        items = self.ledger.items()
        self.assertEqual(decode_ledger_items(items)[0]["business_key"], self.key)
        for invalid in (items * 2, [{"business_key": {"S": "a"}, "payload": {"S": '{"business_key":"a","business_key":"a"}'}}],
                [{"business_key": {"S": "a"}, "payload": {"S": '{"business_key":"a","number":NaN}'}}],
                [{"business_key": {"S": "a"}, "payload": {"S": "[]"}}],
                [{"business_key": {"S": "a"}, "payload": {"B": b"bytes"}}]):
            with self.subTest(invalid=invalid), self.assertRaises(ExecutionEvidenceError):
                decode_ledger_items(invalid)
