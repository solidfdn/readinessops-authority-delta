from pathlib import Path
import copy
import json
import unittest

import boto3
from botocore.stub import Stubber

from authority_delta.canonical import sha256_json
from authority_delta.domain import ContractError
from authority_delta.registry import FixtureBundle
from scripts.build_registry_seed import build_transaction
from services.vendor_agent.evaluator import VendorRuntimeEvaluator

ROOT = Path(__file__).resolve().parents[1]


class RuntimeEvaluatorTests(unittest.TestCase):
    def setUp(self):
        self.fixtures = FixtureBundle.load(ROOT / "fixtures/decision_cases.json")
        self.client = boto3.client("dynamodb", region_name="ap-northeast-1", aws_access_key_id="unit-test", aws_secret_access_key="unit-test")
        self.items = {t["Put"]["Item"]["request_id"]["S"]: t["Put"]["Item"] for t in build_transaction(self.fixtures, "registry-test")}

    def evaluator(self, release="V1"):
        definition = self.fixtures.releases[release]
        return VendorRuntimeEvaluator(release=definition, definition_hash=sha256_json(definition.as_contract()),
            fixture_snapshot_hash=self.fixtures.request_registry_snapshot_hash,
            registry_table="registry-test", dynamodb=self.client)

    def test_both_fixed_releases_read_same_records_and_only_p002_changes(self):
        outputs = {}
        with Stubber(self.client) as stub:
            for release in ("V1", "V2", "V1-BENIGN"):
                evaluator = self.evaluator(release)
                outputs[release] = {}
                for case in self.fixtures.cases:
                    stub.add_response("get_item", {"Item": self.items[case.request_id], "ResponseMetadata": {"RequestId": "read-" + case.case_id}},
                        {"TableName": "registry-test", "Key": {"request_id": {"S": case.request_id}}, "ConsistentRead": True})
                    result = evaluator.evaluate({"request_id": case.request_id})
                    self.assertEqual(result["gateway_outcome"], "NOT_RUN")
                    outputs[release][case.case_id] = result["judgment"]
            stub.assert_no_pending_responses()
        self.assertEqual([c for c in outputs["V1"] if outputs["V1"][c] != outputs["V2"][c]], ["P-002"])
        self.assertEqual(outputs["V1"], outputs["V1-BENIGN"])

    def test_request_cannot_override_release_or_business_facts_and_drift_is_unknown(self):
        evaluator = self.evaluator("V2")
        case = self.fixtures.cases[1]
        with self.assertRaises(ContractError):
            evaluator.evaluate({"request_id": case.request_id, "release_id": "V1"})
        with self.assertRaises(ContractError):
            evaluator.evaluate({"request_id": case.request_id, "verified": True})
        tampered = copy.deepcopy(self.items[case.request_id])
        facts = json.loads(tampered["payload"]["S"])
        facts["amount_minor"] = 1
        tampered["payload"]["S"] = json.dumps(facts)
        bad_snapshot = copy.deepcopy(self.items[case.request_id])
        bad_snapshot["fixture_snapshot_hash"]["S"] = "0" * 64
        with Stubber(self.client) as stub:
            for item, reason in [(tampered, "IMMUTABLE_REQUEST_HASH_MISMATCH"), (bad_snapshot, "REGISTRY_BINDING_MISMATCH"), (None, "REQUEST_NOT_FOUND")]:
                stub.add_response("get_item", {"Item": item} if item else {},
                    {"TableName": "registry-test", "Key": {"request_id": {"S": case.request_id}}, "ConsistentRead": True})
                result = evaluator.evaluate({"request_id": case.request_id})
                self.assertEqual((result["judgment"], result["reason"]), ("UNKNOWN", reason))
            stub.assert_no_pending_responses()
