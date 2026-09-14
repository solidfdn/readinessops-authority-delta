from __future__ import annotations

import copy
import json
import unittest
from pathlib import Path

from authority_delta.approval import approval_digest, validate_approval_payload
from authority_delta.contracts import validate_contract
from authority_delta.domain import ContractError
from authority_delta.local_proof import build_local_proof
from authority_delta.registry import FixtureBundle


ROOT = Path(__file__).resolve().parents[1]
ZERO = "0" * 64


def valid_approval_payload() -> dict[str, object]:
    return {
        "schema_version": "1.0", "baseline_id": "AD-BASELINE-1.0",
        "connection_id": "conn-demo", "governance_object_id": "vendor-payment-agent",
        "decision_pack_id": "DP-DEMO-001", "boundary_version": 1,
        "approval_generation": 1, "patch_id": "patch-demo",
        "before_manifest_hash": "1" * 64, "candidate_manifest_hash": "2" * 64,
        "fixture_snapshot_hash": "3" * 64, "request_registry_snapshot_hash": "4" * 64,
        "replay_evidence_hash": "5" * 64, "analysis_evidence_hash": "6" * 64,
        "decision_patch_hash": "7" * 64, "target_account_id": "123456789012",
        "target_region": "us-west-2", "runtime_arn": "arn:aws:bedrock-agentcore:demo:runtime/v2",
        "runtime_version": "2", "execution_role_arn": "arn:aws:iam::123456789012:role/v2",
        "gateway_arn": "arn:aws:bedrock-agentcore:demo:gateway/main", "policy_engine_id": "engine-demo",
        "current_owned_policy_snapshot_hash": "8" * 64, "compiler_version": "compiler-1",
        "proposed_policy_hash": "9" * 64, "allowed_request_ids": ["req-a"],
        "forbidden_tool_ids": ["export_credentials", "update_vendor_bank"],
        "decision": "MAINTAIN", "resulting_boundary_hash": "a" * 64,
        "approver_identity": "reviewer-demo", "approved_at": "2026-09-08T01:00:00Z",
        "effective_until": "2026-10-09T00:00:00Z",
    }


class ContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.fixtures = FixtureBundle.load(ROOT / "fixtures/decision_cases.json")

    def test_approval_digest_binds_every_field(self) -> None:
        payload = valid_approval_payload()
        original = approval_digest(payload)
        changed = copy.deepcopy(payload)
        changed["runtime_version"] = "3"
        self.assertNotEqual(original, approval_digest(changed))

    def test_approval_rejects_unknown_or_missing_fields(self) -> None:
        payload = valid_approval_payload()
        payload["browser_supplied_is_approved"] = True
        with self.assertRaises(ContractError):
            validate_approval_payload(payload)
        payload = valid_approval_payload()
        del payload["candidate_manifest_hash"]
        with self.assertRaises(ContractError):
            validate_approval_payload(payload)

    def test_reject_decision_cannot_carry_permissions(self) -> None:
        payload = valid_approval_payload()
        payload["decision"] = "REJECT"
        with self.assertRaises(ContractError):
            validate_approval_payload(payload)
        payload["allowed_request_ids"] = []
        payload["proposed_policy_hash"] = ZERO
        payload["resulting_boundary_hash"] = ZERO
        validate_approval_payload(payload)

    def test_publishing_decision_requires_real_target_and_future_expiry(self) -> None:
        payload = valid_approval_payload()
        payload["target_account_id"] = "demo"
        with self.assertRaises(ContractError):
            validate_approval_payload(payload)
        payload = valid_approval_payload()
        payload["effective_until"] = payload["approved_at"]
        with self.assertRaises(ContractError):
            validate_approval_payload(payload)
        payload = valid_approval_payload()
        payload["proposed_policy_hash"] = ZERO
        with self.assertRaises(ContractError):
            validate_approval_payload(payload)

    def test_fixture_request_content_is_immutable_identity(self) -> None:
        value = json.loads((ROOT / "fixtures/decision_cases.json").read_text())
        value["cases"][0]["request"]["amount_minor"] = 1
        with self.assertRaises(ContractError):
            FixtureBundle(value)

    def test_contract_schema_is_strict_and_contains_all_public_contracts(self) -> None:
        schema = json.loads((ROOT / "packages/contracts/authority-delta.schema.json").read_text())
        for name in ("decision_pack", "release_manifest", "decision_patch", "execution_evidence", "approval_payload"):
            self.assertIn(name, schema["$defs"])
            self.assertFalse(schema["$defs"][name]["additionalProperties"])

    def test_generated_decision_patch_passes_runtime_schema_validation(self) -> None:
        proof = build_local_proof(self.fixtures)
        validated = validate_contract("DecisionPatch", proof["decision_patch"])
        self.assertEqual(validated["affected_case_ids"], ["P-002"])

    def test_runtime_schema_rejects_unknown_contract_and_extra_field(self) -> None:
        with self.assertRaises(ContractError):
            validate_contract("Unknown", {})
        patch = build_local_proof(self.fixtures)["decision_patch"]
        patch["not_in_v1"] = True
        with self.assertRaises(ContractError):
            validate_contract("DecisionPatch", patch)


if __name__ == "__main__":
    unittest.main()
