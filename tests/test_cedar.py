from __future__ import annotations

import copy
from pathlib import Path
import unittest

from authority_delta.canonical import sha256_json
from authority_delta.cedar import (
    CedarContractError, assert_observed_role_matches,
    compile_permit, principal_id_from_role_arn,
)
from authority_delta.domain import Decision
from authority_delta.policy_plan import build_policy_plan
from authority_delta.registry import FixtureBundle


ROOT = Path(__file__).resolve().parents[1]
GATEWAY = "arn:aws:bedrock-agentcore:ap-northeast-1:538522204923:gateway/authority-delta-gateway-rvplvkk1t7"
ROLE = "arn:aws:iam::538522204923:role/AuthorityDeltaVendorV1"
SESSION = "arn:aws:sts::538522204923:assumed-role/AuthorityDeltaVendorV1/runtime-session-01"


class CedarCompilerTests(unittest.TestCase):
    def setUp(self):
        self.fixtures = FixtureBundle.load(ROOT / "fixtures/decision_cases.json")

    def compile(self, plan=None, **overrides):
        plan = plan or build_policy_plan(self.fixtures, Decision.MAINTAIN)
        arguments = dict(gateway_arn=GATEWAY, role_arn=ROLE,
                         allowed_request_ids=plan["allowed_request_ids"],
                         request_registry_snapshot_hash=plan["request_registry_snapshot_hash"])
        arguments.update(overrides)
        return compile_permit(**arguments)

    def test_compiles_trusted_boundary_with_exact_principal_tool_gateway_and_ids(self):
        plan = build_policy_plan(self.fixtures, Decision.MAINTAIN)
        policy = self.compile(plan)
        self.assertEqual(policy["allowed_request_ids"], plan["allowed_request_ids"])
        self.assertEqual(len(policy["allowed_request_ids"]), 2)
        self.assertIn('principal == AgentCore::IamEntity::"arn:aws:sts::538522204923:assumed-role/AuthorityDeltaVendorV1"', policy["statement"])
        self.assertIn('action == AgentCore::Action::"VendorPaymentTools___prepare_vendor_payment"', policy["statement"])
        self.assertIn(f'resource == AgentCore::Gateway::"{GATEWAY}"', policy["statement"])
        self.assertIn('.contains(context.input.payment_request_id)', policy["statement"])
        for case in self.fixtures.all_cases:
            self.assertEqual(case.request_id in policy["statement"], case.request_id in plan["allowed_request_ids"])
        self.assertNotIn("P-001", policy["statement"])
        self.assertNotIn("P-002", policy["statement"])
        self.assertNotIn("*", policy["statement"])
        self.assertNotIn("update_vendor_bank", policy["statement"])

    def test_changed_trusted_facts_change_ids_without_case_label_shortcuts(self):
        raw = copy.deepcopy(self.fixtures.raw)
        for case in raw["cases"]:
            if case["request"]["action"] == "prepare_vendor_payment":
                case["request"]["fixture_dataset_id"] += "-new"
                case["request_id"] = "req-" + sha256_json(case["request"])
        changed = FixtureBundle(raw)
        plan = build_policy_plan(changed, Decision.MAINTAIN)
        actual = self.compile(plan)
        self.assertEqual(actual["allowed_request_ids"], plan["allowed_request_ids"])
        self.assertNotEqual(actual["policy_hash"], self.compile()["policy_hash"])

    def test_narrowing_keeps_positive_control_and_reject_emits_no_permit(self):
        narrow = self.compile(build_policy_plan(self.fixtures, Decision.NARROW))
        self.assertEqual(len(narrow["allowed_request_ids"]), 1)
        self.assertEqual(narrow["allowed_request_ids"], [self.fixtures.auxiliary_cases[0].request_id])
        self.assertIsNone(self.compile(build_policy_plan(self.fixtures, Decision.REJECT)))

    def test_order_and_ephemeral_session_do_not_change_policy_identity(self):
        plan = build_policy_plan(self.fixtures, Decision.MAINTAIN)
        a = self.compile(plan)
        b = self.compile(plan, role_arn=SESSION, allowed_request_ids=list(reversed(plan["allowed_request_ids"])))
        self.assertEqual(a, b)
        self.assertNotEqual(a["binding_hash"], self.compile(request_registry_snapshot_hash="f" * 64)["binding_hash"])
        self.assertNotEqual(a["policy_hash"], self.compile(role_arn=ROLE.replace("V1", "V2"))["policy_hash"])

    def test_registered_path_and_observed_session_match_without_path_invention(self):
        self.assertEqual(principal_id_from_role_arn(ROLE), principal_id_from_role_arn(SESSION))
        path_role = ROLE.replace(":role/", ":role/service-role/customer/")
        self.assertEqual(assert_observed_role_matches(path_role, SESSION), principal_id_from_role_arn(ROLE))
        for observed in [SESSION.replace("538522204923", "538522204924"),
                         SESSION.replace("VendorV1", "VendorV10"),
                         SESSION.replace("VendorV1", "vendorv1"),
                         SESSION.replace("assumed-role/", "assumed-role/service-role/")]:
            with self.subTest(observed=observed), self.assertRaises(CedarContractError):
                assert_observed_role_matches(path_role, observed)

    def test_rejects_ambiguous_or_untrusted_scope_values(self):
        bad_roles = [ROLE + "\n", ROLE + "*", ROLE.replace(":role/", ":role//"),
                     ROLE.replace(":role/", ":role/../"), ROLE.replace(":role/", ":role/%2f/"),
                     ROLE.replace(":role/", ":user/"), "arn:aws:iam::538522204923:root",
                     SESSION.rsplit("/", 1)[0], SESSION + "/extra", SESSION.replace("runtime-session-01", "")]
        for role in bad_roles:
            with self.subTest(role=role), self.assertRaises(CedarContractError):
                self.compile(role_arn=role)
        bad_inputs = [dict(gateway_arn=GATEWAY + "*"), dict(gateway_arn=GATEWAY.replace("538522204923", "538522204924")),
                      dict(target_name='X___export_credentials'), dict(target_name='X\"); permit(principal, action, resource);'),
                      dict(allowed_request_ids=["P-001"]), dict(allowed_request_ids=["req-" + "f" * 64] * 2),
                      dict(allowed_request_ids="req-" + "f" * 64), dict(allowed_request_ids=[None]),
                      dict(request_registry_snapshot_hash="F" * 64)]
        for arguments in bad_inputs:
            with self.subTest(arguments=arguments), self.assertRaises(CedarContractError):
                self.compile(**arguments)

    def test_oversized_set_fails_before_an_aws_policy_write(self):
        with self.assertRaises(CedarContractError):
            self.compile(allowed_request_ids=[f"req-{i:064x}" for i in range(200)])


if __name__ == "__main__":
    unittest.main()
