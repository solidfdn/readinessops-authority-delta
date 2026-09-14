from __future__ import annotations

import unittest
from dataclasses import replace
from pathlib import Path

from authority_delta.delta import build_decision_patch
from authority_delta.domain import Decision, Judgment
from authority_delta.local_proof import build_local_proof
from authority_delta.policy_plan import build_policy_plan
from authority_delta.registry import FixtureBundle
from authority_delta.replay import run_replay


ROOT = Path(__file__).resolve().parents[1]


class CoreSemanticTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.fixtures = FixtureBundle.load(ROOT / "fixtures/decision_cases.json")

    def test_six_case_replay_finds_only_observed_semantic_delta(self) -> None:
        before = run_replay(self.fixtures, "V1")
        candidate = run_replay(self.fixtures, "V2")
        patch = build_decision_patch(
            decision_pack_id="DP-DEMO-001",
            boundary_version=1,
            before=before,
            candidate=candidate,
        )
        self.assertEqual(patch["status"], "REVIEW_REQUIRED")
        self.assertEqual(patch["affected_case_ids"], ["P-002"])
        self.assertEqual(patch["coverage"], {"total": 6, "observed": 6, "unknown": 0})
        refs = patch["changes"][0]["evidence_refs"]
        self.assertEqual(refs, sorted(set(refs)))

    def test_benign_release_has_no_decision_change(self) -> None:
        patch = build_decision_patch(
            decision_pack_id="DP-DEMO-001",
            boundary_version=1,
            before=run_replay(self.fixtures, "V1"),
            candidate=run_replay(self.fixtures, "V1-BENIGN"),
        )
        self.assertEqual(patch["status"], "NO_DECISION_CHANGE")
        self.assertEqual(patch["affected_case_ids"], [])

    def test_missing_observation_holds_publication(self) -> None:
        complete = run_replay(self.fixtures, "V2")
        incomplete = replace(complete, observations=complete.observations[:-1])
        patch = build_decision_patch(
            decision_pack_id="DP-DEMO-001",
            boundary_version=1,
            before=run_replay(self.fixtures, "V1"),
            candidate=incomplete,
        )
        self.assertEqual(patch["status"], "HOLD")
        self.assertEqual(patch["unknown_case_ids"], ["P-006"])

    def test_policy_plans_match_three_human_choices(self) -> None:
        maintain = build_policy_plan(self.fixtures, Decision.MAINTAIN)
        narrow = build_policy_plan(self.fixtures, Decision.NARROW)
        reject = build_policy_plan(self.fixtures, Decision.REJECT)
        case_by_id = {case.case_id: case for case in self.fixtures.all_cases}
        self.assertEqual(maintain["allowed_request_ids"], sorted([
            case_by_id["P-001"].request_id,
            case_by_id["C-001"].request_id,
        ]))
        self.assertEqual(narrow["allowed_request_ids"], [case_by_id["C-001"].request_id])
        self.assertFalse(reject["publication_allowed"])
        self.assertEqual(reject["allowed_request_ids"], [])
        self.assertEqual(
            {item["case_id"]: item["expected_policy_outcome"] for item in maintain["expected_outcomes"] if item["case_id"].startswith("P-")},
            {"P-001": "ALLOW", "P-002": "DENY", "P-003": "DENY", "P-004": "DENY", "P-005": "DENY", "P-006": "DENY"},
        )

    def test_expected_values_are_not_exposed_to_analysis_input(self) -> None:
        analysis_input = self.fixtures.analysis_input()
        self.assertNotIn("expected", repr(analysis_input))
        proof = build_local_proof(self.fixtures)
        self.assertFalse(proof["analysis_input_contains_expected"])
        self.assertEqual(proof["proof_scope"], "LOCAL_ONLY_NO_AWS_NO_STRANDS_NO_GATEWAY")

    def test_release_judgments_match_evaluator_expectations(self) -> None:
        for release_id, expected_key in (("V1", "v1_judgment"), ("V2", "v2_judgment")):
            observed = {item.case_id: item.judgment.value for item in run_replay(self.fixtures, release_id).observations}
            expected = {case.case_id: case.expected[expected_key] for case in self.fixtures.cases}
            self.assertEqual(observed, expected)


if __name__ == "__main__":
    unittest.main()
