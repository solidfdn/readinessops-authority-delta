"""Build a deterministic authorization plan from trusted request facts."""

from __future__ import annotations

from typing import Any

from ..canonical import sha256_json
from .vendor_payment import BoundaryDefinition, boundary_allows
from ..decisions import Decision, GatewayExpectation
from ..registry import FixtureBundle


def build_policy_plan(fixtures: FixtureBundle, decision: Decision) -> dict[str, Any]:
    boundary: BoundaryDefinition | None
    if decision is Decision.MAINTAIN:
        boundary = fixtures.approved_boundary
    elif decision is Decision.NARROW:
        boundary = fixtures.narrow_boundary
    else:
        boundary = None

    allowed_request_ids = sorted(
        case.request_id
        for case in fixtures.all_cases
        if boundary is not None and boundary_allows(boundary, fixtures.trusted_request(case.request_id))
    )
    outcomes = [
        {
            "case_id": case.case_id,
            "request_id": case.request_id,
            "expected_policy_outcome": (
                GatewayExpectation.ALLOW.value
                if case.request_id in allowed_request_ids
                else GatewayExpectation.DENY.value
            ),
        }
        for case in fixtures.all_cases
    ]
    plan = {
        "schema_version": "1.0",
        "baseline_id": fixtures.raw["baseline_id"],
        "decision": decision.value,
        "request_registry_snapshot_hash": fixtures.request_registry_snapshot_hash,
        "resulting_boundary": boundary.as_contract() if boundary is not None else None,
        "allowed_request_ids": allowed_request_ids,
        "forbidden_tool_ids": ["export_credentials", "update_vendor_bank"],
        "expected_outcomes": outcomes,
        "publication_allowed": decision is not Decision.REJECT,
        "cedar_compilation_status": "AWAITING_OBSERVED_AGENTCORE_SCHEMA",
    }
    plan["plan_hash"] = sha256_json(plan)
    return plan
