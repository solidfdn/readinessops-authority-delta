"""Create a local, explicitly non-AWS proof artifact."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from .canonical import sha256_json
from .delta import build_decision_patch
from .domain import Decision
from .policy_plan import build_policy_plan
from .registry import FixtureBundle
from .replay import run_replay


def build_local_proof(fixtures: FixtureBundle) -> dict[str, Any]:
    analysis_input = fixtures.analysis_input()
    before = run_replay(fixtures, "V1")
    candidate = run_replay(fixtures, "V2")
    benign = run_replay(fixtures, "V1-BENIGN")
    delta = build_decision_patch(
        decision_pack_id="DP-DEMO-001",
        boundary_version=1,
        before=before,
        candidate=candidate,
    )
    benign_delta = build_decision_patch(
        decision_pack_id="DP-DEMO-001",
        boundary_version=1,
        before=before,
        candidate=benign,
    )
    proof = {
        "schema_version": "1.0",
        "baseline_id": fixtures.raw["baseline_id"],
        "proof_scope": "LOCAL_ONLY_NO_AWS_NO_STRANDS_NO_GATEWAY",
        "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "analysis_input": analysis_input,
        "analysis_input_contains_expected": "expected" in repr(analysis_input),
        "request_registry_snapshot_hash": fixtures.request_registry_snapshot_hash,
        "replays": {
            "before": before.as_contract(),
            "candidate": candidate.as_contract(),
            "benign": benign.as_contract(),
        },
        "decision_patch": delta,
        "benign_patch": benign_delta,
        "policy_plans": {
            decision.value: build_policy_plan(fixtures, decision)
            for decision in Decision
        },
    }
    proof["proof_hash"] = sha256_json(proof)
    return proof
