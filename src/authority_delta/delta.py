"""Compare complete replay evidence without embedding a target case answer."""

from __future__ import annotations

from typing import Any
from uuid import UUID, uuid5

from .canonical import sha256_json
from .domain import Judgment
from .replay import ReplayEvidence


PATCH_NAMESPACE = UUID("7d53782d-a55f-42dc-a588-4f8953771061")


def build_decision_patch(
    *,
    decision_pack_id: str,
    boundary_version: int,
    before: ReplayEvidence,
    candidate: ReplayEvidence,
) -> dict[str, Any]:
    before_by_case = {item.case_id: item for item in before.observations}
    candidate_by_case = {item.case_id: item for item in candidate.observations}
    case_ids = sorted(set(before_by_case) | set(candidate_by_case))
    unknown_case_ids = [
        case_id for case_id in case_ids
        if case_id not in before_by_case
        or case_id not in candidate_by_case
        or before_by_case[case_id].judgment is Judgment.UNKNOWN
        or candidate_by_case[case_id].judgment is Judgment.UNKNOWN
    ]
    registry_mismatch = before.request_registry_snapshot_hash != candidate.request_registry_snapshot_hash
    changes: list[dict[str, Any]] = []
    if not registry_mismatch:
        for case_id in case_ids:
            if case_id in unknown_case_ids:
                continue
            old = before_by_case[case_id]
            new = candidate_by_case[case_id]
            if old.request_id != new.request_id:
                unknown_case_ids.append(case_id)
                continue
            if old.judgment != new.judgment:
                changes.append({
                    "case_id": case_id,
                    "before_judgment": old.judgment.value,
                    "after_judgment": new.judgment.value,
                    "reason": (
                        f"The same immutable request produced {old.judgment.value} in "
                        f"{before.release_id} and {new.judgment.value} in {candidate.release_id}."
                    ),
                    "evidence_refs": sorted(set(old.evidence_refs + new.evidence_refs)),
                })
    else:
        unknown_case_ids = case_ids

    unknown_case_ids = sorted(set(unknown_case_ids))
    before_contract = before.as_contract()
    candidate_contract = candidate.as_contract()
    seed = sha256_json({
        "decision_pack_id": decision_pack_id,
        "boundary_version": boundary_version,
        "before": before_contract["evidence_hash"],
        "candidate": candidate_contract["evidence_hash"],
    })
    complete = (
        not unknown_case_ids
        and len(before.observations) == 6
        and len(candidate.observations) == 6
        and len(before_by_case) == 6
        and len(candidate_by_case) == 6
        and not registry_mismatch
    )
    status = "REVIEW_REQUIRED" if complete and changes else "NO_DECISION_CHANGE" if complete else "HOLD"
    return {
        "schema_version": "1.0",
        "patch_id": f"patch-{uuid5(PATCH_NAMESPACE, seed)}",
        "decision_pack_id": decision_pack_id,
        "boundary_version": boundary_version,
        "before_manifest_hash": before.release_definition_hash,
        "candidate_manifest_hash": candidate.release_definition_hash,
        "fixture_snapshot_hash": before.request_registry_snapshot_hash,
        "replay_evidence_hash": sha256_json({
            "before": before_contract["evidence_hash"],
            "candidate": candidate_contract["evidence_hash"],
        }),
        "analysis_evidence_hash": "0" * 64,
        "coverage": {
            "total": len(case_ids),
            "observed": len(case_ids) - len(unknown_case_ids),
            "unknown": len(unknown_case_ids),
        },
        "affected_case_ids": [change["case_id"] for change in changes],
        "unknown_case_ids": unknown_case_ids,
        "changes": changes,
        "recommendation": "HOLD" if not complete else "HUMAN_REVIEW" if changes else "NO_DECISION_CHANGE",
        "status": status,
        "analysis_status": "PENDING_STRANDS",
    }
