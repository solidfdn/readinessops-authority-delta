"""Deterministic replay orchestration across fixed agent releases."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable

from .canonical import sha256_json
from .domain import Judgment, judge_release
from .registry import FixtureBundle, FixtureCase


@dataclass(frozen=True)
class ReplayObservation:
    case_id: str
    request_id: str
    release_id: str
    judgment: Judgment
    evidence_refs: tuple[str, ...]

    def as_contract(self) -> dict[str, Any]:
        return {
            "case_id": self.case_id,
            "request_id": self.request_id,
            "release_id": self.release_id,
            "judgment": self.judgment.value,
            "evidence_refs": list(self.evidence_refs),
        }


@dataclass(frozen=True)
class ReplayEvidence:
    schema_version: str
    baseline_id: str
    release_id: str
    release_definition_hash: str
    request_registry_snapshot_hash: str
    observations: tuple[ReplayObservation, ...]

    def as_contract(self) -> dict[str, Any]:
        value = {
            "schema_version": self.schema_version,
            "baseline_id": self.baseline_id,
            "release_id": self.release_id,
            "release_definition_hash": self.release_definition_hash,
            "request_registry_snapshot_hash": self.request_registry_snapshot_hash,
            "coverage": {
                "total": len(self.observations),
                "observed": sum(o.judgment is not Judgment.UNKNOWN for o in self.observations),
                "unknown": sum(o.judgment is Judgment.UNKNOWN for o in self.observations),
            },
            "observations": [observation.as_contract() for observation in self.observations],
        }
        value["evidence_hash"] = sha256_json(value)
        return value


def replay_from_contract(value: dict[str, Any]) -> ReplayEvidence:
    """Load complete stored observations and verify their canonical hash and shape."""
    replay = ReplayEvidence(value['schema_version'], value['baseline_id'], value['release_id'],
        value['release_definition_hash'], value['request_registry_snapshot_hash'],
        tuple(ReplayObservation(o['case_id'], o['request_id'], o['release_id'],
            Judgment(o['judgment']), tuple(o['evidence_refs'])) for o in value['observations']))
    if replay.as_contract() != value:
        raise ValueError('Stored replay hash, coverage or schema mismatch')
    return replay


def run_replay(
    fixtures: FixtureBundle,
    release_id: str,
    cases: Iterable[FixtureCase] | None = None,
) -> ReplayEvidence:
    release = fixtures.releases[release_id]
    selected = tuple(cases if cases is not None else fixtures.cases)
    observations = tuple(
        ReplayObservation(
            case_id=case.case_id,
            request_id=case.request_id,
            release_id=release_id,
            judgment=judge_release(release, fixtures.trusted_request(case.request_id)),
            evidence_refs=(
                f"release:{release_id}:definition",
                f"request-registry:{fixtures.request_registry_snapshot_hash}:{case.request_id}",
            ),
        )
        for case in selected
    )
    return ReplayEvidence(
        schema_version="1.0",
        baseline_id=fixtures.raw["baseline_id"],
        release_id=release_id,
        release_definition_hash=sha256_json(release.as_contract()),
        request_registry_snapshot_hash=fixtures.request_registry_snapshot_hash,
        observations=observations,
    )
