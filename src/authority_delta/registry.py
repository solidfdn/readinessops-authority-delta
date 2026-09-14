"""Immutable synthetic request registry and fixture loader."""

from __future__ import annotations

import copy
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from .canonical import sha256_json
from .domain import BoundaryDefinition, ContractError, ReleaseDefinition


@dataclass(frozen=True)
class FixtureCase:
    case_id: str
    request_id: str
    request: dict[str, Any]
    expected: dict[str, str]
    auxiliary: bool


class FixtureBundle:
    def __init__(self, value: Mapping[str, Any]) -> None:
        required = {
            "schema_version", "baseline_id", "data_classification", "analysis_visibility",
            "request_id_rule", "releases", "approved_boundary", "narrow_boundary", "cases",
            "auxiliary_cases", "expected_delta_case_ids", "expected_benign_delta_case_ids",
            "main_case_count", "unknown_input_behavior",
        }
        if set(value) != required:
            raise ContractError("Unexpected top-level fixture fields")
        if value["schema_version"] != "1.0" or value["baseline_id"] != "AD-BASELINE-1.0":
            raise ContractError("Unsupported fixture version or baseline")
        if value["data_classification"] != "SYNTHETIC_ONLY":
            raise ContractError("Fixture must contain synthetic data only")
        self.raw = copy.deepcopy(dict(value))
        self.releases = {
            name: ReleaseDefinition.from_mapping(name, definition)
            for name, definition in value["releases"].items()
        }
        self.approved_boundary = BoundaryDefinition.from_mapping(value["approved_boundary"])
        self.narrow_boundary = BoundaryDefinition.from_mapping(value["narrow_boundary"])
        self.cases = self._parse_cases(value["cases"], auxiliary=False)
        self.auxiliary_cases = self._parse_cases(value["auxiliary_cases"], auxiliary=True)
        if len(self.cases) != value["main_case_count"] or [c.case_id for c in self.cases] != [f"P-{n:03d}" for n in range(1, 7)]:
            raise ContractError("The six core cases are incomplete or out of order")
        if [c.case_id for c in self.auxiliary_cases] != ["C-001"]:
            raise ContractError("The narrowing positive control is missing")
        request_ids = [c.request_id for c in self.all_cases]
        if len(request_ids) != len(set(request_ids)):
            raise ContractError("Request identities must be unique")

    @classmethod
    def load(cls, path: str | Path) -> "FixtureBundle":
        return cls(json.loads(Path(path).read_text(encoding="utf-8")))

    def _parse_cases(self, values: Any, *, auxiliary: bool) -> tuple[FixtureCase, ...]:
        if not isinstance(values, list):
            raise ContractError("Cases must be a list")
        parsed: list[FixtureCase] = []
        for value in values:
            if set(value) != {"case_id", "request_id", "request", "expected"}:
                raise ContractError("Invalid case fields")
            expected_id = "req-" + sha256_json(value["request"])
            if value["request_id"] != expected_id:
                raise ContractError(f"Immutable request hash mismatch: {value['case_id']}")
            parsed.append(FixtureCase(
                case_id=value["case_id"], request_id=value["request_id"],
                request=copy.deepcopy(value["request"]), expected=copy.deepcopy(value["expected"]),
                auxiliary=auxiliary,
            ))
        return tuple(parsed)

    @property
    def all_cases(self) -> tuple[FixtureCase, ...]:
        return self.cases + self.auxiliary_cases

    @property
    def request_registry_snapshot(self) -> dict[str, Any]:
        return {
            "schema_version": "1.0",
            "records": [
                {"request_id": case.request_id, "request": copy.deepcopy(case.request)}
                for case in sorted(self.all_cases, key=lambda item: item.request_id)
            ],
        }

    @property
    def request_registry_snapshot_hash(self) -> str:
        return sha256_json(self.request_registry_snapshot)

    def trusted_request(self, request_id: str) -> dict[str, Any]:
        for case in self.all_cases:
            if case.request_id == request_id:
                return copy.deepcopy(case.request)
        raise KeyError(request_id)

    def analysis_input(self) -> dict[str, Any]:
        """Return agent-readable inputs with evaluator-only expected values removed."""

        return {
            "schema_version": self.raw["schema_version"],
            "baseline_id": self.raw["baseline_id"],
            "releases": {name: definition.as_contract() for name, definition in self.releases.items()},
            "cases": [
                {"case_id": case.case_id, "request_id": case.request_id, "request": copy.deepcopy(case.request)}
                for case in self.cases
            ],
            "request_registry_snapshot_hash": self.request_registry_snapshot_hash,
        }
