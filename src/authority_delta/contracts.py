"""Strict validation for the five public Authority Delta JSON contracts."""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path
from typing import Any, Mapping

from jsonschema import Draft202012Validator, FormatChecker
from jsonschema.exceptions import ValidationError

from .domain import ContractError


CONTRACT_NAMES = {
    "DecisionPack": "decision_pack",
    "ReleaseManifest": "release_manifest",
    "DecisionPatch": "decision_patch",
    "ExecutionEvidence": "execution_evidence",
    "ApprovalPayload": "approval_payload",
}


def _default_schema_path() -> Path:
    return Path(__file__).resolve().parents[2] / "packages/contracts/authority-delta.schema.json"


@lru_cache(maxsize=4)
def _schema(path: str) -> dict[str, Any]:
    value = json.loads(Path(path).read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(value)
    return value


def validate_contract(
    contract_name: str,
    value: Mapping[str, Any],
    *,
    schema_path: str | Path | None = None,
) -> dict[str, Any]:
    """Validate one named public contract; reject unknown names and fields."""

    definition = CONTRACT_NAMES.get(contract_name)
    if definition is None:
        raise ContractError(f"Unknown contract: {contract_name}")
    path = Path(schema_path) if schema_path is not None else _default_schema_path()
    schema = _schema(str(path.resolve()))
    validator = Draft202012Validator(
        {"$ref": f"#/$defs/{definition}", "$defs": schema["$defs"]},
        format_checker=FormatChecker(),
    )
    errors = sorted(validator.iter_errors(dict(value)), key=lambda item: list(item.absolute_path))
    if errors:
        error: ValidationError = errors[0]
        location = ".".join(str(item) for item in error.absolute_path) or "$"
        raise ContractError(f"Invalid {contract_name} at {location}: {error.message}")
    return dict(value)
