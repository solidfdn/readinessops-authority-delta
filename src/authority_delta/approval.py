"""Exact-field approval payload validation and digest."""

from __future__ import annotations

from datetime import datetime
import re
from typing import Any, Mapping

from .canonical import sha256_json
from .domain import ContractError, Decision


APPROVAL_FIELDS = {
    "schema_version", "baseline_id", "connection_id", "governance_object_id",
    "decision_pack_id", "boundary_version", "approval_generation", "patch_id",
    "before_manifest_hash", "candidate_manifest_hash", "fixture_snapshot_hash",
    "request_registry_snapshot_hash", "replay_evidence_hash", "analysis_evidence_hash",
    "decision_patch_hash", "target_account_id", "target_region", "runtime_arn",
    "runtime_version", "execution_role_arn", "gateway_arn", "policy_engine_id",
    "current_owned_policy_snapshot_hash", "compiler_version", "proposed_policy_hash",
    "allowed_request_ids", "forbidden_tool_ids", "decision", "resulting_boundary_hash",
    "approver_identity", "approved_at", "effective_until",
}
HASH_FIELDS = {name for name in APPROVAL_FIELDS if name.endswith("_hash")}
HEX_64 = re.compile(r"^[0-9a-f]{64}$")


def validate_approval_payload(value: Mapping[str, Any]) -> dict[str, Any]:
    if set(value) != APPROVAL_FIELDS:
        missing = sorted(APPROVAL_FIELDS - set(value))
        extra = sorted(set(value) - APPROVAL_FIELDS)
        raise ContractError(f"ApprovalPayload fields differ; missing={missing}, extra={extra}")
    if value["schema_version"] != "1.0" or value["baseline_id"] != "AD-BASELINE-1.0":
        raise ContractError("Unsupported approval schema or baseline")
    for name in HASH_FIELDS:
        if not isinstance(value[name], str) or not HEX_64.fullmatch(value[name]):
            raise ContractError(f"Invalid SHA-256 field: {name}")
    for name in ("allowed_request_ids", "forbidden_tool_ids"):
        items = value[name]
        if not isinstance(items, list) or not all(isinstance(item, str) and item for item in items):
            raise ContractError(f"Invalid set array: {name}")
        if items != sorted(set(items)):
            raise ContractError(f"Set array must be unique and sorted: {name}")
    if not isinstance(value["boundary_version"], int) or value["boundary_version"] < 1:
        raise ContractError("Invalid boundary_version")
    if not isinstance(value["approval_generation"], int) or value["approval_generation"] < 1:
        raise ContractError("Invalid approval_generation")
    try:
        decision = Decision(value["decision"])
    except ValueError as exc:
        raise ContractError("Invalid decision") from exc
    zero_hash = "0" * 64
    if decision is Decision.REJECT and (
        value["allowed_request_ids"]
        or value["proposed_policy_hash"] != zero_hash
        or value["resulting_boundary_hash"] != zero_hash
    ):
        raise ContractError("REJECT must bind no permissions and no resulting boundary")
    if decision is not Decision.REJECT and (
        not value["allowed_request_ids"]
        or value["proposed_policy_hash"] == zero_hash
        or value["resulting_boundary_hash"] == zero_hash
    ):
        raise ContractError("A publishing decision must bind a non-empty policy and boundary")
    if not isinstance(value["target_account_id"], str) or not re.fullmatch(r"[0-9]{12}", value["target_account_id"]):
        raise ContractError("target_account_id must contain 12 digits")
    parsed_times: dict[str, datetime] = {}
    for name in ("approved_at", "effective_until"):
        raw = value[name]
        if not isinstance(raw, str) or not raw.endswith("Z"):
            raise ContractError(f"{name} must be RFC3339 UTC")
        try:
            parsed_times[name] = datetime.fromisoformat(raw.replace("Z", "+00:00"))
        except ValueError as exc:
            raise ContractError(f"Invalid timestamp: {name}") from exc
    if parsed_times["effective_until"] <= parsed_times["approved_at"]:
        raise ContractError("effective_until must be later than approved_at")
    for name in APPROVAL_FIELDS - HASH_FIELDS - {
        "boundary_version", "approval_generation", "allowed_request_ids", "forbidden_tool_ids",
    }:
        if not isinstance(value[name], str) or not value[name]:
            raise ContractError(f"Invalid string field: {name}")
    return dict(value)


def approval_digest(value: Mapping[str, Any]) -> str:
    return sha256_json(validate_approval_payload(value))
