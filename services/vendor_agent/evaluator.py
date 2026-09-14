"""Read-only evaluation component for the fixed V1/V2 AgentCore runtimes.

Release configuration is supplied by the deployed version, never by a request.
HTTP hosting, immutable runtime version/role bindings and Gateway execution are
separate integration steps; this module does not claim they are deployed.
"""
from __future__ import annotations

import json
import re

from authority_delta.canonical import sha256_json
from authority_delta.domain import ContractError, Judgment, ReleaseDefinition, judge_release


class VendorRuntimeEvaluator:
    def __init__(self, *, release: ReleaseDefinition, definition_hash: str,
            fixture_snapshot_hash: str, registry_table: str, dynamodb):
        if sha256_json(release.as_contract()) != definition_hash:
            raise ContractError("Deployed release definition hash mismatch")
        if not re.fullmatch(r"[0-9a-f]{64}", fixture_snapshot_hash):
            raise ContractError("Invalid registry snapshot binding")
        self.release = release
        self.definition_hash = definition_hash
        self.fixture_snapshot_hash = fixture_snapshot_hash
        self.registry_table = registry_table
        self.dynamodb = dynamodb

    def evaluate(self, payload):
        if not isinstance(payload, dict) or set(payload) != {"request_id"}:
            raise ContractError("Only request_id is accepted; release and business facts are server-bound")
        request_id = payload["request_id"]
        if not isinstance(request_id, str) or not re.fullmatch(r"req-[0-9a-f]{64}", request_id):
            raise ContractError("Invalid immutable request identity")
        observation = {"release_id": self.release.release_id, "release_definition_hash": self.definition_hash,
            "request_id": request_id, "request_registry_snapshot_hash": self.fixture_snapshot_hash,
            "judgment": Judgment.UNKNOWN.value, "gateway_outcome": "NOT_RUN"}
        try:
            response = self.dynamodb.get_item(TableName=self.registry_table,
                Key={"request_id": {"S": request_id}}, ConsistentRead=True)
            observation["registry_request_id"] = response.get("ResponseMetadata", {}).get("RequestId")
            item = response.get("Item")
            if not item:
                observation["reason"] = "REQUEST_NOT_FOUND"
                return observation
            if item.get("request_id", {}).get("S") != request_id or item.get("fixture_snapshot_hash", {}).get("S") != self.fixture_snapshot_hash:
                observation["reason"] = "REGISTRY_BINDING_MISMATCH"
                return observation
            request = json.loads(item["payload"]["S"])
            if not isinstance(request, dict) or "req-" + sha256_json(request) != request_id:
                observation["reason"] = "IMMUTABLE_REQUEST_HASH_MISMATCH"
                return observation
            observation["judgment"] = judge_release(self.release, request).value
            return observation
        except Exception as exc:
            # An incomplete lookup must not become an unchanged/allowed judgment.
            observation["reason"] = "REGISTRY_READ_FAILED"
            observation["error_type"] = type(exc).__name__
            return observation
