"""Correlate real Gateway tool results with consistent sandbox ledger reads.

This proves tool execution, not release approval or a completed publication. The
caller must collect before/after Items using ConsistentRead=True around one call.
MCP CallToolResult may contain JSON text and/or structuredContent. If both are
present they must agree. No service call or credential is handled by this module.

Sources: MCP 2025-06-18 server/tools; AWS gateway-add-target-lambda.html. The
current deployed Lambda result contract is services/sandbox/handler.py.
"""
from __future__ import annotations

import json
from typing import Any

from .canonical import sha256_json
from .gateway_probe import REQUEST_HEADERS


class ExecutionEvidenceError(ValueError):
    pass


def _json_object(value: str) -> dict[str, Any]:
    def pairs(entries):
        result = {}
        for key, item in entries:
            if key in result:
                raise ExecutionEvidenceError("Duplicate JSON member in execution evidence")
            result[key] = item
        return result

    def invalid_constant(_):
        raise ExecutionEvidenceError("Non-finite JSON value in execution evidence")

    try:
        result = json.loads(value, object_pairs_hook=pairs, parse_constant=invalid_constant)
    except (TypeError, ValueError) as exc:
        raise ExecutionEvidenceError("Execution evidence is not an unambiguous JSON object") from exc
    if not isinstance(result, dict):
        raise ExecutionEvidenceError("Execution evidence must be a JSON object")
    return result


def decode_ledger_items(items) -> list[dict[str, Any]]:
    """Decode low-level DynamoDB Items; reject duplicate/mismatched ledger keys."""
    if not isinstance(items, list):
        raise ExecutionEvidenceError("Expected a complete ledger Items list")
    records = {}
    for item in items:
        if not isinstance(item, dict) or set(item) != {"business_key", "payload"}:
            raise ExecutionEvidenceError("Unexpected ledger item shape")
        for attribute in ("business_key", "payload"):
            value = item[attribute]
            if not isinstance(value, dict) or set(value) != {"S"} or not isinstance(value["S"], str):
                raise ExecutionEvidenceError("Ledger attributes must be DynamoDB strings")
        key = item["business_key"]["S"]
        record = _json_object(item["payload"]["S"])
        if not key or record.get("business_key") != key or key in records:
            raise ExecutionEvidenceError("Duplicate or mismatched ledger business key")
        records[key] = record
    return [records[key] for key in sorted(records)]


def _tool_result(response, mcp_id):
    if not isinstance(response, dict) or type(response.get("http_status")) is not int or response["http_status"] != 200:
        raise ExecutionEvidenceError("No successful Gateway HTTP response")
    body = response.get("body")
    if not isinstance(body, dict) or body.get("jsonrpc") != "2.0" or body.get("id") != mcp_id or "error" in body:
        raise ExecutionEvidenceError("Gateway MCP result identity/error mismatch")
    headers = response.get("headers")
    if not isinstance(headers, dict):
        raise ExecutionEvidenceError("Gateway response lacks AWS request correlation")
    aws_ids = {value for key, value in headers.items()
        if isinstance(key, str) and key.lower() in REQUEST_HEADERS
        and isinstance(value, str) and value.strip()}
    if len(aws_ids) != 1:
        raise ExecutionEvidenceError("Gateway response lacks an unambiguous AWS request ID")
    result = body.get("result")
    if not isinstance(result, dict) or "error" in result or result.get("isError", False) is not False:
        raise ExecutionEvidenceError("Gateway tool result is missing or reports an error")
    representations = []
    if "structuredContent" in result:
        structured = result["structuredContent"]
        if not isinstance(structured, dict):
            raise ExecutionEvidenceError("MCP structuredContent must be an object")
        representations.append(structured)
    if "content" in result:
        content = result["content"]
        if not isinstance(content, list) or len(content) > 1:
            raise ExecutionEvidenceError("Unexpected synthetic tool content shape")
        for block in content:
            if not isinstance(block, dict) or block.get("type") != "text" or not isinstance(block.get("text"), str):
                raise ExecutionEvidenceError("Expected synthetic tool JSON text content")
            representations.append(_json_object(block["text"]))
    # Check every representation before equality: in Python False == 0, which
    # must not hide an invalid alternate JSON representation.
    for value in representations:
        if set(value) != {"status", "request_id", "business_key", "idempotent_replay"} or type(value["idempotent_replay"]) is not bool:
            raise ExecutionEvidenceError("Unexpected synthetic payment result contract")
        if any(not isinstance(value[key], str) or not value[key] for key in ("status", "request_id", "business_key")):
            raise ExecutionEvidenceError("Synthetic payment result identifiers must be strings")
        if value["status"] != "PAYMENT_PREPARED":
            raise ExecutionEvidenceError("Payment preparation was not confirmed by the tool")
    if not representations or any(value != representations[0] for value in representations[1:]):
        raise ExecutionEvidenceError("Missing or conflicting tool result representations")
    value = representations[0]
    return value, next(iter(aws_ids))


def validate_execution_evidence(response, *, mcp_id: str, request_id: str,
        business_key: str, gateway_id: str, target_id: str,
        before_items, after_items) -> dict[str, Any]:
    """Require one corresponding insert, or an unchanged idempotent replay.

    A first insert must be correlated to this call's AWS and MCP identifiers.
    A replay retains the first insert's identifiers and must not alter any item.
    Successful parsing without the matching ledger effect never proves ALLOW.
    """
    if any(not isinstance(value, str) or not value for value in
            (mcp_id, request_id, business_key, gateway_id, target_id)):
        raise ExecutionEvidenceError("Execution binding is incomplete")
    value, aws_request_id = _tool_result(response, mcp_id)
    if value["request_id"] != request_id or value["business_key"] != business_key:
        raise ExecutionEvidenceError("Tool result does not match the intended request")
    before = decode_ledger_items(before_items)
    after = decode_ledger_items(after_items)
    before_by_key = {record["business_key"]: record for record in before}
    after_by_key = {record["business_key"]: record for record in after}
    record = after_by_key.get(business_key)
    if record is None:
        raise ExecutionEvidenceError("Tool success has no corresponding ledger record")
    required_strings = {"business_key", "connection_id", "fixture_dataset_id", "request_id",
        "action", "execution_status", "aws_request_id", "mcp_message_id", "gateway_id",
        "target_id", "observed_at"}
    if not required_strings <= set(record) or any(not isinstance(record[key], str) or not record[key] for key in required_strings):
        raise ExecutionEvidenceError("Ledger record lacks required execution evidence")
    expected = {"business_key": business_key, "request_id": request_id,
        "action": "prepare_vendor_payment", "execution_status": "PAYMENT_PREPARED",
        "gateway_id": gateway_id, "target_id": target_id}
    if any(record.get(key) != item for key, item in expected.items()) or business_key != "#".join(
            (record["connection_id"], record["fixture_dataset_id"], request_id)):
        raise ExecutionEvidenceError("Ledger record does not match the bound execution")
    existed = business_key in before_by_key
    if value["idempotent_replay"]:
        if not existed or before != after:
            raise ExecutionEvidenceError("Idempotent replay changed the ledger or lacks a prior record")
    else:
        if existed or set(after_by_key) != set(before_by_key) | {business_key}:
            raise ExecutionEvidenceError("Expected exactly one newly prepared business key")
        if any(after_by_key[key] != item for key, item in before_by_key.items()):
            raise ExecutionEvidenceError("An unrelated ledger record changed")
        if record["mcp_message_id"] != mcp_id or record["aws_request_id"] != aws_request_id:
            raise ExecutionEvidenceError("New ledger record is not correlated to this Gateway call")
    return {"status": "PASS", "outcome": "ALLOW", "created": not existed,
        "aws_request_id": aws_request_id, "mcp_id": mcp_id,
        "business_key": business_key, "tool_result": dict(value), "ledger_record": dict(record),
        "before_ledger_hash": sha256_json(before), "after_ledger_hash": sha256_json(after)}
