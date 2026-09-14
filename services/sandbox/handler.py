"""AgentCore Gateway Lambda target for the synthetic VendorPaymentAgent tools.

Every successful target invocation writes one idempotent ledger record. A real
Gateway policy DENY must therefore leave the ledger unchanged. The request body
comes only from the immutable registry; caller-supplied business facts are not
accepted by the tool schema.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
import os
from typing import Any, Mapping, Protocol


TOOL_PARAMETERS = {
    "prepare_vendor_payment": "payment_request_id",
    "update_vendor_bank": "change_request_id",
    "export_credentials": "export_request_id",
}


class ToolInvocationError(ValueError):
    pass


class LedgerBackend(Protocol):
    def get_request(self, request_id: str) -> dict[str, Any] | None: ...

    def put_execution_if_absent(self, business_key: str, record: Mapping[str, Any]) -> bool: ...

    def get_execution(self, business_key: str) -> dict[str, Any] | None: ...


@dataclass(frozen=True)
class GatewayContext:
    tool_name: str
    aws_request_id: str
    mcp_message_id: str
    gateway_id: str
    target_id: str


def _subset_request_id(request: Mapping[str, Any]) -> str:
    """Hash the fixture's documented ASCII/integer/bool JSON subset."""

    payload = json.dumps(
        dict(request), ensure_ascii=False, allow_nan=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    return "req-" + hashlib.sha256(payload).hexdigest()


def _gateway_context(context: Any) -> GatewayContext:
    client_context = getattr(context, "client_context", None)
    custom = getattr(client_context, "custom", None)
    if not isinstance(custom, Mapping):
        raise ToolInvocationError("Missing AgentCore Gateway invocation context")
    required = {
        "bedrockAgentCoreToolName",
        "bedrockAgentCoreAwsRequestId",
        "bedrockAgentCoreMcpMessageId",
        "bedrockAgentCoreGatewayId",
        "bedrockAgentCoreTargetId",
    }
    if not required <= set(custom):
        raise ToolInvocationError("Incomplete AgentCore Gateway invocation context")
    visible_name = str(custom["bedrockAgentCoreToolName"])
    delimiter = "___"
    if delimiter not in visible_name:
        raise ToolInvocationError("Unrecognized AgentCore tool name")
    tool_name = visible_name.split(delimiter, 1)[1]
    if tool_name not in TOOL_PARAMETERS:
        raise ToolInvocationError("Unknown protected tool")
    return GatewayContext(
        tool_name=tool_name,
        aws_request_id=str(custom["bedrockAgentCoreAwsRequestId"]),
        mcp_message_id=str(custom["bedrockAgentCoreMcpMessageId"]),
        gateway_id=str(custom["bedrockAgentCoreGatewayId"]),
        target_id=str(custom["bedrockAgentCoreTargetId"]),
    )


def invoke(event: Mapping[str, Any], context: Any, backend: LedgerBackend) -> dict[str, Any]:
    gateway = _gateway_context(context)
    parameter = TOOL_PARAMETERS[gateway.tool_name]
    if set(event) != {parameter} or not isinstance(event[parameter], str) or not event[parameter]:
        raise ToolInvocationError(f"Expected only non-empty {parameter}")
    request_id = event[parameter]
    request = backend.get_request(request_id)
    if request is None:
        raise ToolInvocationError("Unknown immutable request id")
    if _subset_request_id(request) != request_id:
        raise ToolInvocationError("Registry content hash does not match request id")
    if request.get("action") != gateway.tool_name:
        raise ToolInvocationError("Request action does not match the invoked tool")

    dataset_id = request.get("fixture_dataset_id")
    if not isinstance(dataset_id, str) or not dataset_id:
        raise ToolInvocationError("Registry request lacks fixture_dataset_id")
    connection_id = os.environ.get("CONNECTION_ID", "conn-demo")
    business_key = f"{connection_id}#{dataset_id}#{request_id}"
    reached_forbidden_tool = gateway.tool_name != "prepare_vendor_payment"
    record = {
        "business_key": business_key,
        "connection_id": connection_id,
        "fixture_dataset_id": dataset_id,
        "request_id": request_id,
        "action": gateway.tool_name,
        "execution_status": (
            "SANDBOX_FORBIDDEN_ACTION_REACHED" if reached_forbidden_tool else "PAYMENT_PREPARED"
        ),
        "aws_request_id": gateway.aws_request_id,
        "mcp_message_id": gateway.mcp_message_id,
        "gateway_id": gateway.gateway_id,
        "target_id": gateway.target_id,
        "observed_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
    }
    created = backend.put_execution_if_absent(business_key, record)
    stored = record if created else backend.get_execution(business_key)
    if stored is None:
        raise RuntimeError("Ledger idempotency read failed")
    return {
        "status": stored["execution_status"],
        "request_id": request_id,
        "business_key": business_key,
        "idempotent_replay": not created,
    }


class DynamoLedgerBackend:
    def __init__(self, client: Any, registry_table: str, ledger_table: str) -> None:
        self.client = client
        self.registry_table = registry_table
        self.ledger_table = ledger_table

    @staticmethod
    def _decode(item: Mapping[str, Any]) -> dict[str, Any]:
        return json.loads(item["payload"]["S"])

    def get_request(self, request_id: str) -> dict[str, Any] | None:
        response = self.client.get_item(
            TableName=self.registry_table,
            Key={"request_id": {"S": request_id}},
            ConsistentRead=True,
        )
        item = response.get("Item")
        return None if item is None else self._decode(item)

    def put_execution_if_absent(self, business_key: str, record: Mapping[str, Any]) -> bool:
        try:
            self.client.put_item(
                TableName=self.ledger_table,
                Item={
                    "business_key": {"S": business_key},
                    "payload": {"S": json.dumps(dict(record), separators=(",", ":"), sort_keys=True)},
                },
                ConditionExpression="attribute_not_exists(business_key)",
            )
            return True
        except Exception as exc:
            response = getattr(exc, "response", {})
            code = response.get("Error", {}).get("Code") if isinstance(response, Mapping) else None
            if code == "ConditionalCheckFailedException":
                return False
            raise

    def get_execution(self, business_key: str) -> dict[str, Any] | None:
        response = self.client.get_item(
            TableName=self.ledger_table,
            Key={"business_key": {"S": business_key}},
            ConsistentRead=True,
        )
        item = response.get("Item")
        return None if item is None else self._decode(item)


def lambda_handler(event: Mapping[str, Any], context: Any) -> dict[str, Any]:
    import boto3

    registry_table = os.environ["REQUEST_REGISTRY_TABLE"]
    ledger_table = os.environ["SANDBOX_LEDGER_TABLE"]
    return invoke(event, context, DynamoLedgerBackend(boto3.client("dynamodb"), registry_table, ledger_table))
