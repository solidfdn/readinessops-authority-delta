"""Finite, exact-scope Cedar compiler for trusted Authority Delta policy plans.

This module does not approve a release or discover AWS identities. Its caller
must bind a trusted policy plan and registry snapshot to the registered Runtime
version and role before publishing. A rendered policy is not AWS validation.
"""

from __future__ import annotations

from collections.abc import Sequence
import json
import re
from typing import Any

from .canonical import sha256_bytes, sha256_json


class CedarContractError(ValueError):
    """The input cannot be expressed by this finite, exact-role adapter."""


_PARTITION = r"aws(?:-cn|-us-gov)?"
_NAME = r"[A-Za-z0-9_+=,.@-]"
_IAM_ROLE = re.compile(
    rf"arn:(?P<partition>{_PARTITION}):iam::(?P<account>[0-9]{{12}}):role/(?P<resource>.+)"
)
_STS_ROLE = re.compile(
    rf"arn:(?P<partition>{_PARTITION}):sts::(?P<account>[0-9]{{12}}):"
    rf"assumed-role/(?P<role>{_NAME}{{1,64}})/(?P<session>{_NAME}{{2,64}})"
)
_GATEWAY = re.compile(
    rf"arn:(?P<partition>{_PARTITION}):bedrock-agentcore:"
    r"(?P<region>[a-z0-9-]{1,20}):(?P<account>[0-9]{12}):"
    r"gateway/([0-9a-z][-]?){1,48}-[a-z0-9]{10}"
)
_ROLE_COMPONENT = re.compile(rf"{_NAME}+")
_REQUEST_ID = re.compile(r"req-[0-9a-f]{64}")
_HASH = re.compile(r"[0-9a-f]{64}")
_TARGET = re.compile(r"[A-Za-z][A-Za-z0-9-]{0,99}")


def _text(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        raise CedarContractError(f"{label} must be a non-empty exact string")
    return value


def _registered_role(role_arn: str) -> tuple[str, str, str]:
    match = _IAM_ROLE.fullmatch(_text(role_arn, "IAM role ARN"))
    if match is None:
        raise CedarContractError("Expected an IAM role ARN with no Region")
    resource = match["resource"]
    components = resource.split("/")
    # Keep the complete registered ARN in bindings. Only its role-name component
    # maps to the documented STS identity. Never remove empty/path traversal
    # segments or decode escaped input into an alternative role.
    if any(c in {"", ".", ".."} or _ROLE_COMPONENT.fullmatch(c) is None for c in components):
        raise CedarContractError("Unsupported or ambiguous IAM role path")
    if len(components[-1]) > 64:
        raise CedarContractError("IAM role name exceeds 64 characters")
    path = "/" + "/".join(components[:-1]) + ("/" if len(components) > 1 else "")
    if len(path) > 512:
        raise CedarContractError("IAM role path exceeds 512 characters")
    return match["partition"], match["account"], components[-1]


def _observed_role(session_arn: str) -> tuple[str, str, str]:
    match = _STS_ROLE.fullmatch(_text(session_arn, "STS role session ARN"))
    if match is None or match["role"] in {".", ".."} or match["session"] in {".", ".."}:
        raise CedarContractError("Expected a complete STS assumed-role/name/session ARN")
    return match["partition"], match["account"], match["role"]


def principal_id_from_role_arn(role_arn: str) -> str:
    """Map an IAM role or complete observed STS session to AgentCore's role ID.

    Bare normalized STS IDs are rejected as input: they are compiler output,
    not GetCallerIdentity observations. No wildcard or session prefix matching.
    """
    role_arn = _text(role_arn, "Role ARN")
    binding = _registered_role(role_arn) if ":iam::" in role_arn else _observed_role(role_arn)
    partition, account, role = binding
    return f"arn:{partition}:sts::{account}:assumed-role/{role}"


def assert_observed_role_matches(registered_role_arn: str, observed_session_arn: str) -> str:
    """Require exact partition/account/role identity; return normalized ID.

    An STS session does not reveal an IAM path or a role's immutable RoleId.
    Callers must separately retain and verify the registered ARN/RoleId and
    Runtime version. This helper must not be used to reconstruct a role ARN.
    """
    if _registered_role(registered_role_arn) != _observed_role(observed_session_arn):
        raise CedarContractError("Observed STS role does not match registered execution role")
    return principal_id_from_role_arn(registered_role_arn)


def compile_exact_scope_permit(
    *,
    gateway_arn: str,
    role_arn: str,
    allowed_request_ids: Sequence[str],
    request_registry_snapshot_hash: str,
    target_name: str,
    tool_name: str,
    input_name: str,
    compiler_id: str,
) -> dict[str, Any] | None:
    """Render registered principal/tool/input scope; caller validates adapter and schema.

    Tool/input names must come from a trusted, versioned adapter binding, never
    from client or model permission proposals. This renders only finite request IDs.
    """
    for name in (tool_name,input_name):
        if not isinstance(name,str) or not re.fullmatch(r"[A-Za-z][A-Za-z0-9_]{0,99}",name):
            raise CedarContractError("Tool/input binding must be one exact schema identifier")
    if not isinstance(compiler_id,str) or not re.fullmatch(r"[a-z0-9-]{1,100}",compiler_id):
        raise CedarContractError("Registered compiler identifier required")
    gateway = _GATEWAY.fullmatch(_text(gateway_arn, "Gateway ARN"))
    if gateway is None:
        raise CedarContractError("Expected an exact AgentCore Gateway ARN")
    principal_id = principal_id_from_role_arn(role_arn)
    role = _registered_role(role_arn) if ":iam::" in role_arn else _observed_role(role_arn)
    if (gateway["partition"], gateway["account"]) != role[:2]:
        raise CedarContractError("Gateway and customer execution role must share partition/account")
    if _TARGET.fullmatch(_text(target_name, "Gateway target name")) is None:
        raise CedarContractError("Unsupported target name or embedded tool delimiter")
    if _HASH.fullmatch(_text(request_registry_snapshot_hash, "Registry snapshot hash")) is None:
        raise CedarContractError("Registry snapshot hash must be SHA-256 lowercase hex")
    if not isinstance(allowed_request_ids, Sequence) or isinstance(allowed_request_ids, (str, bytes)):
        raise CedarContractError("Allowed request IDs must be a sequence of content identities")
    if any(not isinstance(v, str) or _REQUEST_ID.fullmatch(v) is None for v in allowed_request_ids):
        raise CedarContractError("Allowed request IDs must have the immutable req-SHA256 format")
    if len(set(allowed_request_ids)) != len(allowed_request_ids):
        raise CedarContractError("Allowed request IDs must be unique")
    allowed = sorted(allowed_request_ids)
    if not allowed:
        return None

    action_name = f"{target_name}___{tool_name}"
    # JSON string literals are also valid Cedar string literals for this
    # validated ASCII subset. This text is an SDK value, never shell code.
    literal = lambda value: json.dumps(value, ensure_ascii=True, allow_nan=False)
    statement = (
        "permit(\n"
        f"  principal == AgentCore::IamEntity::{literal(principal_id)},\n"
        f"  action == AgentCore::Action::{literal(action_name)},\n"
        f"  resource == AgentCore::Gateway::{literal(gateway_arn)}\n"
        ")\nwhen {\n"
        f"  {literal(allowed)}.contains(context.input.{input_name})\n"
        "};"
    )
    if len(statement.encode("utf-8")) > 10000:
        raise CedarContractError("Policy exceeds the fixed SDK's 10000-character policy limit")
    binding = {
        "schema_version": "1.0",
        "compiler": compiler_id,
        "gateway_arn": gateway_arn,
        "principal_id": principal_id,
        "action_name": action_name,
        "allowed_request_ids": allowed,
        "request_registry_snapshot_hash": request_registry_snapshot_hash,
    }
    return {
        **binding,
        "statement": statement,
        "policy_hash": sha256_bytes(statement.encode("utf-8")),
        "binding_hash": sha256_json(binding),
    }


def compile_permit(*,gateway_arn,role_arn,allowed_request_ids,request_registry_snapshot_hash,target_name="VendorPaymentTools"):
    """Compatibility wrapper preserving the deployed payment compiler bytes."""
    from .adapters.vendor_payment_policy import compile_payment_permit
    return compile_payment_permit(gateway_arn=gateway_arn,role_arn=role_arn,
        allowed_request_ids=allowed_request_ids,request_registry_snapshot_hash=request_registry_snapshot_hash,target_name=target_name)
