#!/usr/bin/env bash
set -euo pipefail

# Read-only AWS preflight for AD-BASELINE-1.0.
# Run from the repository root in AWS CloudShell or another authenticated shell.

readonly EXPECTED_ACCOUNT_ID="${EXPECTED_AWS_ACCOUNT_ID:-538522204923}"
readonly TARGET_REGION="${AUTHORITY_DELTA_REGION:-ap-northeast-1}"
readonly EVIDENCE_DIR="${AUTHORITY_DELTA_EVIDENCE_DIR:-evidence/aws}"
readonly RUN_TIMESTAMP="$(date -u +%Y%m%dT%H%M%SZ)"
readonly OUTPUT_PATH="${EVIDENCE_DIR}/g0-preflight-${RUN_TIMESTAMP}.json"

command -v aws >/dev/null 2>&1 || {
  echo "ERROR: AWS CLI is required." >&2
  exit 2
}
command -v python3 >/dev/null 2>&1 || {
  echo "ERROR: python3 is required." >&2
  exit 2
}

mkdir -p "${EVIDENCE_DIR}"
readonly WORK_DIR="$(mktemp -d)"
trap 'rm -rf "${WORK_DIR}"' EXIT

export AWS_PAGER=""
export AWS_DEFAULT_REGION="${TARGET_REGION}"

aws --version >"${WORK_DIR}/aws-version.txt" 2>&1
aws sts get-caller-identity --output json >"${WORK_DIR}/identity.json"

readonly ACTUAL_ACCOUNT_ID="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1], encoding="utf-8"))["Account"])' "${WORK_DIR}/identity.json")"
if [[ "${ACTUAL_ACCOUNT_ID}" != "${EXPECTED_ACCOUNT_ID}" ]]; then
  echo "ERROR: signed-in account is ${ACTUAL_ACCOUNT_ID}; expected ${EXPECTED_ACCOUNT_ID}." >&2
  exit 3
fi

readonly TYPE_NAMES=(
  "AWS::BedrockAgentCore::PolicyEngine"
  "AWS::BedrockAgentCore::Gateway"
  "AWS::BedrockAgentCore::GatewayTarget"
)

for type_name in "${TYPE_NAMES[@]}"; do
  safe_name="${type_name//:/_}"
  aws cloudformation describe-type \
    --type RESOURCE \
    --type-name "${type_name}" \
    --region "${TARGET_REGION}" \
    --output json >"${WORK_DIR}/type-${safe_name}.json"
done

aws cloudformation validate-template \
  --template-body file://infra/customer-baseline/template.json \
  --region "${TARGET_REGION}" \
  --output json >"${WORK_DIR}/template-validation.json"

# Empty inventories are valid. A successful signed response proves endpoint and IAM access.
aws bedrock-agentcore-control list-gateways \
  --region "${TARGET_REGION}" \
  --page-size 1 \
  --max-items 1 \
  --output json >"${WORK_DIR}/gateways.json"

aws bedrock-agentcore-control list-policy-engines \
  --region "${TARGET_REGION}" \
  --page-size 1 \
  --max-items 1 \
  --output json >"${WORK_DIR}/policy-engines.json"

aws bedrock list-foundation-models \
  --region "${TARGET_REGION}" \
  --by-output-modality TEXT \
  --output json >"${WORK_DIR}/models.json"

python3 - "${WORK_DIR}" "${OUTPUT_PATH}" "${TARGET_REGION}" <<'PY'
from __future__ import annotations

import datetime as dt
import json
from pathlib import Path
import sys


work = Path(sys.argv[1])
output = Path(sys.argv[2])
region = sys.argv[3]


def load(name: str) -> dict:
    return json.loads((work / name).read_text(encoding="utf-8"))


identity = load("identity.json")
types = {}
for path in sorted(work.glob("type-*.json")):
    item = json.loads(path.read_text(encoding="utf-8"))
    type_name = item.get("TypeName") or path.stem.removeprefix("type-").replace("__", "::")
    types[type_name] = {
        "arn": item.get("Arn"),
        "default_version_id": item.get("DefaultVersionId"),
        "provisioning_type": item.get("ProvisioningType"),
    }

models = load("models.json").get("modelSummaries", [])
active_text_models = [
    {
        "model_id": item.get("modelId"),
        "provider": item.get("providerName"),
        "inference_types": item.get("inferenceTypesSupported", []),
    }
    for item in models
    if item.get("modelLifecycle", {}).get("status") == "ACTIVE"
]

evidence = {
    "schema_version": "1.0",
    "baseline_id": "AD-BASELINE-1.0",
    "scope": "READ_ONLY_G0_PREFLIGHT_NO_RESOURCES_CREATED",
    "observed_at": dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat(),
    "identity": {
        "account": identity["Account"],
        "arn": identity["Arn"],
        "user_id": identity["UserId"],
    },
    "region": region,
    "aws_cli_version": (work / "aws-version.txt").read_text(encoding="utf-8").strip(),
    "cloudformation": {
        "types": types,
        "template_capabilities": load("template-validation.json").get("Capabilities", []),
    },
    "agentcore": {
        "gateway_list_call": "PASS",
        "gateway_sample_count": len(load("gateways.json").get("items", [])),
        "policy_engine_list_call": "PASS",
        "policy_engine_sample_count": len(load("policy-engines.json").get("policyEngines", [])),
    },
    "bedrock": {
        "list_foundation_models_call": "PASS",
        "active_text_model_count": len(active_text_models),
        "active_text_models": active_text_models,
        "model_invocation_tested": False,
    },
    "result": "PASS",
    "credentials_recorded": False,
    "resources_created": False,
}
output.write_text(json.dumps(evidence, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
print(output)
PY

echo "G0 read-only preflight PASS: ${OUTPUT_PATH}"
