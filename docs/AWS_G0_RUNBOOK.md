# AWS G0 preflight runbook

G0 verifies the actual signed-in AWS identity and Tokyo Region service surface before any Authority Delta resource is created. It is deliberately read-only.

## Run in AWS CloudShell

Upload or clone this repository, open its root directory, and run:

```bash
chmod +x scripts/aws_g0_preflight.sh
EXPECTED_AWS_ACCOUNT_ID=538522204923 \
AUTHORITY_DELTA_REGION=ap-northeast-1 \
./scripts/aws_g0_preflight.sh
```

The command fails closed when the signed-in account differs from `538522204923`, any required CloudFormation type is unavailable, the template cannot be validated, or the AgentCore/Bedrock read APIs cannot be called.

On success it writes `evidence/aws/g0-preflight-<UTC timestamp>.json`. The file contains the caller identity, Region, AWS CLI version, CloudFormation type metadata, and bounded service-response metadata. It never writes credentials, tokens, or keys and creates no AWS resource.

Do not deploy the customer baseline until this evidence is reviewed and `status/PROJECT_STATE.json` is updated. A successful G0 does not prove model invocation, Gateway enforcement, or Gate A.
