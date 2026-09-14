# Live baseline verification V3

**Completed:** the user-provided V3 excerpt at 2026-09-08 06:28:54Z records seven
default denials, unchanged state and Gate 0 PASS. The instructions below document
that completed operation; do not ask the operator to rerun it. Next is Gate A
V1/V2 identities and scoped permit controls.

V1 misclassified the real Tokyo JSON-RPC `error.code = -32002` Policy rejection.
V2 recognizes that observed envelope and the documented `result.isError` envelope.
Both still require the Policy-specific text and matching AWS/MCP request identity.
The original V1 evidence remains intact. Its P-001 call is a confirmed policy
rejection with unchanged state; the other six calls were not executed.

Run after the successful Recovery R1 deployment. This package uses the existing
`authority-delta-deploy` CodeBuild project and the exact registered Tokyo resources.
It does not deploy CloudFormation, change IAM, create policies, reseed tables or
reset the ledger. It uploads versioned source and writes versioned test evidence.

The user's V2 build `216ae0dc-03d0-4950-8471-d212e6ccedfb` failed during final
JSON serialization at 06:09:03Z. No final report was saved; its Gateway/model
outcomes cannot be inferred from the supplied traceback. The bundled SDK returns
model lifecycle timestamps as Python datetime objects, which reproduces this defect.

Upload the small `Authority_Delta_Repair_V3.py` file to CloudShell and run:

```bash
python3 ~/Authority_Delta_Repair_V3.py
```

Keep the already uploaded `ReadinessOps_Authority_Delta_AWS_Verification_V2.zip`
in CloudShell home. The repair checks its exact SHA-256, extracts into a new
working directory, applies the embedded committed changes, recovers the failed
build's progress logs, and starts the repaired verification once. It does not
change the original ZIP. Progress log lines alone cannot complete a gate.
The complete V3 ZIP is an alternative archive; its `scripts/verify_existing.sh`
executes the same verifier without the failed-run log recovery wrapper.

V3 explicitly serializes AWS dates/timestamps; canonical approval hashes are
unchanged. It saves a versioned Gateway checkpoint before model invocation, then
prints and saves the final report. Unsupported object types produce an explicit
FAIL report with the affected sections named and valid evidence retained. If the
final report is unavailable, the launcher retrieves the matching checkpoint and
still exits with failure. A checkpoint is not a completed verification.

The job verifies the code hash, target input schemas, immutable registry and empty
ENFORCE engine. It calls all seven fixture requests across three actual tools using
the CodeBuild role's SigV4 credentials. Each response must identify an AgentCore
Policy rejection, carry an AWS request ID, and match its MCP request ID. The full
registry, ledger, policy and target state must remain unchanged after the calls.
An unexpected response stops further tool calls and preserves diagnostics.

The model check attempts `openai.gpt-5.6-terra`, the candidate observed in the user's
Tokyo catalog. Only if it is unavailable, incompatible or returns no usable text,
it may attempt `amazon.nova-lite-v1:0` after reading that model's live catalog entry.
At most two Converse calls, each at most 128 output tokens; no automatic SDK retry,
subscription, model-access agreement, cross-Region profile or provisioned throughput.
The actual selected model and any first-attempt error are recorded. This tests model
connectivity, not model quality or Strands integration. Budget alerts are not a hard
spending stop. The existing $50 monthly notification configuration is unchanged.

V2 records the exact model catalog fields and unmet condition names. V1's combined
message did not identify which condition failed for the OpenAI candidate; it is not
evidence that the model itself is unsupported or inactive. The observed Nova error
was specifically AWS account verification pending. V2 reports that error as BLOCKED
and stops further model attempts. It does not treat generic IAM denial as this blocker.
No repeated polling or waiting build is added.

If Gateway verification passes while the account check is pending, CodeBuild may
complete SUCCEEDED while the verification result and Gate 0 remain BLOCKED. The
launcher prints BLOCKED and exits 2; this never means the product passed its gates.

The CodeBuild execution limit is 10 minutes. The launcher retrieves the result even
when the job reports failure, provided the worker reached evidence upload. It verifies
the build ID, source digest and immutable report version, then prints
`AUTHORITY_DELTA_VERIFICATION`. Source and report are stored in the existing private
versioned bucket. CloudShell keeps the downloaded evidence under `evidence/aws/<run>`.
If CloudShell disconnects, inspect the printed CodeBuild ID before starting another run.

**PASS means baseline verification only.** Gate A remains NOT_RUN because the
deployment role is not V2's runtime identity. Next implement and test V1/V2 fixed
runtime identities, unapproved V2 rejection (AUTH-01), and principal/tool/request
scoping with a real permit control (AUTH-02). Do not weaken the acceptance criteria.
Strands, human decisions, publication, two-account connection and UI remain unfinished.

Model-independent implementation added in V2: `services/vendor_agent/evaluator.py`
reads immutable requests with DynamoDB consistent reads, checks request/snapshot/
release-definition bindings and evaluates fixed V1/V2 definitions. Incomplete or
changed registry data becomes UNKNOWN. The module has local SDK tests; AgentCore
hosting, deployed V1/V2 identities and Gateway execution integration are not deployed.

Sources used for the implementation:

- [AWS Gateway Policy responses](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/use-gateway-with-policy.html)
- [AWS IAM inbound authorization](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/gateway-inbound-auth.html)
- [AWS Converse API](https://docs.aws.amazon.com/bedrock/latest/APIReference/API_runtime_Converse.html)
- Bundled botocore 1.43.89 service schemas: signing name `bedrock-agentcore`,
  `GetGatewayTarget`, `StartBuild.buildspecOverride`, `GetFoundationModel`, `Converse`.

Local tests use botocore Stubber and a synthetic HTTP transport. They validate SDK
shapes, request signing and error classification without claiming an AWS test run.
