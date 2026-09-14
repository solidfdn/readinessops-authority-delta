# Implementation — ReadinessOps AWS edition

This document describes the current implemented boundary. It distinguishes the
ReadinessOps product core from its optional connected AWS enforcement path and
does not reduce the product to VendorPayment.

## Product boundary

ReadinessOps supports a complete evidence-to-decision workflow without a second
AWS account or an execution adapter:

1. Register a business object, owner, question, goals and measures.
2. Add versioned TXT, text-PDF or JSON evidence.
3. Run a cited Strands assessment from a fixed input snapshot.
4. Let an authenticated reviewer edit, approve, return or reject the proposal.
5. Explicitly publish one revision as the official decision.
6. Assign Actions, record Outcomes and retain the versioned history.
7. Use Authority Delta to identify affected, unchanged and unknown decision items
   when evidence, rules or an Agent release changes.

`VendorPayment V2` is the first registered execution adapter used for live
acceptance. It is synthetic and performs no real payment. A non-payment business
object can complete the common workflow without pretending that another execution
adapter exists.

## Core AWS services

| Responsibility | Implementation | Authority boundary |
| --- | --- | --- |
| Reviewer workspace | React and TypeScript behind Amazon CloudFront; Amazon Cognito sign-in | The browser supplies business commands, never trusted AWS resource identities or Policy text |
| Business API | Amazon API Gateway and AWS Lambda | JWT subject and scopes are verified server-side; revisions and request IDs are checked conditionally |
| Versioned truth | Amazon DynamoDB and versioned Amazon S3 | Evidence, snapshots, runs, drafts, receipts and publications remain version-fixed |
| Assessment | Amazon SQS worker, Strands Agents SDK, Amazon Bedrock AgentCore Runtime and Amazon Nova Pro | The Agent reads only its fixed snapshot and proposes cited items; it cannot approve, publish or mutate AWS Policy |
| Recovery | DynamoDB outboxes, SQS/DLQ and scheduled dispatch | Duplicate delivery, lost responses and uncertain results remain recoverable without being guessed successful |

ApprovalReceipt, DecisionPublication/PublishedCurrent, AWS delegation,
AppliedBinding and execution Outcome are separate records. Business approval or
publication alone never grants runtime permission.

## Optional connected AWS enforcement

Connected enforcement starts only when the server has a registered adapter and an
authenticated person separately approves an `AWS_DELEGATION_AUTHORITY` receipt.
The receipt binds the exact publication, connection, Runtime release, finite
request set, compiled Policy hash, expiry and generation.

The connector contract binds a registered target account but does not make a
two-account layout a product-wide requirement. The live RO-07 topology uses
account A for the ReadinessOps control plane and a distinct customer account B for
the registered VendorPayment enforcement plane. That distinct-account layout is
the connected topology proven by this repository. The supplied foundation and
connector operators explicitly reject account A as their target. A same-account
connector deployment is therefore not supported or verified by this release.

### 1. Deployment verification

The account-A deployment operator assumes only the ExternalId-bound, read-only
account-B `DiscoveryRole`. It rereads the Runtime, Gateway, Policy Engine, target,
connector functions and immutable registry before accepting the packaged binding.
CodeBuild is used for deployment and readback, not for ordinary user runs.

### 2. Policy application and revocation

The account-A Application/Revocation Worker assumes the ExternalId-bound
`PublishInvokeRole` and invokes only the qualified account-B Publisher Lambda.
The worker has no direct AgentCore Policy permission.

The Publisher owns only the exact Policy derived from the immutable candidate. It
journals each cloud mutation, creates or removes that Policy, and uses the fixed
Canary to verify real Gateway `ALLOW`/`DENY` results. An application becomes the
AppliedBinding only after complete Publisher and canary evidence is verified.

### 3. Normal controlled invocation

Normal execution does not pass through the Policy Publisher. The authenticated
Invocation Gate first verifies that the exact AppliedBinding, delegation receipt,
generation, publication and request identity are current and open. Acceptance is
linearized against stop and written to an invocation outbox.

The Invocation Worker then assumes the separate ExternalId-bound
`RuntimeInvokeRole` and invokes only the qualified account-B Invocation Lambda.
That Lambda verifies the active Publisher journal before calling the registered
AgentCore Runtime. The Runtime reaches the synthetic tool only through AgentCore
Gateway and its Policy Engine. The immutable request registry fixes the input, and
the sandbox ledger records an idempotent synthetic effect.

The qualified result and its evidence hash return to account A, where the result
is retained with the business record and history.

## Stop and expiry invariant

A stop request or expiry first closes the product-controlled entry and invalidates
the delegation generation. An already accepted invocation is drained before the
Policy is removed; new invocation acceptance cannot reopen the closed generation.

`STOP_REQUESTED` and `UNKNOWN` are not completion states. Suspension becomes
`SUSPENDED_CONFIRMED` only after all of the following are verified:

- the entry remains closed;
- the exact owned Policy is absent;
- every registered request returns a fresh live `DENY`;
- the synthetic ledger is unchanged; and
- the complete result matches the current application, enforcement digest and
  revocation request.

Lost or malformed cloud responses remain `UNKNOWN`, retain the writer fence and
reconcile the same operation. They are never converted to success by timeout or
retry alone.

## Evidence-backed status

| Scope | Status |
| --- | --- |
| Deployed common workspace, authenticated publication and retained history | Observed in the live product |
| Strands/AgentCore cited assessment path | Live evidence retained for the accepted scope |
| Optional two-account VendorPayment application, normal registered `ALLOW`, stop, exact Policy removal and all-request live `DENY` | `RO07_LIVE_AUTHORITY_LIFECYCLE_CONFIRMED` |
| Non-payment common workflow | Implemented and separately validated without claiming a second execution adapter |
| RO-10 outcome recording and RO-11 fixed-reference import | Authenticated UI and integrity checks passed for the [documented scope](BUSINESS_OUTCOME_INTERCHANGE.md) |
| RO-08 action completion and reassessment | Action completion and immutable history verified; reliable reassessment remains open. Runtime 23 deployed successfully, but live reassessment still rejected missing required fields and empty impact citations. RO-08 is not accepted. Failed runs retain their fixed inputs; official decision, delegation, application, revocation, invocation, outcomes and imports were verified unchanged. |
| Final submission checks | Tracked separately from technical acceptance |

The offline RO-07 verifier performs no AWS action. Local tests, synthetic canaries
and generated contracts are not presented as substitutes for authenticated human
or live AWS evidence.

## Code map

- `workbench/` and `services/workbench/`: authenticated reviewer workspace.
- `services/business/handler.py`: JWT-authorized business API.
- `services/business/worker.py`: queued assessment and recovery.
- `services/business/application_worker.py`: application and revocation workers.
- `services/business/invocation_gate.py`: authenticated execution entry and worker.
- `services/customer_publisher/handler.py`: limited Publisher, Canary and Invocation
  Lambda entry points in the connected account.
- `services/sandbox/handler.py`: registered synthetic Gateway target and idempotent
  sandbox ledger behavior.
- `src/authority_delta/business/`: receipts, applications, invocation, revocation,
  storage, evidence and interchange contracts.
- `infra/`: reproducible CloudFormation resource definitions.
- `evidence/`: scoped observed and local verification records.

See [the architecture diagrams](ARCHITECTURE.md) and
[the live RO-07 acceptance record](RO07_LIVE_ACCEPTANCE.md).
