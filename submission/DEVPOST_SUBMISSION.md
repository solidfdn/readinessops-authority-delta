# Devpost submission copy

## Project name

ReadinessOps — Authority Delta

## Tagline

Keep evidence-backed human decisions current—and optionally connect them to
finite, revocable AWS agent authority.

## Track

Professional Agents

## Short description

ReadinessOps helps AI initiative owners decide how to proceed, why the decision
is justified, and what must be reviewed when the evidence changes. Strands
analyzes versioned evidence and proposes cited gaps, risks, actions and decision
items. A human edits, approves and explicitly publishes the exact decision.
Authority Delta then identifies affected, unchanged and unknown decision items
when evidence or an Agent release changes. If a registered execution adapter is
available, a separate finite delegation can optionally connect that decision to
AWS authority.

## Inspiration

Enterprise AI teams often have policy documents, model evaluations and approval
meetings, yet the final business decision is disconnected from the permission an
agent actually receives. A policy can say “human approval required” while the
runtime path remains broader, older or difficult to revoke. ReadinessOps was built
to connect evidence, accountable human judgment and enforceable runtime authority
without asking the model to approve itself.

## What it does

- Registers a business initiative, its owner, question and success measures.
- Stores versioned TXT, text-PDF and JSON evidence.
- Runs a Strands agent on Amazon Bedrock AgentCore to produce cited Gap, Risk,
  Action and Decision proposals across Governance, Value, Model Routing and
  Portfolio perspectives.
- Keeps AI output advisory: an authenticated person edits, approves and explicitly
  publishes a fixed decision revision.
- Keeps the evidence, assessment, human publication, Actions, Outcomes and history
  workflow usable without a connected execution account.
- For an optional registered AWS adapter, applies a separate typed delegation only
  after publication. The browser cannot submit arbitrary ARNs, Policy text or
  requests.
- Uses an account-A control plane and an ExternalId-bound account-B publisher for
  the RO-07-verified VendorPayment connection, not as a requirement for core use.
- Allows only a finite, registered request set through the Gateway and records the
  real outcome.
- Closes the product entry before revocation, removes only the owned Policy, proves
  live DENY for the complete request set, and keeps the ledger unchanged.
- Preserves immutable evidence, receipts, publications, applications, invocations,
  revocations and outcomes for later reassessment.

## How we built it

The product uses React and TypeScript behind CloudFront, Amazon Cognito for the
reviewer identity, API Gateway and Lambda for version-checked business operations,
DynamoDB for conditional state transitions and S3 for immutable evidence. SQS
outboxes make assessment, application, invocation and revocation recoverable.

The analysis agent is built with the Strands Agents SDK and deployed to Amazon
Bedrock AgentCore Runtime using Amazon Nova Pro. Its tools can read only the fixed
assessment snapshot and return structured, cited proposals; they cannot approve,
publish or edit AWS Policy.

The ReadinessOps core runs without a second account, and the connector contract
does not prescribe an account topology. For the optional VendorPayment connection
verified by RO-07, the deployment uses two AWS accounts as a least-privilege
choice. Account A owns business state and workers. Account B owns the registered
Runtime, Gateway, Policy engine, publisher and synthetic ledger. STS roles bind
that connection with an ExternalId and separate read-only discovery, Policy
publication and normal runtime invocation. Every candidate starts closed, uses
deterministic Policy input and idempotent journals, and becomes active only after
live canary verification.

## Challenges

The hardest part was defining “done” across distributed authority. A successful
API call is not the same as a verified Policy, and a stop request is not the same
as confirmed suspension. AgentCore Policy responses also contain optional fields,
and lost responses must not create duplicate authority. We built explicit states,
readback contracts, durable outboxes and same-candidate reconciliation so unknown
results remain closed instead of being guessed successful.

## Accomplishments

- A complete evidence-to-human-decision product flow, not a chat-only agent.
- A real Strands/AgentCore analysis path with source-bound citations.
- An optional VendorPayment connector deployed across two accounts for the live
  least-privilege proof, with separate discovery, publishing and
  runtime-invocation roles.
- Live proof of one registered `ALLOW` invocation followed by entry closure, exact
  Policy removal, complete live `DENY`, and unchanged-ledger verification.
- An authenticated, hash-bound export that passed
  `RO07_LIVE_AUTHORITY_LIFECYCLE_CONFIRMED`.
- Fail-closed handling for stale revisions, timeouts, duplicate delivery, partial
  writes and unconfirmed cloud responses.

## What we learned

Agent governance is not only about writing a policy. It is the operational chain
from evidence, to a named human decision, to finite authority, to real execution,
to verified removal. The system must preserve those distinctions even when a
network response is lost or an agent release changes.

## What is next

The same typed adapter boundary can support additional enterprise workflows while
keeping business-specific schemas and side effects outside the shared decision
plane. Future work includes customer-managed identity federation, portfolio-level
governance views and additional measured outcomes. We will retain the rule that a
new adapter must prove its own finite authority and revocation contract.

## Technologies

Python 3.12, TypeScript, React, Strands Agents SDK, Amazon Bedrock AgentCore
Runtime, Amazon Bedrock AgentCore Gateway and Policy, Amazon Nova Pro, AWS Lambda,
Amazon API Gateway, Amazon Cognito, Amazon CloudFront, Amazon S3, Amazon DynamoDB,
Amazon SQS, AWS STS, AWS CloudFormation and AWS CodeBuild.

## Required links and fields

- Public repository: `https://github.com/solidfdn/readinessops-authority-delta`
- Architecture diagrams: `docs/ARCHITECTURE.md`
- Live demo: `https://d3rn3hqm0ax5ux.cloudfront.net/`
- Demo video: add the final public YouTube or Vimeo URL
- AWS Builder ID: enter the Builder ID used for the registered submission
- Testing access: provide the existing judge username and password only in the
  private Devpost testing-instructions field; never commit credentials.

## Prior-work disclosure

ReadinessOps as a governance concept predates this event. This AWS project,
including the Strands agent, AgentCore Runtime and Gateway/Policy integration,
optional connected VendorPayment topology, authenticated Workbench and Authority
Delta implementation, was created during the hackathon period. No source code
from the prior Snowflake or Google implementations was incorporated. Standard
open-source libraries and AI coding assistance were used; dependencies and the
Apache-2.0 license are included in the repository.
