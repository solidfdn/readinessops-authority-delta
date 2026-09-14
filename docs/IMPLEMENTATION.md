# Implementation sequence — ReadinessOps AWS edition 1.2

This document records the implemented product boundary and its evidence-backed
acceptance sequence. It does not reduce the product to payments or remove
non-payment validation.

## Preserve what has passed

G0, GA and GB SEM-01/02 have preserved live evidence. Business workflow V2,
its synthetic non-payment assessment canary, and the deployed product UI
are user-reported PASS. Actual human approval/publication and complete GB UI,
GC/GD acceptance are pending. No reset, repeat deployment or successful-gate rerun
is the next step. Regress changed paths when needed without relabelling old proof.

## Engineering order and measurable exits

The live business workflow must ultimately begin with real authenticated human
approval and explicit publication. That is an **acceptance dependency**, not a
prerequisite for locally implementing subsequent stages with synthetic records.
Do not block engineering on the user entering a sample name or uploading a file.

| Stage | Engineering outcome | Exit evidence |
| --- | --- | --- |
| D1 Retain initial workflow | Preserve deployed object/question/evidence intake, queued assessment, editable pack, authenticated receipt and explicit business publication | Existing deployment/canary proof retained; real human workflow is checked in the integrated live acceptance, not invented from the canary |
| D2 Change and reassessment | Bind the prior publication/pack/receipt into the immutable input; validate affected Decision Items and dependencies; present changed/unchanged/unknown items, operational Actions and current-versus-candidate effects; record typed Outcome/Metric values; export/import issuer-bound fixed documents | Local positive and negative contract/UI tests, followed by real RO-03/06/08/09/10/11 evidence. Local implementation does not replace live acceptance |
| D3 AWS application | Explicitly connect the registered VendorPayment adapter and observed runtime bindings; require a separate typed delegation receipt; implement limited publisher, deny-first canary, verified AppliedBinding and outcomes | Local receipt/binding/publisher failure and recovery tests; then actual account B, remaining GB/SEM-03, GC and RO-05/07 live evidence |
| D4 Completion and delivery | Verify the connected user journey, negative controls, reconnection, clean installation, product UX, judge access and export/demo | RO-01–12 and relevant original gates/GD; submission conditions checked separately before authorized submission |

The D2 prior-publication binding, affected-item contract/review UI and operational
Action lifecycle are now locally implemented. The server issues stable Decision
Item IDs, maps historical objects explicitly, validates the exact prior
publication/digest and all AFFECTED / UNCHANGED / UNKNOWN classifications, and
returns the official comparison baseline to the review UI. Published Action
proposals start as `PROPOSED`; assignment requires an owner and due date, completion
requires new versioned evidence, and the first later assessment selecting that
evidence is linked without transferring approval. It is not deployed, and D2 live
RO acceptance remains pending.
The D3 control plane and bounded AWS execution package are now locally implemented. A packaged,
server-controlled adapter registry is empty by default and therefore fail-closed.
When supplied with an integrity-checked VendorPayment registration, the API can
issue a separate `AWS_DELEGATION_AUTHORITY` receipt bound to the exact current
publication, connection, boundary, Runtime, execution role, finite request set,
compiled policy, expiry and generation. It can then commit one immutable
enforcement candidate and one writer lock per connection/policy engine.

The application worker accepts only exact publisher evidence. It installs an
`AppliedBinding` only after registered ALLOW/DENY outcomes and all readback checks
are verified. A timeout, malformed result or terminal-commit uncertainty becomes
`UNKNOWN`, retains the writer lock and preserves the prior AppliedBinding; retry
uses reconciliation. Verified closed recovery releases the lock without installing
the candidate. A separate Application SQS/DLQ and DynamoDB outbox now recover failed
delivery and cap automatic UNKNOWN reconciliation attempts. Account A invokes only
the qualified customer Publisher Lambda in the registered account; it has no Policy
API or Runtime permission. The customer Publisher journals deny-first evidence and
owns only the bound Policy Engine. It invokes a distinct qualified canary Lambda;
only that canary can read the fixed registry/ledger and invoke the bound Runtime.
Policy create response loss is reconciled with the same client token, and failed
canaries delete only the exact owned candidate before proving closed recovery.

The shipped registry is still empty, and all AWS boundaries were tested with pinned
SDK shapes and local doubles. The account-B connector now has distinct ExternalId-
bound Discovery and PublishInvoke roles. The A worker assumes only the latter and
then invokes the qualified Publisher; it no longer has direct cross-account Lambda
permission. A recoverable operator performs baseline/Runtime readback, deploys and
reads back the connector, updates the exact Canary Runtime resource policy, derives
the fixed registration and activates the functions. This is deployable source, not
an actual account-B Policy write or Gateway result. The next dependency is a real,
distinct account B, using the recoverable clean-foundation operator only when its
bootstrap/baseline/Runtime preconditions are absent, followed by the verified
account-A registry wiring operator and the one bounded live D3 acceptance. The
wiring worker rereads account B through a dedicated read-only DiscoveryRole instead
of trusting the transferred report. Each launcher now records `COLLECTED` only after
the full report passes the stage's semantic and no-side-effect contract. A final
offline gate binds connector report bytes, launch/source/report versions, account,
Region, registration and account-A live readback before authenticated acceptance.
Foundation continuity is checked when the clean foundation operator was needed;
an existing matching foundation is not rerun solely to create evidence. The wiring
report explicitly records zero Policy and ledger counts. This gate runs no AWS or
human action and grants no authority. D2 and D3 live acceptance remain pending.

The first local D4 boundary is also implemented. An authenticated read-only API
now exports one object's complete positive-path audit projection after rereading
the fixed blobs and cross-checking Evidence, Run, Decision Pack, human receipt,
publication, Action, delegation, application, Publisher result, Outcome and
history. Connector ExternalIds are replaced by hashes. The offline D4 composition
gate binds the connected readiness result, one payment initial/reassessment/
recovery/verified-application export and one separate non-payment publication
export. Its PASS only permits the remaining negative, browser, judge and GD
acceptance; it cannot mark the product ready or promote a gate. See
`INTEGRATED_ACCEPTANCE_EVIDENCE.md`.

The next D4 prerequisite is implemented without claiming a live negative test.
Every business API response now emits one bounded correlation record containing
only safe request metadata and SHA-256 digests of the object, authenticated
subject, mutation request ID and response. Tokens, bodies, plaintext identities,
evidence and unmatched paths are excluded. Client-generated sign-in, pending and
uncertain-result errors use the product language; local rendering checks validate
the required user-visible copy across intake and object tabs. See
`D4_NEGATIVE_ACCEPTANCE_OBSERVABILITY.md`. Correlation logs and render contracts
do not themselves pass RO-02/04/12 or live browser UX.

The corresponding offline D4 negative evidence collector/checker is now
implemented. It accepts only the exact positive-path start gate and eight bounded
private case directories, recomputes every HTTP/audit digest, verifies each
authenticated export, requires rejection-state invariance, a single replay side
effect, request-ID conflict rejection and recovery of the same completed Run.
Instruction-like evidence is fixed by a synthetic repository marker and cannot
create business or AWS authority. API Gateway signed-out rejection is kept
distinct from Lambda audit evidence. Its PASS advances only to remaining browser,
judge and release acceptance; see `D4_NEGATIVE_ACCEPTANCE_EVIDENCE.md`.

General business approval must never create runtime authority. Keep ApprovalReceipt,
DecisionPublication/PublishedCurrent, typed delegation approval, AppliedBinding and
outcomes distinct. The existing `GET /review` is saved proof, not an approval API.
An object's display name is not an adapter ID or connection. Non-payment RO-09 remains
part of acceptance without pretending that a second execution adapter exists.

Reuse Cognito, CloudFront, API, versioned S3, AgentCore and the deployment service.
Keep application records separate from immutable sandbox tables. CodeBuild is for
deployments, not ordinary user runs. Check pinned SDK/API contracts before adding
cloud calls. Actual account B remains mandatory for D3 live proof, but is not a local
D1/D2/D3 implementation dependency; do not substitute another role in account A.

## Release gate before requesting user operation

1. Test the changed user path end to end locally, including adjacent authorization,
   persistence, serialization and idempotency boundaries. Include malformed, stale,
   foreign-object and unknown-state cases, not only the success fixture.
2. Build from the exact distribution source in a fresh directory with locked
   dependencies. Exercise the actual delivered operator/entrypoint, result recovery,
   interrupted/failed execution and duplicate-run handling. A unit-test count or a
   successful worker import alone is not sufficient delivery evidence.
3. Verify the affected browser flow and authentication/reconnection behavior.
   If live browser or AWS checks are still needed, mark them pending and define one
   bounded acceptance operation; do not present local doubles as live PASS.
4. Only then request the minimum user-owned live action, stating its purpose, expected
   outcome and recovery path. Preserve the current password and successful resources.
   Never ask for re-registration or a different scenario to disguise an unimplemented
   connection.
5. Record local and live results separately in PROJECT_STATE and SESSION_HANDOFF,
   with one next engineering dependency. Do not invent percentages, remaining hours,
   user capacity, gate completion or background progress.

Real human approval is performed by the authenticated reviewer at live acceptance,
not by the model or a deployment canary. Public repository/submission and external
messages remain subject to the applicable user authorization. U1–U3 retain their
original conditional adoption rules.
