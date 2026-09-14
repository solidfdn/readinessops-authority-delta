# D4 negative acceptance observability

2026-09-12. This is a local implementation boundary for collecting correlated
RO-02/04/12 API evidence. It does not claim that any live negative, browser,
judge-access or product-acceptance test has run.

## Safe API audit record

Every business API response emits one `BUSINESS_API_AUDIT` JSON message. The
record contains the API Gateway request ID, or the Lambda invocation ID only when
the Gateway value is absent or unsafe. It records the normalized resource,
method, HTTP status, error code and result classification.

Object ID, authenticated Cognito subject, mutation `request_id` and complete
response body are represented only by SHA-256 digests. Authorization headers,
JWTs, request bodies, evidence text, response bodies, filenames, display names,
ExternalIds and plaintext identities are not logged. Unmatched paths are recorded
as `UNMATCHED`, not copied from the request. Audit emission failure cannot change
the API response already determined by the handler.

`SUCCESS` means only HTTP success. `REJECTED` means an observed 4xx response and
`UNCONFIRMED` means a 5xx response; these labels do not assert an AWS Policy
ALLOW/DENY or a completed business operation.

## Acceptance use

The later connected acceptance collection must correlate the audit digest fields
with retained HTTP responses and authenticated acceptance exports. An audit line
alone is not enough to pass a test.

| Requirement | Required correlated observation |
| --- | --- |
| RO-02 | unreadable evidence is retained as `NEEDS_INPUT`; a Run cannot cite or use it; instruction-like evidence cannot create approval, publication, delegation or Policy authority |
| RO-04 | stale revision/digest and old receipt receive the expected 4xx code; before/after exports prove `PublishedCurrent` and authority unchanged; edited content requires a new revision and approval |
| RO-12 | signed-out, missing-scope and foreign-subject requests are rejected; same mutation `request_id` and response hashes correlate a recovered replay; a different payload with that ID is rejected; reconnect reads the same Run |

CloudWatch correlation is supporting evidence, not a substitute for the state
comparison, actual browser observation or AWS canary required by the acceptance
plan. Raw private log exports must not be committed to the source repository.

## English client boundary

All locally generated client-side sign-in, unconfirmed-operation and pending-write
errors use the product language. The server-rendered workflow is checked for the
required user-visible copy across intake and all seven object tabs, and the
compiled API client is checked for its required error messages. This is a render/client
contract, not a live-browser visual or accessibility result.

## Offline evidence composition

The fail-closed collector/checker is now defined in
`D4_NEGATIVE_ACCEPTANCE_EVIDENCE.md`. It binds the exact HTTP bodies, matching safe
audit record and authenticated before/after exports for the required RO-02/04/12
cases. Rejections must leave the export digest unchanged; replay must have one
side effect and an identical recovered response. The signed-out request is
correctly represented as an API Gateway Authorizer rejection without an invented
Lambda audit.

This is still local code, not a claim that those connected cases ran. Actual
RO-02/04/12 execution follows only after the positive connected acceptance path is
ready. Browser observation, judge access, the five-minute demonstration, relevant
original gates/GD and authorized submission remain separate required checks.
