# Integrated acceptance evidence contract

2026-09-11. This is the local D4 positive-path evidence boundary. It does not
claim live AWS, browser, human, UX, judge-access, GD or product acceptance.

## Authenticated object export

`GET /business/objects/{object_id}/acceptance-evidence` requires the existing
Cognito read scope and object owner. It reads without changing application state.
Before returning a document, the service rereads and verifies every available
versioned Evidence, assessment input/result, published Decision Pack and approval
receipt, delegation receipt, enforcement candidate and Publisher result, Outcome
and imported interchange document. It also binds operational Actions and
authenticated history events from the same object.

The export is bounded to 5.2 MB of canonical JSON. It includes a hash of each
source record and a separately verifiable hash of each portable projection, plus
one digest over the complete export. Connector `external_id` values are replaced
recursively by `external_id_sha256`; the plaintext value is never downloaded.
The export sets `runtime_authority_changed_by_export: false` and performs no
approval, publication, delegation, application or recovery operation.

This export complements, rather than replaces, the deterministic Decision Pack /
Outcome interchange. Interchange remains the issuer-bound portable business
contract. Acceptance evidence is the larger audit projection used to verify one
connected product journey.

## Offline composition gate

`scripts/check_integrated_acceptance_evidence.py` consumes exactly:

1. the PASS output from `check_connected_acceptance_readiness.py`;
2. one authenticated acceptance export for the VendorPayment connected path; and
3. one separate authenticated export for the customer-data-sharing non-payment
   path.

The payment export must continue the readiness-bound live account-B registration,
contain initial and reassessment publications, an evidence-backed Action linked to
the reassessment, a separately approved delegation, one proved-closed recovery,
one verified application with deny-first and finite ALLOW/DENY outcomes, and a
business Outcome bound to that verified application. The applied binding must be
for the current official publication.

The separate non-payment export must contain the customer-data-sharing context,
evidence, initial assessment, four decision perspectives, authenticated approval
and publication, while containing no delegation, application or AppliedBinding.
This proves the common path without pretending that a second execution adapter
exists.

A successful composition returns
`READY_FOR_NEGATIVE_UX_AND_JUDGE_ACCEPTANCE`, never
`READINESSOPS_PRODUCT_READY`. RO-02 input boundaries, RO-04 stale-screen rejection,
RO-12 authorization/replay/reconnection, browser UX, judge access,
the five-minute demo, relevant original gates/GD and authorized submission checks
remain explicit required work. The checker performs none of those actions and
promotes no gate.

## Failure behavior

Duplicate JSON members, non-finite or oversized input, a foreign object, a broken
projection digest, mixed account/registration, missing reassessment or Action
link, missing recovery, incomplete canary outcomes, an Outcome not bound to the
verified application, or authority on the non-payment object returns `BLOCKED`.
The failed output is bounded and retains no ExternalId.
