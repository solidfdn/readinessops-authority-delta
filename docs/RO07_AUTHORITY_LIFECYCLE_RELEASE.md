# RO-07 authority lifecycle release

This release completes the local implementation and deployable boundary for the
previously missing applied-authority stop/expiry lifecycle. It does not claim the
live result before the two-account update and authenticated acceptance export pass.

The product-controlled invocation gate revalidates the exact current publication,
receipt, generation, expiry, Runtime and finite request set, then linearizes an
accepted operation against stop. Accepted operations use a durable outbox and the
dedicated account-A worker; the browser and general business API cannot invoke the
Runtime directly. Account B rereads the still-VERIFIED publisher journal before
normal execution. Its sandbox business key is idempotent.

Manual stop and expiry use one revocation protocol. The A transaction closes the
entry and invalidates the current generation before queuing B. B serializes its
publisher/revocation worker with a durable 12-minute fence, reads the exactly owned
Policy, journals deletion intent, confirms Policy absence, and probes every
registered request for real AgentCore/Gateway DENY with unchanged ledger. A does
not emit `SUSPENDED_CONFIRMED` until it validates and stores that complete result.
Unknown results retain the writer lock and are retried from the same outbox.

Timeout ordering is explicit: B publisher 600 seconds < durable B fence 720 < A
worker lease 900, and A worker hard timeout is 840 seconds. The SQS visibility
timeout exceeds its worker timeout. The normal invocation path uses the same
lost-response-safe idempotent business key and waits for an accepted operation
before revocation removes Policy.

The coordinated release intentionally updates B first, then transfers four exact
foundation/connector reports to A and updates A. The B launcher now permits a new
bundle version after a previously collected successful build while retaining the
same ExternalId; an active or uncollected predecessor still blocks. The release
contains account-checked wrappers under `operator/ro07` and an English, field-level
live checklist. No account recreation, foundation redeployment, prior RO-09 repeat,
or gate reset is required.

Local qualification includes Python regression, React SSR and DOM-to-handler flow,
TypeScript compilation, regenerated CloudFormation/OpenAPI, locked x86/ARM package
construction, source archive member comparison, fresh-clone incremental
fast-forward, and offline RO-07 export rejection/pass cases. AWS and human
acceptance remain `NOT_RUN` until the exported live evidence passes
`scripts/check_ro07_acceptance.py`.
