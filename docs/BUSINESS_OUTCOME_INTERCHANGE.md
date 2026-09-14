# Business Outcome and fixed interchange

Updated 2026-09-14 UTC. This describes the RO-10/11 contract and the authenticated
workspace checks below. File interchange does not establish live Snowflake connectivity.

## Outcome and Metric

`POST /business/objects/{object_id}/outcomes` records an immutable
`BUSINESS_OUTCOME` against the current official publication. A Decision
Publication or AWS Application target must exist in the same authorized object,
must belong to the current publication, and must carry the saved digest. A trace
target uses a constrained external trace identifier. Recording an Outcome never
changes `PublishedCurrent`, `AppliedBinding` or runtime authority.

The authority result is exactly `ALLOW`, `DENY` or `ERROR`; the separate
`business_result` explains what happened in the business. Metrics are optional.
Every metric is one of:

- `MEASURED`: finite numeric value, unit, period, source and `OBSERVED` or
  `ESTIMATED` basis are required.
- `NOT_MEASURED`: source and reason are required; value, unit, period and basis
  are forbidden. The application therefore cannot turn missing evidence into
  zero, success or an improvement rate.

The server creates the Outcome ID and digest, writes the complete JSON to a
versioned object, reads it back, and then atomically commits its index, event and
request-id replay record. The UI labels observed, estimated and unmeasured values.

## Export

`GET /business/objects/{object_id}/interchange` verifies and returns the current
published Decision Pack and every Outcome recorded for that publication. The
document contains:

- `authority_source`, source workspace/object, pack ID/revision and decision
  digest;
- the exact immutable Decision Pack;
- a publication projection without internal blob references;
- exact Outcome documents sorted by server-generated ID;
- `transport_status: FILE_INTERCHANGE_ONLY`; and
- `document_digest` over the complete preceding content.

There is no export timestamp, so unchanged fixed content produces the same
document and digest.

## Import and canonical-source protection

`POST /business/objects/{object_id}/imports` accepts a complete interchange
document, verifies its outer digest and every nested Decision Pack and Outcome
digest, and stores the exact bytes as a fixed external reference. It does not
make the imported Decision Pack editable and does not change the receiving
object's official decision or AWS authority.

The receiver binds each `pack_id` to one authority and source object. It rejects:

- the local `aws:solifan` authority presented as an external copy;
- a pack ID already owned by the local editable authority;
- a pack ID reused by another issuer or source object;
- an existing pack revision with different fixed content;
- an Outcome ID reused by another issuer, object or digest; and
- malformed, duplicated or tampered nested records.

An exact repeat with a new request ID reports `already_imported: true`; a repeat
of the same request ID replays its original result. Imported records and history
explicitly retain `FILE_INTERCHANGE_ONLY`. This is file-contract success, not a
claim that Snowflake communication succeeded.

## Scope and remaining acceptance

Authenticated workspace checks on 2026-09-14 UTC verified:

- RO-10: two retained outcomes against the existing suspended AWS application,
  with an observed metric of seven denied synthetic requests and a separate
  explicitly unmeasured commercial-savings metric. These do not claim new
  execution or measured business savings. The fixed export retained both.
- RO-11: a clearly labeled synthetic external-reference file was imported
  through the live UI. Reimporting the same file retained one import record.
  The authenticated acceptance export passed integrity verification; official
  decision, delegation, application, revocation, invocation and outcome records
  were unchanged by import. The fixture contained a Decision Pack and zero
  outcomes; this check does not establish cross-platform connectivity.

Local contract tests cover additional validation paths. No live Snowflake
connection is required by the fixed product baseline.
