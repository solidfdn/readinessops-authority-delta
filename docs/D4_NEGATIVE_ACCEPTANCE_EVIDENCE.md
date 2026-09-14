# D4 negative acceptance evidence

2026-09-12. This is the fail-closed offline collection and verification contract
for the connected RO-02/04/12 HTTP paths. The checker sends no request and performs
no AWS, browser or human operation. A PASS does not mark ReadinessOps product-ready
or promote an original gate.

## Private input boundary

Run this only after `check_integrated_acceptance_evidence.py` returns the exact
`READY_FOR_NEGATIVE_UX_AND_JUDGE_ACCEPTANCE` start gate. Retain the negative input
directory privately. It contains exact HTTP bodies and authenticated exports and
must not be committed. Never save an Authorization header, access/refresh token,
cookie, plaintext Cognito subject, ExternalId or password in it.

The directory contains `metadata.json` and exactly these case directories:

| Directory | Snapshots | Exchanges | Bound observation |
| --- | ---: | ---: | --- |
| `ro02_unreadable_evidence` | 3 | 2 | add corrupt PDF as `NEEDS_INPUT`, then reject its Run without state change |
| `ro02_instruction_reconnect` | 3 | 2 | start a Run over the fixed synthetic instruction fixture, complete it, and read the same Run after reconnect |
| `ro04_stale_revision` | 2 | 1 | reject review from an old record revision with `STALE_VERSION` |
| `ro04_old_receipt` | 2 | 1 | after an edited draft, reject its prior published receipt with `APPROVAL_REQUIRED` |
| `ro12_signed_out` | 2 | 1 | reject the object GET at the API Gateway JWT Authorizer |
| `ro12_foreign_subject` | 2 | 1 | reject a valid foreign subject with `FORBIDDEN` |
| `ro12_missing_scope` | 2 | 1 | reject the reviewer mutation with `SCOPE_REQUIRED` |
| `ro12_replay_conflict` | 4 | 3 | commit once, recover the same response on replay, then reject changed input using that request ID |

Files are zero-indexed `snapshot-N.json` and `exchange-N.json`. Extra, missing or
symbolically linked entries fail closed. The sum is bounded to 48 MB; each export
must also pass the existing 5.2 MB authenticated acceptance verifier.

`metadata.json` has exactly:

```json
{
  "schema_version": "1.0",
  "scope": "PRIVATE_D4_NEGATIVE_HTTP_AUDIT_EXPORT_OBSERVATIONS",
  "source_commit": "40-lowercase-hex-characters",
  "account_a": "538522204923",
  "region": "ap-northeast-1",
  "api_origin": "https://example.execute-api.ap-northeast-1.amazonaws.com",
  "reviewer_subject_sha256": "64-lowercase-hex-characters"
}
```

An exchange has exactly `transport`, `request`, `response` and `audit`. Request
fields are `gateway_request_id`, `method`, `path`, exact raw `body` (or `null` for
GET), and `subject_sha256`. Response fields are numeric `status` and the exact raw
JSON `body`. `BUSINESS_HANDLER` requires the complete matching
`BUSINESS_API_AUDIT` record. The checker recomputes the object, subject, mutation
request ID and response hashes and checks method, normalized resource, item flag,
status, code and result.

The signed-out case is different by construction: the deployed route's JWT
Authorizer rejects it before Lambda invocation. Its transport is
`API_GATEWAY_AUTHORIZER`, subject and audit are `null`, and the HTTP status is 401.
An invented Lambda audit is rejected.

## Browser capture assembly

The business handler now returns its safe Gateway correlation value as
`X-Request-ID`, and the workspace CORS contract exposes that header. It is the
same value in the privacy-bounded `BUSINESS_API_AUDIT` record. The header never
contains a token, subject, command request ID, object ID or body. The signed-out
401 never reaches the handler; for that one exchange the assembler reads the
Gateway-provided `apigw-requestid` (or `x-amzn-requestid`) response header and
requires that no Lambda audit exists.

Keep one private capture directory with exactly `index.json`, the named filtered
HAR file, the named audit JSON file and `snapshots/`. The HAR must contain only the
12 mapped business exchanges. Browser-exported HAR files can retain Authorization
headers and cookies, so never commit or redistribute the input. The assembler
reads only method, exact URL/body, response status/body and the safe correlation
header; request headers and cookies are never copied to its output.

The audit input is the JSON string array produced by an exact bounded CloudWatch
read such as:

```bash
aws logs filter-log-events \
  --region ap-northeast-1 \
  --log-group-name /aws/lambda/authority-delta-business-api \
  --start-time START_EPOCH_MILLISECONDS \
  --end-time END_EPOCH_MILLISECONDS \
  --filter-pattern '"BUSINESS_API_AUDIT"' \
  --query 'events[].message' \
  --output json > PRIVATE/d4-capture/business-audit.json
```

Use the smallest time window that contains the 11 handler exchanges. Extra,
missing or duplicate audit records fail. `index.json` has the same source/account/
region/API/reviewer bindings as `metadata.json`, plus exact `har_file`,
`audit_file`, and all eight cases. Each case maps its required snapshot filenames
and HAR entries without containing any credential:

```json
{
  "schema_version": "1.0",
  "scope": "PRIVATE_D4_BROWSER_HAR_AUDIT_EXPORT_CAPTURE",
  "source_commit": "40-lowercase-hex-characters",
  "account_a": "538522204923",
  "region": "ap-northeast-1",
  "api_origin": "https://example.execute-api.ap-northeast-1.amazonaws.com",
  "reviewer_subject_sha256": "64-lowercase-hex-characters",
  "har_file": "browser.har.json",
  "audit_file": "business-audit.json",
  "cases": {
    "ro02_unreadable_evidence": {
      "snapshots": ["unreadable-0.json", "unreadable-1.json", "unreadable-2.json"],
      "exchanges": [
        {"har_entry_index": 0, "subject_sha256": "64-lowercase-hex-characters", "transport": "BUSINESS_HANDLER"},
        {"har_entry_index": 1, "subject_sha256": "64-lowercase-hex-characters", "transport": "BUSINESS_HANDLER"}
      ]
    }
  }
}
```

The example abbreviates `cases`; the actual index must contain all eight exact
case names and the snapshot/exchange counts in the table above. Snapshot filenames
are basenames under `snapshots/`; reuse, traversal, symlinks and extras fail.

Run the one-step assembler/checker only after the positive start gate exists:

```bash
PYTHONPATH=src:scripts:. \
python scripts/assemble_d4_negative_browser_capture.py \
  --positive-result PRIVATE/integrated-positive.json \
  --capture-dir PRIVATE/d4-capture \
  --observation-dir PRIVATE/d4-negative \
  --output PRIVATE/d4-negative-assembly-result.json
```

The destination must not already exist. Assembly is staged, round-tripped through
the exact case-directory collector and verified before the directory is published;
failure leaves no partial destination and never overwrites prior evidence. The
program makes no live call and cannot claim that the supplied inputs came from a
completed browser or human operation.

## State rules

Every snapshot is reread through the authenticated acceptance export. Rejections
require the exact before/after document digest to remain equal. Evidence replay
requires one new Evidence and one `EVIDENCE_ADDED` event on the first call, the
same exact HTTP response on the second call, and no second state change. Reusing
that request ID with different input must return `REQUEST_CONFLICT` without change.

The unreadable fixture may add only one `NEEDS_INPUT` Evidence record and its
history event. It cannot be selected for a Run. The instruction case selects the
repository fixture `fixtures/d4-instruction-boundary.txt`; its marker must appear
in both the retained Evidence and immutable Run input. Completion may create only
the assessment state and queued event. Draft, approval, publication, delegation,
application, outcome and AppliedBinding remain absent. Reconnection must return
the exact completed Run represented by the final export.

The old-receipt case starts from an existing publication and a later edited draft
whose approval is empty. Its rejected request must name the prior publication's
receipt. The authenticated publication and all authority state remain byte-bound
and unchanged.

## Command and output

```bash
PYTHONPATH=src \
python scripts/check_d4_negative_acceptance.py \
  --positive-result PRIVATE/integrated-positive.json \
  --observation-dir PRIVATE/d4-negative \
  --output PRIVATE/d4-negative-result.json
```

For an already-composed private manifest, replace `--observation-dir` with
`--observations PRIVATE/d4-negative-observations.json`. Successful output contains
only safe hashes and the fixed status
`READY_FOR_REMAINING_BROWSER_AND_RELEASE_ACCEPTANCE`. Live browser observation,
English UX, judge access, the five-minute demonstration, relevant original gates,
GD and authorized submission remain required.
