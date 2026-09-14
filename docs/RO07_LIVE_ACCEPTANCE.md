# RO-07 live authority lifecycle — PASS

On 2026-09-14, the authenticated two-account acceptance completed for the
bounded `VendorPayment` adapter in `ap-northeast-1`.

## Observed sequence

1. Account A verified application
   `application-84ed051249524be2adc7d0d46f0503c5` against the registered
   account-B connection.
2. The reviewer used the normal product entry to execute registered request
   `req-96a43671e6b49676a15ef4a87d30dfcf4b6bdb3d88ab128911b1b678851fafd2`.
3. The Workbench reported `Execution confirmed` and `ALLOW`.
4. The reviewer requested suspension. The entry closed before Policy removal.
5. Account B removed the exactly owned Policy and returned live DENY evidence
   for every registered request with unchanged ledger evidence.
6. The Workbench reported `Suspension confirmed` and retained the history.
7. The authenticated export passed the bounded offline checker with:

```json
{"scope":"OFFLINE_RO07_EXPORTED_LIVE_AUTHORITY_LIFECYCLE_NO_AWS_ACTION","result":"PASS","status":"RO07_LIVE_AUTHORITY_LIFECYCLE_CONFIRMED"}
```

The checker does not perform an AWS action. It verifies the exported identity,
digest, application, invocation, revocation, Policy-removal, live-DENY,
endpoint-version and unchanged-ledger evidence chain.

Machine-readable capture:
[`evidence/aws/20260914-ro07-live-authority-lifecycle-pass-user-reported.json`](../evidence/aws/20260914-ro07-live-authority-lifecycle-pass-user-reported.json).
