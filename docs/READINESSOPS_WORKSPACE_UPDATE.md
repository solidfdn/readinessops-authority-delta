# ReadinessOps AWS workspace update — 2026-09-09

This update corrects the product composition identified by the user. It implements
shared object/evidence/finding/action/history data and navigation, separates the
VendorPayment business adapter and preserves the actual Authority Delta review.
It is a **read-only stage of the AWS edition**, not a claim that the product is complete.

## Operator action

Upload `ReadinessOps_AWS_Workspace_Update.py` to CloudShell home, then run:

```bash
python3 ~/ReadinessOps_AWS_Workspace_Update.py
```

The unchanged V2 source ZIP and analysis dependency ZIP already used in this
CloudShell account are reused and checksum-verified. No dependency download or
password reset is requested. Prepared source and the printed resume command are
kept under `~/readinessops-work/workspace-update-*/`.

The updater checks account 538522204923, Tokyo, the existing workspace URL and a
CONFIRMED `okada` reviewer before starting one existing CodeBuild project. It uses
`authority-delta-workbench`, preserves its identity and original infrastructure
logical IDs, and updates versioned read data, reader code and frontend assets.
The template has no changes to Cognito, IAM, API authorization or resource topology.

At success, reopen https://d3rn3hqm0ax5ux.cloudfront.net/ with the same login.
The initial page is the ReadinessOps overview. Navigate to Evidence, Findings &
actions, Human review and History. Evidence is derived from the pinned real report.
Payment-specific details appear within the explicitly identified sample object.

## Evidence and recovery

Saved successful report reused:
`evidence/b9074918a5114c34a19f723efb1a9383/gate-b-result.json`,
version `k2EAn2Uy7jv5AmISBKnfVQPgOluM560i`, in the existing artifact bucket.
No model invocation, replay, policy publication or ledger reset runs in this update.

If the connection is interrupted, use the **Resume this build** command printed
by the launcher. It collects the same build. Do not start bootstrap or repeat
successful gates. If deployment fails, the final report includes the observed
stage/error. Retain that report; a failed update does not turn into a passed gate.
The operator refuses an unconfirmed reviewer rather than asking to set a password.

## What this update does not yet complete

- General user-entered object registration and new evidence upload/assessment.
- Server-recorded human decisions, approval receipts and policy publication.
- A customer second account and its limited publisher connection.
- Full UI acceptance, SEM-03 and Gate C/D acceptance.

ReadinessOps remains the business target. These are remaining product requirements,
not deleted scope. Existing semantic analysis is visible as observed history;
missing human decisions/publications are shown as absent, never invented.

## Validation boundaries

Local checks include shared contracts with an independent non-payment scenario,
version/type/content tamper rejection, linked source evidence, unchanged legacy
policy bytes, compiled React UI, five rendered sections, PKCE/auth guards and the
actual operator process with failure/recovery/identity scenarios. These checks do
not constitute a live AWS update or browser acceptance. The new live result must
be collected before changing deployment status.
