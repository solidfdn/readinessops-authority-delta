# ReadinessOps AWS business workflow — D1 implementation

2026-09-09. AD-BASELINE-1.2. This document describes implemented source. It does
not record a new AWS deployment, human approval, publication or completed product.

The common workflow is business object/purpose/question/owner/goals → versioned
TXT/text-PDF/JSON → fixed input → queued Strands/Nova Pro assessment → editable
Governance/Value/Model Routing/Portfolio proposal → human review → explicit
business Decision Pack publication → history. VendorPayment is not required.
Missing evidence stays missing; no invented costs/ROI or automated model switch.

| Component | New implementation | Authority |
| --- | --- | --- |
| Existing Cognito/API/CloudFront | Same user/client/pool/origin, expanded business scopes | Verified assigned Cognito sub; unchanged password |
| Business API | Create/read/evidence/run/draft/review/publish | App/Jobs conditional transactions and own versioned blobs |
| SQS + worker + outbox dispatcher | Durable job start, bounded execution, diagnostic/result recovery | Jobs and analysis input/result only; no AppTable |
| Separate business AgentCore Runtime | Real Strands read_context/read_evidence and typed proposal | Own runtime code/model inference; no approvals/Gateway |
| PublishedCurrent | Exact saved draft and current receipt/generation/expiry, explicit publish | Business judgment only; AppliedBinding remains empty |

`services/business/requests.schema.json` validates all command bodies. The
published API description is `packages/contracts/business.openapi.json`.
DynamoDB stores versioned JSON records with consistent reads and conditional
transactions. A command and its request-id result commit together. Source blobs,
drafts, receipts and publications are pinned to S3 versions and read back before
committing their references. Failed S3 saves may leave unreferenced versions;
they cannot become an authoritative receipt or Current pointer.

A committed run/outbox survives send failure. Scheduled recovery retries pending
outboxes once per minute; the worker conditionally claims the job, so duplicate
SQS messages do not rerun successful analysis. Runtime work is bounded at240s,
worker330s, claim420s. A lost worker result is exposed as FAILED after its lease;
no automatic duplicate model invocation. QUEUED records expire after10minutes
when read. The SQS visibility timeout is2100s and failed starts go to a DLQ after
three receives; a separate DLQ mapping marks the saved job failed. Starting
another assessment preserves the first Run and its input. Up to8 model calls and
3 proposal attempts are allowed per Run. APAC inference may route outside Tokyo.

Each document is at most2MB. TXT/JSON must be UTF-8; supported PDFs contain text,
are unencrypted and at most30pages. Every PDF page must yield text; scan-only,
corrupt, encrypted or partial text becomes NEEDS_INPUT. Extraction runs in a
bounded subprocess. Original files are retained even when unreadable. Extraction
is not verification of a document's truth. Extracted text is limited to100KB per
file,120KB per assessment,1MB per business object. Eight selected files,40documents
and60runs per object are supported in D1; these are explicit service limits.

An approval requires a saved, validated draft and an authenticated assigned user.
Receipt type BUSINESS_DECISION_ONLY cannot authorize AWS policy changes. Editing
or adding evidence changes revision/generation and invalidates pending approval.
Approve/reject/return are recorded separately from publication. Publication reads
back the receipt and draft and conditionally changes Current. A new draft/run or
evidence leaves the former official publication and its full history intact.
No previous DP-demo reference is converted to a real user approval.

## Deployment and recovery

Download `ReadinessOps_AWS_Business_Workflow.py` into CloudShell home and execute
`python3 ~/ReadinessOps_AWS_Business_Workflow.py`. It reuses the existing V2 base
ZIP and Analysis Dependencies ZIP; no dependency recollection or password setup.
Source is prepared under `~/readinessops-work/business-workflow-*`.

The launcher saves an intent locally and in the existing versioned artifact
bucket before starting CodeBuild. Interrupted start responses are reconciled by
the exact report key and source hash. Rerun the same downloaded file to collect
the same build; remote records also recover a missing local launch file. Never
start a fresh build merely because collection was interrupted. A failed deployment
returns its phase, error, stack events and model/job diagnostics. Preserve the
full result/checkpoint for repair.

The existing deployed source is still14e5faa until a returned new AWS PASS proves
otherwise. The updater deploys `authority-delta-business`, checks runtime code,
role/model/version, and runs one clearly synthetic nonpayment canary through the
real outbox/queue/worker/model/result path. This creates no AppTable object,
human receipt or formal publication. Only after that succeeds does it stage all
UI assets, read them back, then update the existing CloudFront path and Cognito
scopes/CORS. Existing physical identities must remain exactly equal. Static asset
bytes and unauthenticated API401 are verified. Successful deployment still reports
human_workflow NOT_RUN and never promotes full GB/GC or RO acceptance.

The same URL and password are used. An old read-only token requires signing in
again to obtain the new scopes. Normal use begins by creating a business object
and adding the user's evidence. No terminal operation is needed for assessment,
review or official publication after deployment.

## Validation and remaining work

Local application/SDK/Strands-loop tests, distribution package imports and actual
text/encrypted/scan/broken PDF extraction have passed. React server render and
client request recovery tests are recorded separately. Test model/identity data
are always synthetic. The cloud browser URL policy rejected local navigation;
actual browser interactions and desktop/mobile visual acceptance are NOT_RUN.
This limitation is not a browser pass or an AWS defect.

The actual distributed operator must pass fresh restoration/entrypoint/recovery
checks before it is delivered. See `evidence/local/business-delivery.json`.
This is the historical D1 implementation record, not the current acceptance
status. Later authenticated acceptance covers the optional connected authority
lifecycle ([RO-07](RO07_LIVE_ACCEPTANCE.md)), Action completion and reassessment
([RO-08](RO08_LIVE_ACCEPTANCE.md)), and
[outcome recording and fixed-reference import](BUSINESS_OUTCOME_INTERCHANGE.md).
See [Implementation](IMPLEMENTATION.md) for current scope. Submission completion
is tracked separately.

## Operations boundary

No live resources/costs were inspected or changed by this implementation turn.
The launcher only changes the declared business stack and the existing workspace
scopes/CORS/static origin. Existing IAM bootstrap, V1/V2/Gateway policy, registry,
ledger and sign-in user are preserved and compared. No unrestricted publisher is
introduced. The known USD50 notification budget remains; it is not a hard cap.

After actual deployment, to pause new processing, disable the
`authority-delta-business` RecoverySchedule and both queue event-source mappings;
retain AppTable, JobsTable and DataBucket. Mark/reconcile saved active jobs before
resuming. Disable business write routes before decommissioning. The data resources
have Retain policies. Do not delete the customer baseline, clear its nonempty
ledger, reset the user password or touch approved runtime policies for D1 cleanup.
Runtime sessions have idle60/max600-second lifetimes; the dispatcher is scheduled,
not a promise of ongoing Codex development. No business AWS application is active
merely because PublishedCurrent has a value.
