# Connected business flow update — 2026-09-12

## Current evidence

The operator reported PASS at c8b0f9e for build
`authority-delta-deploy:09977602-3f1a-4f06-8a5a-d4c1d06ec6da`.
The customer registry and deployment assessment canary passed; protected state
was unchanged and Policy/ledger counts were zero. Human workflow, Policy writes
and the live customer canary remain NOT_RUN. The support-reply object has not
been reassessed after the citation repair. Preserve it as a regression record.
The full latest report was not attached; this is operator-reported terminal
evidence, not an independent AWS readback.

## Changes and reasons

- Separate the global verified adapter catalog from each business object's
  explicit connection. A write-scoped owner command records the exact adapter,
  version, connection, registration hash and selection reason. It grants no
  delegation or runtime authority. An existing binding is not silently replaced.
- Require that exact connection before a separate delegation approval. Do not
  infer applicability from a business name or preselect a payment connection for
  every object. The owner must select a matching registered business connection.
- Let Outcomes target a terminal AWS application and its enforcement digest,
  or the current official decision. Require an explicit observed result; reject
  pending applications and ALLOW claims for a closed recovery.
- Poll application status until its recorded terminal result becomes available.
- Align the HTTP connection-ID syntax with the existing domain contract
  (`conn-` plus 4–80 allowed characters). Exact registered identity and digest
  checks remain mandatory. This fixes an API/domain discrepancy exposed by the
  complete UI path; it does not relax an authority check.
- Add a React DOM event test through the real API handler, service, storage and
  final acceptance composition. Identity, model, AWS and storage durability are
  local doubles. Fixed jsdom 24.1.3 is a development-only dependency.

The local flow covers two distinct objects, assessment/review/publication,
explicit connection, separate delegation, closed recovery, action resolution
with new evidence, reassessment, verified application and an Outcome bound to
that application. A composed PASS explicitly keeps `product_ready=false`.
The test does not prove a real browser, live Nova reliability, IAM, AWS effects
or a person's approval. The file chooser is represented by a supplied File;
the native chooser and visual layout are not exercised by jsdom.

The new distribution is based on c8b0f9e. Its final commit, bundle SHA-256,
fresh restoration, handler/launcher tests and compiled asset comparison are
recorded in the companion `Connected_Flow_Verification.json`.

## Next operator operation

Upload `ReadinessOps_Connected_Flow_Update.bundle` into account A CloudShell's
home directory. From the existing repository, fast-forward the update and run
the existing customer-wiring launcher with the original connector report.
This deploys the changed business API and UI and runs its deployment canary.
It does not recreate the successful account-B foundation or connector.
After PASS, reload the existing workspace and follow the RO-09 input below.
If CloudShell disconnects, use the exact `--resume` command printed by the
launcher; do not start a replacement build.

## RO-09: customer data sharing, in the English UI

Use `docs/acceptance-inputs/Customer_Data_Sharing_Context_EN.json` for the five
intake fields. These are synthetic test inputs, not an approval or an observed
improvement. Keep the existing support-reply object unchanged.

1. Select **Add business object**, enter the five context values, then
   **Create and add evidence**.
2. Upload **Customer_Data_Sharing_Evidence_EN.txt**. Title:
   **Customer data sharing — scope and evidence gaps**. Source:
   **SOLIFAN synthetic acceptance scenario — v1.0**. Select **Add evidence**.
3. Confirm **Text ready**, select that document and **Start assessment** once.
   Wait for the same run. A terminal failure is not an instruction to replace
   the evidence or to retry blindly; retain its Assessment record.
4. Use **Review the proposed decision**. Review the four perspectives and the
   actual citations. Keep unsupported claims and proposed metrics distinct
   from facts. Correct the draft if necessary, enter your review note and
   select **Save decision draft**.
5. If you agree with this exact draft, enter your own reason and select
   **Record approval**, then **Publish this decision**. Approval alone must
   not change the official version. Return or reject it if you do not agree.
6. Confirm the official decision is shown and AWS remains **Not applied**
   with **No AWS execution adapter is connected**. This data-sharing scenario
   has no implemented execution adapter; no connection selection is needed.
7. Open **History → Download acceptance evidence**. Retain that export for
   the later combined acceptance check.

These seven steps cover the RO-09 path only. The model may correctly propose a
conditional synthetic pilot or request missing evidence; no preselected approval
or successful business result is prescribed.

## Remaining release blockers

RO-07 is an implementation gap: post-application expiry/revocation needs an
authenticated stop request, generation invalidation, controlled-entry closure,
owned-permit invalidation and an actual DENY observation. Existing pre-approval
and pre-application expiry validation, closed candidate recovery and Runtime
session cleanup do not implement that lifecycle. Do not treat STOP_REQUESTED
or a database flag as confirmed closure. Implement and qualify this path before
the next live authority-opening acceptance operation.

Live human acceptance, connected positive/negative cases, browser UX, judge
access, demo and submission conditions remain separate. This update cannot
promote READINESSOPS_PRODUCT_READY. The original baseline and all completion
conditions are unchanged. No new AWS operation was performed locally; no
background retry is running. Operator time and current AWS spend are unmeasured.
