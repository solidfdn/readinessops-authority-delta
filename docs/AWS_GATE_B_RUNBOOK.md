# Gate B semantic Runtime operation

Upload Authority_Delta_Gate_B_V3.py into CloudShell home and run:

```bash
python3 ~/Authority_Delta_Gate_B_V3.py
```

Retain ReadinessOps_Authority_Delta_AWS_Verification_V2.zip and
Authority_Delta_Analysis_Dependencies.zip in that home directory. Exact hashes
are enforced before any AWS operation. No package download is performed.

The V3 recovery reads the exact failed report version and verifies its digest.
It reuses pinned Gate A evidence and six saved benign observations, verifies current
bindings, and updates only authority-delta-analysis-runtime. It invokes Strands/Nova
for semantic and benign comparisons with up to three proposal attempts and eight
model calls per comparison. Invalid proposals receive evidence-validation feedback;
unresolved output stays HOLD. The old rejected answer is never rewritten as success. It does not create payment permissions or reset the ledger.

Success is semantic_runtime_proof PASS, SEM-01/02 PASS and state_unchanged true.
Full gate_b remains NOT_PASSED_UI_PENDING. Do not call this complete Gate B.

On disconnect use the printed resume command; it collects the same build.
On FAIL preserve the report/version. Do not rerun setup or Gate A. Logs/checkpoint
and final report retain the failing stage; the model is never replaced by a canned
successful explanation. Runtime sessions are stopped best effort, idle60/max600.
Stack deletion, if subsequently requested, removes only these two added runtimes;
it does not delete the existing customer baseline or its retained evidence.

The completed failed build cannot run corrected code with --resume. Use the new V3
file once; use only its printed --resume to collect that same new build if disconnected.
Rejection reasons and failed proposal attempts are now included in the normal output.

## V3 model and evidence grounding

All six cases are presented with their own request facts and both observations.
No case is prefiltered as an expected answer. Validation names the offending case
and exact observed judgments/facts in correction feedback.

The worker resolves `apac.amazon.nova-pro-v1:0` with GetInferenceProfile in Tokyo.
Profile ID/ARN/account/status/type and every destination model ARN are checked
before deployment. IAM permits only that profile and the exact source/destination
Nova Pro ARNs, conditioned on `bedrock:InferenceProfileArn`. These are synthetic
fixtures; prompts may route within APAC, while app and evidence remain in Tokyo.
This is an implementation choice within the frozen product boundary (P1).

Official references (checked 2026-09-09):
- https://docs.aws.amazon.com/bedrock/latest/userguide/model-card-amazon-nova-pro.html
- https://docs.aws.amazon.com/bedrock/latest/userguide/geographic-cross-region-inference.html

Nova Pro account access and live semantic acceptance remain to be proved by the
new build. Local SDK/contract tests do not measure live model response quality.
