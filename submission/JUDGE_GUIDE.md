# Review ReadinessOps in three minutes

ReadinessOps helps operations leads prepare evidence-based decisions, track the
work that follows, and reconsider those decisions when evidence changes.
Authority Delta connects that review to a separately controlled AWS execution
boundary when an adapter is registered.

[Live workspace](https://d3rn3hqm0ax5ux.cloudfront.net/) ·
[Product overview](../README.md) · [Architecture](../docs/ARCHITECTURE.md)

## Follow one business record

Sign in using the private testing credentials supplied with the submission.
Open **VendorPayment authority lifecycle acceptance**. The name describes the
synthetic execution example; the workspace also contains non-payment objects.

| Time | Open | What to look for |
| --- | --- | --- |
| 0:00–0:30 | Overview → Evidence | The question and success criteria, original evidence, and the later RO-07 suspension verification document. |
| 0:30–1:15 | Assessment → Review & publish | Select the successful assessment dated **2026-09-15 02:19 JST / 2026-09-14 17:19 UTC**. It is Ready for review. Governance and Portfolio are affected; Value and Model routing remain unknown. The published decision is unchanged. Times display in your browser's locale. |
| 1:15–1:45 | Actions | “Obtain evidence on suspension confirmation” has an owner, due date, completion note and new resolution evidence. Its first linked reassessment remains in history; the later successful run retains the same fixed input. |
| 1:45–2:15 | Outcomes & exchange | Two outcome records distinguish observed technical proof from unmeasured commercial value. One synthetic imported reference remains fixed; repeating its import did not create a duplicate. |
| 2:15–3:00 | Review & publish → History | The AWS section shows **Suspension confirmed** and the retained accepted ALLOW invocation. Download acceptance evidence to inspect the decision, action, assessment and authority history together. |

The default assessment may change as people use the workspace. The verified run
is `run-6b10a33b227a4ac1acac3f79ff3a53a3`, runtime version 25.
The existing record can be reviewed without applying fresh authority or making a
new approval. The execution demonstration uses synthetic requests and performs
no real payment.

## What the agent actually does

A person selects evidence and starts the assessment. The Strands agent then reads
the fixed inputs and prepares structured findings, proposed actions and decision
items. During reassessment it compares the four items against the pinned prior
publication. Validation checks the required structure, source quotations and
item identities; incomplete output remains a failed or needs-input run.

The person reviews and may edit the candidate. Saving a draft, approving it,
publishing it and delegating AWS authority are distinct actions.

## Inspect the proof behind the experience

| Capability | Direct evidence | Implementation |
| --- | --- | --- |
| New evidence changes the review candidate | [RO-08 live acceptance](../docs/RO08_LIVE_ACCEPTANCE.md) | [Strands assessment](../services/business_analysis/agent.py), [validation contract](../src/authority_delta/business/contracts.py) |
| Finite authority can be used and verifiably stopped | [RO-07 live acceptance](../docs/RO07_LIVE_ACCEPTANCE.md) | [Invocation gate](../services/business/invocation_gate.py), [application/revocation worker](../services/business/application_worker.py) |
| Outcomes and imported references retain their provenance | [RO-10/11 observed scope](../docs/BUSINESS_OUTCOME_INTERCHANGE.md) | [Business contracts and storage](../src/authority_delta/business/) |
| The product is usable across the full workflow | [Seven workspace views](../README.md#explore-the-complete-workspace) | [React workspace](../workbench/), [authenticated API](../services/business/handler.py) |

## Verify the downloaded evidence

From the repository root, with Python 3.12 and the analysis dependencies installed
as described in the [development guide](../docs/DEVELOPMENT.md):

```bash
PYTHONPATH=src .venv-analysis/bin/python scripts/check_ro07_acceptance.py \
  --acceptance-export /path/to/acceptance-export.json \
  --output /tmp/ro07-acceptance-result.json
```

The verified export returns `result: PASS` and
`status: RO07_LIVE_AUTHORITY_LIFECYCLE_CONFIRMED`. This checker runs offline;
it verifies the exported live evidence and makes no AWS call. It checks RO-07,
not every product feature. The separate
[RO-08 verification record](../evidence/aws/20260914-ro08-live-reassessment-verified.json)
identifies the successful reassessment and its export digest.

## Read the results in their demonstrated scope

The live connected test proves one registered ALLOW execution and seven DENY
results after suspension. The core workflow does not require a second account;
the supplied VendorPayment connector uses a distinct target account.

The latest reassessment is a human-review candidate. Technical acceptance does
not establish commercial savings, model quality or permission to expand a real
payment workload. Reviewers should inspect original evidence where a quotation
is short or its relevance needs interpretation. File import establishes a fixed
reference, not live Snowflake connectivity.
