# ReadinessOps — AWS edition

**The accountable path from evidence to human decision to finite AWS authority—and verifiable removal.**

[Live product](https://d3rn3hqm0ax5ux.cloudfront.net/) ·
[Judge guide](submission/JUDGE_GUIDE.md) ·
[Architecture](docs/ARCHITECTURE.svg) ·
[RO-07 live acceptance](docs/RO07_LIVE_ACCEPTANCE.md) ·
[Implementation](docs/IMPLEMENTATION.md) ·
[Acceptance evidence contract](docs/INTEGRATED_ACCEPTANCE_EVIDENCE.md)

![The complete ReadinessOps workspace: business objects, evidence, cited assessment, human decisions, actions, outcomes and history](docs/product-screens/viewport-01-overview.jpg)

ReadinessOps is a shared operating record for consequential AI work. It keeps the
business question, versioned evidence, cited agent analysis, human judgment,
publication, accountable follow-up, measured outcomes and operational history in
one place. **Authority Delta** is the AWS control plane behind that record: it
turns one published decision into narrowly bounded, time-limited authority and
proves when that authority has been removed.

**VendorPayment is a synthetic acceptance adapter, not the product boundary.** The
same workflow supports other business objects, evidence sets and registered
adapters without giving an agent open-ended AWS access.

Created for the AWS Agents for Humans Hackathon, Professional Agents track.
Apache-2.0. Prior ReadinessOps projects informed the design; no prior application
source has been incorporated into this repository.

## Why it matters

An AI proposal, a human approval, a published business decision and active runtime
permission are different facts. ReadinessOps keeps them separate and joins them
with evidence. The Strands agent can propose; only an authenticated human can
approve and publish; only a verified, finite adapter binding can execute.

When authority is stopped, the product closes its entry first and does not report
completion until the exactly owned Policy is absent and every registered request
returns a live DENY result.

## The complete product journey

These are live screens from one completed VendorPayment acceptance—not mockups.
Each screen preserves the full workspace context: the business-object portfolio,
the seven-stage workflow and the current published state.

| 1. Versioned evidence | 2. Cited agent assessment |
| --- | --- |
| Originals and extracted text are retained; a new version never rewrites the evidence used by an earlier assessment. | A Strands agent returns gaps, risks and next actions tied to the fixed evidence snapshot. |
| [![Evidence workspace](docs/product-screens/viewport-02-evidence-v2.jpg)](docs/product-screens/readinessops-02-evidence-clean.jpg) | [![Assessment with cited gaps and risks](docs/product-screens/viewport-03-assessment.jpg)](docs/product-screens/03-assessment-v2.jpg) |

| 3. Human review and publication | 4. Accountable actions |
| --- | --- |
| A signed-in reviewer edits the proposal, records judgment and publishes an official revision explicitly. | Published actions receive an owner, due date, status and new resolution evidence before completion. |
| [![Human review and publish workspace](docs/product-screens/viewport-04-review-v2.jpg)](docs/product-screens/readinessops-04-review-and-publish-clean.jpg) | [![Accountable actions workspace](docs/product-screens/viewport-05-actions.jpg)](docs/product-screens/readinessops-05-actions-clean.jpg) |

| 5. Outcomes and exchange | 6. Retained history |
| --- | --- |
| Outcomes attach to the official decision or completed AWS application; unmeasured metrics remain explicit and external packs are immutable references. | Evidence, assessments, human decisions, publications and AWS lifecycle events remain downloadable and reviewable. |
| [![Outcome recording and fixed-version exchange](docs/product-screens/viewport-06-outcomes-v2.jpg)](docs/product-screens/06-outcomes-v2.jpg) | [![Retained decision and authority history](docs/product-screens/viewport-07-history.jpg)](docs/product-screens/07-history-v2.jpg) |

## Authority Delta — finite AWS authority with proof

Business approval does not silently become runtime permission. An authenticated
person separately approves a registered boundary containing the publication,
connection, Runtime release, finite request set, policy hash and expiry. The entry
starts closed, opens only after verification, and closes before revocation begins.

| Registered execution | Revocation in progress | Verified suspension |
| --- | --- | --- |
| [![One registered request returns ALLOW](submission/video/live_screens/execution-allow.png)](submission/video/live_screens/execution-allow.png) | [![The product entry is closed while AWS proof is collected](submission/video/live_screens/stop-verifying.png)](submission/video/live_screens/stop-verifying.png) | [![The owned Policy is absent and every registered request returns live DENY](submission/video/live_screens/suspension-confirmed.png)](submission/video/live_screens/suspension-confirmed.png) |

## Live result — 2026-09-14

The two-account VendorPayment acceptance completed in `ap-northeast-1`:

- authenticated business decision and separate AWS delegation;
- application verified against the registered account-B Runtime and Policy engine;
- one normal registered request completed with `ALLOW`;
- the product entry closed before revocation;
- the exactly owned Policy was removed;
- every registered request returned live `DENY` with unchanged-ledger evidence;
- the authenticated export passed `RO07_LIVE_AUTHORITY_LIFECYCLE_CONFIRMED`.

See [the live acceptance record](docs/RO07_LIVE_ACCEPTANCE.md). The check is
offline and performs no AWS action.

## How it works

1. Register a business question, owner, goals and versioned evidence.
2. Run a Strands agent that returns cited Gap, Risk, Action and Decision proposals.
3. Let an authenticated person edit, approve and explicitly publish one revision.
4. When a registered adapter exists, approve a separate finite delegation.
5. Apply only after live canary verification; record controlled outcomes.
6. Reassess affected decisions when evidence or an agent release changes.
7. Close the entry, remove exact authority, prove DENY and retain the history.

![ReadinessOps Authority Delta architecture](docs/ARCHITECTURE.svg)

## Evidence-backed state

The local business workflow now includes publication-bound operational Actions
and version-fixed Outcome/Metric interchange. Measured metrics require value,
unit, period, source and observed/estimated basis; unmeasured metrics cannot carry
a zero or implied result. External imports are immutable references and cannot
replace the AWS workspace's official decision or AppliedBinding. See
`docs/BUSINESS_ACTION_LIFECYCLE.md` and
`docs/BUSINESS_OUTCOME_INTERCHANGE.md`. Live RO-08/10/11 acceptance remains
`NOT_RUN`.

| Area | Evidence-backed state |
| --- | --- |
| AWS baseline and fixed Runtime authorization | Gate 0 and Gate A PASS from operator-returned AWS evidence |
| Strands semantic analysis | SEM-01/02 PASS; changed case P-002, benign comparison unchanged |
| Authenticated workspace | Earlier Workbench sign-in and screen access confirmed by user |
| Shared ReadinessOps workspace | Deployed object, evidence, cited assessment, human review, publication, Actions and history workflow |
| Business contracts | Registered/versioned adapter binding; independent data-sharing contract tested locally; only VendorPayment has live AWS proof |
| Human decisions / publication | Authenticated reviewer approval and explicit publication observed in the live workspace |
| Customer connector | Distinct account-B foundation/connector and verified account-A wiring deployed |
| Live authority lifecycle | Registered ALLOW execution, entry closure, exact Policy removal, all-request DENY and unchanged-ledger export: PASS |
| Submission readiness | Public repository, public video and Devpost publication are external release steps |

The implemented product boundary is summarized in the
[implementation record](docs/IMPLEMENTATION.md) and acceptance evidence contracts.
Historical AWS proofs remain unchanged. No local
calculation, view or test is claimed as a live Gateway authorization result.

## Existing environment update

The prepared `ReadinessOps_AWS_Workspace_Update.py` updates the existing workspace
at its current URL using the already saved, version-pinned Gate B evidence.
It checks the confirmed reviewer and retains the password. The source and resume
record are kept under `~/readinessops-work/` in CloudShell, not `/tmp`.
See [workspace update](docs/READINESSOPS_WORKSPACE_UPDATE.md) for exact scope and
recovery. Do not rerun bootstrap, Gate A or Gate B to update the workspace.

## Local verification

The fixed Python 3.12 environment uses the committed deployment and analysis
lockfiles and vendor wheels. With `.venv-analysis` prepared:

```bash
PYTHONPATH=src:scripts:tests:. .venv-analysis/bin/python -m unittest discover -s tests -q
npm run build --prefix workbench
```

`workbench/test.mjs` consumes the locally generated review fixture from
`tests/test_workbench.py`. It tests rendered sections and the PKCE contract; it
is not browser or live AWS acceptance. Delivery validation runs the actual
operator file from an isolated directory through a local AWS CLI double.

## Code boundaries

- `src/authority_delta/readiness.py`: shared evidence/findings/actions/history.
- `adapter_contract.py`, `decisions.py`, `cedar.py`: common validated boundary
  identities, decisions and exact principal/tool/input scope rendering.
- `adapters/vendor_payment*.py`: sample business evaluation, boundary, policy and
  presentation. Historical `domain.py` / `policy_plan.py` imports are compatibility shims.
- `packages/contracts/readinessops.schema.json`: shared read-only workspace and
  boundary envelope v1.1; legacy `authority-delta.schema.json` is retained unchanged.
- `workbench/`, `services/workbench/`: authenticated UI and version-pinned read API.
- `infra/`, `services/`, `scripts/`: AWS resources, runtimes and delivery.
- `evidence/`: observed results and exact acceptance scope.

The general workflow, reassessment contract and bounded VendorPayment application
path are implemented. Published action proposals remain unstarted until
an authenticated user assigns an owner and due date; completion requires new,
versioned resolution evidence and links to the next reassessment. See
`docs/BUSINESS_ACTION_LIFECYCLE.md`.

A distinct account B is connected through separate ExternalId-bound discovery and
publisher roles. Account A independently rereads the registered resources through
the read-only DiscoveryRole before deploying its observed binding. The connected
readiness gate rejects mixed versions/accounts and premature authority claims
without exposing the ExternalId. The live lifecycle result is documented in
`docs/RO07_LIVE_ACCEPTANCE.md`.
