# Business Action lifecycle

ReadinessOps keeps an AI-proposed action separate from operational completion.
An assessment proposal cannot assign work, close a finding or prove that the work
was effective.

## Lifecycle

When an approved Decision Pack is explicitly published, each action proposal is
materialized as an immutable-source `OPERATIONAL_ACTION` in `PROPOSED`. It is bound
to the publication digest, pack revision, related Finding IDs and the complete
evidence set used by that assessment.

An authenticated caller with the workspace `write` scope may then use the Actions
view to make one of these transitions:

| Current | Allowed next state | Additional requirement |
| --- | --- | --- |
| `PROPOSED` | `ACTIVE`, `CANCELLED` | `ACTIVE` requires owner and due date |
| `ACTIVE` | `ACTIVE`, `IN_PROGRESS`, `COMPLETED`, `CANCELLED` | owner, due date and update reason |
| `IN_PROGRESS` | `ACTIVE`, `IN_PROGRESS`, `COMPLETED`, `CANCELLED` | owner, due date and update reason |
| `COMPLETED`, `CANCELLED` | none | terminal records are not rewritten |

`COMPLETED` additionally requires one to eight readable EvidenceVersions from the
same business object. Evidence used in the assessment that proposed the action is
rejected as resolution evidence. The API reads back each original and stores its
version/hash reference with the completion record.

The first later assessment that selects all resolution evidence is linked to the
completed action by `reassessment_run_id` and the fixed input hash. This records
that a reassessment occurred; it does not predetermine the model result or transfer
the earlier approval.

## Integrity and authority boundaries

- Action IDs are server-generated and scoped to the authenticated object owner.
- Updates require both the current object revision and Action record revision.
- A repeated request ID returns the committed result; changed input with the same
  request ID is rejected.
- Action updates cannot publish a Decision Pack, approve AWS delegation, write an
  AgentCore Policy or change an `AppliedBinding`.
- Cancellation is not completion. Completion is not successful reassessment.
- Proposal text, uploaded evidence and model output remain untrusted data.

The API contract is `POST
/business/objects/{object_id}/actions/{action_id}` and is generated into
`packages/contracts/business.openapi.json`. Local tests use synthetic reviewers and
evidence only. The [RO-08 live acceptance record](RO08_LIVE_ACCEPTANCE.md)
separately documents authenticated action completion with new resolution evidence
and a subsequent validated reassessment on runtime 25. The first failed
reassessment link remains immutable; the later successful run uses the same fixed
input hash. The candidate does not carry forward human approval or AWS authority.
