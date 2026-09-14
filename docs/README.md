# Documentation

## Review the product

| Start with | What it explains |
| --- | --- |
| [Product overview](../README.md) | Who ReadinessOps helps, what the agent does, and the full workspace journey |
| [Three-minute judge guide](../submission/JUDGE_GUIDE.md) | One concrete path through the live record, with expected results |
| [Architecture](ARCHITECTURE.md) | The evidence-to-decision core and optional connected AWS authority |
| [Implementation](IMPLEMENTATION.md) | Current service responsibilities, code boundaries and acceptance status |

## Inspect the live evidence

| Record | Demonstrated scope |
| --- | --- |
| [RO-08: action and reassessment](RO08_LIVE_ACCEPTANCE.md) | New resolution evidence, completed action, a validated candidate and fixed prior-decision comparison |
| [RO-07: authority lifecycle](RO07_LIVE_ACCEPTANCE.md) | Registered ALLOW execution, entry closure, exact Policy removal and seven-request DENY verification |
| [RO-10/11: outcomes and exchange](BUSINESS_OUTCOME_INTERCHANGE.md) | Observed versus unmeasured outcomes and idempotent fixed-reference import |
| [Integrated evidence contract](INTEGRATED_ACCEPTANCE_EVIDENCE.md) | Export composition, provenance and integrity checks |

## Build and inspect contracts

[Development guide](DEVELOPMENT.md) provides local dependency installation,
verification commands, source locations and AWS runbook entry points.

[Action lifecycle](BUSINESS_ACTION_LIFECYCLE.md) and the other `BUSINESS_*`
documents describe the core contracts. `AWS_CUSTOMER_*`, `CONNECTED_*` and
`RO07_*` documents describe an optional execution connector or its evidence.
The distinct-account topology used by that connector is not a prerequisite for
the ReadinessOps core.

Dated plans, gate notes and recovery reports preserve the implementation history.
Use the current pages above for present capabilities and acceptance status;
historical `NOT_RUN` or pending statements describe their original checkpoints.
