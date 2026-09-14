# Account-A verified customer wiring operator

Run this only after the distinct account-B connector operator returns PASS. Copy
its complete `customer-connector-result.json` to the account-A CloudShell; do not
edit it or copy only the console summary. The console summary intentionally omits
the ExternalId required for correlated verification.

From the existing account-A source directory:

```sh
python3 scripts/launch_customer_wiring.py \
  --connector-report /path/to/customer-connector-result.json
```

The launcher verifies the connector report structure and derived registration,
uploads that exact report and the current source as private versioned objects, and
starts one recoverable CodeBuild job. The worker does not trust the report as AWS
proof. It assumes only the report-bound, ExternalId-protected read-only DiscoveryRole
and rereads the account-B baseline, Gateway, Policy Engine, target, fixed V2 Runtime,
connector stack and qualified functions. Policy and ledger must both still be empty.

Only an exact readback packages the single generated adapter registration and runs
the existing business deployment checks. This updates the account-A business API,
application worker and English UI while preserving the protected Gate A/B resources.
It also runs the existing synthetic non-payment Strands deployment canary; it does
not create a real business object or human approval.

The printed `--resume` command collects the same build. A terminal build without a
final report can be retried with the printed `--recover` command, which reuses both
the same immutable source and connector report. The launcher records `COLLECTED`
only after the full result is bound to those versions and confirms the verified
registry, unchanged business state, synthetic assessment PASS, empty Policy and
ledger readback, no human approval, and Policy/live customer canary/human workflow
as `NOT_RUN`.

Do not begin live D3 acceptance from this report alone. Run the offline chain gate
in `CONNECTED_ACCEPTANCE_READINESS.md` with the private connector and wiring launch
and result files, plus the foundation pair only when that operator was actually
needed. Only its exact `READY_FOR_AUTHENTICATED_ACCEPTANCE` result is the start
condition; it still does not count as human or live Policy acceptance.
