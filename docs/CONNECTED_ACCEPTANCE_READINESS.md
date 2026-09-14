# Connected acceptance readiness gate

Run this offline gate after the account-B connector and account-A wiring
operators have both returned a validated, collected result. If the clean
foundation operator was required, retain and include its launch and result files.
If the matching foundation already existed and the foundation operator was
correctly skipped, omit both foundation arguments; do not rerun it just to create
evidence.

Keep all launch and full result files private. The connector launch and full
connector result contain the saved ExternalId. Do not paste them into chat or use
console summaries in their place.

From the exact account-A source used for wiring:

```sh
python3 scripts/check_connected_acceptance_readiness.py \
  --foundation-launch /private/customer-foundation-latest-launch.json \
  --foundation-report /private/customer-foundation-result.json \
  --connector-launch /private/customer-connector-latest-launch.json \
  --connector-report /private/customer-connector-result.json \
  --wiring-launch /private/customer-wiring-latest-launch.json \
  --wiring-report /private/customer-wiring-result.json \
  --output /private/connected-acceptance-readiness.json
```

When the foundation operator was not needed, remove both `--foundation-*` lines.
Providing only one of that pair is rejected.

The gate rejects non-finite or duplicate-member JSON, oversized files, failed or
uncollected builds, mixed accounts/Regions/builds/sources, a changed ExternalId or
registration, a connector report whose exact bytes differ from the wiring input,
foundation-to-connector drift when foundation evidence is present, connector-to-
wiring readback drift, non-empty Policy or ledger state, and any report claiming
human approval, Policy publication or live customer canary execution.

Only `result: PASS` with
`status: READY_FOR_AUTHENTICATED_ACCEPTANCE` permits the bounded live acceptance
to begin. The output contains hashes and version bindings, not the ExternalId.
This check performs no AWS call, human decision, official publication, Policy
write or Runtime invocation. Its PASS is a start condition, not D2/D3 acceptance.

