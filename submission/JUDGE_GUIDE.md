# Judge guide

## Fastest review path

1. Open the live product: https://d3rn3hqm0ax5ux.cloudfront.net/
2. Sign in with the private credentials supplied in the Devpost testing instructions.
3. Review the product journey across Overview, Evidence, Assessment, Review &
   publish, Actions, Outcomes & exchange, and History.
4. Confirm that cited AI proposals, human judgment and explicit publication remain
   separate in the official business record.
5. Then open **VendorPayment authority lifecycle acceptance** to inspect the
   optional connected-enforcement path and its retained RO-07 record.

The core ReadinessOps workflow does not require account B. The completed
VendorPayment record additionally proves the following optional bounded lifecycle:

- one registered protected request returned `ALLOW` through the controlled entry point;
- the stop request closed new execution entry;
- the exact customer-owned AWS Policy was removed;
- every registered request returned live `DENY` after suspension;
- the evidence export passed the repository verifier with
  `RO07_LIVE_AUTHORITY_LIFECYCLE_CONFIRMED`.

## Offline evidence verification

Download the acceptance evidence JSON from the product, then run:

```bash
python3 scripts/check_ro07_acceptance.py \
  --acceptance-export /path/to/acceptance-export.json \
  --output /tmp/ro07-acceptance-result.json
```

The verifier automatically loads the pinned vendored RFC 8785 wheel. A valid
export returns:

```json
{"scope":"OFFLINE_RO07_EXPORTED_LIVE_AUTHORITY_LIFECYCLE_NO_AWS_ACTION","result":"PASS","status":"RO07_LIVE_AUTHORITY_LIFECYCLE_CONFIRMED"}
```

This command is offline and performs no AWS action.

## Safety boundary

- The acceptance used a synthetic `VendorPayment` request set.
- No real payment or unrestricted AWS execution was authorized.
- For this connected acceptance, the account-B publisher could act only on the
  registered finite Policy lifecycle.
- Suspension is not reported complete until Policy absence and live `DENY`
  results are both proven.

Architecture: [`docs/ARCHITECTURE.md`](../docs/ARCHITECTURE.md)

Detailed acceptance result: [`docs/RO07_LIVE_ACCEPTANCE.md`](../docs/RO07_LIVE_ACCEPTANCE.md)
