# RO-07 live AWS acceptance — browser sequence

Prerequisite status: `READY_FOR_AUTHENTICATED_ACCEPTANCE`. This procedure uses
only the registered synthetic sandbox requests and never sends a real payment.
The product interface is English.

## 1. Register the business object

Select `＋ Add business object` and enter the following values.

| Field | Value |
| --- | --- |
| Business / initiative name | VendorPayment authority lifecycle acceptance |
| Responsible person | Shinji Okada |
| Business purpose | Confirm that only the fixed synthetic VendorPayment requests can run under finite authority, without sending a real payment, and that the authority can be removed conclusively. |
| Question to assess | May the synthetic MAINTAIN request set be delegated to the registered account-B adapter, used for one controlled invocation, and then stopped? |
| Goal / measurement | One registered ALLOW request completes through the controlled entry. Unregistered or prohibited requests never run. After stopping, the entry is closed, the owned Policy is absent, all registered requests return DENY, and the ledger remains unchanged during DENY verification. |

Select `Create and add evidence`, add `Evidence_VendorPayment_RO07_EN.txt`, and
then start the assessment with the selected evidence. The assessment continues if
the page is closed. Wait until it is ready for human review.

## 2. Record the human decision and publish

Review the assessment and its citations. Continue only if you agree with the
recorded content.

1. Open `Review & publish` and inspect the editable proposal.
2. Review note: `I verified that this is a synthetic, finite-request acceptance test and does not authorize real payments.`
3. Select `Save decision draft`.
4. Decision reason: `I approve this exact recorded decision for the bounded synthetic acceptance test only. No real payment or unrestricted AWS execution is authorized.`
5. Set validity to `1` day, select `Record approval`, and then select `Publish this decision`.
6. Confirm the green `PUBLICATION COMPLETE` panel and its `View official decision` and `View history and records` actions.

## 3. Delegate, invoke once, and stop

Continue at the bottom of the same `Review & publish` screen.

1. Under the missing execution connection panel, select the registered `vendor_payment` connection for account B `062788795311`.
2. Connection reason: `This object is the bounded synthetic VendorPayment lifecycle acceptance for the registered account-B connection.` Save the connection.
3. Select profile `MAINTAIN`. Delegation reason: `Authorize only the registered finite synthetic MAINTAIN requests for this one-day acceptance.` Set validity to `1` day and select `Approve AWS delegation separately`.
4. Select `Start closed application and verification`. Wait for `Verified and applied`. If the state becomes `Unknown — recovery required` or `Recovered closed`, stop and do not approve or apply again.
5. Select the first `Registered protected request`, choose `Run with current authority`, and confirm `Execution confirmed` with `ALLOW`.
6. Stop reason: `RO-07 acceptance completed; close the entry and remove the exact finite authority.` Select `Close entry and begin suspension`.
7. Only `Suspension confirmed` is a pass. `Stop requested — verifying` and `Entry closed — AWS result unknown` are not passes. Recovery of the same request continues if the page is closed.

## 4. Verify the evidence once

Open `History`, select `Download acceptance evidence`, and upload the JSON to
account-A CloudShell as `ro07-acceptance-export.json`. Run only:

```sh
cd /home/cloudshell-user/readinessops-connected-a &&
python3 scripts/check_ro07_acceptance.py \
  --acceptance-export /home/cloudshell-user/ro07-acceptance-export.json \
  --output /home/cloudshell-user/ro07-acceptance-result.json
```

The only passing value is:

```json
{"result":"PASS","status":"RO07_LIVE_AUTHORITY_LIFECYCLE_CONFIRMED"}
```

For any other result, do not apply again. Preserve
`ro07-acceptance-result.json` and the visible product state.
