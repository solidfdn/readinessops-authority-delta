# Customer publisher deployment boundary

This stack is deployed in the registered customer account only after its exact
account, Region, Policy Engine, V2 Runtime, registry and ledger bindings are
confirmed. The account-A application worker assumes only the customer
`PublishInvokeRole` with the connector ExternalId; that role can invoke only the
qualified publisher alias. A separate ExternalId-bound `DiscoveryRole` has only
the read APIs needed to confirm the registered resources. The publisher can mutate
only the bound Policy Engine and can
invoke only the qualified canary alias. The canary can read the immutable
request registry and sandbox ledger and invoke only the bound Runtime.

The packaged adapter registry remains empty until those values are confirmed.
After this stack creates the canary role, the V2 Runtime resource policy must be
updated from the same distribution to name that exact role; IAM permission alone
does not make the Runtime callable. No deployment or live acceptance is claimed
by this template.

After readback verifies the stack and existing Gateway/Policy Engine/Runtime,
create `services/business/adapter_registrations.json` only with
`scripts/build_customer_adapter_registry.py`. The builder derives the finite
profiles and Cedar input from the fixed fixture, rejects account A, and accepts no
browser/model supplied policy or request list.

`scripts/launch_customer_connector.py` is the recoverable account-B entrypoint.
It requires the existing bootstrap, customer baseline and fixed Runtime stacks,
root MFA and the fixed budget guard. It does not create a business publication,
Policy or live canary result. The exact live operation remains a later acceptance.
