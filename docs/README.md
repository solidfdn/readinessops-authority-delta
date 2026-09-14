# Documentation map

Use the following documents as the current product definition:

1. [Repository overview](../README.md) — product purpose, complete user journey
   and evidence-backed status.
2. [Architecture](ARCHITECTURE.md) — account-neutral product core, optional
   connector boundary and the distinct-account RO-07 topology.
3. [Implementation](IMPLEMENTATION.md) — current service boundaries, execution
   paths and stop invariant.
4. [RO-07 live acceptance](RO07_LIVE_ACCEPTANCE.md) — scoped evidence for the
   optional VendorPayment connector deployed across two AWS accounts.
5. [Integrated acceptance evidence](INTEGRATED_ACCEPTANCE_EVIDENCE.md) — export
   composition and verification contract.

## Scope of the other documents

- `BUSINESS_*` documents define product-core workflow contracts.
- `AWS_CUSTOMER_*`, `CONNECTED_*` and `RO07_*` documents are runbooks or evidence
  for an optional connected adapter. They do not define a two-account prerequisite
  for ReadinessOps.
- Dated plans, recovery notes, gate notes and baseline documents preserve the
  implementation chronology. Their then-current status statements are historical
  and must not override the current definition above.

The repository contains one English product and one product architecture. It does
not publish a separate localized edition.
