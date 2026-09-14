# Account-B customer foundation operator

Use this only when the confirmed, distinct account B does not already contain this
distribution's `authority-delta-bootstrap`, `authority-delta-customer-baseline` and
`authority-delta-vendor-runtimes` stacks. If those stacks already exist, use the
customer connector operator; it performs exact readback before changing anything.

The launcher checks the signed-in account is not account A, root MFA is enabled and
the approved budget notifications are present. For confirmed account 062788795311,
the user selected USD 30 and name `readinessops-validation-monthly`; other historical
profiles stay USD 50. Run `python3 scripts/prepare_customer_budget.py` to reconcile
the observed template alerts into actual 20/50/100 and forecast 80 percent without
changing the budget amount. These alerts are not a spending cap.
The launcher then creates or resumes the
same-account CodeBuild bootstrap, uploads one immutable source version and starts a
bounded foundation build. Root credentials are not forwarded and root does not
deploy the baseline or Runtime resources directly.

Run later from CloudShell in the confirmed account B:

```sh
python3 scripts/launch_customer_foundation.py
```

The worker creates the synthetic-only Gateway/Policy Engine/Lambda tables and fixed
V1/V2 Runtime identities. It seeds the seven immutable fixture requests only when
the registry is empty. An altered registry, any existing Policy, any ledger outcome,
an unstable stack, a changed artifact bucket, or a failed exact readback stops the
operation without deleting or normalizing existing state.

The printed `--resume` command only collects the same build. If that build is
terminal but its final report is absent, the printed `--recover` command reuses the
same immutable source version. Neither path starts a duplicate active build.
Collection is recorded as `COLLECTED` only after the complete report is bound to
the exact build, source, account, Region and version and confirms zero Policy and
ledger entries plus all prohibited side effects as `NOT_RUN`.

Foundation PASS means only that the account-B prerequisites are installed and read
back. The connector, account-A registry wiring, Policy publication, live canary,
business publication and human approval all remain `NOT_RUN`. Continue with
`scripts/launch_customer_connector.py`; never substitute account A. Retain the
private launch and full result files for the connected readiness gate.
