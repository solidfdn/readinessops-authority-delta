# Account-B customer connector operator

This is the next account-B deployment entrypoint after a distinct customer account
has the versioned bootstrap bucket, `authority-delta-customer-baseline`, and
`authority-delta-vendor-runtimes` stacks from this same distribution. If those
prerequisites are absent, first use `AWS_CUSTOMER_FOUNDATION_RUNBOOK.md`. Neither
operator substitutes for confirming the distinct customer account.

The operator performs readback before any deployment. It rejects account A, a
different Region, missing root MFA, a changed USD 50 budget guard, an unexpected
CodeBuild project, a changed registry, Gateway, Policy Engine, target, V2 Runtime,
endpoint, execution role or artifact bucket. It creates no business decision and
does not run a Policy write or live ALLOW/DENY canary.

Run later from CloudShell in the confirmed account B:

```sh
python3 scripts/launch_customer_connector.py
```

The launcher generates one ExternalId, writes a local and versioned-S3 recovery
record before starting CodeBuild, and reuses it on rerun. A disconnect while the
build remains available is collected with the printed `--resume` command. If that
exact build is terminal and has no recoverable report, the printed `--recover`
command starts one explicit recovery build with the same immutable source version
and ExternalId. It never starts while the earlier build is active. CloudFormation
uses the same three stack names, while artifacts are content addressed and
versioned.

The launcher marks the report `COLLECTED` only after validating its complete
observed binding, derived registration, ExternalId, account/Region/build/source,
immutable artifacts and all three `NOT_RUN` side-effect fields. A successful build
with an incomplete or unsafe report remains uncollected and cannot feed account A.

The worker deploys two distinct cross-account roles. Their trust names account A,
requires the exact `authority-delta-application-worker` principal through
`aws:PrincipalArn`, and requires the saved ExternalId. `DiscoveryRole` is read-only.
`PublishInvokeRole` can invoke only the qualified customer Publisher alias. The
Publisher alone can update its bound Policy Engine, and the isolated Canary alone
can read the synthetic registry/ledger and invoke the fixed V2 Runtime.

After readback, the worker derives the finite adapter registry from the fixed
fixture, rebuilds both customer functions with that exact registration, updates
the V2 Runtime resource policy for the exact Canary role, and saves the generated
registry and full report as versioned private objects. The console summary omits
the ExternalId. Transfer the complete report and follow
`AWS_CUSTOMER_WIRING_RUNBOOK.md`; account A wiring and the authenticated D3
acceptance remain separate steps and must not be reported as complete here. Keep
the private connector launch record with the full result for the final offline
chain check; neither file should be pasted into chat.
