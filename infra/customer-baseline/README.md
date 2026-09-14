# Customer baseline stack

This template creates the synthetic-only customer sandbox and attaches an empty
AgentCore Policy Engine in `ENFORCE` mode. With no permit policy, Gateway is
default-deny. Deployment is **not** Gate A: Gate A passes only after the real
Gateway denial trace is correlated with an unchanged sandbox ledger.

The Lambda artifact is built from `services/sandbox/handler.py`. The request
registry is seeded separately and the Lambda role has `GetItem` only, so the
runtime cannot overwrite approved facts.

After stack creation, generate the idempotent seed transaction with the actual
table name and apply it through AWS CLI/CloudShell:

```bash
python scripts/build_registry_seed.py \
  --table-name ACTUAL_TABLE_NAME \
  --output evidence/local/registry-seed.json
aws dynamodb transact-write-items \
  --transact-items file://evidence/local/registry-seed.json \
  --region ACTUAL_REGION
```

The condition permits an identical replay but rejects reuse of the same request
ID with changed content.

Do not deploy until `status/PROJECT_STATE.json` records the actual AWS identity,
selected supported Region, budget controls, and successful CloudFormation type
availability preflight.
