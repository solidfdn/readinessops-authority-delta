#!/usr/bin/env python3
"""Install and verify the account-B baseline and fixed V1/V2 Runtimes.

This CodeBuild worker creates only the synthetic customer foundation needed by the
separate connector operator.  It never creates a Policy, invokes a Runtime, records
a business decision, or connects account A.  Existing non-empty state is preserved
and rejected instead of being normalized or deleted.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / 'src'), str(ROOT / 'scripts')]

from authority_delta.canonical import sha256_json
from authority_delta.evidence_json import encode_evidence
from authority_delta.registry import FixtureBundle
from build_registry_seed import build_transaction
from build_runtime_artifact import build as build_runtime_artifact
from deploy_baseline import all_records
from deploy_customer_connector import observe_customer
from verify_aws import observed_at, safe_error, save_evidence


ACCOUNT_A = '538522204923'
REGION = 'ap-northeast-1'
ROLE = 'ReadinessOpsAuthorityDeltaDeployer'
BOOTSTRAP_STACK = 'authority-delta-bootstrap'
BASELINE_STACK = 'authority-delta-customer-baseline'
RUNTIME_STACK = 'authority-delta-vendor-runtimes'
SCOPE = 'ACCOUNT_B_CUSTOMER_FOUNDATION_NO_POLICY_CANARY_CONNECTOR_OR_BUSINESS_PUBLICATION'


def require_identity(identity, environment):
    account = identity.get('Account', '')
    if (not re.fullmatch(r'[0-9]{12}', account) or account == ACCOUNT_A
            or environment.get('AD_EXPECTED_ACCOUNT') != account):
        raise ValueError('A distinct exact account-B identity is required')
    if environment.get('AD_REGION') != REGION:
        raise ValueError('Customer foundation Region must be ap-northeast-1')
    if not re.fullmatch(
            rf'arn:aws:sts::{account}:assumed-role/{ROLE}/[^/]+', identity.get('Arn', '')):
        raise ValueError('Customer foundation deployment requires the owned CodeBuild role')
    if not environment.get('CODEBUILD_BUILD_ID', '').startswith('authority-delta-deploy:'):
        raise ValueError('Customer foundation deployment requires the owned CodeBuild project')
    if not re.fullmatch(r'[0-9a-f]{64}', environment.get('AD_SOURCE_SHA256', '')):
        raise ValueError('Deployment source digest is missing')
    return account


def stable_stack(session, name):
    value = session.client('cloudformation').describe_stacks(StackName=name)['Stacks'][0]
    if value.get('StackStatus') not in ('CREATE_COMPLETE', 'UPDATE_COMPLETE'):
        raise ValueError(f'{name} is not in a stable completed state')
    return value


def outputs(value):
    return {item['OutputKey']: item['OutputValue'] for item in value.get('Outputs', [])}


def deploy_stack(run, template, name, values, *, named=False):
    command = ['aws', 'cloudformation', 'deploy', '--region', REGION,
        '--no-cli-pager', '--template-file', str(template), '--stack-name', name,
        '--capabilities', 'CAPABILITY_NAMED_IAM' if named else 'CAPABILITY_IAM',
        '--no-fail-on-empty-changeset']
    if values:
        command += ['--parameter-overrides',
            *[key + '=' + value for key, value in values.items()]]
    command += ['--tags', 'Project=ReadinessOpsAuthorityDelta',
        'Baseline=AD-BASELINE-1.0', 'DataClass=SyntheticOnly']
    run(command, cwd=ROOT, check=True)


def upload_versioned(session, bucket, path, prefix):
    raw = Path(path).read_bytes()
    digest = hashlib.sha256(raw).hexdigest()
    key = f'{prefix}/{digest}/{Path(path).name}'
    s3 = session.client('s3')
    if s3.get_bucket_versioning(Bucket=bucket).get('Status') != 'Enabled':
        raise ValueError('Customer artifact bucket is not versioned')
    try:
        head = s3.head_object(Bucket=bucket, Key=key)
        if head.get('Metadata', {}).get('sha256') != digest:
            raise ValueError('Existing content-addressed artifact differs')
        version = head.get('VersionId')
    except Exception as exc:
        if getattr(exc, 'response', {}).get('Error', {}).get('Code') not in (
                '404', 'NoSuchKey', 'NotFound'):
            raise
        stored = s3.put_object(Bucket=bucket, Key=key, Body=raw,
            Metadata={'sha256': digest}, ContentType='application/zip')
        version = stored.get('VersionId')
    if not version or version == 'null':
        raise ValueError('Customer artifact has no immutable version')
    return {'bucket': bucket, 'key': key, 'version_id': version,
            'sha256': digest, 'size_bytes': len(raw)}


def ensure_registry(session, table, fixtures):
    ddb = session.client('dynamodb')
    expected = [item['Put']['Item'] for item in build_transaction(fixtures, table)]
    current = all_records(ddb, table)
    seeded = not current
    normalize = lambda values: sorted(values, key=lambda item: item['request_id']['S'])
    if not current:
        ddb.transact_write_items(TransactItems=build_transaction(fixtures, table))
        current = all_records(ddb, table)
    if normalize(current) != normalize(expected):
        raise ValueError('Customer immutable request registry differs; existing data was preserved')
    return {'count': len(current), 'hash': sha256_json(normalize(current)),
            'seeded': seeded}


def execute(session, environment, report, *, run=subprocess.run):
    identity = session.client('sts').get_caller_identity()
    account = require_identity(identity, environment)
    bucket = environment.get('AD_ARTIFACT_BUCKET', '')
    report.update(account=account, region=REGION, caller_arn=identity['Arn'])
    bootstrap = outputs(stable_stack(session, BOOTSTRAP_STACK))
    if bootstrap.get('ArtifactBucketName') != bucket:
        raise ValueError('Customer bootstrap artifact bucket differs')

    fixtures = FixtureBundle.load(ROOT / 'fixtures/decision_cases.json')
    subprocess_result = run([sys.executable, 'scripts/build_sandbox_artifact.py'],
                            cwd=ROOT, check=True)
    del subprocess_result
    sandbox = upload_versioned(session, bucket,
        ROOT / 'dist/authority-delta-sandbox.zip', 'customer-foundation/sandbox')
    deploy_stack(run, ROOT / 'infra/customer-baseline/template.json', BASELINE_STACK,
        {'ConnectionId': 'conn-demo', 'SandboxArtifactBucket': bucket,
         'SandboxArtifactKey': sandbox['key'],
         'SandboxArtifactVersion': sandbox['version_id']})
    baseline = outputs(stable_stack(session, BASELINE_STACK))
    required = {'GatewayArn', 'GatewayIdentifier', 'GatewayUrl', 'PolicyEngineId',
        'RequestRegistryTableName', 'SandboxLedgerTableName'}
    if not required.issubset(baseline):
        raise ValueError('Customer baseline outputs are incomplete')
    control = session.client('bedrock-agentcore-control')
    policy_page = control.list_policies(policyEngineId=baseline['PolicyEngineId'])
    if policy_page.get('policies') or policy_page.get('nextToken'):
        raise ValueError('Customer Policy Engine is not empty; existing policies were preserved')
    if all_records(session.client('dynamodb'), baseline['SandboxLedgerTableName']):
        raise ValueError('Customer ledger is not empty; existing outcomes were preserved')
    registry = ensure_registry(session, baseline['RequestRegistryTableName'], fixtures)

    artifacts = {}
    for release in ('V1', 'V2'):
        built = build_runtime_artifact(fixtures, release,
            ROOT / f'dist/customer-foundation-{release.lower()}.zip')
        artifacts[release] = upload_versioned(session, bucket, built['path'],
                                               'customer-foundation/runtime')
        artifacts[release].update(
            release_definition_hash=built['release_definition_hash'],
            request_registry_snapshot_hash=built['request_registry_snapshot_hash'])
    deployer = f'arn:aws:iam::{account}:role/{ROLE}'
    runtime_values = {'ArtifactBucket': bucket, 'GatewayArn': baseline['GatewayArn'],
        'GatewayIdentifier': baseline['GatewayIdentifier'],
        'GatewayUrl': baseline['GatewayUrl'],
        'RequestRegistryTableName': baseline['RequestRegistryTableName'],
        'DeployerRoleArn': deployer, 'ApplicationCanaryRoleArn': deployer,
        'NormalInvocationRoleArn': deployer}
    for release in ('V1', 'V2'):
        runtime_values[release + 'ArtifactKey'] = artifacts[release]['key']
        runtime_values[release + 'ArtifactVersionId'] = artifacts[release]['version_id']
    deploy_stack(run, ROOT / 'infra/vendor-runtimes/template.json', RUNTIME_STACK,
                 runtime_values, named=True)

    observed = observe_customer(session, account)
    observed['account'] = account
    runtime_outputs = outputs(stable_stack(session, RUNTIME_STACK))
    if runtime_outputs.get('V1RuntimeArn') == runtime_outputs.get('V2RuntimeArn'):
        raise ValueError('V1 and V2 Runtime identities are not distinct')
    if runtime_outputs.get('V1ExecutionRoleArn') == runtime_outputs.get('V2ExecutionRoleArn'):
        raise ValueError('V1 and V2 execution roles are not distinct')
    report.update(result='PASS', bootstrap_stack_id=stable_stack(
        session, BOOTSTRAP_STACK)['StackId'],
        baseline_stack_id=observed['baseline_stack']['StackId'],
        runtime_stack_id=observed['runtime_stack']['StackId'],
        baseline_artifact=sandbox, runtime_artifacts=artifacts,
        request_registry=registry,
        observed={'connection_id': observed['connection_id'],
            'target_id': observed['target_id'], 'target_name': observed['target_name'],
            'registry_hash': observed['registry_hash'],
            'ledger_hash': observed['ledger_hash'],
            'runtimes': observed['runtimes']},
        policy_count=0, ledger_count=0, connector='NOT_RUN',
        policy_write='NOT_RUN', live_canary='NOT_RUN',
        business_publication='NOT_RUN')
    return report


def main():
    import boto3
    import botocore
    environment = os.environ
    report = {'schema_version': '1.0', 'scope': SCOPE, 'result': 'FAIL',
        'observed_at': observed_at(), 'build_id': environment.get('CODEBUILD_BUILD_ID'),
        'source_sha256': environment.get('AD_SOURCE_SHA256'),
        'connector': 'NOT_RUN', 'policy_write': 'NOT_RUN',
        'live_canary': 'NOT_RUN', 'business_publication': 'NOT_RUN'}
    session = boto3.Session(region_name=REGION)
    try:
        execute(session, environment, report)
    except Exception as exc:
        report['error'] = safe_error(exc)
        print('ERROR: ' + str(exc), flush=True)
    report['sdk_versions'] = {'boto3': boto3.__version__,
                              'botocore': botocore.__version__}
    data = encode_evidence(report)
    path = ROOT / 'evidence/aws/customer-foundation-result.json'
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    try:
        save_evidence(session, environment, data, path, environment['AD_REPORT_KEY'])
    except Exception as exc:
        print('ERROR saving customer foundation evidence: ' + str(exc), flush=True)
        return 1
    print(data.decode(), flush=True)
    return 0 if report['result'] == 'PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
