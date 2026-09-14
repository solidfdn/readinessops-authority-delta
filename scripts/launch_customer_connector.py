#!/usr/bin/env python3
"""Launch or resume the bounded account-B customer connector deployment."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import shlex
import subprocess
import sys
import tempfile
import time
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
from check_connected_acceptance_readiness import (decode_document,
    validate_collected_launch, validate_connector_result)
from launch_deployment import (AwsCli, DeploymentError, source_archive,
    stack_outputs, show_failure_details)
from launch_gate_a import write_record


ACCOUNT_A = '538522204923'
REGION = 'ap-northeast-1'
SCOPE = 'ACCOUNT_B_CUSTOMER_CONNECTOR_DEPLOYMENT_NO_BUSINESS_PUBLICATION'
BUNDLE_VERSION = '20260914-customer-connector-v12-policy-create-discovery-recovery'
LATEST_KEY = 'customer-connector-launch/latest.json'
SOURCE_ROLE = f'arn:aws:iam::{ACCOUNT_A}:role/authority-delta-application-worker'


def budget_profile(account):
    # User-confirmed account-B operating value; account A and historical profiles stay unchanged.
    if account == '062788795311':
        return 'readinessops-validation-monthly', 30.0
    return 'ReadinessOps-Authority-Delta', 50.0


def budget(cli, account, operation):
    command = ['aws', 'budgets', operation, '--account-id', account,
        '--budget-name', budget_profile(account)[0], '--region', 'us-east-1',
        '--output', 'json', '--no-cli-pager', '--cli-connect-timeout', '10',
        '--cli-read-timeout', '30']
    result = subprocess.run(command, cwd=ROOT, env=cli.env, text=True,
                            capture_output=True)
    if result.returncode:
        raise DeploymentError(result.stderr.strip())
    return json.loads(result.stdout)


def guard(cli):
    identity = cli.run('sts', 'get-caller-identity')
    account = identity.get('Account', '')
    if not re.fullmatch(r'[0-9]{12}', account) or account == ACCOUNT_A:
        raise DeploymentError('Run this operator only in a distinct account B. No operation started.')
    summary = cli.run('iam', 'get-account-summary')
    if summary.get('SummaryMap', {}).get('AccountMFAEnabled') != 1:
        raise DeploymentError('Account-B root MFA is not enabled. No operation started.')
    value = budget(cli, account, 'describe-budget')['Budget']
    notifications = budget(cli, account, 'describe-notifications-for-budget')
    if ((value.get('BudgetType'), value.get('TimeUnit'),
            value.get('BudgetLimit', {}).get('Unit'),
            float(value.get('BudgetLimit', {}).get('Amount', -1)))
            != ('COST', 'MONTHLY', 'USD', budget_profile(account)[1])):
        raise DeploymentError('Account B does not have its approved monthly USD budget.')
    observed = {(item['NotificationType'], float(item['Threshold']))
                for item in notifications.get('Notifications', [])}
    if observed != {('ACTUAL', 20.0), ('ACTUAL', 50.0), ('ACTUAL', 100.0),
                    ('FORECASTED', 80.0)}:
        raise DeploymentError('Account-B budget notification thresholds differ.')
    return account


def validate(record, account, bucket, project):
    expected = {'scope': SCOPE, 'account': account, 'region': REGION,
        'bucket': bucket, 'project': project,
        'source_application_worker_role_arn': SOURCE_ROLE}
    if not isinstance(record, dict) or any(record.get(k) != v for k, v in expected.items()):
        raise DeploymentError('Saved connector launch binding differs')
    if (not re.fullmatch(r'evidence/[0-9a-f]{32}/customer-connector-result\.json',
            record.get('report_key', ''))
            or not re.fullmatch(r'[0-9a-f]{64}', record.get('source_sha256', ''))
            or not re.fullmatch(r'[A-Za-z0-9+=,.@:/_-]{32,128}',
                                record.get('external_id', ''))
            or record.get('external_id_hash') != hashlib.sha256(
                record['external_id'].encode()).hexdigest()
            or not record.get('source_version')
            or record['source_version'] == 'null'):
        raise DeploymentError('Saved connector source, report or ExternalId binding is invalid')
    if record.get('build_id') and not re.fullmatch(
            re.escape(project) + r':[A-Za-z0-9_-]+', record['build_id']):
        raise DeploymentError('Saved connector build identity is invalid')


def save(cli, path, record):
    write_record(path, record)
    cli.run('s3api', 'put-object', '--bucket', record['bucket'], '--key',
            LATEST_KEY, '--body', str(path))
    cli.run('s3api', 'put-object', '--bucket', record['bucket'], '--key',
            record['report_key'].replace('customer-connector-result.json',
                                         'customer-connector-launch.json'),
            '--body', str(path))


def recent(cli, project):
    ids = cli.run('codebuild', 'list-builds-for-project', '--project-name', project,
        '--sort-order', 'DESCENDING', '--max-items', '50').get('ids', [])
    return cli.run('codebuild', 'batch-get-builds', '--ids', *ids).get('builds', []) if ids else []


def reconcile(cli, record, path):
    matches = []
    for build in recent(cli, record['project']):
        values = {item['name']: item['value'] for item in
                  build.get('environment', {}).get('environmentVariables', [])}
        if (values.get('AD_REPORT_KEY') == record['report_key']
                and values.get('AD_SOURCE_SHA256') == record['source_sha256']
                and values.get('AD_EXTERNAL_ID') == record['external_id']):
            matches.append(build)
    if len(matches) != 1:
        raise DeploymentError('Connector launch is not confirmed; rerun with the saved record. No duplicate build started.')
    record['build_id'] = matches[0]['id']
    save(cli, path, record)


def collect(cli, record, path, delay=time.sleep):
    if not record.get('build_id'):
        reconcile(cli, record, path)
    print('Build ID: ' + record['build_id'], flush=True)
    print('Resume this build: ' + shlex.join([
        'python3', str(ROOT / 'scripts/launch_customer_connector.py'),
        '--resume', str(path)]), flush=True)
    last = None
    for _ in range(210):
        builds = cli.run('codebuild', 'batch-get-builds', '--ids',
                         record['build_id']).get('builds', [])
        if len(builds) != 1 or builds[0].get('id') != record['build_id']:
            raise DeploymentError('Connector build identity is not confirmed')
        build = builds[0]
        state = (build.get('currentPhase'), build.get('buildStatus'))
        if state != last:
            print('CodeBuild: ' + str(state[0]) + ' / ' + str(state[1]), flush=True)
            last = state
        if state[1] != 'IN_PROGRESS':
            break
        delay(10)
    else:
        raise DeploymentError('Collection timed out; rerun the same saved launch record.')
    result_path = path.parent / 'customer-connector-result.json'
    try:
        downloaded = cli.run('s3api', 'get-object', '--bucket', record['bucket'],
            '--key', record['report_key'], str(result_path))
    except DeploymentError:
        show_failure_details(cli, build)
        print('Recover the retained CloudFormation state with: ' + shlex.join([
            'python3', str(ROOT / 'scripts/launch_customer_connector.py'),
            '--recover', str(path)]), flush=True)
        raise DeploymentError('No final connector report was recovered; collect or explicitly recover the saved operation.')
    result = decode_document(result_path.read_bytes())
    if (any(result.get(key) != record[key] for key in
            ('scope', 'account', 'build_id', 'source_sha256'))
            or not downloaded.get('VersionId')
            or downloaded['VersionId'] == 'null'):
        raise DeploymentError('Downloaded connector report belongs to another run')
    collected = dict(record, report_version_id=downloaded['VersionId'],
        build_status=build.get('buildStatus'), collection_result='COLLECTED')
    try:
        validate_collected_launch(collected, result, SCOPE)
        validate_connector_result(result, record['account'], record['external_id'])
    except (ValueError, TypeError, KeyError, IndexError, AttributeError) as exc:
        print('Connector worker error: ' + json.dumps(result.get('error'), ensure_ascii=False), flush=True)
        show_failure_details(cli, build)
        raise DeploymentError(
            'Customer connector result is unsafe or incomplete; do not wire account A: '
            + str(exc)) from exc
    record.update(report_version_id=downloaded['VersionId'],
        build_status=build.get('buildStatus'), collection_result='COLLECTED')
    save(cli, path, record)
    summary = {key: result.get(key) for key in ('result', 'account', 'region',
        'connector_stack_id', 'connector_outputs', 'registration_hash',
        'adapter_registry_ref', 'business_publication', 'policy_write', 'live_canary')}
    print('READINESSOPS_CUSTOMER_CONNECTOR_RESULT', flush=True)
    print(json.dumps(summary, ensure_ascii=False, indent=2), flush=True)
    print('Full report: ' + str(result_path), flush=True)
    print(f"Evidence: s3://{record['bucket']}/{record['report_key']} (version {downloaded['VersionId']})", flush=True)
    return 0


def launch(cli, resume=None, recover=None, *, delay=time.sleep):
    account = guard(cli)
    bootstrap = stack_outputs(cli, 'authority-delta-bootstrap')
    bucket, project = bootstrap['ArtifactBucketName'], bootstrap['BuildProjectName']
    # These readbacks happen before any source upload or build start.
    stack_outputs(cli, 'authority-delta-customer-baseline')
    stack_outputs(cli, 'authority-delta-vendor-runtimes')
    path = Path(resume or recover).resolve() if (resume or recover) else ROOT.parent / 'customer-connector-latest-launch.json'
    if resume:
        record = json.loads(path.read_text(encoding='utf-8'))
        validate(record, account, bucket, project)
        return collect(cli, record, path, delay)
    if recover:
        previous = json.loads(path.read_text(encoding='utf-8'))
        validate(previous, account, bucket, project)
        builds = cli.run('codebuild', 'batch-get-builds', '--ids',
                         previous['build_id']).get('builds', [])
        if (len(builds) != 1 or builds[0].get('id') != previous['build_id']
                or builds[0].get('buildStatus') == 'IN_PROGRESS'):
            raise DeploymentError('The previous connector build is missing or still active; recovery did not start.')
        run_id = uuid.uuid4().hex
        record = dict(previous, run_id=run_id, build_id=None,
            report_key=f'evidence/{run_id}/customer-connector-result.json',
            recovered_from_build_id=previous['build_id'],
            collection_result='RECOVERY_STARTING')
        for name in ('report_version_id', 'build_status'):
            record.pop(name, None)
        validate(record, account, bucket, project)
        save(cli, path, record)
        variables = [{'name': name, 'value': value, 'type': 'PLAINTEXT'} for name, value in (
            ('AD_REPORT_KEY', record['report_key']),
            ('AD_SOURCE_SHA256', record['source_sha256']),
            ('AD_SOURCE_APPLICATION_WORKER_ROLE_ARN', SOURCE_ROLE),
            ('AD_EXTERNAL_ID', record['external_id']))]
        try:
            started = cli.run('codebuild', 'start-build', '--project-name', project,
                '--source-location-override', bucket + '/' + record['source_key'],
                '--source-version', record['source_version'], '--buildspec-override',
                'buildspec.customer-connector.yml', '--timeout-in-minutes-override', '25',
                '--environment-variables-override', json.dumps(variables),
                '--idempotency-token', run_id)
            record['build_id'] = started['build']['id']
            save(cli, path, record)
        except (DeploymentError, KeyError):
            reconcile(cli, record, path)
        return collect(cli, record, path, delay)
    if not path.exists():
        try:
            cli.run('s3api', 'get-object', '--bucket', bucket, '--key',
                    LATEST_KEY, str(path))
        except DeploymentError as exc:
            if not any(code in str(exc) for code in ('NoSuchKey', 'NotFound', '(404)')):
                raise
            path.unlink(missing_ok=True)
    previous = None
    if path.exists():
        record = json.loads(path.read_text(encoding='utf-8'))
        validate(record, account, bucket, project)
        if record.get('bundle_version') == BUNDLE_VERSION:
            return collect(cli, record, path, delay)
        builds = cli.run('codebuild', 'batch-get-builds', '--ids', record['build_id']).get('builds', [])
        if len(builds) != 1 or builds[0].get('id') != record['build_id']:
            raise DeploymentError('Previous connector build is not confirmed; no source upgrade started.')
        prior_status = builds[0].get('buildStatus')
        if prior_status == 'SUCCEEDED':
            if (record.get('collection_result') != 'COLLECTED'
                    or not record.get('report_version_id')):
                raise DeploymentError('Previous successful connector evidence was not collected; no source upgrade started.')
        elif prior_status not in ('FAILED', 'FAULT', 'STOPPED', 'TIMED_OUT'):
            raise DeploymentError('Previous connector build is not terminal; no source upgrade started.')
        previous = record
    if any(item.get('buildStatus') == 'IN_PROGRESS' for item in recent(cli, project)):
        raise DeploymentError('Another deployment build is active. No duplicate operation started.')
    run_id, external_id = uuid.uuid4().hex, uuid.uuid4().hex
    if previous:
        external_id = previous['external_id']
    with tempfile.TemporaryDirectory(prefix='authority-delta-customer-source-') as directory:
        archive = Path(directory) / 'source.zip'
        digest = source_archive(archive)
        key = 'source/' + digest + '.zip'
        uploaded = cli.run('s3api', 'put-object', '--bucket', bucket, '--key', key,
            '--body', str(archive), '--metadata', 'sha256=' + digest)
    version = uploaded.get('VersionId')
    if not version or version == 'null':
        raise DeploymentError('Connector source upload is not versioned')
    record = {'schema_version': '1.0', 'scope': SCOPE,
        'bundle_version': BUNDLE_VERSION, 'account': account, 'region': REGION,
        'project': project, 'bucket': bucket, 'source_sha256': digest,
        'source_key': key, 'source_version': version, 'run_id': run_id,
        'report_key': f'evidence/{run_id}/customer-connector-result.json',
        'build_id': None, 'external_id': external_id,
        'external_id_hash': hashlib.sha256(external_id.encode()).hexdigest(),
        'source_application_worker_role_arn': SOURCE_ROLE}
    if previous:
        record['recovered_from_build_id'] = previous['build_id']
    validate(record, account, bucket, project)
    save(cli, path, record)
    variables = [{'name': name, 'value': value, 'type': 'PLAINTEXT'} for name, value in (
        ('AD_REPORT_KEY', record['report_key']), ('AD_SOURCE_SHA256', digest),
        ('AD_SOURCE_APPLICATION_WORKER_ROLE_ARN', SOURCE_ROLE),
        ('AD_EXTERNAL_ID', external_id))]
    try:
        started = cli.run('codebuild', 'start-build', '--project-name', project,
            '--source-location-override', bucket + '/' + key,
            '--source-version', version, '--buildspec-override',
            'buildspec.customer-connector.yml', '--timeout-in-minutes-override', '25',
            '--environment-variables-override', json.dumps(variables),
            '--idempotency-token', run_id)
        record['build_id'] = started['build']['id']
        save(cli, path, record)
    except (DeploymentError, KeyError):
        reconcile(cli, record, path)
    return collect(cli, record, path, delay)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    action = parser.add_mutually_exclusive_group()
    action.add_argument('--resume')
    action.add_argument('--recover')
    args = parser.parse_args(argv)
    try:
        return launch(AwsCli(), args.resume, args.recover)
    except (DeploymentError, OSError, ValueError, KeyError, TypeError,
            KeyboardInterrupt, subprocess.TimeoutExpired) as exc:
        print('ERROR: ' + str(exc), flush=True)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
