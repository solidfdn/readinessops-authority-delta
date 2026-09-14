#!/usr/bin/env python3
"""Bootstrap, launch, resume or recover an account-B foundation deployment."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import shlex
import tempfile
import time
import uuid

ROOT = Path(__file__).resolve().parents[1]
import sys
sys.path.insert(0, str(ROOT / 'scripts'))

from launch_customer_connector import budget, budget_profile
from check_connected_acceptance_readiness import (decode_document,
    validate_collected_launch, validate_foundation_result)
from launch_deployment import (AwsCli, DeploymentError, source_archive,
    stack_outputs, show_failure_details)
from launch_gate_a import write_record


ACCOUNT_A = '538522204923'
REGION = 'ap-northeast-1'
SCOPE = 'ACCOUNT_B_CUSTOMER_FOUNDATION_NO_POLICY_CANARY_CONNECTOR_OR_BUSINESS_PUBLICATION'
BUNDLE_VERSION = '20260911-customer-foundation-v1'
BOOTSTRAP_STACK = 'authority-delta-bootstrap'
LATEST_KEY = 'customer-foundation-launch/latest.json'


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
            float(value.get('BudgetLimit', {}).get('Amount', -1))) !=
            ('COST', 'MONTHLY', 'USD', budget_profile(account)[1])):
        raise DeploymentError('Account B does not have its approved monthly USD budget.')
    observed = {(item['NotificationType'], float(item['Threshold']))
                for item in notifications.get('Notifications', [])}
    if observed != {('ACTUAL', 20.0), ('ACTUAL', 50.0), ('ACTUAL', 100.0),
                    ('FORECASTED', 80.0)}:
        raise DeploymentError('Account-B budget notification thresholds differ.')
    return account


def validate(record, account, bucket, project):
    expected = {'scope': SCOPE, 'account': account, 'region': REGION,
        'bucket': bucket, 'project': project}
    if not isinstance(record, dict) or any(record.get(k) != v for k, v in expected.items()):
        raise DeploymentError('Saved customer foundation launch binding differs')
    if (not re.fullmatch(r'evidence/[0-9a-f]{32}/customer-foundation-result\.json',
            record.get('report_key', ''))
            or not re.fullmatch(r'[0-9a-f]{64}', record.get('source_sha256', ''))
            or not record.get('source_version') or record['source_version'] == 'null'):
        raise DeploymentError('Saved customer foundation source or report binding is invalid')
    if record.get('build_id') and not re.fullmatch(
            re.escape(project) + r':[A-Za-z0-9_-]+', record['build_id']):
        raise DeploymentError('Saved customer foundation build identity is invalid')


def save(cli, path, record):
    write_record(path, record)
    cli.run('s3api', 'put-object', '--bucket', record['bucket'], '--key',
            LATEST_KEY, '--body', str(path))
    cli.run('s3api', 'put-object', '--bucket', record['bucket'], '--key',
            record['report_key'].replace('customer-foundation-result.json',
                                         'customer-foundation-launch.json'),
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
                and values.get('AD_SOURCE_SHA256') == record['source_sha256']):
            matches.append(build)
    if len(matches) != 1:
        raise DeploymentError('Foundation launch is not confirmed; rerun with the saved record. No duplicate build started.')
    record['build_id'] = matches[0]['id']
    save(cli, path, record)


def collect(cli, record, path, delay=time.sleep):
    if not record.get('build_id'):
        reconcile(cli, record, path)
    print('Build ID: ' + record['build_id'], flush=True)
    print('Resume this build: ' + shlex.join([
        'python3', str(ROOT / 'scripts/launch_customer_foundation.py'),
        '--resume', str(path)]), flush=True)
    last = None
    for _ in range(210):
        builds = cli.run('codebuild', 'batch-get-builds', '--ids',
                         record['build_id']).get('builds', [])
        if len(builds) != 1 or builds[0].get('id') != record['build_id']:
            raise DeploymentError('Foundation build identity is not confirmed')
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
    result_path = path.parent / 'customer-foundation-result.json'
    try:
        downloaded = cli.run('s3api', 'get-object', '--bucket', record['bucket'],
            '--key', record['report_key'], str(result_path))
    except DeploymentError:
        show_failure_details(cli, build)
        print('Recover the retained CloudFormation state with: ' + shlex.join([
            'python3', str(ROOT / 'scripts/launch_customer_foundation.py'),
            '--recover', str(path)]), flush=True)
        raise DeploymentError('No final foundation report was recovered; collect or explicitly recover the saved operation.')
    result = decode_document(result_path.read_bytes())
    if (any(result.get(key) != record[key] for key in
            ('scope', 'account', 'build_id', 'source_sha256'))
            or not downloaded.get('VersionId') or downloaded['VersionId'] == 'null'):
        raise DeploymentError('Downloaded foundation report belongs to another run')
    collected = dict(record, report_version_id=downloaded['VersionId'],
        build_status=build.get('buildStatus'), collection_result='COLLECTED')
    try:
        validate_collected_launch(collected, result, SCOPE)
        validate_foundation_result(result, record['account'])
    except (ValueError, TypeError, KeyError, IndexError, AttributeError) as exc:
        show_failure_details(cli, build)
        raise DeploymentError(
            'Customer foundation result is unsafe or incomplete; do not run the connector: '
            + str(exc)) from exc
    record.update(report_version_id=downloaded['VersionId'],
        build_status=build.get('buildStatus'), collection_result='COLLECTED')
    save(cli, path, record)
    summary = {key: result.get(key) for key in ('result', 'account', 'region',
        'bootstrap_stack_id', 'baseline_stack_id', 'runtime_stack_id',
        'request_registry', 'policy_count', 'ledger_count', 'connector',
        'policy_write', 'live_canary',
        'business_publication')}
    print('READINESSOPS_CUSTOMER_FOUNDATION_RESULT', flush=True)
    print(json.dumps(summary, ensure_ascii=False, indent=2), flush=True)
    print('Full report: ' + str(result_path), flush=True)
    return 0


def bootstrap(cli):
    cli.run('cloudformation', 'validate-template', '--template-body',
            'file://infra/bootstrap/template.json')
    cli.run('cloudformation', 'deploy', '--template-file',
        'infra/bootstrap/template.json', '--stack-name', BOOTSTRAP_STACK,
        '--capabilities', 'CAPABILITY_NAMED_IAM', '--no-fail-on-empty-changeset',
        '--tags', 'Project=ReadinessOpsAuthorityDelta',
        'Baseline=AD-BASELINE-1.0', json_output=False, stream=True)
    return stack_outputs(cli, BOOTSTRAP_STACK)


def variables(record):
    return [{'name': name, 'value': value, 'type': 'PLAINTEXT'} for name, value in (
        ('AD_REPORT_KEY', record['report_key']),
        ('AD_SOURCE_SHA256', record['source_sha256']))]


def launch(cli, resume=None, recover=None, *, delay=time.sleep):
    account = guard(cli)
    if resume or recover:
        outputs = stack_outputs(cli, BOOTSTRAP_STACK)
    else:
        outputs = bootstrap(cli)
    bucket, project = outputs['ArtifactBucketName'], outputs['BuildProjectName']
    path = Path(resume or recover).resolve() if (resume or recover) else (
        ROOT.parent / 'customer-foundation-latest-launch.json')
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
            raise DeploymentError('The previous foundation build is missing or still active; recovery did not start.')
        run_id = uuid.uuid4().hex
        record = dict(previous, run_id=run_id, build_id=None,
            report_key=f'evidence/{run_id}/customer-foundation-result.json',
            recovered_from_build_id=previous['build_id'],
            collection_result='RECOVERY_STARTING')
        for name in ('report_version_id', 'build_status'):
            record.pop(name, None)
        save(cli, path, record)
        try:
            started = cli.run('codebuild', 'start-build', '--project-name', project,
                '--source-location-override', bucket + '/' + record['source_key'],
                '--source-version', record['source_version'], '--buildspec-override',
                'buildspec.customer-foundation.yml', '--timeout-in-minutes-override', '25',
                '--environment-variables-override', json.dumps(variables(record)),
                '--idempotency-token', run_id)
            record['build_id'] = started['build']['id']
            save(cli, path, record)
        except (DeploymentError, KeyError):
            reconcile(cli, record, path)
        return collect(cli, record, path, delay)
    if path.exists():
        existing = json.loads(path.read_text(encoding='utf-8'))
        validate(existing, account, bucket, project)
        if existing.get('bundle_version') == BUNDLE_VERSION:
            return collect(cli, existing, path, delay)
    if any(item.get('buildStatus') == 'IN_PROGRESS' for item in recent(cli, project)):
        raise DeploymentError('Another deployment build is active. No duplicate operation started.')
    run_id = uuid.uuid4().hex
    with tempfile.TemporaryDirectory(prefix='authority-delta-customer-foundation-') as directory:
        archive = Path(directory) / 'source.zip'
        digest = source_archive(archive)
        key = 'source/' + digest + '.zip'
        uploaded = cli.run('s3api', 'put-object', '--bucket', bucket, '--key', key,
            '--body', str(archive), '--metadata', 'sha256=' + digest)
    version = uploaded.get('VersionId')
    if not version or version == 'null':
        raise DeploymentError('Foundation source upload is not versioned')
    record = {'schema_version': '1.0', 'scope': SCOPE,
        'bundle_version': BUNDLE_VERSION, 'account': account, 'region': REGION,
        'project': project, 'bucket': bucket, 'source_sha256': digest,
        'source_key': key, 'source_version': version, 'run_id': run_id,
        'report_key': f'evidence/{run_id}/customer-foundation-result.json',
        'build_id': None}
    validate(record, account, bucket, project)
    save(cli, path, record)
    try:
        started = cli.run('codebuild', 'start-build', '--project-name', project,
            '--source-location-override', bucket + '/' + key,
            '--source-version', version, '--buildspec-override',
            'buildspec.customer-foundation.yml', '--timeout-in-minutes-override', '25',
            '--environment-variables-override', json.dumps(variables(record)),
            '--idempotency-token', run_id)
        record['build_id'] = started['build']['id']
        save(cli, path, record)
    except (DeploymentError, KeyError):
        reconcile(cli, record, path)
    return collect(cli, record, path, delay)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    choice = parser.add_mutually_exclusive_group()
    choice.add_argument('--resume', metavar='LAUNCH_RECORD')
    choice.add_argument('--recover', metavar='LAUNCH_RECORD')
    args = parser.parse_args(argv)
    try:
        return launch(AwsCli(), resume=args.resume, recover=args.recover)
    except (DeploymentError, OSError, KeyError, ValueError, TypeError) as exc:
        print('ERROR: ' + str(exc), flush=True)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
