#!/usr/bin/env python3
"""Launch or recover account-A deployment from one account-B connector report."""
from __future__ import annotations

import argparse
import hashlib
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

from check_connected_acceptance_readiness import (decode_document,
    WIRING_SCOPE as SCOPE, validate_collected_launch, validate_connector_binding,
    validate_wiring_result)
from launch_deployment import (AwsCli, DeploymentError, source_archive,
    stack_outputs, show_failure_details)
from launch_gate_a import write_record


REGION = 'ap-northeast-1'
BUNDLE_VERSION = '20260914-customer-wiring-v19-policy-create-discovery-recovery'
LATEST_KEY = 'customer-wiring-launch/latest.json'


def binding():
    return json.loads((ROOT / 'infra/environments/development.json').read_text())


def validate(record, expected):
    fixed = {'scope': SCOPE, 'account': expected['account'],
        'region': expected['region'], 'bucket': expected['artifact_bucket'],
        'project': expected['project']}
    if not isinstance(record, dict) or any(record.get(k) != v for k, v in fixed.items()):
        raise DeploymentError('Saved customer wiring launch binding differs')
    patterns = [('report_key', r'evidence/[0-9a-f]{32}/customer-wiring-result\.json'),
        ('source_sha256', r'[0-9a-f]{64}'),
        ('connector_report_sha256', r'[0-9a-f]{64}'),
        ('target_account_id', r'[0-9]{12}')]
    if any(not re.fullmatch(pattern, record.get(name, '')) for name, pattern in patterns):
        raise DeploymentError('Saved customer wiring source, report or account binding is invalid')
    if record['target_account_id'] == expected['account']:
        raise DeploymentError('Customer wiring cannot target account A')
    recovery = record.get('recovery_application_id')
    if recovery is not None and not re.fullmatch(r'application-[0-9a-f]{32}', recovery):
        raise DeploymentError('Saved recovery application identity is invalid')
    for name in ('source_version', 'connector_report_version',
                 'connector_report_key', 'registration_hash'):
        if not record.get(name) or record[name] == 'null':
            raise DeploymentError('Saved customer wiring immutable binding is incomplete')
    if record.get('build_id') and not re.fullmatch(
            re.escape(expected['project']) + r':[A-Za-z0-9_-]+', record['build_id']):
        raise DeploymentError('Saved customer wiring build identity is invalid')


def save(cli, path, record):
    write_record(path, record)
    cli.run('s3api', 'put-object', '--bucket', record['bucket'], '--key',
            LATEST_KEY, '--body', str(path))
    cli.run('s3api', 'put-object', '--bucket', record['bucket'], '--key',
            record['report_key'].replace('customer-wiring-result.json',
                                         'customer-wiring-launch.json'),
            '--body', str(path))


def recent(cli, project):
    ids = cli.run('codebuild', 'list-builds-for-project', '--project-name', project,
        '--sort-order', 'DESCENDING', '--max-items', '50').get('ids', [])
    return cli.run('codebuild', 'batch-get-builds', '--ids', *ids).get('builds', []) if ids else []


def environment(record):
    return [{'name': name, 'value': value, 'type': 'PLAINTEXT'} for name, value in (
        ('AD_REPORT_KEY', record['report_key']),
        ('AD_SOURCE_SHA256', record['source_sha256']),
        ('AD_CONNECTOR_REPORT_KEY', record['connector_report_key']),
        ('AD_CONNECTOR_REPORT_VERSION', record['connector_report_version']),
        ('AD_CONNECTOR_REPORT_SHA256', record['connector_report_sha256']),
        ('AD_RECOVERY_APPLICATION_ID', record.get('recovery_application_id') or ''))]


def reconcile(cli, record, path):
    matches = []
    for build in recent(cli, record['project']):
        values = {item['name']: item['value'] for item in
                  build.get('environment', {}).get('environmentVariables', [])}
        if all(values.get(name) == value for name, value in (
                ('AD_REPORT_KEY', record['report_key']),
                ('AD_SOURCE_SHA256', record['source_sha256']),
                ('AD_CONNECTOR_REPORT_SHA256', record['connector_report_sha256']),
                ('AD_RECOVERY_APPLICATION_ID',
                 record.get('recovery_application_id') or ''))):
            matches.append(build)
    if len(matches) != 1:
        raise DeploymentError('Customer wiring launch is not confirmed; no duplicate build started.')
    record['build_id'] = matches[0]['id']
    save(cli, path, record)


def collect(cli, record, path, delay=time.sleep):
    if not record.get('build_id'):
        reconcile(cli, record, path)
    print('Build ID: ' + record['build_id'], flush=True)
    print('Resume this build: ' + shlex.join([
        'python3', str(ROOT / 'scripts/launch_customer_wiring.py'),
        '--resume', str(path)]), flush=True)
    last = None
    for _ in range(210):
        builds = cli.run('codebuild', 'batch-get-builds', '--ids',
                         record['build_id']).get('builds', [])
        if len(builds) != 1 or builds[0].get('id') != record['build_id']:
            raise DeploymentError('Customer wiring build identity is not confirmed')
        build = builds[0]
        state = (build.get('currentPhase'), build.get('buildStatus'))
        if state != last:
            print('CodeBuild: ' + str(state[0]) + ' / ' + str(state[1]), flush=True)
            last = state
        if state[1] != 'IN_PROGRESS':
            break
        delay(10)
    else:
        raise DeploymentError('Collection timed out; resume the same customer wiring record.')
    result_path = path.parent / 'customer-wiring-result.json'
    try:
        downloaded = cli.run('s3api', 'get-object', '--bucket', record['bucket'],
            '--key', record['report_key'], str(result_path))
    except DeploymentError:
        show_failure_details(cli, build)
        print('Recover the same source and connector report with: ' + shlex.join([
            'python3', str(ROOT / 'scripts/launch_customer_wiring.py'),
            '--recover', str(path)]), flush=True)
        raise DeploymentError('No final customer wiring report was recovered.')
    result = decode_document(result_path.read_bytes())
    customer_wiring = result.get('customer_wiring')
    if (any(result.get(key) != record[key] for key in
            ('scope', 'account', 'build_id', 'source_sha256'))
            or (customer_wiring is not None and (not isinstance(customer_wiring, dict)
                or customer_wiring.get('target_account_id') != record['target_account_id']))
            or not downloaded.get('VersionId') or downloaded['VersionId'] == 'null'):
        raise DeploymentError('Downloaded customer wiring report belongs to another operation')
    collected = dict(record, report_version_id=downloaded['VersionId'],
        build_status=build.get('buildStatus'), collection_result='COLLECTED')
    try:
        validate_collected_launch(collected, result, SCOPE)
        validate_wiring_result(result, collected)
    except (ValueError, TypeError, KeyError, IndexError, AttributeError) as exc:
        show_failure_details(cli, build)
        print('READINESSOPS_WIRING_FAILURE_DETAILS', flush=True)
        print(json.dumps({key:result.get(key) for key in
            ('build_id','result','phase','error','state_unchanged','state_error','assessment_diagnostics')},
            ensure_ascii=False, indent=2), flush=True)
        print('Full report: ' + str(result_path), flush=True)
        raise DeploymentError(
            'Customer wiring result is unsafe or incomplete; do not begin live acceptance: '
            + str(exc)) from exc
    record.update(report_version_id=downloaded['VersionId'],
        build_status=build.get('buildStatus'), collection_result='COLLECTED')
    save(cli, path, record)
    summary = {key: result.get(key) for key in ('result', 'customer_registry',
        'business_assessment_canary', 'human_workflow', 'policy_write',
        'live_customer_canary', 'state_unchanged')}
    summary.update(policy_count=customer_wiring['verification']['policy_count'],
                   ledger_count=customer_wiring['verification']['ledger_count'])
    print('READINESSOPS_CUSTOMER_WIRING_RESULT', flush=True)
    print(json.dumps(summary, ensure_ascii=False, indent=2), flush=True)
    print('Full report: ' + str(result_path), flush=True)
    return 0


def start(cli, record, run_id):
    try:
        started = cli.run('codebuild', 'start-build', '--project-name',
            record['project'], '--source-location-override',
            record['bucket'] + '/' + record['source_key'], '--source-version',
            record['source_version'], '--buildspec-override',
            'buildspec.customer-wiring.yml', '--timeout-in-minutes-override', '25',
            '--environment-variables-override', json.dumps(environment(record)),
            '--idempotency-token', run_id)
        record['build_id'] = started['build']['id']
    except (DeploymentError, KeyError):
        return False
    return True


def launch(cli, connector_report=None, resume=None, recover=None,
           recovery_application_id=None, *, delay=time.sleep):
    expected = binding()
    if cli.run('sts', 'get-caller-identity').get('Account') != expected['account']:
        raise DeploymentError('Run customer wiring only in account A. No operation started.')
    bootstrap = stack_outputs(cli, expected['bootstrap_stack'])
    baseline = stack_outputs(cli, expected['application_stack'])
    if (bootstrap.get('ArtifactBucketName') != expected['artifact_bucket']
            or bootstrap.get('BuildProjectName') != expected['project']
            or any(baseline.get(key) != value
                   for key, value in expected['resources'].items())):
        raise DeploymentError('Account-A deployment or protected baseline binding differs')
    path = Path(resume or recover).resolve() if (resume or recover) else (
        ROOT.parent / 'customer-wiring-latest-launch.json')
    if resume:
        record = json.loads(path.read_text())
        validate(record, expected)
        return collect(cli, record, path, delay)
    if recover:
        previous = json.loads(path.read_text())
        validate(previous, expected)
        builds = cli.run('codebuild', 'batch-get-builds', '--ids',
                         previous['build_id']).get('builds', [])
        if (len(builds) != 1 or builds[0].get('id') != previous['build_id']
                or builds[0].get('buildStatus') == 'IN_PROGRESS'):
            raise DeploymentError('Previous customer wiring build is missing or active')
        run_id = uuid.uuid4().hex
        record = dict(previous, run_id=run_id, build_id=None,
            report_key=f'evidence/{run_id}/customer-wiring-result.json',
            recovered_from_build_id=previous['build_id'])
        for name in ('report_version_id', 'build_status', 'collection_result'):
            record.pop(name, None)
        save(cli, path, record)
        if not start(cli, record, run_id):
            reconcile(cli, record, path)
        else:
            save(cli, path, record)
        return collect(cli, record, path, delay)
    if connector_report is None:
        raise DeploymentError('A connector report is required for a new wiring operation')
    if (recovery_application_id is not None
            and not re.fullmatch(r'application-[0-9a-f]{32}',
                                 recovery_application_id)):
        raise DeploymentError('Recovery application ID is invalid')
    if any(item.get('buildStatus') == 'IN_PROGRESS'
           for item in recent(cli, expected['project'])):
        raise DeploymentError('Another deployment build is active. No operation started.')
    raw = Path(connector_report).resolve().read_bytes()
    if len(raw) > 2_000_000:
        raise DeploymentError('Connector report exceeds the bounded size')
    try:
        report = decode_document(raw)
        validate_connector_binding(report)
    except (ValueError, TypeError, json.JSONDecodeError) as exc:
        raise DeploymentError('Connector report validation failed: ' + str(exc)) from exc
    digest = hashlib.sha256(raw).hexdigest()
    bucket = expected['artifact_bucket']
    connector_key = f'customer-wiring-input/{digest}/customer-connector-result.json'
    run_id = uuid.uuid4().hex
    with tempfile.TemporaryDirectory(prefix='readinessops-customer-wiring-') as directory:
        archive = Path(directory) / 'source.zip'
        source_digest = source_archive(archive)
        if path.exists():
            previous = decode_document(path.read_bytes())
            validate(previous, expected)
            if (previous['source_sha256'] == source_digest
                    and previous['connector_report_sha256'] == digest
                    and previous.get('recovery_application_id')
                        == recovery_application_id):
                print('Collecting the saved operation for this unchanged source and connector report.', flush=True)
                return collect(cli, previous, path, delay)
        uploaded_report = cli.run('s3api', 'put-object', '--bucket', bucket,
            '--key', connector_key, '--body', str(Path(connector_report).resolve()),
            '--metadata', 'sha256=' + digest)
        connector_version = uploaded_report.get('VersionId')
        if not connector_version or connector_version == 'null':
            raise DeploymentError('Connector report upload is not versioned')
        source_key = 'source/' + source_digest + '.zip'
        uploaded = cli.run('s3api', 'put-object', '--bucket', bucket,
            '--key', source_key, '--body', str(archive),
            '--metadata', 'sha256=' + source_digest)
    source_version = uploaded.get('VersionId')
    if not source_version or source_version == 'null':
        raise DeploymentError('Customer wiring source upload is not versioned')
    record = {'schema_version': '1.0', 'scope': SCOPE,
        'bundle_version': BUNDLE_VERSION, 'account': expected['account'],
        'region': REGION, 'project': expected['project'], 'bucket': bucket,
        'source_sha256': source_digest, 'source_key': source_key,
        'source_version': source_version, 'run_id': run_id,
        'report_key': f'evidence/{run_id}/customer-wiring-result.json',
        'build_id': None, 'connector_report_key': connector_key,
        'connector_report_version': connector_version,
        'connector_report_sha256': digest,
        'target_account_id': report['account'],
        'registration_hash': report['registration_hash']}
    record['recovery_application_id'] = recovery_application_id
    validate(record, expected)
    save(cli, path, record)
    if not start(cli, record, run_id):
        reconcile(cli, record, path)
    else:
        save(cli, path, record)
    return collect(cli, record, path, delay)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    choice = parser.add_mutually_exclusive_group(required=True)
    choice.add_argument('--connector-report')
    choice.add_argument('--resume')
    choice.add_argument('--recover')
    parser.add_argument('--recovery-application-id')
    args = parser.parse_args(argv)
    try:
        return launch(AwsCli(), connector_report=args.connector_report,
            resume=args.resume, recover=args.recover,
            recovery_application_id=args.recovery_application_id)
    except (DeploymentError, OSError, KeyError, ValueError, TypeError) as exc:
        print('ERROR: ' + str(exc), flush=True)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
