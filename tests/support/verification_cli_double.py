#!/usr/bin/env python3
"""Offline process-boundary double. Never contacts AWS or represents AWS evidence."""
import hashlib
import json
import os
from pathlib import Path
import sys
import zipfile

args = sys.argv[1:]
state_dir = Path(os.environ['AD_TEST_STATE'])
mode = os.environ['AD_TEST_SCENARIO']
binding = json.loads((Path.cwd() / 'infra/environments/development.json').read_text())
action = args[:2]

def value(flag):
    return args[args.index(flag) + 1]

def emit(data):
    print(json.dumps(data))
    raise SystemExit(0)

def fail(message):
    print(message, file=sys.stderr)
    raise SystemExit(1)

assert value('--region') == 'ap-northeast-1'
assert value('--output') == 'json'
assert '--no-cli-pager' in args
with (state_dir / 'calls.jsonl').open('a') as f:
    f.write(json.dumps(action) + '\n')
if action == ['sts', 'get-caller-identity']:
    account = '111122223333' if mode == 'WRONG_ACCOUNT' else binding['account']
    emit({'Account': account, 'Arn': f'arn:aws:iam::{account}:root'})
if action == ['cloudformation', 'describe-stacks']:
    name = value('--stack-name')
    assert name in (binding['application_stack'], binding['bootstrap_stack'])
    values = binding['resources'] if name == binding['application_stack'] else {'ArtifactBucketName': binding['artifact_bucket'], 'BuildProjectName': binding['project']}
    emit({'Stacks': [{'StackStatus': 'CREATE_COMPLETE', 'Outputs': [{'OutputKey': k, 'OutputValue': v} for k, v in values.items()]}]})
if action == ['codebuild', 'list-builds-for-project']:
    emit({'ids': ['authority-delta-deploy:active']} if mode == 'ACTIVE_BUILD' else {'ids': []})
if action == ['codebuild', 'batch-get-builds']:
    build_id = value('--ids')
    status = 'IN_PROGRESS' if build_id.endswith(':active') else ('SUCCEEDED' if mode in ('PASS', 'BLOCKED') and build_id.endswith(':offline-test') else 'FAILED')
    emit({'builds': [{'id': build_id, 'projectName': binding['project'], 'currentPhase': 'BUILD' if status == 'IN_PROGRESS' else 'COMPLETED', 'buildStatus': status, 'logs': {'groupName': '/aws/codebuild/authority-delta-deploy', 'streamName': 'offline-only'}}]})
if action == ['logs', 'get-log-events']:
    emit({'events': [] if '--next-token' in args else [{'timestamp': 1, 'message': '[gateway] P-001: PASS\n'}], 'nextForwardToken': 'end'})
if action == ['s3api', 'put-object']:
    assert value('--bucket') == binding['artifact_bucket']
    archive = Path(value('--body'))
    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    assert value('--metadata') == f'sha256={digest}'
    assert value('--key') == f'source/{digest}.zip'
    with zipfile.ZipFile(archive) as z:
        names = set(z.namelist())
        assert {'scripts/verify_aws.py', 'src/authority_delta/evidence_json.py', 'buildspec.verify.yml', 'requirements-deploy.lock'} <= names
        assert any(n.startswith('vendor/wheels/') for n in names)
        assert not any(n.startswith(('evidence/', 'tests/')) for n in names)
    (state_dir / 'source.json').write_text(json.dumps({'hash': digest, 'key': value('--key')}))
    emit({'VersionId': 'offline-source-version'})
if action == ['codebuild', 'start-build']:
    source = json.loads((state_dir / 'source.json').read_text())
    assert value('--project-name') == binding['project']
    assert value('--source-location-override') == f"{binding['artifact_bucket']}/{source['key']}"
    assert value('--source-version') == 'offline-source-version'
    assert value('--buildspec-override') == 'buildspec.verify.yml'
    assert value('--timeout-in-minutes-override') == '10'
    variables = {x['name']: x['value'] for x in json.loads(value('--environment-variables-override'))}
    assert variables['AD_SOURCE_SHA256'] == source['hash']
    assert value('--idempotency-token') in variables['AD_REPORT_KEY']
    (state_dir / 'build.json').write_text(json.dumps(variables))
    emit({'build': {'id': 'authority-delta-deploy:offline-test'}})
if action == ['s3api', 'get-object']:
    variables = json.loads((state_dir / 'build.json').read_text())
    assert value('--bucket') == binding['artifact_bucket']
    key = value('--key')
    partial = key.endswith('-gateway.json')
    assert key == (variables['AD_REPORT_KEY'].removesuffix('.json') + '-gateway.json' if partial else variables['AD_REPORT_KEY'])
    if mode == 'FINAL_MISSING' and not partial:
        fail('NoSuchKey (injected offline failure)')
    report = {'scope': 'LIVE_BASELINE_VERIFICATION_NOT_FULL_GATE_A', 'build_id': 'authority-delta-deploy:offline-test', 'source_sha256': variables['AD_SOURCE_SHA256'], 'result': 'IN_PROGRESS' if partial else mode, 'gate_a': 'NOT_RUN', 'model_invocation': {'status': 'NOT_RUN' if partial else mode}, 'gateway_default_deny': {'status': 'PASS'}, '_offline_test': True}
    if partial:
        report['checkpoint_phase'] = 'gateway'
    # AwsCli places its flags after the positional output filename.
    destination = Path(args[args.index('--key') + 2])
    destination.write_text(json.dumps(report))
    emit({'VersionId': 'offline-report-version'})
fail('Unexpected operation in offline contract double: ' + ' '.join(action))
