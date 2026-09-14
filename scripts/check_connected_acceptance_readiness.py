#!/usr/bin/env python3
"""Fail-closed offline check of the collected connected-path reports.

This checker performs no AWS operation and grants no runtime authority.  It only
binds the collected account-B foundation and connector reports to the account-A
wiring report so that a human acceptance run cannot start from mixed or unsafe
evidence.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / 'src'), str(ROOT / 'scripts')]

ACCOUNT_A = '538522204923'
REGION = 'ap-northeast-1'
SOURCE_APPLICATION_WORKER_ROLE = (
    f'arn:aws:iam::{ACCOUNT_A}:role/authority-delta-application-worker')
FOUNDATION_SCOPE = (
    'ACCOUNT_B_CUSTOMER_FOUNDATION_NO_POLICY_CANARY_CONNECTOR_OR_BUSINESS_PUBLICATION')
CONNECTOR_SCOPE = 'ACCOUNT_B_CUSTOMER_CONNECTOR_DEPLOYMENT_NO_BUSINESS_PUBLICATION'
WIRING_SCOPE = (
    'ACCOUNT_A_VERIFIED_CUSTOMER_REGISTRY_AND_BUSINESS_DEPLOYMENT_NO_HUMAN_APPROVAL_OR_POLICY_WRITE')
CHECK_SCOPE = 'OFFLINE_CONNECTED_ACCEPTANCE_REPORT_CHAIN_NO_LIVE_ACTION'
MAX_DOCUMENT_BYTES = 2_000_000


def require(condition, message):
    if not condition:
        raise ValueError(message)


def _reject_constant(value):
    raise ValueError('Non-finite JSON number is not permitted: ' + value)


def _object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError('Duplicate JSON member is not permitted: ' + key)
        value[key] = item
    return value


def decode_document(raw):
    require(len(raw) <= MAX_DOCUMENT_BYTES, 'Evidence document exceeds the bounded size')
    value = json.loads(raw, object_pairs_hook=_object, parse_constant=_reject_constant)
    require(isinstance(value, dict), 'Evidence document must be a JSON object')
    return value


def load_document(path):
    with Path(path).open('rb') as stream:
        raw = stream.read(MAX_DOCUMENT_BYTES + 1)
    return decode_document(raw)


def read_document(path):
    with Path(path).open('rb') as stream:
        raw = stream.read(MAX_DOCUMENT_BYTES + 1)
    require(len(raw) <= MAX_DOCUMENT_BYTES,
            'Evidence document exceeds the bounded size')
    return raw


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def _sha256(value):
    return isinstance(value, str) and re.fullmatch(r'[0-9a-f]{64}', value) is not None


def _version(value):
    return isinstance(value, str) and bool(value) and value != 'null'


def _artifact(value):
    return (isinstance(value, dict)
            and all(value.get(name) for name in ('bucket', 'key', 'version_id'))
            and _sha256(value.get('sha256'))
            and isinstance(value.get('size_bytes'), int)
            and value['size_bytes'] > 0)


def _caller(value, account):
    return (isinstance(value, str)
            and re.fullmatch(rf'arn:aws:(?:iam|sts)::{account}:.+', value) is not None)


def validate_collected_launch(launch, report, expected_scope):
    """Verify that one downloaded report is bound to one completed launch."""
    require(isinstance(launch, dict), 'Launch record must be an object')
    required = {'schema_version', 'scope', 'account', 'region', 'bucket', 'project',
        'source_sha256', 'source_key', 'source_version', 'report_key', 'build_id',
        'report_version_id', 'build_status', 'collection_result'}
    require(required.issubset(launch), 'Collected launch record is incomplete')
    require(launch['scope'] == expected_scope, 'Launch scope differs')
    require(launch['region'] == REGION, 'Launch region differs')
    require(re.fullmatch(r'[0-9]{12}', str(launch['account'])) is not None,
            'Launch account is invalid')
    require(_sha256(launch['source_sha256']), 'Launch source digest is invalid')
    require(launch['source_key'] == 'source/' + launch['source_sha256'] + '.zip',
            'Launch source key is not content-addressed')
    require(_version(launch['source_version']), 'Launch source version is missing')
    require(_version(launch['report_version_id']), 'Collected report version is missing')
    require(launch['build_status'] == 'SUCCEEDED', 'Collected build did not succeed')
    require(launch['collection_result'] == 'COLLECTED',
            'Launch record has not collected a validated report')
    require(isinstance(launch['bucket'], str) and bool(launch['bucket'])
            and isinstance(launch['project'], str) and bool(launch['project'])
            and re.fullmatch(re.escape(launch['project']) + r':[A-Za-z0-9_-]+',
                             str(launch['build_id'])) is not None,
            'Collected launch storage or build identity is invalid')
    expected = {'scope': launch['scope'], 'account': launch['account'],
        'region': launch['region'], 'build_id': launch['build_id'],
        'source_sha256': launch['source_sha256']}
    require(all(report.get(key) == value for key, value in expected.items()),
            'Report identity differs from its collected launch')
    return launch


def validate_foundation_result(report, expected_account=None):
    required = {'schema_version', 'scope', 'result', 'account', 'region', 'caller_arn',
        'bootstrap_stack_id', 'baseline_stack_id', 'runtime_stack_id',
        'baseline_artifact', 'runtime_artifacts', 'request_registry', 'observed',
        'policy_count', 'ledger_count', 'connector', 'policy_write', 'live_canary',
        'business_publication'}
    require(isinstance(report, dict) and required.issubset(report),
            'Foundation report is incomplete')
    require(report['scope'] == FOUNDATION_SCOPE and report['result'] == 'PASS',
            'Foundation report is not PASS for the fixed scope')
    account = report['account']
    require(re.fullmatch(r'[0-9]{12}', str(account)) is not None and account != ACCOUNT_A,
            'Foundation report does not identify a distinct account B')
    require(expected_account is None or account == expected_account,
            'Foundation account differs from the launch')
    require(report['region'] == REGION, 'Foundation region differs')
    require(_caller(report['caller_arn'], account),
            'Foundation caller does not belong to account B')
    require(report['policy_count'] == 0 and report['ledger_count'] == 0,
            'Foundation Policy Engine or ledger is not empty')
    require(all(report.get(name) == 'NOT_RUN' for name in
                ('connector', 'policy_write', 'live_canary', 'business_publication')),
            'Foundation report claims a prohibited side effect')
    require(all(isinstance(report.get(name), dict) and report[name] for name in
                ('runtime_artifacts', 'request_registry', 'observed'))
            and _artifact(report['baseline_artifact'])
            and {'V1', 'V2'} <= set(report['runtime_artifacts'])
            and all(_artifact(report['runtime_artifacts'][name])
                    for name in ('V1', 'V2')),
            'Foundation artifact or observation evidence is missing')
    registry = report['request_registry']
    observed = report['observed']
    require(registry.get('count') == 7
            and _sha256(registry.get('hash'))
            and isinstance(registry.get('seeded'), bool),
            'Foundation request registry evidence is invalid')
    required_observed = {'connection_id', 'target_id', 'target_name',
        'registry_hash', 'ledger_hash', 'runtimes'}
    require(required_observed.issubset(observed)
            and observed['registry_hash'] == registry['hash']
            and _sha256(observed['ledger_hash'])
            and isinstance(observed['runtimes'], dict),
            'Foundation observed state is incomplete or inconsistent')
    for name in ('V2RuntimeId', 'V2RuntimeArn', 'V2RuntimeVersion',
                 'V2EndpointName', 'V2EndpointArn', 'V2ExecutionRoleArn'):
        require(bool(observed['runtimes'].get(name)),
                'Foundation V2 Runtime binding is incomplete')
    return observed


def validate_connector_result(report, expected_account=None, expected_external_id=None):
    required = {'schema_version', 'scope', 'result', 'account', 'region', 'caller_arn',
        'baseline_readback', 'runtime_policy', 'connector_stack_id',
        'connector_outputs', 'observed_binding', 'artifact', 'registration_hash',
        'adapter_registry_ref', 'business_publication', 'policy_write', 'live_canary'}
    require(isinstance(report, dict) and required.issubset(report),
            'Connector report is incomplete')
    binding = validate_connector_binding(report)
    require(expected_account is None or report['account'] == expected_account,
            'Connector account differs from the launch')
    require(_caller(report['caller_arn'], report['account']),
            'Connector caller does not belong to account B')
    require(expected_external_id is None or binding.get('external_id') == expected_external_id,
            'Connector ExternalId differs from the launch binding')
    readback = report['baseline_readback']
    names = ('connection_id', 'target_id', 'target_name', 'registry_hash', 'ledger_hash')
    require(isinstance(readback, dict) and all(name in readback for name in names)
            and isinstance(readback.get('api_evidence'), dict),
            'Connector baseline readback is incomplete')
    require(all(readback[name] == binding[name] for name in
                ('connection_id', 'target_id', 'target_name')),
            'Connector baseline readback differs from its observed binding')
    require(_sha256(readback['registry_hash']) and _sha256(readback['ledger_hash']),
            'Connector state hashes are invalid')
    require(isinstance(report['runtime_policy'], dict) and report['runtime_policy']
            and _artifact(report['artifact']),
            'Connector runtime policy or artifact evidence is missing')
    reference = report['adapter_registry_ref']
    require(isinstance(reference, dict)
            and all(reference.get(name) for name in ('bucket', 'key', 'version_id'))
            and _sha256(reference.get('sha256'))
            and isinstance(reference.get('size'), int) and reference['size'] > 0,
            'Connector adapter registry reference is invalid')
    return binding


def validate_connector_binding(report):
    """Validate transport identity without importing worker-only dependencies."""
    required = {'scope', 'result', 'account', 'region', 'connector_stack_id',
        'connector_outputs', 'observed_binding', 'registration_hash',
        'business_publication', 'policy_write', 'live_canary'}
    require(isinstance(report, dict) and required.issubset(report)
            and report['scope'] == CONNECTOR_SCOPE and report['result'] == 'PASS'
            and re.fullmatch(r'[0-9]{12}', str(report['account'])) is not None
            and report['account'] != ACCOUNT_A and report['region'] == REGION
            and all(report.get(name) == 'NOT_RUN' for name in
                    ('business_publication', 'policy_write', 'live_canary')),
            'Connector report is not a successful distinct account-B result')
    account = report['account']
    stack = report['connector_stack_id']
    require(re.fullmatch(
        rf'arn:aws:cloudformation:{REGION}:{account}:'
        r'stack/authority-delta-customer-publisher/[A-Za-z0-9-]+', str(stack))
        is not None, 'Connector stack authority differs')
    binding = report['observed_binding']
    fields = {'schema_version', 'source_authority', 'connection_id',
        'target_account_id', 'target_region', 'gateway_arn', 'gateway_id',
        'policy_engine_id', 'target_id', 'target_name', 'runtime',
        'discovery_role_arn', 'publisher_invoke_role_arn', 'external_id',
        'publisher_function_arn', 'runtime_invoke_role_arn',
        'invocation_function_arn', 'canary_function_arn',
        'request_registry_table_name', 'sandbox_ledger_table_name'}
    require(isinstance(binding, dict) and set(binding) == fields
            and binding['schema_version'] == '1.0'
            and binding['source_authority'] == 'aws:customer-connector:' + stack
            and binding['target_account_id'] == account
            and binding['target_region'] == REGION
            and re.fullmatch(r'[A-Za-z0-9+=,.@:/_-]{32,128}',
                             str(binding['external_id'])) is not None,
            'Connector observed binding identity differs')
    outputs = report['connector_outputs']
    expected_outputs = {
        'DiscoveryRoleArn': binding['discovery_role_arn'],
        'PublisherInvokeRoleArn': binding['publisher_invoke_role_arn'],
        'PublisherFunctionArn': binding['publisher_function_arn'],
        'RuntimeInvokeRoleArn': binding['runtime_invoke_role_arn'],
        'InvocationFunctionArn': binding['invocation_function_arn'],
        'CanaryFunctionArn': binding['canary_function_arn']}
    require(isinstance(outputs, dict)
            and all(outputs.get(name) == value
                    for name, value in expected_outputs.items())
            and outputs.get('ExternalIdHash') ==
                hashlib.sha256(binding['external_id'].encode()).hexdigest(),
            'Connector outputs differ from the observed binding')
    require(_sha256(report['registration_hash']),
            'Connector registration identity is invalid')
    role_pattern = rf'arn:aws:iam::{account}:role/[A-Za-z0-9+=,.@_-]+'
    function_pattern = (
        rf'arn:aws:lambda:{REGION}:{account}:function:[A-Za-z0-9_-]+:[A-Za-z0-9_$-]+')
    require(all(re.fullmatch(role_pattern, binding[name]) is not None for name in
                ('discovery_role_arn', 'publisher_invoke_role_arn',
                 'runtime_invoke_role_arn'))
            and all(re.fullmatch(function_pattern, binding[name]) is not None for name in
                    ('publisher_function_arn', 'canary_function_arn',
                     'invocation_function_arn')),
            'Connector roles or qualified functions differ from account B')
    return binding


def validate_wiring_result(report, launch=None):
    required = {'schema_version', 'scope', 'result', 'account', 'region',
        'customer_wiring', 'customer_registry', 'business_assessment_canary',
        'human_workflow', 'policy_write', 'live_customer_canary',
        'approval_recorded', 'state_unchanged'}
    require(isinstance(report, dict) and required.issubset(report),
            'Customer wiring report is incomplete')
    require(report['scope'] == WIRING_SCOPE and report['result'] == 'PASS'
            and report['account'] == ACCOUNT_A and report['region'] == REGION,
            'Customer wiring report identity or result differs')
    require(report['customer_registry'] == 'VERIFIED_AND_DEPLOYED'
            and report['business_assessment_canary'] == 'PASS'
            and report['state_unchanged'] is True,
            'Customer wiring deployment or synthetic assessment did not pass safely')
    require(report['approval_recorded'] is False
            and all(report.get(name) == 'NOT_RUN' for name in
                    ('human_workflow', 'policy_write', 'live_customer_canary')),
            'Customer wiring report claims human approval or live authority')
    wiring = report['customer_wiring']
    require(isinstance(wiring, dict)
            and re.fullmatch(r'[0-9]{12}', str(wiring.get('target_account_id', '')))
            and wiring['target_account_id'] != ACCOUNT_A
            and _sha256(wiring.get('connector_report_sha256'))
            and _version(wiring.get('connector_report_version')),
            'Customer wiring connector binding is incomplete')
    verification = wiring.get('verification')
    recovery_id = launch.get('recovery_application_id') if launch else None
    recovery = verification.get('application_recovery') if isinstance(verification, dict) else None
    counts_valid = (isinstance(verification, dict)
                    and verification.get('policy_count') == 0
                    and verification.get('ledger_count') == 0)
    if recovery_id:
        counts_valid = (isinstance(recovery, dict)
            and recovery.get('application_id') == recovery_id
            and recovery.get('policy_count') == verification.get('policy_count')
            and recovery.get('ledger_count') == verification.get('ledger_count'))
    require(isinstance(verification, dict)
            and _sha256(verification.get('registration_hash'))
            and _sha256(verification.get('observed_registry_hash'))
            and _sha256(verification.get('observed_ledger_hash'))
            and counts_valid
            and bool(verification.get('connector_stack_id'))
            and isinstance(verification.get('functions'), dict)
            and set(verification['functions']) ==
                {'PublisherFunctionArn', 'CanaryFunctionArn',
                 'InvocationFunctionArn'},
            'Customer wiring live readback is incomplete')
    if launch is not None:
        require(wiring['target_account_id'] == launch.get('target_account_id')
                and wiring['connector_report_sha256'] ==
                    launch.get('connector_report_sha256')
                and wiring['connector_report_version'] ==
                    launch.get('connector_report_version')
                and verification['registration_hash'] == launch.get('registration_hash'),
                'Customer wiring result differs from its immutable launch binding')
    return wiring


def _validate_runtime_transition(foundation, connector, proof):
    require(isinstance(proof, dict) and set(proof) == {'foundation_runtime', 'connector_runtime'},
            'Runtime version change requires both original GetAgentRuntime observations')
    old, new = proof['foundation_runtime'], proof['connector_runtime']
    require(isinstance(old, dict) and isinstance(new, dict), 'Runtime observations must be objects')
    prior = foundation['observed']['runtimes']
    current = connector['observed_binding']['runtime']
    for observed, version in ((old, prior['V2RuntimeVersion']), (new, current['runtime_version'])):
        require(observed.get('agentRuntimeArn') == current['runtime_arn']
                and observed.get('agentRuntimeId') == current['runtime_id']
                and observed.get('roleArn') == current['execution_role_arn']
                and observed.get('agentRuntimeVersion') == version
                and observed.get('status') == 'READY',
                'Runtime transition observation identity, version, role or readiness differs')
        require(isinstance(version, str) and re.fullmatch(r'[1-9][0-9]*', version) is not None,
                'Runtime transition version is invalid')
    require(int(new['agentRuntimeVersion']) >= int(old['agentRuntimeVersion']),
            'Runtime transition cannot silently authorize a downgrade')
    required = {'agentRuntimeArtifact', 'environmentVariables', 'networkConfiguration',
                'protocolConfiguration', 'lifecycleConfiguration'}
    require(required <= set(old) and all(isinstance(old[k], dict) and old[k] for k in required),
            'Runtime transition configuration is incomplete')
    # Only transport metadata, timestamps and version may differ. Compare all
    # other fields, including optional/new fields, rather than an allowlist.
    ignored = {'agentRuntimeVersion', 'createdAt', 'lastUpdatedAt', 'ResponseMetadata'}
    require({k:v for k,v in old.items() if k not in ignored} ==
            {k:v for k,v in new.items() if k not in ignored},
            'Runtime code or configuration changed across versions')
    config = old['agentRuntimeArtifact'].get('codeConfiguration', {})
    artifact = foundation['runtime_artifacts']['V2']
    require(config.get('runtime') == 'PYTHON_3_12' and config.get('entryPoint') == ['runtime.py']
            and config.get('code', {}).get('s3') == {
                'bucket': artifact['bucket'], 'prefix': artifact['key'], 'versionId': artifact['version_id']},
            'Runtime transition code does not bind the immutable foundation artifact')


def _compare_foundation_connector(foundation, connector, transition=None):
    observed = foundation['observed']
    readback = connector['baseline_readback']
    binding = connector['observed_binding']
    require(all(observed[name] == readback[name] for name in
                ('connection_id', 'target_id', 'target_name',
                 'registry_hash', 'ledger_hash')),
            'Connector baseline does not continue the collected foundation state')
    runtime = binding['runtime']
    expected = {'runtime_id': 'V2RuntimeId', 'runtime_arn': 'V2RuntimeArn',
        'runtime_version': 'V2RuntimeVersion', 'endpoint_name': 'V2EndpointName',
        'endpoint_arn': 'V2EndpointArn', 'execution_role_arn': 'V2ExecutionRoleArn'}
    require(all(runtime.get(name) == observed['runtimes'].get(source)
                for name, source in expected.items() if name != 'runtime_version'),
            'Connector V2 Runtime does not continue the foundation binding')
    if transition is not None or runtime['runtime_version'] != observed['runtimes']['V2RuntimeVersion']:
        _validate_runtime_transition(foundation, connector, transition)


def check_chain(documents, raw_documents):
    connector_launch = documents['connector_launch']
    connector = documents['connector_report']
    wiring_launch = documents['wiring_launch']
    wiring = documents['wiring_report']

    validate_collected_launch(connector_launch, connector, CONNECTOR_SCOPE)
    validate_collected_launch(wiring_launch, wiring, WIRING_SCOPE)
    validate_connector_result(connector, connector_launch['account'],
                              connector_launch.get('external_id'))
    wiring_binding = validate_wiring_result(wiring, wiring_launch)

    foundation_names = {'foundation_launch', 'foundation_report'}
    supplied_foundation = foundation_names & set(documents)
    require(not supplied_foundation or supplied_foundation == foundation_names,
            'Foundation launch and report must be supplied together')
    require('runtime_transition' not in documents or bool(supplied_foundation),
            'Runtime transition requires foundation evidence')
    account_b = connector['account']
    external_id = connector_launch.get('external_id')
    require(isinstance(external_id, str)
            and re.fullmatch(r'[A-Za-z0-9+=,.@:/_-]{32,128}', external_id) is not None
            and connector_launch.get('external_id_hash') ==
                hashlib.sha256(external_id.encode()).hexdigest()
            and connector_launch.get('source_application_worker_role_arn') ==
                SOURCE_APPLICATION_WORKER_ROLE,
            'Connector launch ExternalId or source principal binding differs')
    checks = ['COLLECTED_LAUNCH_BINDINGS', 'CONNECTOR_REGISTRATION_INTEGRITY',
        'ACCOUNT_A_LIVE_READBACK_CONTINUITY', 'EMPTY_CONNECTED_STATE',
        'NO_HUMAN_OR_RUNTIME_AUTHORITY']
    if supplied_foundation:
        foundation_launch = documents['foundation_launch']
        foundation = documents['foundation_report']
        validate_collected_launch(foundation_launch, foundation, FOUNDATION_SCOPE)
        validate_foundation_result(foundation, foundation_launch['account'])
        require(foundation['account'] == account_b,
                'The foundation and connector reports mix customer accounts')
        _compare_foundation_connector(foundation, connector, documents.get('runtime_transition'))
        checks.extend(['EMPTY_FOUNDATION_STATE',
                       'FOUNDATION_TO_CONNECTOR_CONTINUITY'])
    require(wiring_binding['target_account_id'] == account_b,
            'The report chain mixes customer accounts')
    require(wiring_launch['account'] == ACCOUNT_A,
            'Customer wiring launch is not bound to account A')
    connector_digest = digest(raw_documents['connector_report'])
    require(wiring_launch.get('connector_report_sha256') == connector_digest
            and wiring_launch.get('connector_report_key') ==
                f'customer-wiring-input/{connector_digest}/customer-connector-result.json',
            'Wiring launch does not bind the supplied connector report bytes')
    verification = wiring_binding['verification']
    require(wiring_launch['registration_hash'] == connector['registration_hash']
            and verification['registration_hash'] == connector['registration_hash'],
            'Wiring registration does not continue the connector registration')
    readback = connector['baseline_readback']
    require(verification['observed_registry_hash'] == readback['registry_hash']
            and verification['observed_ledger_hash'] == readback['ledger_hash']
            and verification['connector_stack_id'] == connector['connector_stack_id'],
            'Wiring live readback does not continue the connector state')

    result = {'schema_version': '1.0', 'scope': CHECK_SCOPE, 'result': 'PASS',
        'status': 'READY_FOR_AUTHENTICATED_ACCEPTANCE',
        'checked_at': datetime.now(timezone.utc).isoformat(),
        'aws_execution': 'NOT_RUN_BY_THIS_CHECKER',
        'live_acceptance': 'NOT_RUN',
        'runtime_authority': 'NOT_APPLIED_BY_THIS_CHECKER',
        'account_a': ACCOUNT_A, 'account_b': account_b, 'region': REGION,
        'foundation_evidence': ('VERIFIED' if supplied_foundation else
            'NOT_SUPPLIED_CONNECTOR_AND_WIRING_READBACK_USED'),
        'bindings': {'connector_report_sha256': connector_digest,
            'connector_report_version': connector_launch['report_version_id'],
            'wiring_report_sha256': digest(raw_documents['wiring_report']),
            'wiring_report_version': wiring_launch['report_version_id'],
            'registration_hash': connector['registration_hash']},
        'checks': checks}
    if supplied_foundation:
        result['bindings'].update(
            foundation_report_sha256=digest(raw_documents['foundation_report']),
            foundation_report_version=foundation_launch['report_version_id'])
    if 'runtime_transition' in documents:
        result['bindings']['runtime_transition_sha256'] = digest(raw_documents['runtime_transition'])
        result['checks'].append('IMMUTABLE_RUNTIME_CODE_AND_CONFIGURATION_CONTINUITY')
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('foundation-launch', 'foundation-report', 'runtime-transition'):
        parser.add_argument('--' + name, type=Path)
    for name in ('connector-launch', 'connector-report', 'wiring-launch',
                 'wiring-report'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args(argv)
    paths = {name: getattr(args, name) for name in
        ('foundation_launch', 'foundation_report', 'connector_launch',
         'connector_report', 'wiring_launch', 'wiring_report', 'runtime_transition')
        if getattr(args, name) is not None}
    report = {'schema_version': '1.0', 'scope': CHECK_SCOPE, 'result': 'BLOCKED',
        'status': 'NOT_READY', 'checked_at': datetime.now(timezone.utc).isoformat(),
        'aws_execution': 'NOT_RUN_BY_THIS_CHECKER', 'live_acceptance': 'NOT_RUN',
        'runtime_authority': 'NOT_APPLIED_BY_THIS_CHECKER'}
    try:
        raw = {name: read_document(path) for name, path in paths.items()}
        documents = {name: decode_document(value) for name, value in raw.items()}
        report = check_chain(documents, raw)
    except (OSError, ValueError, TypeError, KeyError, IndexError, AttributeError,
            json.JSONDecodeError) as exc:
        report['error'] = {'type': type(exc).__name__, 'message': str(exc)[:1000]}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2,
                                      allow_nan=False) + '\n', encoding='utf-8')
    print(json.dumps({'scope': report['scope'], 'result': report['result'],
                      'status': report['status'], **({'error': report['error']} if 'error' in report else {})}, ensure_ascii=False), flush=True)
    return 0 if report['result'] == 'PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
