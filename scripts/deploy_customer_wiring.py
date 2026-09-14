#!/usr/bin/env python3
"""Verify an account-B connector and deploy its registry into account A.

The connector report is only transport.  Before packaging or deployment this
worker assumes the report-bound read-only DiscoveryRole, rereads the customer
resources and rebuilds the registration from those observations.  It then invokes
the existing business deployment path with that one registry temporarily present.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / 'src'), str(ROOT / 'scripts')]

from authority_delta.evidence_json import encode_evidence
from authority_delta.business.customer_publisher import verify_customer_candidate
from authority_delta.execution_evidence import decode_ledger_items
from build_customer_adapter_registry import build as build_registry
from deploy_baseline import ACCOUNT, REGION, require_worker_identity
from deploy_baseline import all_records
from deploy_business import (execute as deploy_business, verify_protected_baseline,
                             assessment_diagnostics)
from deploy_customer_connector import (CONNECTOR_STACK, SCOPE as CONNECTOR_SCOPE,
    observe_customer, observed_binding, outputs, stack,
    verify_publisher_journal_permissions)
from verify_aws import observed_at, safe_error, save_evidence, sdk_evidence


SCOPE = 'ACCOUNT_A_VERIFIED_CUSTOMER_REGISTRY_AND_BUSINESS_DEPLOYMENT_NO_HUMAN_APPROVAL_OR_POLICY_WRITE'
MAX_REPORT_BYTES = 2_000_000
APPLICATION_ID = re.compile(r'application-[0-9a-f]{32}')
DELETE_ITEM_ERROR_MARKERS = ('Publisher invocation failed:',
    'remote=ClientError:', 'AccessDeniedException',
    'authority-delta-customer-publisher', 'dynamodb:DeleteItem')
CANARY_RESULT_ERROR_MARKERS = ('Publisher invocation failed:',
    'remote=ValueError:', 'Canary Lambda result differs')
RESOURCE_SCOPED_POLICY_ERROR_MARKERS = ('Publisher invocation failed:',
    'remote=AccessDeniedException:', 'CreatePolicy operation',
    'authority-delta-customer-publisher',
    'bedrock-agentcore:ManageResourceScopedPolicy')
GATEWAY_POLICY_VALIDATION_ERROR_MARKERS = ('Publisher invocation failed:',
    'remote=AccessDeniedException:', 'CreatePolicy operation',
    'Failed to confirm existence on AgentCore Gateway',
    'bedrock-agentcore:GetGateway')
FAILED_POLICY_TARGET_DISCOVERY_ERROR_MARKERS = ('Publisher invocation failed:',
    'remote=ValueError:', 'Owned candidate Policy entered a failed state')
POLICY_DELETE_RESPONSE_ERROR_MARKERS = ('Publisher invocation failed:',
    'remote=ValueError:',
    'Failed candidate Policy delete lacks successful AWS evidence')
POLICY_CREATE_RESPONSE_ERROR_MARKERS = ('Publisher invocation failed:',
    'remote=ValueError:', 'Policy create lacks successful AWS evidence')


def application_recovery_mode(state):
    """Return one exact, unused recovery class; never infer a generic retry."""
    if (not isinstance(state, dict) or state.get('status') != 'UNKNOWN'
            or not isinstance(state.get('last_error'), str)):
        return None
    error = state['last_error']
    if (all(marker in error for marker in DELETE_ITEM_ERROR_MARKERS)
            and state.get('publisher_delete_item_recovery_attempts', 0) == 0):
        return 'PUBLISHER_DELETE_ITEM_IAM'
    if (all(marker in error for marker in CANARY_RESULT_ERROR_MARKERS)
            and state.get('canary_result_recovery_attempts', 0) == 0):
        return 'CANARY_RESULT_CONTRACT'
    if (all(marker in error for marker in RESOURCE_SCOPED_POLICY_ERROR_MARKERS)
            and state.get('resource_scoped_policy_recovery_attempts', 0) == 0):
        return 'RESOURCE_SCOPED_POLICY_IAM'
    if (all(marker in error for marker in GATEWAY_POLICY_VALIDATION_ERROR_MARKERS)
            and state.get('gateway_policy_validation_recovery_attempts', 0) == 0):
        return 'GATEWAY_POLICY_VALIDATION_IAM'
    if (all(marker in error
            for marker in FAILED_POLICY_TARGET_DISCOVERY_ERROR_MARKERS)
            and state.get('failed_policy_target_discovery_recovery_attempts', 0) == 0):
        return 'FAILED_POLICY_TARGET_DISCOVERY'
    if (all(marker in error for marker in POLICY_DELETE_RESPONSE_ERROR_MARKERS)
            and state.get('policy_delete_response_recovery_attempts', 0) == 0):
        return 'POLICY_DELETE_RESPONSE_CONTRACT'
    if (all(marker in error for marker in POLICY_CREATE_RESPONSE_ERROR_MARKERS)
            and state.get('policy_create_response_recovery_attempts', 0) == 0):
        return 'POLICY_CREATE_RESPONSE_CONTRACT'
    if (all(marker in error for marker in POLICY_CREATE_RESPONSE_ERROR_MARKERS)
            and state.get('policy_create_response_recovery_attempts', 0) >= 1
            and state.get('policy_create_discovery_recovery_attempts', 0) == 0):
        return 'POLICY_CREATE_DISCOVERY_RECONCILIATION'
    return None


def validate_connector_report(report):
    required = {'scope', 'result', 'account', 'region', 'connector_stack_id',
        'connector_outputs', 'observed_binding', 'registration_hash',
        'business_publication', 'policy_write', 'live_canary'}
    if (not required.issubset(report) or report['scope'] != CONNECTOR_SCOPE
            or report['result'] != 'PASS' or report['account'] == ACCOUNT
            or not re.fullmatch(r'[0-9]{12}', report['account'])
            or report['region'] != REGION
            or any(report.get(name) != 'NOT_RUN' for name in
                   ('business_publication', 'policy_write', 'live_canary'))):
        raise ValueError('Connector report is not a successful distinct account-B result')
    binding = report['observed_binding']
    registry = build_registry(binding)
    registration = registry['registrations'][0]
    if (registration['registration_hash'] != report['registration_hash']
            or registration['target_account_id'] != report['account']):
        raise ValueError('Connector report registration identity differs')
    connector = report['connector_outputs']
    expected = {'DiscoveryRoleArn': registration['discovery_binding']['role_arn'],
        'PublisherInvokeRoleArn': registration['publisher_binding']['invoke_role_arn'],
        'PublisherFunctionArn': registration['publisher_binding']['function_arn'],
        'RuntimeInvokeRoleArn': registration['invocation_binding']['invoke_role_arn'],
        'InvocationFunctionArn': registration['invocation_binding']['function_arn'],
        'CanaryFunctionArn': registration['probe_binding']['function_arn']}
    if any(connector.get(key) != value for key, value in expected.items()):
        raise ValueError('Connector report outputs differ from the observed binding')
    if connector.get('ExternalIdHash') != hashlib.sha256(
            binding['external_id'].encode()).hexdigest():
        raise ValueError('Connector report ExternalId hash differs')
    stack_pattern = (rf'arn:aws:cloudformation:{REGION}:{report["account"]}:'
                     r'stack/authority-delta-customer-publisher/[A-Za-z0-9-]+')
    if (not re.fullmatch(stack_pattern, report['connector_stack_id'])
            or binding.get('source_authority') !=
                'aws:customer-connector:' + report['connector_stack_id']):
        raise ValueError('Connector stack authority differs')
    return registry


def load_connector_report(session, environment):
    bucket = environment.get('AD_ARTIFACT_BUCKET', '')
    key = environment.get('AD_CONNECTOR_REPORT_KEY', '')
    version = environment.get('AD_CONNECTOR_REPORT_VERSION', '')
    digest = environment.get('AD_CONNECTOR_REPORT_SHA256', '')
    if (not key.startswith('customer-wiring-input/') or not version
            or not re.fullmatch(r'[0-9a-f]{64}', digest)):
        raise ValueError('Connector report transport binding is incomplete')
    item = session.client('s3').get_object(Bucket=bucket, Key=key, VersionId=version)
    body = item['Body']
    try:
        raw = body.read(MAX_REPORT_BYTES + 1)
    finally:
        body.close()
    if (item.get('VersionId') != version or len(raw) > MAX_REPORT_BYTES
            or hashlib.sha256(raw).hexdigest() != digest):
        raise ValueError('Connector report version, size or digest differs')
    report = json.loads(raw)
    return report, validate_connector_report(report)


def assume_customer(session, registration, build_id, *, session_factory=None):
    role = registration['discovery_binding']['role_arn']
    external_id = registration['discovery_binding']['external_id']
    suffix = re.sub(r'[^A-Za-z0-9+=,.@_-]', '-', build_id or 'local')[-40:]
    response = session.client('sts').assume_role(RoleArn=role,
        RoleSessionName='readinessops-wiring-' + suffix,
        ExternalId=external_id, DurationSeconds=900)
    account = registration['target_account_id']
    expected = rf'arn:aws:sts::{account}:assumed-role/authority-delta-customer-discovery/[^/]+'
    assumed = response.get('AssumedRoleUser', {})
    credentials = response.get('Credentials', {})
    if (not re.fullmatch(expected, assumed.get('Arn', ''))
            or not {'AccessKeyId', 'SecretAccessKey', 'SessionToken'} <= set(credentials)):
        raise ValueError('DiscoveryRole assumption identity or credentials differ')
    if session_factory is None:
        import boto3
        session_factory = lambda values: boto3.Session(
            aws_access_key_id=values['AccessKeyId'],
            aws_secret_access_key=values['SecretAccessKey'],
            aws_session_token=values['SessionToken'], region_name=REGION)
    return session_factory(credentials), {'role_arn': role,
        'assumed_role_arn': assumed['Arn'],
        'request': sdk_evidence(response)}


def _successful(response, label):
    metadata = response.get('ResponseMetadata', {})
    if metadata.get('HTTPStatusCode') != 200 or not metadata.get('RequestId'):
        raise ValueError(label + ' lacks successful AWS evidence')
    return sdk_evidence(response)


def _read_candidate(session, data_bucket, reference):
    if (not isinstance(reference, dict) or reference.get('bucket') != data_bucket
            or not reference.get('key', '').startswith('business/applications/')
            or not reference.get('version_id')
            or not re.fullmatch(r'[0-9a-f]{64}', reference.get('sha256', ''))
            or type(reference.get('size')) is not int
            or not 0 < reference['size'] <= 900_000):
        raise ValueError('Recovery candidate reference is invalid')
    response = session.client('s3').get_object(Bucket=data_bucket,
        Key=reference['key'], VersionId=reference['version_id'])
    stream = response['Body']
    try:
        raw = stream.read(reference['size'] + 1)
    finally:
        stream.close()
    if (response.get('VersionId') != reference['version_id']
            or len(raw) != reference['size']
            or hashlib.sha256(raw).hexdigest() != reference['sha256']):
        raise ValueError('Recovery candidate immutable readback differs')
    return json.loads(raw), _successful(response, 'Recovery candidate read')


def application_recovery_evidence(session, customer, registration,
                                  connector_outputs, application_id):
    """Verify the exact parked application and its candidate-owned B state."""
    if not APPLICATION_ID.fullmatch(application_id or ''):
        raise ValueError('Recovery application ID is invalid')
    business = outputs(stack(session, 'authority-delta-business'))
    if not {'AppTable', 'DataBucket'} <= set(business):
        raise ValueError('Account-A business recovery resources are incomplete')
    ddb = session.client('dynamodb')
    args = {'TableName': business['AppTable'], 'ConsistentRead': True,
        'FilterExpression': 'sk = :application',
        'ExpressionAttributeValues': {
            ':application': {'S': 'APPLICATION#' + application_id}}}
    items, scan_evidence = [], []
    while True:
        page = ddb.scan(**args)
        scan_evidence.append(_successful(page, 'Recovery application scan'))
        items.extend(page.get('Items', []))
        if len(items) > 1:
            break
        if not page.get('LastEvaluatedKey'):
            break
        args['ExclusiveStartKey'] = page['LastEvaluatedKey']
    if len(items) != 1 or set(items[0]) != {'pk', 'sk', 'version', 'data'}:
        raise ValueError('Recovery application record is missing or ambiguous')
    state = json.loads(items[0]['data']['S'])
    recovery_mode = application_recovery_mode(state)
    if (state.get('application_id') != application_id
            or state.get('status') != 'UNKNOWN' or recovery_mode is None):
        raise ValueError('Recovery application is not an exact supported parked failure')
    candidate, candidate_evidence = _read_candidate(
        session, business['DataBucket'], state.get('candidate_ref'))
    candidate = verify_customer_candidate(candidate, registration)
    if (candidate.get('application_id') != application_id
            or candidate.get('enforcement_digest') != state.get('enforcement_digest')):
        raise ValueError('Recovery candidate differs from the parked application')

    journal_response = customer.client('dynamodb').get_item(
        TableName=connector_outputs['PublisherJournalTable'],
        Key={'pk': {'S': candidate['enforcement_digest']},
             'sk': {'S': 'STATE'}}, ConsistentRead=True)
    journal_evidence = _successful(journal_response, 'Publisher journal read')
    journal_item = journal_response.get('Item')
    if (not isinstance(journal_item, dict)
            or set(journal_item) != {'pk', 'sk', 'version', 'data'}):
        raise ValueError('Exact publisher journal state is missing')
    journal = json.loads(journal_item['data']['S'])
    if journal.get('candidate') != candidate:
        raise ValueError('Publisher journal candidate differs from account A')

    fence_response = customer.client('dynamodb').get_item(
        TableName=connector_outputs['PublisherJournalTable'],
        Key={'pk': {'S': candidate['enforcement_digest']},
             'sk': {'S': 'WORKER_FENCE'}}, ConsistentRead=True)
    fence_evidence = _successful(fence_response, 'Publisher worker fence read')
    if fence_response.get('Item') is not None:
        raise ValueError('Publisher worker fence is still present; recovery remains parked')

    control = customer.client('bedrock-agentcore-control')
    listed = control.list_policies(policyEngineId=registration['policy_engine_id'],
                                   maxResults=100)
    list_evidence = _successful(listed, 'Policy list')
    policies = listed.get('policies', [])
    if listed.get('nextToken') or len(policies) > 1:
        raise ValueError('Recovery Policy Engine state is ambiguous')
    expected_name = 'AuthorityDeltaApp_' + candidate['enforcement_digest'][:16]
    policy_evidence = None
    failed_target_discovery = recovery_mode == 'FAILED_POLICY_TARGET_DISCOVERY'
    delete_response_recovery = recovery_mode == 'POLICY_DELETE_RESPONSE_CONTRACT'
    create_response_recovery = recovery_mode in (
        'POLICY_CREATE_RESPONSE_CONTRACT',
        'POLICY_CREATE_DISCOVERY_RECONCILIATION')
    if policies:
        policy_id = (policies[0].get('policyId') if create_response_recovery
                     else journal.get('policy_id'))
        if (journal.get('status') == 'RECOVERED_CLOSED'
                or policies[0].get('policyId') != policy_id
                or policies[0].get('name') != expected_name
                or journal.get('policy_name') != expected_name):
            raise ValueError('Active Policy is not owned by the recovery candidate')
        policy = control.get_policy(
            policyEngineId=registration['policy_engine_id'], policyId=policy_id)
        policy_evidence = _successful(policy, 'Owned recovery Policy read')
        if (policy.get('policyEngineId') != registration['policy_engine_id']
                or policy.get('policyId') != policy_id
                or policy.get('name') != expected_name
                or (policy.get('enforcementMode') is not None
                    and policy.get('enforcementMode') != 'ACTIVE')
                or policy.get('definition', {}).get('cedar', {}).get('statement')
                    != candidate['policy_binding']['statement']):
            raise ValueError('Owned recovery Policy readback differs')
        if create_response_recovery:
            if (journal.get('status') != 'CLOSED_PROVEN'
                    or journal.get('policy_id') is not None
                    or policy.get('status') not in ('CREATING', 'ACTIVE')):
                raise ValueError('Policy create-response recovery boundary differs')
        elif failed_target_discovery or delete_response_recovery:
            expected_reason = ('Insufficient permissions to list targets on gateway with ID '
                               + registration['gateway_id'])
            if (policy.get('status') == 'CREATE_FAILED'
                    and policy.get('statusReasons') == [expected_reason]):
                pass
            elif (delete_response_recovery
                    and policy.get('status') == 'DELETING'):
                pass
            else:
                raise ValueError('Failed recovery Policy reason differs')
        elif policy.get('status') != 'ACTIVE':
            raise ValueError('Owned recovery Policy is not active')
    elif journal.get('status') == 'VERIFIED':
        raise ValueError('Verified publisher journal has no active owned Policy')
    if (recovery_mode == 'CANARY_RESULT_CONTRACT'
            and (journal.get('status') != 'PREPARED' or policies)):
        raise ValueError('Canary-result recovery is not at the expected closed boundary')
    if (recovery_mode == 'RESOURCE_SCOPED_POLICY_IAM'
            and (journal.get('status') != 'CLOSED_PROVEN' or policies)):
        raise ValueError('Resource-scoped Policy recovery is not at its closed boundary')
    if (recovery_mode == 'GATEWAY_POLICY_VALIDATION_IAM'
            and (journal.get('status') != 'CLOSED_PROVEN' or policies)):
        raise ValueError('Gateway Policy validation recovery is not at its closed boundary')
    if (failed_target_discovery
            and (journal.get('status') != 'POLICY_CREATED' or len(policies) != 1)):
        raise ValueError('Failed Policy target-discovery recovery boundary differs')
    if (delete_response_recovery
            and (journal.get('status') not in (
                    'POLICY_CREATED', 'FAILED_POLICY_DELETE_INTENT')
                 or len(policies) > 1)):
        raise ValueError('Policy delete-response recovery boundary differs')
    if (create_response_recovery
            and (journal.get('status') != 'CLOSED_PROVEN'
                 or journal.get('policy_id') is not None
                 or len(policies) > 1)):
        raise ValueError('Policy create-response recovery boundary differs')

    raw_ledger = all_records(customer.client('dynamodb'),
        registration['probe_binding']['sandbox_ledger_table_name'])
    ledger = decode_ledger_items(raw_ledger)
    expected_requests = {item['request_id'] for item in candidate['expected_outcomes']}
    if (len(ledger) > len(expected_requests)
            or any(item.get('request_id') not in expected_requests
                   or item.get('connection_id') != registration['connection_id']
                   or item.get('execution_status') != 'PAYMENT_PREPARED'
                   for item in ledger)):
        raise ValueError('Recovery ledger contains non-candidate execution state')
    return {'application_id': application_id, 'status': state['status'],
        'recovery_mode': recovery_mode,
        'attempt': state.get('attempt'), 'enforcement_digest': candidate['enforcement_digest'],
        'journal_status': journal.get('status'), 'policy_count': len(policies),
        'ledger_count': len(ledger), 'application_scan': scan_evidence,
        'candidate_read': candidate_evidence, 'journal_read': journal_evidence,
        'worker_fence_read': fence_evidence,
        'policy_list': list_evidence, 'policy_read': policy_evidence}


def verify_customer(session, connector_report, registry, build_id,
                    *, session_factory=None, recovery_application_id=None):
    registration = registry['registrations'][0]
    customer, assumption = assume_customer(session, registration, build_id,
                                           session_factory=session_factory)
    account = registration['target_account_id']
    observed = observe_customer(customer, account)
    observed['account'] = account
    connector_stack = stack(customer, CONNECTOR_STACK)
    connector_outputs = outputs(connector_stack)
    if (connector_stack.get('StackId') != connector_report['connector_stack_id']
            or connector_outputs != connector_report['connector_outputs']):
        raise ValueError('Live connector stack differs from the transported report')
    connector = {'stack_id': connector_stack['StackId'],
                 'outputs': connector_outputs}
    actual = observed_binding(observed, connector,
        registration['discovery_binding']['external_id'])
    if actual != connector_report['observed_binding']:
        raise ValueError('Live customer resource binding differs from the report')
    journal_permissions = verify_publisher_journal_permissions(customer, account,
        connector_outputs['PublisherJournalTable'], registration['gateway_arn'])
    recovery = None
    if recovery_application_id:
        recovery = application_recovery_evidence(session, customer, registration,
            connector_outputs, recovery_application_id)
        policy_count, ledger_count = recovery['policy_count'], recovery['ledger_count']
    else:
        policies = customer.client('bedrock-agentcore-control').list_policies(
            policyEngineId=registration['policy_engine_id'])
        if policies.get('policies') or policies.get('nextToken'):
            raise ValueError('Customer Policy Engine is not empty before connected acceptance')
        ledger = all_records(customer.client('dynamodb'),
            registration['probe_binding']['sandbox_ledger_table_name'])
        if ledger:
            raise ValueError('Customer ledger is not empty before connected acceptance')
        policy_count, ledger_count = 0, 0
    lam = customer.client('lambda')
    functions = {}
    for key in ('PublisherFunctionArn', 'CanaryFunctionArn', 'InvocationFunctionArn'):
        config = lam.get_function_configuration(FunctionName=connector_outputs[key])
        if (config.get('State') != 'Active'
                or config.get('LastUpdateStatus') != 'Successful'
                or config.get('FunctionArn') != connector_outputs[key]):
            raise ValueError(key + ' is not an active qualified function')
        functions[key] = {'function_arn': config['FunctionArn'],
                          'code_sha256': config.get('CodeSha256')}
    return {'assumption': assumption, 'connector_stack_id': connector_stack['StackId'],
        'registration_hash': registration['registration_hash'],
        'observed_registry_hash': observed['registry_hash'],
        'observed_ledger_hash': observed['ledger_hash'],
        'policy_count': policy_count, 'ledger_count': ledger_count,
        'publisher_journal_permissions': journal_permissions,
        'application_recovery': recovery, 'functions': functions}


def execute(session, environment, report, *, root=ROOT, run=None,
            session_factory=None, business_executor=deploy_business):
    identity = session.client('sts').get_caller_identity()
    require_worker_identity(identity, environment)
    report.update(account=ACCOUNT, region=REGION, caller_arn=identity['Arn'])
    connector_report, registry = load_connector_report(session, environment)
    verification = verify_customer(session, connector_report, registry,
        environment.get('CODEBUILD_BUILD_ID'), session_factory=session_factory,
        recovery_application_id=environment.get('AD_RECOVERY_APPLICATION_ID') or None)
    report['customer_wiring'] = {'target_account_id': connector_report['account'],
        'connector_report_sha256': environment['AD_CONNECTOR_REPORT_SHA256'],
        'connector_report_version': environment['AD_CONNECTOR_REPORT_VERSION'],
        'verification': verification}
    registry_path = root / 'services/business/adapter_registrations.json'
    original = registry_path.read_bytes()
    try:
        registry_path.write_text(json.dumps(registry, indent=2) + '\n', encoding='utf-8')
        kwargs = {'root': root}
        if run is not None:
            kwargs['run'] = run
        business_executor(session, environment, report, **kwargs)
    finally:
        try:
            registry_path.write_bytes(original)
        finally:
            verify_protected_baseline(session, report, root=root)
    if (report.get('result') != 'PASS' or report.get('approval_recorded') is not False
            or report.get('state_unchanged') is not True):
        raise ValueError('Connected business deployment did not complete safely')
    report.update(customer_registry='VERIFIED_AND_DEPLOYED',
        policy_write='NOT_RUN', live_customer_canary='NOT_RUN',
        human_workflow='NOT_RUN', approval_recorded=False)
    return report


def main():
    import boto3
    from botocore.config import Config
    environment = os.environ
    report = {'schema_version': '1.2', 'baseline_id': 'AD-BASELINE-1.2',
        'scope': SCOPE, 'result': 'FAIL',
        'build_id': environment.get('CODEBUILD_BUILD_ID'),
        'source_sha256': environment.get('AD_SOURCE_SHA256'),
        'started_at': observed_at(), 'approval_recorded': False,
        'policy_write': 'NOT_RUN', 'live_customer_canary': 'NOT_RUN'}
    base = boto3.Session(region_name=REGION)
    original = base.client
    base.client = lambda service, **values: original(service,
        config=Config(connect_timeout=10, read_timeout=60,
                      retries={'total_max_attempts': 2}), **values)
    try:
        execute(base, environment, report)
    except Exception as exc:
        report.update(result='FAIL', error=safe_error(exc))
        print('ERROR: ' + str(exc), flush=True)
    report['completed_at'] = observed_at()
    report['assessment_diagnostics'] = assessment_diagnostics(report)
    data = encode_evidence(report)
    path = ROOT / 'evidence/aws/customer-wiring-result.json'
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    try:
        save_evidence(base, environment, data, path, environment['AD_REPORT_KEY'])
    except Exception as exc:
        print('ERROR saving customer wiring evidence: ' + str(exc), flush=True)
        return 1
    print(encode_evidence({key: report.get(key) for key in (
        'result', 'customer_registry', 'business_assessment_canary',
        'human_workflow', 'policy_write', 'live_customer_canary',
        'state_unchanged', 'state_error', 'assessment_diagnostics', 'error')}).decode(), flush=True)
    return 0 if report['result'] == 'PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
