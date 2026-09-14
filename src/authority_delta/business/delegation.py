"""Typed delegation and application contracts for registered AWS adapters.

Business approval and official publication are inputs to this module, never AWS
authority by themselves.  A registration is trusted server configuration.  The
browser may select one registered profile but cannot supply ARNs, policy text or
the finite request set.
"""
from __future__ import annotations

import copy
import json
import re
from datetime import datetime, timedelta

from authority_delta.canonical import sha256_json
from authority_delta.adapters.vendor_payment_policy import compile_payment_permit
from authority_delta.adapters.vendor_payment_view import ADAPTER as VENDOR_PAYMENT


ADAPTERS = {VENDOR_PAYMENT.adapter_id: VENDOR_PAYMENT}
PROFILES = ('MAINTAIN', 'NARROW')
REQUEST_ID = re.compile(r'^req-[0-9a-f]{64}$')
HASH = re.compile(r'^[0-9a-f]{64}$')
ACCOUNT = re.compile(r'^[0-9]{12}$')
REGION = re.compile(r'^[a-z]{2}(?:-gov)?-[a-z]+-[0-9]$')
CONNECTION = re.compile(r'^conn-[A-Za-z0-9_-]{4,80}$')
RUNTIME_ID = re.compile(r'^[A-Za-z][A-Za-z0-9_-]{7,80}$')
LAMBDA_ARN = re.compile(
    r'^arn:aws:lambda:([a-z]{2}(?:-gov)?-[a-z]+-[0-9]):([0-9]{12}):function:'
    r'([A-Za-z0-9_-]{1,64}):([A-Za-z0-9_$-]{1,128})$')
TABLE_NAME = re.compile(r'^[A-Za-z0-9_.-]{3,255}$')


def _exact(value, fields, label):
    if not isinstance(value, dict) or set(value) != set(fields):
        raise ValueError(f'{label} fields differ')
    return value


def _nonempty(value, label, maximum=500):
    if not isinstance(value, str) or not value or value != value.strip() or len(value) > maximum:
        raise ValueError(f'{label} must be one bounded exact string')
    return value


def _timestamp(value, label):
    _nonempty(value, label, 80)
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as exc:
        raise ValueError(f'{label} must be RFC3339') from exc
    if parsed.tzinfo is None or parsed.utcoffset() != timedelta(0):
        raise ValueError(f'{label} must use UTC')
    return parsed


def verify_registration(value):
    """Verify one server-controlled adapter/connection/runtime registration."""
    value = copy.deepcopy(value)
    fields = {'schema_version', 'status', 'connection_mode', 'adapter_id', 'adapter_version',
              'connection_id', 'source_authority', 'target_account_id', 'target_region',
              'gateway_arn', 'gateway_id', 'policy_engine_id', 'target_id', 'target_name',
              'runtime', 'discovery_binding', 'publisher_binding', 'invocation_binding',
              'probe_binding',
              'request_registry_snapshot_hash', 'forbidden_tool_ids', 'profiles',
              'registration_hash'}
    _exact(value, fields, 'Adapter registration')
    if value['schema_version'] != '1.0' or value['status'] != 'ACTIVE':
        raise ValueError('Adapter registration is not active or supported')
    if value['connection_mode'] not in ('SYNTHETIC_LOCAL', 'LIVE_CUSTOMER'):
        raise ValueError('Connection mode is not explicit')
    adapter = ADAPTERS.get(value['adapter_id'])
    if adapter is None or value['adapter_version'] != adapter.version:
        raise ValueError('Adapter identity or exact version is not registered')
    if not CONNECTION.fullmatch(value['connection_id']):
        raise ValueError('Connection ID is invalid')
    if not ACCOUNT.fullmatch(value['target_account_id']) or not REGION.fullmatch(value['target_region']):
        raise ValueError('Target account or Region is invalid')
    for name in ('source_authority', 'gateway_id', 'policy_engine_id', 'target_id', 'target_name'):
        _nonempty(value[name], name, 160)
    prefix = f"arn:aws:bedrock-agentcore:{value['target_region']}:{value['target_account_id']}:"
    if value['gateway_arn'] != prefix + 'gateway/' + value['gateway_id']:
        raise ValueError('Gateway ARN does not match the registered account, Region and ID')
    runtime = _exact(value['runtime'], {'release_id', 'runtime_id', 'runtime_arn', 'runtime_version',
        'endpoint_name', 'endpoint_arn', 'execution_role_arn'}, 'Runtime binding')
    for name in ('release_id', 'runtime_version', 'endpoint_name'):
        _nonempty(runtime[name], name, 100)
    if not RUNTIME_ID.fullmatch(runtime['runtime_id']):
        raise ValueError('Runtime ID is invalid')
    if runtime['runtime_arn'] != prefix + 'runtime/' + runtime['runtime_id']:
        raise ValueError('Runtime ARN does not match the connection')
    if runtime['endpoint_arn'] != runtime['runtime_arn'] + '/runtime-endpoint/' + runtime['endpoint_name']:
        raise ValueError('Runtime endpoint is not exactly bound')
    role_prefix = f"arn:aws:iam::{value['target_account_id']}:role/"
    if not isinstance(runtime['execution_role_arn'], str) or not runtime['execution_role_arn'].startswith(role_prefix):
        raise ValueError('Execution role is not in the target account')
    discovery = _exact(value['discovery_binding'], {'role_arn', 'external_id'},
                       'Discovery binding')
    publisher = _exact(value['publisher_binding'], {
        'function_arn', 'invoke_role_arn', 'external_id'}, 'Publisher binding')
    invocation = _exact(value['invocation_binding'], {
        'function_arn', 'invoke_role_arn', 'external_id'}, 'Invocation binding')
    match = LAMBDA_ARN.fullmatch(publisher['function_arn'])
    if (match is None or match.group(1) != value['target_region']
            or match.group(2) != value['target_account_id']):
        raise ValueError('Publisher must be a qualified Lambda in the target account and Region')
    invocation_match = LAMBDA_ARN.fullmatch(invocation['function_arn'])
    if (invocation_match is None or invocation_match.group(1) != value['target_region']
            or invocation_match.group(2) != value['target_account_id']):
        raise ValueError('Invocation endpoint must be a qualified Lambda in the target account and Region')
    role_pattern = re.compile(r'^arn:aws:iam::([0-9]{12}):role/([A-Za-z0-9+=,.@_-]{1,64})$')
    discovery_role = role_pattern.fullmatch(discovery['role_arn'])
    invoke_role = role_pattern.fullmatch(publisher['invoke_role_arn'])
    runtime_invoke_role = role_pattern.fullmatch(invocation['invoke_role_arn'])
    if (discovery_role is None or invoke_role is None
            or runtime_invoke_role is None
            or discovery_role.group(1) != value['target_account_id']
            or invoke_role.group(1) != value['target_account_id']
            or runtime_invoke_role.group(1) != value['target_account_id']
            or len({discovery['role_arn'], publisher['invoke_role_arn'],
                    invocation['invoke_role_arn']}) != 3):
        raise ValueError('Discovery, publish and invocation roles must be distinct target roles')
    external_id = publisher['external_id']
    if (not isinstance(external_id, str)
            or not re.fullmatch(r'[A-Za-z0-9+=,.@:/_-]{32,128}', external_id)
            or discovery['external_id'] != external_id
            or invocation['external_id'] != external_id):
        raise ValueError('Connector ExternalId is missing or inconsistent')
    probe = _exact(value['probe_binding'], {'function_arn',
        'request_registry_table_name', 'sandbox_ledger_table_name'}, 'Probe binding')
    probe_match = LAMBDA_ARN.fullmatch(probe['function_arn'])
    if (probe_match is None or probe_match.group(1) != value['target_region']
            or probe_match.group(2) != value['target_account_id']):
        raise ValueError('Probe must be a qualified Lambda in the target account and Region')
    if any(not isinstance(probe[name], str) or not TABLE_NAME.fullmatch(probe[name])
           for name in ('request_registry_table_name', 'sandbox_ledger_table_name')):
        raise ValueError('Probe tables are invalid')
    if not HASH.fullmatch(value['request_registry_snapshot_hash']):
        raise ValueError('Request registry snapshot hash is invalid')
    forbidden = value['forbidden_tool_ids']
    if (not isinstance(forbidden, list) or forbidden != sorted(set(forbidden))
            or any(not isinstance(x, str) or not x for x in forbidden)
            or not {'export_credentials', 'update_vendor_bank'}.issubset(forbidden)):
        raise ValueError('Forbidden tools are not a complete sorted set')
    profiles = value['profiles']
    if not isinstance(profiles, dict) or not profiles or not set(profiles).issubset(PROFILES):
        raise ValueError('Registered profiles are invalid')
    request_universes = []
    for name, profile in profiles.items():
        _exact(profile, {'boundary_parameters', 'allowed_request_ids', 'expected_outcomes'}, 'Adapter profile')
        adapter.binding(profile['boundary_parameters'])
        allowed = profile['allowed_request_ids']
        if (not isinstance(allowed, list) or not allowed or allowed != sorted(set(allowed))
                or any(not isinstance(x, str) or not REQUEST_ID.fullmatch(x) for x in allowed)):
            raise ValueError('Allowed request IDs are not a finite sorted set')
        outcomes = profile['expected_outcomes']
        if not isinstance(outcomes, list) or not outcomes:
            raise ValueError('Canary outcomes are missing')
        by_id = {}
        for item in outcomes:
            _exact(item, {'request_id', 'expected_outcome'}, 'Canary outcome')
            if (not REQUEST_ID.fullmatch(item['request_id'])
                    or item['expected_outcome'] not in ('ALLOW', 'DENY')
                    or item['request_id'] in by_id):
                raise ValueError('Canary outcome is malformed or duplicated')
            by_id[item['request_id']] = item['expected_outcome']
        if {request_id for request_id, result in by_id.items() if result == 'ALLOW'} != set(allowed):
            raise ValueError('Policy permission set differs from canary expectations')
        request_universes.append(set(by_id))
        policy = compile_payment_permit(gateway_arn=value['gateway_arn'],
            role_arn=runtime['execution_role_arn'], allowed_request_ids=allowed,
            request_registry_snapshot_hash=value['request_registry_snapshot_hash'],
            target_name=value['target_name'])
        if policy is None:
            raise ValueError('An active delegation profile must compile a finite policy')
    if any(universe != request_universes[0] for universe in request_universes[1:]):
        raise ValueError('Registered profiles do not cover the same finite request universe')
    expected_hash = sha256_json({k: v for k, v in value.items() if k != 'registration_hash'})
    if value['registration_hash'] != expected_hash:
        raise ValueError('Adapter registration digest differs')
    return value


def registration_with_hash(value):
    value = copy.deepcopy(value)
    value['registration_hash'] = sha256_json(value)
    return verify_registration(value)


def load_adapter_registry(path):
    """Load the packaged, server-controlled registry; an empty file is fail-closed."""
    document = json.loads(path.read_text(encoding='utf-8'))
    _exact(document, {'schema_version', 'registrations'}, 'Adapter registry')
    if document['schema_version'] != '1.0' or not isinstance(document['registrations'], list):
        raise ValueError('Adapter registry is unsupported')
    if len(document['registrations']) > 8:
        raise ValueError('Adapter registry exceeds its bounded connection count')
    result = [verify_registration(value) for value in document['registrations']]
    keys = [(value['adapter_id'], value['connection_id']) for value in result]
    if len(keys) != len(set(keys)):
        raise ValueError('Adapter registry contains duplicate connections')
    return result


def public_registration(value):
    value = verify_registration(value)
    return {'adapter_id': value['adapter_id'], 'adapter_version': value['adapter_version'],
        'connection_id': value['connection_id'], 'connection_mode': value['connection_mode'],
        'target_account_id': value['target_account_id'], 'target_region': value['target_region'],
        'release_id': value['runtime']['release_id'], 'runtime_version': value['runtime']['runtime_version'],
        'registration_hash': value['registration_hash'],
        'profiles': [{'profile_id': name,
            'boundary': ADAPTERS[value['adapter_id']].binding(profile['boundary_parameters']),
            'allowed_request_count': len(profile['allowed_request_ids']),
            'allowed_request_ids': copy.deepcopy(profile['allowed_request_ids'])}
            for name, profile in sorted(value['profiles'].items())]}


def _resolved_profile(registration, profile_id):
    registration = verify_registration(registration)
    if profile_id not in registration['profiles']:
        raise ValueError('Delegation profile is not registered')
    profile = registration['profiles'][profile_id]
    boundary = ADAPTERS[registration['adapter_id']].binding(profile['boundary_parameters'])
    runtime = registration['runtime']
    policy = compile_payment_permit(gateway_arn=registration['gateway_arn'],
        role_arn=runtime['execution_role_arn'], allowed_request_ids=profile['allowed_request_ids'],
        request_registry_snapshot_hash=registration['request_registry_snapshot_hash'],
        target_name=registration['target_name'])
    return profile, boundary, policy


def build_delegation_receipt(*, receipt_id, object_record, publication, publication_ref,
        registration, profile_id, actor, reason, valid_days, approved_at, approval_generation):
    """Create a separate, typed human authority to attempt one AWS application."""
    registration = verify_registration(registration)
    profile, boundary, policy = _resolved_profile(registration, profile_id)
    if not re.fullmatch(r'delegation-[0-9a-f]{32}', receipt_id):
        raise ValueError('Delegation receipt ID is invalid')
    if type(valid_days) is not int or not 1 <= valid_days <= 30:
        raise ValueError('Delegation validity must be between one and thirty days')
    start = _timestamp(approved_at, 'approved_at')
    _nonempty(reason, 'Delegation reason', 1600)
    _nonempty(actor.get('sub'), 'Delegation approver subject', 160)
    _nonempty(actor.get('name'), 'Delegation approver name', 160)
    if type(approval_generation) is not int or approval_generation < 1:
        raise ValueError('Delegation generation is invalid')
    runtime = registration['runtime']
    receipt = {'schema_version': '1.0', 'kind': 'AWS_DELEGATION_AUTHORITY',
        'receipt_id': receipt_id, 'object_id': object_record['object_id'],
        'workspace_id': object_record['workspace_id'],
        'publication_id': publication['publication_id'], 'publication_digest': publication['digest'],
        'publication_ref': copy.deepcopy(publication_ref),
        'adapter_id': registration['adapter_id'], 'adapter_version': registration['adapter_version'],
        'adapter_registration_hash': registration['registration_hash'],
        'connection_id': registration['connection_id'], 'connection_mode': registration['connection_mode'],
        'profile_id': profile_id, 'boundary_binding': boundary,
        'execution_binding': {'target_account_id': registration['target_account_id'],
            'target_region': registration['target_region'], 'gateway_arn': registration['gateway_arn'],
            'gateway_id': registration['gateway_id'], 'policy_engine_id': registration['policy_engine_id'],
            'target_id': registration['target_id'], 'target_name': registration['target_name'],
            'runtime': copy.deepcopy(runtime),
            'request_registry_snapshot_hash': registration['request_registry_snapshot_hash']},
        'discovery_binding': copy.deepcopy(registration['discovery_binding']),
        'publisher_binding': copy.deepcopy(registration['publisher_binding']),
        'invocation_binding': copy.deepcopy(registration['invocation_binding']),
        'probe_binding': copy.deepcopy(registration['probe_binding']),
        'policy_binding': policy, 'expected_outcomes': copy.deepcopy(profile['expected_outcomes']),
        'forbidden_tool_ids': copy.deepcopy(registration['forbidden_tool_ids']),
        'approval_generation': approval_generation, 'decision': 'APPROVE_DELEGATION',
        'reason': reason, 'approver_sub': actor['sub'], 'approver_name': actor['name'],
        'approved_at': approved_at, 'expires_at': (start + timedelta(days=valid_days)).isoformat(),
        'runtime_authority_active': False}
    receipt['digest'] = sha256_json(receipt)
    return receipt


def verify_delegation_receipt(receipt, *, object_record, publication, registration,
        current_generation=None, at=None):
    receipt = copy.deepcopy(receipt)
    required = {'schema_version', 'kind', 'receipt_id', 'object_id', 'workspace_id',
        'publication_id', 'publication_digest', 'publication_ref', 'adapter_id', 'adapter_version',
        'adapter_registration_hash', 'connection_id', 'connection_mode', 'profile_id',
        'boundary_binding', 'execution_binding', 'policy_binding', 'expected_outcomes',
        'discovery_binding', 'publisher_binding', 'invocation_binding', 'probe_binding',
        'forbidden_tool_ids', 'approval_generation', 'decision', 'reason', 'approver_sub',
        'approver_name', 'approved_at', 'expires_at', 'runtime_authority_active', 'digest'}
    _exact(receipt, required, 'Delegation receipt')
    digest = receipt.pop('digest')
    if not HASH.fullmatch(digest) or sha256_json(receipt) != digest:
        raise ValueError('Delegation receipt digest differs')
    receipt['digest'] = digest
    if not re.fullmatch(r'delegation-[0-9a-f]{32}', receipt['receipt_id']):
        raise ValueError('Delegation receipt ID is invalid')
    registration = verify_registration(registration)
    profile, boundary, policy = _resolved_profile(registration, receipt['profile_id'])
    expected = {'schema_version': '1.0', 'kind': 'AWS_DELEGATION_AUTHORITY',
        'object_id': object_record['object_id'], 'workspace_id': object_record['workspace_id'],
        'publication_id': publication['publication_id'], 'publication_digest': publication['digest'],
        'publication_ref': publication['ref'],
        'adapter_id': registration['adapter_id'], 'adapter_version': registration['adapter_version'],
        'adapter_registration_hash': registration['registration_hash'],
        'connection_id': registration['connection_id'], 'connection_mode': registration['connection_mode'],
        'boundary_binding': boundary, 'policy_binding': policy,
        'discovery_binding': registration['discovery_binding'],
        'publisher_binding': registration['publisher_binding'],
        'invocation_binding': registration['invocation_binding'],
        'probe_binding': registration['probe_binding'],
        'expected_outcomes': profile['expected_outcomes'],
        'forbidden_tool_ids': registration['forbidden_tool_ids'],
        'decision': 'APPROVE_DELEGATION', 'runtime_authority_active': False}
    if any(receipt.get(k) != v for k, v in expected.items()):
        raise ValueError('Delegation receipt does not match the registered publication or authority')
    binding = receipt['execution_binding']
    if binding != {'target_account_id': registration['target_account_id'],
            'target_region': registration['target_region'], 'gateway_arn': registration['gateway_arn'],
            'gateway_id': registration['gateway_id'], 'policy_engine_id': registration['policy_engine_id'],
            'target_id': registration['target_id'], 'target_name': registration['target_name'],
            'runtime': registration['runtime'],
            'request_registry_snapshot_hash': registration['request_registry_snapshot_hash']}:
        raise ValueError('Delegation execution binding differs')
    if current_generation is not None and receipt['approval_generation'] != current_generation:
        raise ValueError('Delegation receipt is not the current generation')
    if type(receipt['approval_generation']) is not int or receipt['approval_generation'] < 1:
        raise ValueError('Delegation generation is invalid')
    approved = _timestamp(receipt['approved_at'], 'approved_at')
    expires = _timestamp(receipt['expires_at'], 'expires_at')
    if (expires <= approved or expires - approved > timedelta(days=30)
            or (at is not None and not approved <= _timestamp(at, 'current time') < expires)):
        raise ValueError('Delegation receipt is outside its validity period')
    _nonempty(receipt['reason'], 'Delegation reason', 1600)
    _nonempty(receipt['approver_sub'], 'Delegation approver subject', 160)
    _nonempty(receipt['approver_name'], 'Delegation approver name', 160)
    return receipt


def build_enforcement_candidate(*, application_id, receipt, receipt_ref, publication,
        publication_ref, previous_applied_binding, created_at):
    if not re.fullmatch(r'application-[0-9a-f]{32}', application_id):
        raise ValueError('Application ID is invalid')
    candidate = {'schema_version': '1.0', 'kind': 'ENFORCEMENT_CANDIDATE',
        'application_id': application_id, 'object_id': receipt['object_id'],
        'publication_id': publication['publication_id'], 'publication_digest': publication['digest'],
        'publication_ref': copy.deepcopy(publication_ref), 'delegation_receipt_id': receipt['receipt_id'],
        'delegation_receipt_digest': receipt['digest'], 'delegation_receipt_ref': copy.deepcopy(receipt_ref),
        'adapter_id': receipt['adapter_id'], 'adapter_version': receipt['adapter_version'],
        'adapter_registration_hash': receipt['adapter_registration_hash'],
        'connection_id': receipt['connection_id'], 'connection_mode': receipt['connection_mode'],
        'profile_id': receipt['profile_id'], 'boundary_binding': copy.deepcopy(receipt['boundary_binding']),
        'execution_binding': copy.deepcopy(receipt['execution_binding']),
        'discovery_binding': copy.deepcopy(receipt['discovery_binding']),
        'publisher_binding': copy.deepcopy(receipt['publisher_binding']),
        'invocation_binding': copy.deepcopy(receipt['invocation_binding']),
        'probe_binding': copy.deepcopy(receipt['probe_binding']),
        'policy_binding': copy.deepcopy(receipt['policy_binding']),
        'expected_outcomes': copy.deepcopy(receipt['expected_outcomes']),
        'previous_applied_binding': copy.deepcopy(previous_applied_binding), 'created_at': created_at}
    candidate['enforcement_digest'] = sha256_json(candidate)
    return candidate


def verify_enforcement_candidate(candidate, *, receipt, publication):
    candidate = copy.deepcopy(candidate)
    required = {'schema_version', 'kind', 'application_id', 'object_id', 'publication_id',
        'publication_digest', 'publication_ref', 'delegation_receipt_id',
        'delegation_receipt_digest', 'delegation_receipt_ref', 'adapter_id',
        'adapter_version', 'adapter_registration_hash', 'connection_id', 'connection_mode',
        'profile_id', 'boundary_binding', 'execution_binding', 'discovery_binding', 'publisher_binding',
        'invocation_binding',
        'probe_binding', 'policy_binding',
        'expected_outcomes', 'previous_applied_binding', 'created_at', 'enforcement_digest'}
    _exact(candidate, required, 'Enforcement candidate')
    digest = candidate.pop('enforcement_digest')
    if not HASH.fullmatch(digest) or sha256_json(candidate) != digest:
        raise ValueError('Enforcement candidate digest differs')
    candidate['enforcement_digest'] = digest
    if not re.fullmatch(r'application-[0-9a-f]{32}', candidate['application_id']):
        raise ValueError('Application ID is invalid')
    expected = {'schema_version': '1.0', 'kind': 'ENFORCEMENT_CANDIDATE',
        'object_id': receipt['object_id'], 'publication_id': publication['publication_id'],
        'publication_digest': publication['digest'], 'publication_ref': publication['ref'],
        'delegation_receipt_id': receipt['receipt_id'],
        'delegation_receipt_digest': receipt['digest'],
        'delegation_receipt_ref': receipt['ref'], 'adapter_id': receipt['adapter_id'],
        'adapter_version': receipt['adapter_version'],
        'adapter_registration_hash': receipt['adapter_registration_hash'],
        'connection_id': receipt['connection_id'], 'connection_mode': receipt['connection_mode'],
        'profile_id': receipt['profile_id'], 'boundary_binding': receipt['boundary_binding'],
        'execution_binding': receipt['execution_binding'], 'policy_binding': receipt['policy_binding'],
        'discovery_binding': receipt['discovery_binding'],
        'publisher_binding': receipt['publisher_binding'], 'probe_binding': receipt['probe_binding'],
        'invocation_binding': receipt['invocation_binding'],
        'expected_outcomes': receipt['expected_outcomes']}
    if any(candidate.get(k) != v for k, v in expected.items()):
        raise ValueError('Enforcement candidate differs from its immutable authorities')
    _timestamp(candidate['created_at'], 'candidate created_at')
    return candidate


def verify_publisher_result(value, candidate):
    """Accept only exact, correlated publisher evidence; this does not emulate AWS."""
    value = copy.deepcopy(value)
    required = {'schema_version', 'status', 'application_id', 'enforcement_digest',
        'policy_id', 'policy_name', 'policy_hash', 'observed_at', 'checks',
        'previous_binding_status', 'closed_outcomes', 'outcomes', 'publisher_invocation'}
    _exact(value, required, 'Publisher result')
    if value['schema_version'] != '1.0' or value['status'] not in ('VERIFIED', 'RECOVERED_CLOSED'):
        raise ValueError('Publisher result status is not terminal and verified')
    if (value['application_id'] != candidate['application_id']
            or value['enforcement_digest'] != candidate['enforcement_digest']
            or value['policy_hash'] != candidate['policy_binding']['policy_hash']):
        raise ValueError('Publisher result does not match the enforcement candidate')
    _nonempty(value['policy_id'], 'Policy ID', 160)
    expected_name = 'AuthorityDeltaApp_' + candidate['enforcement_digest'][:16]
    if value['policy_name'] != expected_name:
        raise ValueError('Publisher result policy name does not identify this candidate')
    invocation = _exact(value['publisher_invocation'], {
        'function_arn', 'request_id', 'http_status', 'executed_version',
        'invoke_role_arn', 'assume_role_request_id'},
        'Publisher invocation')
    if (invocation['function_arn'] != candidate['publisher_binding']['function_arn']
            or invocation['invoke_role_arn'] != candidate['publisher_binding']['invoke_role_arn']
            or type(invocation['http_status']) is not int or invocation['http_status'] != 200
            or not isinstance(invocation['request_id'], str) or not invocation['request_id']
            or not isinstance(invocation['assume_role_request_id'], str)
            or not invocation['assume_role_request_id']
            or not isinstance(invocation['executed_version'], str)
            or not invocation['executed_version']):
        raise ValueError('Publisher invocation is not exact successful AWS evidence')
    if (candidate['connection_mode'] == 'LIVE_CUSTOMER'
            and invocation['assume_role_request_id'] == 'LOCAL_NOT_ASSUMED'):
        raise ValueError('Live customer publisher invocation did not use STS')
    if _timestamp(value['observed_at'], 'observed_at') < _timestamp(candidate['created_at'], 'candidate created_at'):
        raise ValueError('Publisher result predates the enforcement candidate')
    checks = _exact(value['checks'], {'candidate_closed_before_write', 'policy_active_readback',
        'same_runtime_role_policy_for_canary', 'candidate_cleanup_readback'}, 'Publisher checks')
    if any(type(item) is not bool for item in checks.values()):
        raise ValueError('Publisher checks must be observed booleans')
    expected = {x['request_id']: x['expected_outcome'] for x in candidate['expected_outcomes']}
    def checked_outcomes(outcomes, label):
        if not isinstance(outcomes, list) or len(outcomes) != len(expected):
            raise ValueError(label + ' outcomes are incomplete')
        seen = set()
        for item in outcomes:
            _exact(item, {'request_id', 'outcome', 'evidence_hash'}, label + ' outcome')
            if (item['request_id'] in seen or item['request_id'] not in expected
                    or item['outcome'] not in ('ALLOW', 'DENY')
                    or not HASH.fullmatch(item['evidence_hash'])):
                raise ValueError(label + ' outcome is malformed, foreign or duplicated')
            seen.add(item['request_id'])
        return outcomes
    closed = checked_outcomes(value['closed_outcomes'], 'Closed-canary')
    outcomes = checked_outcomes(value['outcomes'], 'Publisher')
    if any(item['outcome'] != 'DENY' for item in closed):
        raise ValueError('Deny-first canary was not closed before the policy write')
    prior = candidate['previous_applied_binding']
    required_previous = ('RETIRED' if value['status'] == 'VERIFIED' and prior else
                         'PRESERVED' if value['status'] == 'RECOVERED_CLOSED' and prior else 'NONE')
    if value['previous_binding_status'] != required_previous:
        raise ValueError('Previous AppliedBinding disposition was not proven')
    if value['status'] == 'VERIFIED':
        if (not checks['candidate_closed_before_write'] or not checks['policy_active_readback']
                or not checks['same_runtime_role_policy_for_canary'] or checks['candidate_cleanup_readback']
                or any(item['outcome'] != expected[item['request_id']] for item in outcomes)):
            raise ValueError('Publisher did not prove the registered canary plan')
    else:
        if (not checks['candidate_cleanup_readback'] or checks['policy_active_readback']
                or any(item['outcome'] != 'DENY' for item in outcomes)):
            raise ValueError('Publisher did not prove closed recovery')
    return value
