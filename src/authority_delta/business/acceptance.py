"""Portable, redacted evidence for integrated ReadinessOps acceptance.

The service validates immutable source records before calling this module.  The
portable projection deliberately replaces connector ExternalIds with hashes and
does not grant, publish or apply authority.
"""
from __future__ import annotations

import copy
import hashlib
import re

from authority_delta.canonical import canonicalize, sha256_json
from .interchange import verify_outcome


COLLECTIONS_V1 = ('evidence', 'assessments', 'decisions', 'actions', 'delegations',
                  'applications', 'outcomes', 'imports', 'history')
COLLECTIONS_V11 = COLLECTIONS_V1 + ('revocations', 'invocations')
MAX_EXPORT_BYTES = 5_200_000


def _redact(value):
    if isinstance(value, list):
        return [_redact(item) for item in value]
    if not isinstance(value, dict):
        return copy.deepcopy(value)
    result = {}
    for key, item in value.items():
        if key == 'external_id':
            if 'external_id_sha256' in value:
                raise ValueError('ExternalId projection field is ambiguous')
            if not isinstance(item, str) or not item:
                raise ValueError('ExternalId is invalid')
            result['external_id_sha256'] = hashlib.sha256(item.encode()).hexdigest()
        else:
            result[key] = _redact(item)
    return result


def projected(value):
    """Bind a safe projection to both its source and projected content hashes."""
    document = _redact(value)
    return {'source_sha256': sha256_json(value),
            'projection_sha256': sha256_json(document), 'document': document}


def build_acceptance_evidence(*, object_record, evidence, assessments, decisions,
                              actions, delegations, applications, outcomes,
                              imports, history, available_adapters,
                              revocations=None, invocations=None):
    revocations = list(revocations or [])
    invocations = list(invocations or [])
    value = {
        'schema_version': '1.1' if revocations or invocations else '1.0',
        'kind': 'READINESSOPS_ACCEPTANCE_EVIDENCE',
        'scope': 'AUTHENTICATED_READ_ONLY_OBJECT_EXPORT',
        'source_authority': 'aws:solifan',
        'workspace_id': object_record['workspace_id'],
        'object_id': object_record['object_id'],
        'runtime_authority_changed_by_export': False,
        'object': projected(object_record),
        'evidence': [projected(item) for item in evidence],
        'assessments': [projected(item) for item in assessments],
        'decisions': [projected(item) for item in decisions],
        'actions': [projected(item) for item in actions],
        'delegations': [projected(item) for item in delegations],
        'applications': [projected(item) for item in applications],
        'outcomes': [projected(item) for item in outcomes],
        'imports': [projected(item) for item in imports],
        'history': [projected(item) for item in history],
        'available_adapters': copy.deepcopy(available_adapters),
    }
    if revocations or invocations:
        value['revocations'] = [projected(item) for item in revocations]
        value['invocations'] = [projected(item) for item in invocations]
    value['document_digest'] = sha256_json(value)
    return verify_acceptance_evidence(value)


def _contains_key(value, forbidden):
    if isinstance(value, dict):
        return forbidden in value or any(_contains_key(v, forbidden)
                                         for v in value.values())
    return isinstance(value, list) and any(_contains_key(v, forbidden) for v in value)


def _unwrap(value, label):
    if (not isinstance(value, dict)
            or set(value) != {'source_sha256', 'projection_sha256', 'document'}
            or not re.fullmatch(r'[0-9a-f]{64}', str(value.get('source_sha256')))
            or not re.fullmatch(r'[0-9a-f]{64}', str(value.get('projection_sha256')))
            or sha256_json(value.get('document')) != value.get('projection_sha256')):
        raise ValueError(label + ' projection digest differs')
    if _contains_key(value['document'], 'external_id'):
        raise ValueError(label + ' exposes a connector ExternalId')
    return value['document']


def _unique(values, key, label):
    identifiers = [value.get(key) for value in values]
    if any(not isinstance(value, str) or not value for value in identifiers):
        raise ValueError(label + ' identifier is missing')
    if len(identifiers) != len(set(identifiers)):
        raise ValueError(label + ' identifiers are duplicated')
    return set(identifiers)


def verify_acceptance_evidence(value):
    """Verify projection integrity and the cross-record object/version chain."""
    version = value.get('schema_version') if isinstance(value, dict) else None
    collections_spec = COLLECTIONS_V11 if version == '1.1' else COLLECTIONS_V1
    required = {'schema_version', 'kind', 'scope', 'source_authority',
        'workspace_id', 'object_id', 'runtime_authority_changed_by_export',
        'object', *collections_spec, 'available_adapters', 'document_digest'}
    if (not isinstance(value, dict) or set(value) != required
            or version not in ('1.0', '1.1')
            or value.get('kind') != 'READINESSOPS_ACCEPTANCE_EVIDENCE'
            or value.get('scope') != 'AUTHENTICATED_READ_ONLY_OBJECT_EXPORT'
            or value.get('source_authority') != 'aws:solifan'
            or value.get('runtime_authority_changed_by_export') is not False
            or not re.fullmatch(r'o-[0-9a-f]{32}', str(value.get('object_id')))
            or sha256_json({k: v for k, v in value.items()
                            if k != 'document_digest'}) != value.get('document_digest')):
        raise ValueError('Acceptance evidence fields or document digest differ')
    if len(canonicalize(value)) > MAX_EXPORT_BYTES:
        raise ValueError('Acceptance evidence exceeds the single-download limit')
    if any(not isinstance(value[name], list) or len(value[name]) > 80
           for name in collections_spec):
        raise ValueError('Acceptance evidence collection is invalid or unbounded')
    if not isinstance(value['available_adapters'], list) or len(value['available_adapters']) > 8:
        raise ValueError('Acceptance adapter projection is invalid')

    oid, workspace = value['object_id'], value['workspace_id']
    head = _unwrap(value['object'], 'object')
    if (head.get('object_id'), head.get('workspace_id')) != (oid, workspace):
        raise ValueError('Acceptance object identity differs')
    collections = {name: [_unwrap(item, name) for item in value[name]]
                   for name in collections_spec}
    for name, items in collections.items():
        if any(item.get('object_id') != oid for item in items):
            raise ValueError(name + ' contains a foreign object')

    evidence_ids = _unique(collections['evidence'], 'evidence_id', 'Evidence')
    run_ids = _unique((item['state'] for item in collections['assessments']),
                      'run_id', 'Assessment')
    publication_ids = _unique((item['publication'] for item in collections['decisions']),
                              'publication_id', 'Publication')
    receipt_ids = _unique((item['approval_receipt'] for item in collections['decisions']),
                          'receipt_id', 'Approval receipt')
    delegation_ids = _unique(collections['delegations'], 'receipt_id', 'Delegation receipt')
    application_ids = _unique((item['state'] for item in collections['applications']),
                              'application_id', 'Application')
    revocation_ids = (_unique((item['state'] for item in collections.get('revocations', [])),
                              'revocation_id', 'Revocation')
                      if collections.get('revocations') else set())
    invocation_ids = (_unique((item['state'] for item in collections.get('invocations', [])),
                              'operation_id', 'Invocation')
                      if collections.get('invocations') else set())
    _unique(collections['actions'], 'action_id', 'Action')
    _unique(collections['outcomes'], 'outcome_id', 'Outcome')
    _unique(collections['history'], 'event_id', 'History event')

    previous = None
    for item in collections['decisions']:
        publication, pack, receipt = (item['publication'], item['decision_pack'],
                                      item['approval_receipt'])
        if (publication.get('previous_publication_id') != previous
                or pack.get('run_id') not in run_ids
                or publication.get('receipt_id') != receipt.get('receipt_id')
                or publication.get('published_by') != receipt.get('approver_sub')
                or receipt.get('decision') != 'APPROVE'
                or receipt.get('runtime_authority_granted') is not False
                or (publication.get('pack_id'), publication.get('revision'),
                    publication.get('digest')) !=
                   (pack.get('pack_id'), pack.get('revision'), pack.get('digest'))
                or receipt.get('digest') != pack.get('digest')):
            raise ValueError('Decision publication, pack or approval chain differs')
        previous = publication['publication_id']
    current = head.get('published_current')
    if current is not None and (not publication_ids
            or current.get('publication_id') != previous):
        raise ValueError('PublishedCurrent is not the final exported publication')

    for item in collections['assessments']:
        state, snapshot = item['state'], item['input_snapshot']
        if (snapshot.get('object_id') != oid
                or snapshot.get('input_hash') != state.get('input_hash')):
            raise ValueError('Assessment state differs from its input snapshot')
        selected = {e.get('evidence_id') for e in snapshot.get('evidence', [])}
        if not selected or not selected.issubset(evidence_ids):
            raise ValueError('Assessment references missing evidence')
        if snapshot.get('mode') == 'REASSESSMENT':
            prior = snapshot.get('prior_publication', {}).get('publication', {})
            if prior.get('publication_id') not in publication_ids:
                raise ValueError('Reassessment prior publication is missing')
        if item.get('analysis') is not None and item['analysis'].get('input_hash') != state.get('input_hash'):
            raise ValueError('Assessment result differs from its input')

    for receipt in collections['delegations']:
        if (receipt.get('publication_id') not in publication_ids
                or receipt.get('runtime_authority_active') is not False
                or receipt.get('decision') != 'APPROVE_DELEGATION'):
            raise ValueError('Delegation is not bound to an exported publication')
    for item in collections['applications']:
        state, candidate = item['state'], item['candidate']
        if (state.get('publication_id') not in publication_ids
                or state.get('delegation_receipt_id') not in delegation_ids
                or candidate.get('application_id') != state.get('application_id')
                or candidate.get('enforcement_digest') != state.get('enforcement_digest')):
            raise ValueError('Application authority chain differs')
        result = item.get('publisher_result')
        if state.get('status') in {'VERIFIED', 'RECOVERED_CLOSED'} and result is None:
            raise ValueError('Terminal application result is missing')
        if result is not None and (result.get('application_id') != state.get('application_id')
                or result.get('enforcement_digest') != state.get('enforcement_digest')
                or result.get('status') != state.get('status')):
            raise ValueError('Application result differs from terminal state')
    for item in collections.get('revocations', []):
        state, request = item['state'], item['request']
        if (state.get('application_id') not in application_ids
                or request.get('revocation_id') != state.get('revocation_id')
                or request.get('digest') != state.get('revocation_digest')
                or request.get('application_id') != state.get('application_id')
                or request.get('enforcement_digest') != state.get('enforcement_digest')
                or request.get('revocation_id') not in revocation_ids
                or state.get('entry_status') != 'CLOSED'):
            raise ValueError('Revocation authority chain differs')
        result = item.get('publisher_result')
        if state.get('status') == 'SUSPENDED_CONFIRMED' and result is None:
            raise ValueError('Confirmed revocation result is missing')
        if result is not None and (result.get('revocation_id') != state.get('revocation_id')
                or result.get('revocation_digest') != state.get('revocation_digest')
                or result.get('status') != 'POLICY_REMOVED_DENY_CONFIRMED'):
            raise ValueError('Revocation result differs from terminal state')
    application_candidates = {item['state']['application_id']: item['candidate']
                              for item in collections['applications']}
    for item in collections.get('invocations', []):
        state, result = item['state'], item.get('result')
        candidate = application_candidates.get(state.get('application_id'))
        if (state.get('operation_id') not in invocation_ids or candidate is None
                or state.get('kind') != 'CONTROLLED_INVOCATION'
                or state.get('enforcement_digest') != candidate.get('enforcement_digest')
                or state.get('fingerprint') != sha256_json({
                    'object_id': oid, 'request_id': state.get('request_id')})
                or state.get('status') not in ('ACCEPTED', 'UNKNOWN', 'EXECUTED')
                or type(state.get('delegation_generation')) is not int
                or state['delegation_generation'] < 1):
            raise ValueError('Controlled invocation authority chain differs')
        if state['status'] == 'EXECUTED':
            transport = (result.get('invocation_transport', {})
                         if isinstance(result, dict) else {})
            binding = candidate.get('invocation_binding', {})
            if (not isinstance(result, dict)
                    or result.get('status') != 'EXECUTED'
                    or result.get('application_id') != state['application_id']
                    or result.get('enforcement_digest') != state['enforcement_digest']
                    or result.get('request_id') != state['request_id']
                    or result.get('outcome') != 'ALLOW'
                    or result.get('accepted_at') != state.get('accepted_at')
                    or result.get('authority_generation')
                        != state['delegation_generation']
                    or not isinstance(result.get('evidence'), dict)
                    or result.get('evidence_hash') != sha256_json(result.get('evidence'))
                    or transport.get('function_arn') != binding.get('function_arn')
                    or transport.get('invoke_role_arn') != binding.get('invoke_role_arn')
                    or transport.get('http_status') != 200):
                raise ValueError('Controlled invocation result differs')
        elif result is not None:
            raise ValueError('Incomplete invocation exposes a terminal result')
    for outcome in collections['outcomes']:
        verify_outcome(outcome)
        if outcome['publication_id'] not in publication_ids:
            raise ValueError('Outcome publication is missing')
        target = outcome['target']
        if target['kind'] == 'AWS_APPLICATION' and target['id'] not in application_ids:
            raise ValueError('Outcome application is missing')
    for action in collections['actions']:
        resolution_ids = {item.get('evidence_id')
                          for item in action.get('resolution_evidence', [])}
        if (action.get('publication_id') not in publication_ids
                or not set(action.get('baseline_evidence_ids', [])).issubset(evidence_ids)
                or not resolution_ids.issubset(evidence_ids)
                or (action.get('reassessment_run_id') is not None
                    and action['reassessment_run_id'] not in run_ids)):
            raise ValueError('Action evidence or reassessment chain differs')
    if any(event.get('actor_sub') is None for event in collections['history']):
        raise ValueError('History event has no authenticated actor')
    if collections['history'] != sorted(collections['history'],
            key=lambda event: (event.get('at', ''), event.get('event_id', ''))):
        raise ValueError('History events are not chronologically ordered')
    applied = head.get('applied_binding')
    if applied is not None and (applied.get('application_id') not in application_ids
            or applied.get('publication_id') not in publication_ids
            or applied.get('runtime_authority_active') is not True):
        raise ValueError('AppliedBinding is not backed by exported authority evidence')
    control = head.get('authority_control')
    if control is not None:
        if (control.get('entry_status') == 'OPEN'
                and control.get('runtime_authority_active') is not True):
            raise ValueError('Open authority control is not active')
        if control.get('entry_status') == 'CLOSED':
            if (control.get('runtime_authority_active') is not False
                    or control.get('revocation_id') not in revocation_ids):
                raise ValueError('Closed authority control lacks exported revocation evidence')
            if (control.get('status') == 'SUSPENDED_CONFIRMED'
                    and control.get('deny_status') != 'CONFIRMED'):
                raise ValueError('Confirmed suspension lacks DENY evidence')
    if receipt_ids and not publication_ids:
        raise ValueError('Approval receipts are not published')
    return copy.deepcopy(value)
