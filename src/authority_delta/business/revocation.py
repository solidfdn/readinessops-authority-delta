"""Typed, digest-bound lifecycle records for applied AWS authority revocation.

STOP_REQUESTED closes the product-controlled entry and invalidates the current
delegation generation.  It is deliberately not proof that the customer Policy
has been removed.  Only a qualified account-B result with Policy absence and a
real all-DENY canary can be promoted to SUSPENDED_CONFIRMED by account A.
"""
from __future__ import annotations

import copy
import json
import re
import uuid
from datetime import datetime, timedelta

from authority_delta.canonical import sha256_json
from authority_delta.gateway_probe import policy_denial
from .storage import Conflict, encode


HASH = re.compile(r'^[0-9a-f]{64}$')


def _exact(value, fields, label):
    if not isinstance(value, dict) or set(value) != set(fields):
        raise ValueError(label + ' fields differ')
    return value


def _text(value, label, maximum=1600):
    if not isinstance(value, str) or not 1 <= len(value.strip()) <= maximum or '\x00' in value:
        raise ValueError(label + ' is invalid')
    return value.strip()


def build_revocation_request(*, revocation_id, candidate, applied_binding, trigger,
        reason, actor, requested_at, invalidated_generation):
    if not re.fullmatch(r'revocation-[0-9a-f]{32}', revocation_id):
        raise ValueError('Revocation ID is invalid')
    if trigger not in ('MANUAL', 'EXPIRY'):
        raise ValueError('Revocation trigger is invalid')
    if type(invalidated_generation) is not int or invalidated_generation < 1:
        raise ValueError('Invalidated delegation generation is invalid')
    if (not isinstance(applied_binding, dict)
            or applied_binding.get('application_id') != candidate.get('application_id')
            or applied_binding.get('enforcement_digest') != candidate.get('enforcement_digest')
            or applied_binding.get('policy_id') is None
            or applied_binding.get('digest') is None):
        raise ValueError('Applied binding does not match the revocation candidate')
    request = {'schema_version': '1.0', 'kind': 'AUTHORITY_REVOCATION_REQUEST',
        'revocation_id': revocation_id, 'object_id': candidate['object_id'],
        'application_id': candidate['application_id'],
        'enforcement_digest': candidate['enforcement_digest'],
        'applied_binding_digest': applied_binding['digest'],
        'delegation_receipt_id': candidate['delegation_receipt_id'],
        'delegation_receipt_digest': candidate['delegation_receipt_digest'],
        'connection_id': candidate['connection_id'],
        'policy_engine_id': candidate['execution_binding']['policy_engine_id'],
        'policy_id': applied_binding['policy_id'],
        'policy_name': applied_binding['policy_name'],
        'policy_hash': applied_binding['policy_hash'],
        'invalidated_generation': invalidated_generation,
        'trigger': trigger, 'reason': _text(reason, 'Revocation reason'),
        'requested_by_sub': _text(actor.get('sub'), 'Revocation actor subject', 160),
        'requested_by_name': _text(actor.get('name'), 'Revocation actor name', 160),
        'requested_at': _text(requested_at, 'Revocation requested_at', 80)}
    request['digest'] = sha256_json(request)
    return verify_revocation_request(request, candidate=candidate,
                                     applied_binding=applied_binding)


def verify_revocation_request(value, *, candidate, applied_binding=None):
    value = copy.deepcopy(value)
    fields = {'schema_version', 'kind', 'revocation_id', 'object_id',
        'application_id', 'enforcement_digest', 'applied_binding_digest',
        'delegation_receipt_id', 'delegation_receipt_digest', 'connection_id',
        'policy_engine_id', 'policy_id', 'policy_name', 'policy_hash',
        'invalidated_generation', 'trigger', 'reason', 'requested_by_sub',
        'requested_by_name', 'requested_at', 'digest'}
    _exact(value, fields, 'Revocation request')
    digest = value.pop('digest')
    if not HASH.fullmatch(str(digest)) or sha256_json(value) != digest:
        raise ValueError('Revocation request digest differs')
    value['digest'] = digest
    if (value['schema_version'] != '1.0'
            or value['kind'] != 'AUTHORITY_REVOCATION_REQUEST'
            or not re.fullmatch(r'revocation-[0-9a-f]{32}', str(value['revocation_id']))
            or value['trigger'] not in ('MANUAL', 'EXPIRY')
            or type(value['invalidated_generation']) is not int
            or value['invalidated_generation'] < 1):
        raise ValueError('Revocation request identity differs')
    expected = {'object_id': candidate.get('object_id'),
        'application_id': candidate.get('application_id'),
        'enforcement_digest': candidate.get('enforcement_digest'),
        'delegation_receipt_id': candidate.get('delegation_receipt_id'),
        'delegation_receipt_digest': candidate.get('delegation_receipt_digest'),
        'connection_id': candidate.get('connection_id'),
        'policy_engine_id': candidate.get('execution_binding', {}).get('policy_engine_id')}
    if any(value.get(k) != v for k, v in expected.items()):
        raise ValueError('Revocation request differs from its immutable candidate')
    if applied_binding is not None:
        binding = {'applied_binding_digest': applied_binding.get('digest'),
            'policy_id': applied_binding.get('policy_id'),
            'policy_name': applied_binding.get('policy_name'),
            'policy_hash': applied_binding.get('policy_hash')}
        if any(value.get(k) != v for k, v in binding.items()):
            raise ValueError('Revocation request differs from the AppliedBinding')
    for field, maximum in (('reason', 1600), ('requested_by_sub', 160),
                           ('requested_by_name', 160), ('requested_at', 80)):
        _text(value[field], field, maximum)
    return value


def verify_revocation_result(value, request, candidate):
    value = copy.deepcopy(value)
    fields = {'schema_version', 'kind', 'status', 'revocation_id',
        'revocation_digest', 'application_id', 'enforcement_digest', 'policy_id',
        'policy_name', 'policy_hash', 'observed_at', 'checks', 'outcomes',
        'publisher_invocation'}
    _exact(value, fields, 'Revocation result')
    if (value['schema_version'] != '1.0'
            or value['kind'] != 'AUTHORITY_REVOCATION_RESULT'
            or value['status'] != 'POLICY_REMOVED_DENY_CONFIRMED'):
        raise ValueError('Revocation result is not terminal customer evidence')
    expected = {'revocation_id': request['revocation_id'],
        'revocation_digest': request['digest'],
        'application_id': candidate['application_id'],
        'enforcement_digest': candidate['enforcement_digest'],
        'policy_id': request['policy_id'], 'policy_name': request['policy_name'],
        'policy_hash': request['policy_hash']}
    if any(value.get(k) != v for k, v in expected.items()):
        raise ValueError('Revocation result differs from its request')
    checks = _exact(value['checks'], {'owned_policy_readback',
        'delete_intent_journaled', 'policy_absent_readback'}, 'Revocation checks')
    if any(checks.get(k) is not True for k in checks):
        raise ValueError('Revocation checks are incomplete')
    registered = {item['request_id'] for item in candidate['expected_outcomes']}
    outcomes = value['outcomes']
    if (not isinstance(outcomes, list) or len(outcomes) != len(registered)
            or {item.get('request_id') for item in outcomes} != registered
            or any(set(item) != {'request_id', 'outcome', 'evidence_hash', 'evidence'}
                   or item['outcome'] != 'DENY'
                   or not HASH.fullmatch(str(item['evidence_hash']))
                   or not isinstance(item.get('evidence'), dict)
                   or sha256_json(item['evidence']) != item['evidence_hash']
                   for item in outcomes)):
        raise ValueError('Revocation did not prove the complete registered DENY set')
    runtime = candidate['execution_binding']['runtime']
    for item in outcomes:
        evidence = item['evidence']
        before, after = (evidence.get('before_ledger_hash'),
                         evidence.get('after_ledger_hash'))
        endpoints = (evidence.get('endpoint_before'), evidence.get('endpoint_after'))
        if (evidence.get('outcome') != 'DENY'
                or not isinstance(evidence.get('runtime_request_id'), str)
                or not evidence['runtime_request_id']
                or evidence.get('principal') != candidate['policy_binding']['principal_id']
                or not HASH.fullmatch(str(before)) or before != after
                or not policy_denial(evidence.get('gateway_response', {}),
                                     evidence.get('mcp_id'))
                or any(not isinstance(endpoint, dict)
                       or endpoint.get('endpoint_arn') != runtime['endpoint_arn']
                       or endpoint.get('live_version') != runtime['runtime_version']
                       or not endpoint.get('request_id') for endpoint in endpoints)):
            raise ValueError('Revocation DENY evidence is incomplete or differs')
    invocation = _exact(value['publisher_invocation'], {'function_arn', 'request_id',
        'http_status', 'executed_version', 'invoke_role_arn',
        'assume_role_request_id'}, 'Revocation publisher invocation')
    binding = candidate['publisher_binding']
    if (invocation['function_arn'] != binding['function_arn']
            or invocation['invoke_role_arn'] != binding['invoke_role_arn']
            or invocation['http_status'] != 200
            or not all(isinstance(invocation[k], str) and invocation[k]
                       for k in ('request_id', 'executed_version',
                                 'assume_role_request_id'))):
        raise ValueError('Revocation publisher invocation is not exact successful evidence')
    if (candidate['connection_mode'] == 'LIVE_CUSTOMER'
            and invocation['assume_role_request_id'] == 'LOCAL_NOT_ASSUMED'):
        raise ValueError('Live revocation did not use the registered STS connector')
    observed_at = _text(value['observed_at'], 'Revocation observed_at', 80)
    try:
        if datetime.fromisoformat(observed_at) < datetime.fromisoformat(request['requested_at']):
            raise ValueError('Revocation result predates its request')
    except (TypeError, ValueError) as exc:
        raise ValueError('Revocation observed_at is invalid') from exc
    return value


def revocation_message(request):
    return {'operation': 'REVOKE', 'object_id': request['object_id'],
        'application_id': request['application_id'],
        'enforcement_digest': request['enforcement_digest'],
        'revocation_id': request['revocation_id'],
        'revocation_digest': request['digest']}


def revocation_state(request, request_ref, applied_binding, lock_pk):
    return {'schema_version': '1.0', 'kind': 'AUTHORITY_REVOCATION',
        'revocation_id': request['revocation_id'], 'object_id': request['object_id'],
        'application_id': request['application_id'],
        'enforcement_digest': request['enforcement_digest'],
        'revocation_digest': request['digest'], 'trigger': request['trigger'],
        'status': 'STOP_REQUESTED', 'entry_status': 'CLOSED',
        'entry_closed_at': request['requested_at'], 'created_at': request['requested_at'],
        'updated_at': request['requested_at'], 'attempt': 0, 'lease_until': None,
        'next_attempt_at': None,
        'request_ref': copy.deepcopy(request_ref),
        'applied_binding': copy.deepcopy(applied_binding), 'lock_pk': lock_pk,
        'result_ref': None, 'last_error': None}


def expiry_revocation_id(application_id, expires_at):
    seed = sha256_json({'application_id': application_id, 'expires_at': expires_at})
    return 'revocation-' + uuid.UUID(seed[:32]).hex


class RevocationWorker:
    """Serialize applied-authority removal with the application writer lock."""

    def __init__(self, db, blobs, publisher, adapters, clock):
        self.db, self.blobs, self.publisher, self.clock = db, blobs, publisher, clock
        self.adapters = {(item['adapter_id'], item['connection_id']): item
                         for item in adapters}

    def _load(self, message):
        if (not isinstance(message, dict)
                or set(message) != {'operation', 'object_id', 'application_id',
                                    'enforcement_digest', 'revocation_id',
                                    'revocation_digest'}
                or message.get('operation') != 'REVOKE'
                or not re.fullmatch(r'o-[0-9a-f]{32}', str(message.get('object_id')))
                or not re.fullmatch(r'application-[0-9a-f]{32}',
                                    str(message.get('application_id')))
                or not HASH.fullmatch(str(message.get('enforcement_digest')))
                or not re.fullmatch(r'revocation-[0-9a-f]{32}',
                                    str(message.get('revocation_id')))
                or not HASH.fullmatch(str(message.get('revocation_digest')))):
            raise ValueError('Revocation message is invalid')
        oid, rid, aid = (message['object_id'], message['revocation_id'],
                         message['application_id'])
        state = self.db.get('app', oid, 'REVOCATION#' + rid)
        application = self.db.get('app', oid, 'APPLICATION#' + aid)
        head = self.db.get('app', oid, 'HEAD')
        if state is None or application is None or head is None:
            raise ValueError('Revocation authority state is missing')
        if (state.value.get('revocation_digest') != message['revocation_digest']
                or state.value.get('enforcement_digest') != message['enforcement_digest']
                or application.value.get('enforcement_digest') != message['enforcement_digest']):
            raise ValueError('Revocation message differs from committed authority state')
        candidate = json.loads(self.blobs.read(application.value['candidate_ref']))
        if (candidate.get('application_id') != aid
                or candidate.get('enforcement_digest') != message['enforcement_digest']
                or sha256_json({k: v for k, v in candidate.items()
                                if k != 'enforcement_digest'})
                    != candidate['enforcement_digest']):
            raise ValueError('Revocation candidate digest differs')
        applied = state.value.get('applied_binding')
        if (not isinstance(applied, dict)
                or sha256_json({k: v for k, v in applied.items() if k != 'digest'})
                    != applied.get('digest')):
            raise ValueError('Revocation AppliedBinding digest differs')
        request = json.loads(self.blobs.read(state.value['request_ref']))
        request = verify_revocation_request(request, candidate=candidate,
                                            applied_binding=applied)
        if request['digest'] != message['revocation_digest']:
            raise ValueError('Revocation request does not match its message')
        return state, application, head, candidate, request

    def _requeue(self, state, message):
        row = self.db.get('jobs', 'APPLICATION_OUTBOX', state.value['revocation_id'])
        if row is not None and row.value != message:
            raise ValueError('Revocation recovery outbox differs')
        if row is None:
            try:
                self.db.transact([('jobs', 'APPLICATION_OUTBOX',
                    state.value['revocation_id'], message, None)])
            except Conflict:
                pass

    def _claim(self, state, message):
        stamp = datetime.fromisoformat(self.clock())
        lock = self.db.get('app', state.value['lock_pk'], 'WRITER')
        if lock is not None and lock.value.get('revocation_id') != state.value['revocation_id']:
            self._requeue(state, message)
            return None
        lease = state.value.get('lease_until')
        if (state.value['status'] == 'REVOKING' and lease
                and stamp < datetime.fromisoformat(lease)):
            return None
        claimed = dict(state.value, status='REVOKING', updated_at=stamp.isoformat(),
                       attempt=state.value['attempt'] + 1,
                       lease_until=(stamp + timedelta(minutes=12)).isoformat(),
                       next_attempt_at=None, last_error=None)
        writer = {'revocation_id': state.value['revocation_id'],
            'object_id': state.value['object_id'],
            'application_id': state.value['application_id'],
            'enforcement_digest': state.value['enforcement_digest'],
            'acquired_at': stamp.isoformat()}
        writes = [('app', state.value['object_id'],
            'REVOCATION#' + state.value['revocation_id'], claimed, state.version)]
        if lock is None:
            writes.append(('app', state.value['lock_pk'], 'WRITER', writer, None))
        try:
            self.db.transact(writes)
        except Conflict:
            self._requeue(state, message)
            return None
        return self.db.get('app', state.value['object_id'],
                           'REVOCATION#' + state.value['revocation_id'])

    def _unknown(self, claimed, message, error):
        stamp = datetime.fromisoformat(self.clock())
        value = dict(claimed.value, status='UNKNOWN', updated_at=stamp.isoformat(),
                     lease_until=None,
                     next_attempt_at=None,
                     last_error=str(error)[:450]
                     or 'Customer Policy removal was not confirmed')
        try:
            self.db.transact([('app', value['object_id'],
                'REVOCATION#' + value['revocation_id'], value, claimed.version)])
        except Conflict:
            current = self.db.get('app', value['object_id'],
                                  'REVOCATION#' + value['revocation_id'])
            return current.value if current else value
        current = self.db.get('app', value['object_id'],
                              'REVOCATION#' + value['revocation_id'])
        self._requeue(current, message)
        for _ in range(3):
            head = self.db.get('app', value['object_id'], 'HEAD')
            control = head.value.get('authority_control') if head else None
            if not head or not control or control.get('revocation_id') != value['revocation_id']:
                break
            updated_control = dict(control, status='UNKNOWN', updated_at=self.clock(),
                                   last_error=value['last_error'])
            try:
                self.db.transact([('app', value['object_id'], 'HEAD',
                    dict(head.value, application_status='STOP_UNKNOWN',
                         authority_control=updated_control), head.version)])
                break
            except Conflict:
                continue
        return value

    def delivery_failed(self, message, error):
        """Record an unhandled DLQ delivery without claiming confirmed suspension."""
        try:
            state, _, _, _, _ = self._load(message)
        except Exception:
            return None
        if state.value['status'] == 'SUSPENDED_CONFIRMED':
            return state.value
        stamp = datetime.fromisoformat(self.clock())
        value = dict(state.value, status='UNKNOWN', updated_at=stamp.isoformat(),
                     lease_until=None, attempt=state.value.get('attempt', 0) + 1,
                     next_attempt_at=None,
                     last_error=('Revocation delivery failed: ' + str(error))[:450])
        try:
            self.db.transact([('app', value['object_id'],
                'REVOCATION#' + value['revocation_id'], value, state.version)])
        except Conflict:
            pass
        current = self.db.get('app', value['object_id'],
                              'REVOCATION#' + value['revocation_id'])
        if current:
            retry = {'operation': 'REVOKE', 'object_id': value['object_id'],
                'application_id': value['application_id'],
                'enforcement_digest': value['enforcement_digest'],
                'revocation_id': value['revocation_id'],
                'revocation_digest': value['revocation_digest']}
            self._requeue(current, retry)
        return value

    def process(self, message):
        state, application, head, candidate, request = self._load(message)
        if state.value['status'] == 'SUSPENDED_CONFIRMED':
            return state.value
        control = head.value.get('authority_control')
        if (not control or control.get('revocation_id') != request['revocation_id']
                or control.get('entry_status') != 'CLOSED'
                or control.get('runtime_authority_active') is not False):
            raise ValueError('Product-controlled entry is not durably closed')
        # Invocation acceptance and the stop request both linearize on HEAD.
        # Anything accepted first must reach a terminal result before account B
        # removes the Policy; after entry closure no later invocation can appear.
        pending = [row for row in self.db.query('app', request['object_id'],
                                                'INVOCATION#')
                   if row.value.get('application_id') == request['application_id']
                   and row.value.get('status') in ('ACCEPTED', 'UNKNOWN')]
        if pending:
            self._requeue(state, message)
            return state.value
        claimed = self._claim(state, message)
        if claimed is None:
            return self.db.get('app', request['object_id'],
                               'REVOCATION#' + request['revocation_id']).value
        try:
            result = self.publisher.revoke(copy.deepcopy(candidate), copy.deepcopy(request))
            result = verify_revocation_result(result, request, candidate)
            raw = encode(result)
            result_ref = self.blobs.put('business/revocations/' + request['revocation_id']
                                        + '/publisher-result.json', raw)
            if self.blobs.read(result_ref) != raw:
                raise ValueError('Revocation result readback differs')
            head = self.db.get('app', request['object_id'], 'HEAD')
            lock = self.db.get('app', claimed.value['lock_pk'], 'WRITER')
            control = head.value.get('authority_control') if head else None
            if (not head or not lock
                    or lock.value.get('revocation_id') != request['revocation_id']
                    or not control or control.get('revocation_id') != request['revocation_id']
                    or control.get('entry_status') != 'CLOSED'):
                raise ValueError('Revocation authority changed before terminal commit')
            terminal = dict(claimed.value, status='SUSPENDED_CONFIRMED',
                            updated_at=self.clock(), lease_until=None,
                            next_attempt_at=None,
                            result_ref=result_ref, last_error=None)
            updated_control = dict(control, status='SUSPENDED_CONFIRMED',
                updated_at=self.clock(), policy_status='REMOVED',
                deny_status='CONFIRMED', result_ref=result_ref, last_error=None)
            updated = dict(head.value, application_status='SUSPENDED_CONFIRMED',
                           authority_control=updated_control,
                           delegation_approval=None)
            expiry = self.db.get('jobs', 'AUTHORITY_EXPIRY', request['application_id'])
            writes = [('app', request['object_id'], 'REVOCATION#' + request['revocation_id'],
                       terminal, claimed.version),
                      ('app', request['object_id'], 'HEAD', updated, head.version),
                      ('app', claimed.value['lock_pk'], 'WRITER', None, lock.version)]
            if expiry is not None:
                writes.append(('jobs', 'AUTHORITY_EXPIRY', request['application_id'],
                               None, expiry.version))
            self.db.transact(writes)
            return terminal
        except Exception as exc:
            return self._unknown(claimed, message, exc)


def request_due_expiries(db, blobs, clock):
    """Close due authority before enqueuing the exact revocation request."""
    stamp = datetime.fromisoformat(clock())
    for expiry in db.query('jobs', 'AUTHORITY_EXPIRY'):
        value = expiry.value
        if stamp < datetime.fromisoformat(value['expires_at']):
            continue
        oid, aid = value['object_id'], value['application_id']
        head = db.get('app', oid, 'HEAD')
        application = db.get('app', oid, 'APPLICATION#' + aid)
        if head is None or application is None:
            continue
        applied = head.value.get('applied_binding')
        if (application.value.get('status') != 'VERIFIED' or not applied
                or applied.get('application_id') != aid
                or applied.get('enforcement_digest') != value['enforcement_digest']):
            try:
                db.transact([('jobs', 'AUTHORITY_EXPIRY', aid, None, expiry.version)])
            except Conflict:
                pass
            continue
        existing = head.value.get('authority_control')
        if (existing and existing.get('application_id') == aid
                and existing.get('status') != 'VERIFIED'):
            try:
                db.transact([('jobs', 'AUTHORITY_EXPIRY', aid, None, expiry.version)])
            except Conflict:
                pass
            continue
        candidate = json.loads(blobs.read(application.value['candidate_ref']))
        generation = head.value.get('delegation_generation', 0) + 1
        request = build_revocation_request(
            revocation_id=expiry_revocation_id(aid, value['expires_at']),
            candidate=candidate, applied_binding=applied, trigger='EXPIRY',
            reason='The approved AWS delegation reached its fixed expiry time.',
            actor={'sub': 'system:delegation-expiry', 'name': 'Delegation expiry'},
            requested_at=clock(), invalidated_generation=generation)
        ref = blobs.put('business/revocations/' + request['revocation_id']
                        + '/request.json', encode(request))
        lock_pk = application.value['lock_pk']
        state = revocation_state(request, ref, applied, lock_pk)
        message = revocation_message(request)
        control = {'schema_version': '1.0', 'revocation_id': request['revocation_id'],
            'revocation_digest': request['digest'], 'application_id': aid,
            'entry_status': 'CLOSED', 'status': 'STOP_REQUESTED',
            'trigger': 'EXPIRY', 'requested_at': request['requested_at'],
            'updated_at': request['requested_at'], 'policy_status': 'REMOVAL_PENDING',
            'deny_status': 'NOT_CONFIRMED', 'runtime_authority_active': False,
            'last_error': None}
        updated = dict(head.value, delegation_generation=generation,
                       delegation_approval=None, application_status='STOP_REQUESTED',
                       authority_control=control)
        event_id = 'event-' + uuid.uuid4().hex
        event = {'event_id': event_id, 'object_id': oid,
            'kind': 'AWS_AUTHORITY_STOP_REQUESTED',
            'at': request['requested_at'],
            'actor_sub': 'system:delegation-expiry',
            'actor_name': 'Delegation expiry',
            'details': {'revocation_id': request['revocation_id'],
                'application_id': aid, 'trigger': 'EXPIRY',
                'entry_status': 'CLOSED', 'policy_status': 'REMOVAL_PENDING',
                'deny_status': 'NOT_CONFIRMED',
                'runtime_authority_active': False,
                'reason': request['reason']}}
        try:
            db.transact([('app', oid, 'HEAD', updated, head.version),
                ('app', oid, 'REVOCATION#' + request['revocation_id'], state, None),
                ('app', oid, 'EVENT#' + request['requested_at'] + '#' + event_id,
                 event, None),
                ('jobs', 'APPLICATION_OUTBOX', request['revocation_id'], message, None),
                ('jobs', 'AUTHORITY_EXPIRY', aid, None, expiry.version)])
        except Conflict:
            continue
