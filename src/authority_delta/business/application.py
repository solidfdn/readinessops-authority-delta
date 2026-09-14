"""Recoverable, single-writer application of a registered enforcement candidate.

The publisher is an injected port.  This worker never treats a successful API
call as proof: it accepts only a complete terminal result validated against the
immutable candidate.  UNKNOWN retains the writer lock for reconciliation.
"""
from __future__ import annotations

import copy
import json
import re
from datetime import datetime, timedelta

from authority_delta.canonical import sha256_json
from .delegation import (verify_delegation_receipt, verify_enforcement_candidate,
                         verify_publisher_result, verify_registration)
from .storage import Conflict, encode


def _summary(state):
    return {'application_id': state['application_id'], 'status': state['status'],
            'enforcement_digest': state['enforcement_digest'],
            'publication_id': state['publication_id'], 'updated_at': state['updated_at']}


class ApplicationWorker:
    """Drive deny-first publication and deterministic recovery for one candidate."""

    def __init__(self, db, blobs, publisher, adapters, clock):
        self.db, self.blobs, self.publisher, self.clock = db, blobs, publisher, clock
        self.adapters = {}
        for raw in adapters:
            value = verify_registration(raw)
            key = (value['adapter_id'], value['connection_id'])
            if key in self.adapters:
                raise ValueError('Adapter registration is duplicated')
            self.adapters[key] = value

    def _load(self, message):
        if (not isinstance(message, dict)
                or set(message) != {'object_id', 'application_id', 'enforcement_digest'}
                or any(not isinstance(message[name], str) for name in message)
                or not re.fullmatch(r'o-[0-9a-f]{32}', message['object_id'])
                or not re.fullmatch(r'application-[0-9a-f]{32}', message['application_id'])
                or not re.fullmatch(r'[0-9a-f]{64}', message['enforcement_digest'])):
            raise ValueError('Application message is invalid')
        oid, aid = message['object_id'], message['application_id']
        state = self.db.get('app', oid, 'APPLICATION#' + aid)
        head = self.db.get('app', oid, 'HEAD')
        if state is None or head is None:
            raise ValueError('Application state is missing')
        if (state.value['object_id'] != oid or state.value['application_id'] != aid
                or state.value['enforcement_digest'] != message['enforcement_digest']):
            raise ValueError('Application message does not match committed state')
        if state.value['status'] in ('VERIFIED', 'RECOVERED_CLOSED', 'CANCELLED'):
            return state, head, None, None
        candidate = json.loads(self.blobs.read(state.value['candidate_ref']))
        if candidate.get('enforcement_digest') != message['enforcement_digest']:
            raise ValueError('Application candidate does not match the message')
        publication_row = self.db.get('app', oid, 'PUBLICATION#' + state.value['publication_id'])
        receipt_row = self.db.get('app', oid, 'DELEGATION#' + state.value['delegation_receipt_id'])
        if publication_row is None or receipt_row is None:
            raise ValueError('Application authority record is missing')
        publication, recorded = publication_row.value, receipt_row.value
        if publication.get('digest') != state.value['publication_digest']:
            raise ValueError('Application publication binding differs')
        registration = self.adapters.get((recorded.get('adapter_id'), recorded.get('connection_id')))
        if registration is None:
            raise ValueError('Application adapter is not registered')
        raw_receipt = json.loads(self.blobs.read(recorded['ref']))
        if raw_receipt != {k: v for k, v in recorded.items() if k != 'ref'}:
            raise ValueError('Delegation receipt record differs from its document')
        # Historical integrity must remain verifiable after expiry/invalidation,
        # otherwise even a closed recovery becomes impossible. Permission to open
        # is checked separately, against the current record, at every boundary.
        receipt = verify_delegation_receipt(raw_receipt, object_record=head.value,
            publication=publication, registration=registration)
        verified_candidate = verify_enforcement_candidate(candidate,
            receipt=dict(receipt, ref=recorded['ref']), publication=publication)
        lock = self.db.get('app', state.value['lock_pk'], 'WRITER')
        if (lock is None or lock.value.get('application_id') != aid
                or lock.value.get('object_id') != oid
                or lock.value.get('enforcement_digest') != message['enforcement_digest']):
            raise ValueError('Application writer lock differs')
        return state, head, lock, verified_candidate

    def _authority_current(self, head, candidate):
        if head is None:
            return False
        current = head.value.get('published_current')
        recorded = head.value.get('delegation_approval')
        generation = head.value.get('delegation_generation')
        if (type(generation) is not int or generation < 1
                or not current or not recorded
                or current.get('publication_id') != candidate['publication_id']
                or current.get('digest') != candidate['publication_digest']
                or recorded.get('receipt_id') != candidate['delegation_receipt_id']
                or recorded.get('digest') != candidate['delegation_receipt_digest']
                or recorded.get('ref') != candidate['delegation_receipt_ref']):
            return False
        raw = json.loads(self.blobs.read(candidate['delegation_receipt_ref']))
        if recorded != dict(raw, ref=candidate['delegation_receipt_ref']):
            return False
        registration = self.adapters[(candidate['adapter_id'], candidate['connection_id'])]
        try:
            verify_delegation_receipt(raw, object_record=head.value,
                publication=current, registration=registration,
                current_generation=generation, at=self.clock())
        except (ValueError, TypeError, KeyError):
            return False
        return True

    def _closed_status(self, head):
        applied = head.value.get('applied_binding')
        if not applied:
            return 'RECOVERED_CLOSED'
        current = head.value.get('published_current')
        return ('VERIFIED' if current and applied['publication_id'] == current['publication_id']
                else 'VERIFIED_PREVIOUS_PUBLICATION')

    def _cancel_unstarted(self, state, head, lock):
        stamp = self.clock()
        terminal = dict(state.value, status='CANCELLED', updated_at=stamp, lease_until=None,
                        last_error='The bound delegation is no longer current before publisher claim')
        updated = dict(head.value, latest_application=_summary(terminal),
                       application_status=self._closed_status(head))
        try:
            self.db.transact([('app', state.value['object_id'],
                'APPLICATION#' + state.value['application_id'], terminal, state.version),
                ('app', state.value['object_id'], 'HEAD', updated, head.version),
                ('app', state.value['lock_pk'], 'WRITER', None, lock.version)])
        except Conflict:
            return self.db.get('app', state.value['object_id'],
                               'APPLICATION#' + state.value['application_id']).value
        return terminal

    def _claim(self, state):
        stamp = datetime.fromisoformat(self.clock())
        lease = state.value.get('lease_until')
        if state.value['status'] == 'CANARY' and lease and stamp < datetime.fromisoformat(lease):
            return None
        claimed = dict(state.value, status='CANARY', updated_at=stamp.isoformat(),
                       attempt=state.value['attempt'] + 1,
                       lease_until=(stamp + timedelta(minutes=15)).isoformat(),
                       next_attempt_at=None, last_error=None)
        try:
            self.db.transact([('app', state.value['object_id'],
                'APPLICATION#' + state.value['application_id'], claimed, state.version)])
        except Conflict:
            return None
        return self.db.get('app', state.value['object_id'],
                           'APPLICATION#' + state.value['application_id'])

    def _mark_unknown(self, claimed, error):
        stamp = self.clock()
        unknown = dict(claimed.value, status='UNKNOWN', updated_at=stamp, lease_until=None,
                       next_attempt_at=None,
                       last_error=str(error)[:450] or 'Publisher outcome was not confirmed')
        message = {'object_id': unknown['object_id'],
            'application_id': unknown['application_id'],
            'enforcement_digest': unknown['enforcement_digest']}
        writes = [('app', unknown['object_id'],
            'APPLICATION#' + unknown['application_id'], unknown, claimed.version)]
        outbox = self.db.get('jobs', 'APPLICATION_OUTBOX', unknown['application_id'])
        if outbox is not None and outbox.value != message:
            raise ValueError('Application recovery outbox differs')
        writes.append(('jobs', 'APPLICATION_OUTBOX', unknown['application_id'],
                       message, outbox.version if outbox else None))
        try:
            self.db.transact(writes)
        except Conflict:
            current = self.db.get('app', unknown['object_id'],
                                  'APPLICATION#' + unknown['application_id'])
            return current.value if current else unknown
        for _ in range(3):
            head = self.db.get('app', unknown['object_id'], 'HEAD')
            if head is None or head.value.get('latest_application', {}).get('application_id') != unknown['application_id']:
                break
            updated = dict(head.value, latest_application=_summary(unknown),
                           application_status='UNKNOWN')
            try:
                self.db.transact([('app', unknown['object_id'], 'HEAD', updated, head.version)])
                break
            except Conflict:
                continue
        return unknown

    def delivery_failed(self, message, error):
        """Retain the writer lock and restore exact work after a terminal delivery."""
        if not isinstance(message, dict):
            return None
        oid, aid, digest = (message.get('object_id'), message.get('application_id'),
                            message.get('enforcement_digest'))
        if not all(isinstance(value, str) for value in (oid, aid, digest)):
            return None
        state = self.db.get('app', oid, 'APPLICATION#' + aid)
        if (state is None or state.value.get('enforcement_digest') != digest
                or state.value.get('status') in ('VERIFIED', 'RECOVERED_CLOSED', 'CANCELLED')):
            return None
        lock = self.db.get('app', state.value.get('lock_pk'), 'WRITER')
        if (lock is None or lock.value.get('application_id') != aid
                or lock.value.get('enforcement_digest') != digest):
            return None
        stamp = self.clock()
        unknown = dict(state.value, status='UNKNOWN', updated_at=stamp,
                       lease_until=None, attempt=state.value.get('attempt', 0) + 1,
                       next_attempt_at=None,
                       last_error=('Application delivery failed: ' + str(error))[:450])
        recovery = {'object_id': oid, 'application_id': aid,
                    'enforcement_digest': digest}
        outbox = self.db.get('jobs', 'APPLICATION_OUTBOX', aid)
        if outbox is not None and outbox.value != recovery:
            raise ValueError('Application recovery outbox differs')
        try:
            self.db.transact([
                ('app', oid, 'APPLICATION#' + aid, unknown, state.version),
                ('jobs', 'APPLICATION_OUTBOX', aid, recovery,
                 outbox.version if outbox else None)])
        except Conflict:
            current = self.db.get('app', oid, 'APPLICATION#' + aid)
            return current.value if current else unknown
        for _ in range(3):
            head = self.db.get('app', oid, 'HEAD')
            if head is None:
                break
            updated = dict(head.value, latest_application=_summary(unknown),
                           application_status='UNKNOWN')
            try:
                self.db.transact([('app', oid, 'HEAD', updated, head.version)])
                break
            except Conflict:
                continue
        return unknown

    def _applied_binding(self, candidate, result, result_ref, receipt):
        binding = {'schema_version': '1.0', 'kind': 'APPLIED_BINDING',
            'application_id': candidate['application_id'],
            'enforcement_digest': candidate['enforcement_digest'],
            'publication_id': candidate['publication_id'],
            'publication_digest': candidate['publication_digest'],
            'publication_ref': copy.deepcopy(candidate['publication_ref']),
            'delegation_receipt_id': candidate['delegation_receipt_id'],
            'delegation_receipt_digest': candidate['delegation_receipt_digest'],
            'delegation_receipt_ref': copy.deepcopy(candidate['delegation_receipt_ref']),
            'delegation_generation': receipt['approval_generation'],
            'delegation_expires_at': receipt['expires_at'],
            'adapter_id': candidate['adapter_id'], 'adapter_version': candidate['adapter_version'],
            'adapter_registration_hash': candidate['adapter_registration_hash'],
            'connection_id': candidate['connection_id'],
            'execution_binding': copy.deepcopy(candidate['execution_binding']),
            'publisher_binding': copy.deepcopy(candidate['publisher_binding']),
            'invocation_binding': copy.deepcopy(candidate['invocation_binding']),
            'probe_binding': copy.deepcopy(candidate['probe_binding']),
            'boundary_binding': copy.deepcopy(candidate['boundary_binding']),
            'policy_binding': copy.deepcopy(candidate['policy_binding']),
            'policy_id': result['policy_id'], 'policy_name': result['policy_name'],
            'policy_hash': result['policy_hash'],
            'publisher_result_ref': copy.deepcopy(result_ref),
            'previous_binding_status': result['previous_binding_status'],
            'closed_outcomes': copy.deepcopy(result['closed_outcomes']),
            'outcomes': copy.deepcopy(result['outcomes']), 'verified_at': result['observed_at'],
            'runtime_authority_active': True}
        binding['digest'] = sha256_json(binding)
        return binding

    def _finish(self, claimed, candidate, result):
        raw = encode(result)
        result_ref = self.blobs.put('business/applications/' + candidate['application_id'] +
                                    '/publisher-result.json', raw)
        if self.blobs.read(result_ref) != raw:
            raise ValueError('Publisher result readback differs')
        state = dict(claimed.value, status=result['status'], updated_at=self.clock(),
                     lease_until=None, result_ref=result_ref, last_error=None)
        oid = state['object_id']
        head = self.db.get('app', oid, 'HEAD')
        lock = self.db.get('app', state['lock_pk'], 'WRITER')
        if (head is None or lock is None
                or lock.value.get('application_id') != state['application_id']
                or lock.value.get('object_id') != oid
                or lock.value.get('enforcement_digest') != candidate['enforcement_digest']):
            raise ValueError('Application state changed before terminal commit')
        if result['status'] == 'VERIFIED' and not self._authority_current(head, candidate):
            raise ValueError('Verified result no longer has current unexpired delegation authority')
        if result['status'] == 'VERIFIED':
            receipt = json.loads(self.blobs.read(candidate['delegation_receipt_ref']))
            if (receipt.get('digest') != candidate['delegation_receipt_digest']
                    or receipt.get('receipt_id') != candidate['delegation_receipt_id']):
                raise ValueError('Applied delegation receipt readback differs')
            applied = self._applied_binding(candidate, result, result_ref, receipt)
            updated = dict(head.value, applied_binding=applied,
                           latest_application=_summary(state), application_status='VERIFIED',
                           authority_control={'schema_version': '1.0',
                               'application_id': candidate['application_id'],
                               'entry_status': 'OPEN', 'status': 'VERIFIED',
                               'trigger': None, 'requested_at': None,
                               'updated_at': self.clock(), 'policy_status': 'ACTIVE',
                               'deny_status': 'NOT_APPLICABLE',
                               'runtime_authority_active': True,
                               'last_error': None})
        else:
            updated = dict(head.value, latest_application=_summary(state),
                           application_status=self._closed_status(head))
        writes = [('app', oid, 'APPLICATION#' + state['application_id'], state,
                   claimed.version), ('app', oid, 'HEAD', updated, head.version),
                  ('app', state['lock_pk'], 'WRITER', None, lock.version)]
        if result['status'] == 'VERIFIED':
            writes.append(('jobs', 'AUTHORITY_EXPIRY', state['application_id'], {
                'schema_version': '1.0', 'object_id': oid,
                'application_id': state['application_id'],
                'enforcement_digest': state['enforcement_digest'],
                'delegation_receipt_id': state['delegation_receipt_id'],
                'expires_at': receipt['expires_at']}, None))
        self.db.transact(writes)
        return state

    def process(self, message):
        state, head, lock, candidate = self._load(message)
        if state.value['status'] in ('VERIFIED', 'RECOVERED_CLOSED', 'CANCELLED'):
            return state.value
        authority_current = self._authority_current(head, candidate)
        if state.value['status'] == 'APPLYING' and not authority_current:
            return self._cancel_unstarted(state, head, lock)
        recovery = state.value['status'] in ('CANARY', 'UNKNOWN')
        claimed = self._claim(state)
        if claimed is None:
            return self.db.get('app', state.value['object_id'],
                               'APPLICATION#' + state.value['application_id']).value
        try:
            # A claim is not authority: approval can expire or be invalidated
            # between queue receipt, the remote call and its terminal commit.
            require_closed = not self._authority_current(
                self.db.get('app', state.value['object_id'], 'HEAD'), candidate)
            if recovery or require_closed:
                result = self.publisher.reconcile(copy.deepcopy(candidate),
                    require_closed=require_closed)
            else:
                result = self.publisher.publish(copy.deepcopy(candidate))
            result = verify_publisher_result(result, candidate)
            if require_closed and result['status'] != 'RECOVERED_CLOSED':
                raise ValueError('Invalidated application was not recovered closed')
            if (result['status'] == 'VERIFIED' and not self._authority_current(
                    self.db.get('app', state.value['object_id'], 'HEAD'), candidate)):
                result = verify_publisher_result(self.publisher.reconcile(
                    copy.deepcopy(candidate), require_closed=True), candidate)
                if result['status'] != 'RECOVERED_CLOSED':
                    raise ValueError('Late publisher result was not recovered closed')
            return self._finish(claimed, candidate, result)
        except Exception as exc:
            return self._mark_unknown(claimed, exc)
