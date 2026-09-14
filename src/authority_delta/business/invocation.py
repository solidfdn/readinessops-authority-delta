"""Linearized, queued account-A InvocationGate for verified authority."""
from __future__ import annotations

import copy
import json
import re
from datetime import datetime

from authority_delta.canonical import sha256_json
from .delegation import (verify_delegation_receipt, verify_enforcement_candidate,
                         verify_registration)
from .storage import Conflict, encode


REQUEST_ID = re.compile(r'^req-[0-9a-f]{64}$')
OPERATION_ID = re.compile(r'^[A-Za-z0-9_-]{16,80}$')


class InvocationRejected(Exception):
    pass


class LambdaRuntimeInvoker:
    """Invoke only the registered account-B runtime endpoint Lambda via STS."""

    def __init__(self, client, registrations, *, sts=None, assumed_client=None):
        self.client, self.sts, self.assumed_client = client, sts, assumed_client
        self.registrations = {(v['adapter_id'], v['connection_id']):
                              verify_registration(v) for v in registrations}

    def invoke(self, candidate, request_id):
        registration = self.registrations.get((candidate.get('adapter_id'),
                                               candidate.get('connection_id')))
        if (registration is None
                or candidate.get('adapter_registration_hash')
                    != registration['registration_hash']
                or candidate.get('invocation_binding')
                    != registration['invocation_binding']):
            raise ValueError('Runtime invocation is not registered')
        binding = registration['invocation_binding']
        client, assume_id = self.client, 'LOCAL_NOT_ASSUMED'
        if registration['connection_mode'] == 'LIVE_CUSTOMER':
            if self.sts is None or self.assumed_client is None:
                raise ValueError('Live invocation requires the registered STS connector')
            session = 'authority-gate-' + candidate['application_id'].split('-', 1)[1][:16]
            response = self.sts.assume_role(RoleArn=binding['invoke_role_arn'],
                RoleSessionName=session, ExternalId=binding['external_id'],
                DurationSeconds=900)
            metadata, credentials = (response.get('ResponseMetadata', {}),
                                     response.get('Credentials', {}))
            role = binding['invoke_role_arn'].rsplit('/', 1)[1]
            expected = (f"arn:aws:sts::{registration['target_account_id']}:assumed-role/"
                        f"{role}/{session}")
            if (metadata.get('HTTPStatusCode') != 200 or not metadata.get('RequestId')
                    or response.get('AssumedRoleUser', {}).get('Arn') != expected
                    or not all(credentials.get(k) for k in (
                        'AccessKeyId', 'SecretAccessKey', 'SessionToken'))):
                raise ValueError('Runtime invocation role assumption was not confirmed')
            assume_id = metadata['RequestId']
            client = self.assumed_client(credentials, registration['target_region'])
        payload = encode({'schema_version': '1.0',
            'registration_hash': registration['registration_hash'],
            'application_id': candidate['application_id'],
            'enforcement_digest': candidate['enforcement_digest'],
            'request_id': request_id})
        response = client.invoke(FunctionName=binding['function_arn'],
            InvocationType='RequestResponse', Payload=payload)
        stream, metadata = response.get('Payload'), response.get('ResponseMetadata', {})
        if stream is None:
            raise ValueError('Runtime endpoint invocation has no response stream')
        try:
            raw = stream.read(900_001)
        finally:
            stream.close()
        if (len(raw) > 900_000 or response.get('StatusCode') != 200
                or metadata.get('HTTPStatusCode') != 200
                or not metadata.get('RequestId') or response.get('FunctionError')):
            raise ValueError('Runtime endpoint invocation was not confirmed')
        value = json.loads(raw)
        if (not isinstance(value, dict) or value.get('status') != 'EXECUTED'
                or value.get('application_id') != candidate['application_id']
                or value.get('enforcement_digest') != candidate['enforcement_digest']
                or value.get('request_id') != request_id
                or value.get('outcome') != 'ALLOW'
                or not isinstance(value.get('evidence'), dict)
                or value.get('evidence_hash') != sha256_json(value['evidence'])):
            raise ValueError('Runtime endpoint result differs from the accepted invocation')
        value['invocation_transport'] = {'function_arn': binding['function_arn'],
            'request_id': metadata['RequestId'], 'http_status': response['StatusCode'],
            'executed_version': response.get('ExecutedVersion')
                or binding['function_arn'].rsplit(':', 1)[1],
            'invoke_role_arn': binding['invoke_role_arn'],
            'assume_role_request_id': assume_id}
        return value


class InvocationGate:
    """Accept one request only while the exact live generation is open."""

    def __init__(self, db, blobs, invoker, adapters, clock):
        self.db, self.blobs, self.invoker, self.clock = db, blobs, invoker, clock
        self.adapters = {(v['adapter_id'], v['connection_id']):
                         verify_registration(v) for v in adapters}

    def _authority(self, actor, oid, request_id):
        head = self.db.get('app', oid, 'HEAD')
        if head is None or head.value.get('owner_sub') != actor['sub']:
            raise InvocationRejected('Object not found')
        applied, control = (head.value.get('applied_binding'),
                            head.value.get('authority_control'))
        if (not applied or not control or control.get('entry_status') != 'OPEN'
                or control.get('status') != 'VERIFIED'
                or control.get('runtime_authority_active') is not True
                or control.get('application_id') != applied.get('application_id')
                or applied.get('runtime_authority_active') is not True
                or applied.get('publication_id')
                    != head.value.get('published_current', {}).get('publication_id')
                or applied.get('delegation_generation')
                    != head.value.get('delegation_generation')):
            raise InvocationRejected('AWS runtime authority is closed')
        receipt_record = head.value.get('delegation_approval')
        if (not receipt_record
                or receipt_record.get('receipt_id') != applied['delegation_receipt_id']
                or receipt_record.get('digest') != applied['delegation_receipt_digest']):
            raise InvocationRejected('Current delegation authority differs')
        application = self.db.get('app', oid,
            'APPLICATION#' + applied['application_id'])
        publication = self.db.get('app', oid,
            'PUBLICATION#' + applied['publication_id'])
        if application is None or publication is None or application.value.get('status') != 'VERIFIED':
            raise InvocationRejected('Verified application evidence is missing')
        candidate = json.loads(self.blobs.read(application.value['candidate_ref']))
        raw_receipt = json.loads(self.blobs.read(receipt_record['ref']))
        registration = self.adapters.get((candidate.get('adapter_id'),
                                          candidate.get('connection_id')))
        if registration is None:
            raise InvocationRejected('Invocation adapter is not registered')
        try:
            receipt = verify_delegation_receipt(raw_receipt,
                object_record=head.value, publication=publication.value,
                registration=registration,
                current_generation=head.value['delegation_generation'], at=self.clock())
            candidate = verify_enforcement_candidate(candidate,
                receipt=dict(receipt, ref=receipt_record['ref']),
                publication=publication.value)
        except (KeyError, TypeError, ValueError) as exc:
            raise InvocationRejected('Current authority integrity check failed') from exc
        expected = {item['request_id']: item['expected_outcome']
                    for item in candidate['expected_outcomes']}
        if expected.get(request_id) != 'ALLOW':
            raise InvocationRejected('This request is outside the applied finite authority')
        return head, candidate

    def accept(self, actor, oid, body):
        operation_id, request_id = body.get('operation_id'), body.get('request_id')
        if (not OPERATION_ID.fullmatch(str(operation_id))
                or not REQUEST_ID.fullmatch(str(request_id))
                or set(body) != {'operation_id', 'request_id'}):
            raise InvocationRejected('Invocation request is invalid')
        key = ('app', oid, 'INVOCATION#' + operation_id)
        fingerprint = sha256_json({'object_id': oid, 'request_id': request_id})
        existing = self.db.get(*key)
        if existing:
            if existing.value.get('fingerprint') != fingerprint:
                raise InvocationRejected('Operation identifier was reused for different input')
            return self._response(existing.value)
        head, candidate = self._authority(actor, oid, request_id)
        accepted_at = self.clock()
        accepted = {'schema_version': '1.0', 'kind': 'CONTROLLED_INVOCATION',
            'operation_id': operation_id, 'object_id': oid,
            'application_id': candidate['application_id'],
            'enforcement_digest': candidate['enforcement_digest'],
            'delegation_generation': head.value['delegation_generation'],
            'request_id': request_id, 'fingerprint': fingerprint,
            'status': 'ACCEPTED', 'accepted_at': accepted_at,
            'updated_at': accepted_at, 'attempt': 0,
            'result_ref': None, 'last_error': None}
        message = {name: accepted[name] for name in ('operation_id', 'object_id',
            'application_id', 'enforcement_digest', 'request_id')}
        try:
            # Updating HEAD without changing its value linearizes acceptance
            # against the stop transaction's conditional HEAD update.
            self.db.transact([('app', oid, 'HEAD', dict(head.value), head.version),
                              (*key, accepted, None),
                              ('jobs', 'INVOCATION_OUTBOX', operation_id,
                               message, None)])
        except Conflict as exc:
            raise InvocationRejected('Authority changed while accepting the invocation') from exc
        return self._response(accepted)

    def get(self, actor, oid, operation_id):
        if not OPERATION_ID.fullmatch(str(operation_id)):
            raise InvocationRejected('Invocation operation is invalid')
        head = self.db.get('app', oid, 'HEAD')
        if head is None or head.value.get('owner_sub') != actor.get('sub'):
            raise InvocationRejected('Object not found')
        row = self.db.get('app', oid, 'INVOCATION#' + operation_id)
        if row is None:
            raise InvocationRejected('Invocation operation not found')
        return self._response(row.value)

    def _response(self, value):
        result = None
        if value.get('status') == 'EXECUTED':
            result = json.loads(self.blobs.read(value['result_ref']))
        return {'schema_version': '1.0', 'operation_id': value['operation_id'],
            'object_id': value['object_id'], 'application_id': value['application_id'],
            'request_id': value['request_id'], 'status': value['status'],
            'accepted_at': value['accepted_at'], 'updated_at': value['updated_at'],
            'result': result,
            'error': value.get('last_error') if value.get('status') == 'UNKNOWN' else None}

    def invoke(self, actor, oid, body):
        """Local compatibility helper: accept, then execute with the worker."""
        accepted = self.accept(actor, oid, body)
        message = {name: accepted[name] for name in ('operation_id', 'object_id',
            'application_id', 'request_id')}
        row = self.db.get('app', oid, 'INVOCATION#' + accepted['operation_id'])
        message['enforcement_digest'] = row.value['enforcement_digest']
        return InvocationWorker(self.db, self.blobs, self.invoker,
                                self.adapters.values(), self.clock).process(message)


def verify_invocation_message(value):
    if (not isinstance(value, dict)
            or set(value) != {'operation_id', 'object_id', 'application_id',
                              'enforcement_digest', 'request_id'}
            or not OPERATION_ID.fullmatch(str(value.get('operation_id')))
            or not re.fullmatch(r'^o-[0-9a-f]{32}$', str(value.get('object_id')))
            or not re.fullmatch(r'^application-[0-9a-f]{32}$',
                                str(value.get('application_id')))
            or not re.fullmatch(r'^[0-9a-f]{64}$',
                                str(value.get('enforcement_digest')))
            or not REQUEST_ID.fullmatch(str(value.get('request_id')))):
        raise ValueError('Invocation message is invalid')
    return copy.deepcopy(value)


def dispatch_pending_invocations(db, sqs, queue_url):
    failures = 0
    for row in db.query('jobs', 'INVOCATION_OUTBOX'):
        try:
            message = verify_invocation_message(row.value)
            response = sqs.send_message(QueueUrl=queue_url,
                                         MessageBody=encode(message).decode())
            metadata = response.get('ResponseMetadata', {})
            if (metadata.get('HTTPStatusCode') != 200
                    or not metadata.get('RequestId') or not response.get('MessageId')):
                raise ValueError('Invocation queue send lacks successful AWS evidence')
            try:
                db.transact([('jobs', 'INVOCATION_OUTBOX', message['operation_id'],
                              None, row.version)])
            except Conflict:
                pass
        except Exception:
            failures += 1
    if failures:
        raise RuntimeError('Invocation outbox dispatch incomplete; pending records retained')


class InvocationWorker:
    """Execute an already-linearized invocation without reopening its authority."""

    def __init__(self, db, blobs, invoker, adapters, clock):
        self.db, self.blobs, self.invoker, self.clock = db, blobs, invoker, clock
        self.adapters = {(value['adapter_id'], value['connection_id']):
                         verify_registration(value) for value in adapters}

    def _load(self, message):
        message = verify_invocation_message(message)
        row = self.db.get('app', message['object_id'],
                          'INVOCATION#' + message['operation_id'])
        application = self.db.get('app', message['object_id'],
            'APPLICATION#' + message['application_id'])
        if row is None or application is None:
            raise ValueError('Accepted invocation state is missing')
        if any(row.value.get(name) != value for name, value in message.items()):
            raise ValueError('Invocation message differs from accepted state')
        candidate = json.loads(self.blobs.read(application.value['candidate_ref']))
        if (candidate.get('application_id') != message['application_id']
                or candidate.get('enforcement_digest') != message['enforcement_digest']
                or sha256_json({k: v for k, v in candidate.items()
                                if k != 'enforcement_digest'})
                    != candidate.get('enforcement_digest')):
            raise ValueError('Invocation candidate integrity differs')
        registration = self.adapters.get((candidate.get('adapter_id'),
                                          candidate.get('connection_id')))
        if registration is None:
            raise ValueError('Invocation adapter is not registered')
        return row, candidate

    def _mark_unknown(self, row, message, error, *, requeue):
        if row.value.get('status') == 'EXECUTED':
            return row.value
        unknown = dict(row.value, status='UNKNOWN', updated_at=self.clock(),
            attempt=row.value.get('attempt', 0) + 1,
            last_error=(str(error)[:400] or 'Invocation result is unconfirmed'))
        writes = [('app', message['object_id'],
            'INVOCATION#' + message['operation_id'], unknown, row.version)]
        if requeue:
            outbox = self.db.get('jobs', 'INVOCATION_OUTBOX',
                                 message['operation_id'])
            if outbox is not None and outbox.value != message:
                raise ValueError('Invocation recovery outbox differs')
            writes.append(('jobs', 'INVOCATION_OUTBOX', message['operation_id'],
                           copy.deepcopy(message), outbox.version if outbox else None))
        try:
            self.db.transact(writes)
        except Conflict:
            current = self.db.get('app', message['object_id'],
                                  'INVOCATION#' + message['operation_id'])
            return current.value if current else unknown
        return unknown

    def delivery_failed(self, message, error):
        """Turn a valid terminal DLQ delivery back into the exact durable work."""
        try:
            message = verify_invocation_message(message)
        except ValueError:
            return None
        row = self.db.get('app', message['object_id'],
                          'INVOCATION#' + message['operation_id'])
        if row is None or any(row.value.get(name) != value
                              for name, value in message.items()):
            return None
        return self._mark_unknown(row, message,
            'Invocation delivery failed: ' + str(error), requeue=True)

    def process(self, message, dead_letter=False):
        row, candidate = self._load(message)
        if row.value['status'] == 'EXECUTED':
            return json.loads(self.blobs.read(row.value['result_ref']))
        if row.value['status'] not in ('ACCEPTED', 'UNKNOWN'):
            raise ValueError('Invocation is not executable')
        try:
            result = copy.deepcopy(self.invoker.invoke(candidate, message['request_id']))
            result['accepted_at'] = row.value['accepted_at']
            result['authority_generation'] = row.value['delegation_generation']
            raw = encode(result)
            ref = self.blobs.put('business/invocations/' + message['operation_id']
                                 + '/result.json', raw)
            if self.blobs.read(ref) != raw:
                raise ValueError('Invocation result readback differs')
            completed = dict(row.value, status='EXECUTED', updated_at=self.clock(),
                             attempt=row.value.get('attempt', 0) + 1,
                             result_ref=ref, last_error=None)
            self.db.transact([('app', message['object_id'],
                'INVOCATION#' + message['operation_id'], completed, row.version)])
            return result
        except Exception as exc:
            current = self.db.get('app', message['object_id'],
                                  'INVOCATION#' + message['operation_id'])
            if current is None:
                raise
            unknown = self._mark_unknown(current, message, exc,
                                         requeue=dead_letter)
            if unknown.get('status') == 'EXECUTED':
                return json.loads(self.blobs.read(unknown['result_ref']))
            if not dead_letter:
                raise
            return unknown
