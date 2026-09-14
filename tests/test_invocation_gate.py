"""Normal execution is accepted only through the exact current authority gate."""
import copy
import io
import json
import unittest
import uuid
from botocore.response import StreamingBody

from authority_delta.business.invocation import (InvocationGate, InvocationRejected,
    InvocationWorker, LambdaRuntimeInvoker, dispatch_pending_invocations)
from authority_delta.business.revocation import RevocationWorker
from authority_delta.canonical import sha256_json
from support.business import ACTOR
import test_business_delegation as d3
import test_authority_revocation as revocation_contracts


class Invoker:
    def __init__(self, callback=None):
        self.calls, self.callback = [], callback

    def invoke(self, candidate, request_id):
        self.calls.append((copy.deepcopy(candidate), request_id))
        if self.callback:
            self.callback()
        evidence = {'local': True}
        return {'schema_version': '1.0', 'kind': 'CUSTOMER_RUNTIME_INVOCATION',
            'status': 'EXECUTED', 'application_id': candidate['application_id'],
            'enforcement_digest': candidate['enforcement_digest'],
            'request_id': request_id, 'outcome': 'ALLOW',
            'evidence_hash': sha256_json(evidence), 'evidence': evidence,
            'invocation_transport': {
                'function_arn': candidate['invocation_binding']['function_arn'],
                'request_id': 'local-invocation-request', 'http_status': 200,
                'executed_version': 'live',
                'invoke_role_arn': candidate['invocation_binding']['invoke_role_arn'],
            'assume_role_request_id': 'LOCAL_NOT_ASSUMED'}}


class FailingInvoker:
    def __init__(self):
        self.calls = 0

    def invoke(self, candidate, request_id):
        self.calls += 1
        raise TimeoutError('runtime result unavailable')


class Queue:
    def __init__(self):
        self.messages = []
    def send_message(self, **values):
        self.messages.append(json.loads(values['MessageBody']))
        return {'MessageId': 'message-id',
                'ResponseMetadata': {'HTTPStatusCode': 200,
                                     'RequestId': 'queue-request'}}


class RuntimeClient:
    def __init__(self, result):
        self.result, self.calls = result, []

    def invoke(self, **values):
        self.calls.append(values)
        raw = json.dumps(self.result).encode()
        return {'StatusCode': 200, 'ExecutedVersion': 'live',
            'Payload': StreamingBody(io.BytesIO(raw), len(raw)),
            'ResponseMetadata': {'HTTPStatusCode': 200,
                                 'RequestId': 'runtime-lambda-request'}}


class InvocationGateTests(unittest.TestCase):
    def setUp(self):
        self.flow = d3.DelegationFlow(
            methodName='test_verified_canary_is_only_transition_to_applied_binding')
        self.flow.setUp()
        self.flow.publish()
        self.started = self.flow.start(self.flow.delegate('MAINTAIN', days=1))
        self.flow.worker(d3.ScriptedPublisher()).process(self.flow.message(self.started))
        candidate = self.candidate()
        self.allowed = next(item['request_id'] for item in candidate['expected_outcomes']
                            if item['expected_outcome'] == 'ALLOW')

    def gate(self, invoker):
        return InvocationGate(self.flow.flow.db, self.flow.flow.blobs, invoker,
                              [self.flow.registration], self.flow.flow.clock)

    def candidate(self):
        row = self.flow.flow.db.get('app', self.flow.oid,
            'APPLICATION#' + self.started['application_id'])
        return json.loads(self.flow.flow.blobs.read(row.value['candidate_ref']))

    def body(self, **changes):
        value = {'operation_id': uuid.uuid4().hex, 'request_id': self.allowed}
        value.update(changes)
        return value

    def test_verified_current_generation_executes_and_replay_is_read_only(self):
        invoker = Invoker()
        gate, body = self.gate(invoker), self.body()
        first = gate.invoke(ACTOR, self.flow.oid, body)
        second = gate.invoke(ACTOR, self.flow.oid, body)
        self.assertEqual(first, second)
        self.assertEqual(len(invoker.calls), 1)
        self.assertEqual(first['authority_generation'],
            self.flow.app.detail(ACTOR, self.flow.oid)['object']['delegation_generation'])

    def test_accept_is_queued_and_export_binds_the_executed_result(self):
        invoker = Invoker()
        gate, body = self.gate(invoker), self.body()
        accepted = gate.accept(ACTOR, self.flow.oid, body)
        self.assertEqual(accepted['status'], 'ACCEPTED')
        self.assertEqual(invoker.calls, [])
        queue = Queue()
        dispatch_pending_invocations(self.flow.flow.db, queue, 'invocation-queue')
        self.assertEqual(len(queue.messages), 1)
        self.assertIsNone(self.flow.flow.db.get(
            'jobs', 'INVOCATION_OUTBOX', body['operation_id']))
        worker = InvocationWorker(self.flow.flow.db, self.flow.flow.blobs, invoker,
            [self.flow.registration], self.flow.flow.clock)
        result = worker.process(queue.messages[0])
        self.assertEqual(result['status'], 'EXECUTED')
        self.assertEqual(gate.get(ACTOR, self.flow.oid,
                                  body['operation_id'])['result'], result)
        exported = self.flow.app.export_acceptance_evidence(ACTOR, self.flow.oid)
        self.assertEqual(exported['schema_version'], '1.1')
        self.assertEqual(exported['invocations'][0]['document']['result']['status'],
                         'EXECUTED')

    def test_denied_request_expiry_and_changed_generation_fail_before_remote_call(self):
        invoker = Invoker()
        gate = self.gate(invoker)
        denied = next(item['request_id'] for item in self.candidate()[
            'expected_outcomes'] if item['expected_outcome'] == 'DENY')
        with self.assertRaises(InvocationRejected):
            gate.invoke(ACTOR, self.flow.oid, self.body(request_id=denied))
        self.flow.flow.clock.advance(86400)
        with self.assertRaises(InvocationRejected):
            gate.invoke(ACTOR, self.flow.oid, self.body())
        self.assertEqual(invoker.calls, [])

    def test_stop_linearizes_after_already_accepted_call_and_blocks_next(self):
        stopped = []
        def stop_after_acceptance():
            stopped.append(self.flow.app.request_revocation(ACTOR, self.flow.oid,
                self.flow.command(application_id=self.started['application_id'],
                                  reason='Stop after the already accepted invocation')))
        invoker = Invoker(stop_after_acceptance)
        first = self.gate(invoker).invoke(ACTOR, self.flow.oid, self.body())
        self.assertEqual(first['status'], 'EXECUTED')
        self.assertEqual(stopped[0]['status'], 'STOP_REQUESTED')
        with self.assertRaises(InvocationRejected):
            self.gate(Invoker()).invoke(ACTOR, self.flow.oid, self.body())

    def test_stop_after_queue_acceptance_does_not_cancel_that_exact_invocation(self):
        invoker, body = Invoker(), self.body()
        gate = self.gate(invoker)
        accepted = gate.accept(ACTOR, self.flow.oid, body)
        self.flow.app.request_revocation(ACTOR, self.flow.oid,
            self.flow.command(application_id=self.started['application_id'],
                              reason='Close after the invocation acceptance point'))
        row = self.flow.flow.db.get('app', self.flow.oid,
            'INVOCATION#' + accepted['operation_id'])
        message = {name: row.value[name] for name in ('operation_id', 'object_id',
            'application_id', 'enforcement_digest', 'request_id')}
        result = InvocationWorker(self.flow.flow.db, self.flow.flow.blobs, invoker,
            [self.flow.registration], self.flow.flow.clock).process(message)
        self.assertEqual(result['status'], 'EXECUTED')
        self.assertEqual(len(invoker.calls), 1)

    def test_revocation_waits_for_an_invocation_accepted_before_stop(self):
        invoker, body = Invoker(), self.body()
        accepted = self.gate(invoker).accept(ACTOR, self.flow.oid, body)
        stopped = self.flow.app.request_revocation(ACTOR, self.flow.oid,
            self.flow.command(application_id=self.started['application_id'],
                              reason='Drain the accepted invocation before removal'))
        stop_message = {key: stopped[key] for key in ('operation', 'object_id',
            'application_id', 'enforcement_digest', 'revocation_id',
            'revocation_digest')}
        publisher = revocation_contracts.RevocationPublisher()
        revoker = RevocationWorker(self.flow.flow.db, self.flow.flow.blobs,
            publisher, [self.flow.registration], self.flow.flow.clock)
        self.assertEqual(revoker.process(stop_message)['status'], 'STOP_REQUESTED')
        self.assertEqual(publisher.calls, [])
        row = self.flow.flow.db.get('app', self.flow.oid,
            'INVOCATION#' + accepted['operation_id'])
        invocation_message = {name: row.value[name] for name in ('operation_id',
            'object_id', 'application_id', 'enforcement_digest', 'request_id')}
        InvocationWorker(self.flow.flow.db, self.flow.flow.blobs, invoker,
            [self.flow.registration], self.flow.flow.clock).process(invocation_message)
        self.assertEqual(revoker.process(stop_message)['status'],
                         'SUSPENDED_CONFIRMED')
        self.assertEqual(len(publisher.calls), 1)

    def test_terminal_delivery_failure_restores_exact_outbox(self):
        invoker, body = FailingInvoker(), self.body()
        accepted = self.gate(invoker).accept(ACTOR, self.flow.oid, body)
        row = self.flow.flow.db.get('app', self.flow.oid,
            'INVOCATION#' + accepted['operation_id'])
        message = {name: row.value[name] for name in ('operation_id', 'object_id',
            'application_id', 'enforcement_digest', 'request_id')}
        worker = InvocationWorker(self.flow.flow.db, self.flow.flow.blobs, invoker,
            [self.flow.registration], self.flow.flow.clock)
        result = worker.process(message, dead_letter=True)
        self.assertEqual(result['status'], 'UNKNOWN')
        self.assertEqual(self.flow.flow.db.get('jobs', 'INVOCATION_OUTBOX',
            body['operation_id']).value, message)

    def test_closed_or_tampered_control_never_reaches_runtime(self):
        for mutate in (
                lambda head: head['authority_control'].update(entry_status='CLOSED'),
                lambda head: head.update(delegation_generation=99),
                lambda head: head['applied_binding'].update(runtime_authority_active=False)):
            with self.subTest(mutate=mutate):
                row = self.flow.flow.db.get('app', self.flow.oid, 'HEAD')
                changed = copy.deepcopy(row.value)
                mutate(changed)
                self.flow.flow.db.transact([('app', self.flow.oid, 'HEAD',
                                             changed, row.version)])
                invoker = Invoker()
                with self.assertRaises(InvocationRejected):
                    self.gate(invoker).invoke(ACTOR, self.flow.oid, self.body())
                self.assertEqual(invoker.calls, [])
                current = self.flow.flow.db.get('app', self.flow.oid, 'HEAD')
                self.flow.flow.db.transact([('app', self.flow.oid, 'HEAD',
                                             row.value, current.version)])

    def test_registered_runtime_transport_and_result_hash_are_both_exact(self):
        candidate = self.candidate()
        evidence = {'request_id': self.allowed, 'outcome': 'ALLOW'}
        result = {'schema_version': '1.0', 'kind': 'CUSTOMER_RUNTIME_INVOCATION',
            'status': 'EXECUTED', 'application_id': candidate['application_id'],
            'enforcement_digest': candidate['enforcement_digest'],
            'request_id': self.allowed, 'outcome': 'ALLOW',
            'evidence': evidence, 'evidence_hash': sha256_json(evidence)}
        client = RuntimeClient(result)
        observed = LambdaRuntimeInvoker(client, [self.flow.registration]).invoke(
            candidate, self.allowed)
        self.assertEqual(client.calls[0]['FunctionName'],
                         candidate['invocation_binding']['function_arn'])
        self.assertEqual(observed['invocation_transport']['request_id'],
                         'runtime-lambda-request')
        changed = copy.deepcopy(result)
        changed['evidence_hash'] = '0' * 64
        with self.assertRaisesRegex(ValueError, 'differs'):
            LambdaRuntimeInvoker(RuntimeClient(changed),
                                 [self.flow.registration]).invoke(candidate, self.allowed)


if __name__ == '__main__':
    unittest.main()
