"""RO-07 stop, expiry, customer removal and evidence contracts."""
import copy
import json
import unittest

from authority_delta.business.customer_publisher import CustomerPolicyPublisher
from authority_delta.business.revocation import (RevocationWorker,
    build_revocation_request, request_due_expiries, verify_revocation_result)
from authority_delta.canonical import sha256_json
from support.business import ACTOR, MemoryStore
import test_business_application_aws as aws_contracts
import test_business_delegation as d3


def raw_revocation_result(candidate, request):
    def denied(request_id):
        mcp_id = 'mcp-' + request_id[-16:]
        evidence = {'runtime_request_id': 'runtime-' + request_id[-8:],
            'runtime_session_id': 'session-' + request_id[-8:],
            'principal': candidate['policy_binding']['principal_id'],
            'endpoint_before': {'request_id': 'endpoint-before-' + request_id[-8:],
                'endpoint_arn': candidate['execution_binding']['runtime']['endpoint_arn'],
                'live_version': candidate['execution_binding']['runtime']['runtime_version']},
            'endpoint_after': {'request_id': 'endpoint-after-' + request_id[-8:],
                'endpoint_arn': candidate['execution_binding']['runtime']['endpoint_arn'],
                'live_version': candidate['execution_binding']['runtime']['runtime_version']},
            'gateway_response': {'http_status': 403,
                'headers': {'x-amzn-requestid': 'gateway-' + request_id[-8:]},
                'body': {'jsonrpc': '2.0', 'id': mcp_id,
                    'error': {'code': -32002,
                        'message': 'Tool Execution Denied: Tool call not allowed due to policy enforcement'}}},
            'mcp_id': mcp_id, 'outcome': 'DENY',
            'before_ledger_hash': 'a' * 64, 'after_ledger_hash': 'a' * 64}
        return {'request_id': request_id, 'outcome': 'DENY',
                'evidence_hash': sha256_json(evidence), 'evidence': evidence}
    return {'schema_version': '1.0', 'kind': 'AUTHORITY_REVOCATION_RESULT',
        'status': 'POLICY_REMOVED_DENY_CONFIRMED',
        'revocation_id': request['revocation_id'],
        'revocation_digest': request['digest'],
        'application_id': candidate['application_id'],
        'enforcement_digest': candidate['enforcement_digest'],
        'policy_id': request['policy_id'], 'policy_name': request['policy_name'],
        'policy_hash': request['policy_hash'],
        'observed_at': '2026-09-09T00:01:00+00:00',
        'checks': {'owned_policy_readback': True,
                   'delete_intent_journaled': True,
                   'policy_absent_readback': True},
        'outcomes': [denied(item['request_id']) for item in sorted(
            candidate['expected_outcomes'], key=lambda item: item['request_id'])],
        'publisher_invocation': {
            'function_arn': candidate['publisher_binding']['function_arn'],
            'request_id': 'LOCAL_SCRIPTED_REVOCATION_ONLY', 'http_status': 200,
            'executed_version': 'live',
            'invoke_role_arn': candidate['publisher_binding']['invoke_role_arn'],
            'assume_role_request_id': ('LOCAL_SCRIPTED_STS_ONLY'
                if candidate['connection_mode'] == 'LIVE_CUSTOMER'
                else 'LOCAL_NOT_ASSUMED')}}


class RevocationPublisher:
    def __init__(self, error=None):
        self.error, self.calls = error, []

    def revoke(self, candidate, request):
        self.calls.append((copy.deepcopy(candidate), copy.deepcopy(request)))
        if self.error:
            raise self.error
        return raw_revocation_result(candidate, request)


class AuthorityRevocationFlow(unittest.TestCase):
    def setUp(self):
        self.flow = d3.DelegationFlow(
            methodName='test_verified_canary_is_only_transition_to_applied_binding')
        self.flow.setUp()
        self.flow.publish()
        self.started = self.flow.start(self.flow.delegate(days=1))
        self.flow.worker(d3.ScriptedPublisher()).process(self.flow.message(self.started))
        self.app, self.oid = self.flow.app, self.flow.oid

    def stop(self, reason='Reviewer explicitly stops this applied authority'):
        return self.app.request_revocation(ACTOR, self.oid, self.flow.command(
            application_id=self.started['application_id'], reason=reason))

    def worker(self, publisher):
        return RevocationWorker(self.flow.flow.db, self.flow.flow.blobs, publisher,
            [self.flow.registration], self.flow.flow.clock)

    def test_manual_stop_closes_entry_before_customer_confirmation(self):
        before = self.app.detail(ACTOR, self.oid)['object']
        stopped = self.stop()
        after = self.app.detail(ACTOR, self.oid)['object']
        self.assertEqual(stopped['status'], 'STOP_REQUESTED')
        self.assertEqual(after['authority_control']['entry_status'], 'CLOSED')
        self.assertFalse(after['authority_control']['runtime_authority_active'])
        self.assertEqual(after['authority_control']['deny_status'], 'NOT_CONFIRMED')
        self.assertEqual(after['application_status'], 'STOP_REQUESTED')
        self.assertIsNone(after['delegation_approval'])
        self.assertEqual(after['delegation_generation'],
                         before['delegation_generation'] + 1)
        self.assertEqual(after['applied_binding'], before['applied_binding'])
        self.assertIsNotNone(self.flow.flow.db.get('jobs', 'APPLICATION_OUTBOX',
                                                  stopped['revocation_id']))

    def test_only_policy_absence_and_all_deny_promote_confirmed_suspension(self):
        stopped = self.stop()
        state = self.worker(RevocationPublisher()).process({k: stopped[k] for k in (
            'operation', 'object_id', 'application_id', 'enforcement_digest',
            'revocation_id', 'revocation_digest')})
        self.assertEqual(state['status'], 'SUSPENDED_CONFIRMED')
        head = self.app.detail(ACTOR, self.oid)['object']
        self.assertEqual(head['application_status'], 'SUSPENDED_CONFIRMED')
        self.assertEqual(head['authority_control']['policy_status'], 'REMOVED')
        self.assertEqual(head['authority_control']['deny_status'], 'CONFIRMED')
        self.assertFalse(head['authority_control']['runtime_authority_active'])
        self.assertIsNone(self.flow.flow.db.get(
            'jobs', 'AUTHORITY_EXPIRY', self.started['application_id']))
        exported = self.app.export_acceptance_evidence(ACTOR, self.oid)
        self.assertEqual(exported['schema_version'], '1.1')
        self.assertEqual(exported['revocations'][0]['document']['state']['status'],
                         'SUSPENDED_CONFIRMED')

    def test_uncertain_customer_result_never_claims_suspension(self):
        stopped = self.stop()
        state = self.worker(RevocationPublisher(TimeoutError('response lost'))).process(
            {k: stopped[k] for k in ('operation', 'object_id', 'application_id',
                                     'enforcement_digest', 'revocation_id',
                                     'revocation_digest')})
        self.assertEqual(state['status'], 'UNKNOWN')
        head = self.app.detail(ACTOR, self.oid)['object']
        self.assertEqual(head['application_status'], 'STOP_UNKNOWN')
        self.assertEqual(head['authority_control']['entry_status'], 'CLOSED')
        self.assertEqual(head['authority_control']['deny_status'], 'NOT_CONFIRMED')
        self.assertIsNotNone(self.flow.flow.db.get('app', state['lock_pk'], 'WRITER'))

    def test_expiry_deterministically_closes_and_queues_same_authority(self):
        self.flow.flow.clock.advance(86400)
        request_due_expiries(self.flow.flow.db, self.flow.flow.blobs,
                             self.flow.flow.clock)
        head = self.app.detail(ACTOR, self.oid)['object']
        self.assertEqual(head['authority_control']['trigger'], 'EXPIRY')
        self.assertEqual(head['authority_control']['entry_status'], 'CLOSED')
        rid = head['authority_control']['revocation_id']
        self.assertIsNotNone(self.flow.flow.db.get('app', self.oid,
                                                  'REVOCATION#' + rid))
        message = self.flow.flow.db.get('jobs', 'APPLICATION_OUTBOX', rid).value
        request_due_expiries(self.flow.flow.db, self.flow.flow.blobs,
                             self.flow.flow.clock)
        self.assertEqual(self.flow.flow.db.get('jobs', 'APPLICATION_OUTBOX', rid).value,
                         message)

    def test_application_writer_blocks_revocation_without_false_progress(self):
        stopped = self.stop()
        state = self.flow.flow.db.get('app', self.oid,
            'APPLICATION#' + self.started['application_id'])
        lock = {'application_id': self.started['application_id'],
            'object_id': self.oid,
            'enforcement_digest': self.started['enforcement_digest']}
        self.flow.flow.db.transact([('app', state.value['lock_pk'], 'WRITER', lock, None)])
        publisher = RevocationPublisher()
        message = {k: stopped[k] for k in ('operation', 'object_id', 'application_id',
            'enforcement_digest', 'revocation_id', 'revocation_digest')}
        result = self.worker(publisher).process(message)
        self.assertEqual(result['status'], 'STOP_REQUESTED')
        self.assertEqual(publisher.calls, [])
        self.assertEqual(self.app.detail(ACTOR, self.oid)['object']['application_status'],
                         'STOP_REQUESTED')


class CustomerRevocationContracts(unittest.TestCase):
    def test_customer_publisher_journals_delete_then_proves_all_deny(self):
        candidate, registration = aws_contracts.candidate_fixture()
        control, probe, journal = (aws_contracts.PolicyControl(),
                                   aws_contracts.ProbeDouble(), MemoryStore())
        publisher = CustomerPolicyPublisher(control, journal, probe, registration,
            lambda: '2026-09-09T00:01:00+00:00', sleep=lambda _: None)
        publication = publisher.publish(candidate)
        applied = {'application_id': candidate['application_id'],
            'enforcement_digest': candidate['enforcement_digest'],
            'policy_id': publication['policy_id'], 'policy_name': publication['policy_name'],
            'policy_hash': publication['policy_hash']}
        applied['digest'] = sha256_json(applied)
        request = build_revocation_request(
            revocation_id='revocation-' + 'a' * 32, candidate=candidate,
            applied_binding=applied, trigger='MANUAL', reason='Local exact stop',
            actor=ACTOR, requested_at='2026-09-09T00:00:30+00:00',
            invalidated_generation=2)
        result = publisher.revoke(candidate, request)
        result['publisher_invocation'] = raw_revocation_result(
            candidate, request)['publisher_invocation']
        verify_revocation_result(result, request, candidate)
        self.assertEqual(control.deleted, [publication['policy_id']])
        count = len(candidate['expected_outcomes'])
        self.assertEqual([outcome for _, outcome in probe.calls[-count:]],
                         ['DENY'] * count)
        self.assertEqual(publisher.revoke(candidate, request)['status'],
                         'POLICY_REMOVED_DENY_CONFIRMED')
        with self.assertRaisesRegex(ValueError, 'fenced'):
            publisher.publish(candidate)

    def test_lost_delete_response_resumes_only_the_same_journaled_revocation(self):
        class LostDeleteControl(aws_contracts.PolicyControl):
            def __init__(self):
                super().__init__()
                self.lose_delete = True

            def delete_policy(self, **values):
                response = super().delete_policy(**values)
                if self.lose_delete:
                    self.lose_delete = False
                    raise TimeoutError('delete response lost after customer removal')
                return response

        candidate, registration = aws_contracts.candidate_fixture()
        control, journal = LostDeleteControl(), MemoryStore()
        publisher = CustomerPolicyPublisher(control, journal,
            aws_contracts.ProbeDouble(), registration,
            lambda: '2026-09-09T00:01:00+00:00', sleep=lambda _: None)
        publication = publisher.publish(candidate)
        applied = {'application_id': candidate['application_id'],
            'enforcement_digest': candidate['enforcement_digest'],
            'policy_id': publication['policy_id'],
            'policy_name': publication['policy_name'],
            'policy_hash': publication['policy_hash']}
        applied['digest'] = sha256_json(applied)
        request = build_revocation_request(
            revocation_id='revocation-' + 'b' * 32, candidate=candidate,
            applied_binding=applied, trigger='MANUAL', reason='Lost response recovery',
            actor=ACTOR, requested_at='2026-09-09T00:00:30+00:00',
            invalidated_generation=2)
        with self.assertRaises(TimeoutError):
            publisher.revoke(candidate, request)
        self.assertIsNone(control.policy)
        row = journal.get('publisher', candidate['enforcement_digest'], 'STATE')
        self.assertEqual(row.value['status'], 'POLICY_DELETE_INTENT')
        result = publisher.revoke(candidate, request)
        self.assertEqual(result['status'], 'POLICY_REMOVED_DENY_CONFIRMED')
        self.assertTrue(result['checks']['policy_absent_readback'])


if __name__ == '__main__':
    unittest.main()
