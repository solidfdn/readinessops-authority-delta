"""Local D3 authority separation, single-writer and recovery contracts."""
import copy
import json
import unittest
import uuid
from pathlib import Path

import test_business as existing
from authority_delta.business.application import ApplicationWorker
from authority_delta.business.delegation import load_adapter_registry, verify_delegation_receipt
from authority_delta.business.service import BusinessService, Problem
from authority_delta.canonical import sha256_json
from services.business.handler import handle
from support.business import ACTOR, vendor_registration


def publisher_result(candidate, status='VERIFIED'):
    recovered = status == 'RECOVERED_CLOSED'
    expected = {x['request_id']: x['expected_outcome'] for x in candidate['expected_outcomes']}
    outcomes = [{'request_id': request_id,
                 'outcome': 'DENY' if recovered else outcome,
                 'evidence_hash': sha256_json({'request_id': request_id,
                                               'outcome': 'DENY' if recovered else outcome})}
                for request_id, outcome in sorted(expected.items())]
    closed = [{'request_id': request_id, 'outcome': 'DENY',
               'evidence_hash': sha256_json({'phase': 'closed', 'request_id': request_id,
                                             'outcome': 'DENY'})}
              for request_id in sorted(expected)]
    return {'schema_version': '1.0', 'status': status,
            'application_id': candidate['application_id'],
            'enforcement_digest': candidate['enforcement_digest'],
            'policy_id': 'policy-local-test-only',
            'policy_name': 'AuthorityDeltaApp_' + candidate['enforcement_digest'][:16],
            'policy_hash': candidate['policy_binding']['policy_hash'],
            'observed_at': '2026-09-09T00:00:30+00:00',
            'publisher_invocation': {
                'function_arn': candidate['publisher_binding']['function_arn'],
                'request_id': 'LOCAL_SCRIPTED_PUBLISHER_ONLY', 'http_status': 200,
                'executed_version': 'live',
                'invoke_role_arn': candidate['publisher_binding']['invoke_role_arn'],
                'assume_role_request_id': ('LOCAL_SCRIPTED_STS_ONLY'
                    if candidate['connection_mode'] == 'LIVE_CUSTOMER'
                    else 'LOCAL_NOT_ASSUMED')},
            'previous_binding_status': ('RETIRED' if not recovered and candidate['previous_applied_binding']
                                        else 'PRESERVED' if recovered and candidate['previous_applied_binding']
                                        else 'NONE'),
            'checks': {'candidate_closed_before_write': True,
                       'policy_active_readback': not recovered,
                       'same_runtime_role_policy_for_canary': not recovered,
                       'candidate_cleanup_readback': recovered},
            'closed_outcomes': closed, 'outcomes': outcomes}


class ScriptedPublisher:
    def __init__(self, publish='VERIFIED', reconcile='VERIFIED'):
        self.publish_result, self.reconcile_result = publish, reconcile
        self.calls = []

    def _result(self, kind, candidate, value, require_closed=False):
        self.calls.append((kind, candidate['enforcement_digest'], require_closed))
        if isinstance(value, Exception):
            raise value
        return publisher_result(candidate, value)

    def publish(self, candidate):
        return self._result('publish', candidate, self.publish_result)

    def reconcile(self, candidate, require_closed=False):
        return self._result('reconcile', candidate, self.reconcile_result, require_closed)


class DelegationFlow(unittest.TestCase):
    def setUp(self):
        self.flow = existing.Flow(methodName='test_nonpayment_cycle_and_new_input_preserves_official_history')
        self.flow.setUp()
        self.registration = vendor_registration()
        self.flow.app = BusinessService(self.flow.db, self.flow.blobs, clock=self.flow.clock,
                                        adapters=[self.registration])
        self.app, self.oid = self.flow.app, self.flow.oid

    def command(self, **values):
        return dict(request_id=uuid.uuid4().hex,
                    expected_revision=self.app.detail(ACTOR, self.oid)['object']['record_revision'],
                    **values)

    def publish(self):
        receipt = self.flow.approve()
        return self.app.publish(ACTOR, self.oid,
                                self.command(receipt_id=receipt['receipt_id']))

    def connect(self):
        if not self.app.detail(ACTOR, self.oid)['object'].get('execution_connection'):
            self.app.connect_adapter(ACTOR, self.oid, self.command(
                **{k:self.registration[k] for k in ('adapter_id','adapter_version','connection_id','registration_hash')},
                reason='Local test reviewer explicitly selects this registered execution scope'))

    def delegate(self, profile='MAINTAIN', days=7):
        self.connect()
        current = self.app.detail(ACTOR, self.oid)['object']['published_current']
        return self.app.approve_delegation(ACTOR, self.oid, self.command(
            publication_id=current['publication_id'], publication_digest=current['digest'],
            adapter_id='vendor_payment', adapter_version='1.0.0',
            connection_id=self.registration['connection_id'], profile_id=profile,
            reason='Local reviewer separately authorized this exact registered boundary',
            valid_days=days))

    def start(self, receipt):
        return self.app.start_application(ACTOR, self.oid, self.command(
            delegation_receipt_id=receipt['delegation_receipt_id']))

    def worker(self, publisher):
        return ApplicationWorker(self.flow.db, self.flow.blobs, publisher,
                                 [self.registration], self.flow.clock)

    def message(self, started):
        return {k: started[k] for k in ('object_id', 'application_id', 'enforcement_digest')}

    def test_business_approval_and_publication_never_imply_aws_authority(self):
        publication = self.publish()
        detail = self.app.detail(ACTOR, self.oid)
        self.assertEqual(detail['object']['application_status'], 'NOT_APPLIED')
        self.assertIsNone(detail['object']['applied_binding'])
        self.assertIsNone(detail['object']['delegation_approval'])
        self.assertEqual(detail['available_adapters'], [])
        self.assertEqual(detail['registered_adapters'][0]['adapter_id'], 'vendor_payment')
        self.assertEqual(publication['application_status'], 'NOT_APPLIED')

    def test_no_registered_adapter_fails_closed(self):
        self.assertEqual(load_adapter_registry(Path(__file__).resolve().parents[1] /
                         'services/business/adapter_registrations.json'), [])
        publication = self.publish()
        closed = BusinessService(self.flow.db, self.flow.blobs, clock=self.flow.clock)
        body = self.command(publication_id=publication['publication_id'],
            publication_digest=publication['digest'], adapter_id='vendor_payment',
            adapter_version='1.0.0', connection_id=self.registration['connection_id'],
            profile_id='MAINTAIN', reason='Separate authority', valid_days=7)
        with self.assertRaises(Problem) as ctx:
            closed.approve_delegation(ACTOR, self.oid, body)
        self.assertEqual(ctx.exception.code, 'ADAPTER_NOT_REGISTERED')
        self.assertEqual(closed.detail(ACTOR, self.oid)['available_adapters'], [])

    def test_typed_receipt_binds_publication_adapter_runtime_policy_and_canary(self):
        publication = self.publish()
        approved = self.delegate('NARROW')
        detail = self.app.detail(ACTOR, self.oid)
        recorded = detail['delegation_receipts'][0]
        raw = json.loads(self.flow.blobs.read(recorded['ref']))
        verified = verify_delegation_receipt(raw, object_record=detail['object'],
            publication=publication, registration=self.registration,
            current_generation=detail['object']['delegation_generation'], at=self.flow.clock())
        self.assertEqual(verified['kind'], 'AWS_DELEGATION_AUTHORITY')
        self.assertFalse(approved['runtime_authority_active'])
        self.assertFalse(verified['runtime_authority_active'])
        self.assertEqual(verified['execution_binding']['target_account_id'], '111122223333')
        self.assertEqual(len([x for x in verified['expected_outcomes']
                              if x['expected_outcome'] == 'ALLOW']), 1)
        self.assertEqual(detail['object']['application_status'], 'DELEGATION_APPROVED')

    def test_receipt_tampering_is_rejected(self):
        self.publish()
        self.delegate()
        detail = self.app.detail(ACTOR, self.oid)
        recorded = detail['delegation_receipts'][0]
        raw = json.loads(self.flow.blobs.read(recorded['ref']))
        mutations = [
            lambda x: x.update(publication_digest='0' * 64),
            lambda x: x.update(connection_id='conn-foreign-vendor'),
            lambda x: x['execution_binding'].update(target_account_id='999900001111'),
            lambda x: x['discovery_binding'].update(
                role_arn='arn:aws:iam::999900001111:role/foreign-discovery'),
            lambda x: x['publisher_binding'].update(
                invoke_role_arn='arn:aws:iam::999900001111:role/foreign-publish'),
            lambda x: x['publisher_binding'].update(
                external_id='foreign-external-id-00000000000001'),
            lambda x: x['policy_binding'].update(policy_hash='0' * 64),
            lambda x: x['expected_outcomes'][0].update(expected_outcome=(
                'DENY' if x['expected_outcomes'][0]['expected_outcome'] == 'ALLOW' else 'ALLOW')),
        ]
        for mutate in mutations:
            changed = copy.deepcopy(raw)
            mutate(changed)
            with self.subTest(changed=changed):
                with self.assertRaises(ValueError):
                    verify_delegation_receipt(changed, object_record=detail['object'],
                        publication=detail['object']['published_current'],
                        registration=self.registration,
                        current_generation=detail['object']['delegation_generation'],
                        at=self.flow.clock())

    def test_application_is_idempotent_and_one_writer_per_connection_engine(self):
        self.publish()
        receipt = self.delegate()
        command = self.command(delegation_receipt_id=receipt['delegation_receipt_id'])
        first = self.app.start_application(ACTOR, self.oid, command)
        self.assertEqual(self.app.start_application(ACTOR, self.oid, command), first)
        with self.assertRaises(Problem) as ctx:
            self.start(receipt)
        self.assertEqual(ctx.exception.code, 'APPLICATION_ACTIVE')
        lock_pk = 'AUTHORITY#' + self.registration['connection_id'] + '#' + self.registration['policy_engine_id']
        self.assertEqual(self.flow.db.get('app', lock_pk, 'WRITER').value['application_id'],
                         first['application_id'])

    def test_connection_writer_lock_blocks_a_second_object(self):
        self.publish()
        self.start(self.delegate())
        second = self.app.create(ACTOR, dict(request_id=uuid.uuid4().hex,
            name='Second local object', purpose='Exercise a cross-object writer collision',
            question='Can another object use the same connection?', owner='Local test'))['object_id']
        self.oid = second
        self.flow.oid = second
        self.publish()
        receipt = self.delegate()
        with self.assertRaises(Problem) as ctx:
            self.start(receipt)
        self.assertEqual(ctx.exception.code, 'APPLICATION_ACTIVE')

    def test_application_dispatch_contains_only_committed_candidate_identity(self):
        messages = []
        self.app = BusinessService(self.flow.db, self.flow.blobs, clock=self.flow.clock,
            adapters=[self.registration], application_dispatch=messages.append)
        self.flow.app = self.app
        self.publish()
        receipt = self.delegate()
        command = self.command(delegation_receipt_id=receipt['delegation_receipt_id'])
        started = self.app.start_application(ACTOR, self.oid, command)
        self.app.start_application(ACTOR, self.oid, command)
        self.assertEqual(messages, [self.message(started), self.message(started)])

    def test_verified_canary_is_only_transition_to_applied_binding(self):
        self.publish()
        started = self.start(self.delegate())
        before = self.app.detail(ACTOR, self.oid)['object']
        self.assertIsNone(before['applied_binding'])
        publisher = ScriptedPublisher()
        message = self.message(started)
        state = self.worker(publisher).process(message)
        after = self.app.detail(ACTOR, self.oid)['object']
        self.assertEqual(state['status'], 'VERIFIED')
        self.assertEqual(after['application_status'], 'VERIFIED')
        self.assertTrue(after['applied_binding']['runtime_authority_active'])
        self.assertEqual(after['applied_binding']['enforcement_digest'],
                         started['enforcement_digest'])
        self.assertEqual(publisher.calls[0][0], 'publish')
        self.assertIsNone(self.flow.db.get('app', state['lock_pk'], 'WRITER'))
        self.assertEqual(self.worker(ScriptedPublisher()).process(message)['status'], 'VERIFIED')

    def test_unconfirmed_publish_retains_lock_and_previous_applied_then_reconciles(self):
        self.publish()
        first = self.start(self.delegate('NARROW'))
        self.worker(ScriptedPublisher()).process(self.message(first))
        prior = copy.deepcopy(self.app.detail(ACTOR, self.oid)['object']['applied_binding'])
        second = self.start(self.delegate('MAINTAIN'))
        failed = ScriptedPublisher(publish=RuntimeError('connection lost after write'))
        message = self.message(second)
        state = self.worker(failed).process(message)
        detail = self.app.detail(ACTOR, self.oid)
        self.assertEqual(state['status'], 'UNKNOWN')
        self.assertEqual(detail['object']['application_status'], 'UNKNOWN')
        self.assertEqual(detail['object']['applied_binding'], prior)
        self.assertIsNotNone(self.flow.db.get('app', state['lock_pk'], 'WRITER'))
        with self.assertRaises(Problem) as ctx:
            self.delegate('NARROW')
        self.assertEqual(ctx.exception.code, 'APPLICATION_UNRESOLVED')
        recovered = ScriptedPublisher(reconcile='VERIFIED')
        final = self.worker(recovered).process(message)
        self.assertEqual(final['status'], 'VERIFIED')
        self.assertEqual(recovered.calls[0][0], 'reconcile')
        self.assertIsNone(self.flow.db.get('app', final['lock_pk'], 'WRITER'))

    def test_recovery_can_prove_closed_without_installing_binding(self):
        self.publish()
        started = self.start(self.delegate())
        message = self.message(started)
        self.worker(ScriptedPublisher(publish=RuntimeError('timeout'))).process(message)
        final = self.worker(ScriptedPublisher(reconcile='RECOVERED_CLOSED')).process(message)
        detail = self.app.detail(ACTOR, self.oid)
        self.assertEqual(final['status'], 'RECOVERED_CLOSED')
        self.assertIsNone(detail['object']['applied_binding'])
        self.assertEqual(detail['object']['application_status'], 'RECOVERED_CLOSED')

    def test_invalid_publisher_evidence_is_unknown_and_never_applied(self):
        class InvalidPublisher(ScriptedPublisher):
            def publish(inner, candidate):
                value = publisher_result(candidate)
                value['policy_name'] = 'ForeignPolicy'
                return value
        self.publish()
        started = self.start(self.delegate())
        state = self.worker(InvalidPublisher()).process(self.message(started))
        detail = self.app.detail(ACTOR, self.oid)
        self.assertEqual(state['status'], 'UNKNOWN')
        self.assertIsNone(detail['object']['applied_binding'])
        self.assertIsNotNone(self.flow.db.get('app', state['lock_pk'], 'WRITER'))

    def test_expired_receipt_and_browser_supplied_authority_are_rejected(self):
        self.publish()
        receipt = self.delegate(days=1)
        self.flow.clock.advance(86401)
        with self.assertRaises(Problem) as ctx:
            self.start(receipt)
        self.assertEqual(ctx.exception.code, 'DELEGATION_INTEGRITY_FAILED')
        env = {'CLIENT_ID': 'client', 'REVIEWER_SUB': ACTOR['sub'],
               'REVIEWER_USERNAME': 'local'}
        current = self.app.detail(ACTOR, self.oid)['object']['published_current']
        body = self.command(publication_id=current['publication_id'],
            publication_digest=current['digest'], adapter_id='vendor_payment',
            adapter_version='1.0.0', connection_id=self.registration['connection_id'],
            profile_id='MAINTAIN', reason='Exact registered authority', valid_days=7,
            gateway_arn=self.registration['gateway_arn'])
        event = {'rawPath': '/business/objects/' + self.oid + '/delegation',
                 'body': json.dumps(body), 'requestContext': {'http': {'method': 'POST'},
                 'authorizer': {'jwt': {'claims': {'token_use': 'access',
                 'client_id': 'client', 'sub': ACTOR['sub'],
                 'scope': 'authority-delta/read authority-delta/approve'}}}}}
        self.assertEqual(handle(event, self.app, env)['statusCode'], 422)


if __name__ == '__main__':
    unittest.main()
