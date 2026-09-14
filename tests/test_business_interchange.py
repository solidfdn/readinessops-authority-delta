"""RO-10/11 metric semantics and fixed Decision Pack/Outcome interchange."""
import copy
import json
import unittest
import uuid

import test_business as existing
from authority_delta.business.interchange import verify_interchange
from authority_delta.business.service import Problem
from authority_delta.canonical import sha256_json
from services.business.handler import handle
from support.business import ACTOR


def externalize(document, authority='snowflake:solifan-reference'):
    value = copy.deepcopy(document)
    value['authority_source'] = authority
    pack = value['decision_pack']
    pack['source_authority'] = authority
    pack['digest'] = sha256_json({k: v for k, v in pack.items() if k != 'digest'})
    value['decision_digest'] = pack['digest']
    publication = value['publication']
    publication['source_authority'] = authority
    publication['digest'] = pack['digest']
    for outcome in value['outcomes']:
        outcome['authority_source'] = authority
        outcome['decision_digest'] = pack['digest']
        outcome['digest'] = sha256_json({k: v for k, v in outcome.items()
                                         if k != 'digest'})
    value['document_digest'] = sha256_json({k: v for k, v in value.items()
                                            if k != 'document_digest'})
    return value


class InterchangeFlow(unittest.TestCase):
    def setUp(self):
        self.flow = existing.Flow(
            methodName='test_nonpayment_cycle_and_new_input_preserves_official_history')
        self.flow.setUp()
        self.app, self.oid = self.flow.app, self.flow.oid

    def command(self, **values):
        detail = self.app.detail(ACTOR, self.oid)
        return dict(request_id=uuid.uuid4().hex,
                    expected_revision=detail['object']['record_revision'], **values)

    def publish(self):
        receipt = self.flow.approve()
        return self.app.publish(ACTOR, self.oid,
            self.command(receipt_id=receipt['receipt_id']))

    def outcome_body(self, publication, metrics=None):
        return self.command(target={
                'kind': 'DECISION_PUBLICATION', 'id': publication['publication_id'],
                'digest': publication['digest']},
            authority_result='ALLOW',
            business_result='Reviewer observed the approved data-sharing procedure.',
            metrics=metrics if metrics is not None else [])

    def test_measured_and_unmeasured_metrics_export_without_invented_zero(self):
        publication = self.publish()
        metrics = [
            {'name': 'Weekly review time', 'measurement_status': 'MEASURED',
             'value': 42.5, 'unit': 'minutes/week', 'period': '2026-W36',
             'source': 'Operations time log', 'basis': 'OBSERVED'},
            {'name': 'Error reduction', 'measurement_status': 'NOT_MEASURED',
             'source': 'No baseline collected',
             'reason': 'A comparable pre-change period is unavailable'},
        ]
        response = self.app.record_outcome(
            ACTOR, self.oid, self.outcome_body(publication, metrics))
        self.assertFalse(response['runtime_authority_changed'])
        exported = self.app.export_interchange(ACTOR, self.oid)
        self.assertEqual(exported, self.app.export_interchange(ACTOR, self.oid))
        self.assertEqual(exported['transport_status'], 'FILE_INTERCHANGE_ONLY')
        self.assertNotIn('ref', exported['publication'])
        outcome = exported['outcomes'][0]
        self.assertEqual(outcome['metrics'][0]['basis'], 'OBSERVED')
        self.assertEqual(outcome['metrics'][1]['measurement_status'], 'NOT_MEASURED')
        self.assertNotIn('value', outcome['metrics'][1])
        self.assertEqual(verify_interchange(exported), exported)

    def test_outcome_rejects_false_value_stale_target_and_prepublication(self):
        with self.assertRaises(Problem) as caught:
            self.app.record_outcome(ACTOR, self.oid, self.command(
                target={'kind': 'TRACE', 'id': 'trace-12345678'},
                authority_result='ALLOW', business_result='No publication', metrics=[]))
        self.assertEqual(caught.exception.code, 'PUBLICATION_REQUIRED')
        publication = self.publish()
        bad = [{'name': 'Savings', 'measurement_status': 'NOT_MEASURED',
                'value': 0, 'source': 'No observation', 'reason': 'Not collected'}]
        with self.assertRaises(Problem):
            self.app.record_outcome(ACTOR, self.oid,
                                    self.outcome_body(publication, bad))
        body = self.outcome_body(publication)
        body['target']['digest'] = '0' * 64
        with self.assertRaises(Problem) as caught:
            self.app.record_outcome(ACTOR, self.oid, body)
        self.assertEqual(caught.exception.code, 'OUTCOME_TARGET_STALE')
        self.assertEqual(self.app.detail(ACTOR, self.oid)['outcome_records'], [])

    def test_external_import_is_fixed_idempotent_and_never_canonical(self):
        publication = self.publish()
        self.app.record_outcome(ACTOR, self.oid,
                                self.outcome_body(publication))
        external = externalize(self.app.export_interchange(ACTOR, self.oid))
        target = existing.Flow(
            methodName='test_nonpayment_cycle_and_new_input_preserves_official_history')
        target.setUp()
        target_app, target_oid = target.app, target.oid

        def target_command(document):
            revision = target_app.detail(ACTOR, target_oid)['object']['record_revision']
            return {'request_id': uuid.uuid4().hex, 'expected_revision': revision,
                    'document': document}

        before = copy.deepcopy(target_app.detail(ACTOR, target_oid)['object'])
        first = target_app.import_interchange(
            ACTOR, target_oid, target_command(external))
        self.assertFalse(first['canonical_decision_changed'])
        self.assertFalse(first['runtime_authority_changed'])
        after = target_app.detail(ACTOR, target_oid)
        self.assertEqual(after['object']['published_current'], before['published_current'])
        self.assertEqual(after['object']['application_status'], before['application_status'])
        self.assertEqual(after['imported_records'][0]['authority_source'],
                         'snowflake:solifan-reference')
        replay = target_app.import_interchange(
            ACTOR, target_oid, target_command(external))
        self.assertTrue(replay['already_imported'])

        conflict = externalize(external, 'snowflake:other-issuer')
        with self.assertRaises(Problem) as caught:
            target_app.import_interchange(
                ACTOR, target_oid, target_command(conflict))
        self.assertEqual(caught.exception.code, 'PACK_AUTHORITY_CONFLICT')

    def test_tamper_and_own_authority_import_fail_closed(self):
        self.publish()
        exported = self.app.export_interchange(ACTOR, self.oid)
        target = existing.Flow(
            methodName='test_nonpayment_cycle_and_new_input_preserves_official_history')
        target.setUp()
        target_app, target_oid = target.app, target.oid
        revision = target_app.detail(ACTOR, target_oid)['object']['record_revision']
        def body(document):
            return {'request_id': uuid.uuid4().hex, 'expected_revision': revision,
                    'document': document}
        with self.assertRaises(Problem) as caught:
            target_app.import_interchange(ACTOR, target_oid, body(exported))
        self.assertEqual(caught.exception.code, 'OWN_AUTHORITY_IMPORT_REJECTED')
        tampered = externalize(exported)
        tampered['decision_pack']['proposal']['summary'] = 'Changed after export'
        with self.assertRaises(Problem) as caught:
            target_app.import_interchange(ACTOR, target_oid, body(tampered))
        self.assertEqual(caught.exception.code, 'INTERCHANGE_INVALID')
        self.assertEqual(target_app.detail(ACTOR, target_oid)['imported_records'], [])

    def test_api_routes_require_read_or_write_and_reject_extra_fields(self):
        publication = self.publish()
        env = {'CLIENT_ID': 'client', 'REVIEWER_SUB': ACTOR['sub'],
               'REVIEWER_USERNAME': 'local'}
        def event(method, path, scope, value=None):
            return {'rawPath': path, 'body': json.dumps(value),
                    'requestContext': {'http': {'method': method},
                        'authorizer': {'jwt': {'claims': {
                            'token_use': 'access', 'client_id': 'client',
                            'sub': ACTOR['sub'], 'scope': scope}}}}}
        base = '/business/objects/' + self.oid
        self.assertEqual(handle(event('GET', base + '/interchange',
            'authority-delta/read'), self.app, env)['statusCode'], 200)
        body = self.outcome_body(publication)
        self.assertEqual(handle(event('POST', base + '/outcomes',
            'authority-delta/read', body), self.app, env)['statusCode'], 403)
        bad = dict(body, approver_sub='forged')
        self.assertEqual(handle(event('POST', base + '/outcomes',
            'authority-delta/read authority-delta/write', bad),
            self.app, env)['statusCode'], 422)
        self.assertEqual(handle(event('POST', base + '/outcomes',
            'authority-delta/read authority-delta/write', body),
            self.app, env)['statusCode'], 200)


if __name__ == '__main__':
    unittest.main()
