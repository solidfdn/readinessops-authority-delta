"""D4 authenticated, redacted and tamper-evident object export contracts."""
import copy
import json
import unittest

from authority_delta.business.acceptance import verify_acceptance_evidence
from authority_delta.business.service import Problem
from authority_delta.canonical import sha256_json
from services.business.handler import handle
from support.business import ACTOR
import test_business_delegation as d3


class AcceptanceEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.flow = d3.DelegationFlow(
            methodName='test_verified_canary_is_only_transition_to_applied_binding')
        self.flow.setUp()
        self.app, self.oid = self.flow.app, self.flow.oid

    def verified_flow(self):
        publication = self.flow.publish()
        started = self.flow.start(self.flow.delegate('MAINTAIN'))
        self.flow.worker(d3.ScriptedPublisher()).process(self.flow.message(started))
        self.app.record_outcome(ACTOR, self.oid, self.flow.command(
            target={'kind': 'AWS_APPLICATION', 'id': started['application_id'],
                    'digest': started['enforcement_digest']},
            authority_result='ALLOW',
            business_result='The bounded local acceptance fixture completed.',
            metrics=[{'name': 'Review time', 'measurement_status': 'NOT_MEASURED',
                      'source': 'Local acceptance fixture',
                      'reason': 'No live observation was performed'}]))
        return publication, started

    def test_export_verifies_complete_chain_and_redacts_external_id(self):
        publication, started = self.verified_flow()
        exported = self.app.export_acceptance_evidence(ACTOR, self.oid)
        self.assertEqual(verify_acceptance_evidence(exported), exported)
        self.assertEqual(exported['scope'], 'AUTHENTICATED_READ_ONLY_OBJECT_EXPORT')
        self.assertFalse(exported['runtime_authority_changed_by_export'])
        self.assertEqual(exported['decisions'][0]['document']['publication']
                         ['publication_id'], publication['publication_id'])
        self.assertEqual(exported['applications'][0]['document']['state']
                         ['application_id'], started['application_id'])
        encoded = json.dumps(exported)
        self.assertNotIn(self.flow.registration['publisher_binding']['external_id'], encoded)
        self.assertNotIn('"external_id"', encoded)
        self.assertIn('external_id_sha256', encoded)

    def test_projection_and_semantic_tampering_fail_closed(self):
        self.verified_flow()
        exported = self.app.export_acceptance_evidence(ACTOR, self.oid)
        changed = copy.deepcopy(exported)
        changed['applications'][0]['document']['state']['publication_id'] = 'pub-foreign00000000'
        with self.assertRaises(ValueError):
            verify_acceptance_evidence(changed)

        changed['applications'][0]['projection_sha256'] = sha256_json(
            changed['applications'][0]['document'])
        changed['document_digest'] = sha256_json({k: v for k, v in changed.items()
                                                  if k != 'document_digest'})
        with self.assertRaisesRegex(ValueError, 'Application authority chain'):
            verify_acceptance_evidence(changed)

    def test_source_blob_corruption_blocks_export(self):
        self.verified_flow()
        state = self.flow.flow.db.query('app', self.oid, 'APPLICATION#')[0].value
        ref = state['candidate_ref']
        self.flow.flow.blobs.data[(ref['key'], ref['version_id'])] = b'{}'
        with self.assertRaises(Problem) as caught:
            self.app.export_acceptance_evidence(ACTOR, self.oid)
        self.assertEqual(caught.exception.code, 'INTEGRITY_FAILED')

    def test_recovered_closed_result_is_exported_without_applied_binding(self):
        self.flow.publish()
        started = self.flow.start(self.flow.delegate())
        message = self.flow.message(started)
        self.flow.worker(d3.ScriptedPublisher(publish=RuntimeError('timeout'))).process(message)
        self.flow.worker(d3.ScriptedPublisher(
            reconcile='RECOVERED_CLOSED')).process(message)
        exported = self.app.export_acceptance_evidence(ACTOR, self.oid)
        application = exported['applications'][0]['document']
        self.assertEqual(application['state']['status'], 'RECOVERED_CLOSED')
        self.assertEqual(application['publisher_result']['status'], 'RECOVERED_CLOSED')
        self.assertIsNone(exported['object']['document']['applied_binding'])

    def test_route_requires_read_scope_and_uses_authenticated_object_owner(self):
        self.verified_flow()
        env = {'CLIENT_ID': 'client', 'REVIEWER_SUB': ACTOR['sub'],
               'REVIEWER_USERNAME': ACTOR['name']}
        def event(sub=ACTOR['sub'], scope='authority-delta/read'):
            return {'rawPath': '/business/objects/' + self.oid + '/acceptance-evidence',
                    'requestContext': {'http': {'method': 'GET'},
                    'authorizer': {'jwt': {'claims': {'token_use': 'access',
                    'client_id': 'client', 'sub': sub, 'scope': scope}}}}}
        response = handle(event(), self.app, env)
        self.assertEqual(response['statusCode'], 200)
        self.assertEqual(json.loads(response['body'])['object_id'], self.oid)
        self.assertEqual(handle(event(scope='authority-delta/write'),
                                self.app, env)['statusCode'], 403)
        self.assertEqual(handle(event(sub='other'), self.app, env)['statusCode'], 403)


if __name__ == '__main__':
    unittest.main()
