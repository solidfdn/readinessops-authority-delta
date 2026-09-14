"""D2 operational actions stay separate from AI proposals and require evidence."""
import base64
import json
import unittest
import uuid

import test_business as existing
from authority_delta.business.jobs import AssessmentWorker
from authority_delta.business.service import Problem
from services.business.handler import handle
from support.business import ACTOR, observed


class ActionFlow(unittest.TestCase):
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

    def action(self):
        return self.app.detail(ACTOR, self.oid)['action_records'][0]

    def update(self, action, **values):
        defaults = dict(expected_action_revision=action['record_revision'],
                        owner='Operations owner', due_on='2026-09-30',
                        reason='Local reviewer confirmed the operational action',
                        resolution_evidence_ids=[])
        defaults.update(values)
        return self.app.update_action(ACTOR, self.oid, action['action_id'],
                                      self.command(**defaults))

    def add_resolution_evidence(self):
        text = ('The data owner signed the processor terms and approved the external '
                'sharing scope for this exact business object.')
        return self.app.add_evidence(ACTOR, self.oid, self.command(
            filename='resolution.txt', title='Signed scope confirmation',
            source='Local action test',
            content_base64=base64.b64encode(text.encode()).decode()))['evidence_id']

    def test_publication_materializes_proposal_but_never_marks_it_done(self):
        publication = self.publish()
        action = self.action()
        self.assertEqual(action['status'], 'PROPOSED')
        self.assertIsNone(action['owner'])
        self.assertIsNone(action['due_on'])
        self.assertEqual(action['publication_id'], publication['publication_id'])
        self.assertEqual(action['source'], 'PUBLISHED_DECISION_ACTION_PROPOSAL')
        self.assertEqual(len(action['baseline_evidence_ids']), 1)
        self.assertEqual(action['resolution_evidence'], [])
        event = next(e for e in self.app.detail(ACTOR, self.oid)['history']
                     if e['kind'] == 'DECISION_PUBLISHED')
        self.assertIn(action['action_id'], event['details']['proposed_action_ids'])

    def test_assignment_progress_completion_and_reassessment_link(self):
        self.publish()
        action = self.action()
        activated = self.update(action, status='ACTIVE')
        self.assertEqual(activated['status'], 'ACTIVE')
        action = self.action()
        self.update(action, status='IN_PROGRESS',
                    reason='Implementation work has started')
        action = self.action()
        resolution_id = self.add_resolution_evidence()
        action = self.action()
        completed = self.update(action, status='COMPLETED',
                                reason='Signed confirmation resolves the published gap',
                                resolution_evidence_ids=[resolution_id])
        self.assertEqual(completed['status'], 'COMPLETED')
        action = self.action()
        self.assertEqual(action['resolution_evidence'][0]['evidence_id'], resolution_id)
        self.assertIsNone(action['reassessment_run_id'])
        started = self.app.start_run(ACTOR, self.oid,
                                     self.command(evidence_ids=[resolution_id]))
        self.assertEqual(started['linked_completed_action_ids'], [action['action_id']])
        linked = self.action()
        self.assertEqual(linked['reassessment_run_id'], started['run_id'])
        job = self.flow.db.get('jobs', started['run_id'], 'STATE').value
        AssessmentWorker(self.flow.db, self.flow.blobs, observed,
                         self.flow.clock).process({
                             'run_id': started['run_id'],
                             'input_hash': job['input_hash']})
        self.assertEqual(self.app.run(ACTOR, self.oid, started['run_id'])['status'],
                         'REVIEW_REQUIRED')

    def test_completion_rejects_baseline_missing_foreign_and_unreadable_evidence(self):
        self.publish()
        action = self.action()
        self.update(action, status='ACTIVE')
        action = self.action()
        baseline = action['baseline_evidence_ids'][0]
        with self.assertRaises(Problem) as caught:
            self.update(action, status='COMPLETED',
                        resolution_evidence_ids=[baseline])
        self.assertEqual(caught.exception.code, 'NEW_RESOLUTION_EVIDENCE_REQUIRED')
        for evidence_id in ['e-' + 'f' * 32, 'bad']:
            with self.subTest(evidence_id=evidence_id):
                with self.assertRaises(Problem):
                    self.update(action, status='COMPLETED',
                                resolution_evidence_ids=[evidence_id])
        unreadable = self.flow.evidence('%PDF-corrupt', 'broken-resolution.pdf')
        action = self.action()
        with self.assertRaises(Problem) as caught:
            self.update(action, status='COMPLETED',
                        resolution_evidence_ids=[unreadable])
        self.assertEqual(caught.exception.code, 'RESOLUTION_EVIDENCE_INVALID')
        self.assertEqual(self.action()['status'], 'ACTIVE')

    def test_terminal_stale_and_request_replay_fail_closed(self):
        self.publish()
        action = self.action()
        body = self.command(expected_action_revision=action['record_revision'],
                            status='ACTIVE', owner='Owner', due_on='2026-09-30',
                            reason='Assign exact owner and deadline',
                            resolution_evidence_ids=[])
        result = self.app.update_action(ACTOR, self.oid, action['action_id'], body)
        self.assertEqual(self.app.update_action(ACTOR, self.oid, action['action_id'], body),
                         result)
        with self.assertRaises(Problem) as caught:
            self.app.update_action(ACTOR, self.oid, action['action_id'],
                                   dict(body, owner='Different owner'))
        self.assertEqual(caught.exception.code, 'REQUEST_CONFLICT')
        stale = self.command(expected_action_revision=action['record_revision'],
                             status='IN_PROGRESS', owner='Owner', due_on='2026-09-30',
                             reason='Stale update', resolution_evidence_ids=[])
        with self.assertRaises(Problem) as caught:
            self.app.update_action(ACTOR, self.oid, action['action_id'], stale)
        self.assertEqual(caught.exception.code, 'ACTION_STALE')
        current = self.action()
        self.update(current, status='CANCELLED', reason='No longer required')
        with self.assertRaises(Problem) as caught:
            self.update(self.action(), status='ACTIVE')
        self.assertEqual(caught.exception.code, 'ACTION_STATE_INVALID')

    def test_action_route_requires_write_scope_and_strict_schema(self):
        self.publish()
        action = self.action()
        env = {'CLIENT_ID': 'client', 'REVIEWER_SUB': ACTOR['sub'],
               'REVIEWER_USERNAME': 'local'}
        body = self.command(expected_action_revision=action['record_revision'],
                            status='ACTIVE', owner='Operations', due_on='2026-09-30',
                            reason='Assigned by authenticated reviewer',
                            resolution_evidence_ids=[])
        def event(scope, value=body):
            return {'rawPath': '/business/objects/' + self.oid + '/actions/' +
                    action['action_id'], 'body': json.dumps(value),
                    'requestContext': {'http': {'method': 'POST'},
                        'authorizer': {'jwt': {'claims': {
                            'token_use': 'access', 'client_id': 'client',
                            'sub': ACTOR['sub'], 'scope': scope}}}}}
        self.assertEqual(handle(event('authority-delta/read'), self.app, env)
                         ['statusCode'], 403)
        bad = dict(body, approver_sub='forged')
        self.assertEqual(handle(event('authority-delta/read authority-delta/write', bad),
                                self.app, env)['statusCode'], 422)
        self.assertEqual(handle(event('authority-delta/read authority-delta/write'),
                                self.app, env)['statusCode'], 200)


if __name__ == '__main__':
    unittest.main()
