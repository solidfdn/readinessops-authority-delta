"""D4 positive-path evidence composition without live AWS or human claims."""
from contextlib import redirect_stdout
import copy
import io
import json
from pathlib import Path
import tempfile
import unittest

import test_business as existing
from authority_delta.business.service import BusinessService
from scripts import check_connected_acceptance_readiness as connected_checker
from scripts import check_integrated_acceptance_evidence as checker
from support.business import ACTOR
import test_business_delegation as d3
from test_connected_acceptance_readiness import chain


class IntegratedAcceptanceEvidenceTests(unittest.TestCase):
    def setUp(self):
        documents, raws = chain()
        self.connected = connected_checker.check_chain(documents, raws)
        from build_customer_adapter_registry import build
        registration = build(documents['connector_report']['observed_binding'])['registrations'][0]
        self.payment = d3.DelegationFlow(
            methodName='test_verified_canary_is_only_transition_to_applied_binding')
        self.payment.setUp()
        self.payment.registration = registration
        self.payment.app = BusinessService(self.payment.flow.db, self.payment.flow.blobs,
            clock=self.payment.flow.clock, adapters=[registration])
        self.payment.flow.app = self.payment.app
        self.payment.oid = self.payment.flow.oid

    def payment_export(self, include_recovery=True):
        self.payment.publish()
        if include_recovery:
            failed = self.payment.start(self.payment.delegate('NARROW'))
            message = self.payment.message(failed)
            self.payment.worker(d3.ScriptedPublisher(
                publish=RuntimeError('simulated uncertainty'))).process(message)
            self.payment.worker(d3.ScriptedPublisher(
                reconcile='RECOVERED_CLOSED')).process(message)

        action = self.payment.app.detail(ACTOR, self.payment.oid)['action_records'][0]
        self.payment.app.update_action(ACTOR, self.payment.oid, action['action_id'],
            self.payment.command(expected_action_revision=action['record_revision'],
                status='ACTIVE', owner='Operations', due_on='2026-09-30',
                reason='Assign the published action', resolution_evidence_ids=[]))
        evidence_id = self.payment.flow.evidence(
            'The data owner approved the documented scope. A processor contract is signed.',
            'resolution.txt')
        action = self.payment.app.detail(ACTOR, self.payment.oid)['action_records'][0]
        self.payment.app.update_action(ACTOR, self.payment.oid, action['action_id'],
            self.payment.command(expected_action_revision=action['record_revision'],
                status='COMPLETED', owner='Operations', due_on='2026-09-30',
                reason='Attach new evidence and complete the action',
                resolution_evidence_ids=[evidence_id]))
        run_id = self.payment.app.start_run(ACTOR, self.payment.oid,
            self.payment.command(evidence_ids=[evidence_id]))['run_id']
        self.payment.flow.work(run_id)
        proposal = self.payment.app.run(ACTOR, self.payment.oid, run_id)['analysis']['proposal']
        draft = self.payment.app.save_draft(ACTOR, self.payment.oid,
            self.payment.command(run_id=run_id, proposal=proposal,
                                 change_reason='Review the changed evidence'))
        receipt = self.payment.app.review(ACTOR, self.payment.oid,
            self.payment.command(digest=draft['digest'], decision='APPROVE',
                                 reason='Reviewer confirmed the reassessment', valid_days=7))
        self.payment.app.publish(ACTOR, self.payment.oid,
            self.payment.command(receipt_id=receipt['receipt_id']))
        started = self.payment.start(self.payment.delegate('MAINTAIN'))
        self.payment.worker(d3.ScriptedPublisher()).process(self.payment.message(started))
        self.payment.app.record_outcome(ACTOR, self.payment.oid,
            self.payment.command(target={'kind': 'AWS_APPLICATION',
                'id': started['application_id'], 'digest': started['enforcement_digest']},
                authority_result='ALLOW',
                business_result='The bounded connected fixture completed.', metrics=[]))
        return self.payment.app.export_acceptance_evidence(ACTOR, self.payment.oid)

    def nonpayment_export(self):
        flow = existing.Flow(
            methodName='test_nonpayment_cycle_and_new_input_preserves_official_history')
        flow.setUp()
        receipt = flow.approve()
        flow.app.publish(ACTOR, flow.oid,
                         flow.command(receipt_id=receipt['receipt_id']))
        return flow.app.export_acceptance_evidence(ACTOR, flow.oid)

    def test_exact_positive_paths_are_ready_only_for_remaining_acceptance(self):
        result = checker.check(self.connected, self.payment_export(),
                               self.nonpayment_export())
        self.assertEqual(result['status'],
                         'READY_FOR_NEGATIVE_UX_AND_JUDGE_ACCEPTANCE')
        self.assertFalse(result['product_ready'])
        self.assertFalse(result['gates_promoted'])
        self.assertIn('RO_12_AUTH_REPLAY_AND_RECONNECTION',
                      result['remaining_required'])

    def test_missing_recovery_and_same_object_fail_closed(self):
        payment = self.payment_export(include_recovery=False)
        nonpayment = self.nonpayment_export()
        with self.assertRaisesRegex(ValueError, 'closed recovery'):
            checker.check(self.connected, payment, nonpayment)
        with self.assertRaisesRegex(ValueError, 'separate objects'):
            checker.check(self.connected, nonpayment, nonpayment)

    def test_connected_registration_and_export_tampering_fail_closed(self):
        payment, nonpayment = self.payment_export(), self.nonpayment_export()
        changed = copy.deepcopy(self.connected)
        changed['bindings']['registration_hash'] = '0' * 64
        with self.assertRaisesRegex(ValueError, 'readiness-bound'):
            checker.check(changed, payment, nonpayment)
        payment['object']['document']['application_status'] = 'UNKNOWN'
        with self.assertRaises(ValueError):
            checker.check(self.connected, payment, nonpayment)

    def test_cli_rejects_duplicate_json_and_writes_bounded_blocked_result(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            connected = root / 'connected.json'
            payment = root / 'payment.json'
            nonpayment = root / 'nonpayment.json'
            output = root / 'result.json'
            connected.write_text('{"result":"PASS","result":"FAIL"}')
            payment.write_text(json.dumps(self.nonpayment_export()))
            nonpayment.write_text(json.dumps(self.nonpayment_export()))
            with redirect_stdout(io.StringIO()):
                code = checker.main(['--connected-readiness', str(connected),
                    '--payment-export', str(payment), '--nonpayment-export',
                    str(nonpayment), '--output', str(output)])
            self.assertEqual(code, 1)
            result = json.loads(output.read_text())
            self.assertEqual(result['status'], 'NOT_READY')
            self.assertIn('Duplicate JSON member', result['error']['message'])


if __name__ == '__main__':
    unittest.main()
