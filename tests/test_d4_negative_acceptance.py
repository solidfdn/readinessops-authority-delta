"""D4 negative HTTP/audit/export composition without live acceptance claims."""
import base64
from contextlib import redirect_stdout
import copy
import hashlib
import io
import json
from pathlib import Path
import tempfile
import unittest
import uuid
from unittest.mock import patch

import test_business as existing
from authority_delta.business.service import BusinessService
from scripts import check_d4_negative_acceptance as checker
from services.business.handler import LOGGER, handle
from support.business import ACTOR


ROOT = Path(__file__).resolve().parents[1]
FULL_SCOPE = ('authority-delta/read authority-delta/write '
              'authority-delta/approve authority-delta/publish')


class D4NegativeAcceptanceTests(unittest.TestCase):
    def setUp(self):
        self.request_number = 0
        self.positive = {
            'schema_version': '1.0', 'scope': checker.POSITIVE_SCOPE,
            'result': 'PASS',
            'status': 'READY_FOR_NEGATIVE_UX_AND_JUDGE_ACCEPTANCE',
            'account_a': checker.ACCOUNT_A, 'account_b': '111122223333',
            'region': checker.REGION, 'product_ready': False,
            'gates_promoted': False,
            'remaining_required': ['RO_02_LIVE_INPUT_BOUNDARY',
                'RO_04_STALE_SCREEN_NEGATIVE',
                'RO_12_AUTH_REPLAY_AND_RECONNECTION'],
        }
        self.manifest = self.build_manifest()

    def flow(self):
        value = existing.Flow(methodName='test_unsupported_pdf_preserved_but_never_analyzed')
        value.setUp()
        return value

    @staticmethod
    def export(flow):
        return flow.app.export_acceptance_evidence(ACTOR, flow.oid)

    def exchange(self, flow, method, path, body=None, *, subject=ACTOR['sub'],
                 scope=FULL_SCOPE):
        self.request_number += 1
        request_id = 'gateway-' + str(self.request_number)
        raw = None if body is None else json.dumps(
            body, ensure_ascii=False, separators=(',', ':'), allow_nan=False)
        event = {'rawPath': path, 'body': raw,
            'requestContext': {'requestId': request_id, 'http': {'method': method},
                'authorizer': {'jwt': {'claims': {
                    'token_use': 'access', 'client_id': 'client', 'sub': subject,
                    'scope': scope}}}}}
        env = {'CLIENT_ID': 'client', 'REVIEWER_SUB': ACTOR['sub'],
               'REVIEWER_USERNAME': ACTOR['name']}
        with patch.object(LOGGER, 'info') as emitted:
            response = handle(event, flow.app, env, 'lambda-fallback')
        emitted.assert_called_once()
        audit = json.loads(emitted.call_args.args[0])
        return {'transport': 'BUSINESS_HANDLER',
            'request': {'gateway_request_id': request_id, 'method': method,
                'path': path, 'body': raw,
                'subject_sha256': hashlib.sha256(subject.encode()).hexdigest()},
            'response': {'status': response['statusCode'], 'body': response['body']},
            'audit': audit}

    def command(self, flow, **values):
        return dict(request_id=uuid.uuid4().hex,
                    expected_revision=self.export(flow)['object']['document']['record_revision'],
                    **values)

    def unreadable_case(self):
        flow = self.flow()
        before = self.export(flow)
        body = self.command(flow, filename='broken.pdf', title='Unreadable synthetic PDF',
            source='D4 synthetic negative fixture',
            content_base64=base64.b64encode(b'%PDF-corrupt').decode())
        added = self.exchange(flow, 'POST',
            f'/business/objects/{flow.oid}/evidence', body)
        after_add = self.export(flow)
        evidence_id = json.loads(added['response']['body'])['evidence_id']
        rejected = self.exchange(flow, 'POST',
            f'/business/objects/{flow.oid}/runs',
            self.command(flow, evidence_ids=[evidence_id]))
        return {'snapshots': [before, after_add, self.export(flow)],
                'exchanges': [added, rejected]}

    def instruction_case(self):
        flow = self.flow()
        text = (ROOT / 'fixtures' / 'd4-instruction-boundary.txt').read_text()
        evidence_id = flow.app.add_evidence(ACTOR, flow.oid,
            self.command(flow, filename='d4-instruction-boundary.txt',
                title='D4 untrusted instruction fixture',
                source='Repository synthetic negative fixture',
                content_base64=base64.b64encode(text.encode()).decode()))['evidence_id']
        before = self.export(flow)
        started = self.exchange(flow, 'POST',
            f'/business/objects/{flow.oid}/runs',
            self.command(flow, evidence_ids=[evidence_id]))
        queued = self.export(flow)
        run_id = json.loads(started['response']['body'])['run_id']
        flow.work(run_id)
        recovered = self.exchange(flow, 'GET',
            f'/business/objects/{flow.oid}/runs/{run_id}')
        return {'snapshots': [before, queued, self.export(flow)],
                'exchanges': [started, recovered]}

    def ro04_cases(self):
        flow = self.flow()
        receipt = flow.approve()
        flow.app.publish(ACTOR, flow.oid,
                         flow.command(receipt_id=receipt['receipt_id']))
        detail = flow.app.detail(ACTOR, flow.oid)
        proposal = copy.deepcopy(detail['draft']['proposal'])
        proposal['summary'] = 'Edited review requires a new exact approval receipt.'
        draft = flow.app.save_draft(ACTOR, flow.oid,
            flow.command(run_id=detail['object']['latest_run'], proposal=proposal,
                         change_reason='D4 stale receipt fixture'))

        stale_before = self.export(flow)
        stale_body = dict(request_id=uuid.uuid4().hex,
            expected_revision=stale_before['object']['document']['record_revision'] - 1,
            digest=draft['digest'], decision='APPROVE', reason='Stale screen',
            valid_days=7)
        stale = self.exchange(flow, 'POST',
            f'/business/objects/{flow.oid}/review', stale_body)
        stale_case = {'snapshots': [stale_before, self.export(flow)],
                      'exchanges': [stale]}

        receipt_before = self.export(flow)
        old = self.exchange(flow, 'POST',
            f'/business/objects/{flow.oid}/publish',
            self.command(flow, receipt_id=receipt['receipt_id']))
        receipt_case = {'snapshots': [receipt_before, self.export(flow)],
                        'exchanges': [old]}
        return stale_case, receipt_case

    def auth_cases(self):
        flow = self.flow()
        before = self.export(flow)
        signed_out = {'transport': 'API_GATEWAY_AUTHORIZER',
            'request': {'gateway_request_id': 'gateway-signed-out', 'method': 'GET',
                'path': f'/business/objects/{flow.oid}', 'body': None,
                'subject_sha256': None},
            'response': {'status': 401,
                         'body': json.dumps({'message': 'Unauthorized'}, separators=(',', ':'))},
            'audit': None}
        signed_case = {'snapshots': [before, self.export(flow)],
                       'exchanges': [signed_out]}

        foreign_before = self.export(flow)
        foreign = self.exchange(flow, 'GET', f'/business/objects/{flow.oid}',
                                subject='foreign-reviewer')
        foreign_case = {'snapshots': [foreign_before, self.export(flow)],
                        'exchanges': [foreign]}

        missing_before = self.export(flow)
        missing = self.exchange(flow, 'POST',
            f'/business/objects/{flow.oid}/evidence', {},
            scope='authority-delta/read')
        missing_case = {'snapshots': [missing_before, self.export(flow)],
                        'exchanges': [missing]}
        return signed_case, foreign_case, missing_case

    def replay_case(self):
        flow = self.flow()
        before = self.export(flow)
        body = self.command(flow, filename='replay.txt', title='Replay fixture',
            source='D4 synthetic replay fixture',
            content_base64=base64.b64encode(b'Synthetic replay evidence.').decode())
        first = self.exchange(flow, 'POST',
            f'/business/objects/{flow.oid}/evidence', body)
        after_first = self.export(flow)
        duplicate = self.exchange(flow, 'POST',
            f'/business/objects/{flow.oid}/evidence', body)
        after_duplicate = self.export(flow)
        changed = dict(body, title='Changed input with reused request ID')
        conflict = self.exchange(flow, 'POST',
            f'/business/objects/{flow.oid}/evidence', changed)
        return {'snapshots': [before, after_first, after_duplicate, self.export(flow)],
                'exchanges': [first, duplicate, conflict]}

    def build_manifest(self):
        stale, old_receipt = self.ro04_cases()
        signed, foreign, missing = self.auth_cases()
        return {'schema_version': '1.0', 'scope': checker.OBSERVATION_SCOPE,
            'source_commit': '1' * 40, 'account_a': checker.ACCOUNT_A,
            'region': checker.REGION, 'api_origin': 'https://api.example.test',
            'reviewer_subject_sha256': hashlib.sha256(ACTOR['sub'].encode()).hexdigest(),
            'cases': {
                'ro02_unreadable_evidence': self.unreadable_case(),
                'ro02_instruction_reconnect': self.instruction_case(),
                'ro04_stale_revision': stale,
                'ro04_old_receipt': old_receipt,
                'ro12_signed_out': signed,
                'ro12_foreign_subject': foreign,
                'ro12_missing_scope': missing,
                'ro12_replay_conflict': self.replay_case(),
            }}

    def test_exact_correlated_negative_evidence_is_only_ready_for_remaining_acceptance(self):
        result = checker.check(self.positive, self.manifest)
        self.assertEqual(result['status'],
                         'READY_FOR_REMAINING_BROWSER_AND_RELEASE_ACCEPTANCE')
        self.assertFalse(result['product_ready'])
        self.assertFalse(result['gates_promoted'])
        self.assertIn('LIVE_BROWSER_RO_02_04_12_OBSERVATION',
                      result['remaining_required'])

    def test_audit_tamper_missing_case_and_changed_rejection_state_fail_closed(self):
        changed = copy.deepcopy(self.manifest)
        changed['cases']['ro12_foreign_subject']['exchanges'][0]['audit'][
            'response_sha256'] = '0' * 64
        with self.assertRaisesRegex(ValueError, 'exact HTTP exchange'):
            checker.check(self.positive, changed)

        changed = copy.deepcopy(self.manifest)
        del changed['cases']['ro12_missing_scope']
        with self.assertRaisesRegex(ValueError, 'case set'):
            checker.check(self.positive, changed)

        changed = copy.deepcopy(self.manifest)
        changed['cases']['ro12_signed_out']['snapshots'][1] = copy.deepcopy(
            self.manifest['cases']['ro12_replay_conflict']['snapshots'][1])
        with self.assertRaisesRegex(ValueError, 'mix objects'):
            checker.check(self.positive, changed)

    def test_replay_duplication_instruction_binding_and_positive_gate_fail_closed(self):
        changed = copy.deepcopy(self.manifest)
        changed['cases']['ro12_replay_conflict']['snapshots'][2] = copy.deepcopy(
            changed['cases']['ro12_replay_conflict']['snapshots'][0])
        with self.assertRaisesRegex(ValueError, 'replay'):
            checker.check(self.positive, changed)

        changed = copy.deepcopy(self.manifest)
        changed['cases']['ro02_instruction_reconnect']['exchanges'][0]['request'][
            'body'] = changed['cases']['ro02_unreadable_evidence']['exchanges'][1][
                'request']['body']
        with self.assertRaises(ValueError):
            checker.check(self.positive, changed)

        positive = dict(self.positive, product_ready=True)
        with self.assertRaisesRegex(ValueError, 'start gate'):
            checker.check(positive, self.manifest)

    def test_cli_rejects_duplicate_json_and_never_promotes_product(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            positive = root / 'positive.json'
            observations = root / 'observations.json'
            output = root / 'result.json'
            positive.write_text(json.dumps(self.positive))
            observations.write_text('{"scope":"x","scope":"y"}')
            with redirect_stdout(io.StringIO()):
                code = checker.main(['--positive-result', str(positive),
                    '--observations', str(observations), '--output', str(output)])
            self.assertEqual(code, 1)
            result = json.loads(output.read_text())
            self.assertEqual(result['status'], 'NOT_READY')
            self.assertFalse(result['product_ready'])
            self.assertFalse(result['gates_promoted'])
            self.assertIn('Duplicate JSON member', result['error']['message'])

    def test_case_directory_collector_requires_exact_files(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            metadata = {key: value for key, value in self.manifest.items()
                        if key != 'cases'}
            (root / 'metadata.json').write_text(json.dumps(metadata))
            for name, value in self.manifest['cases'].items():
                case_root = root / name
                case_root.mkdir()
                for index, snapshot in enumerate(value['snapshots']):
                    (case_root / f'snapshot-{index}.json').write_text(
                        json.dumps(snapshot))
                for index, exchange in enumerate(value['exchanges']):
                    (case_root / f'exchange-{index}.json').write_text(
                        json.dumps(exchange))
            self.assertEqual(checker.collect(root), self.manifest)
            (root / 'ro12_signed_out' / 'unexpected.json').write_text('{}')
            with self.assertRaisesRegex(ValueError, 'directory entries differ'):
                checker.collect(root)


if __name__ == '__main__':
    unittest.main()
