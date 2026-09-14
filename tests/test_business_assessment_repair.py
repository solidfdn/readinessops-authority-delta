"""Captured failure replay through pinned Strands; no live model/AWS claims."""
import copy
import json
from pathlib import Path
import unittest
import test_business as business_tests

from authority_delta.business.contracts import (Proposal, ProposalContent,
    ProposalValidationError, validate_proposal)
from authority_delta.business.service import Problem
from authority_delta.canonical import sha256_json
from deploy_business import canary_input
from services.business_analysis.agent import assess
from support.business import ACTOR, proposal
from test_business import ScriptedBusinessModel


FIXTURE = Path(__file__).parent / 'fixtures/business_assessment_20260912_rejected.json'


def reconstructed_source(capture):
    # The user supplied outputs, not the original versioned input object. Keep
    # outputs unchanged and label the known-canary-text replay as reconstructed.
    source = canary_input('LOCAL_REPLAY_ONLY')
    original = capture['analysis']['attempts'][0]['proposal']
    source['evidence'][0]['evidence_id'] = original['findings'][0]['citations'][0]['evidence_id']
    source['decision_item_registry'] = [{k: item[k] for k in ('perspective', 'decision_item_id')}
                                        for item in original['decision_items']]
    source['input_hash'] = sha256_json({k: v for k, v in source.items() if k != 'input_hash'})
    return source


def draft(source):
    result = proposal(source)
    result.pop('input_hash')
    return result


class BusinessAssessmentRepair(unittest.TestCase):
    def setUp(self):
        self.capture = json.loads(FIXTURE.read_text())
        self.source = reconstructed_source(self.capture)

    def test_captured_three_outputs_remain_rejected_with_all_independent_reasons(self):
        originals = [x['proposal'] for x in self.capture['analysis']['attempts']]
        model = ScriptedBusinessModel(originals)
        result = assess(self.source, model=model)
        self.assertEqual(result['status'], 'NEEDS_INPUT')
        self.assertIsNone(result['proposal'])
        self.assertEqual(result['failure_classification'], 'MODEL_OUTPUT_CONTRACT')
        self.assertEqual([x['proposal'] for x in result['attempts']], originals)
        self.assertEqual(len(model.calls), 5)
        for attempt in result['attempts']:
            errors = attempt['validation_errors']
            self.assertEqual({(x['path'], x['code']) for x in errors}, {
                ('actions.1.finding_ids', 'MISSING_FINDING'),
                ('decision_items.2.citations.0', 'EXACT_QUOTE_REQUIRED'),
                ('decision_items.3.citations.0', 'EXACT_QUOTE_REQUIRED')})
            self.assertNotIn('input_hash', {x['path'] for x in errors})
        # Feedback from the real SDK tool result reaches the next model call,
        # containing all three errors rather than only the first schema defect.
        feedback = json.dumps(model.calls[3])
        for code in ('MISSING_FINDING', 'EXACT_QUOTE_REQUIRED'):
            self.assertIn(code, feedback)
        self.assertIn('decision_items.3.citations.0', feedback)

    def test_real_sdk_repair_requires_model_to_fix_references_and_quotes(self):
        bad = self.capture['analysis']['attempts'][0]['proposal']
        corrected = copy.deepcopy(bad)
        corrected['actions'] = corrected['actions'][:1]
        for index in (2, 3):
            corrected['decision_items'][index]['citations'] = []
        corrected['summary'] = 'The selected evidence documents missing owner approval and an unmeasured baseline; obtain the missing information before deciding.'
        model = ScriptedBusinessModel([bad, corrected])
        result = assess(self.source, model=model)
        self.assertEqual(result['status'], 'VALIDATED')
        self.assertEqual(len(result['attempts']), 2)
        self.assertEqual(result['attempts'][0]['proposal'], bad)
        self.assertEqual(result['attempts'][1]['proposal'], corrected)
        self.assertEqual(result['proposal']['input_hash'], self.source['input_hash'])
        self.assertEqual(result['proposal']['decision_items'][3]['recommendation'], 'NEEDS_INPUT')
        validate_proposal(result['proposal'], self.source, result['reads'])

    def test_model_schema_excludes_binding_but_accepted_wire_schema_still_requires_it(self):
        schema = ProposalContent.model_json_schema()
        self.assertNotIn('input_hash', schema['properties'])
        self.assertFalse(schema['additionalProperties'])
        external = Proposal.model_json_schema()
        self.assertIn('input_hash', external['required'])
        self.assertEqual(set(external['properties']), {
            'input_hash', 'summary', 'findings', 'actions', 'decision_items',
            'reassessment', 'missing_information'})
        for value in (draft(self.source), dict(proposal(self.source), input_hash='0' * 64)):
            with self.assertRaises(ValueError):
                validate_proposal(value, self.source)

    def test_model_cannot_supply_or_override_even_a_matching_hash(self):
        good = draft(self.source)
        for digest in ('0' * 64, self.source['input_hash']):
            with self.subTest(digest=digest):
                spoofed = dict(good, input_hash=digest)
                model = ScriptedBusinessModel([spoofed, good])
                result = assess(self.source, model=model)
                self.assertEqual(result['status'], 'VALIDATED')
                first = result['attempts'][0]
                self.assertEqual(first['proposal']['input_hash'], digest)
                self.assertEqual(first['validation_errors'][0]['path'], '<extra-field>')
                self.assertEqual(first['validation_errors'][0]['code'], 'extra_forbidden')
                self.assertEqual(result['proposal']['input_hash'], self.source['input_hash'])

    def test_model_generated_extra_key_is_redacted_from_diagnostics_and_feedback(self):
        sensitive = 'Unique private evidence sentence for diagnostic privacy verification.'
        good = draft(self.source)
        malformed = copy.deepcopy(good)
        malformed['decision_items'][0][sensitive] = True
        model = ScriptedBusinessModel([malformed, good])
        result = assess(self.source, model=model)
        self.assertEqual(result['status'], 'VALIDATED')
        rejected = result['attempts'][0]
        self.assertEqual(rejected['proposal'], malformed)
        self.assertIn(sensitive, rejected['proposal']['decision_items'][0])
        self.assertNotIn(sensitive, json.dumps(rejected['validation_errors']))
        self.assertNotIn(sensitive, rejected['error'])
        self.assertEqual(rejected['validation_errors'][0]['path'], 'decision_items.0.<extra-field>')
        # The assistant's earlier tool input legitimately remains in private
        # history; inspect only the SDK's returned validation-error feedback.
        feedback = [block['toolResult'] for message in model.calls[-1]
                    for block in message.get('content', []) if 'toolResult' in block
                    and block['toolResult'].get('status') == 'error']
        self.assertTrue(feedback)
        self.assertNotIn(sensitive, json.dumps(feedback))
        self.assertIn('decision_items.0.<extra-field>', json.dumps(feedback))

    def test_input_tampering_never_reaches_the_model(self):
        changed = copy.deepcopy(self.source)
        changed['evidence'][0]['text'] += 'Tampered after input binding.'
        model = ScriptedBusinessModel([draft(self.source)])
        with self.assertRaisesRegex(ValueError, 'digest mismatch'):
            assess(changed, model=model)
        self.assertEqual(model.calls, [])

    def test_repeated_read_tools_still_stop_at_eight_model_calls(self):
        class RepeatedReads(ScriptedBusinessModel):
            async def stream(self, messages, tool_specs=None, system_prompt=None, **kwargs):
                self.calls.append(copy.deepcopy(messages))
                index = len(self.calls)
                yield {'messageStart': {'role': 'assistant'}}
                yield {'contentBlockStart': {'contentBlockIndex': 0, 'start': {
                    'toolUse': {'toolUseId': f'read-{index}', 'name': 'read_context' if index % 2 else 'read_evidence'}}}}
                yield {'contentBlockDelta': {'contentBlockIndex': 0, 'delta': {'toolUse': {'input': '{}'}}}}
                yield {'contentBlockStop': {'contentBlockIndex': 0}}
                yield {'messageStop': {'stopReason': 'tool_use'}}
        model = RepeatedReads([])
        result = assess(self.source, model=model)
        self.assertEqual(len(model.calls), 8)
        self.assertEqual(result['attempts'], [])
        self.assertEqual(result['failure_classification'], 'ASSESSMENT_EXECUTION')
        self.assertIsNone(result['proposal'])

    def test_no_reads_or_injected_authority_never_returns_an_accepted_proposal(self):
        good = draft(self.source)
        for value, omit in ((good, True), (dict(good, approve=True), False),
                            (dict(good, policy_write=True), False), ({}, False)):
            with self.subTest(value=value, omit=omit):
                model = ScriptedBusinessModel([value], omit=omit)
                result = assess(self.source, model=model)
                self.assertEqual(result['status'], 'NEEDS_INPUT')
                self.assertIsNone(result['proposal'])
                self.assertEqual(len(result['attempts']), 3)
                self.assertLessEqual(len(model.calls), 8)
                self.assertTrue(all(x['validation_errors'] for x in result['attempts']))

    def test_quote_and_reference_validation_never_changes_the_submitted_content(self):
        original = self.capture['analysis']['attempts'][0]['proposal']
        value = dict(copy.deepcopy(original), input_hash=self.source['input_hash'])
        before = copy.deepcopy(value)
        with self.assertRaises(ProposalValidationError) as caught:
            validate_proposal(value, self.source, ['context', 'evidence'])
        self.assertEqual(value, before)
        self.assertEqual(len(caught.exception.issues), 3)

    def test_worker_persists_complete_rejections_and_never_creates_approval(self):
        flow = business_tests.Flow(methodName='test_nonpayment_cycle_and_new_input_preserves_official_history')
        flow.setUp()
        eid = flow.evidence()
        rid = flow.app.start_run(ACTOR, flow.oid, flow.command(evidence_ids=[eid]))['run_id']
        def invoke(source):
            bad = draft(source)
            bad['actions'][0]['finding_ids'] = ['F-99']
            bad['decision_items'][0]['citations'] = [dict(bad['decision_items'][0]['citations'][0], quote='Fabricated quoted text.')]
            result = assess(source, model=ScriptedBusinessModel([bad]))
            return dict(result, input_hash=source['input_hash'], result='HOLD')
        flow.work(rid, invoke)
        row = flow.db.get('jobs', rid, 'STATE').value
        self.assertEqual(row['status'], 'NEEDS_INPUT')
        self.assertEqual(row['error'], 'The assessment could not produce a valid proposal. Your selected evidence is saved.')
        saved = json.loads(flow.blobs.read(row['result_ref']))
        self.assertEqual(saved['failure_classification'], 'MODEL_OUTPUT_CONTRACT')
        self.assertEqual(len(saved['attempts']), 3)
        self.assertTrue(all(len(a['validation_errors']) == 2 for a in saved['attempts']))
        current = flow.app.detail(ACTOR, flow.oid)
        self.assertIsNone(current['object']['approval'])
        self.assertIsNone(current['object']['published_current'])
        self.assertIsNone(current['object']['applied_binding'])
        self.assertIsNone(saved['proposal'])
        with self.assertRaises(Problem):
            flow.app.save_draft(ACTOR, flow.oid, flow.command(run_id=rid, proposal={}, change_reason='Must not accept failed output'))


if __name__ == '__main__':
    unittest.main()
