"""Staged reassessment preserves the complete acceptance contract and fails closed."""
import copy
import json
import unittest
import test_business_prior as prior
from services.business_analysis.agent import assess
from support.business import proposal
from support.staged_model import StagedModel, responses


class StagedAssessment(unittest.TestCase):
    def setUp(self):
        flow = prior.PriorPublicationInput()
        flow.setUp()
        _, eid = flow.prepare()
        self.source = flow.start(eid)

    def test_complete_four_judgments_and_exact_evidence_with_pinned_prior(self):
        original = copy.deepcopy(self.source)
        model = StagedModel(responses(self.source))
        result = assess(self.source, model=model)
        self.assertEqual(result['status'], 'VALIDATED', result)
        self.assertEqual(result['proposal'], proposal(self.source))
        self.assertEqual(self.source, original)
        self.assertEqual(len(model.calls), 6)
        self.assertEqual(len(result['stages']), 5)
        self.assertEqual(result['reads'], ['context', 'evidence'])
        self.assertIn(self.source['prior_publication']['publication']['digest'], json.dumps(model.calls))

    def test_missing_evidence_read_never_accepts(self):
        result = assess(self.source, model=StagedModel(responses(self.source)[1:]))
        self.assertEqual(result['status'], 'NEEDS_INPUT')
        self.assertIsNone(result['proposal'])

    def test_missing_field_repairs_only_that_section(self):
        steps = responses(self.source)
        bad = copy.deepcopy(steps[2])
        bad[1].pop('impact_citation_ids')
        steps.insert(2, bad)
        model = StagedModel(steps)
        result = assess(self.source, model=model)
        self.assertEqual(result['status'], 'VALIDATED', result)
        self.assertEqual(len(model.calls), 7)
        rejected = [x for x in result['section_attempts'] if x['status'] == 'REJECTED']
        self.assertEqual(len(rejected), 1)
        self.assertIn('impact_citation_ids', rejected[0]['error'])
        payload = json.loads(model.calls[3][0]['content'][0]['text'])
        self.assertNotIn('snapshot', payload)
        self.assertEqual(payload['evidence'], self.source['evidence'])
        self.assertIn('prior_item', payload)
        self.assertIn('unknowns', payload['required_output_fields'])
        self.assertEqual(len(result['stages']), 5)

    def test_invalid_citations_unknown_or_authority_fields_never_accept(self):
        for patch in ({'impact_citation_ids': []}, {'citation_ids': ['q-forged']},
                      {'impact_status': 'UNKNOWN', 'unknowns': []}, {'approve': True}):
            with self.subTest(patch=patch):
                steps = responses(self.source)[:2]
                steps[1][1].update(patch)
                model = StagedModel(steps)
                result = assess(self.source, model=model)
                self.assertEqual(result['status'], 'NEEDS_INPUT')
                self.assertIsNone(result['proposal'])
                self.assertLessEqual(len(model.calls), 8)

    def test_unchanged_boundary_and_action_references_are_checked(self):
        steps = responses(self.source)
        steps[2][1]['conditions'] = 'A different decision boundary.'
        model = StagedModel(steps[:3])
        result = assess(self.source, model=model)
        self.assertEqual(result['status'], 'NEEDS_INPUT')
        self.assertIsNone(result['proposal'])
        steps = responses(self.source)
        steps[-1][1]['actions'][0]['finding_ids'] = ['F-99']
        result = assess(self.source, model=StagedModel(steps))
        self.assertEqual(result['status'], 'NEEDS_INPUT')
        self.assertIsNone(result['proposal'])

    def test_incomplete_later_stage_keeps_completed_stages_but_no_proposal(self):
        steps = responses(self.source)[:4]
        steps[-1][1].pop('question')
        model = StagedModel(steps)
        result = assess(self.source, model=model)
        self.assertEqual(result['status'], 'NEEDS_INPUT')
        self.assertEqual(len(result['stages']), 2)
        self.assertIsNone(result['proposal'])
        self.assertLessEqual(len(model.calls), 8)
