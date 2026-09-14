"""Bounded source-quote repair with synthetic local input; no live model claim."""
import copy
import json
import unittest
from test_business_prior import PriorPublicationInput
from test_business_field_revision import RecordingModel
from support.business import proposal
from services.business_analysis.agent import assess


class CatalogRevision(unittest.TestCase):
    def test_reassessment_rebuilds_with_source_quotes_and_keeps_rejected_record(self):
        flow = PriorPublicationInput()
        flow.setUp()
        _, eid = flow.prepare()
        source = flow.start(eid)
        good = proposal(source)
        good.pop('input_hash')
        bad = copy.deepcopy(good)
        bad['reassessment'] = None
        bad['decision_items'][0]['citations'][0]['quote'] = 'Invented quotation outside the source.'
        model = RecordingModel([bad, good])
        result = assess(source, model=model)
        self.assertEqual(result['status'], 'VALIDATED')
        self.assertEqual(result['attempts'][0]['proposal'], bad)
        payload = json.loads(model.calls[-1][0]['content'][0]['text'])
        self.assertEqual(payload['previous_proposal'], {})
        self.assertEqual(set(payload['replace_only_fields']), set(good))
        schema = next(x for x in model.schemas[-1] if x['name'] == 'BoundProposal')['inputSchema']['json']
        self.assertIn('enum', json.dumps(schema))
        rejected = assess(source, model=RecordingModel([bad, bad, bad]))
        self.assertEqual(rejected['status'], 'NEEDS_INPUT')
        self.assertIsNone(rejected['proposal'])
        self.assertLessEqual(len(rejected['attempts']), 3)

    def test_missing_fields_and_long_titles_enter_bounded_repair(self):
        flow = PriorPublicationInput()
        flow.setUp()
        _, eid = flow.prepare()
        source = flow.start(eid)
        good = proposal(source)
        good.pop('input_hash')
        missing = copy.deepcopy(good)
        missing.pop('missing_information')
        missing['decision_items'] = missing['decision_items'][:1]
        long_title = copy.deepcopy(good)
        long_title['findings'][0]['title'] = 'x' * 161
        model = RecordingModel([missing, long_title, good])
        result = assess(source, model=model)
        self.assertEqual(result['status'], 'VALIDATED')
        self.assertEqual(len(result['attempts']), 3)
        self.assertIn('revision', result['attempts'][1])
        self.assertEqual(result['attempts'][1]['validation_errors'][0]['code'], 'string_too_long')
        schema = next(x for x in model.schemas[0] if x['name'] == 'BoundProposal')['inputSchema']['json']
        self.assertIn('reassessment', schema['required'])

    def test_catalog_ids_resolve_exact_text_and_reject_wrong_evidence(self):
        flow = PriorPublicationInput()
        flow.setUp()
        _, eid = flow.prepare()
        source = flow.start(eid)
        good = proposal(source)
        good.pop('input_hash')
        def encode(value):
            if isinstance(value, list): return [encode(x) for x in value]
            if isinstance(value, dict):
                if set(value) == {'evidence_id', 'quote'}:
                    return {'evidence_id': value['evidence_id'], 'quote_id': 'q0'}
                return {k: encode(v) for k, v in value.items()}
            return value
        wire = encode(good)
        result = assess(source, model=RecordingModel([wire]))
        self.assertEqual(result['status'], 'VALIDATED')
        self.assertEqual(result['proposal']['decision_items'], good['decision_items'])
        self.assertNotIn('quote_id', json.dumps(result['proposal']))
        bad = copy.deepcopy(wire)
        bad['decision_items'][0]['citations'][0]['evidence_id'] = 'e-wrong-source'
        rejected = assess(source, model=RecordingModel([bad, bad, bad]))
        self.assertEqual(rejected['status'], 'NEEDS_INPUT')
        self.assertIsNone(rejected['proposal'])
