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
