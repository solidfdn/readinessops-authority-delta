"""Actual repeated output, real SDK, scripted model; no live inference claim."""
import copy
import json
from pathlib import Path
import unittest
from pydantic import ValidationError
from authority_delta.business.contracts import validate_proposal
from services.business_analysis.agent import assess
from test_business import ScriptedBusinessModel
from test_business_assessment_repair import reconstructed_source

CAPTURE = Path(__file__).parent / 'fixtures/business_assessment_20260912_length.json'

class RecordingModel(ScriptedBusinessModel):
    def __init__(self, proposals):
        super().__init__(proposals)
        self.schemas = []
    async def stream(self, messages, tool_specs=None, system_prompt=None, **kwargs):
        self.schemas.append(copy.deepcopy(tool_specs))
        async for event in super().stream(messages, tool_specs=tool_specs, system_prompt=system_prompt, **kwargs):
            yield event

class BusinessFieldRevision(unittest.TestCase):
    def setUp(self):
        self.capture = json.loads(CAPTURE.read_text())
        self.source = reconstructed_source(self.capture)
        self.original = copy.deepcopy(self.capture['analysis']['attempts'][0]['proposal'])
        items = copy.deepcopy(self.original['decision_items'])
        items[3]['citations'] = [dict(items[3]['citations'][0],
            quote='No owner approval or processor contract has been supplied.')]
        self.patch = {'summary':'The proposal lacks owner approval, a processor contract and baseline measurements. Obtain the missing evidence before deciding on external sharing.', 'decision_items':items}

    def test_captured_failure_and_hidden_quote_are_both_diagnosed_before_revision(self):
        originals = [x['proposal'] for x in self.capture['analysis']['attempts']]
        self.assertTrue(all(x == originals[0] for x in originals))
        self.assertEqual(len(self.original['summary']),4092)
        with self.assertRaises(ValidationError):
            validate_proposal(dict(self.original,input_hash=self.source['input_hash']),self.source,['context','evidence'])
        model = RecordingModel([self.original,self.patch])
        result = assess(self.source,model=model)
        self.assertEqual(result['status'],'VALIDATED')
        self.assertEqual(len(result['attempts']),2)
        self.assertEqual(result['attempts'][0]['proposal'],self.original)
        self.assertEqual({(e['path'],e['code']) for e in result['attempts'][0]['validation_errors']},
            {('summary','string_too_long'),('decision_items.3.citations.0','EXACT_QUOTE_REQUIRED')})
        self.assertEqual(len(model.calls),4)
        self.assertNotIn(self.original['summary'], json.dumps(model.calls[-1],ensure_ascii=False))
        request=json.loads(model.calls[-1][0]['content'][0]['text'])
        self.assertNotIn('summary', request['previous_proposal'])
        self.assertEqual(request['input_context']['context'], self.source['context'])
        schema = next(x for x in model.schemas[-1] if x['name']=='BoundProposal')['inputSchema']['json']
        self.assertEqual(set(schema['properties']),{'summary','decision_items'})
        for field in ('actions','findings','missing_information'):
            self.assertEqual(result['proposal'][field],self.original[field])
        self.assertEqual(result['attempts'][1]['revision'],self.patch)
        validate_proposal(result['proposal'],self.source,result['reads'])

    def test_summary_only_correction_does_not_bypass_required_quote_repair(self):
        model=RecordingModel([self.original,{'summary':self.patch['summary']}])
        result=assess(self.source,model=model)
        self.assertIsNone(result['proposal'])
        self.assertEqual(result['status'],'NEEDS_INPUT')
        self.assertLessEqual(len(result['attempts']),3)

    def test_overlong_revision_and_then_valid_revision_share_three_attempt_budget(self):
        bad=dict(self.patch,summary=self.original['summary'])
        result=assess(self.source,model=RecordingModel([self.original,bad,{'summary':self.patch['summary']}]))
        self.assertEqual(result['status'],'VALIDATED')
        self.assertEqual(len(result['attempts']),3)
        self.assertEqual(result['proposal']['decision_items'],self.patch['decision_items'])

    def test_repeated_overlong_revisions_never_become_valid(self):
        result=assess(self.source,model=RecordingModel([self.original,dict(self.patch,summary=self.original['summary']),{'summary':self.original['summary']}]))
        self.assertEqual(result['status'],'NEEDS_INPUT')
        self.assertIsNone(result['proposal'])
        self.assertEqual(len(result['attempts']),3)
        self.assertEqual(result['attempts'][0]['proposal'],self.original)

    def test_revision_cannot_change_frozen_fields_or_add_authority_or_hash(self):
        for key,value in [('actions',[]),('approve',True),('input_hash',self.source['input_hash'])]:
            with self.subTest(key=key):
                bad=dict(self.patch,**{key:value})
                result=assess(self.source,model=RecordingModel([self.original,bad]))
                self.assertEqual(result['status'],'NEEDS_INPUT')
                self.assertIsNone(result['proposal'])
                self.assertIn('extra_forbidden',str(result['attempts'][-1]['validation_errors']))

    def test_revision_with_forged_item_id_still_fails_entire_contract(self):
        bad=copy.deepcopy(self.patch)
        bad['decision_items'][0]['decision_item_id']='di-'+'f'*32
        result=assess(self.source,model=RecordingModel([self.original,bad,{'decision_items':bad['decision_items']}]))
        self.assertEqual(result['status'],'NEEDS_INPUT')
        self.assertIsNone(result['proposal'])
        self.assertIn('ITEM_BINDING',str(result['attempts'][-1]['validation_errors']))

if __name__=='__main__':unittest.main()
