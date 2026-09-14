"""Real Strands loop and tool execution; scripted model, no live Bedrock claim."""
import json
import copy
from pathlib import Path
import unittest
from strands.models.model import Model
import test_analysis as support
from services.analysis_agent.agent import analyze

class ScriptedModel(Model):
    def __init__(self, proposal, omit_reads=False):
        self.proposal=proposal;self.calls=[];self.omit_reads=omit_reads
    def update_config(self,**kwargs):pass
    def get_config(self):return {}
    async def structured_output(self,*args,**kwargs):
        raise AssertionError('Legacy output API must not be used')
        yield
    async def stream(self,messages,tool_specs=None,system_prompt=None,**kwargs):
        self.calls.append(json.loads(json.dumps(messages)))
        i=len(self.calls)-1
        names=['read_definitions','read_observations','read_requests']
        name=names[i] if i<3 and not self.omit_reads else 'Proposal'
        value={} if name in names else (self.proposal[min(max(i-3,0),len(self.proposal)-1)] if isinstance(self.proposal,list) else self.proposal)
        yield {'messageStart':{'role':'assistant'}}
        yield {'contentBlockStart':{'contentBlockIndex':0,'start':{'toolUse':{'toolUseId':f'test-{i}','name':name}}}}
        yield {'contentBlockDelta':{'contentBlockIndex':0,'delta':{'toolUse':{'input':json.dumps(value)}}}}
        yield {'contentBlockStop':{'contentBlockIndex':0}}
        yield {'messageStop':{'stopReason':'tool_use'}}

class StrandsTests(unittest.TestCase):
    def test_actual_sdk_loop_reads_and_validates(self):
        helper=support.AnalysisTests();helper.setUp();model=ScriptedModel(helper.proposal())
        result=analyze(helper.source,model=model)
        self.assertEqual(result['analysis_status'],'VALIDATED')
        self.assertEqual(result['reads'],['definitions','observations','requests'])
        self.assertEqual(len(model.calls),4)
        self.assertEqual(helper.attach(result['proposal'],reads=result['reads'])['analysis_status'],'VALIDATED')
        self.assertNotIn('expected',repr(model.calls))

    def test_sdk_output_cannot_skip_evidence(self):
        helper=support.AnalysisTests();helper.setUp();result=analyze(helper.source,model=ScriptedModel(helper.proposal(),True))
        self.assertEqual(helper.attach(result['proposal'],reads=result['reads'])['status'],'HOLD')
        self.assertEqual(result['analysis_status'],'HOLD')

    def test_actual_failed_proposal_gets_feedback_and_can_be_corrected(self):
        from test_gate_b_worker import proposal_for
        report=json.loads((Path(__file__).resolve().parents[1]/'evidence/aws/20260909-gate-b-failure-full.json').read_text())
        source=report['analysis_inputs']['semantic']
        bad=report['analysis_calls'][0]['response']['proposal']
        corrected=proposal_for(source)  # Scripted model output; never sent to live model.
        model=ScriptedModel([bad,corrected]);result=analyze(source,model=model)
        self.assertEqual(result['analysis_status'],'VALIDATED')
        self.assertEqual(len(result['attempts']),2)
        self.assertEqual(result['attempts'][0]['proposal'],bad)
        self.assertEqual(result['attempts'][0]['status'],'REJECTED')
        self.assertIn('recommendation',result['attempts'][0]['error'])
        self.assertIn('maintain_proposal',result['attempts'][0]['error'])
        self.assertIn('Validation failed for Proposal',repr(model.calls[-1]))
        self.assertEqual(len(model.calls),5)

    def test_actual_unchanged_case_is_rejected_even_after_schema_repairs(self):
        from test_gate_b_worker import proposal_for
        report=json.loads((Path(__file__).resolve().parents[1]/'evidence/aws/20260909-gate-b-failure-full.json').read_text())
        source=report['analysis_inputs']['semantic'];bad=copy.deepcopy(report['analysis_calls'][0]['response']['proposal'])
        bad.update(recommendation='HUMAN_REVIEW',maintain_proposal='Retain the approved boundary; this proposal grants no authority.')
        bad['changes'][1]['definition_fields']=['verified_changed_bank_methods']
        result=analyze(source,model=ScriptedModel([bad,proposal_for(source)]))
        self.assertEqual(result['analysis_status'],'VALIDATED')
        self.assertIn('Case P-003 is unchanged',result['attempts'][0]['error'])

    def test_uncorrected_live_failure_holds_with_bounded_attempts_and_full_diagnostics(self):
        report=json.loads((Path(__file__).resolve().parents[1]/'evidence/aws/20260909-gate-b-failure-full.json').read_text())
        source=report['analysis_inputs']['semantic'];bad=report['analysis_calls'][0]['response']['proposal']
        model=ScriptedModel(bad);result=analyze(source,model=model)
        self.assertEqual(result['analysis_status'],'HOLD');self.assertEqual(len(result['attempts']),3)
        self.assertLessEqual(len(model.calls),8);self.assertEqual(result['proposal'],bad)

    def test_v2_failed_proposal_receives_specific_case_and_fact_feedback(self):
        from test_gate_b_worker import proposal_for
        root=Path(__file__).resolve().parents[1]
        source=json.loads((root/'evidence/aws/20260909-gate-b-failure-full.json').read_text())['analysis_inputs']['semantic']
        v2=json.loads((root/'evidence/aws/20260909-gate-b-v2-failure-summary.json').read_text())
        bad=v2['analysis_diagnostics']['semantic']['rejected_proposal']
        self.assertEqual(bad['input_hash'],source['input_hash'])
        model=ScriptedModel([bad,proposal_for(source)])
        result=analyze(source,model=model)
        self.assertEqual(result['analysis_status'],'VALIDATED')
        error=result['attempts'][0]['error']
        self.assertIn('Case P-003 is unchanged',error)
        self.assertIn('candidate=HUMAN_REVIEW',error)
        self.assertIn('80000',error)
        self.assertIn('Case P-003 is unchanged',repr(model.calls[-1]))

if __name__=='__main__':unittest.main()
