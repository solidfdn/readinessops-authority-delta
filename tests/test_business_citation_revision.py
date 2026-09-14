"""Reconstructed input and captured model outputs; never a live model claim."""
import copy,json
from pathlib import Path
import unittest
from deploy_business import canary_input
from authority_delta.canonical import sha256_json
from authority_delta.business.contracts import validate_proposal,ProposalValidationError
from services.business_analysis.agent import assess
from test_business_field_revision import RecordingModel

class CitationRevision(unittest.TestCase):
    def test_captured_failure_repaired_without_dropping_risk_citation(self):
        root=Path(__file__).parent/'fixtures'
        capture=json.loads((root/'business_assessment_20260912_support.json').read_text())
        original=capture['analysis']['attempts'][0]['proposal']
        source=canary_input('LOCAL_RECONSTRUCTION')
        source['context']=capture['context']
        source['evidence'][0].update(evidence_id=capture['selected_evidence_ids'][0],text=(root/'support_reply_pilot.txt').read_text())
        source['evidence'][0]['text_hash']=sha256_json(source['evidence'][0]['text'])
        source['decision_item_registry']=[{k:v[k] for k in ('perspective','decision_item_id')} for v in original['decision_items']]
        source['input_hash']=sha256_json({k:v for k,v in source.items() if k!='input_hash'})
        for attempt in capture['analysis']['attempts']:
            with self.assertRaises(ProposalValidationError):
                validate_proposal(dict(attempt['proposal'],input_hash=source['input_hash']),source,['context','evidence'])
        patch={'findings':copy.deepcopy(original['findings'])}
        patch['findings'][3]['citations'][0]['quote']='Pause the pilot if any message is sent without human review, sensitive data appears, or a draft asks for a password or authentication code.'
        result=assess(source,model=RecordingModel([original,patch]))
        self.assertEqual(result['status'],'VALIDATED')
        self.assertEqual(len(result['attempts']),2)
        for field in ('summary','actions','decision_items','missing_information'):
            self.assertEqual(result['proposal'][field],original[field])
        self.assertEqual(result['attempts'][1]['revision'],patch)
        bad={'findings':copy.deepcopy(original['findings'])}
        bad['findings'][3]['citations']=[]
        result=assess(source,model=RecordingModel([original,bad,{'findings':original['findings']}]))
        self.assertEqual(result['status'],'NEEDS_INPUT')
        self.assertEqual(len(result['attempts']),3)
        self.assertEqual(result['attempts'][1]['validation_errors'][0]['code'],'CITATION_REQUIRED')
