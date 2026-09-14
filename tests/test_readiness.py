"""Shared-contract tests use an independent data-sharing business, no live proof."""
import copy,json,unittest
from pathlib import Path
from jsonschema import Draft202012Validator,ValidationError
from authority_delta.adapter_contract import BoundaryAdapter,verify_boundary
from authority_delta.canonical import sha256_json
from authority_delta.readiness import build_workspace
from authority_delta.cedar import compile_exact_scope_permit,CedarContractError

ROOT=Path(__file__).resolve().parents[1]
SHARING_SCHEMA={'type':'object','additionalProperties':False,'required':['audiences','classifications'],
    'properties':{key:{'type':'array','items':{'type':'string','enum':values},'uniqueItems':True,'minItems':1}
        for key,values in [('audiences',['internal','partner']),('classifications',['public','internal'])]}}
def validate_sharing(value):
    Draft202012Validator(SHARING_SCHEMA).validate(value)
    return value
SHARING=BoundaryAdapter('data_sharing','1.0.0',SHARING_SCHEMA,validate_sharing)

def sharing_fixture():
    """Local independent contract fixture, never installed as an AWS adapter."""
    maintain=SHARING.binding({'audiences':['internal','partner'],'classifications':['public']})
    narrow=SHARING.binding({'audiences':['internal'],'classifications':['public']})
    profile={'adapter_id':'data_sharing','adapter_version':'1.0.0','object_id':'customer-data-sharing',
        'object_name':'Customer data sharing','purpose':'Review which audiences may receive customer data.',
        'sample':True,'sample_label':'Local contract test only',
        'columns':[{'id':'audience','label':'Audience'}],
        'rows':{'S-1':{'audience':'partner'},'S-2':{'audience':'internal'}},
        'boundaries':{'MAINTAIN':maintain,'NARROW':narrow,'REJECT':None},
        'decisions':[{'id':x} for x in ['MAINTAIN','NARROW','REJECT']]}
    change={'case_id':'S-1','before_judgment':'HUMAN_REVIEW','after_judgment':'ALLOW',
        'reason':'The candidate treats an external partner as an internal audience.',
        'evidence_refs':['definitions/R2/internal_audiences','observations/S-1']}
    review={'source':{'bucket':'local-fixture-only','key':'reports/sharing','version_id':'fixed-fixture-version'},
        'approval_recorded':False,'publication_status':'NOT_RUN','connection_id':'local-test-connection',
        'observed_at':'2026-09-09T00:00:00Z',
        'previews':{key:{'allowed_request_ids':ids} for key,ids in [('MAINTAIN',['S-2']),('NARROW',['S-2']),('REJECT',[])]},
        'comparisons':{'semantic':{'before_release':'R1','candidate_release':'R2','runtime_request_id':'local-runtime-observation',
            'definitions':{'R1':{'internal_audiences':['employees']},'R2':{'internal_audiences':['employees','partners']}},
            'cases':[{'case_id':'S-1','before':'HUMAN_REVIEW','candidate':'ALLOW'},{'case_id':'S-2','before':'ALLOW','candidate':'ALLOW'}],
            'patch':{'analysis_status':'VALIDATED','status':'REVIEW_REQUIRED',
                'analysis':{'changes':[change],'maintain_proposal':'Keep external partner sharing subject to human review.'}}}}}
    review['document_hash']=sha256_json(review)
    return review,profile

class SharedReadinessTests(unittest.TestCase):
    def test_nonpayment_object_evidence_finding_action_and_history_remain_linked(self):
        d,p=sharing_fixture();w=build_workspace(d,p,{'data_sharing':SHARING})
        Draft202012Validator(json.loads((ROOT/'packages/contracts/readinessops.schema.json').read_text())).validate(w)
        self.assertEqual(w['objects'][0]['object_id'],'customer-data-sharing')
        self.assertEqual(w['findings'][0]['case_id'],'S-1')
        self.assertEqual(w['actions'][0]['finding_id'],w['findings'][0]['finding_id'])
        evidence={e['evidence_id']:e for e in w['evidence']}
        for item in w['findings']+w['actions']+w['history']:
            self.assertTrue(set(item['evidence_ids'])<=set(evidence))
            self.assertEqual({evidence[x]['kind'] for x in item['evidence_ids']},{'RELEASE_DEFINITION','OBSERVATION'})
        self.assertEqual(w['decisions'],[]);self.assertEqual(w['publications'],[])
        self.assertNotIn('payment',json.dumps(w).lower());self.assertNotIn('currency',json.dumps(w).lower())
        digest=w.pop('workspace_hash');self.assertEqual(digest,sha256_json(w))

    def test_unknown_adapter_invalid_type_version_schema_and_tamper_are_rejected(self):
        value=SHARING.binding({'audiences':['internal'],'classifications':['public']})
        for mutate in [lambda v:v.update(adapter_id='unregistered'),lambda v:v.update(adapter_version='2.0.0'),
                       lambda v:v.update(adapter_schema_hash='0'*64),lambda v:v['parameters'].update(audiences=['anywhere']),
                       lambda v:v['parameters'].update(amount=500),lambda v:v.update(boundary_hash='0'*64)]:
            bad=copy.deepcopy(value);mutate(bad)
            with self.subTest(value=bad),self.assertRaises((ValueError,ValidationError)):
                verify_boundary(bad,{'data_sharing':SHARING})
        with self.assertRaises(ValueError):
            BoundaryAdapter('rewrite','1.0.0',{},lambda value:{'changed':True}).binding({'original':True})

    def test_changed_evidence_missing_rows_unobserved_cases_and_authority_expansion_fail(self):
        for kind in ['tampered','missing-row','unobserved-case','expand','approved']:
            d,p=sharing_fixture()
            if kind=='tampered':d['comparisons']['semantic']['definitions']['R1']['internal_audiences'].append('public')
            elif kind=='missing-row':p['rows'].pop('S-1')
            else:
                if kind=='unobserved-case':d['comparisons']['semantic']['patch']['analysis']['changes'][0]['case_id']='S-999'
                elif kind=='expand':d['previews']['NARROW']['allowed_request_ids'].append('S-1')
                else:d['approval_recorded']=True
                d.pop('document_hash');d['document_hash']=sha256_json(d)
            with self.subTest(kind=kind),self.assertRaises(ValueError):build_workspace(d,p,{'data_sharing':SHARING})

    def test_shared_cedar_renders_nonpayment_scope_and_rejects_identifier_injection(self):
        args={'gateway_arn':'arn:aws:bedrock-agentcore:ap-northeast-1:538522204923:gateway/authority-delta-gateway-rvplvkk1t7',
            'role_arn':'arn:aws:iam::538522204923:role/SharingRuntime',
            'allowed_request_ids':['req-'+'a'*64],'request_registry_snapshot_hash':'b'*64,
            'target_name':'SharingTools','tool_name':'share_dataset','input_name':'sharing_request_id','compiler_id':'local-sharing-test-v1'}
        out=compile_exact_scope_permit(**args)
        self.assertIn('SharingTools___share_dataset',out['statement'])
        self.assertIn('context.input.sharing_request_id',out['statement'])
        self.assertNotIn('payment',json.dumps(out))
        for key in ['tool_name','input_name','target_name']:
            with self.subTest(key=key),self.assertRaises(CedarContractError):
                compile_exact_scope_permit(**{**args,key:'x); permit(principal,action,resource);'})

if __name__=='__main__':unittest.main()
