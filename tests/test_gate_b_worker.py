"""Stateful orchestration test with real Strands, synthetic model/AWS responses."""
import copy,io,json,hashlib,unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch
import test_gate_a_worker as support
from test_strands_sdk import ScriptedModel
from services.analysis_agent.agent import analyze
from scripts import gate_b
from scripts.build_runtime_artifact import release_document
from test_analysis_model import profile,MODEL_ID


def proposal_for(source):
    before={o['case_id']:o for o in source['replays']['before']['observations']};after={o['case_id']:o for o in source['replays']['candidate']['observations']}
    old=source['definitions'][source['before_release_id']];new=source['definitions'][source['candidate_release_id']]
    fields=[k for k in old if k not in ('release_id','description_change_only') and old[k]!=new[k]]
    changes=[];counter=[]
    for cid,a in before.items():
        b=after[cid];refs=sorted(set(a['evidence_refs']+b['evidence_refs']))
        if a['judgment']!=b['judgment']:changes.append({'case_id':cid,'before_judgment':a['judgment'],'after_judgment':b['judgment'],'reason':'Local scripted model explanation.','evidence_refs':refs,'definition_fields':fields})
        else:counter.append({'case_id':cid,'reason':'Observed judgment unchanged.','evidence_refs':refs})
    return {'input_hash':source['input_hash'],'summary':'Local scripted model comparison of observed evidence.','changes':changes,'counterexamples':counter[:1],'maintain_proposal':'Retain the approved boundary; this proposal grants no authority.', 'recommendation':'HUMAN_REVIEW' if changes else 'NO_DECISION_CHANGE'}

class GateBTests(unittest.TestCase):
    def setUp(self):
        self.helper=support.GateAWorkerTests();self.helper.setUp();self.addCleanup(self.helper.doCleanups)
        code,prior=self.helper.run_worker();self.assertEqual(code,0)
        self.aws=self.helper.aws;self.root=self.helper.root
        self.aws.seed_object(gate_b.PRIOR['key'],prior,gate_b.PRIOR['version_id'])
        self.aws.environment['AD_REPORT_KEY']='evidence/test/gate-b-result.json'
        self.aws.calls.clear();original=self.aws.dispatch
        original_client=self.aws.client
        self.aws.client=lambda name,**kw:support.AwsClient(self.aws,name) if name=="bedrock" else original_client(name,**kw)
        self.fail_model=False
        self.deployments=[]
        self.mutate_proposal=lambda proposal:None
        def dispatch(service,method,args):
            if service=='bedrock' and method=='get_inference_profile':return profile()
            if service=='bedrock-agentcore-control' and method=='get_agent_runtime' and 'Analysis' in args['agentRuntimeId']:
                value=original(service,method,args);value['environmentVariables']['AD_ANALYSIS_MODEL_ID']=MODEL_ID;return value
            if service=='bedrock-agentcore' and method=='invoke_agent_runtime' and 'Analysis' in args['agentRuntimeArn']:
                if self.fail_model:raise TimeoutError('Injected analysis timeout')
                source=json.loads(args['payload']);proposal=proposal_for(source)
                result=analyze(source,model=ScriptedModel(proposal))
                self.mutate_proposal(result["proposal"])
                binding=self.aws.runtimes['Analysis'];role=binding['ExecutionRoleArn'].split('/')[-1]
                result.update(result='OBSERVED' if result.get('analysis_status')=='VALIDATED' else 'HOLD',input_hash=source['input_hash'],model_id=MODEL_ID,model_calls=[{'request_id':'test-model-request','http_status':200}],identity={'account':support.BINDING['account'],'arn':f"arn:aws:sts::{support.BINDING['account']}:assumed-role/{role}/session",'request_id':'test-identity'})
                return {'response':io.BytesIO(json.dumps(result).encode()),'statusCode':200,'ResponseMetadata':support.META}
            return original(service,method,args)
        self.aws.dispatch=dispatch

    def runner(self,*args,**kwargs):
        owner=self
        class Job(gate_b.GateB):
            def deploy(self,template_name,stack_name,prefix,artifact,extra=None):
                owner.deployments.append(template_name)
                if prefix=='Analysis':
                    owner.assertEqual(extra['AnalysisModelId'],MODEL_ID)
                    owner.assertIn('foundation-model/amazon.nova-pro-v1:0',extra['AnalysisFoundationModelArns'])
                release='V1-BENIGN' if prefix=='Benign' else 'Analysis'
                rid='AuthorityDelta'+prefix+'-abcdefghij';arn=f'arn:aws:bedrock-agentcore:{gate_b.REGION}:{gate_b.ACCOUNT}:runtime/{rid}'
                value={'RuntimeId':rid,'RuntimeArn':arn,'RuntimeVersion':'1','EndpointName':'fixed_'+prefix.lower(),'EndpointArn':arn+'/runtime-endpoint/fixed_'+prefix.lower(),'ExecutionRoleArn':f'arn:aws:iam::{gate_b.ACCOUNT}:role/authority-delta-'+prefix.lower()}
                owner.aws.runtimes[release]=value;owner.aws.artifacts[release]=artifact
                if release=='V1-BENIGN':(owner.root/('release-'+release+'.json')).write_text(json.dumps(release_document(self.fixtures,release)))
                return value
        return Job(*args,**kwargs,sleep=lambda t:None)

    def run_job(self):
        def build(destination,**kwargs):
            destination.parent.mkdir(exist_ok=True);destination.write_bytes(b'local-artifact-double')
            return {'path':str(destination),'sha256':hashlib.sha256(destination.read_bytes()).hexdigest(),'size_bytes':destination.stat().st_size}
        output=io.StringIO()
        with patch('scripts.gate_a.build_runtime_artifact',self.aws.build_artifact),patch.object(gate_b,'build',build),redirect_stdout(output):
            code=gate_b.run_worker(self.aws,self.aws.environment,root=self.root,runner=self.runner)
        self.output=output.getvalue()
        return code,json.loads((self.root/'evidence/aws/gate-b-result.json').read_text())

    def test_semantic_and_benign_proof_and_no_policy_writes(self):
        code,result=self.run_job();self.assertEqual(code,0,result.get('error'))
        self.assertEqual(result['semantic_runtime_proof'],'PASS');self.assertEqual(result['gate_b'],'NOT_PASSED_UI_PENDING')
        self.assertEqual(result['patches']['semantic']['affected_case_ids'],['P-002']);self.assertEqual(result['patches']['benign']['affected_case_ids'],[])
        self.assertTrue(result['state_unchanged'])
        self.assertFalse([x for x in self.aws.calls if x[1] in ('create_policy','delete_policy','put_item','update_item')])
        self.assertIn('versionId=',repr(result['benign_replay']))

    def test_model_timeout_retains_checkpoint_and_no_gate_promotion(self):
        self.fail_model=True;code,result=self.run_job();self.assertEqual(code,1)
        self.assertEqual(result['result'],'FAIL');self.assertTrue(result['state_unchanged']);self.assertIn('checkpoints',result)
        self.assertEqual(result['error']['type'],'TimeoutError')
        self.assertEqual(result['sem_01'],'FAIL');self.assertEqual(result['sem_02'],'NOT_RUN')

    def test_rejection_reason_survives_worker_checkpoint_and_launcher(self):
        from scripts.launch_gate_b import compact_report
        self.mutate_proposal=lambda p:p.update(recommendation='REVIEW_REQUIRED')
        code,result=self.run_job();self.assertEqual(code,1)
        reason='Recommendation disagrees with observed changes'
        self.assertEqual(result['patches']['semantic']['analysis_error'],reason)
        self.assertEqual(result['sem_01'],'FAIL');self.assertEqual(result['sem_02'],'NOT_RUN')
        self.assertEqual(result['semantic_runtime_proof'],'FAIL');self.assertTrue(result['state_unchanged'])
        self.assertIn(reason,self.output)
        checkpoint=json.loads((self.root/'evidence/aws/gate-b-semantic-analysis.json').read_text())
        self.assertEqual(checkpoint['sem_01'],'FAIL')
        compact=compact_report(result,build_status='FAILED')
        self.assertEqual(compact['analysis_diagnostics']['semantic']['analysis_error'],reason)
        self.assertEqual(compact['analysis_diagnostics']['semantic']['proposal_recommendation'],'REVIEW_REQUIRED')
        self.assertFalse([x for x in self.aws.calls if x[1] in ('create_policy','delete_policy','put_item','update_item')])

    def test_semantic_pass_remains_visible_if_benign_explanation_fails(self):
        self.mutate_proposal=lambda p:p.update(counterexamples=[]) if not p['changes'] else None
        code,result=self.run_job();self.assertEqual(code,1)
        self.assertEqual(result['sem_01'],'PASS');self.assertEqual(result['sem_02'],'FAIL')
        self.assertEqual(result['semantic_runtime_proof'],'FAIL')
        self.assertEqual(result['patches']['benign']['analysis_error'],'Missing unchanged counterexample')
        self.assertIn('Missing unchanged counterexample',self.output)

    def prepare_reuse(self):
        code,previous=self.run_job();self.assertEqual(code,0,previous.get('error'))
        previous['build_id']=gate_b.REUSE['build_id']
        previous['result']='FAIL'  # Reuse observations, never promote previous acceptance.
        self.aws.seed_object(gate_b.REUSE['key'],previous,gate_b.REUSE['version_id'])
        self.aws.environment['AD_REUSE_GATE_B']=gate_b.REUSE['build_id']
        self.aws.environment['AD_REPORT_KEY']='evidence/recovery/gate-b-result.json'
        self.aws.calls.clear();self.deployments.clear()
        return previous

    def test_reuses_pinned_benign_observations_without_vendor_calls_or_redeploy(self):
        previous=self.prepare_reuse()
        with patch.dict(gate_b.REUSE,sha256=gate_b.sha256_json(previous)):
            code,result=self.run_job()
        self.assertEqual(code,0,result.get('error'));self.assertEqual(self.deployments,['analysis-runtime'])
        self.assertEqual(result['reused_observations']['count'],6)
        self.assertEqual(result['benign_replay'],previous['benign_replay'])
        self.assertNotIn('runtime_calls',result)
        invocations=[x for x in self.aws.calls if x[1]=='invoke_agent_runtime']
        self.assertEqual(len(invocations),2)
        self.assertTrue(all('Analysis' in x[2]['agentRuntimeArn'] for x in invocations))

    def test_reuse_digest_mismatch_stops_before_deploy_or_inference(self):
        self.prepare_reuse()
        with patch.dict(gate_b.REUSE,sha256='0'*64):code,result=self.run_job()
        self.assertEqual(code,1);self.assertEqual(self.deployments,[])
        self.assertIn('digest/build mismatch',result['error']['message'])
        self.assertFalse([x for x in self.aws.calls if x[1]=='invoke_agent_runtime'])

    def test_reuse_runtime_drift_stops_before_analysis(self):
        previous=self.prepare_reuse()
        self.aws.runtimes['V1-BENIGN']['RuntimeVersion']='2'
        with patch.dict(gate_b.REUSE,sha256=gate_b.sha256_json(previous)):code,result=self.run_job()
        self.assertEqual(code,1);self.assertEqual(self.deployments,[])
        self.assertFalse([x for x in self.aws.calls if x[1]=='invoke_agent_runtime'])

if __name__=='__main__':unittest.main()
