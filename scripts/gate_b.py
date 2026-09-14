"""Live semantic proof on fixed runtimes. Gate B UI acceptance remains separate."""
import copy
import hashlib
import json
import os
from pathlib import Path
import sys
import uuid
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'scripts'),str(ROOT/'src')]
from gate_a import GateA
from gate_a_state import read_json,observe_baseline,stable_ledger
from deploy_baseline import require_worker_identity,ACCOUNT,REGION
from verify_aws import save_evidence,safe_error,sdk_evidence,observed_at
from authority_delta.evidence_json import encode_evidence
from authority_delta.import_replay import import_gate_a
from authority_delta.analysis import prepare_analysis,attach_analysis
from authority_delta.replay import ReplayObservation,ReplayEvidence,replay_from_contract
from authority_delta.domain import Judgment
from authority_delta.canonical import sha256_json
from build_analysis_runtime import build
from gate_b_diagnostics import semantic_diagnostics
from analysis_model import resolve_analysis_model
SCOPE='GATE_B_LIVE_SEMANTIC_PROOF_UI_NOT_INCLUDED'
REUSE={'key':'evidence/64fe9cd81aaf42149c10a5855cc579d9/gate-b-result.json','version_id':'ClJgbaeJJ_qiIwIhLsWqoRCM3e085M6O','build_id':'authority-delta-deploy:4186d536-a5f8-4bf9-9015-2b697b32fcdb','sha256':'04cebec2af045e684ae5b38dcc27306679654dc5df5440068e5c4502f4ed40bb'}
PRIOR={'key':'evidence/a3c877fa362e4e2b8234b0474ec9ba62/gate-a-result.json','version_id':'9f4gdW9LwTE6_Txqfa9l.MreHJ2ySkQr'}

class GateB(GateA):
    def checkpoint(self,phase):
        partial=dict(self.report,result='IN_PROGRESS',checkpoint_phase=phase,checkpoint_at=observed_at())
        encoded=encode_evidence(partial)
        key=self.env['AD_REPORT_KEY'].removesuffix('.json')+'-'+phase+'.json'
        saved=save_evidence(self.session,self.env,encoded,self.root/f'evidence/aws/gate-b-{phase}.json',key)
        save_evidence(self.session,self.env,encoded,self.root/'evidence/aws/gate-b-latest.json',self.env['AD_REPORT_KEY'].removesuffix('.json')+'-latest.json')
        self.report.setdefault('checkpoints',{})[phase]=saved
        print('[Gate B] '+phase+' saved',flush=True)

    def deploy(self,template_name,stack_name,prefix,artifact,extra=None):
        parameters={'ArtifactBucket':self.bucket,'DeployerRoleArn':f'arn:aws:iam::{ACCOUNT}:role/ReadinessOpsAuthorityDeltaDeployer',prefix+'ArtifactKey':artifact['key'],prefix+'ArtifactVersionId':artifact['version_id']}
        parameters.update(extra or {})
        template=self.root/'infra'/template_name/'template.json'
        self.session.client('cloudformation').validate_template(TemplateBody=template.read_text())
        self.run(['aws','cloudformation','deploy','--region',REGION,'--no-cli-pager','--template-file',str(template),'--stack-name',stack_name,'--capabilities','CAPABILITY_NAMED_IAM','--no-fail-on-empty-changeset','--parameter-overrides',*[k+'='+v for k,v in parameters.items()]],check=True,cwd=self.root)
        stack=self.session.client('cloudformation').describe_stacks(StackName=stack_name)['Stacks'][0]
        if stack['StackStatus'] not in ('CREATE_COMPLETE','UPDATE_COMPLETE'):raise ValueError('Runtime deployment incomplete')
        outputs={o['OutputKey']:o['OutputValue'] for o in stack['Outputs']}
        binding={k:outputs[prefix+k] for k in ('RuntimeArn','RuntimeId','RuntimeVersion','EndpointArn','EndpointName','ExecutionRoleArn')}
        self.endpoint(binding)
        return binding

    def analysis(self,source,label):
        binding=self.report['analysis_runtime_binding'];self.endpoint(binding)
        session=str(uuid.uuid4());self.sessions[binding['RuntimeArn']]=session;self.session_bindings[binding['RuntimeArn']]=binding
        call={'label':label,'input_hash':source['input_hash'],'binding':binding,'status':'FAIL'}
        self.report.setdefault('analysis_calls',[]).append(call)
        for attempt in range(4):
            try:
                result=self.data.invoke_agent_runtime(agentRuntimeArn=binding['RuntimeArn'],qualifier=binding['EndpointName'],runtimeSessionId=session,contentType='application/json',accept='application/json',payload=encode_evidence(source));break
            except Exception as exc:
                if getattr(exc,'response',{}).get('Error',{}).get('Code')!='RetryableConflictException' or attempt==3:raise
                self.sleep(2**attempt)
        stream=result['response']
        try:raw=stream.read(262145)
        finally:stream.close()
        if len(raw)>262144:raise ValueError('Analysis response too large')
        call.update(api_evidence=sdk_evidence(result),response=json.loads(raw));self.endpoint(binding)
        response=call['response'];identity=response.get('identity',{})
        role=binding['ExecutionRoleArn'].rsplit('/',1)[-1]
        if response.get('result')=='HOLD':
            self.checkpoint(label+'-runtime-hold')
            detail=response.get('error',{}).get('message','Analysis held without a validated proposal')
            raise ValueError('Analysis Runtime HOLD: '+str(detail))
        if result.get('statusCode')!=200 or not call['api_evidence'].get('request_id') or response.get('result')!='OBSERVED' or response.get('analysis_status')!='VALIDATED' or response.get('input_hash')!=source['input_hash']:raise ValueError('Analysis Runtime did not return bound observations')
        if identity.get('account')!=ACCOUNT or not identity.get('arn','').startswith(f'arn:aws:sts::{ACCOUNT}:assumed-role/{role}/') or not identity.get('request_id'):raise ValueError('Analysis identity mismatch')
        if response.get('model_id')!=self.report['analysis_model']['model_id']:raise ValueError('Analysis response model differs from resolved profile')
        calls=response.get('model_calls',[])
        if not calls or any(c.get('http_status')!=200 or not c.get('request_id') for c in calls):raise ValueError('Missing real Bedrock request evidence')
        call['status']='PASS';return response

    def obtain_benign(self,replays):
        if self.env.get('AD_REUSE_GATE_B'):
            if self.env['AD_REUSE_GATE_B']!=REUSE['build_id']:raise ValueError('Unexpected replay reuse source')
            previous,metadata=read_json(self.s3,self.bucket,REUSE['key'],REUSE['version_id'])
            if sha256_json(previous)!=REUSE['sha256'] or previous.get('build_id')!=REUSE['build_id']:
                raise ValueError('Prior semantic report digest/build mismatch')
            if previous.get('scope')!=SCOPE or previous.get('account')!=ACCOUNT or previous.get('region')!=REGION or previous.get('state_unchanged') is not True:
                raise ValueError('Prior read-only analysis state is not confirmed')
            old=previous['baseline_after'];current=self.report['baseline_before']
            if old['stable']!=current['stable'] or old['policies']!=current['policies'] or stable_ledger(old['ledger'])!=stable_ledger(current['ledger']):
                raise ValueError('Protected baseline changed since saved replay')
            saved=previous['analysis_inputs']['semantic']
            if saved['replays']!={'before':replays['V1'].as_contract(),'candidate':replays['V2'].as_contract()}:
                raise ValueError('Prior semantic input does not match pinned Gate A replay')
            benign=previous['benign_artifact'];binding=previous['benign_binding']
            self.runtimes['V1-BENIGN']=binding;self.validate_runtime('V1-BENIGN',benign)
            benign_replay=replay_from_contract(previous['benign_replay'])
            prepare_analysis(self.fixtures,replays['V1'],benign_replay)
            if benign_replay.release_id!='V1-BENIGN' or len(benign_replay.observations)!=6:
                raise ValueError('Saved benign coverage differs from the fixed release')
            self.report.update(benign_artifact=benign,benign_binding=binding,benign_replay=benign_replay.as_contract(),
                reused_observations={'location':dict(REUSE,bucket=self.bucket),'count':6,'new_vendor_runtime_invocations':0,
                    'original_checkpoint':previous['checkpoints']['benign-observations']})
            self.checkpoint('reused-benign')
            return benign,benign_replay
        benign=self.artifact('V1-BENIGN');self.report['benign_artifact']=benign
        extras={k:self.binding['resources'][k] for k in ('GatewayArn','GatewayIdentifier','GatewayUrl','RequestRegistryTableName')}
        binding=self.deploy('benign-runtime','authority-delta-benign-runtime','Benign',benign,extras)
        self.runtimes['V1-BENIGN']=binding;self.report['benign_binding']=binding;self.validate_runtime('V1-BENIGN',benign)
        observations=[]
        for case in self.fixtures.cases:
            body=self.invoke('V1-BENIGN',{'operation':'evaluate','request_id':case.request_id},'BENIGN-'+case.case_id)
            evaluation=body.get('evaluation',{})
            if evaluation.get('gateway_outcome')!='NOT_RUN':raise ValueError('Benign replay invoked a protected tool')
            ref=f"s3://{self.bucket}/{self.env['AD_REPORT_KEY']}#BENIGN-{case.case_id}"
            observations.append(ReplayObservation(case.case_id,case.request_id,'V1-BENIGN',Judgment(evaluation.get('judgment')),(ref,)))
        self.checkpoint('benign-observations')
        pinned=self.report['checkpoints']['benign-observations']
        observations=[ReplayObservation(o.case_id,o.request_id,o.release_id,o.judgment,(f"s3://{pinned['bucket']}/{pinned['key']}?versionId={pinned['version_id']}#BENIGN-{o.case_id}",)) for o in observations]
        benign_replay=ReplayEvidence('1.0','AD-BASELINE-1.0','V1-BENIGN',benign['release_definition_hash'],self.fixtures.request_registry_snapshot_hash,tuple(observations))
        self.report['benign_replay']=benign_replay.as_contract();self.checkpoint('benign')
        return benign,benign_replay

    def execute(self):
        identity=self.session.client('sts').get_caller_identity();require_worker_identity(identity,self.env)
        if self.bucket!=self.binding['artifact_bucket']:raise ValueError('Unexpected artifact bucket')
        self.report.update(account=ACCOUNT,region=REGION,caller_arn=identity['Arn'])
        prior,metadata=read_json(self.s3,self.bucket,PRIOR['key'],PRIOR['version_id'])
        location=dict(PRIOR,bucket=self.bucket)
        replays=import_gate_a(prior,fixtures=self.fixtures,location=location,account=ACCOUNT,region=REGION)
        self.report['prior_gate_a']={'location':location,'build_id':prior['build_id'],'sha256':hashlib.sha256(encode_evidence(prior)).hexdigest()}
        self.runtimes=copy.deepcopy(prior['runtime_bindings'])
        for release in ('V1','V2'):self.validate_runtime(release,prior['runtime_artifacts'][release])
        self.report['baseline_before']=observe_baseline(self.session,self.binding,self.fixtures);self.checkpoint('prior')
        benign,benign_replay=self.obtain_benign(replays)
        model=resolve_analysis_model(self.session,ACCOUNT,REGION)
        self.report['analysis_model']=model;self.checkpoint('analysis-model')
        artifact=build(self.root/'dist/analysis-runtime.zip',root=self.root)
        key='runtime/'+artifact['sha256']+'/analysis.zip'
        uploaded=self.s3.put_object(Bucket=self.bucket,Key=key,Body=Path(artifact['path']).read_bytes(),Metadata={'sha256':artifact['sha256']})
        if not uploaded.get('VersionId') or uploaded['VersionId']=='null':raise ValueError('Analysis artifact version missing')
        artifact.update(key=key,version_id=uploaded['VersionId'],bucket=self.bucket);self.report['analysis_artifact']=artifact
        binding=self.deploy('analysis-runtime','authority-delta-analysis-runtime','Analysis',artifact,model['deployment_parameters'])
        self.report['analysis_runtime_binding']=binding
        current=self.control.get_agent_runtime(agentRuntimeId=binding['RuntimeId'],agentRuntimeVersion=binding['RuntimeVersion'])
        code=current.get('agentRuntimeArtifact',{}).get('codeConfiguration',{}).get('code',{}).get('s3',{})
        if current.get('status')!='READY' or current.get('agentRuntimeVersion')!=binding['RuntimeVersion'] or current.get('roleArn')!=binding['ExecutionRoleArn'] or code!={'bucket':self.bucket,'prefix':key,'versionId':artifact['version_id']}:raise ValueError('Analysis Runtime code/role binding mismatch')
        if current.get('environmentVariables',{}).get('AD_ANALYSIS_MODEL_ID')!=model['model_id']:raise ValueError('Analysis Runtime model binding differs from resolved profile')
        self.report['analysis_runtime_control']=current;self.checkpoint('analysis-runtime')
        self.report['patches']={}
        for label,candidate in [('semantic',replays['V2']),('benign',benign_replay)]:
            self.report['semantic_runtime_proof']='IN_PROGRESS'
            gate_key='sem_01' if label=='semantic' else 'sem_02'
            self.report[gate_key]='IN_PROGRESS'
            source=prepare_analysis(self.fixtures,replays['V1'],candidate)
            source['manifests']={release:{'binding':self.runtimes[release], 'artifact':prior['runtime_artifacts'][release] if release in ('V1','V2') else benign} for release in ('V1',candidate.release_id)}
            source.pop('input_hash');source['input_hash']=sha256_json(source)
            self.report.setdefault('analysis_inputs',{})[label]=source
            response=self.analysis(source,label)
            patch=attach_analysis(source=source,before=replays['V1'],candidate=candidate,proposal=response['proposal'],reads=response['reads'],decision_pack_id='DP-demo',boundary_version=1)
            self.report['patches'][label]=patch
            expected=self.fixtures.raw['expected_delta_case_ids'] if label=='semantic' else self.fixtures.raw['expected_benign_delta_case_ids']
            accepted=patch['analysis_status']=='VALIDATED' and patch['affected_case_ids']==expected
            self.report[gate_key]='PASS' if accepted else 'FAIL'
            self.report.setdefault('semantic_acceptance',{})[label]={
                'status':self.report[gate_key], 'expected_case_ids':expected,
                'observed_case_ids':patch['affected_case_ids'],
                'analysis_status':patch['analysis_status'], 'analysis_error':patch.get('analysis_error')}
            if not accepted:self.report['semantic_runtime_proof']='FAIL'
            self.checkpoint(label+'-analysis')
            if not accepted:
                detail=patch.get('analysis_error') or 'Observed case set differs from acceptance'
                raise ValueError(label+' acceptance failed: '+detail)
        self.report['baseline_after']=observe_baseline(self.session,self.binding,self.fixtures)
        before=self.report['baseline_before'];after=self.report['baseline_after']
        if before['stable']!=after['stable'] or before['policies']!=after['policies'] or stable_ledger(before['ledger'])!=stable_ledger(after['ledger']):raise ValueError('Protected baseline changed during read-only analysis')
        self.report.update(result='PASS',semantic_runtime_proof='PASS',sem_01='PASS',sem_02='PASS',gate_b='NOT_PASSED_UI_PENDING',state_unchanged=True)


def run_worker(session,environment,root=ROOT,runner=GateB):
    report={'schema_version':'1.0','baseline_id':'AD-BASELINE-1.0','scope':SCOPE,'result':'FAIL','gate_b':'NOT_PASSED','semantic_runtime_proof':'NOT_RUN','sem_01':'NOT_RUN','sem_02':'NOT_RUN','build_id':environment.get('CODEBUILD_BUILD_ID'),'source_sha256':environment.get('AD_SOURCE_SHA256'),'started_at':observed_at()}
    job=None
    try:job=runner(session,environment,report,root=root);job.execute()
    except Exception as exc:
        report.update(result='FAIL',error=safe_error(exc))
        for key in ('semantic_runtime_proof','sem_01','sem_02'):
            if report[key]=='IN_PROGRESS':report[key]='FAIL'
    finally:
        if job is not None:
            job.stop_sessions()
            if 'baseline_before' in report:
                try:
                    after=observe_baseline(session,job.binding,job.fixtures);report['baseline_after']=after
                    before=report['baseline_before']
                    report['state_unchanged']=before['stable']==after['stable'] and before['policies']==after['policies'] and stable_ledger(before['ledger'])==stable_ledger(after['ledger'])
                    if not report['state_unchanged']:report.update(result='FAIL',state_error='Protected baseline changed')
                except Exception as exc:report.update(result='FAIL',state_unchanged=None,state_error=safe_error(exc))
    report['completed_at']=observed_at();encoded=encode_evidence(report)
    try:save_evidence(session,environment,encoded,root/'evidence/aws/gate-b-result.json',environment['AD_REPORT_KEY'])
    except Exception as exc:print('Evidence save failed: '+str(exc));return 1
    summary={k:report.get(k) for k in ('result','semantic_runtime_proof','gate_b','sem_01','sem_02','error')}
    summary['analysis_diagnostics']=semantic_diagnostics(report)
    print(json.dumps(summary,indent=2))
    return 0 if report['result']=='PASS' else 1

if __name__=='__main__':
    import boto3
    from botocore.config import Config
    session=boto3.Session(region_name=REGION);original=session.client
    session.client=lambda service,**kw:original(service,config=Config(connect_timeout=10,read_timeout=300,retries={'total_max_attempts':1}),**kw)
    raise SystemExit(run_worker(session,os.environ))
