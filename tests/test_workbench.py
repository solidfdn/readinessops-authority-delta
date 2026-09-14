import copy,io,json,os,subprocess,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
from botocore.stub import Stubber
from botocore.response import StreamingBody
import boto3
import test_gate_b_worker as semantic_support
from build_business_ui_fixture import build as build_business_ui_fixture
from authority_delta.workbench import review_document
from authority_delta.registry import FixtureBundle
from services.workbench.handler import handler
from scripts import deploy_workbench as worker
from scripts import launch_workbench as launcher

ROOT=Path(__file__).resolve().parents[1]

class WorkbenchTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        helper=semantic_support.GateBTests();helper.setUp()
        try:
            code,cls.report=helper.run_job();assert code==0
        finally:helper.doCleanups()
        cls.report.update(build_id=worker.PRIOR_BUILD,source_sha256=worker.PRIOR_SOURCE)
        cls.fixtures=FixtureBundle.load(ROOT/'fixtures/decision_cases.json')
        cls.document=review_document(cls.report,cls.fixtures,worker.PRIOR)
        target=ROOT/'workbench/.test/review.json';target.parent.mkdir(exist_ok=True)
        target.write_text(json.dumps(cls.document))
        build_business_ui_fixture()

    def test_preserves_actual_changes_and_computes_boundary_previews(self):
        d=self.document
        self.assertEqual(d['comparisons']['semantic']['patch']['affected_case_ids'],['P-002'])
        self.assertEqual(d['comparisons']['benign']['patch']['affected_case_ids'],[])
        self.assertEqual(len(d['comparisons']['semantic']['cases']),6)
        for decision,allowed in [('MAINTAIN',['P-001','C-001']),('NARROW',['C-001']),('REJECT',[])]:
            self.assertEqual([x['case_id'] for x in d['previews'][decision]['expected_outcomes'] if x['expected_policy_outcome']=='ALLOW'],allowed)
        self.assertFalse(d['approval_recorded']);self.assertEqual(d['publication_status'],'NOT_RUN')
        self.assertNotIn('expected_case_ids',json.dumps(d))
        from jsonschema import Draft202012Validator
        schema=json.loads((ROOT/'packages/contracts/readinessops.schema.json').read_text())
        Draft202012Validator(schema).validate(d['workspace'])
        self.assertEqual(len(d['workspace']['findings']),1)
        self.assertEqual(d['workspace']['findings'][0]['case_id'],'P-002')
        self.assertEqual(len(d['workspace']['history']),2)

    def test_rejects_failed_or_tampered_evidence(self):
        mutations=[lambda x:x.update(sem_02='FAIL'),lambda x:x.update(state_unchanged=False),
            lambda x:x['analysis_inputs']['semantic']['requests'].pop(),
            lambda x:x['patches']['semantic']['affected_case_ids'].append('P-003'),
            lambda x:x['analysis_calls'][0].update(input_hash='0'*64),
            lambda x:x['analysis_calls'][0]['response']['model_calls'][0].update(http_status=403)]
        for change in mutations:
            r=copy.deepcopy(self.report);change(r)
            with self.subTest(change=change),self.assertRaises((ValueError,KeyError)):
                review_document(r,self.fixtures,worker.PRIOR)

    def test_authenticated_reader_uses_exact_s3_version(self):
        client=boto3.client('s3',region_name='ap-northeast-1',aws_access_key_id='test',aws_secret_access_key='test')
        payload=json.dumps(self.document).encode()
        env={'CLIENT_ID':'client123','REVIEWER_USERNAME':'okada','DATA_BUCKET':'private-bucket','DATA_KEY':'review/pinned.json','DATA_VERSION':'fixed-version'}
        event={'routeKey':'GET /review','requestContext':{'authorizer':{'jwt':{'claims':{'token_use':'access','client_id':'client123','sub':'reviewer-sub','username':'okada','scope':'openid authority-delta/read'}}}}}
        with patch.dict(os.environ,env),patch('services.workbench.handler.boto3.client',return_value=client),Stubber(client) as stub:
            stub.add_response('get_object',{'Body':StreamingBody(io.BytesIO(payload),len(payload))},
                {'Bucket':'private-bucket','Key':'review/pinned.json','VersionId':'fixed-version'})
            response=handler(event,None)
            self.assertEqual(response['statusCode'],200);self.assertEqual(json.loads(response['body']),self.document)
            stub.assert_no_pending_responses()

    def test_bad_principals_and_write_routes_never_read_or_mutate(self):
        event={'routeKey':'GET /review','requestContext':{'authorizer':{'jwt':{'claims':{'token_use':'access','client_id':'client123','sub':'s','username':'okada','scope':'authority-delta/read'}}}}}
        with patch.dict(os.environ,{'CLIENT_ID':'client123','REVIEWER_USERNAME':'okada'}),patch('services.workbench.handler.boto3.client') as client:
            for field,value in [('token_use','id'),('client_id','foreign'),('sub',''),('username','foreign'),('scope','openid')]:
                bad=copy.deepcopy(event);bad['requestContext']['authorizer']['jwt']['claims'][field]=value
                self.assertIn(handler(bad,None)['statusCode'],[401,403])
            self.assertEqual(handler({'routeKey':'POST /approve'},None)['statusCode'],404)
            self.assertEqual(handler({'routeKey':'GET /review'},None)['statusCode'],401)
            client.assert_not_called()

    def test_failure_does_not_leak_evidence_or_aws_errors(self):
        event={'routeKey':'GET /review','requestContext':{'authorizer':{'jwt':{'claims':{'token_use':'access','client_id':'client123','sub':'s','username':'okada','scope':'authority-delta/read'}}}}}
        env={'CLIENT_ID':'client123','REVIEWER_USERNAME':'okada','DATA_BUCKET':'private','DATA_KEY':'secret','DATA_VERSION':'v'}
        with patch.dict(os.environ,env),patch('services.workbench.handler.boto3.client',side_effect=RuntimeError('private AWS detail')):
            response=handler(event,None);self.assertEqual(response['statusCode'],503);self.assertNotIn('private',response['body'])

    def test_password_stays_in_seekable_memory_and_out_of_arguments(self):
        class Cli:
            env={'AWS_DEFAULT_REGION':'ap-northeast-1'}
            def run(self,*args):
                calls.append(args);return {'UserStatus':'FORCE_CHANGE_PASSWORD' if len(calls)==1 else 'CONFIRMED'}
        calls=[]; secret='ExampleSecret93'
        def run(args,**kw):
            self.assertNotIn(secret,' '.join(args));self.assertNotIn('input',kw)
            path=args[args.index('--cli-input-json')+1].removeprefix('file://')
            with open(path) as source:
                body=json.load(source);source.seek(0);self.assertEqual(body,json.load(source))
            self.assertEqual(body['Password'],secret)
            self.assertEqual(kw['pass_fds'],(int(path.rsplit('/',1)[1]),))
            self.assertIn('--no-cli-auto-prompt',args);self.assertEqual(kw['env']['AWS_DEFAULT_OUTPUT'],'json')
            return subprocess.CompletedProcess(args,0,'{}','')
        with patch('builtins.print'):
            launcher.setup_password(Cli(),{'UserPoolId':'ap-northeast-1_abc','ReviewerUsername':'okada'},prompt=lambda _:secret,run=run)
        self.assertEqual(len(calls),2)

    def test_confirmed_user_password_is_preserved(self):
        class Cli:
            def run(self,*args):return {'UserStatus':'CONFIRMED'}
        with patch('getpass.getpass') as prompt:
            launcher.setup_password(Cli(),{'UserPoolId':'ap-northeast-1_abc','ReviewerUsername':'okada'},prompt=prompt)
            prompt.assert_not_called()

    def test_infrastructure_has_no_cycles_and_no_authority_write(self):
        template=json.loads((ROOT/'infra/workbench/template.json').read_text());resources=template['Resources'];params=template['Parameters']
        import re
        def references(value):
            out=set()
            if isinstance(value,dict):
                if 'Ref' in value:out.add(value['Ref'])
                if 'Fn::GetAtt' in value:out.add(value['Fn::GetAtt'][0])
                if 'Fn::Sub' in value:out|={m.split('.')[0] for m in re.findall(r'\$\{([^}]+)\}',str(value['Fn::Sub'])) if not m.startswith('AWS::')}
                for x in value.values():out|=references(x)
            elif isinstance(value,list):
                for x in value:out|=references(x)
            return out
        graph={k:references(v) for k,v in resources.items()}
        for k,v in resources.items():
            dep=v.get('DependsOn',[]);graph[k].update([dep] if isinstance(dep,str) else dep)
        def visit(key,path):
            self.assertNotIn(key,path,'CloudFormation circular dependency')
            for next_key in graph[key]:
                self.assertTrue(next_key in resources or next_key in params or next_key.startswith('AWS::'),next_key)
                if next_key in graph:visit(next_key,path+[key])
        for k in graph:visit(k,[])
        role=resources['ReviewRole']['Properties']['Policies'][0]['PolicyDocument']
        self.assertEqual(role['Statement'][0]['Action'],['s3:GetObjectVersion'])
        self.assertEqual(resources['Reviewer']['Properties']['MessageAction'],'SUPPRESS')
        self.assertEqual(resources['ReviewRoute']['Properties']['AuthorizationScopes'],['authority-delta/read'])

    def test_worker_pinned_evidence_sdk_upload_and_http_verification(self):
        from botocore.stub import ANY
        from contextlib import ExitStack, redirect_stdout
        from datetime import datetime,timezone
        clients={name:boto3.client(name,region_name=worker.REGION,aws_access_key_id='test',aws_secret_access_key='test') for name in ['s3','sts','cloudformation']}
        class Session:
            def client(self,name):return clients[name]
        env={'AD_EXPECTED_ACCOUNT':worker.ACCOUNT,'AD_REGION':worker.REGION,'AD_ARTIFACT_BUCKET':worker.PRIOR['bucket'],'CODEBUILD_BUILD_ID':'authority-delta-deploy:test'}
        outputs={'SiteBucket':'review-ui-bucket','WorkspaceUrl':'https://dtest.cloudfront.net/','ClientId':'client123','ApiUrl':'https://api123.execute-api.ap-northeast-1.amazonaws.com',
            'AuthOrigin':'https://authority-delta-test.auth.ap-northeast-1.amazoncognito.com','UserPoolId':'ap-northeast-1_pool','ReviewerUsername':'okada'}
        with ExitStack() as stack:
            stubs={name:stack.enter_context(Stubber(client)) for name,client in clients.items()}
            stubs['sts'].add_response('get_caller_identity',{'Account':worker.ACCOUNT,'Arn':f'arn:aws:sts::{worker.ACCOUNT}:assumed-role/ReadinessOpsAuthorityDeltaDeployer/test','UserId':'test'})
            raw=json.dumps(self.report).encode()
            stubs['s3'].add_response('get_object',{'Body':StreamingBody(io.BytesIO(raw),len(raw)),'VersionId':worker.PRIOR['version_id']},
                {'Bucket':worker.PRIOR['bucket'],'Key':worker.PRIOR['key'],'VersionId':worker.PRIOR['version_id']})
            for _ in range(2):stubs['s3'].add_response('put_object',{'VersionId':'version-artifact'}, {'Bucket':worker.PRIOR['bucket'],'Key':ANY,'Body':ANY,'ContentType':ANY})
            stubs['cloudformation'].add_response('validate_template',{}, {'TemplateBody':(ROOT/'infra/workbench/template.json').read_text()})
            stubs['cloudformation'].add_response('describe_stacks',{'Stacks':[{'StackName':worker.STACK,'CreationTime':datetime.now(timezone.utc),'StackStatus':'CREATE_COMPLETE',
                'Outputs':[{'OutputKey':k,'OutputValue':v} for k,v in outputs.items()]}]}, {'StackName':worker.STACK})
            for _ in range(4):stubs['s3'].add_response('put_object',{'VersionId':'version-ui'}, {'Bucket':'review-ui-bucket','Key':ANY,'Body':ANY,'ContentType':ANY,'CacheControl':ANY})
            def fetch(url):
                if url==outputs['ApiUrl']+'/review':return 401,b'Unauthorized'
                name=url.rsplit('/',1)[-1]
                if name=='config.json':return 200,worker.encode_evidence({'client_id':outputs['ClientId'],'auth_origin':outputs['AuthOrigin'],'api_origin':outputs['ApiUrl'],'redirect_uri':outputs['WorkspaceUrl']})
                return 200,(ROOT/'services/workbench/assets'/name).read_bytes()
            commands=[]
            baseline=self.report['baseline_after']
            with patch.object(worker,'observe_baseline',return_value=baseline),redirect_stdout(io.StringIO()):
                report={};worker.execute(Session(),env,report,root=ROOT,fetch=fetch,run=lambda args,**kw:commands.append(args),sleep=lambda _:None)
            self.assertEqual(report['result'],'PASS');self.assertEqual(report['gate_b'],'UI_LOGIN_AND_REVIEW_PENDING')
            self.assertEqual(report['delivery_checks']['unauthenticated_review']['http_status'],401)
            self.assertEqual(len(commands),1);self.assertIn(worker.STACK,commands[0])
            for stub in stubs.values():stub.assert_no_pending_responses()

    def test_worker_failure_report_survives_serialization_and_collection(self):
        from contextlib import redirect_stdout
        import datetime
        env={'AD_REPORT_KEY':'evidence/test/workbench-result.json','CODEBUILD_BUILD_ID':'authority-delta-deploy:test','AD_SOURCE_SHA256':'0'*64}
        def fail(session,env,report,**kw):
            report['api_date']=datetime.datetime(2026,9,9,tzinfo=datetime.timezone.utc)
            raise ValueError('Evidence binding changed')
        with tempfile.TemporaryDirectory() as tmp,patch.object(worker,'save_evidence') as save,redirect_stdout(io.StringIO()):
            code=worker.run_worker(None,env,root=Path(tmp),executor=fail)
            self.assertEqual(code,1);saved=json.loads(save.call_args.args[2]);self.assertEqual(saved['result'],'FAIL')
            self.assertIn('Evidence binding changed',saved['error']['message']);self.assertIsInstance(saved['api_date'],str)

if __name__=='__main__':unittest.main()
