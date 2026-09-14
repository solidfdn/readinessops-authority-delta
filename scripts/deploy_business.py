"""Add ReadinessOps business workflow to the existing authenticated AWS workspace."""
import hashlib,json,os,subprocess,sys,time,uuid
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import Request,urlopen
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'scripts'),str(ROOT/'src')]
from deploy_baseline import ACCOUNT,REGION,require_worker_identity
from deploy_workbench import fetch_public
from gate_a_state import observe_baseline,stable_ledger
from verify_aws import observed_at,save_evidence,safe_error
from authority_delta.registry import FixtureBundle
from authority_delta.canonical import sha256_json
from authority_delta.evidence_json import encode_evidence
from authority_delta.business.storage import DynamoStore,S3Blobs,encode
from authority_delta.business.delegation import load_adapter_registry
from authority_delta.business.contracts import PERSPECTIVES,PROMPT_VERSION,check_snapshot,validate_proposal
from build_business_artifacts import build
from analysis_model import resolve_analysis_model
SCOPE='READINESSOPS_BUSINESS_WORKFLOW_DEPLOYMENT_NO_HUMAN_APPROVAL'
WORKSPACE_URL='https://d3rn3hqm0ax5ux.cloudfront.net/'
BUSINESS_STACK='authority-delta-business'
WORKBENCH_STACK='authority-delta-workbench'
CANARY_RECOVERY_REPORT={
    'bucket':'authority-delta-bootstrap-artifactbucket-6ebtk8mvvqyp',
    'key':'evidence/f8bf4b664c5b48fda8620d64b9629e54/business-result.json',
    'version_id':'pTrtjLJ0Bz0oN34K8CQAHViU8547ESfr',
    'build_id':'authority-delta-deploy:02244729-c866-4424-885b-6fe8d0209dd6',
    'source_sha256':'705c6651fbe5739cc046644a22bf6dbf4292d6a60bb5d7e9672bb5b2f1e01fd8'}
CANARY_RECOVERY_RUN='run-145ceb8a0f38417c86383044c7818c33'
CANARY_RECOVERY_INPUT={
    'bucket':'authority-delta-business-databucket-m0ydp4cbfqwc',
    'key':'business/inputs/run-145ceb8a0f38417c86383044c7818c33.json',
    'version_id':'i7X5zax2vue6jkiuQ9MQzBlL6A3R4TUj',
    'sha256':'40ee701aef69f38b1cac3bf51f01f0c8253f7678758e21998544cf9b4a2b6299','size':1382}
CANARY_RECOVERY_RUNTIME={
    'bucket':'authority-delta-bootstrap-artifactbucket-6ebtk8mvvqyp',
    'key':'business-code/646b275cbb080bfb4456b50968a5ce4e712330434c9f13cd2a50af0aa2c9c3bb/runtime.zip',
    'version_id':'ccVINKBkk.myjQ8UBXZ.QvobJF6kk0eN',
    'sha256':'646b275cbb080bfb4456b50968a5ce4e712330434c9f13cd2a50af0aa2c9c3bb',
    'size_bytes':28326981,'architecture':'aarch64'}


def browser_preflight(url, origin):
    """Exercise the browser's authenticated-fetch preflight, not only GET."""
    request=Request(url,method='OPTIONS',headers={
        'Origin':origin,
        'Access-Control-Request-Method':'GET',
        'Access-Control-Request-Headers':'authorization'})
    try:
        with urlopen(request,timeout=20) as response:
            return response.status,{k.lower():v for k,v in response.headers.items()}
    except HTTPError as exc:
        return exc.code,{k.lower():v for k,v in exc.headers.items()}


def read_recovery_report(s3):
    """Read only the exact failed deployment reported by the user."""
    pin=CANARY_RECOVERY_REPORT
    obj=s3.get_object(Bucket=pin['bucket'],Key=pin['key'],VersionId=pin['version_id'])
    stream=obj['Body']
    try:raw=stream.read(2_000_001)
    finally:stream.close()
    if obj.get('VersionId')!=pin['version_id'] or len(raw)>2_000_000:
        raise ValueError('Pinned recovery report version/size differs')
    prior=json.loads(raw)
    expected={'scope':SCOPE,'build_id':pin['build_id'],'source_sha256':pin['source_sha256'],
              'account':ACCOUNT,'region':REGION,'result':'FAIL','state_unchanged':True,'approval_recorded':False}
    if any(prior.get(k)!=v for k,v in expected.items()):
        raise ValueError('Pinned failed deployment identity/status differs')
    return prior


def recovery_runtime_artifact(s3,prior):
    """Keep the fixed model runtime while updating the DynamoDB client in Lambda."""
    artifact=prior.get('artifacts',{}).get('runtime',{})
    if any(artifact.get(k)!=v for k,v in CANARY_RECOVERY_RUNTIME.items()):
        raise ValueError('Pinned recovery runtime artifact differs')
    obj=s3.get_object(Bucket=artifact['bucket'],Key=artifact['key'],VersionId=artifact['version_id'])
    stream=obj['Body']
    try:raw=stream.read(artifact['size_bytes']+1)
    finally:stream.close()
    if obj.get('VersionId')!=artifact['version_id'] or len(raw)!=artifact['size_bytes'] or hashlib.sha256(raw).hexdigest()!=artifact['sha256']:
        raise ValueError('Retained runtime artifact bytes differ')
    return dict(artifact,reused_from_pinned_deployment=True)


def recover_business_canary(s3,db,blobs,resources):
    """Read the one pinned failed deployment; never create/reset an assessment."""
    pin=CANARY_RECOVERY_REPORT
    prior=read_recovery_report(s3)
    previous=prior.get('business_resources',{})
    # A code update can advance the runtime version; physical resources stay fixed.
    if set(previous)!=set(resources) or any(previous[k]!=resources[k] for k in previous if k!='AnalysisRuntimeVersion'):
        raise ValueError('Recovery would replace retained business resources')
    canary=prior.get('business_canary',{})
    if canary.get('scope')!='SYNTHETIC_NONPAYMENT_ASSESSMENT_NO_HUMAN_DECISION' or canary.get('run_id')!=CANARY_RECOVERY_RUN or canary.get('input_ref')!=CANARY_RECOVERY_INPUT:
        raise ValueError('Pinned synthetic assessment binding differs')
    ref=CANARY_RECOVERY_INPUT
    if resources.get('DataBucket')!=ref['bucket']:
        raise ValueError('Recovery input is not in the retained business bucket')
    raw=blobs.read(ref)
    if len(raw)!=ref['size'] or hashlib.sha256(raw).hexdigest()!=ref['sha256']:
        raise ValueError('Pinned recovery input bytes differ')
    source=json.loads(raw);check_snapshot(source)
    if source.get('source_authority')!='aws:deployment-canary':
        raise ValueError('Recovery input is not a deployment canary')
    row=db.get('jobs',CANARY_RECOVERY_RUN,'STATE')
    expected_job={'run_id':CANARY_RECOVERY_RUN,'owner_sub':'DEPLOYMENT_CANARY','input_ref':ref,
                  'input_hash':source['input_hash'],'object_id':source['object_id'],'data_revision':source['data_revision']}
    if row is None or any(row.value.get(k)!=v for k,v in expected_job.items()):
        raise ValueError('Saved synthetic job differs from the pinned input/owner')
    job=row.value
    if job.get('status') not in ('QUEUED','RUNNING','REVIEW_REQUIRED'):
        raise ValueError('Saved synthetic assessment is terminal; no automatic model retry: '+str(job.get('status')))
    if job['status']=='QUEUED' and (job.get('attempt')!=0 or job.get('result_ref') is not None):
        raise ValueError('Queued recovery job has unexpected execution evidence')
    if job['status'] in ('RUNNING','REVIEW_REQUIRED') and job.get('attempt')!=1:
        raise ValueError('Recovery job has an unexpected model attempt count')
    if job['status']=='REVIEW_REQUIRED':
        result=json.loads(blobs.read(job['result_ref']))
        if result.get('input_hash')!=source['input_hash'] or result.get('status')!='VALIDATED':
            raise ValueError('Completed recovery result differs from the pinned input')
        validate_proposal(result.get('proposal'),source,result.get('reads',[]))
    outbox=db.get('jobs','OUTBOX',CANARY_RECOVERY_RUN)
    if outbox and outbox.value!={'run_id':CANARY_RECOVERY_RUN,'input_hash':source['input_hash']}:
        raise ValueError('Recovery outbox differs from the pinned input')
    return CANARY_RECOVERY_RUN,source,dict(ref),dict(job),dict(pin)


def outputs(stack):return {o['OutputKey']:o['OutputValue'] for o in stack['Outputs']}


def updated_workbench_template(root=ROOT):
    template=json.loads((root/'infra/workbench/template.json').read_text())
    scopes=[('read','Read assigned evidence and business records'),('write','Create evidence, assessments and decision drafts'),('approve','Record a human decision on a saved draft'),('publish','Publish an approved business decision')]
    template['Resources']['ReviewResource']['Properties']['Scopes']=[{'ScopeName':n,'ScopeDescription':d} for n,d in scopes]
    template['Resources']['ReviewerClient']['Properties']['AllowedOAuthScopes']=['openid']+['authority-delta/'+n for n,d in scopes]
    cors=template['Resources']['Api']['Properties']['CorsConfiguration'];cors['AllowMethods']=['GET','POST','OPTIONS'];cors['AllowHeaders']=['authorization','content-type'];cors['ExposeHeaders']=['x-request-id']
    return template


def canary_input(run_id):
    text='This is a synthetic deployment check, not a customer approval. A customer support team proposes sending customer names and email addresses to an external analytics service. The internal rule requires a documented purpose and the data owner’s approval before sharing personal data externally. No owner approval or processor contract has been supplied. The intended outcome is to reduce weekly report preparation time. The current preparation time, model comparisons and operating costs have not been measured.'
    evidence={'evidence_id':'e-'+uuid.uuid4().hex,'title':'Synthetic external-sharing review','source':'Deployment canary fixture','text':text,'text_hash':sha256_json(text),'extraction_status':'READY'}
    value={'schema_version':'1.2','mode':'INITIAL','object_id':'o-'+uuid.uuid4().hex,'data_revision':1,
           'context':{'name':'Synthetic external data sharing','purpose':'Assess a proposed sharing process','question':'Which decisions and missing evidence should the owner review before external sharing?','owner':'Synthetic test owner','goals':'Reduce weekly reporting work; baseline not measured'},
           'decision_item_registry':[{'decision_item_id':'di-'+uuid.uuid4().hex,'perspective':p} for p in PERSPECTIVES],
           'evidence':[evidence],'prompt_version':PROMPT_VERSION,'model_id':'apac.amazon.nova-pro-v1:0','source_authority':'aws:deployment-canary'}
    value['input_hash']=sha256_json(value);check_snapshot(value);return value


def execute(session,env,report,*,root=ROOT,run=subprocess.run,fetch=fetch_public,sleep=time.sleep):
    binding=json.loads((root/'infra/environments/development.json').read_text());identity=session.client('sts').get_caller_identity();require_worker_identity(identity,env)
    if env['AD_ARTIFACT_BUCKET']!=binding['artifact_bucket']:raise ValueError('Unexpected artifact bucket')
    cfn=session.client('cloudformation');s3=session.client('s3');lam=session.client('lambda');report.update(account=ACCOUNT,region=REGION)
    fixtures=FixtureBundle.load(root/'fixtures/decision_cases.json')
    def checkpoint(phase):
        report['phase']=phase
        saved=save_evidence(session,env,encode_evidence(dict(report,result='IN_PROGRESS')),root/'evidence/aws/business-latest.json',env['AD_REPORT_KEY'].removesuffix('.json')+'-latest.json')
        print('[ReadinessOps] '+phase,flush=True)
    before=observe_baseline(session,binding,fixtures);report['baseline_before']=before
    workspace=cfn.describe_stacks(StackName=WORKBENCH_STACK)['Stacks'][0];original=outputs(workspace)
    if original['WorkspaceUrl']!=WORKSPACE_URL or original['ReviewerUsername']!='okada' or workspace['StackStatus'] not in ('CREATE_COMPLETE','UPDATE_COMPLETE'):raise ValueError('Existing workspace identity/status differs')
    user=session.client('cognito-idp').admin_get_user(UserPoolId=original['UserPoolId'],Username=original['ReviewerUsername'])
    attrs={a['Name']:a['Value'] for a in user['UserAttributes']}
    if user['UserStatus']!='CONFIRMED' or not attrs.get('sub'):raise ValueError('Existing confirmed sign-in was not found')
    authorizer=cfn.describe_stack_resource(StackName=WORKBENCH_STACK,LogicalResourceId='Authorizer')['StackResourceDetail']['PhysicalResourceId']
    report['existing_workspace']=original;report['existing_reviewer_sub']=attrs['sub'];checkpoint('Existing sign-in and protected AWS baseline recorded')
    model=resolve_analysis_model(session,ACCOUNT,REGION);report['analysis_model']=model
    def upload(bucket,key,raw,mime='application/octet-stream',**extra):
        response=s3.put_object(Bucket=bucket,Key=key,Body=raw,ContentType=mime,**extra)
        version=response.get('VersionId')
        if not version or version=='null':raise ValueError('Upload has no immutable version: '+key)
        stored=s3.get_object(Bucket=bucket,Key=key,VersionId=version)['Body']
        try:actual=stored.read(len(raw)+1)
        finally:stored.close()
        if actual!=raw:raise ValueError('Upload readback mismatch: '+key)
        return version
    recovery_prior=read_recovery_report(s3) if env.get('AD_RECOVER_BUSINESS_CANARY')=='1' else None
    report['artifacts']={}
    for kind,arch,runtime in [('lambda','x86_64',False),('runtime','aarch64',True)]:
        if runtime and recovery_prior is not None:
            # The minute dispatcher can resume the saved job during this update.
            # Retaining the original runtime avoids changing its endpoint while
            # an existing worker still holds the earlier immutable binding.
            report['artifacts'][kind]=recovery_runtime_artifact(s3,recovery_prior)
            continue
        artifact=build(root/('dist/business-'+kind+'.zip'),arch,runtime,root=root);key='business-code/'+artifact['sha256']+'/'+kind+'.zip'
        artifact.update(bucket=binding['artifact_bucket'],key=key,version_id=upload(binding['artifact_bucket'],key,Path(artifact['path']).read_bytes()))
        report['artifacts'][kind]=artifact
    params={'ArtifactBucket':binding['artifact_bucket'],'DeployerRoleArn':f'arn:aws:iam::{ACCOUNT}:role/ReadinessOpsAuthorityDeltaDeployer',
            'AnalysisArtifactKey':report['artifacts']['runtime']['key'],'AnalysisArtifactVersionId':report['artifacts']['runtime']['version_id'],
            'CodeKey':report['artifacts']['lambda']['key'],'CodeVersion':report['artifacts']['lambda']['version_id'],
            'ExistingApiId':original['ApiId'],'ExistingAuthorizerId':authorizer,'ClientId':original['ClientId'],'ReviewerSub':attrs['sub'],**model['deployment_parameters']}
    registrations=load_adapter_registry(root/'services/business/adapter_registrations.json')
    publishers=sorted({value['publisher_binding']['function_arn'] for value in registrations})
    invoke_roles=sorted({value['publisher_binding']['invoke_role_arn'] for value in registrations})
    runtime_roles=sorted({value['invocation_binding']['invoke_role_arn'] for value in registrations})
    if len(publishers)>1 or len(invoke_roles)>1 or len(runtime_roles)>1:
        raise ValueError('Business stack supports one exact customer publisher connector per deployment')
    if invoke_roles:
        params['CustomerPublisherInvokeRoleArn']=invoke_roles[0]
    if runtime_roles:
        params['CustomerRuntimeInvokeRoleArn']=runtime_roles[0]
    def deploy(template,name,parameters):
        cfn.validate_template(TemplateBody=template.read_text())
        report['deploying_stack']=name
        run(['aws','cloudformation','deploy','--region',REGION,'--no-cli-pager','--template-file',str(template),'--stack-name',name,'--capabilities','CAPABILITY_NAMED_IAM','--no-fail-on-empty-changeset','--parameter-overrides',*[k+'='+v for k,v in parameters.items()]],check=True,cwd=root)
        stack=cfn.describe_stacks(StackName=name)['Stacks'][0]
        if stack['StackStatus'] not in ('CREATE_COMPLETE','UPDATE_COMPLETE'):raise ValueError(name+' did not reach a completed state')
        return outputs(stack)
    checkpoint('Deploying business records, queue, bounded analysis and authenticated API')
    resources=deploy(root/'infra/business/template.json',BUSINESS_STACK,params);report['business_resources']=resources
    # Verify code, role, version and model against the service response, not only stack outputs.
    runtime=session.client('bedrock-agentcore-control').get_agent_runtime(agentRuntimeId=resources['AnalysisRuntimeId'],agentRuntimeVersion=resources['AnalysisRuntimeVersion'])
    code=runtime.get('agentRuntimeArtifact',{}).get('codeConfiguration',{}).get('code',{}).get('s3',{})
    if runtime.get('status')!='READY' or runtime.get('roleArn')!=resources['AnalysisExecutionRoleArn'] or runtime.get('agentRuntimeVersion')!=resources['AnalysisRuntimeVersion'] or code!={'bucket':binding['artifact_bucket'],'prefix':params['AnalysisArtifactKey'],'versionId':params['AnalysisArtifactVersionId']} or runtime.get('environmentVariables',{}).get('AD_ANALYSIS_MODEL_ID')!=model['model_id']:raise ValueError('Business runtime artifact/identity/model differs')
    report['runtime_control']=runtime
    for key in ['ApiFunction','WorkerFunction','DispatcherFunction',
                'ApplicationWorkerFunction','ApplicationDispatcherFunction',
                'InvocationGateFunction','InvocationWorkerFunction']:
        config=lam.get_function_configuration(FunctionName=resources[key])
        if config.get('State')!='Active' or config.get('LastUpdateStatus')!='Successful':raise ValueError(key+' is not active')
    mappings=lam.list_event_source_mappings(FunctionName=resources['WorkerFunction'])['EventSourceMappings']
    if len(mappings)!=2 or any(m.get('State')!='Enabled' or m.get('BatchSize')!=1 or 'ReportBatchItemFailures' not in m.get('FunctionResponseTypes',[]) for m in mappings):raise ValueError('Business worker queue mapping is not ready')
    application_mappings=lam.list_event_source_mappings(FunctionName=resources['ApplicationWorkerFunction'])['EventSourceMappings']
    if len(application_mappings)!=2 or any(m.get('State')!='Enabled' or m.get('BatchSize')!=1 or 'ReportBatchItemFailures' not in m.get('FunctionResponseTypes',[]) for m in application_mappings):raise ValueError('Application and revocation worker queue mapping is not ready')
    invocation_mappings=lam.list_event_source_mappings(FunctionName=resources['InvocationWorkerFunction'])['EventSourceMappings']
    if len(invocation_mappings)!=2 or any(m.get('State')!='Enabled' or m.get('BatchSize')!=1 or 'ReportBatchItemFailures' not in m.get('FunctionResponseTypes',[]) for m in invocation_mappings):raise ValueError('Invocation worker queue mapping is not ready')
    # This synthetic job exercises the same outbox -> queue -> Lambda -> Strands -> saved result.
    # It creates no BusinessObject, ApprovalReceipt or DecisionPublication.
    db=DynamoStore(session.client('dynamodb'),{'jobs':resources['JobsTable']});blobs=S3Blobs(s3,resources['DataBucket'])
    recover_canary=env.get('AD_RECOVER_BUSINESS_CANARY')=='1'
    # An exact application recovery may make one fresh synthetic retry when a
    # healthy live model call is safely rejected only by the output contract.
    # This is not a business retry and creates no object, approval, publication,
    # Policy or ledger entry. A successful, fully validated proposal is still
    # mandatory before deployment continues.
    canary_limit=1 if recover_canary else (2 if env.get('AD_RECOVERY_APPLICATION_ID') else 1)
    report['business_canary_attempts']=[]
    for canary_number in range(1,canary_limit+1):
        if recover_canary and canary_number==1:
            rid,source,ref,job,recovery=recover_business_canary(s3,db,blobs,resources)
            report['canary_recovery']={'source_report':recovery,'reused_run_id':rid,'observed_status':job['status'],'new_assessment_created':False}
        else:
            rid='run-'+uuid.uuid4().hex;source=canary_input(rid);ref=blobs.put('business/inputs/'+rid+'.json',encode(source))
            job={'run_id':rid,'object_id':source['object_id'],'owner_sub':'DEPLOYMENT_CANARY','status':'QUEUED','created_at':observed_at(),'input_ref':ref,'input_hash':source['input_hash'],'data_revision':1,'attempt':0,'result_ref':None,'error':None}
            db.transact([('jobs',rid,'STATE',job,None),('jobs','OUTBOX',rid,{'run_id':rid,'input_hash':source['input_hash']},None)])
        report['business_canary']={'scope':'SYNTHETIC_NONPAYMENT_ASSESSMENT_NO_HUMAN_DECISION','run_id':rid,'input_ref':ref,'status':'IN_PROGRESS','bounded_run':canary_number,'bounded_run_limit':canary_limit};checkpoint('Running one synthetic non-payment assessment through the real queue and Strands')
        called=lam.invoke(FunctionName=resources['DispatcherFunction'],InvocationType='RequestResponse',Payload=b'{}');stream=called['Payload']
        try:payload=stream.read()
        finally:stream.close()
        if called.get('FunctionError'):raise ValueError('Dispatcher failed: '+payload.decode(errors='replace')[:1600])
        for attempt in range(90):
            row=db.get('jobs',rid,'STATE');report['business_canary']['job']=row.value
            if row.value['status'] not in ('QUEUED','RUNNING'):break
            if attempt%4==0:print('[ReadinessOps] Assessment '+row.value['status']+' ('+str(attempt*5)+'s)',flush=True)
            sleep(5)
        if row.value['result_ref']:
            result=json.loads(blobs.read(row.value['result_ref']));report['business_canary']['analysis']=result
        else:result={}
        report['business_canary']['status']=row.value['status']
        report['business_canary_attempts'].append({'run_id':rid,'status':row.value['status'],
            'analysis_status':result.get('status'),'failure_classification':result.get('failure_classification'),
            'model_call_count':len(result.get('model_calls') or [])})
        checkpoint('Assessment result and diagnostics saved')
        if row.value['status']=='REVIEW_REQUIRED':
            validate_proposal(result.get('proposal'),source,result.get('reads',[]))
            if (not result.get('runtime_evidence',{}).get('request_id')
                    or not result.get('model_calls')
                    or any(call.get('http_status')!=200 or not call.get('request_id')
                           for call in result['model_calls'])):
                raise ValueError('Canary lacks real runtime/model evidence')
            report['business_canary']['status']='PASS'
            break
        calls=result.get('model_calls') or []
        retryable=(canary_number<canary_limit
            and row.value['status']=='NEEDS_INPUT'
            and result.get('status')=='NEEDS_INPUT'
            and result.get('failure_classification')=='MODEL_OUTPUT_CONTRACT'
            and bool(calls)
            and all(call.get('http_status')==200 and call.get('request_id') for call in calls))
        if not retryable:
            raise ValueError('Business assessment incomplete: '+json.dumps(row.value.get('diagnostics') or row.value.get('error')))
        checkpoint('First synthetic assessment safely rejected; starting one bounded fresh canary')
    # Cold-start the actual API package without forging an authenticated human.
    cold=lam.invoke(FunctionName=resources['ApiFunction'],InvocationType='RequestResponse',Payload=b'{}');stream=cold['Payload']
    try:api_result=json.loads(stream.read())
    finally:stream.close()
    if cold.get('FunctionError') or api_result.get('statusCode')!=401:raise ValueError('Packaged API did not reject unauthenticated input')
    report['api_package_unauthenticated_check']={'status':'PASS','http_status':401}
    assets=root/'services/workbench/assets';manifest=json.loads((assets/'manifest.json').read_text())
    if set(manifest)!={'index.html','app.js','app.css'}:raise ValueError('Unexpected compiled asset set')
    for name,digest in manifest.items():
        if hashlib.sha256((assets/name).read_bytes()).hexdigest()!=digest:raise ValueError('Compiled asset differs: '+name)
    digest=sha256_json(manifest);config={'client_id':original['ClientId'],'auth_origin':original['AuthOrigin'],'api_origin':original['ApiUrl'],'redirect_uri':original['WorkspaceUrl']}
    files={**{n:(assets/n).read_bytes() for n in manifest},'config.json':encode_evidence(config)}
    mime={'index.html':'text/html; charset=utf-8','app.js':'text/javascript; charset=utf-8','app.css':'text/css; charset=utf-8','config.json':'application/json'}
    # Stage and read back every file BEFORE changing CloudFront's versioned origin path.
    for name,raw in files.items():upload(original['SiteBucket'],'ui/'+digest+'/'+name,raw,mime[name],CacheControl='no-store' if name=='config.json' else 'no-cache')
    updated=root/'dist/workbench-business.json';updated.write_text(json.dumps(updated_workbench_template(root),indent=2))
    wp={p['ParameterKey']:p['ParameterValue'] for p in workspace['Parameters']};wp['UiDigest']=digest
    checkpoint('Switching the existing workspace to the verified business UI')
    current=deploy(updated,WORKBENCH_STACK,wp)
    if current!=original:raise ValueError('Workspace sign-in or service bindings changed')
    report['resources']=current;report['ui_digest']=digest;report['delivery_checks']={}
    for name,raw in files.items():
        for attempt in range(10):
            try:status,actual=fetch(current['WorkspaceUrl']+name)
            except Exception:status,actual=0,b''
            if status==200 and actual==raw:break
            if attempt==9:raise ValueError('Delivered workspace asset differs: '+name)
            sleep(5)
        report['delivery_checks'][name]={'http_status':status,'sha256':hashlib.sha256(actual).hexdigest()}
    for path in ['/review','/business/objects']:
        status,_=fetch(current['ApiUrl']+path)
        if status!=401:raise ValueError('Unauthenticated API request was not rejected: '+path)
        report['delivery_checks'][path]={'http_status':status}
    origin=current['WorkspaceUrl'].rstrip('/')
    status,headers=browser_preflight(current['ApiUrl']+'/business/objects',origin)
    allowed_headers={x.strip().lower() for x in headers.get('access-control-allow-headers','').split(',')}
    allowed_methods={x.strip().upper() for x in headers.get('access-control-allow-methods','').split(',')}
    # ExposeHeaders governs actual responses, not preflight admission. Read the
    # deployed configuration separately; browser acceptance remains a later gate.
    cors=session.client('apigatewayv2').get_api(ApiId=current['ApiId']).get('CorsConfiguration',{})
    exposed_headers=validate_cors_exposure(cors,origin)
    if status not in (200,204) or headers.get('access-control-allow-origin')!=origin or not {'GET','POST'}.issubset(allowed_methods) or not {'authorization','content-type'}.issubset(allowed_headers):
        raise ValueError('Browser CORS preflight is not usable: '+json.dumps({'status':status,'headers':headers}))
    report['delivery_checks']['browser_preflight']={'status':'PASS','http_status':status,'allow_origin':origin,'allow_methods':sorted(allowed_methods),'allow_headers':sorted(allowed_headers),'configured_expose_headers':sorted(exposed_headers),'actual_browser_header_access':'NOT_RUN'}
    report.update(result='PASS',deployment='PASS',business_assessment_canary='PASS',human_workflow='NOT_RUN',approval_recorded=False,decision_publication='NOT_RUN',runtime_policy_publication='NOT_RUN',gate_b='UI_LOGIN_AND_REVIEW_PENDING',gate_c='NOT_RUN')


def validate_cors_exposure(cors,origin):
    exposed={x.lower() for x in cors.get('ExposeHeaders',[])}
    if (cors.get('AllowOrigins') != [origin] or exposed != {'x-request-id'}
            or not {'GET','POST','OPTIONS'}.issubset(set(cors.get('AllowMethods',[])))
            or not {'authorization','content-type'}.issubset({x.lower() for x in cors.get('AllowHeaders',[])})):
        raise ValueError('Deployed API CORS configuration differs; response correlation is not confirmed')
    return exposed


def verify_protected_baseline(session,report,*,root=ROOT):
    """Finalize protected-state evidence for standalone AND composed deployments."""
    report['state_unchanged']=None
    if 'baseline_before' not in report:
        report.update(result='FAIL',state_error='Protected baseline before-state was not recorded')
        return
    try:
        binding=json.loads((root/'infra/environments/development.json').read_text())
        after=observe_baseline(session,binding,FixtureBundle.load(root/'fixtures/decision_cases.json'))
        before=report['baseline_before'];report['baseline_after']=after
        report['state_unchanged']=(before['stable']==after['stable'] and before['policies']==after['policies']
                                   and stable_ledger(before['ledger'])==stable_ledger(after['ledger']))
        if not report['state_unchanged']:
            report.update(result='FAIL',state_error='Protected runtime baseline changed')
    except Exception as exc:
        report.update(result='FAIL',state_unchanged=None,state_error=safe_error(exc))


def assessment_diagnostics(report):
    """Operator-safe summary; raw proposals and evidence remain in the private report."""
    canary=report.get('business_canary') or {}
    analysis=canary.get('analysis') or {}
    attempts=analysis.get('attempts') or []
    return {'run_id':canary.get('run_id'), 'job_status':(canary.get('job') or {}).get('status'),
            'analysis_status':analysis.get('status'), 'attempt_count':len(attempts),
            'failure_classification':analysis.get('failure_classification'),
            'analysis_contract_version':analysis.get('analysis_contract_version'),
            'validation_errors':[a.get('validation_errors',[]) for a in attempts],
            'error_type':(analysis.get('error') or {}).get('type'),
            'full_diagnostics':'business_canary.analysis in the saved report'}


def run_worker(session,env,*,root=ROOT,executor=execute):
    report={'schema_version':'1.2','baseline_id':'AD-BASELINE-1.2','scope':SCOPE,'result':'FAIL','build_id':env.get('CODEBUILD_BUILD_ID'),'source_sha256':env.get('AD_SOURCE_SHA256'),'started_at':observed_at(),'state_unchanged':None,'approval_recorded':False}
    try:executor(session,env,report,root=root)
    except Exception as exc:
        report.update(result='FAIL',error=safe_error(exc))
        if report.get('deploying_stack'):
            try:
                events=session.client('cloudformation').describe_stack_events(StackName=report['deploying_stack'])['StackEvents']
                report['stack_failures']=[{k:e.get(k) for k in ('Timestamp','LogicalResourceId','ResourceType','ResourceStatus','ResourceStatusReason')} for e in events if 'FAILED' in e.get('ResourceStatus','')][:12]
            except Exception as diagnostic:report['stack_diagnostics_error']=safe_error(diagnostic)
    finally:
        verify_protected_baseline(session,report,root=root)
    report['completed_at']=observed_at()
    try:save_evidence(session,env,encode_evidence(report),root/'evidence/aws/business-result.json',env['AD_REPORT_KEY'])
    except Exception as exc:print('Final report save failed: '+str(exc));return 1
    print(encode_evidence({k:report.get(k) for k in ('result','phase','business_assessment_canary','human_workflow','state_unchanged','error','stack_failures')}).decode(),flush=True)
    return 0 if report['result']=='PASS' else 1

if __name__=='__main__':
    import boto3
    from botocore.config import Config
    session=boto3.Session(region_name=REGION);original=session.client
    session.client=lambda service,**kw:original(service,config=Config(connect_timeout=10,read_timeout=60,retries={'total_max_attempts':2}),**kw)
    raise SystemExit(run_worker(session,os.environ))
