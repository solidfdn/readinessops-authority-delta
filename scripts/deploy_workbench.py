"""Deploy a read-only authenticated review from existing immutable evidence."""
import hashlib, io, json, os, subprocess, sys, time, zipfile
from pathlib import Path
from urllib.request import urlopen, Request
from urllib.error import HTTPError, URLError
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'scripts'), str(ROOT/'src')]
from deploy_baseline import ACCOUNT, REGION, require_worker_identity
from gate_a_state import read_json, observe_baseline, stable_ledger
from verify_aws import observed_at, save_evidence, safe_error
from authority_delta.registry import FixtureBundle
from authority_delta.evidence_json import encode_evidence
from authority_delta.canonical import sha256_json
from authority_delta.workbench import review_document

SCOPE='AUTHENTICATED_REVIEW_WORKBENCH_NO_APPROVAL_OR_PUBLICATION'
PRIOR={'bucket':'authority-delta-bootstrap-artifactbucket-6ebtk8mvvqyp',
    'key':'evidence/b9074918a5114c34a19f723efb1a9383/gate-b-result.json',
    'version_id':'k2EAn2Uy7jv5AmISBKnfVQPgOluM560i'}
PRIOR_BUILD='authority-delta-deploy:d546c96c-43dc-4e7b-beaf-1bdbae50a474'
PRIOR_SOURCE='f7ca7cef62f9455dbea675ea4f4fbb743c7d2b09e67655bd8e49de4afd17fe64'
STACK='authority-delta-workbench'


def fetch_public(url):
    try:
        with urlopen(Request(url,headers={'User-Agent':'AuthorityDelta-Deployment-Check'}),timeout=20) as response:
            return response.status, response.read(2_000_001)
    except HTTPError as exc:
        return exc.code, exc.read(1024)


def execute(session, env, report, *, root=ROOT, run=subprocess.run, fetch=fetch_public, sleep=time.sleep):
    binding=json.loads((root/'infra/environments/development.json').read_text())
    identity=session.client('sts').get_caller_identity();require_worker_identity(identity,env)
    if env['AD_ARTIFACT_BUCKET']!=binding['artifact_bucket']:raise ValueError('Unexpected artifact bucket')
    s3=session.client('s3');cfn=session.client('cloudformation')
    fixtures=FixtureBundle.load(root/'fixtures/decision_cases.json')
    report.update(account=ACCOUNT,region=REGION)
    print('[Workbench] Read the saved semantic proof',flush=True)
    prior,_=read_json(s3,**{'bucket':PRIOR['bucket'],'key':PRIOR['key'],'version_id':PRIOR['version_id']})
    if prior.get('build_id')!=PRIOR_BUILD or prior.get('source_sha256')!=PRIOR_SOURCE or prior.get('account')!=ACCOUNT or prior.get('region')!=REGION:
        raise ValueError('Saved proof identity differs from pinned successful build')
    before=observe_baseline(session,binding,fixtures);report['baseline_before']=before
    if before['stable']!=prior['baseline_after']['stable'] or before['policies']!=prior['baseline_after']['policies'] or stable_ledger(before['ledger'])!=stable_ledger(prior['baseline_after']['ledger']):
        raise ValueError('Protected baseline differs from saved proof')
    document=review_document(prior,fixtures,PRIOR)
    from jsonschema import Draft202012Validator
    Draft202012Validator(json.loads((root/'packages/contracts/readinessops.schema.json').read_text())).validate(document['workspace'])
    report['workspace']={'product':'ReadinessOps','edition':'AWS','schema_version':'1.1',
        'workspace_hash':document['workspace']['workspace_hash'],
        'objects':len(document['workspace']['objects']),'evidence_records':len(document['workspace']['evidence']),
        'findings':len(document['workspace']['findings']),'actions':len(document['workspace']['actions']),
        'capabilities':document['workspace']['capabilities']}
    report['prior_gate_b']=dict(PRIOR,build_id=PRIOR_BUILD,sha256=sha256_json(prior))
    assets=root/'services/workbench/assets'
    manifest=json.loads((assets/'manifest.json').read_text())
    if set(manifest)!={'index.html','app.js','app.css'}:raise ValueError('Unexpected frontend asset set')
    for name,digest in manifest.items():
        if hashlib.sha256((assets/name).read_bytes()).hexdigest()!=digest:raise ValueError('Frontend asset digest mismatch')
    ui_digest=sha256_json(manifest);report['ui_digest']=ui_digest
    def upload(key,body,content_type='application/octet-stream',bucket=PRIOR['bucket'],**extra):
        r=s3.put_object(Bucket=bucket,Key=key,Body=body,ContentType=content_type,**extra)
        if not r.get('VersionId') or r['VersionId']=='null':raise ValueError('Artifact has no immutable version')
        return r['VersionId']
    data_key='review/'+document['document_hash']+'.json'
    data_version=upload(data_key,encode_evidence(document),'application/json')
    code=io.BytesIO()
    with zipfile.ZipFile(code,'w',zipfile.ZIP_DEFLATED) as archive:
        archive.write(root/'services/workbench/handler.py','handler.py')
    code_bytes=code.getvalue();code_key='review-code/'+hashlib.sha256(code_bytes).hexdigest()+'.zip'
    code_version=upload(code_key,code_bytes)
    params={'ArtifactBucket':PRIOR['bucket'],'DataKey':data_key,'DataVersion':data_version,
        'CodeKey':code_key,'CodeVersion':code_version,'UiDigest':ui_digest}
    template=root/'infra/workbench/template.json'
    cfn.validate_template(TemplateBody=template.read_text())
    print('[Workbench] Deploy sign-in, protected review API and HTTPS screen',flush=True)
    run(['aws','cloudformation','deploy','--region',REGION,'--no-cli-pager','--template-file',str(template),
        '--stack-name',STACK,'--capabilities','CAPABILITY_NAMED_IAM','--no-fail-on-empty-changeset',
        '--parameter-overrides',*[k+'='+v for k,v in params.items()]],check=True,cwd=root)
    stack=cfn.describe_stacks(StackName=STACK)['Stacks'][0]
    if stack['StackStatus'] not in ('CREATE_COMPLETE','UPDATE_COMPLETE'):raise ValueError('Workbench stack is not ready')
    outputs={o['OutputKey']:o['OutputValue'] for o in stack['Outputs']};report['resources']=outputs
    config={'client_id':outputs['ClientId'],'auth_origin':outputs['AuthOrigin'],
        'api_origin':outputs['ApiUrl'],'redirect_uri':outputs['WorkspaceUrl']}
    for name in manifest:
        upload('ui/'+ui_digest+'/'+name,(assets/name).read_bytes(),
            {'index.html':'text/html; charset=utf-8','app.js':'text/javascript; charset=utf-8','app.css':'text/css; charset=utf-8'}[name],
            bucket=outputs['SiteBucket'],CacheControl='no-cache')
    config_bytes=encode_evidence(config)
    upload('ui/'+ui_digest+'/config.json',config_bytes,'application/json',bucket=outputs['SiteBucket'],CacheControl='no-store')
    print('[Workbench] Check delivered assets and unauthenticated access denial',flush=True)
    checks={}
    for name,wanted in {**{n:(assets/n).read_bytes() for n in manifest},'config.json':config_bytes}.items():
        for attempt in range(8):
            try:status,content=fetch(outputs['WorkspaceUrl']+name)
            except (TimeoutError,URLError):status,content=0,b''
            if status==200 and hashlib.sha256(content).digest()==hashlib.sha256(wanted).digest():break
            if attempt==7:raise ValueError('Delivered asset could not be verified: '+name)
            sleep(10)
        checks[name]={'http_status':status,'sha256':hashlib.sha256(content).hexdigest()}
    status,_=fetch(outputs['ApiUrl']+'/review')
    if status!=401:raise ValueError('Review API did not reject unauthenticated access')
    checks['unauthenticated_review']={'http_status':status}
    report['delivery_checks']=checks
    after=observe_baseline(session,binding,fixtures);report['baseline_after']=after
    unchanged=before['stable']==after['stable'] and before['policies']==after['policies'] and stable_ledger(before['ledger'])==stable_ledger(after['ledger'])
    if not unchanged:raise ValueError('Protected baseline changed')
    report.update(result='PASS',deployment='PASS',state_unchanged=True,review_document_hash=document['document_hash'],
        semantic_runtime_proof='PASS_REUSED',gate_b='UI_LOGIN_AND_REVIEW_PENDING',
        approval_recorded=False,publication='NOT_RUN',review_data={'bucket':PRIOR['bucket'],'key':data_key,'version_id':data_version})


def run_worker(session,env,*,root=ROOT,executor=execute):
    report={'schema_version':'1.0','baseline_id':'AD-BASELINE-1.0','scope':SCOPE,'result':'FAIL',
        'build_id':env.get('CODEBUILD_BUILD_ID'),'source_sha256':env.get('AD_SOURCE_SHA256'),'started_at':observed_at()}
    try:executor(session,env,report,root=root)
    except Exception as exc:report['error']=safe_error(exc)
    report['completed_at']=observed_at()
    try:save_evidence(session,env,encode_evidence(report),root/'evidence/aws/workbench-result.json',env['AD_REPORT_KEY'])
    except Exception as exc:print('Evidence could not be saved: '+str(exc));return 1
    print(encode_evidence({k:v for k,v in report.items() if k not in ('baseline_before','baseline_after')}).decode())
    return 0 if report['result']=='PASS' else 1


if __name__=='__main__':
    import boto3
    from botocore.config import Config
    session=boto3.Session(region_name=REGION); original=session.client
    session.client=lambda service,**kw:original(service,config=Config(connect_timeout=10,read_timeout=45,retries={'total_max_attempts':2}),**kw)
    raise SystemExit(run_worker(session,os.environ))
