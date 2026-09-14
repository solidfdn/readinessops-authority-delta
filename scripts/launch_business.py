#!/usr/bin/env python3
"""Launch once; recover source/build/report across CloudShell disconnections."""
import argparse,json,os,re,shlex,subprocess,sys,tempfile,time,uuid
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'scripts'))
from launch_deployment import AwsCli,DeploymentError,source_archive,stack_outputs,show_failure_details
from launch_gate_b import write_record
SCOPE='READINESSOPS_BUSINESS_WORKFLOW_DEPLOYMENT_NO_HUMAN_APPROVAL'
BUNDLE_VERSION='20260911-business-v4-sts-connector'
WORKSPACE_URL='https://d3rn3hqm0ax5ux.cloudfront.net/'
LATEST_KEY='business-launch/latest.json'

def validate(record,binding):
    for key,expected in [('scope',SCOPE),('account',binding['account']),('region',binding['region']),('bucket',binding['artifact_bucket']),('project',binding['project'])]:
        if record.get(key)!=expected:raise DeploymentError('Saved business launch binding differs: '+key)
    if not re.fullmatch(r'evidence/[0-9a-f]{32}/business-result\.json',record.get('report_key','')) or not re.fullmatch(r'[0-9a-f]{64}',record.get('source_sha256','')):raise DeploymentError('Invalid saved report/source binding')
    if not record.get('source_version') or record['source_version']=='null':raise DeploymentError('Saved source version missing')
    if record.get('build_id') and not re.fullmatch(re.escape(binding['project'])+r':[A-Za-z0-9_-]+',record['build_id']):raise DeploymentError('Invalid saved build identifier')

def save(cli,path,record):
    write_record(path,record)
    cli.run('s3api','put-object','--bucket',record['bucket'],'--key',LATEST_KEY,'--body',str(path))
    cli.run('s3api','put-object','--bucket',record['bucket'],'--key',record['report_key'].replace('business-result.json','business-launch.json'),'--body',str(path))

def recent(cli,project):
    ids=cli.run('codebuild','list-builds-for-project','--project-name',project,'--sort-order','DESCENDING','--max-items','50').get('ids',[])
    return cli.run('codebuild','batch-get-builds','--ids',*ids).get('builds',[]) if ids else []

def reconcile(cli,record,path):
    matches=[]
    for build in recent(cli,record['project']):
        variables={v['name']:v['value'] for v in build.get('environment',{}).get('environmentVariables',[])}
        if variables.get('AD_REPORT_KEY')==record['report_key'] and variables.get('AD_SOURCE_SHA256')==record['source_sha256']:matches.append(build)
    if len(matches)!=1:raise DeploymentError('Launch result is not yet confirmed. Keep the saved record and rerun this same operator to collect it; no duplicate build was started.')
    record['build_id']=matches[0]['id'];save(cli,path,record)

def collect(cli,record,path,delay=time.sleep):
    if not record.get('build_id'):reconcile(cli,record,path)
    print('Build ID: '+record['build_id'],flush=True)
    print('Resume this build: '+shlex.join(['python3',str(ROOT/'scripts/launch_business.py'),'--resume',str(path)]),flush=True)
    print('Rerunning the same downloaded operator also resumes this build.',flush=True)
    last=None;seen=set()
    for poll in range(210):
        builds=cli.run('codebuild','batch-get-builds','--ids',record['build_id']).get('builds',[])
        if len(builds)!=1 or builds[0].get('id')!=record['build_id']:raise DeploymentError('Build identity is not confirmed; resume the same record')
        build=builds[0];state=(build.get('currentPhase'),build.get('buildStatus'))
        if state!=last:print('CodeBuild: '+str(state[0])+' / '+str(state[1]),flush=True);last=state
        if poll%3==0 and build.get('logs',{}).get('streamName'):
            try:
                logs=cli.run('logs','get-log-events','--log-group-name',build['logs']['groupName'],'--log-stream-name',build['logs']['streamName'],'--limit','20')
                for e in logs.get('events',[]):
                    msg=e.get('message','').strip()
                    if msg.startswith('[ReadinessOps]') and msg not in seen:print(msg,flush=True);seen.add(msg)
            except DeploymentError:pass
        if state[1]!='IN_PROGRESS':break
        delay(10)
    else:raise DeploymentError('Collection timed out. The existing build is retained; rerun the same operator.')
    target=path.parent/'business-result.json'
    try:downloaded=cli.run('s3api','get-object','--bucket',record['bucket'],'--key',record['report_key'],str(target))
    except DeploymentError:
        show_failure_details(cli,build)
        try:
            checkpoint=target.with_name('business-latest.json');cli.run('s3api','get-object','--bucket',record['bucket'],'--key',record['report_key'].removesuffix('.json')+'-latest.json',str(checkpoint))
            print('Last saved checkpoint: '+str(checkpoint),flush=True)
        except DeploymentError:pass
        raise DeploymentError('No final business report was recovered. The build and saved checkpoints remain; do not redeploy.')
    result=json.loads(target.read_text())
    if any(result.get(k)!=record[k] for k in ('scope','build_id','source_sha256')) or not downloaded.get('VersionId') or downloaded['VersionId']=='null':raise DeploymentError('Downloaded report does not match this build/source')
    record.update(report_version_id=downloaded['VersionId'],build_status=build.get('buildStatus'),collection_result='COLLECTED');save(cli,path,record)
    print('READINESSOPS_BUSINESS_RESULT',flush=True)
    summary={k:v for k,v in result.items() if k not in ('baseline_before','baseline_after','runtime_control','analysis_model','business_canary')}
    summary['business_canary']={k:v for k,v in result.get('business_canary',{}).items() if k!='analysis'}
    if result.get('result')!='PASS':summary['canary_diagnostics']=result.get('business_canary',{}).get('analysis',{}).get('error')
    print(json.dumps(summary,ensure_ascii=False,indent=2),flush=True)
    print('Full report: '+str(target),flush=True)
    print('Evidence: s3://'+record['bucket']+'/'+record['report_key']+' (version '+downloaded['VersionId']+')',flush=True)
    if build.get('buildStatus')!='SUCCEEDED' or result.get('result')!='PASS' or result.get('state_unchanged') is not True:
        show_failure_details(cli,build);raise DeploymentError('Business deployment is incomplete. Share this result; do not repeat successful gates.')
    current=stack_outputs(cli,'authority-delta-workbench')
    if current!=record['workspace'] or current!=result.get('resources'):raise DeploymentError('Existing workspace bindings changed')
    print('WORKSPACE_URL: '+current['WorkspaceUrl'],flush=True)
    print('SIGN_IN_USERNAME: '+current['ReviewerUsername'],flush=True)
    print('Sign in with the existing password. New business assessment, review and explicit publication are ready for your live operation.',flush=True)
    return 0

def launch(cli,resume=None,*,delay=time.sleep):
    binding=json.loads((ROOT/'infra/environments/development.json').read_text())
    if cli.run('sts','get-caller-identity').get('Account')!=binding['account']:raise DeploymentError('Wrong account. No operation started.')
    path=Path(resume).resolve() if resume else ROOT.parent/'business-latest-launch.json'
    if resume:
        record=json.loads(path.read_text());validate(record,binding);return collect(cli,record,path,delay)
    # Remote recovery makes the operator independent of an earlier temporary directory.
    if not path.exists():
        try:cli.run('s3api','get-object','--bucket',binding['artifact_bucket'],'--key',LATEST_KEY,str(path))
        except DeploymentError as exc:
            if not any(c in str(exc) for c in ('NoSuchKey','NotFound','(404)')):raise
            path.unlink(missing_ok=True)
    previous=None
    if path.exists():
        record=json.loads(path.read_text());validate(record,binding)
        if record.get('bundle_version')==BUNDLE_VERSION:return collect(cli,record,path,delay)
        previous=record
    workspace=stack_outputs(cli,'authority-delta-workbench')
    if workspace.get('WorkspaceUrl')!=WORKSPACE_URL or workspace.get('ReviewerUsername')!='okada':raise DeploymentError('Existing workspace identity differs')
    user=cli.run('cognito-idp','admin-get-user','--user-pool-id',workspace['UserPoolId'],'--username','okada')
    if user.get('UserStatus')!='CONFIRMED':raise DeploymentError('Existing sign-in is not confirmed. No password changes made.')
    bootstrap=stack_outputs(cli,binding['bootstrap_stack']);baseline=stack_outputs(cli,binding['application_stack'])
    if bootstrap['ArtifactBucketName']!=binding['artifact_bucket'] or bootstrap['BuildProjectName']!=binding['project'] or any(baseline.get(k)!=v for k,v in binding['resources'].items()):raise DeploymentError('Deployment/baseline bindings changed')
    if any(b.get('buildStatus')=='IN_PROGRESS' for b in recent(cli,binding['project'])):raise DeploymentError('Another build is active. No duplicate operation started.')
    run_id=uuid.uuid4().hex;bucket=binding['artifact_bucket'];project=binding['project']
    print('[ReadinessOps] Uploading fixed source; existing sign-in and AWS runtime proof retained',flush=True)
    with tempfile.TemporaryDirectory(prefix='readinessops-source-') as tmp:
        archive=Path(tmp)/'source.zip';digest=source_archive(archive);key='source/'+digest+'.zip'
        uploaded=cli.run('s3api','put-object','--bucket',bucket,'--key',key,'--body',str(archive),'--metadata','sha256='+digest)
    record={'schema_version':'1.2','scope':SCOPE,'bundle_version':BUNDLE_VERSION,'account':binding['account'],'region':binding['region'],'project':project,'bucket':bucket,'source_sha256':digest,'source_key':key,'source_version':uploaded.get('VersionId'),'run_id':run_id,'report_key':'evidence/'+run_id+'/business-result.json','build_id':None,'workspace':workspace}
    validate(record,binding);save(cli,path,record)
    print('Saved recovery record: '+str(path),flush=True)
    variables=[{'name':'AD_REPORT_KEY','value':record['report_key'],'type':'PLAINTEXT'},{'name':'AD_SOURCE_SHA256','value':digest,'type':'PLAINTEXT'}]
    if previous and previous.get('build_id')=='authority-delta-deploy:02244729-c866-4424-885b-6fe8d0209dd6' and previous.get('source_sha256')=='705c6651fbe5739cc046644a22bf6dbf4292d6a60bb5d7e9672bb5b2f1e01fd8':
        variables.append({'name':'AD_RECOVER_BUSINESS_CANARY','value':'1','type':'PLAINTEXT'})
    try:
        started=cli.run('codebuild','start-build','--project-name',project,'--source-location-override',bucket+'/'+key,'--source-version',record['source_version'],'--buildspec-override','buildspec.business.yml','--timeout-in-minutes-override','25','--environment-variables-override',json.dumps(variables),'--idempotency-token',run_id)
        record['build_id']=started['build']['id'];save(cli,path,record)
    except (DeploymentError,KeyError):reconcile(cli,record,path)
    return collect(cli,record,path,delay)

def main():
    parser=argparse.ArgumentParser();parser.add_argument('--resume');args=parser.parse_args()
    try:return launch(AwsCli(),args.resume)
    except (DeploymentError,OSError,ValueError,KeyError,TypeError,KeyboardInterrupt,subprocess.TimeoutExpired) as exc:
        print('ERROR: '+str(exc),flush=True);return 1
if __name__=='__main__':raise SystemExit(main())
