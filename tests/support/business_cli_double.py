#!/usr/bin/env python3
"""Offline operator scenario backend. No live AWS, no human decision evidence."""
import hashlib,json,os,re,sys,zipfile
from pathlib import Path
args=sys.argv[1:];state=Path(os.environ['AD_TEST_STATE']);mode=os.environ['AD_TEST_SCENARIO'];binding=json.loads((Path.cwd()/'infra/environments/development.json').read_text());action=args[:2]
BUILD='authority-delta-deploy:local-business';SCOPE='READINESSOPS_BUSINESS_WORKFLOW_DEPLOYMENT_NO_HUMAN_APPROVAL'
workspace={'WorkspaceUrl':'https://d3rn3hqm0ax5ux.cloudfront.net/','UserPoolId':'ap-northeast-1_local','ReviewerUsername':'okada','ApiUrl':'https://local.execute-api.ap-northeast-1.amazonaws.com','ClientId':'localclient'}
def flag(x):return args[args.index(x)+1]
def emit(value):print(json.dumps(value));raise SystemExit(0)
def fail(value):print(value,file=sys.stderr);raise SystemExit(1)
assert flag('--region')==binding['region'];assert flag('--output')=='json'
with (state/'calls.jsonl').open('a') as f:f.write(json.dumps(action)+'\n')
if action==['sts','get-caller-identity']:emit({'Account':'111122223333' if mode=='WRONG_ACCOUNT' else binding['account']})
if action==['cloudformation','describe-stacks']:
 name=flag('--stack-name');out=workspace if name=='authority-delta-workbench' else binding['resources'] if name==binding['application_stack'] else {'ArtifactBucketName':binding['artifact_bucket'],'BuildProjectName':binding['project']}
 emit({'Stacks':[{'StackStatus':'UPDATE_COMPLETE','Outputs':[{'OutputKey':k,'OutputValue':v} for k,v in out.items()]}]})
if action==['cognito-idp','admin-get-user']:emit({'UserStatus':'FORCE_CHANGE_PASSWORD' if mode=='SIGN_IN_UNCONFIRMED' else 'CONFIRMED'})
if action==['codebuild','list-builds-for-project']:emit({'ids':[BUILD] if (state/'build.json').exists() else ['authority-delta-deploy:active'] if mode=='ACTIVE_BUILD' else []})
if action==['codebuild','batch-get-builds']:
 build_id=flag('--ids');variables=json.loads((state/'build.json').read_text()) if (state/'build.json').exists() else {}
 emit({'builds':[{'id':build_id,'buildStatus':'IN_PROGRESS' if build_id.endswith(':active') else 'FAILED' if mode=='FAIL' else 'SUCCEEDED','currentPhase':'COMPLETED','environment':{'environmentVariables':[{'name':k,'value':v} for k,v in variables.items()]},'logs':{'groupName':'/aws/codebuild/local','streamName':'local'}}]})
if action==['logs','get-log-events']:emit({'events':[{'message':'[ReadinessOps] Local diagnostic retained'}]})
if action==['s3api','put-object']:
 key=flag('--key');body=Path(flag('--body')).read_bytes()
 if key.startswith('source/'):
  digest=hashlib.sha256(body).hexdigest();assert key=='source/'+digest+'.zip';assert flag('--metadata')=='sha256='+digest
  with zipfile.ZipFile(flag('--body')) as z:
   names=set(z.namelist());assert {'buildspec.business.yml','scripts/deploy_business.py','scripts/build_business_artifacts.py','infra/business/template.json','services/business/handler.py','services/business/requests.schema.json','services/business_analysis/agent.py','packages/contracts/business.openapi.json','vendor/business/pypdf-6.10.0.zip','services/workbench/assets/app.js'}<=names
   assert not any(n.startswith(('tests/','evidence/','.git/')) for n in names)
   assert b'BusinessContext' not in z.read('services/business_analysis/agent.py') # No hidden test answer dependency.
   assert b'The work, and the question.' in z.read('services/workbench/assets/app.js')
  (state/'source.json').write_text(json.dumps({'hash':digest,'key':key}));emit({'VersionId':'local-source-v1'})
 assert key=='business-launch/latest.json' or key.endswith('/business-launch.json');json.loads(body);(state/'remote-launch.json').write_bytes(body);emit({'VersionId':'local-launch-v1'})
if action==['codebuild','start-build']:
 assert flag('--buildspec-override')=='buildspec.business.yml';assert (state/'remote-launch.json').exists(),'Intent must be durable before start'
 source=json.loads((state/'source.json').read_text());assert flag('--source-location-override')==binding['artifact_bucket']+'/'+source['key'];assert flag('--source-version')=='local-source-v1'
 variables={v['name']:v['value'] for v in json.loads(flag('--environment-variables-override'))};assert variables['AD_SOURCE_SHA256']==source['hash'];assert re.fullmatch(r'evidence/[0-9a-f]{32}/business-result\.json',variables['AD_REPORT_KEY']);(state/'build.json').write_text(json.dumps(variables))
 if mode=='START_RESPONSE_LOST':fail('Read timeout after accepted build')
 emit({'build':{'id':BUILD}})
if action==['s3api','get-object']:
 key=flag('--key');target=Path(args[args.index('--key')+2]);target.parent.mkdir(parents=True,exist_ok=True)
 if key=='business-launch/latest.json':
  if not (state/'remote-launch.json').exists():fail('NoSuchKey')
  target.write_bytes((state/'remote-launch.json').read_bytes());emit({'VersionId':'local-launch-v1'})
 variables=json.loads((state/'build.json').read_text());partial=key.endswith('-latest.json')
 if mode=='FINAL_MISSING' and not partial:fail('NoSuchKey')
 result={'schema_version':'1.2','scope':SCOPE,'build_id':BUILD,'source_sha256':variables['AD_SOURCE_SHA256'],'result':'FAIL' if mode=='FAIL' else 'PASS','state_unchanged':mode!='STATE_CHANGED','resources':workspace,'business_assessment_canary':'PASS','human_workflow':'NOT_RUN','approval_recorded':False,'_local_test_only':True}
 if mode=='FAIL':result['error']={'type':'ValueError','message':'Pinned runtime code differs'}
 if mode=='REPORT_MISMATCH':result['source_sha256']='f'*64
 target.write_text(json.dumps(result));emit({'VersionId':'local-report-v1'})
fail('Unexpected local operator call '+str(action))
