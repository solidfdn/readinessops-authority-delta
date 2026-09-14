"""Pinned SDK validation and authorization topology; no live AWS claim."""
import io,json,unittest,copy,hashlib
from pathlib import Path
from botocore.stub import Stubber,ANY
from botocore.response import StreamingBody
import boto3
from authority_delta.business.storage import DynamoStore,S3Blobs,Conflict,encode
from authority_delta.business.jobs import RuntimeInvoker
from deploy_business import updated_workbench_template,canary_input,run_worker
from build_business_template import build
ROOT=Path(__file__).resolve().parents[1]
class AwsContracts(unittest.TestCase):
 def client(self,name):return boto3.client(name,region_name='ap-northeast-1',aws_access_key_id='LOCAL',aws_secret_access_key='LOCAL_TEST_ONLY')
 def test_ddb_versioned_transaction_and_conditional_conflict_against_sdk(self):
  client=self.client('dynamodb');store=DynamoStore(client,{'app':'AppTable','jobs':'JobsTable'})
  with Stubber(client) as stub:
   item={'pk':{'S':'object'},'sk':{'S':'HEAD'},'version':{'N':'2'},'data':{'S':'{"value":1}'}}
   expected={'TransactItems':[{'Put':{'TableName':'AppTable','ConditionExpression':'#v = :v','ExpressionAttributeNames':{'#v':'version'},'ExpressionAttributeValues':{':v':{'N':'1'}},'Item':item}}]}
   stub.add_response('transact_write_items',{},expected);store.transact([('app','object','HEAD',{'value':1},1)])
   stub.add_client_error('transact_write_items',service_error_code='TransactionCanceledException',service_message='Conflict',modeled_fields={'CancellationReasons':[{'Code':'ConditionalCheckFailed'}]},expected_params=expected)
   with self.assertRaises(Conflict):store.transact([('app','object','HEAD',{'value':1},1)])
   stub.add_response('get_item',{'Item':item},{'TableName':'AppTable','Key':{'pk':{'S':'object'},'sk':{'S':'HEAD'}},'ConsistentRead':True});self.assertEqual(store.get('app','object','HEAD').version,2);stub.assert_no_pending_responses()
 def test_s3_requires_pinned_readback_and_real_byte_hash(self):
  client=self.client('s3');blobs=S3Blobs(client,'test-business');raw=b'"receipt"'
  with Stubber(client) as stub:
   stub.add_response('put_object',{'VersionId':'v-one'},{'Bucket':'test-business','Key':'business/receipts/test','Body':raw,'ContentType':'application/json'})
   stub.add_response('get_object',{'Body':StreamingBody(io.BytesIO(raw),len(raw)),'VersionId':'v-one'},{'Bucket':'test-business','Key':'business/receipts/test','VersionId':'v-one'})
   ref=blobs.put('business/receipts/test',raw);self.assertEqual(ref['sha256'],hashlib.sha256(raw).hexdigest());self.assertEqual(ref['version_id'],'v-one');stub.assert_no_pending_responses()
 def test_runtime_optional_target_version_sdk_retry_and_endpoint_movement(self):
  control=self.client('bedrock-agentcore-control');runtime=self.client('bedrock-agentcore')
  arn='arn:aws:bedrock-agentcore:ap-northeast-1:538522204923:runtime/authority_delta_business-Abcdefg123'
  b={'id':'authority_delta_business-Abcdefg123','arn':arn,'version':'1','endpoint':'fixed_business','endpoint_arn':arn+'/runtime-endpoint/fixed_business','account':'538522204923','role_name':'authority-delta-business-model'}
  ep={'createdAt':'2026-09-09T00:00:00Z','lastUpdatedAt':'2026-09-09T00:00:01Z','liveVersion':'1','agentRuntimeEndpointArn':b['endpoint_arn'],'agentRuntimeArn':arn,'status':'READY','name':'fixed_business','id':'fixed_business','ResponseMetadata':{'HTTPStatusCode':200,'RequestId':'endpoint-request'}}
  payload={'input_hash':'0'*64,'status':'VALIDATED','model_id':'apac.amazon.nova-pro-v1:0','identity':{'account':b['account'],'arn':'arn:aws:sts::538522204923:assumed-role/authority-delta-business-model/test','request_id':'sts-request'}};raw=encode(payload)
  args={'agentRuntimeArn':arn,'qualifier':'fixed_business','runtimeSessionId':ANY,'contentType':'application/json','accept':'application/json','payload':encode({'x':1})}
  with Stubber(control) as cs,Stubber(runtime) as rs:
   cs.add_response('get_agent_runtime_endpoint',ep,{'agentRuntimeId':b['id'],'endpointName':'fixed_business'});cs.add_response('get_agent_runtime_endpoint',ep,{'agentRuntimeId':b['id'],'endpointName':'fixed_business'})
   rs.add_client_error('invoke_agent_runtime',service_error_code='RetryableConflictException',service_message='Starting',expected_params=args)
   rs.add_response('invoke_agent_runtime',{'statusCode':200,'contentType':'application/json','response':StreamingBody(io.BytesIO(raw),len(raw)),'ResponseMetadata':{'HTTPStatusCode':200,'RequestId':'runtime-request'}},args)
   rs.add_response('stop_runtime_session',{}, {'agentRuntimeArn':arn,'qualifier':'fixed_business','runtimeSessionId':ANY})
   result=RuntimeInvoker(control,runtime,b,sleep=lambda _:None)({'x':1});self.assertEqual(result['runtime_evidence']['request_id'],'runtime-request');cs.assert_no_pending_responses();rs.assert_no_pending_responses()
  with Stubber(control) as cs:
   cs.add_response('get_agent_runtime_endpoint',dict(ep,targetVersion='2'),{'agentRuntimeId':b['id'],'endpointName':'fixed_business'})
   with self.assertRaises(ValueError):RuntimeInvoker(control,runtime,b).endpoint()
 def test_template_keeps_identity_and_separates_worker_authority(self):
  old=json.loads((ROOT/'infra/workbench/template.json').read_text());new=updated_workbench_template();self.assertEqual(set(old['Resources']),set(new['Resources']))
  for key in old['Resources']:
   if key not in ('ReviewResource','ReviewerClient','Api'):self.assertEqual(old['Resources'][key],new['Resources'][key])
  self.assertEqual(new['Resources']['ReviewerClient']['Properties']['AllowedOAuthScopes'],['openid','authority-delta/read','authority-delta/write','authority-delta/approve','authority-delta/publish'])
  self.assertEqual(new['Resources']['Api']['Properties']['CorsConfiguration']['ExposeHeaders'],['x-request-id'])
  t=build();self.assertLess(len(json.dumps(t).encode()),51200)
  options=t['Resources']['BusinessOptionsRoute']['Properties']
  self.assertEqual(options['RouteKey'],'OPTIONS /business/{proxy+}')
  self.assertEqual(options['AuthorizationType'],'NONE')
  for role in ['AnalysisExecutionRole','WorkerRole','DispatcherRole']:
   policies=json.dumps(t['Resources'][role]['Properties']['Policies']);self.assertNotIn('AppTable',policies);self.assertNotIn('CreatePolicy',policies);self.assertNotIn('Gateway',policies)
  self.assertIn('JobsTable',json.dumps(t['Resources']['WorkerRole']));self.assertNotIn('cognito-idp',json.dumps(t['Resources']['WorkerRole']))
  # Reject CloudFormation cycles including implicit Ref/GetAtt/Fn::Sub references.
  names=set(t['Resources']);edges={name:set() for name in names}
  import re
  def refs(v):
   found=set()
   if isinstance(v,dict):
    if 'Ref' in v:found.add(v['Ref'])
    if 'Fn::GetAtt' in v:found.add(v['Fn::GetAtt'][0])
    if 'Fn::Sub' in v and isinstance(v['Fn::Sub'],str):found.update(x.split('.')[0] for x in re.findall(r'\$\{([^}]+)\}',v['Fn::Sub']))
    for x in v.values():found|=refs(x)
   if isinstance(v,list):
    for x in v:found|=refs(x)
   return found
  for name,r in t['Resources'].items():
   dep=r.get('DependsOn',[]);dep=[dep] if isinstance(dep,str) else dep;edges[name]=(refs(r)|set(dep))&names
  seen=set()
  def visit(n,path):
   self.assertNotIn(n,path,'CloudFormation dependency cycle')
   if n in seen:return
   for d in edges[n]:visit(d,path|{n})
   seen.add(n)
  for n in names:visit(n,set())
 def test_api_refs_and_schema_are_resolvable(self):
  from build_business_contracts import build as build_api
  doc=build_api()
  def walk(v):
   if isinstance(v,dict):
    if '$ref' in v:
     target=doc
     for component in v['$ref'].split('/')[1:]:target=target[component]
    for x in v.values():walk(x)
   elif isinstance(v,list):
    for x in v:walk(x)
  walk(doc)
  for path,value in doc['paths'].items():
   if 'post' in value:self.assertIn('request_id',doc['components']['schemas'][value['post']['operationId']+'Request']['properties'])
if __name__=='__main__':unittest.main()
