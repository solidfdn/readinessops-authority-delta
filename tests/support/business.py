"""Local-only stores and scripted proposals. Never AWS or human approval evidence."""
import copy,hashlib,json,threading
from datetime import datetime,timezone,timedelta
from pathlib import Path
from authority_delta.business.storage import Row,Conflict
from authority_delta.business.contracts import PERSPECTIVES,snapshot_item_registry
from authority_delta.business.delegation import registration_with_hash
from authority_delta.decisions import Decision
from authority_delta.policy_plan import build_policy_plan
from authority_delta.registry import FixtureBundle
class Clock:
 def __init__(self):self.value=datetime(2026,9,9,tzinfo=timezone.utc)
 def __call__(self):return self.value.isoformat()
 def advance(self,seconds):self.value+=timedelta(seconds=seconds)
class MemoryStore:
 def __init__(self):self.rows={};self.lock=threading.RLock();self.fail_next=False
 def get(self,*key):
  with self.lock:return copy.deepcopy(self.rows.get(key))
 def query(self,table,pk,prefix='',limit=500):
  with self.lock:return [copy.deepcopy(r) for (t,p,s),r in sorted(self.rows.items()) if t==table and p==pk and s.startswith(prefix)]
 def transact(self,writes):
  with self.lock:
   if self.fail_next:self.fail_next=False;raise RuntimeError('Simulated transaction unavailable')
   if len({tuple(w[:3]) for w in writes})!=len(writes):raise ValueError('Duplicate transaction target')
   for table,pk,sk,value,expected in writes:
    old=self.rows.get((table,pk,sk))
    if (old.version if old else None)!=expected:raise Conflict('Concurrent version')
   for table,pk,sk,value,expected in writes:
    key=(table,pk,sk)
    if value is None:self.rows.pop(key,None)
    else:self.rows[key]=Row(copy.deepcopy(value),(expected or 0)+1)
class MemoryBlobs:
 def __init__(self):self.data={};self.fail_put=False;self.fail_read=False
 def put(self,key,raw,content_type='application/json'):
  if self.fail_put:raise RuntimeError('Simulated storage failure')
  version=str(len(self.data)+1);ref={'bucket':'local-test-only','key':key,'version_id':version,'sha256':hashlib.sha256(raw).hexdigest(),'size':len(raw)};self.data[(key,version)]=bytes(raw);self.read(ref);return ref
 def read(self,ref,maximum=3_000_000):
  if self.fail_read:raise RuntimeError('Simulated readback failure')
  raw=self.data[(ref['key'],ref['version_id'])]
  if hashlib.sha256(raw).hexdigest()!=ref['sha256'] or len(raw)!=ref['size'] or len(raw)>maximum:raise ValueError('Blob differs')
  return raw
ACTOR={'sub':'local-reviewer','name':'Local test reviewer'}
TEXT='Customer names and email addresses must not be shared externally without data owner approval. The proposal aims to reduce reporting time. No approval, cost baseline or model comparison has been supplied.'
def proposal(source):
 citation={'evidence_id':source['evidence'][0]['evidence_id'],'quote':source['evidence'][0]['text'].split('.')[0]+'.'}
 registry={x['perspective']:x['decision_item_id'] for x in snapshot_item_registry(source)}
 value={'input_hash':source['input_hash'],'summary':'Local scripted assessment: confirm owner approval and the missing baseline before proceeding.',
  'findings':[{'finding_id':'F-01','kind':'GAP','title':'Owner approval evidence missing','description':'The supplied evidence does not include data owner approval.','severity':'HIGH','severity_reason':'The documented rule requires approval.','citations':[citation]}],
  'actions':[{'title':'Collect approval evidence','description':'Ask the owner to review the purpose and requested data.','finding_ids':['F-01']}],
  'decision_items':[{'decision_item_id':registry[p],'perspective':p,'question':'What evidence supports this business decision?', 'recommendation':'REVISE' if p=='GOVERNANCE' else 'NEEDS_INPUT','rationale':'The proposal needs an owner decision and measured baseline before it can proceed.','conditions':'Owner confirms the permitted scope.','reassessment_conditions':'New evidence or a changed purpose.','citations':[citation] if p=='GOVERNANCE' else []} for p in PERSPECTIVES],
  'missing_information':['Owner approval and processor terms','Measured baseline and model comparison']}
 if source['mode']=='REASSESSMENT':
  prior=source['prior_publication']['publication']
  value['reassessment']={'compared_publication_id':prior['publication_id'],'compared_decision_digest':prior['digest'],
   'impacts':[{'decision_item_id':registry[p],'status':'AFFECTED' if p=='GOVERNANCE' else 'UNCHANGED',
    'reason':'The selected evidence requires comparison with this prior decision item.',
    'citations':[citation],'unknowns':[]} for p in PERSPECTIVES]}
 return value
def observed(source):return {'input_hash':source['input_hash'],'status':'VALIDATED','result':'OBSERVED','proposal':proposal(source),'reads':['context','evidence'],'model_id':'apac.amazon.nova-pro-v1:0','model_calls':[{'http_status':200,'request_id':'LOCAL_SCRIPTED_MODEL_ONLY'}]}

def vendor_registration():
 root=Path(__file__).resolve().parents[2];fixtures=FixtureBundle.load(root/'fixtures/decision_cases.json')
 profiles={}
 for decision in (Decision.MAINTAIN,Decision.NARROW):
  plan=build_policy_plan(fixtures,decision)
  profiles[decision.value]={'boundary_parameters':plan['resulting_boundary'],'allowed_request_ids':plan['allowed_request_ids'],
   'expected_outcomes':[{'request_id':x['request_id'],'expected_outcome':x['expected_policy_outcome']} for x in plan['expected_outcomes']]}
 account='111122223333';region='ap-northeast-1';gateway='authority-delta-gateway-rvplvkk1t7';runtime='AuthorityDeltaRuntimeV2';endpoint='LIVE'
 return registration_with_hash({'schema_version':'1.0','status':'ACTIVE','connection_mode':'SYNTHETIC_LOCAL',
  'adapter_id':'vendor_payment','adapter_version':'1.0.0','connection_id':'conn-local-vendor-payment',
  'source_authority':'local:test-fixture-only','target_account_id':account,'target_region':region,
  'gateway_arn':f'arn:aws:bedrock-agentcore:{region}:{account}:gateway/{gateway}','gateway_id':gateway,
  'policy_engine_id':'AuthorityDeltaEngine-local','target_id':'LOCALTESTTARGET','target_name':'VendorPaymentTools',
  'runtime':{'release_id':'V2','runtime_id':runtime,'runtime_arn':f'arn:aws:bedrock-agentcore:{region}:{account}:runtime/{runtime}',
   'runtime_version':'2','endpoint_name':endpoint,'endpoint_arn':f'arn:aws:bedrock-agentcore:{region}:{account}:runtime/{runtime}/runtime-endpoint/{endpoint}',
   'execution_role_arn':f'arn:aws:iam::{account}:role/authority-delta-vendor-v2-runtime'},
  'discovery_binding':{'role_arn':f'arn:aws:iam::{account}:role/authority-delta-customer-discovery',
   'external_id':'local-test-external-id-000000000001'},
  'publisher_binding':{'function_arn':f'arn:aws:lambda:{region}:{account}:function:authority-delta-customer-publisher:live',
   'invoke_role_arn':f'arn:aws:iam::{account}:role/authority-delta-customer-publish-invoke',
   'external_id':'local-test-external-id-000000000001'},
  'invocation_binding':{'function_arn':f'arn:aws:lambda:{region}:{account}:function:authority-delta-customer-invocation:live',
   'invoke_role_arn':f'arn:aws:iam::{account}:role/authority-delta-customer-runtime-invoke',
   'external_id':'local-test-external-id-000000000001'},
  'probe_binding':{'function_arn':f'arn:aws:lambda:{region}:{account}:function:authority-delta-vendor-canary:live',
   'request_registry_table_name':'authority-delta-request-registry',
   'sandbox_ledger_table_name':'authority-delta-sandbox-ledger'},
  'request_registry_snapshot_hash':fixtures.request_registry_snapshot_hash,
  'forbidden_tool_ids':['export_credentials','update_vendor_bank'],'profiles':profiles})
