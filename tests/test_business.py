"""Local application contracts, real Strands tool loop, persistence and failure behavior."""
import base64,copy,io,json,os,sys,unittest,uuid
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import patch
from botocore.exceptions import ClientError
from strands.models.model import Model
from authority_delta.business.service import BusinessService,Problem
from authority_delta.business.jobs import AssessmentWorker,RuntimeInvoker,dispatch_one
from authority_delta.business.contracts import validate_proposal
from authority_delta.business.evidence import extract
from services.business.handler import handle,parse_body
from services.business_analysis.agent import assess
from support.business import MemoryStore,MemoryBlobs,Clock,ACTOR,TEXT,proposal,observed
ROOT=Path(__file__).resolve().parents[1]
class Flow(unittest.TestCase):
 def setUp(self):
  self.db=MemoryStore();self.blobs=MemoryBlobs();self.clock=Clock();self.app=BusinessService(self.db,self.blobs,clock=self.clock)
  self.oid=self.app.create(ACTOR,dict(request_id=uuid.uuid4().hex,name='Customer data sharing',purpose='Reduce reporting work',question='May this customer data be shared?',owner='Operations',goals='Measure weekly time'))['object_id']
 def command(self,**values):return dict(request_id=uuid.uuid4().hex,expected_revision=self.app.detail(ACTOR,self.oid)['object']['record_revision'],**values)
 def evidence(self,text=TEXT,name='data-sharing.txt'):
  return self.app.add_evidence(ACTOR,self.oid,self.command(filename=name,title=name,source='Local supplied test',content_base64=base64.b64encode(text.encode()).decode()))['evidence_id']
 def run_job(self):
  eid=self.evidence();rid=self.app.start_run(ACTOR,self.oid,self.command(evidence_ids=[eid]))['run_id'];self.work(rid);return rid
 def work(self,rid,invoke=observed):
  job=self.db.get('jobs',rid,'STATE').value;AssessmentWorker(self.db,self.blobs,invoke,self.clock).process({'run_id':rid,'input_hash':job['input_hash']})
 def draft(self):
  rid=self.run_job();p=self.app.run(ACTOR,self.oid,rid)['analysis']['proposal'];return self.app.save_draft(ACTOR,self.oid,self.command(run_id=rid,proposal=p,change_reason='Human test reviewed the source'))
 def approve(self):
  draft=self.draft();return self.app.review(ACTOR,self.oid,self.command(digest=draft['digest'],decision='APPROVE',reason='Test reviewer checked exact evidence',valid_days=7))
 def test_nonpayment_cycle_and_new_input_preserves_official_history(self):
  receipt=self.approve();d=self.app.detail(ACTOR,self.oid);self.assertIsNone(d['object']['published_current']);self.assertEqual(receipt['approver_sub'],ACTOR['sub']);self.assertFalse(receipt['runtime_authority_granted'])
  cmd=self.command(receipt_id=receipt['receipt_id']);published=self.app.publish(ACTOR,self.oid,cmd);self.assertEqual(self.app.publish(ACTOR,self.oid,cmd),published)
  old=copy.deepcopy(self.app.detail(ACTOR,self.oid)['official_decision']);eid=self.evidence('Additional sharing rules require a signed processor contract.')
  d=self.app.detail(ACTOR,self.oid);self.assertEqual(d['official_decision'],old);self.assertIsNone(d['object']['approval']);self.assertIsNone(d['object']['applied_binding']);self.assertEqual(len(d['publications']),1)
  rid=self.app.start_run(ACTOR,self.oid,self.command(evidence_ids=[eid]))['run_id'];self.work(rid)
  self.assertEqual(self.app.detail(ACTOR,self.oid)['official_decision'],old);self.assertEqual(len(self.app.detail(ACTOR,self.oid)['runs']),2)
  self.assertTrue({'OBJECT_CREATED','EVIDENCE_ADDED','ASSESSMENT_QUEUED','DECISION_DRAFT_SAVED','HUMAN_APPROVE','DECISION_PUBLISHED'}.issubset({e['kind'] for e in self.app.detail(ACTOR,self.oid)['history']}))
 def test_edit_invalidates_receipt_and_creates_new_revision(self):
  receipt=self.approve();d=self.app.detail(ACTOR,self.oid);p=d['draft']['proposal'];p['summary']='Edited by the reviewer; retain documented constraints.'
  new=self.app.save_draft(ACTOR,self.oid,self.command(run_id=d['object']['latest_run'],proposal=p,change_reason='Changed the conclusion'))
  self.assertEqual(new['revision'],2);self.assertNotEqual(new['digest'],receipt['digest'])
  with self.assertRaises(Problem):self.app.publish(ACTOR,self.oid,self.command(receipt_id=receipt['receipt_id']))
  with self.assertRaises(Problem):self.app.review(ACTOR,self.oid,self.command(digest=receipt['digest'],decision='APPROVE',reason='Old hash',valid_days=7))
 def test_stale_screen_other_owner_and_expiry(self):
  draft=self.draft();old=self.command(digest=draft['digest'],decision='APPROVE',reason='Review',valid_days=1);self.evidence()
  with self.assertRaises(Problem):self.app.review(ACTOR,self.oid,old)
  for method,args in [(self.app.detail,()),(self.app.add_evidence,({},)),(self.app.publish,({},))]:
   with self.assertRaises(Problem) as ctx:method({'sub':'another','name':'Other'},self.oid,*args)
   self.assertEqual(ctx.exception.status,404)
  receipt=self.approve();self.clock.advance(8*86400)
  with self.assertRaises(Problem) as ctx:self.app.publish(ACTOR,self.oid,self.command(receipt_id=receipt['receipt_id']))
  self.assertEqual(ctx.exception.code,'APPROVAL_EXPIRED')
 def test_rejection_and_return_do_not_publish(self):
  for decision in ['REJECT','RETURN']:
   draft=self.draft();r=self.app.review(ACTOR,self.oid,self.command(digest=draft['digest'],decision=decision,reason='Needs correction',valid_days=7))
   with self.assertRaises(Problem):self.app.publish(ACTOR,self.oid,self.command(receipt_id=r['receipt_id']))
 def test_storage_failure_never_moves_current_and_replay_after_transaction_failure(self):
  receipt=self.approve();cmd=self.command(receipt_id=receipt['receipt_id']);self.blobs.fail_put=True
  with self.assertRaises(RuntimeError):self.app.publish(ACTOR,self.oid,cmd)
  self.blobs.fail_put=False;self.assertIsNone(self.app.detail(ACTOR,self.oid)['object']['published_current']);self.db.fail_next=True
  with self.assertRaises(RuntimeError):self.app.publish(ACTOR,self.oid,cmd)
  self.assertIsNone(self.app.detail(ACTOR,self.oid)['object']['published_current']);result=self.app.publish(ACTOR,self.oid,cmd);self.assertEqual(self.app.publish(ACTOR,self.oid,cmd),result)
  self.assertEqual(len(self.app.detail(ACTOR,self.oid)['publications']),1)
 def test_corrupt_receipt_fails_closed(self):
  receipt=self.approve();ref=receipt['ref'];self.blobs.data[(ref['key'],ref['version_id'])]=b'{}'
  with self.assertRaises(ValueError):self.app.publish(ACTOR,self.oid,self.command(receipt_id=receipt['receipt_id']))
  self.assertIsNone(self.app.detail(ACTOR,self.oid)['object']['published_current'])
 def test_concurrent_same_request_produces_one_publication(self):
  receipt=self.approve();cmd=self.command(receipt_id=receipt['receipt_id'])
  with ThreadPoolExecutor(max_workers=2) as pool:results=list(pool.map(lambda _:self.app.publish(ACTOR,self.oid,cmd),[1,2]))
  self.assertEqual(results[0],results[1]);self.assertEqual(len(self.app.detail(ACTOR,self.oid)['publications']),1)
 def test_request_identifier_cannot_change_payload(self):
  receipt=self.approve();cmd=self.command(receipt_id=receipt['receipt_id']);self.app.publish(ACTOR,self.oid,cmd)
  with self.assertRaises(Problem) as ctx:self.app.publish(ACTOR,self.oid,dict(cmd,receipt_id='changed'))
  self.assertEqual(ctx.exception.code,'REQUEST_CONFLICT')
 def test_outbox_retry_worker_duplicate_and_reconnection(self):
  class Queue:
   fails=True
   def send_message(q,**kw):
    if q.fails:raise RuntimeError('Queue unavailable')
    q.message=json.loads(kw['MessageBody'])
  queue=Queue();self.app.dispatch=lambda rid:dispatch_one(self.db,queue,'local://queue',rid)
  eid=self.evidence();cmd=self.command(evidence_ids=[eid]);rid=self.app.start_run(ACTOR,self.oid,cmd)['run_id'];self.assertIsNotNone(self.db.get('jobs','OUTBOX',rid));queue.fails=False
  self.assertEqual(self.app.start_run(ACTOR,self.oid,cmd)['run_id'],rid);self.assertIsNone(self.db.get('jobs','OUTBOX',rid));calls=[]
  worker=AssessmentWorker(self.db,self.blobs,lambda s:(calls.append(s),observed(s))[1],self.clock);worker.process(queue.message);worker.process(queue.message);self.assertEqual(len(calls),1)
  reopened=BusinessService(self.db,self.blobs,clock=self.clock);self.assertEqual(reopened.run(ACTOR,self.oid,rid)['status'],'REVIEW_REQUIRED')
 def test_interrupted_running_job_recovers_without_duplicate_model(self):
  eid=self.evidence();rid=self.app.start_run(ACTOR,self.oid,self.command(evidence_ids=[eid]))['run_id'];row=self.db.get('jobs',rid,'STATE');claim=dict(row.value,status='RUNNING',lease_until=self.clock(),attempt=1);self.db.transact([('jobs',rid,'STATE',claim,row.version)])
  self.assertEqual(self.app.run(ACTOR,self.oid,rid)['status'],'FAILED');self.work(rid,lambda s:(_ for _ in ()).throw(AssertionError('Must not run')))
 def test_unsupported_pdf_preserved_but_never_analyzed(self):
  eid=self.evidence('%PDF-corrupt','broken.pdf');self.assertEqual(self.app.detail(ACTOR,self.oid)['evidence'][0]['extraction_status'],'NEEDS_INPUT')
  with self.assertRaises(Problem):self.app.start_run(ACTOR,self.oid,self.command(evidence_ids=[eid]))
  self.assertEqual(base64.b64decode(self.app.original(ACTOR,self.oid,eid)['content_base64']),b'%PDF-corrupt')
 def test_failed_analysis_retains_diagnostics_and_input(self):
  eid=self.evidence();rid=self.app.start_run(ACTOR,self.oid,self.command(evidence_ids=[eid]))['run_id'];self.work(rid,lambda s:(_ for _ in ()).throw(ValueError('Runtime endpoint version mismatch')))
  result=self.app.run(ACTOR,self.oid,rid);self.assertEqual(result['status'],'FAILED');self.assertIn('endpoint version',result['diagnostics']['message']);self.assertEqual(result['selected_evidence_ids'],[eid])
 def test_jwt_scope_routing_and_strict_request_validation(self):
  env={'CLIENT_ID':'client','REVIEWER_SUB':ACTOR['sub'],'REVIEWER_USERNAME':'local'}
  def event(method='GET',path='/business/objects',body=None,**claims):return {'rawPath':path,'body':json.dumps(body),'requestContext':{'http':{'method':method},'authorizer':{'jwt':{'claims':dict(token_use='access',client_id='client',sub=ACTOR['sub'],scope='authority-delta/read',**claims)}}}}
  self.assertEqual(handle({},self.app,env)['statusCode'],401)
  self.assertEqual(handle(event(),self.app,env)['statusCode'],200)
  self.assertEqual(handle(event('POST','/business/objects/'+self.oid+'/review',{}),self.app,env)['statusCode'],403)
  e=event();e['requestContext']['authorizer']['jwt']['claims']['sub']='other';self.assertEqual(handle(e,self.app,env)['statusCode'],403)
  e=event('POST',body={'request_id':uuid.uuid4().hex,'name':'Name','purpose':'Purpose','question':'Question','owner':'Owner','approver_sub':'forged'});e['requestContext']['authorizer']['jwt']['claims']['scope']='authority-delta/write';self.assertEqual(handle(e,self.app,env)['statusCode'],422)
  with self.assertRaises(ValueError):parse_body({'body':'{"x":1,"x":2}'})
  preflight={'rawPath':'/business/objects','requestContext':{'http':{'method':'OPTIONS'}}}
  self.assertEqual(handle(preflight,None,env)['statusCode'],200)

class ScriptedBusinessModel(Model):
 def __init__(self,proposals,omit=False):self.proposals=proposals;self.calls=[];self.omit=omit
 def update_config(self,**kw):pass
 def get_config(self):return {}
 async def structured_output(self,*a,**kw):raise AssertionError('Legacy output path');yield
 async def stream(self,messages,tool_specs=None,system_prompt=None,**kw):
  self.calls.append(copy.deepcopy(messages));i=len(self.calls)-1;names=['read_context','read_evidence'];name=names[i] if i<2 and not self.omit else 'BoundProposal';value={} if name in names else self.proposals[min(max(0,i-2),len(self.proposals)-1)]
  yield {'messageStart':{'role':'assistant'}};yield {'contentBlockStart':{'contentBlockIndex':0,'start':{'toolUse':{'toolUseId':'local-'+str(i),'name':name}}}}
  yield {'contentBlockDelta':{'contentBlockIndex':0,'delta':{'toolUse':{'input':json.dumps(value)}}}};yield {'contentBlockStop':{'contentBlockIndex':0}};yield {'messageStop':{'stopReason':'tool_use'}}
class BusinessStrands(unittest.TestCase):
 def test_real_sdk_tools_feedback_and_no_read_rejection(self):
  from deploy_business import canary_input
  source=canary_input('local');good=proposal(source);good.pop('input_hash');bad=copy.deepcopy(good);bad['decision_items'][0]['citations'][0]['quote']='This quote is invented and not in evidence.'
  model=ScriptedBusinessModel([bad,good]);result=assess(source,model=model);self.assertEqual(result['status'],'VALIDATED');self.assertEqual(result['reads'],['context','evidence']);self.assertEqual(len(result['attempts']),2);self.assertIn('Quote must appear',repr(model.calls[-1]))
  for p,omit in [(good,True),(bad,False)]:
   result=assess(source,model=ScriptedBusinessModel([p],omit));self.assertEqual(result['status'],'NEEDS_INPUT');self.assertLessEqual(len(result['attempts']),3)
 def test_injected_authority_and_cross_evidence_citation_rejected(self):
  from deploy_business import canary_input
  source=canary_input('local');p=proposal(source)
  with self.assertRaises(ValueError):validate_proposal(dict(p,approve=True),source)
  p['decision_items'][0]['citations'][0]['evidence_id']='another-object'
  with self.assertRaises(ValueError):validate_proposal(p,source)

if __name__=='__main__':unittest.main()
