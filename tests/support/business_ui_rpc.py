"""Local DOM test bridge: real handler/service; synthetic identity/model/AWS/storage."""
import json,sys,traceback
from authority_delta.business.service import BusinessService
from authority_delta.business.jobs import AssessmentWorker
from authority_delta.business.application import ApplicationWorker
from services.business.handler import handle
from support.business import ACTOR,MemoryStore,MemoryBlobs,Clock,observed
from test_business_delegation import ScriptedPublisher
from test_connected_acceptance_readiness import chain
from scripts.build_customer_adapter_registry import build
from scripts.check_connected_acceptance_readiness import check_chain
from scripts.check_integrated_acceptance_evidence import check

docs,raws=chain();connected=check_chain(docs,raws)
registration=build(docs['connector_report']['observed_binding'])['registrations'][0]
db,blobs,clock=MemoryStore(),MemoryBlobs(),Clock()
app=BusinessService(db,blobs,clock=clock,adapters=[registration])
class TimedPublisher(ScriptedPublisher):
    def _result(self,*args,**kwargs):
        result=super()._result(*args,**kwargs)
        result['observed_at']=clock()
        return result
mode='VERIFIED'
for line in sys.stdin:
    try:
        request=json.loads(line);kind=request.get('kind')
        if kind=='publisher_mode':
            mode=request['value'];result={'ok':True}
        elif kind=='check':
            result=check(connected,app.export_acceptance_evidence(ACTOR,request['payment']),app.export_acceptance_evidence(ACTOR,request['nonpayment']))
        elif kind=='api':
            clock.advance(1)
            event={'rawPath':request['path'],'body':json.dumps(request.get('body')),'requestContext':{
                'requestId':'local-dom-request','http':{'method':request['method']},'authorizer':{'jwt':{'claims':{
                    'token_use':'access','client_id':'local','sub':ACTOR['sub'],
                    'scope':'authority-delta/read authority-delta/write authority-delta/approve authority-delta/publish'}}}}}
            result=handle(event,app,{'CLIENT_ID':'local','REVIEWER_SUB':ACTOR['sub'],'REVIEWER_USERNAME':'Local test reviewer'})
            # These local workers run after the real API commits. Their outputs
            # are explicit scripted model/publisher doubles, never AWS evidence.
            if result['statusCode']==202:
                value=json.loads(result['body'])
                if request['path'].endswith('/runs'):
                    job=db.get('jobs',value['run_id'],'STATE').value
                    AssessmentWorker(db,blobs,observed,clock).process({'run_id':value['run_id'],'input_hash':job['input_hash']})
                elif request['path'].endswith('/applications'):
                    message={k:value[k] for k in ('object_id','application_id','enforcement_digest')}
                    ApplicationWorker(db,blobs,TimedPublisher(publish=mode),[registration],clock).process(message)
        else:raise ValueError('Unknown local test operation')
        print(json.dumps({'id':request['id'],'result':result}),flush=True)
    except Exception as exc:
        print(json.dumps({'id':request.get('id'),'error':str(exc),'trace':traceback.format_exc()}),flush=True)
