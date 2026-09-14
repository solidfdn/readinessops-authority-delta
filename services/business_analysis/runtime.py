"""Bounded HTTP entrypoint for business Strands assessment on AgentCore Runtime."""
import json
import os
import subprocess
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


def perform(source):
    import boto3
    from botocore.config import Config
    from strands.models import BedrockModel
    from services.business_analysis.agent import assess
    from authority_delta.business.contracts import check_snapshot
    check_snapshot(source)
    region=os.environ['AD_REGION'];account=os.environ['AD_ACCOUNT_ID']
    identity=boto3.client('sts',region_name=region).get_caller_identity()
    prefix=f"arn:aws:sts::{account}:assumed-role/{os.environ['AD_EXPECTED_ROLE_NAME']}/"
    if identity['Account']!=account or not identity['Arn'].startswith(prefix):raise ValueError('Analysis execution role mismatch')
    class BoundedModel(BedrockModel):
        count=0
        async def stream(self,*args,**kwargs):
            self.count+=1
            if self.count>8:raise ValueError('Analysis model call limit exceeded')
            async for event in super().stream(*args,**kwargs):yield event
    model_id=os.environ['AD_ANALYSIS_MODEL_ID']
    if model_id!='apac.amazon.nova-pro-v1:0':raise ValueError('Unexpected analysis model')
    model=BoundedModel(model_id=model_id,region_name=region,temperature=0,max_tokens=5000,streaming=False,
        boto_client_config=Config(connect_timeout=10,read_timeout=70,retries={'total_max_attempts':1}))
    calls=[]
    def capture(parsed,**kwargs):
        metadata=parsed.get('ResponseMetadata',{})
        calls.append({'request_id':metadata.get('RequestId'),'http_status':metadata.get('HTTPStatusCode'),'usage':parsed.get('usage')})
    model.client.meta.events.register('after-call.bedrock-runtime.Converse',capture)
    result=assess(source,model=model)
    result.update(result='OBSERVED' if result.get('status')=='VALIDATED' else 'HOLD',input_hash=source['input_hash'],model_id=model_id,model_calls=calls,
        identity={'account':account,'arn':identity['Arn'],'request_id':identity['ResponseMetadata']['RequestId']})
    return result


class Handler(BaseHTTPRequestHandler):
    def log_message(self,*args):pass
    def send(self,code,value):
        raw=json.dumps(value).encode();self.send_response(code);self.send_header('Content-Type','application/json');self.send_header('Content-Length',str(len(raw)));self.end_headers();self.wfile.write(raw)
    def do_GET(self):
        self.send(200,{'status':'Healthy'}) if self.path=='/ping' else self.send(404,{'error':'Not found'})
    def do_POST(self):
        if self.path!='/invocations':self.send(404,{'error':'Not found'});return
        try:
            size=int(self.headers.get('Content-Length','0'))
            if not 0<size<=262144:raise ValueError('Invalid body size')
            raw=self.rfile.read(size);source=json.loads(raw)
            from authority_delta.business.contracts import check_snapshot
            check_snapshot(source)
            child=subprocess.run([sys.executable,__file__,'--worker'],input=raw,capture_output=True,timeout=240)
            if child.returncode:raise ValueError('Analysis worker failed: '+child.stderr.decode(errors='replace')[-800:])
            result=json.loads(child.stdout)
            self.send(200,result)
        except Exception as exc:self.send(200,{'result':'HOLD','error':{'type':type(exc).__name__,'message':str(exc)[:1000]}})

if __name__=='__main__':
    if '--worker' in sys.argv:
        result=perform(json.load(sys.stdin));print(json.dumps(result))
    else:ThreadingHTTPServer(('0.0.0.0',8080),Handler).serve_forever()
