"""SDK-shaped profile discovery and exact IAM destination binding; no live AWS."""
import copy,json,unittest
from datetime import datetime,timezone
from pathlib import Path
from types import SimpleNamespace
import boto3
from botocore.stub import Stubber
from scripts.analysis_model import resolve_analysis_model,MODEL_ID

ACCOUNT='538522204923';REGION='ap-northeast-1'

def profile():
    return {'inferenceProfileName':'APAC Nova Pro','inferenceProfileId':MODEL_ID,
        'inferenceProfileArn':f'arn:aws:bedrock:{REGION}:{ACCOUNT}:inference-profile/{MODEL_ID}',
        'status':'ACTIVE','type':'SYSTEM_DEFINED','createdAt':datetime(2026,9,9,tzinfo=timezone.utc),
        'models':[{'modelArn':f'arn:aws:bedrock:{r}::foundation-model/amazon.nova-pro-v1:0'} for r in ('ap-northeast-1','ap-southeast-2')],
        'ResponseMetadata':{'RequestId':'profile-test-request','HTTPStatusCode':200}}

class ModelSelectionTests(unittest.TestCase):
    def resolve(self,value):
        client=boto3.client('bedrock',region_name=REGION,aws_access_key_id='offline-test',aws_secret_access_key='offline-test')
        with Stubber(client) as stub:
            stub.add_response('get_inference_profile',value,{'inferenceProfileIdentifier':MODEL_ID})
            return resolve_analysis_model(SimpleNamespace(client=lambda name:client),ACCOUNT,REGION)

    def test_current_profile_binds_source_and_destination_models(self):
        value=self.resolve(profile())
        self.assertEqual(value['model_id'],MODEL_ID)
        self.assertEqual(value['deployment_parameters']['AnalysisFoundationModelArns'],','.join(value['foundation_model_arns']))
        self.assertEqual(len(value['foundation_model_arns']),2)

    def test_wrong_profile_or_destination_is_rejected(self):
        variants=[]
        for key,value in [('inferenceProfileId','us.amazon.nova-pro-v1:0'),('inferenceProfileArn','arn:aws:bedrock:ap-northeast-1:111122223333:inference-profile/'+MODEL_ID),('models',[{'modelArn':'arn:aws:bedrock:us-east-1::foundation-model/amazon.nova-pro-v1:0'}]),('models',[{'modelArn':'arn:aws:bedrock:ap-northeast-1::foundation-model/amazon.nova-lite-v1:0'}])]:
            p=profile();p[key]=value;variants.append(p)
        for p in variants:
            with self.subTest(value=p):
                with self.assertRaises(ValueError):self.resolve(p)

    def test_profile_failure_propagates_without_falling_back_to_lite(self):
        from botocore.exceptions import ClientError
        client=boto3.client('bedrock',region_name=REGION,aws_access_key_id='offline-test',aws_secret_access_key='offline-test')
        with Stubber(client) as stub:
            stub.add_client_error('get_inference_profile','AccessDeniedException',expected_params={'inferenceProfileIdentifier':MODEL_ID})
            with self.assertRaises(ClientError):resolve_analysis_model(SimpleNamespace(client=lambda name:client),ACCOUNT,REGION)

    def test_template_gives_only_resolved_profile_and_models_invoke_permission(self):
        t=json.loads((Path(__file__).resolve().parents[1]/'infra/analysis-runtime/template.json').read_text())
        statements=t['Resources']['AnalysisExecutionRole']['Properties']['Policies'][0]['PolicyDocument']['Statement']
        invocation=[s for s in statements if s['Action']==['bedrock:InvokeModel']]
        self.assertEqual(len(invocation),2)
        self.assertEqual(invocation[0]['Resource'],{'Ref':'AnalysisProfileArn'})
        self.assertEqual(invocation[1]['Resource'],{'Ref':'AnalysisFoundationModelArns'})
        self.assertEqual(invocation[1]['Condition']['StringEquals']['bedrock:InferenceProfileArn'],{'Ref':'AnalysisProfileArn'})

if __name__=='__main__':unittest.main()
