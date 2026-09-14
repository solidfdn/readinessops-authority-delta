"""Resolve only the approved Nova Pro APAC profile from the current AWS response."""
import re

MODEL_ID = 'apac.amazon.nova-pro-v1:0'
FOUNDATION_ID = 'amazon.nova-pro-v1:0'


def resolve_analysis_model(session, account, region):
    if region != 'ap-northeast-1':
        raise ValueError('Analysis profile must be resolved from the bound Tokyo region')
    profile = session.client('bedrock').get_inference_profile(inferenceProfileIdentifier=MODEL_ID)
    arn = f'arn:aws:bedrock:{region}:{account}:inference-profile/{MODEL_ID}'
    if any(profile.get(k) != v for k,v in {
        'inferenceProfileId':MODEL_ID, 'inferenceProfileArn':arn,
        'status':'ACTIVE', 'type':'SYSTEM_DEFINED'}.items()):
        raise ValueError('Nova Pro profile identity/status differs from the approved model')
    metadata = profile.get('ResponseMetadata', {})
    if metadata.get('HTTPStatusCode') != 200 or not metadata.get('RequestId'):
        raise ValueError('Nova Pro profile lacks successful AWS request evidence')
    models=profile.get('models', [])
    if not 1 <= len(models) <= 20:
        raise ValueError('Unexpected Nova Pro destination set')
    arns=[]
    for model in models:
        value=model.get('modelArn','')
        if not re.fullmatch(r'arn:aws:bedrock:ap-[a-z]+-[0-9]+::foundation-model/'+re.escape(FOUNDATION_ID),value):
            raise ValueError('Unexpected model or non-APAC destination in Nova Pro profile')
        arns.append(value)
    arns=sorted(set(arns + [f'arn:aws:bedrock:{region}::foundation-model/{FOUNDATION_ID}']))
    return {'model_id':MODEL_ID, 'profile_arn':arn, 'foundation_model_arns':arns,
        'profile_response':profile,
        'deployment_parameters':{'AnalysisModelId':MODEL_ID, 'AnalysisProfileArn':arn,
            'AnalysisFoundationModelArns':','.join(arns)}}
