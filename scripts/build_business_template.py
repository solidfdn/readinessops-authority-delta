"""Generate the new business stack from verified AgentCore deployment structures."""
import copy,json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
ref=lambda x:{'Ref':x}
att=lambda x,y='Arn':{'Fn::GetAtt':[x,y]}
sub=lambda x:{'Fn::Sub':x}
def allow(actions,resource):return {'Effect':'Allow','Action':actions,'Resource':resource}
def role(name,statements):
 return {'Type':'AWS::IAM::Role','Properties':{'RoleName':name,'AssumeRolePolicyDocument':{'Version':'2012-10-17','Statement':[{'Effect':'Allow','Principal':{'Service':'lambda.amazonaws.com'},'Action':'sts:AssumeRole'}]},'Policies':[{'PolicyName':'BusinessScope','PolicyDocument':{'Version':'2012-10-17','Statement':statements}}]}}
def build():
 t=json.loads((ROOT/'infra/analysis-runtime/template.json').read_text())
 raw=json.dumps(t).replace('authority_delta_analysis','authority_delta_business').replace('authority-delta-analysis-runtime','authority-delta-business-model').replace('fixed_analysis','fixed_business')
 t=json.loads(raw);t['Description']='ReadinessOps business intake, assessment, human decision and official publication. Runtime authority publication is separate.'
 for n in ['CodeKey','CodeVersion','ExistingApiId','ExistingAuthorizerId','ClientId','ReviewerSub']:t['Parameters'][n]={'Type':'String','MinLength':1}
 t['Parameters']['CustomerPublisherInvokeRoleArn']={'Type':'String','Default':'arn:aws:iam::000000000000:role/unregistered-authority-delta-publish-invoke','AllowedPattern':'^arn:aws:iam::[0-9]{12}:role/[A-Za-z0-9+=,.@_-]{1,64}$'}
 t['Parameters']['CustomerRuntimeInvokeRoleArn']={'Type':'String','Default':'arn:aws:iam::000000000000:role/unregistered-authority-delta-runtime-invoke','AllowedPattern':'^arn:aws:iam::[0-9]{12}:role/[A-Za-z0-9+=,.@_-]{1,64}$'}
 r=t['Resources']
 r['DataBucket']={'Type':'AWS::S3::Bucket','DeletionPolicy':'Retain','UpdateReplacePolicy':'Retain','Properties':{'VersioningConfiguration':{'Status':'Enabled'},'BucketEncryption':{'ServerSideEncryptionConfiguration':[{'ServerSideEncryptionByDefault':{'SSEAlgorithm':'AES256'}}]},'PublicAccessBlockConfiguration':{'BlockPublicAcls':True,'BlockPublicPolicy':True,'IgnorePublicAcls':True,'RestrictPublicBuckets':True}}}
 for table in ['AppTable','JobsTable']:
  r[table]={'Type':'AWS::DynamoDB::Table','DeletionPolicy':'Retain','UpdateReplacePolicy':'Retain','Properties':{'BillingMode':'PAY_PER_REQUEST','AttributeDefinitions':[{'AttributeName':x,'AttributeType':'S'} for x in ['pk','sk']],'KeySchema':[{'AttributeName':'pk','KeyType':'HASH'},{'AttributeName':'sk','KeyType':'RANGE'}],'SSESpecification':{'SSEEnabled':True}}}
 for q in ['Queue','DeadQueue','ApplicationQueue','ApplicationDeadQueue','InvocationQueue','InvocationDeadQueue']:
  r[q]={'Type':'AWS::SQS::Queue','Properties':{'SqsManagedSseEnabled':True,'MessageRetentionPeriod':1209600,'VisibilityTimeout':2100}}
 r['Queue']['Properties']['RedrivePolicy']={'deadLetterTargetArn':att('DeadQueue'),'maxReceiveCount':3}
 r['ApplicationQueue']['Properties']['VisibilityTimeout']=5100
 r['ApplicationDeadQueue']['Properties']['VisibilityTimeout']=5100
 r['ApplicationQueue']['Properties']['RedrivePolicy']={'deadLetterTargetArn':att('ApplicationDeadQueue'),'maxReceiveCount':3}
 r['InvocationQueue']['Properties']['VisibilityTimeout']=3600
 r['InvocationDeadQueue']['Properties']['VisibilityTimeout']=3600
 r['InvocationQueue']['Properties']['RedrivePolicy']={'deadLetterTargetArn':att('InvocationDeadQueue'),'maxReceiveCount':3}
 r['DeadQueue']['Properties']['RedriveAllowPolicy']={'redrivePermission':'byQueue','sourceQueueArns':[att('Queue')]}
 # Avoid a Queue/DeadQueue circular dependency: the DLQ receives no public policy.
 r['DeadQueue']['Properties'].pop('RedriveAllowPolicy')
 for name in ['Api','Worker','Dispatcher','ApplicationWorker','ApplicationDispatcher','InvocationGate','InvocationWorker']:
  r[name+'Logs']={'Type':'AWS::Logs::LogGroup','Properties':{'LogGroupName':'/aws/lambda/authority-delta-business-'+name.lower(),'RetentionInDays':14}}
 log=lambda n:allow(['logs:CreateLogStream','logs:PutLogEvents'],att(n+'Logs'))
 ddb=lambda actions,tables:allow(actions,[att(x) for x in tables])
 bucket=sub('arn:${AWS::Partition}:s3:::${DataBucket}/business/*')
 tx='dynamodb:TransactWriteItems'
 r['ApiRole']=role('authority-delta-business-api',[log('Api'),ddb(['dynamodb:GetItem','dynamodb:Query','dynamodb:PutItem','dynamodb:DeleteItem',tx],['AppTable','JobsTable']),allow(['s3:GetObjectVersion','s3:PutObject'],bucket),allow('sqs:SendMessage',[att('Queue'),att('ApplicationQueue')])])
 r['DispatcherRole']=role('authority-delta-business-dispatcher',[log('Dispatcher'),ddb(['dynamodb:GetItem','dynamodb:Query','dynamodb:DeleteItem',tx],['JobsTable']),allow('sqs:SendMessage',att('Queue'))])
 r['WorkerRole']=role('authority-delta-business-worker',[log('Worker'),ddb(['dynamodb:GetItem','dynamodb:PutItem',tx],['JobsTable']),allow(['sqs:ReceiveMessage','sqs:DeleteMessage','sqs:GetQueueAttributes'],[att('Queue'),att('DeadQueue')]),allow('s3:GetObjectVersion',[sub('arn:${AWS::Partition}:s3:::${DataBucket}/business/inputs/*'),sub('arn:${AWS::Partition}:s3:::${DataBucket}/business/results/*')]),allow('s3:PutObject',sub('arn:${AWS::Partition}:s3:::${DataBucket}/business/results/*')),allow(['bedrock-agentcore:InvokeAgentRuntime','bedrock-agentcore:StopRuntimeSession'],[att('AnalysisRuntime','AgentRuntimeArn'),att('AnalysisEndpoint','AgentRuntimeEndpointArn')]),allow('bedrock-agentcore:GetAgentRuntimeEndpoint',[att('AnalysisRuntime','AgentRuntimeArn'),att('AnalysisEndpoint','AgentRuntimeEndpointArn')])])
 r['ApplicationDispatcherRole']=role('authority-delta-application-dispatcher',[log('ApplicationDispatcher'),ddb(['dynamodb:GetItem','dynamodb:Query','dynamodb:PutItem','dynamodb:DeleteItem',tx],['AppTable','JobsTable']),allow(['s3:GetObjectVersion','s3:PutObject'],bucket),allow('sqs:SendMessage',[att('ApplicationQueue'),att('InvocationQueue')])])
 r['ApplicationWorkerRole']=role('authority-delta-application-worker',[log('ApplicationWorker'),ddb(['dynamodb:GetItem','dynamodb:Query','dynamodb:PutItem','dynamodb:DeleteItem',tx],['AppTable','JobsTable']),allow(['sqs:ReceiveMessage','sqs:DeleteMessage','sqs:GetQueueAttributes'],[att('ApplicationQueue'),att('ApplicationDeadQueue')]),allow(['s3:GetObjectVersion','s3:PutObject'],sub('arn:${AWS::Partition}:s3:::${DataBucket}/business/*')),allow('sts:AssumeRole',ref('CustomerPublisherInvokeRoleArn'))])
 r['InvocationGateRole']=role('authority-delta-invocation-gate',[log('InvocationGate'),ddb(['dynamodb:GetItem','dynamodb:PutItem',tx],['AppTable','JobsTable']),allow('s3:GetObjectVersion',sub('arn:${AWS::Partition}:s3:::${DataBucket}/business/*'))])
 r['InvocationWorkerRole']=role('authority-delta-invocation-worker',[log('InvocationWorker'),ddb(['dynamodb:GetItem','dynamodb:PutItem',tx],['AppTable','JobsTable']),allow(['s3:GetObjectVersion','s3:PutObject'],sub('arn:${AWS::Partition}:s3:::${DataBucket}/business/*')),allow(['sqs:ReceiveMessage','sqs:DeleteMessage','sqs:GetQueueAttributes'],[att('InvocationQueue'),att('InvocationDeadQueue')]),allow('sts:AssumeRole',ref('CustomerRuntimeInvokeRoleArn'))])
 policy={'Version':'2012-10-17','Statement':[{'Effect':'Allow','Principal':{'AWS':['${DeployerRoleArn}','${WorkerRole.Arn}']},'Action':['bedrock-agentcore:InvokeAgentRuntime','bedrock-agentcore:StopRuntimeSession'],'Resource':'${AnalysisRuntime.AgentRuntimeArn}'},{'Effect':'Deny','Principal':'*','Action':['bedrock-agentcore:InvokeAgentRuntime','bedrock-agentcore:InvokeAgentRuntimeForUser','bedrock-agentcore:InvokeAgentRuntimeWithWebSocketStream','bedrock-agentcore:InvokeAgentRuntimeCommand','bedrock-agentcore:InvokeAgentRuntimeCommandShell','bedrock-agentcore:InvokeAgentRuntimeWithWebSocketStreamForUser','bedrock-agentcore:StopRuntimeSession'],'Resource':'${AnalysisRuntime.AgentRuntimeArn}','Condition':{'ArnNotEquals':{'aws:PrincipalArn':['${DeployerRoleArn}','${WorkerRole.Arn}']}}}]}
 r['AnalysisRuntimeResourcePolicy']['Properties']['Policy']=sub(json.dumps(policy,separators=(',',':')))
 common={'DATA_BUCKET':ref('DataBucket'),'JOBS_TABLE':ref('JobsTable'),'QUEUE_URL':ref('Queue')}
 api={**common,'APP_TABLE':ref('AppTable'),'APPLICATION_QUEUE_URL':ref('ApplicationQueue'),'CLIENT_ID':ref('ClientId'),'REVIEWER_SUB':ref('ReviewerSub'),'REVIEWER_USERNAME':'okada'}
 worker={**common,'QUEUE_ARN':att('Queue'),'DLQ_ARN':att('DeadQueue'),'RUNTIME_ID':att('AnalysisRuntime','AgentRuntimeId'),'RUNTIME_ARN':att('AnalysisRuntime','AgentRuntimeArn'),'RUNTIME_VERSION':att('AnalysisRuntime','AgentRuntimeVersion'),'RUNTIME_ENDPOINT':'fixed_business','RUNTIME_ACCOUNT':ref('AWS::AccountId'),'RUNTIME_ROLE_NAME':ref('AnalysisExecutionRole'),'RUNTIME_ENDPOINT_ARN':att('AnalysisEndpoint','AgentRuntimeEndpointArn')}
 for name,handler,env,timeout,memory in [('Api','services.business.handler.handler',api,29,1024),('Worker','services.business.worker.handler',worker,330,256),('Dispatcher','services.business.worker.dispatch_handler',common,45,256)]:
  r[name+'Function']={'Type':'AWS::Lambda::Function','Properties':{'FunctionName':'authority-delta-business-'+name.lower(),'Runtime':'python3.12','Architectures':['x86_64'],'Handler':handler,'Role':att(name+'Role'),'Timeout':timeout,'MemorySize':memory,'Code':{'S3Bucket':ref('ArtifactBucket'),'S3Key':ref('CodeKey'),'S3ObjectVersion':ref('CodeVersion')},'Environment':{'Variables':env}}}
 r['WorkerFunction']['DependsOn']=['AnalysisRuntimeResourcePolicy','WorkerLogs']
 application_worker={'DATA_BUCKET':ref('DataBucket'),'APP_TABLE':ref('AppTable'),'JOBS_TABLE':ref('JobsTable'),'APPLICATION_QUEUE_ARN':att('ApplicationQueue'),'APPLICATION_DLQ_ARN':att('ApplicationDeadQueue')}
 application_dispatcher={'DATA_BUCKET':ref('DataBucket'),'APP_TABLE':ref('AppTable'),'JOBS_TABLE':ref('JobsTable'),'APPLICATION_QUEUE_URL':ref('ApplicationQueue'),'INVOCATION_QUEUE_URL':ref('InvocationQueue')}
 for name,handler,env,timeout in [('ApplicationWorker','services.business.application_worker.handler',application_worker,840),('ApplicationDispatcher','services.business.application_worker.dispatch_handler',application_dispatcher,45)]:
  r[name+'Function']={'Type':'AWS::Lambda::Function','Properties':{'FunctionName':'authority-delta-business-'+name.lower(),'Runtime':'python3.12','Architectures':['x86_64'],'Handler':handler,'Role':att(name+'Role'),'Timeout':timeout,'MemorySize':256,'Code':{'S3Bucket':ref('ArtifactBucket'),'S3Key':ref('CodeKey'),'S3ObjectVersion':ref('CodeVersion')},'Environment':{'Variables':env}}}
 invocation_env={'DATA_BUCKET':ref('DataBucket'),'APP_TABLE':ref('AppTable'),'JOBS_TABLE':ref('JobsTable'),'CLIENT_ID':ref('ClientId'),'REVIEWER_SUB':ref('ReviewerSub'),'REVIEWER_USERNAME':'okada'}
 r['InvocationGateFunction']={'Type':'AWS::Lambda::Function','Properties':{'FunctionName':'authority-delta-business-invocation-gate','Runtime':'python3.12','Architectures':['x86_64'],'Handler':'services.business.invocation_gate.handler','Role':att('InvocationGateRole'),'Timeout':29,'MemorySize':256,'Code':{'S3Bucket':ref('ArtifactBucket'),'S3Key':ref('CodeKey'),'S3ObjectVersion':ref('CodeVersion')},'Environment':{'Variables':invocation_env}}}
 invocation_worker={**invocation_env,'INVOCATION_QUEUE_ARN':att('InvocationQueue'),'INVOCATION_DLQ_ARN':att('InvocationDeadQueue')}
 r['InvocationWorkerFunction']={'Type':'AWS::Lambda::Function','Properties':{'FunctionName':'authority-delta-business-invocation-worker','Runtime':'python3.12','Architectures':['x86_64'],'Handler':'services.business.invocation_gate.worker_handler','Role':att('InvocationWorkerRole'),'Timeout':600,'MemorySize':256,'Code':{'S3Bucket':ref('ArtifactBucket'),'S3Key':ref('CodeKey'),'S3ObjectVersion':ref('CodeVersion')},'Environment':{'Variables':invocation_worker}}}
 for q in ['Queue','DeadQueue']:
  r[q+'Mapping']={'Type':'AWS::Lambda::EventSourceMapping','Properties':{'EventSourceArn':att(q),'FunctionName':ref('WorkerFunction'),'BatchSize':1,'MaximumBatchingWindowInSeconds':0,'FunctionResponseTypes':['ReportBatchItemFailures'],'ScalingConfig':{'MaximumConcurrency':2},'Enabled':True}}
 for q in ['ApplicationQueue','ApplicationDeadQueue']:
  r[q+'Mapping']={'Type':'AWS::Lambda::EventSourceMapping','Properties':{'EventSourceArn':att(q),'FunctionName':ref('ApplicationWorkerFunction'),'BatchSize':1,'MaximumBatchingWindowInSeconds':0,'FunctionResponseTypes':['ReportBatchItemFailures'],'ScalingConfig':{'MaximumConcurrency':2},'Enabled':True}}
 for q in ['InvocationQueue','InvocationDeadQueue']:
  r[q+'Mapping']={'Type':'AWS::Lambda::EventSourceMapping','Properties':{'EventSourceArn':att(q),'FunctionName':ref('InvocationWorkerFunction'),'BatchSize':1,'MaximumBatchingWindowInSeconds':0,'FunctionResponseTypes':['ReportBatchItemFailures'],'ScalingConfig':{'MaximumConcurrency':2},'Enabled':True}}
 r['RecoverySchedule']={'Type':'AWS::Events::Rule','Properties':{'ScheduleExpression':'rate(1 minute)','State':'ENABLED','Targets':[{'Id':'Dispatch','Arn':att('DispatcherFunction')} ]}}
 r['SchedulePermission']={'Type':'AWS::Lambda::Permission','Properties':{'Action':'lambda:InvokeFunction','FunctionName':ref('DispatcherFunction'),'Principal':'events.amazonaws.com','SourceArn':att('RecoverySchedule')}}
 r['ApplicationRecoverySchedule']={'Type':'AWS::Events::Rule','Properties':{'ScheduleExpression':'rate(1 minute)','State':'ENABLED','Targets':[{'Id':'Dispatch','Arn':att('ApplicationDispatcherFunction')} ]}}
 r['ApplicationSchedulePermission']={'Type':'AWS::Lambda::Permission','Properties':{'Action':'lambda:InvokeFunction','FunctionName':ref('ApplicationDispatcherFunction'),'Principal':'events.amazonaws.com','SourceArn':att('ApplicationRecoverySchedule')}}
 r['Integration']={'Type':'AWS::ApiGatewayV2::Integration','Properties':{'ApiId':ref('ExistingApiId'),'IntegrationType':'AWS_PROXY','IntegrationUri':att('ApiFunction'),'PayloadFormatVersion':'2.0','TimeoutInMillis':29000}}
 r['InvocationIntegration']={'Type':'AWS::ApiGatewayV2::Integration','Properties':{'ApiId':ref('ExistingApiId'),'IntegrationType':'AWS_PROXY','IntegrationUri':att('InvocationGateFunction'),'PayloadFormatVersion':'2.0','TimeoutInMillis':29000}}
 r['InvocationRoute']={'Type':'AWS::ApiGatewayV2::Route','Properties':{'ApiId':ref('ExistingApiId'),'RouteKey':'POST /business/objects/{object_id}/invocations','Target':sub('integrations/${InvocationIntegration}'),'AuthorizationType':'JWT','AuthorizerId':ref('ExistingAuthorizerId'),'AuthorizationScopes':['authority-delta/publish']}}
 r['InvocationStatusRoute']={'Type':'AWS::ApiGatewayV2::Route','Properties':{'ApiId':ref('ExistingApiId'),'RouteKey':'GET /business/objects/{object_id}/invocations/{operation_id}','Target':sub('integrations/${InvocationIntegration}'),'AuthorizationType':'JWT','AuthorizerId':ref('ExistingAuthorizerId'),'AuthorizationScopes':['authority-delta/read']}}
 r['InvocationPermission']={'Type':'AWS::Lambda::Permission','Properties':{'Action':'lambda:InvokeFunction','FunctionName':ref('InvocationGateFunction'),'Principal':'apigateway.amazonaws.com','SourceArn':sub('arn:${AWS::Partition}:execute-api:${AWS::Region}:${AWS::AccountId}:${ExistingApiId}/*/POST/business/objects/*/invocations')}}
 r['InvocationStatusPermission']={'Type':'AWS::Lambda::Permission','Properties':{'Action':'lambda:InvokeFunction','FunctionName':ref('InvocationGateFunction'),'Principal':'apigateway.amazonaws.com','SourceArn':sub('arn:${AWS::Partition}:execute-api:${AWS::Region}:${AWS::AccountId}:${ExistingApiId}/*/GET/business/objects/*/invocations/*')}}
 r['BusinessRoute']={'Type':'AWS::ApiGatewayV2::Route','Properties':{'ApiId':ref('ExistingApiId'),'RouteKey':'ANY /business/{proxy+}','Target':sub('integrations/${Integration}'),'AuthorizationType':'JWT','AuthorizerId':ref('ExistingAuthorizerId'),'AuthorizationScopes':['authority-delta/read']}}
 r['BusinessOptionsRoute']={'Type':'AWS::ApiGatewayV2::Route','Properties':{'ApiId':ref('ExistingApiId'),'RouteKey':'OPTIONS /business/{proxy+}','Target':sub('integrations/${Integration}'),'AuthorizationType':'NONE'}}
 r['ApiPermission']={'Type':'AWS::Lambda::Permission','Properties':{'Action':'lambda:InvokeFunction','FunctionName':ref('ApiFunction'),'Principal':'apigateway.amazonaws.com','SourceArn':sub('arn:${AWS::Partition}:execute-api:${AWS::Region}:${AWS::AccountId}:${ExistingApiId}/*/*/business/*')}}
 for k in ['AppTable','JobsTable','DataBucket','Queue','ApplicationQueue','InvocationQueue','ApiFunction','WorkerFunction','DispatcherFunction','ApplicationWorkerFunction','ApplicationDispatcherFunction','InvocationGateFunction','InvocationWorkerFunction']:t['Outputs'][k]={'Value':ref(k)}
 t['Outputs']['InvocationGateRoleArn']={'Value':att('InvocationGateRole')}
 t['Outputs']['QueueArn']={'Value':att('Queue')}
 t['Outputs']['ApplicationQueueArn']={'Value':att('ApplicationQueue')}
 return t

if __name__=='__main__':
 t=build();path=ROOT/'infra/business/template.json';path.write_text(json.dumps(t,indent=2)+'\n');print(path)
