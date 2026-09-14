"""Build the account-B publisher/canary stack without creating customer resources."""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ref = lambda name: {'Ref': name}
att = lambda name, attr='Arn': {'Fn::GetAtt': [name, attr]}
sub = lambda value: {'Fn::Sub': value}


def role(name, statements):
    return {'Type': 'AWS::IAM::Role', 'Properties': {'RoleName': name,
        'AssumeRolePolicyDocument': {'Version': '2012-10-17', 'Statement': [{
            'Effect': 'Allow', 'Principal': {'Service': 'lambda.amazonaws.com'},
            'Action': 'sts:AssumeRole'}]},
        'Policies': [{'PolicyName': 'BoundedCustomerApplication',
            'PolicyDocument': {'Version': '2012-10-17', 'Statement': statements}}]}}


def connector_role(name, source_role, external_id, statements):
    return {'Type': 'AWS::IAM::Role', 'Properties': {'RoleName': name,
        'MaxSessionDuration': 3600,
        'AssumeRolePolicyDocument': {'Version': '2012-10-17', 'Statement': [{
            'Sid': 'OnlyRegisteredSourceRoleWithExternalId',
            'Effect': 'Allow', 'Principal': {'AWS': sub(
                'arn:${AWS::Partition}:iam::${SourceAccountId}:root')},
            'Action': 'sts:AssumeRole', 'Condition': {
                'ArnEquals': {'aws:PrincipalArn': source_role},
                'StringEquals': {'sts:ExternalId': external_id}}}]},
        'Policies': [{'PolicyName': 'BoundedCustomerConnector',
            'PolicyDocument': {'Version': '2012-10-17', 'Statement': statements}}]}}


def allow(actions, resource):
    return {'Effect': 'Allow', 'Action': actions, 'Resource': resource}


def build():
    string = {'Type': 'String', 'MinLength': 1}
    parameters = {name: dict(string) for name in (
        'ArtifactBucket', 'CodeKey', 'CodeVersion', 'CodeSha256',
        'SourceAccountId', 'SourceDiscoveryRoleArn',
        'SourceApplicationWorkerRoleArn', 'SourceInvocationWorkerRoleArn', 'ExternalId',
        'ExternalIdHash', 'ConnectionId', 'GatewayArn',
        'PolicyEngineId',
        'PolicyEngineArn', 'RuntimeArn', 'RuntimeEndpointArn',
        'RequestRegistryTableName', 'SandboxLedgerTableName',
        'SandboxToolFunctionArn')}
    parameters['ArtifactBucket']['AllowedPattern'] = '^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$'
    parameters['SourceApplicationWorkerRoleArn']['AllowedPattern'] = '^arn:aws:iam::[0-9]{12}:role/authority-delta-application-worker$'
    parameters['SourceInvocationWorkerRoleArn']['AllowedPattern'] = '^arn:aws:iam::[0-9]{12}:role/authority-delta-invocation-worker$'
    parameters['SourceDiscoveryRoleArn']['AllowedPattern'] = '^arn:aws:iam::[0-9]{12}:role/ReadinessOpsAuthorityDeltaDeployer$'
    parameters['SourceAccountId']['AllowedPattern'] = '^[0-9]{12}$'
    parameters['ExternalId'].update(AllowedPattern='^[A-Za-z0-9+=,.@:/_-]{32,128}$',
                                    NoEcho=True)
    parameters['ExternalIdHash']['AllowedPattern'] = '^[0-9a-f]{64}$'
    parameters['GatewayArn']['AllowedPattern'] = '^arn:aws:bedrock-agentcore:ap-northeast-1:[0-9]{12}:gateway/[A-Za-z0-9_-]+$'
    parameters['ConnectionId']['AllowedPattern'] = '^conn-[A-Za-z0-9_-]{4,80}$'
    parameters['RuntimeArn']['AllowedPattern'] = '^arn:aws:bedrock-agentcore:ap-northeast-1:[0-9]{12}:runtime/[A-Za-z0-9_-]+$'
    parameters['RuntimeEndpointArn']['AllowedPattern'] = '^arn:aws:bedrock-agentcore:ap-northeast-1:[0-9]{12}:runtime/[A-Za-z0-9_-]+/runtime-endpoint/[A-Za-z0-9_-]+$'
    resources = {}
    resources['PublisherJournal'] = {'Type': 'AWS::DynamoDB::Table',
        'DeletionPolicy': 'Retain', 'UpdateReplacePolicy': 'Retain', 'Properties': {
            'BillingMode': 'PAY_PER_REQUEST',
            'AttributeDefinitions': [{'AttributeName': 'pk', 'AttributeType': 'S'},
                                     {'AttributeName': 'sk', 'AttributeType': 'S'}],
            'KeySchema': [{'AttributeName': 'pk', 'KeyType': 'HASH'},
                          {'AttributeName': 'sk', 'KeyType': 'RANGE'}],
            'SSESpecification': {'SSEEnabled': True},
            'PointInTimeRecoverySpecification': {'PointInTimeRecoveryEnabled': True}}}
    for name in ('Publisher', 'Canary', 'Invocation'):
        resources[name + 'Logs'] = {'Type': 'AWS::Logs::LogGroup', 'Properties': {
            'LogGroupName': '/aws/lambda/authority-delta-customer-' + name.lower(),
            'RetentionInDays': 14}}
    logs = lambda name: allow(['logs:CreateLogStream', 'logs:PutLogEvents'],
                              att(name + 'Logs'))
    resources['CanaryRole'] = role('authority-delta-customer-canary', [logs('Canary'),
        allow('dynamodb:GetItem', sub('arn:${AWS::Partition}:dynamodb:${AWS::Region}:${AWS::AccountId}:table/${RequestRegistryTableName}')),
        allow('dynamodb:Scan', sub('arn:${AWS::Partition}:dynamodb:${AWS::Region}:${AWS::AccountId}:table/${SandboxLedgerTableName}')),
        allow('bedrock-agentcore:GetAgentRuntimeEndpoint', [ref('RuntimeArn'), ref('RuntimeEndpointArn')]),
        allow(['bedrock-agentcore:InvokeAgentRuntime', 'bedrock-agentcore:StopRuntimeSession'], [ref('RuntimeArn'), ref('RuntimeEndpointArn')])])
    resources['InvocationRole'] = role('authority-delta-customer-invocation', [logs('Invocation'),
        allow('dynamodb:GetItem', att('PublisherJournal')),
        allow('dynamodb:GetItem', sub('arn:${AWS::Partition}:dynamodb:${AWS::Region}:${AWS::AccountId}:table/${RequestRegistryTableName}')),
        allow('dynamodb:Scan', sub('arn:${AWS::Partition}:dynamodb:${AWS::Region}:${AWS::AccountId}:table/${SandboxLedgerTableName}')),
        allow('bedrock-agentcore:GetAgentRuntimeEndpoint', [ref('RuntimeArn'), ref('RuntimeEndpointArn')]),
        allow(['bedrock-agentcore:InvokeAgentRuntime', 'bedrock-agentcore:StopRuntimeSession'], [ref('RuntimeArn'), ref('RuntimeEndpointArn')])])
    resources['PublisherRole'] = role('authority-delta-customer-publisher', [logs('Publisher'),
        allow(['dynamodb:GetItem', 'dynamodb:PutItem', 'dynamodb:DeleteItem',
               'dynamodb:TransactWriteItems'], att('PublisherJournal')),
        allow(['bedrock-agentcore:CreatePolicy', 'bedrock-agentcore:GetPolicy',
               'bedrock-agentcore:DeletePolicy', 'bedrock-agentcore:ListPolicies'], [ref('PolicyEngineArn'),
                    sub('${PolicyEngineArn}/*')]),
        allow('bedrock-agentcore:ManageResourceScopedPolicy', ref('GatewayArn')),
        allow(['bedrock-agentcore:GetGateway',
               'bedrock-agentcore:InvokeGateway',
               'bedrock-agentcore:ListGatewayTargets',
               'bedrock-agentcore:GetGatewayTarget'], ref('GatewayArn')),
        allow('lambda:InvokeFunction', sub('${CanaryFunction.Arn}:*'))])
    code = {'S3Bucket': ref('ArtifactBucket'), 'S3Key': ref('CodeKey'),
            'S3ObjectVersion': ref('CodeVersion')}
    for name, handler, role_name, timeout in (
            ('Publisher', 'services.customer_publisher.handler.handler', 'PublisherRole', 600),
            ('Canary', 'services.customer_publisher.handler.canary_handler', 'CanaryRole', 180),
            ('Invocation', 'services.customer_publisher.handler.invocation_handler', 'InvocationRole', 300)):
        resources[name + 'Function'] = {'Type': 'AWS::Lambda::Function', 'Properties': {
            'FunctionName': 'authority-delta-customer-' + name.lower(),
            'Runtime': 'python3.12', 'Architectures': ['x86_64'], 'Handler': handler,
            'Role': att(role_name), 'Timeout': timeout, 'MemorySize': 256,
            'Code': code, 'Environment': {'Variables': {
                'CONNECTION_ID': ref('ConnectionId'),
                'PUBLISHER_JOURNAL_TABLE': ref('PublisherJournal')}}}}
        resources[name + 'Version'] = {'Type': 'AWS::Lambda::Version',
            'Properties': {'FunctionName': ref(name + 'Function'),
                           'CodeSha256': ref('CodeSha256')}}
        resources[name + 'Alias'] = {'Type': 'AWS::Lambda::Alias', 'Properties': {
            'Name': 'live', 'FunctionName': ref(name + 'Function'),
            'FunctionVersion': att(name + 'Version', 'Version')}}
    resources['CanaryPermission'] = {'Type': 'AWS::Lambda::Permission', 'Properties': {
        'Action': 'lambda:InvokeFunction', 'FunctionName': ref('CanaryAlias'),
        'Principal': att('PublisherRole')}}
    resources['DiscoveryRole'] = connector_role('authority-delta-customer-discovery',
        ref('SourceDiscoveryRoleArn'), ref('ExternalId'), [
            allow('dynamodb:GetItem', att('PublisherJournal')),
            allow('iam:GetRolePolicy', att('PublisherRole')),
            allow(['bedrock-agentcore:GetGateway', 'bedrock-agentcore:GetGatewayTarget',
                   'bedrock-agentcore:GetPolicyEngine', 'bedrock-agentcore:GetAgentRuntime',
                   'bedrock-agentcore:GetAgentRuntimeEndpoint',
                   'bedrock-agentcore:GetResourcePolicy'],
                  [ref('GatewayArn'), ref('PolicyEngineArn'), ref('RuntimeArn'),
                   ref('RuntimeEndpointArn')]),
            allow('bedrock-agentcore:GetPolicy', [ref('PolicyEngineArn'),
                  sub('${PolicyEngineArn}/*')]),
            allow(['bedrock-agentcore:ListGatewayTargets', 'bedrock-agentcore:ListPolicies'], '*'),
            allow(['dynamodb:DescribeTable', 'dynamodb:GetItem', 'dynamodb:Scan'], [
                sub('arn:${AWS::Partition}:dynamodb:${AWS::Region}:${AWS::AccountId}:table/${RequestRegistryTableName}'),
                sub('arn:${AWS::Partition}:dynamodb:${AWS::Region}:${AWS::AccountId}:table/${SandboxLedgerTableName}')]),
            allow('lambda:GetFunctionConfiguration', [ref('SandboxToolFunctionArn'),
                ref('PublisherAlias'), ref('CanaryAlias'), ref('InvocationAlias')]),
            allow('cloudformation:DescribeStacks', [
                sub('arn:${AWS::Partition}:cloudformation:${AWS::Region}:${AWS::AccountId}:stack/authority-delta-customer-baseline/*'),
                sub('arn:${AWS::Partition}:cloudformation:${AWS::Region}:${AWS::AccountId}:stack/authority-delta-vendor-runtimes/*'),
                sub('arn:${AWS::Partition}:cloudformation:${AWS::Region}:${AWS::AccountId}:stack/authority-delta-customer-publisher/*')])])
    resources['PublishInvokeRole'] = connector_role(
        'authority-delta-customer-publish-invoke',
        ref('SourceApplicationWorkerRoleArn'), ref('ExternalId'), [
            allow('lambda:InvokeFunction', ref('PublisherAlias'))])
    resources['RuntimeInvokeRole'] = connector_role(
        'authority-delta-customer-runtime-invoke',
        ref('SourceInvocationWorkerRoleArn'), ref('ExternalId'), [
            allow('lambda:InvokeFunction', ref('InvocationAlias'))])
    return {'AWSTemplateFormatVersion': '2010-09-09',
        'Description': 'Account-B bounded Policy publisher and isolated VendorPayment canary. No business approval UI.',
        'Parameters': parameters, 'Resources': resources,
        'Outputs': {'PublisherFunctionArn': {'Value': ref('PublisherAlias')},
            'CanaryFunctionArn': {'Value': ref('CanaryAlias')},
            'CanaryRoleArn': {'Value': att('CanaryRole')},
            'InvocationFunctionArn': {'Value': ref('InvocationAlias')},
            'InvocationRoleArn': {'Value': att('InvocationRole')},
            'DiscoveryRoleArn': {'Value': att('DiscoveryRole')},
            'PublisherInvokeRoleArn': {'Value': att('PublishInvokeRole')},
            'RuntimeInvokeRoleArn': {'Value': att('RuntimeInvokeRole')},
            'ExternalIdHash': {'Value': ref('ExternalIdHash')},
            'PublisherJournalTable': {'Value': ref('PublisherJournal')}}}


if __name__ == '__main__':
    path = ROOT / 'infra/customer-publisher/template.json'
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(build(), indent=2) + '\n')
    print(path)
