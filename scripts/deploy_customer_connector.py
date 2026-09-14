#!/usr/bin/env python3
"""Deploy and read back the bounded account-B connector from CodeBuild.

The worker is deliberately account-agnostic except that it rejects account A.
It requires an existing customer baseline and fixed V1/V2 Runtime stack.  Every
write is a named CloudFormation update or a content-addressed, versioned object;
rerunning the same source and ExternalId resumes the same resources.
"""
from __future__ import annotations

import base64
import copy
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / 'src'), str(ROOT / 'scripts')]

from authority_delta.canonical import sha256_json
from authority_delta.evidence_json import encode_evidence
from authority_delta.registry import FixtureBundle
from build_business_artifacts import build as build_artifact
from build_customer_adapter_registry import build as build_registry
from build_registry_seed import build_transaction
from deploy_baseline import all_records
from authority_delta.gateway_probe import validate_endpoint
from verify_aws import (TOOL_ARGUMENTS, observed_at, safe_error, save_evidence,
                        sdk_evidence)


ACCOUNT_A = '538522204923'
REGION = 'ap-northeast-1'
BASELINE_STACK = 'authority-delta-customer-baseline'
RUNTIME_STACK = 'authority-delta-vendor-runtimes'
CONNECTOR_STACK = 'authority-delta-customer-publisher'
SCOPE = 'ACCOUNT_B_CUSTOMER_CONNECTOR_DEPLOYMENT_NO_BUSINESS_PUBLICATION'
ROLE = 'ReadinessOpsAuthorityDeltaDeployer'
SOURCE_ROLE = f'arn:aws:iam::{ACCOUNT_A}:role/authority-delta-application-worker'
SOURCE_INVOCATION_WORKER_ROLE = f'arn:aws:iam::{ACCOUNT_A}:role/authority-delta-invocation-worker'
SOURCE_DISCOVERY_ROLE = f'arn:aws:iam::{ACCOUNT_A}:role/{ROLE}'
PUBLISHER_ROLE = 'authority-delta-customer-publisher'
PUBLISHER_POLICY = 'BoundedCustomerApplication'
DISCOVERY_ROLE = 'authority-delta-customer-discovery'
DISCOVERY_POLICY = 'BoundedCustomerConnector'
PUBLISHER_JOURNAL_ACTIONS = {
    'dynamodb:GetItem', 'dynamodb:PutItem', 'dynamodb:DeleteItem',
    'dynamodb:TransactWriteItems'}
PUBLISHER_POLICY_GATEWAY_ACTIONS = {
    'bedrock-agentcore:GetGateway', 'bedrock-agentcore:InvokeGateway',
    'bedrock-agentcore:ListGatewayTargets',
    'bedrock-agentcore:GetGatewayTarget'}


def stack(session, name, *, optional=False):
    try:
        value = session.client('cloudformation').describe_stacks(StackName=name)['Stacks'][0]
    except Exception as exc:
        if optional and getattr(exc, 'response', {}).get('Error', {}).get('Code') in (
                'ValidationError', 'ResourceNotFoundException'):
            return None
        raise
    if value.get('StackStatus') not in ('CREATE_COMPLETE', 'UPDATE_COMPLETE'):
        raise ValueError(f'{name} is not in a stable completed state')
    return value


def outputs(value):
    return {item['OutputKey']: item['OutputValue'] for item in value.get('Outputs', [])}


def parameters(value):
    return {item['ParameterKey']: item['ParameterValue'] for item in value.get('Parameters', [])}


def require_identity(identity, environment):
    account = identity.get('Account', '')
    expected = environment.get('AD_EXPECTED_ACCOUNT', '')
    if not re.fullmatch(r'[0-9]{12}', account) or account != expected or account == ACCOUNT_A:
        raise ValueError('A distinct exact account-B identity is required')
    if environment.get('AD_REGION') != REGION:
        raise ValueError('Customer connector Region must be ap-northeast-1')
    if not re.fullmatch(
            rf'arn:aws:sts::{account}:assumed-role/{ROLE}/[^/]+', identity.get('Arn', '')):
        raise ValueError('Customer connector deployment requires the owned CodeBuild role')
    if not environment.get('CODEBUILD_BUILD_ID', '').startswith('authority-delta-deploy:'):
        raise ValueError('Customer connector deployment requires the owned CodeBuild project')
    if environment.get('AD_SOURCE_APPLICATION_WORKER_ROLE_ARN') != SOURCE_ROLE:
        raise ValueError('Source application worker role differs from account A')
    external_id = environment.get('AD_EXTERNAL_ID', '')
    if not re.fullmatch(r'[A-Za-z0-9+=,.@:/_-]{32,128}', external_id):
        raise ValueError('Connector ExternalId is missing or malformed')
    if not re.fullmatch(r'[0-9a-f]{64}', environment.get('AD_SOURCE_SHA256', '')):
        raise ValueError('Deployment source digest is missing')
    return account, external_id


def upload_artifact(session, bucket, path, digest):
    s3 = session.client('s3')
    if s3.get_bucket_versioning(Bucket=bucket).get('Status') != 'Enabled':
        raise ValueError('Customer artifact bucket is not versioned')
    key = f'customer-connector-code/{digest}/lambda.zip'
    raw = Path(path).read_bytes()
    try:
        head = s3.head_object(Bucket=bucket, Key=key)
        if head.get('Metadata', {}).get('sha256') != digest:
            raise ValueError('Existing content-addressed connector artifact differs')
        version = head.get('VersionId')
    except Exception as exc:
        if getattr(exc, 'response', {}).get('Error', {}).get('Code') not in (
                '404', 'NoSuchKey', 'NotFound'):
            raise
        response = s3.put_object(Bucket=bucket, Key=key, Body=raw,
            Metadata={'sha256': digest}, ContentType='application/zip')
        version = response.get('VersionId')
    if not version or version == 'null':
        raise ValueError('Connector artifact has no immutable version')
    stored = s3.get_object(Bucket=bucket, Key=key, VersionId=version)
    body = stored['Body']
    try:
        observed = body.read(len(raw) + 1)
    finally:
        body.close()
    if stored.get('VersionId') != version or observed != raw:
        raise ValueError('Connector artifact version readback differs')
    return {'bucket': bucket, 'key': key, 'version_id': version,
            'sha256': digest, 'size_bytes': len(raw)}


def deploy_stack(run, template, name, values):
    run(['aws', 'cloudformation', 'deploy', '--region', REGION, '--no-cli-pager',
        '--template-file', str(template), '--stack-name', name,
        '--capabilities', 'CAPABILITY_NAMED_IAM', '--no-fail-on-empty-changeset',
        '--parameter-overrides', *[key + '=' + value for key, value in values.items()],
        '--tags', 'Project=ReadinessOpsAuthorityDelta', 'DataClass=SyntheticOnly'],
        cwd=ROOT, check=True)


def verify_publisher_journal_permissions(session, account, table_name,
                                         gateway_arn=None):
    """Require exact journal and optional resource-scoped Policy permissions."""
    if (not re.fullmatch(r'[0-9]{12}', account or '')
            or not isinstance(table_name, str) or not table_name):
        raise ValueError('Publisher journal permission binding is incomplete')
    response = session.client('iam').get_role_policy(
        RoleName=PUBLISHER_ROLE, PolicyName=PUBLISHER_POLICY)
    metadata = response.get('ResponseMetadata', {})
    document = response.get('PolicyDocument')
    if (metadata.get('HTTPStatusCode') != 200 or not metadata.get('RequestId')
            or not isinstance(document, dict)):
        raise ValueError('Publisher journal role policy lacks successful AWS evidence')
    expected_resource = (
        f'arn:aws:dynamodb:{REGION}:{account}:table/{table_name}')
    matches = []
    for statement in document.get('Statement', []):
        actions = statement.get('Action', [])
        if isinstance(actions, str):
            actions = [actions]
        resource = statement.get('Resource')
        resources = resource if isinstance(resource, list) else [resource]
        if (statement.get('Effect') == 'Allow'
                and expected_resource in resources
                and any(isinstance(action, str)
                        and action.startswith('dynamodb:') for action in actions)):
            matches.append(set(actions))
    if matches != [PUBLISHER_JOURNAL_ACTIONS]:
        raise ValueError('Publisher journal permissions are not the exact qualified set')
    scoped = gateway_access = None
    if gateway_arn is not None:
        expected_gateway = (
            f'arn:aws:bedrock-agentcore:{REGION}:{account}:gateway/')
        if (not isinstance(gateway_arn, str)
                or not gateway_arn.startswith(expected_gateway)):
            raise ValueError('Publisher gateway permission binding is invalid')
        scoped_matches = []
        for statement in document.get('Statement', []):
            actions = statement.get('Action', [])
            actions = [actions] if isinstance(actions, str) else actions
            resources = statement.get('Resource', [])
            resources = [resources] if isinstance(resources, str) else resources
            if (statement.get('Effect') == 'Allow' and gateway_arn in resources
                    and any(isinstance(action, str)
                            and action.startswith('bedrock-agentcore:Manage')
                            for action in actions)):
                scoped_matches.append(set(actions))
        expected = {'bedrock-agentcore:ManageResourceScopedPolicy'}
        if scoped_matches != [expected]:
            raise ValueError('Publisher resource-scoped Policy permission is not exact')
        scoped = {'gateway_arn': gateway_arn, 'actions': sorted(expected)}
        gateway_matches = []
        for statement in document.get('Statement', []):
            actions = statement.get('Action', [])
            actions = [actions] if isinstance(actions, str) else actions
            resources = statement.get('Resource', [])
            resources = [resources] if isinstance(resources, str) else resources
            if (statement.get('Effect') == 'Allow' and gateway_arn in resources
                    and any(action in PUBLISHER_POLICY_GATEWAY_ACTIONS
                            for action in actions)):
                gateway_matches.append(set(actions))
        if gateway_matches != [PUBLISHER_POLICY_GATEWAY_ACTIONS]:
            raise ValueError('Publisher Policy gateway validation permission is not exact')
        gateway_access = {'gateway_arn': gateway_arn,
            'actions': sorted(PUBLISHER_POLICY_GATEWAY_ACTIONS)}
    return {'role_name': PUBLISHER_ROLE, 'policy_name': PUBLISHER_POLICY,
        'journal_table': table_name, 'journal_table_arn': expected_resource,
        'actions': sorted(PUBLISHER_JOURNAL_ACTIONS),
        'resource_scoped_policy': scoped,
        'policy_gateway_validation': gateway_access,
        'request': sdk_evidence(response)}


def verify_discovery_recovery_permissions(session, account, policy_engine_arn):
    """Read back exact Policy inspection access used by Account-A recovery."""
    prefix = f'arn:aws:bedrock-agentcore:{REGION}:{account}:policy-engine/'
    if (not isinstance(policy_engine_arn, str)
            or not policy_engine_arn.startswith(prefix)
            or policy_engine_arn.endswith('/*')):
        raise ValueError('Discovery Policy Engine binding is invalid')
    response = session.client('iam').get_role_policy(
        RoleName=DISCOVERY_ROLE, PolicyName=DISCOVERY_POLICY)
    metadata = response.get('ResponseMetadata', {})
    document = response.get('PolicyDocument')
    if (metadata.get('HTTPStatusCode') != 200 or not metadata.get('RequestId')
            or not isinstance(document, dict)):
        raise ValueError('Discovery role policy lacks successful AWS evidence')
    matches, prohibited = [], []
    forbidden = {'bedrock-agentcore:CreatePolicy',
        'bedrock-agentcore:UpdatePolicy', 'bedrock-agentcore:DeletePolicy',
        'bedrock-agentcore:ManageAdminPolicy',
        'bedrock-agentcore:ManageResourceScopedPolicy'}
    for statement in document.get('Statement', []):
        actions = statement.get('Action', [])
        actions = [actions] if isinstance(actions, str) else actions
        resources = statement.get('Resource', [])
        resources = [resources] if isinstance(resources, str) else resources
        prohibited.extend(action for action in actions if action in forbidden)
        if ('bedrock-agentcore:GetPolicy' in actions
                and statement.get('Effect') == 'Allow'):
            matches.append((set(actions), set(resources)))
    expected_resources = {policy_engine_arn, policy_engine_arn + '/*'}
    if (matches != [({'bedrock-agentcore:GetPolicy'}, expected_resources)]
            or prohibited):
        raise ValueError('Discovery Policy read permission is not exact')
    return {'role_name': DISCOVERY_ROLE, 'policy_name': DISCOVERY_POLICY,
        'policy_engine_arn': policy_engine_arn,
        'actions': ['bedrock-agentcore:GetPolicy'],
        'resources': sorted(expected_resources), 'request': sdk_evidence(response)}


def observe_customer(session, account):
    baseline_stack = stack(session, BASELINE_STACK)
    runtime_stack = stack(session, RUNTIME_STACK)
    baseline, runtimes = outputs(baseline_stack), outputs(runtime_stack)
    required_baseline = {'GatewayIdentifier', 'GatewayArn', 'GatewayUrl',
        'PolicyEngineId', 'PolicyEngineArn', 'RequestRegistryTableName',
        'SandboxLedgerTableName', 'SandboxToolFunctionArn'}
    required_runtime = {f'V2{name}' for name in (
        'RuntimeArn', 'RuntimeId', 'RuntimeVersion', 'EndpointArn',
        'EndpointName', 'ExecutionRoleArn')}
    if not required_baseline.issubset(baseline) or not required_runtime.issubset(runtimes):
        raise ValueError('Customer baseline or V2 Runtime outputs are incomplete')
    prefix = f'arn:aws:bedrock-agentcore:{REGION}:{account}:'
    if (baseline['GatewayArn'] != prefix + 'gateway/' + baseline['GatewayIdentifier']
            or baseline['PolicyEngineArn'].split(':')[4] != account
            or runtimes['V2RuntimeArn'] != prefix + 'runtime/' + runtimes['V2RuntimeId']
            or runtimes['V2EndpointArn'] != runtimes['V2RuntimeArn'] +
                '/runtime-endpoint/' + runtimes['V2EndpointName']
            or not runtimes['V2ExecutionRoleArn'].startswith(f'arn:aws:iam::{account}:role/')):
        raise ValueError('Customer resource ARNs do not belong to account B')
    control = session.client('bedrock-agentcore-control')
    gateway = control.get_gateway(gatewayIdentifier=baseline['GatewayIdentifier'])
    engine = control.get_policy_engine(policyEngineId=baseline['PolicyEngineId'])
    if (gateway.get('status') != 'READY' or gateway.get('authorizerType') != 'AWS_IAM'
            or gateway.get('gatewayArn') != baseline['GatewayArn']
            or gateway.get('gatewayUrl') != baseline['GatewayUrl']
            or engine.get('status') != 'ACTIVE'
            or engine.get('policyEngineArn') != baseline['PolicyEngineArn']
            or gateway.get('policyEngineConfiguration') != {
                'mode': 'ENFORCE', 'arn': baseline['PolicyEngineArn']}):
        raise ValueError('Customer Gateway or Policy Engine binding differs')
    validate_endpoint(gateway['gatewayUrl'], baseline['GatewayIdentifier'], REGION)
    page = control.list_gateway_targets(gatewayIdentifier=baseline['GatewayIdentifier'])
    if page.get('nextToken') or len(page.get('items', [])) != 1:
        raise ValueError('Customer Gateway target is missing or ambiguous')
    target = control.get_gateway_target(gatewayIdentifier=baseline['GatewayIdentifier'],
                                        targetId=page['items'][0]['targetId'])
    if (target.get('status') != 'READY' or target.get('name') != 'VendorPaymentTools'
            or target.get('gatewayArn') != baseline['GatewayArn']):
        raise ValueError('Customer Gateway target binding differs')
    target_lambda = target.get('targetConfiguration', {}).get('mcp', {}).get('lambda', {})
    tools = target_lambda.get('toolSchema', {}).get('inlinePayload', [])
    if (target_lambda.get('lambdaArn') != baseline['SandboxToolFunctionArn']
            or len(tools) != len(TOOL_ARGUMENTS)
            or {tool.get('name') for tool in tools} != set(TOOL_ARGUMENTS)):
        raise ValueError('Customer protected tool target or schema differs')
    for tool in tools:
        schema = tool.get('inputSchema', {})
        argument = TOOL_ARGUMENTS[tool['name']]
        if (schema.get('type') != 'object' or schema.get('required') != [argument]
                or set(schema.get('properties', {})) != {argument}
                or schema['properties'][argument].get('type') != 'string'):
            raise ValueError('Customer protected tool request-ID contract differs')
    function = session.client('lambda').get_function_configuration(
        FunctionName=baseline['SandboxToolFunctionArn'])
    environment = function.get('Environment', {}).get('Variables', {})
    connection = environment.get('CONNECTION_ID')
    if (function.get('State') != 'Active' or function.get('LastUpdateStatus') != 'Successful'
            or environment != {'CONNECTION_ID': connection,
                'REQUEST_REGISTRY_TABLE': baseline['RequestRegistryTableName'],
                'SANDBOX_LEDGER_TABLE': baseline['SandboxLedgerTableName']}
            or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.:-]{2,127}', connection or '')):
        raise ValueError('Customer sandbox function binding differs')
    fixtures = FixtureBundle.load(ROOT / 'fixtures/decision_cases.json')
    expected_registry = [item['Put']['Item'] for item in build_transaction(
        fixtures, baseline['RequestRegistryTableName'])]
    ddb = session.client('dynamodb')
    registry = all_records(ddb, baseline['RequestRegistryTableName'])
    if sorted(registry, key=lambda x: x['request_id']['S']) != sorted(
            expected_registry, key=lambda x: x['request_id']['S']):
        raise ValueError('Customer immutable request registry differs')
    runtime = control.get_agent_runtime(agentRuntimeId=runtimes['V2RuntimeId'],
        agentRuntimeVersion=runtimes['V2RuntimeVersion'])
    endpoint = control.get_agent_runtime_endpoint(agentRuntimeId=runtimes['V2RuntimeId'],
        endpointName=runtimes['V2EndpointName'])
    if (runtime.get('status') != 'READY'
            or runtime.get('agentRuntimeArn') != runtimes['V2RuntimeArn']
            or runtime.get('agentRuntimeVersion') != runtimes['V2RuntimeVersion']
            or runtime.get('roleArn') != runtimes['V2ExecutionRoleArn']
            or endpoint.get('status') != 'READY'
            or endpoint.get('liveVersion') != runtimes['V2RuntimeVersion']
            or endpoint.get('agentRuntimeArn') != runtimes['V2RuntimeArn']
            or endpoint.get('agentRuntimeEndpointArn') != runtimes['V2EndpointArn']
            or endpoint.get('name') != runtimes['V2EndpointName']):
        raise ValueError('Customer V2 Runtime binding differs')
    expected_runtime_environment = {'AD_ACCOUNT_ID': account, 'AD_REGION': REGION,
        'AD_GATEWAY_URL': baseline['GatewayUrl'],
        'AD_GATEWAY_ID': baseline['GatewayIdentifier'],
        'AD_REGISTRY_TABLE': baseline['RequestRegistryTableName'],
        'AD_EXPECTED_ROLE_NAME': runtimes['V2ExecutionRoleArn'].rsplit('/', 1)[1]}
    if (runtime.get('environmentVariables') != expected_runtime_environment
            or runtime.get('authorizerConfiguration')
            or runtime.get('protocolConfiguration') != {'serverProtocol': 'HTTP'}):
        raise ValueError('Customer V2 Runtime environment or protocol differs')
    return {'baseline_stack': baseline_stack, 'runtime_stack': runtime_stack,
        'baseline': baseline, 'runtimes': runtimes, 'connection_id': connection,
        'target_id': target['targetId'], 'target_name': target['name'],
        'registry_hash': sha256_json(sorted(registry,
            key=lambda x: x['request_id']['S'])),
        'ledger_hash': sha256_json(sorted(all_records(
            ddb, baseline['SandboxLedgerTableName']),
            key=lambda x: json.dumps(x, sort_keys=True))),
        'api_evidence': {'gateway': sdk_evidence(gateway), 'engine': sdk_evidence(engine),
            'target': sdk_evidence(target), 'runtime': sdk_evidence(runtime),
            'endpoint': sdk_evidence(endpoint)}}


def connector_parameters(observed, artifact, external_id):
    base, runtimes = observed['baseline'], observed['runtimes']
    return {'ArtifactBucket': artifact['bucket'], 'CodeKey': artifact['key'],
        'CodeVersion': artifact['version_id'],
        'CodeSha256': base64.b64encode(bytes.fromhex(artifact['sha256'])).decode(),
        'SourceAccountId': ACCOUNT_A,
        'SourceDiscoveryRoleArn': SOURCE_DISCOVERY_ROLE,
        'SourceApplicationWorkerRoleArn': SOURCE_ROLE,
        'SourceInvocationWorkerRoleArn': SOURCE_INVOCATION_WORKER_ROLE,
        'ExternalId': external_id,
        'ExternalIdHash': hashlib.sha256(external_id.encode()).hexdigest(),
        'ConnectionId': observed['connection_id'], 'GatewayArn': base['GatewayArn'],
        'PolicyEngineId': base['PolicyEngineId'], 'PolicyEngineArn': base['PolicyEngineArn'],
        'RuntimeArn': runtimes['V2RuntimeArn'], 'RuntimeEndpointArn': runtimes['V2EndpointArn'],
        'RequestRegistryTableName': base['RequestRegistryTableName'],
        'SandboxLedgerTableName': base['SandboxLedgerTableName'],
        'SandboxToolFunctionArn': base['SandboxToolFunctionArn']}


def runtime_policy_matches(policy, expected):
    """Ignore order only in the two principal lists; preserve all other checks."""
    def normalize(document):
        result = copy.deepcopy(document)
        for statement in result.get('Statement', []):
            principal = statement.get('Principal')
            if isinstance(principal, dict):
                values = principal.get('AWS')
                if isinstance(values, list) and all(isinstance(v, str) for v in values):
                    principal['AWS'] = sorted(values)
            condition = statement.get('Condition', {}).get('ArnNotEquals', {})
            values = condition.get('aws:PrincipalArn')
            if isinstance(values, list) and all(isinstance(v, str) for v in values):
                condition['aws:PrincipalArn'] = sorted(values)
        return result
    return normalize(policy) == normalize(expected)


def update_runtime_policy(session, observed, canary_role, invocation_role, run):
    current = parameters(observed['runtime_stack'])
    expected = set(json.loads((ROOT / 'infra/vendor-runtimes/template.json').read_text())['Parameters'])
    # Account B can be upgraded from the pre-invocation stack.  Until the
    # connector's dedicated role is deployed, the already-authorized deployer
    # is the only safe seed for the newly introduced parameter.
    legacy_expected = expected - {'NormalInvocationRoleArn'}
    if not legacy_expected.issubset(current) or current.get('DeployerRoleArn') != (
            f"arn:aws:iam::{observed['account']}:role/{ROLE}"):
        raise ValueError('Existing Runtime stack parameters or deployer role differ')
    current.setdefault('NormalInvocationRoleArn', current['DeployerRoleArn'])
    current['ApplicationCanaryRoleArn'] = canary_role
    current['NormalInvocationRoleArn'] = invocation_role
    deploy_stack(run, ROOT / 'infra/vendor-runtimes/template.json', RUNTIME_STACK,
                 {key: current[key] for key in expected})
    refreshed = stack(session, RUNTIME_STACK)
    if outputs(refreshed).get('V2RuntimeArn') != observed['runtimes']['V2RuntimeArn']:
        raise ValueError('Runtime policy update replaced the V2 Runtime binding')
    policy = json.loads(session.client('bedrock-agentcore-control').get_resource_policy(
        resourceArn=observed['runtimes']['V2RuntimeArn'])['policy'])
    deployer = current['DeployerRoleArn']
    invoke = ['bedrock-agentcore:InvokeAgentRuntime',
              'bedrock-agentcore:StopRuntimeSession']
    deny = ['bedrock-agentcore:InvokeAgentRuntime',
        'bedrock-agentcore:InvokeAgentRuntimeForUser',
        'bedrock-agentcore:InvokeAgentRuntimeCommand',
        'bedrock-agentcore:InvokeAgentRuntimeCommandShell',
        'bedrock-agentcore:InvokeAgentRuntimeWithWebSocketStream',
        'bedrock-agentcore:InvokeAgentRuntimeWithWebSocketStreamForUser',
        'bedrock-agentcore:StopRuntimeSession']
    runtime_arn = observed['runtimes']['V2RuntimeArn']
    expected_policy = {'Version': '2012-10-17', 'Statement': [
        {'Sid': 'PermitOnlyDeploymentCanaryAndInvocation', 'Effect': 'Allow',
         'Principal': {'AWS': [deployer, canary_role, invocation_role]}, 'Action': invoke,
         'Resource': runtime_arn},
        {'Sid': 'DenyOtherCallers', 'Effect': 'Deny', 'Principal': '*',
         'Action': deny, 'Resource': runtime_arn,
         'Condition': {'ArnNotEquals': {
             'aws:PrincipalArn': [deployer, canary_role, invocation_role]}}}]}
    if not runtime_policy_matches(policy, expected_policy):
        raise ValueError('V2 Runtime resource policy principals differ')
    return {'stack_id': refreshed['StackId'], 'policy_hash': sha256_json(policy),
            'canary_role_arn': canary_role,
            'invocation_role_arn': invocation_role,
            'deployer_role_arn': deployer}


def observed_binding(observed, connector, external_id):
    base, runtimes = observed['baseline'], observed['runtimes']
    return {'schema_version': '1.0',
        'source_authority': 'aws:customer-connector:' + connector['stack_id'],
        'connection_id': observed['connection_id'],
        'target_account_id': observed['account'], 'target_region': REGION,
        'gateway_arn': base['GatewayArn'], 'gateway_id': base['GatewayIdentifier'],
        'policy_engine_id': base['PolicyEngineId'], 'target_id': observed['target_id'],
        'target_name': observed['target_name'],
        'runtime': {'release_id': 'V2', 'runtime_id': runtimes['V2RuntimeId'],
            'runtime_arn': runtimes['V2RuntimeArn'],
            'runtime_version': runtimes['V2RuntimeVersion'],
            'endpoint_name': runtimes['V2EndpointName'],
            'endpoint_arn': runtimes['V2EndpointArn'],
            'execution_role_arn': runtimes['V2ExecutionRoleArn']},
        'discovery_role_arn': connector['outputs']['DiscoveryRoleArn'],
        'publisher_invoke_role_arn': connector['outputs']['PublisherInvokeRoleArn'],
        'external_id': external_id,
        'publisher_function_arn': connector['outputs']['PublisherFunctionArn'],
        'runtime_invoke_role_arn': connector['outputs']['RuntimeInvokeRoleArn'],
        'invocation_function_arn': connector['outputs']['InvocationFunctionArn'],
        'canary_function_arn': connector['outputs']['CanaryFunctionArn'],
        'request_registry_table_name': base['RequestRegistryTableName'],
        'sandbox_ledger_table_name': base['SandboxLedgerTableName']}


def execute(session, environment, report, *, run=subprocess.run):
    identity = session.client('sts').get_caller_identity()
    account, external_id = require_identity(identity, environment)
    report.update(account=account, region=REGION, caller_arn=identity['Arn'])
    observed = observe_customer(session, account)
    observed['account'] = account
    report['baseline_readback'] = {key: observed[key] for key in (
        'connection_id', 'target_id', 'target_name', 'registry_hash', 'ledger_hash',
        'api_evidence')}
    bucket = environment['AD_ARTIFACT_BUCKET']
    bootstrap = outputs(stack(session, 'authority-delta-bootstrap'))
    if bootstrap.get('ArtifactBucketName') != bucket:
        raise ValueError('Customer bootstrap artifact bucket differs')
    registry_path = ROOT / 'services/business/adapter_registrations.json'
    original_registry = registry_path.read_bytes()
    try:
        initial = build_artifact(ROOT / 'dist/customer-connector-bootstrap.zip', root=ROOT)
        initial_artifact = upload_artifact(session, bucket, initial['path'], initial['sha256'])
        deploy_stack(run, ROOT / 'infra/customer-publisher/template.json', CONNECTOR_STACK,
                     connector_parameters(observed, initial_artifact, external_id))
        deployed = stack(session, CONNECTOR_STACK)
        connector_outputs = outputs(deployed)
        required = {'PublisherFunctionArn', 'CanaryFunctionArn', 'CanaryRoleArn',
            'InvocationFunctionArn', 'InvocationRoleArn', 'RuntimeInvokeRoleArn',
            'DiscoveryRoleArn', 'PublisherInvokeRoleArn', 'PublisherJournalTable',
            'ExternalIdHash'}
        if (not required.issubset(connector_outputs)
                or connector_outputs['ExternalIdHash'] != hashlib.sha256(
                    external_id.encode()).hexdigest()):
            raise ValueError('Customer connector outputs are incomplete or belong to another ExternalId')
        connector = {'stack_id': deployed['StackId'], 'outputs': connector_outputs}
        report['runtime_policy'] = update_runtime_policy(session, observed,
            connector_outputs['CanaryRoleArn'], connector_outputs['InvocationRoleArn'], run)
        binding = observed_binding(observed, connector, external_id)
        registry = build_registry(binding)
        registry_path.write_text(json.dumps(registry, indent=2) + '\n', encoding='utf-8')
        final = build_artifact(ROOT / 'dist/customer-connector.zip', root=ROOT)
        artifact = upload_artifact(session, bucket, final['path'], final['sha256'])
        deploy_stack(run, ROOT / 'infra/customer-publisher/template.json', CONNECTOR_STACK,
                     connector_parameters(observed, artifact, external_id))
    finally:
        registry_path.write_bytes(original_registry)
    deployed = stack(session, CONNECTOR_STACK)
    connector_outputs = outputs(deployed)
    if connector_outputs != connector['outputs']:
        raise ValueError('Customer connector identity changed during activation')
    lam = session.client('lambda')
    report['publisher_journal_permissions'] = verify_publisher_journal_permissions(
        session, account, connector_outputs['PublisherJournalTable'],
        observed['baseline']['GatewayArn'])
    report['discovery_recovery_permissions'] = verify_discovery_recovery_permissions(
        session, account, observed['baseline']['PolicyEngineArn'])
    code_sha = base64.b64encode(bytes.fromhex(artifact['sha256'])).decode()
    for key in ('PublisherFunctionArn', 'CanaryFunctionArn', 'InvocationFunctionArn'):
        config = lam.get_function_configuration(FunctionName=connector_outputs[key])
        if (config.get('State') != 'Active' or config.get('LastUpdateStatus') != 'Successful'
                or config.get('CodeSha256') != code_sha):
            raise ValueError(key + ' immutable code readback differs')
    registry_raw = encode_evidence(registry)
    registry_key = ('customer-connector/' + account + '/' +
                    registry['registrations'][0]['registration_hash'] + '/adapter-registry.json')
    stored = session.client('s3').put_object(Bucket=bucket, Key=registry_key,
        Body=registry_raw, ContentType='application/json',
        Metadata={'sha256': hashlib.sha256(registry_raw).hexdigest()})
    if not stored.get('VersionId') or stored['VersionId'] == 'null':
        raise ValueError('Generated adapter registry is not versioned')
    report.update(result='PASS', connector_stack_id=deployed['StackId'],
        connector_outputs=connector_outputs, observed_binding=binding,
        artifact=artifact, registration_hash=registry['registrations'][0]['registration_hash'],
        adapter_registry_ref={'bucket': bucket, 'key': registry_key,
            'version_id': stored['VersionId'],
            'sha256': hashlib.sha256(registry_raw).hexdigest(),
            'size': len(registry_raw)}, business_publication='NOT_RUN',
        policy_write='NOT_RUN', live_canary='NOT_RUN')
    return report


def main():
    import boto3
    import botocore
    environment = os.environ
    report = {'schema_version': '1.0', 'scope': SCOPE, 'result': 'FAIL',
        'observed_at': observed_at(), 'build_id': environment.get('CODEBUILD_BUILD_ID'),
        'source_sha256': environment.get('AD_SOURCE_SHA256'),
        'business_publication': 'NOT_RUN', 'policy_write': 'NOT_RUN',
        'live_canary': 'NOT_RUN'}
    try:
        session = boto3.Session(region_name=REGION)
        execute(session, environment, report)
    except Exception as exc:
        report['error'] = safe_error(exc)
        print('ERROR: ' + str(exc), flush=True)
    report['sdk_versions'] = {'boto3': boto3.__version__,
                              'botocore': botocore.__version__}
    data = encode_evidence(report)
    path = ROOT / 'evidence/aws/customer-connector-result.json'
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    try:
        save_evidence(session, environment, data, path, environment['AD_REPORT_KEY'])
    except Exception as exc:
        print('ERROR saving customer connector evidence: ' + str(exc), flush=True)
        return 1
    print(data.decode(), flush=True)
    return 0 if report['result'] == 'PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
