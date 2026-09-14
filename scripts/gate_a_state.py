"""Owned Gate A journal and observations; never reuse G0's empty-ledger invariant."""
from __future__ import annotations
import base64
import json
from pathlib import Path

from authority_delta.canonical import sha256_json
from authority_delta.evidence_json import encode_evidence
from authority_delta.gateway_probe import validate_endpoint
from build_registry_seed import build_transaction
from deploy_baseline import all_records
from verify_aws import TOOL_ARGUMENTS, sdk_evidence

JOURNAL_KEY = 'gate-a/control/current.json'

def missing(exc):
    return getattr(exc, 'response', {}).get('Error', {}).get('Code') in ('NoSuchKey', '404', 'NotFound', 'ResourceNotFoundException')

def read_json(s3, bucket, key, version_id=None):
    args = {'Bucket': bucket, 'Key': key}
    if version_id:
        args['VersionId'] = version_id
    response = s3.get_object(**args)
    stream = response['Body']
    try:
        raw = stream.read(2_000_001)
    finally:
        stream.close()
    if len(raw) > 2_000_000:
        raise ValueError('Evidence object exceeds bounded JSON size')
    if not response.get('VersionId') or response['VersionId'] == 'null':
        raise ValueError('Evidence is not versioned')
    if version_id and response['VersionId'] != version_id:
        raise ValueError('Evidence version mismatch')
    return json.loads(raw), response

class Journal:
    def __init__(self, s3, bucket):
        self.s3, self.bucket, self.etag, self.value = s3, bucket, None, None
        try:
            self.value, metadata = read_json(s3, bucket, JOURNAL_KEY)
            self.etag = metadata['ETag']
        except Exception as exc:
            if not missing(exc):
                raise
    def write(self, value):
        condition = {'IfMatch': self.etag} if self.etag else {'IfNoneMatch': '*'}
        result = self.s3.put_object(Bucket=self.bucket, Key=JOURNAL_KEY,
            Body=encode_evidence(value), ContentType='application/json', **condition)
        if not result.get('VersionId') or result['VersionId'] == 'null' or not result.get('ETag'):
            raise ValueError('Journal write did not return immutable version and ETag')
        self.etag, self.value = result['ETag'], value.copy()
        return result['VersionId']

def policies(control, engine):
    values, arguments = [], {'policyEngineId': engine, 'maxResults': 100}
    for _ in range(10):
        result = control.list_policies(**arguments)
        values.extend(result.get('policies', []))
        if not result.get('nextToken'):
            return values
        arguments['nextToken'] = result['nextToken']
    raise ValueError('Unexpected number of policies; no policies changed')

def stable_ledger(items):
    return sha256_json(sorted(items, key=lambda item: item['business_key']['S']))

def observe_baseline(session, binding, fixtures):
    output = binding['resources']
    stack = session.client('cloudformation').describe_stacks(StackName=binding['application_stack'])['Stacks'][0]
    if stack['StackStatus'] not in ('CREATE_COMPLETE', 'UPDATE_COMPLETE'):
        raise ValueError('Existing baseline stack is not stable')
    current = {v['OutputKey']: v['OutputValue'] for v in stack.get('Outputs', [])}
    if any(current.get(k) != v for k, v in output.items()):
        raise ValueError('Baseline bindings changed')
    control = session.client('bedrock-agentcore-control')
    gateway = control.get_gateway(gatewayIdentifier=output['GatewayIdentifier'])
    engine = control.get_policy_engine(policyEngineId=output['PolicyEngineId'])
    if gateway.get('status') != 'READY' or gateway.get('authorizerType') != 'AWS_IAM':
        raise ValueError('Gateway is not READY with IAM authentication')
    if gateway.get('gatewayArn') != output['GatewayArn'] or gateway.get('gatewayUrl') != output['GatewayUrl']:
        raise ValueError('Unexpected Gateway identity')
    validate_endpoint(gateway['gatewayUrl'], output['GatewayIdentifier'], binding['region'])
    if engine.get('status') != 'ACTIVE' or engine.get('policyEngineArn') != output['PolicyEngineArn']:
        raise ValueError('Unexpected Policy Engine')
    if gateway.get('policyEngineConfiguration', {}).get('mode') != 'ENFORCE' or gateway['policyEngineConfiguration'].get('arn') != output['PolicyEngineArn']:
        raise ValueError('Gateway Policy is not bound in ENFORCE mode')
    targets = control.list_gateway_targets(gatewayIdentifier=output['GatewayIdentifier'])
    if targets.get('nextToken') or len(targets.get('items', [])) != 1:
        raise ValueError('Gateway target set changed')
    target = control.get_gateway_target(gatewayIdentifier=output['GatewayIdentifier'], targetId=targets['items'][0]['targetId'])
    if target.get('status') != 'READY' or target.get('name') != 'VendorPaymentTools' or target.get('gatewayArn') != output['GatewayArn']:
        raise ValueError('Gateway target is not the bound protected target')
    configuration = target.get('targetConfiguration', {}).get('mcp', {}).get('lambda', {})
    if configuration.get('lambdaArn') != output['SandboxToolFunctionArn']:
        raise ValueError('Gateway tool function changed')
    tools = configuration.get('toolSchema', {}).get('inlinePayload', [])
    if len(tools) != 3 or {t.get('name') for t in tools} != set(TOOL_ARGUMENTS):
        raise ValueError('Expected three existing protected tools')
    for tool in tools:
        schema = tool.get('inputSchema', {}); argument = TOOL_ARGUMENTS[tool['name']]
        if schema.get('type') != 'object' or schema.get('required') != [argument] or set(schema.get('properties', {})) != {argument} or schema['properties'][argument].get('type') != 'string':
            raise ValueError('Protected tool is not the immutable request-ID contract')
    function = session.client('lambda').get_function_configuration(FunctionName=output['SandboxToolFunctionArn'])
    expected_env = {'CONNECTION_ID': 'conn-demo', 'REQUEST_REGISTRY_TABLE': output['RequestRegistryTableName'], 'SANDBOX_LEDGER_TABLE': output['SandboxLedgerTableName']}
    if function.get('State') != 'Active' or function.get('LastUpdateStatus') != 'Successful' or function.get('Environment', {}).get('Variables') != expected_env:
        raise ValueError('Protected tool environment changed')
    if base64.b64decode(function.get('CodeSha256', ''), validate=True).hex() != binding['sandbox_code_sha256']:
        raise ValueError('Protected tool code changed')
    ddb = session.client('dynamodb')
    registry = all_records(ddb, output['RequestRegistryTableName'])
    expected = [t['Put']['Item'] for t in build_transaction(fixtures, output['RequestRegistryTableName'])]
    if sorted(registry, key=lambda v:v['request_id']['S']) != sorted(expected, key=lambda v:v['request_id']['S']):
        raise ValueError('Immutable request registry changed')
    return {'stable': {'gateway_arn': output['GatewayArn'], 'policy_engine_arn': output['PolicyEngineArn'],
        'target_id': target['targetId'], 'target_schema_hash': sha256_json(configuration),
        'sandbox_code_sha256': binding['sandbox_code_sha256'], 'registry_hash': sha256_json(sorted(registry, key=lambda v:v['request_id']['S']))},
        'policies': policies(control, output['PolicyEngineId']), 'ledger': all_records(ddb, output['SandboxLedgerTableName']),
        'api_evidence': {'gateway': sdk_evidence(gateway), 'engine': sdk_evidence(engine), 'target': sdk_evidence(target)}}
