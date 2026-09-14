"""Full worker orchestration against botocore's request/response schemas (no AWS traffic)."""
from contextlib import ExitStack, redirect_stdout
from datetime import datetime, timezone
import io
import os
from pathlib import Path
import subprocess
import unittest

import boto3
from botocore.stub import ANY, Stubber

from authority_delta.registry import FixtureBundle
from scripts.build_registry_seed import build_transaction
from scripts import deploy_baseline as worker

ROOT = Path(__file__).resolve().parents[1]


class DeploymentSdkTests(unittest.TestCase):
    def test_worker_runs_all_sdk_operations_and_validates_observed_state(self):
        session = boto3.Session(aws_access_key_id='unit-test', aws_secret_access_key='unit-test', region_name=worker.REGION)
        clients = {name: session.client(name) for name in ('sts', 's3', 'cloudformation', 'bedrock-agentcore-control', 'dynamodb', 'lambda')}
        stubs = {name: Stubber(client) for name, client in clients.items()}
        identity = {'Account': worker.ACCOUNT, 'Arn': f'arn:aws:sts::{worker.ACCOUNT}:assumed-role/ReadinessOpsAuthorityDeltaDeployer/AWSCodeBuild-test', 'UserId': 'test-principal'}
        environment = {'AD_EXPECTED_ACCOUNT': worker.ACCOUNT, 'AD_REGION': worker.REGION, 'CODEBUILD_BUILD_ID': 'authority-delta-deploy:build-1', 'AD_ARTIFACT_BUCKET': 'owned-artifacts', 'AD_SOURCE_SHA256': 'source-digest'}
        stubs['sts'].add_response('get_caller_identity', identity, {})
        stubs['s3'].add_response('put_object', {'VersionId': 'artifact-version'}, {'Bucket': 'owned-artifacts', 'Key': ANY, 'Body': ANY, 'Metadata': ANY})
        stubs['cloudformation'].add_response('validate_template', {'Capabilities': ['CAPABILITY_IAM']}, {'TemplateBody': ANY})
        values = {'RequestRegistryTableName': 'registry-table', 'SandboxLedgerTableName': 'ledger-table', 'GatewayIdentifier': 'authoritydelta-0123456789', 'GatewayArn': f'arn:aws:bedrock-agentcore:{worker.REGION}:{worker.ACCOUNT}:gateway/authoritydelta-0123456789', 'GatewayUrl': 'https://example.invalid/mcp', 'PolicyEngineId': 'AuthorityDeltaEngine-0123456789', 'PolicyEngineArn': f'arn:aws:bedrock-agentcore:{worker.REGION}:{worker.ACCOUNT}:policy-engine/AuthorityDeltaEngine-0123456789', 'SandboxToolFunctionArn': f'arn:aws:lambda:{worker.REGION}:{worker.ACCOUNT}:function:authority-delta-sandbox'}
        now = datetime.now(timezone.utc)
        stubs['cloudformation'].add_response('describe_stacks', {'Stacks': [{'StackName': worker.STACK, 'StackStatus': 'CREATE_COMPLETE', 'CreationTime': now, 'Outputs': [{'OutputKey': k, 'OutputValue': v} for k,v in values.items()]}]}, {'StackName': worker.STACK})
        control = stubs['bedrock-agentcore-control']
        control.add_response('get_gateway', {'gatewayArn': values['GatewayArn'], 'gatewayId': values['GatewayIdentifier'], 'createdAt': now, 'updatedAt': now, 'status': 'READY', 'name': 'authority-delta-gateway', 'authorizerType': 'AWS_IAM', 'policyEngineConfiguration': {'arn': values['PolicyEngineArn'], 'mode': 'ENFORCE'}}, {'gatewayIdentifier': values['GatewayIdentifier']})
        control.add_response('get_policy_engine', {'policyEngineId': values['PolicyEngineId'], 'name': 'AuthorityDeltaEngine', 'createdAt': now, 'updatedAt': now, 'policyEngineArn': values['PolicyEngineArn'], 'status': 'ACTIVE', 'statusReasons': []}, {'policyEngineId': values['PolicyEngineId']})
        control.add_response('list_policies', {'policies': []}, {'policyEngineId': values['PolicyEngineId']})
        control.add_response('list_gateway_targets', {'items': [{'targetId': 'target-0123456789', 'name': 'VendorPaymentTools', 'status': 'READY', 'createdAt': now, 'updatedAt': now}]}, {'gatewayIdentifier': values['GatewayIdentifier']})
        fixtures = FixtureBundle.load(ROOT/'fixtures/decision_cases.json')
        transaction = build_transaction(fixtures, 'registry-table')
        stubs['dynamodb'].add_response('scan', {'Items': []}, {'TableName': 'ledger-table', 'ConsistentRead': True})
        stubs['dynamodb'].add_response('transact_write_items', {}, {'TransactItems': transaction})
        stubs['dynamodb'].add_response('scan', {'Items': [t['Put']['Item'] for t in transaction]}, {'TableName': 'registry-table', 'ConsistentRead': True})
        stubs['dynamodb'].add_response('scan', {'Items': []}, {'TableName': 'ledger-table', 'ConsistentRead': True})
        stubs['lambda'].add_response('get_function_configuration', {'State': 'Active', 'LastUpdateStatus': 'Successful'}, {'FunctionName': values['SandboxToolFunctionArn']})
        class BoundSession:
            def client(self, name, **kwargs):
                return clients[name]
        cfn_calls = []
        def run(command, **kwargs):
            if command[0] == 'aws':
                self.assertEqual(command[1:3], ['cloudformation', 'deploy'])
                self.assertIn('SandboxArtifactVersion=artifact-version', command)
                cfn_calls.append(command)
                return subprocess.CompletedProcess(command, 0)
            return subprocess.run(command, capture_output=True, **kwargs)
        with ExitStack() as stack, redirect_stdout(io.StringIO()):
            for stub in stubs.values():
                stack.enter_context(stub)
            result = worker.deploy(BoundSession(), environment, run=run)
            for stub in stubs.values():
                stub.assert_no_pending_responses()
        self.assertEqual(len(cfn_calls), 1)
        self.assertEqual(result['postconditions']['request_registry_count'], 7)
        self.assertEqual(result['postconditions']['ledger_count'], 0)
        self.assertEqual(result['result'], 'PASS')
        self.assertEqual(result['gate_a'], 'NOT_RUN')


if __name__ == '__main__':
    unittest.main()
