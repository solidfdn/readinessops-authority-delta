"""Local contracts for the account-B STS connector and recoverable operator."""
import base64
import boto3
import copy
import hashlib
import json
import unittest
from pathlib import Path
import tempfile
from unittest.mock import patch

from scripts import deploy_customer_connector as worker
from build_customer_adapter_registry import build as build_registry
from build_customer_publisher_template import build as build_template
from deploy_customer_connector import (ACCOUNT_A, REGION, SOURCE_DISCOVERY_ROLE,
    SOURCE_INVOCATION_WORKER_ROLE, SOURCE_ROLE,
    connector_parameters, observed_binding, require_identity,
    verify_discovery_recovery_permissions, verify_publisher_journal_permissions)


EXTERNAL_ID = 'connector-test-external-id-00000001'
ACCOUNT_B = '111122223333'


def observed():
    gateway_id = 'authority-delta-gateway-rvplvkk1t7'
    runtime_id = 'authority_delta_vendor_v2-test123'
    runtime_arn = f'arn:aws:bedrock-agentcore:{REGION}:{ACCOUNT_B}:runtime/{runtime_id}'
    endpoint = 'fixed_v2'
    return {'account': ACCOUNT_B, 'connection_id': 'conn-demo',
        'target_id': 'TARGET123', 'target_name': 'VendorPaymentTools',
        'baseline': {
            'GatewayIdentifier': gateway_id,
            'GatewayArn': f'arn:aws:bedrock-agentcore:{REGION}:{ACCOUNT_B}:gateway/{gateway_id}',
            'PolicyEngineId': 'AuthorityDeltaEngine-test123',
            'PolicyEngineArn': f'arn:aws:bedrock-agentcore:{REGION}:{ACCOUNT_B}:policy-engine/AuthorityDeltaEngine-test123',
            'RequestRegistryTableName': 'authority-delta-request-registry',
            'SandboxLedgerTableName': 'authority-delta-sandbox-ledger',
            'SandboxToolFunctionArn': f'arn:aws:lambda:{REGION}:{ACCOUNT_B}:function:authority-delta-sandbox'},
        'runtimes': {'V2RuntimeId': runtime_id, 'V2RuntimeArn': runtime_arn,
            'V2RuntimeVersion': '2', 'V2EndpointName': endpoint,
            'V2EndpointArn': runtime_arn + '/runtime-endpoint/' + endpoint,
            'V2ExecutionRoleArn': f'arn:aws:iam::{ACCOUNT_B}:role/authority-delta-vendor-v2-runtime'}}


class CustomerConnectorOperator(unittest.TestCase):
    def environment(self):
        return {'AD_EXPECTED_ACCOUNT': ACCOUNT_B, 'AD_REGION': REGION,
            'CODEBUILD_BUILD_ID': 'authority-delta-deploy:local-test',
            'AD_SOURCE_APPLICATION_WORKER_ROLE_ARN': SOURCE_ROLE,
            'AD_EXTERNAL_ID': EXTERNAL_ID, 'AD_SOURCE_SHA256': 'a' * 64}

    def identity(self):
        return {'Account': ACCOUNT_B,
            'Arn': f'arn:aws:sts::{ACCOUNT_B}:assumed-role/ReadinessOpsAuthorityDeltaDeployer/local'}

    def test_worker_requires_distinct_b_account_owned_role_source_and_external_id(self):
        self.assertEqual(require_identity(self.identity(), self.environment()),
                         (ACCOUNT_B, EXTERNAL_ID))
        mutations = [
            ({'Account': ACCOUNT_A,
              'Arn': f'arn:aws:sts::{ACCOUNT_A}:assumed-role/ReadinessOpsAuthorityDeltaDeployer/local'}, {}),
            ({'Account': ACCOUNT_B,
              'Arn': f'arn:aws:sts::{ACCOUNT_B}:assumed-role/Foreign/local'}, {}),
            (self.identity(), {'AD_SOURCE_APPLICATION_WORKER_ROLE_ARN':
                               f'arn:aws:iam::{ACCOUNT_B}:role/authority-delta-application-worker'}),
            (self.identity(), {'AD_EXTERNAL_ID': 'short'}),
        ]
        for identity, changes in mutations:
            with self.subTest(identity=identity, changes=changes):
                environment = dict(self.environment(), **changes)
                with self.assertRaises(ValueError):
                    require_identity(identity, environment)

    def test_template_has_separate_external_id_roles_and_no_direct_a_invoke(self):
        template = build_template()
        resources = template['Resources']
        self.assertNotIn('PublisherPermission', resources)
        discovery = resources['DiscoveryRole']['Properties']
        publish = resources['PublishInvokeRole']['Properties']
        for role, source in ((discovery, 'SourceDiscoveryRoleArn'),
                             (publish, 'SourceApplicationWorkerRoleArn')):
            trust = role['AssumeRolePolicyDocument']['Statement'][0]
            self.assertEqual(trust['Principal']['AWS'], {'Fn::Sub':
                'arn:${AWS::Partition}:iam::${SourceAccountId}:root'})
            self.assertEqual(trust['Condition']['ArnEquals']['aws:PrincipalArn'],
                             {'Ref': source})
            self.assertEqual(trust['Condition']['StringEquals']['sts:ExternalId'],
                             {'Ref': 'ExternalId'})
            self.assertEqual(role['MaxSessionDuration'], 3600)
        self.assertIn('GetAgentRuntime', json.dumps(discovery))
        self.assertNotIn('CreatePolicy', json.dumps(discovery))
        self.assertIn('lambda:InvokeFunction', json.dumps(publish))
        self.assertNotIn('GetAgentRuntime', json.dumps(publish))
        publisher = resources['PublisherRole']['Properties']['Policies'][0]
        publisher_text = json.dumps(publisher)
        self.assertIn('ManageResourceScopedPolicy', publisher_text)
        self.assertNotIn('ManageAdminPolicy', publisher_text)
        self.assertIn('bedrock-agentcore:GetGateway', publisher_text)
        self.assertIn('bedrock-agentcore:InvokeGateway', publisher_text)
        self.assertIn('bedrock-agentcore:ListGatewayTargets', publisher_text)
        self.assertIn('bedrock-agentcore:GetGatewayTarget', publisher_text)
        journal = [statement for statement in
            publisher['PolicyDocument']['Statement']
            if statement.get('Resource') == {
                'Fn::GetAtt': ['PublisherJournal', 'Arn']}][0]
        self.assertEqual(set(journal['Action']), {
            'dynamodb:GetItem', 'dynamodb:PutItem', 'dynamodb:DeleteItem',
            'dynamodb:TransactWriteItems'})
        self.assertIn('iam:GetRolePolicy', json.dumps(discovery))
        discovery_statements = discovery['Policies'][0]['PolicyDocument']['Statement']
        policy_read = [statement for statement in discovery_statements
            if statement.get('Action') == 'bedrock-agentcore:GetPolicy']
        self.assertEqual(policy_read, [{'Effect': 'Allow',
            'Action': 'bedrock-agentcore:GetPolicy', 'Resource': [
                {'Ref': 'PolicyEngineArn'}, {'Fn::Sub': '${PolicyEngineArn}/*'}]}])

    def test_discovery_policy_readback_is_exact_and_non_mutating(self):
        engine = (f'arn:aws:bedrock-agentcore:{REGION}:{ACCOUNT_B}:'
                  'policy-engine/AuthorityDeltaEngine-test123')
        document = {'Version': '2012-10-17', 'Statement': [
            {'Effect': 'Allow', 'Action': 'bedrock-agentcore:GetPolicy',
             'Resource': [engine, engine + '/*']}]}
        class Iam:
            def get_role_policy(self, **values):
                self.values = values
                return {'PolicyDocument': document, 'ResponseMetadata': {
                    'HTTPStatusCode': 200, 'RequestId': 'discovery-iam-request'}}
        iam = Iam()
        session = type('Session', (), {'client': lambda self, name: iam})()
        result = verify_discovery_recovery_permissions(
            session, ACCOUNT_B, engine)
        self.assertEqual(result['actions'], ['bedrock-agentcore:GetPolicy'])
        self.assertEqual(iam.values, {'RoleName':
            'authority-delta-customer-discovery',
            'PolicyName': 'BoundedCustomerConnector'})
        document['Statement'][0]['Resource'] = [engine]
        with self.assertRaisesRegex(ValueError, 'not exact'):
            verify_discovery_recovery_permissions(session, ACCOUNT_B, engine)
        document['Statement'][0]['Resource'] = [engine, engine + '/*']
        document['Statement'].append({'Effect': 'Allow',
            'Action': 'bedrock-agentcore:DeletePolicy', 'Resource': engine + '/*'})
        with self.assertRaisesRegex(ValueError, 'not exact'):
            verify_discovery_recovery_permissions(session, ACCOUNT_B, engine)

    def test_publisher_journal_permission_readback_is_exact(self):
        table = 'publisher-journal'
        gateway = (f'arn:aws:bedrock-agentcore:{REGION}:{ACCOUNT_B}:'
                   'gateway/authority-delta-gateway-test')
        document = {'Version': '2012-10-17', 'Statement': [
            {'Effect': 'Allow',
             'Action': ['dynamodb:GetItem', 'dynamodb:PutItem',
                        'dynamodb:DeleteItem', 'dynamodb:TransactWriteItems'],
             'Resource': f'arn:aws:dynamodb:{REGION}:{ACCOUNT_B}:table/{table}'},
            {'Effect': 'Allow',
             'Action': 'bedrock-agentcore:ManageResourceScopedPolicy',
             'Resource': gateway},
            {'Effect': 'Allow',
             'Action': ['bedrock-agentcore:GetGateway',
                        'bedrock-agentcore:InvokeGateway',
                        'bedrock-agentcore:ListGatewayTargets',
                        'bedrock-agentcore:GetGatewayTarget'],
             'Resource': gateway}]}
        class Iam:
            def get_role_policy(self, **values):
                return {'PolicyDocument': document, 'ResponseMetadata': {
                    'HTTPStatusCode': 200, 'RequestId': 'iam-request'}}
        session = type('Session', (), {'client': lambda self, name: Iam()})()
        result = verify_publisher_journal_permissions(
            session, ACCOUNT_B, table, gateway)
        self.assertIn('dynamodb:DeleteItem', result['actions'])
        self.assertEqual(result['resource_scoped_policy']['actions'],
                         ['bedrock-agentcore:ManageResourceScopedPolicy'])
        self.assertEqual(result['policy_gateway_validation']['actions'], [
            'bedrock-agentcore:GetGateway',
            'bedrock-agentcore:GetGatewayTarget',
            'bedrock-agentcore:InvokeGateway',
            'bedrock-agentcore:ListGatewayTargets'])
        document['Statement'][0]['Action'].remove('dynamodb:DeleteItem')
        with self.assertRaisesRegex(ValueError, 'exact qualified set'):
            verify_publisher_journal_permissions(session, ACCOUNT_B, table, gateway)
        document['Statement'][0]['Action'].append('dynamodb:DeleteItem')
        document['Statement'][1]['Action'] = 'bedrock-agentcore:ManageAdminPolicy'
        with self.assertRaisesRegex(ValueError, 'resource-scoped Policy permission'):
            verify_publisher_journal_permissions(session, ACCOUNT_B, table, gateway)
        document['Statement'][1]['Action'] = 'bedrock-agentcore:ManageResourceScopedPolicy'
        document['Statement'][2]['Action'] = 'bedrock-agentcore:GetGateway'
        with self.assertRaisesRegex(ValueError, 'gateway validation permission'):
            verify_publisher_journal_permissions(session, ACCOUNT_B, table, gateway)

    def test_observed_binding_is_the_only_registry_input(self):
        connector = {'stack_id':
            f'arn:aws:cloudformation:{REGION}:{ACCOUNT_B}:stack/authority-delta-customer-publisher/abc',
            'outputs': {
                'DiscoveryRoleArn': f'arn:aws:iam::{ACCOUNT_B}:role/authority-delta-customer-discovery',
                'PublisherInvokeRoleArn': f'arn:aws:iam::{ACCOUNT_B}:role/authority-delta-customer-publish-invoke',
                'PublisherFunctionArn': f'arn:aws:lambda:{REGION}:{ACCOUNT_B}:function:authority-delta-customer-publisher:live',
                'RuntimeInvokeRoleArn': f'arn:aws:iam::{ACCOUNT_B}:role/authority-delta-customer-runtime-invoke',
                'InvocationFunctionArn': f'arn:aws:lambda:{REGION}:{ACCOUNT_B}:function:authority-delta-customer-invocation:live',
                'CanaryFunctionArn': f'arn:aws:lambda:{REGION}:{ACCOUNT_B}:function:authority-delta-customer-canary:live'}}
        binding = observed_binding(observed(), connector, EXTERNAL_ID)
        registry = build_registry(binding)
        registration = registry['registrations'][0]
        self.assertEqual(registration['connection_mode'], 'LIVE_CUSTOMER')
        self.assertEqual(registration['publisher_binding']['invoke_role_arn'],
                         connector['outputs']['PublisherInvokeRoleArn'])
        self.assertEqual(registration['discovery_binding']['external_id'], EXTERNAL_ID)
        self.assertNotEqual(registration['target_account_id'], ACCOUNT_A)

    def test_connector_parameters_bind_hash_and_lambda_digest(self):
        artifact = {'bucket': 'customer-artifacts-test', 'key': 'code/test.zip',
            'version_id': 'version-1', 'sha256': 'ab' * 32}
        values = connector_parameters(observed(), artifact, EXTERNAL_ID)
        self.assertEqual(values['ExternalIdHash'],
                         hashlib.sha256(EXTERNAL_ID.encode()).hexdigest())
        self.assertEqual(values['CodeSha256'],
                         base64.b64encode(bytes.fromhex('ab' * 32)).decode())
        self.assertEqual(values['SourceApplicationWorkerRoleArn'], SOURCE_ROLE)
        self.assertEqual(values['SourceInvocationWorkerRoleArn'],
                         SOURCE_INVOCATION_WORKER_ROLE)
        self.assertEqual(values['SourceDiscoveryRoleArn'], SOURCE_DISCOVERY_ROLE)
        self.assertEqual(values['SourceAccountId'], ACCOUNT_A)
        changed = copy.deepcopy(values)
        changed['ExternalId'] = 'different-external-id-00000000001'
        self.assertNotEqual(hashlib.sha256(changed['ExternalId'].encode()).hexdigest(),
                            changed['ExternalIdHash'])

    def test_pinned_sdk_exposes_exact_sts_and_runtime_policy_calls(self):
        session = boto3.Session(region_name=REGION, aws_access_key_id='LOCAL',
            aws_secret_access_key='LOCAL_TEST_ONLY')
        sts = session.client('sts').meta.service_model.operation_model('AssumeRole')
        self.assertTrue({'RoleArn', 'RoleSessionName', 'ExternalId',
                         'DurationSeconds'} <= set(sts.input_shape.members))
        control = session.client('bedrock-agentcore-control').meta.service_model
        policy = control.operation_model('GetResourcePolicy')
        self.assertEqual(set(policy.input_shape.members), {'resourceArn'})
        self.assertIn('policy', policy.output_shape.members)
        for operation in ('GetGateway', 'GetGatewayTarget', 'GetPolicyEngine',
                          'GetAgentRuntime', 'GetAgentRuntimeEndpoint'):
            self.assertIn(operation, control.operation_names)
        deletion = control.operation_model('DeletePolicy')
        self.assertEqual(deletion.http, {'method': 'DELETE',
            'requestUri': '/policy-engines/{policyEngineId}/policies/{policyId}',
            'responseCode': 202})
        self.assertIn('DELETING', deletion.output_shape.members['status'].enum)

    def test_worker_builds_observed_registry_activates_and_restores_source(self):
        connector_outputs = {
            'PublisherFunctionArn': f'arn:aws:lambda:{REGION}:{ACCOUNT_B}:function:authority-delta-customer-publisher:live',
            'CanaryFunctionArn': f'arn:aws:lambda:{REGION}:{ACCOUNT_B}:function:authority-delta-customer-canary:live',
            'CanaryRoleArn': f'arn:aws:iam::{ACCOUNT_B}:role/authority-delta-customer-canary',
            'InvocationFunctionArn': f'arn:aws:lambda:{REGION}:{ACCOUNT_B}:function:authority-delta-customer-invocation:live',
            'InvocationRoleArn': f'arn:aws:iam::{ACCOUNT_B}:role/authority-delta-customer-invocation',
            'RuntimeInvokeRoleArn': f'arn:aws:iam::{ACCOUNT_B}:role/authority-delta-customer-runtime-invoke',
            'DiscoveryRoleArn': f'arn:aws:iam::{ACCOUNT_B}:role/authority-delta-customer-discovery',
            'PublisherInvokeRoleArn': f'arn:aws:iam::{ACCOUNT_B}:role/authority-delta-customer-publish-invoke',
            'PublisherJournalTable': 'publisher-journal',
            'ExternalIdHash': hashlib.sha256(EXTERNAL_ID.encode()).hexdigest()}
        connector_stack = {'StackStatus': 'UPDATE_COMPLETE', 'StackId':
            f'arn:aws:cloudformation:{REGION}:{ACCOUNT_B}:stack/authority-delta-customer-publisher/abc',
            'Outputs': [{'OutputKey': key, 'OutputValue': value}
                        for key, value in connector_outputs.items()]}
        bootstrap = {'StackStatus': 'CREATE_COMPLETE', 'Outputs': [
            {'OutputKey': 'ArtifactBucketName',
             'OutputValue': 'customer-artifact-bucket'}]}
        artifact = {'path': 'unused.zip', 'sha256': 'ab' * 32,
            'size_bytes': 100, 'uncompressed_bytes': 200,
            'architecture': 'x86_64'}
        uploaded = {'bucket': 'customer-artifact-bucket', 'key': 'code.zip',
            'version_id': 'version-1', 'sha256': artifact['sha256'],
            'size_bytes': 100}

        class Sts:
            def get_caller_identity(self):
                return self_identity
        class Lambda:
            def get_function_configuration(self, **values):
                return {'State': 'Active', 'LastUpdateStatus': 'Successful',
                    'CodeSha256': base64.b64encode(bytes.fromhex('ab' * 32)).decode()}
        class S3:
            def put_object(self, **values):
                return {'VersionId': 'registry-version'}
        class Session:
            def client(self, name):
                return {'sts': Sts(), 'lambda': Lambda(), 's3': S3()}[name]
        self_identity = self.identity()
        source_observed = observed()
        source_observed.update(baseline_stack={}, runtime_stack={}, registry_hash='a' * 64,
            ledger_hash='b' * 64, api_evidence={})
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            registry_path = root / 'services/business/adapter_registrations.json'
            registry_path.parent.mkdir(parents=True)
            original = b'{"schema_version":"1.0","registrations":[]}\n'
            registry_path.write_bytes(original)
            calls = []
            def deploy(*args):
                calls.append(args)
            with (patch.object(worker, 'ROOT', root),
                  patch.object(worker, 'observe_customer', return_value=source_observed),
                  patch.object(worker, 'stack', side_effect=[bootstrap, connector_stack,
                                                             connector_stack, connector_stack]),
                  patch.object(worker, 'build_artifact', return_value=artifact),
                  patch.object(worker, 'upload_artifact', return_value=uploaded),
                  patch.object(worker, 'deploy_stack', side_effect=deploy),
                  patch.object(worker, 'verify_publisher_journal_permissions',
                    return_value={'actions': sorted(
                        worker.PUBLISHER_JOURNAL_ACTIONS)}),
                  patch.object(worker, 'verify_discovery_recovery_permissions',
                    return_value={'actions': ['bedrock-agentcore:GetPolicy']}),
                  patch.object(worker, 'update_runtime_policy', return_value={
                    'stack_id': 'runtime-stack', 'policy_hash': 'c' * 64,
                    'canary_role_arn': connector_outputs['CanaryRoleArn'],
                    'invocation_role_arn': connector_outputs['InvocationRoleArn'],
                    'deployer_role_arn': f'arn:aws:iam::{ACCOUNT_B}:role/ReadinessOpsAuthorityDeltaDeployer'})):
                report = worker.execute(Session(), dict(self.environment(),
                    AD_ARTIFACT_BUCKET='customer-artifact-bucket'), {})
            self.assertEqual(report['result'], 'PASS')
            self.assertEqual(report['business_publication'], 'NOT_RUN')
            self.assertEqual(report['registration_hash'],
                             report['observed_binding'] and report['registration_hash'])
            self.assertEqual(registry_path.read_bytes(), original)
            self.assertEqual(len(calls), 2)

if __name__ == '__main__':
    unittest.main()
