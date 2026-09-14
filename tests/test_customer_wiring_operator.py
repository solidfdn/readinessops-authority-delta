"""Contracts for verified account-B discovery and account-A registry wiring."""
import io
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
import subprocess
from unittest.mock import patch

from scripts import deploy_customer_wiring as worker
from build_customer_adapter_registry import build as build_registry
from deploy_customer_connector import observed_binding


ACCOUNT_B = '111122223333'
EXTERNAL_ID = 'connector-test-external-id-00000001'
META = {'RequestId': 'sts-assume-request', 'HTTPStatusCode': 200}


def connector_report(external_id=EXTERNAL_ID):
    runtime_id = 'authority_delta_vendor_v2-test123'
    runtime_arn = f'arn:aws:bedrock-agentcore:{worker.REGION}:{ACCOUNT_B}:runtime/{runtime_id}'
    observed = {'account': ACCOUNT_B, 'connection_id': 'conn-demo',
        'target_id': 'TARGET123', 'target_name': 'VendorPaymentTools',
        'baseline': {'GatewayIdentifier': 'authority-delta-gateway-abcde12345',
            'GatewayArn': f'arn:aws:bedrock-agentcore:{worker.REGION}:{ACCOUNT_B}:gateway/authority-delta-gateway-abcde12345',
            'PolicyEngineId': 'engine-test',
            'RequestRegistryTableName': 'request-registry',
            'SandboxLedgerTableName': 'sandbox-ledger'},
        'runtimes': {'V2RuntimeId': runtime_id, 'V2RuntimeArn': runtime_arn,
            'V2RuntimeVersion': '2', 'V2EndpointName': 'fixed_v2',
            'V2EndpointArn': runtime_arn + '/runtime-endpoint/fixed_v2',
            'V2ExecutionRoleArn': f'arn:aws:iam::{ACCOUNT_B}:role/authority-delta-vendor-v2-runtime'}}
    stack_id = f'arn:aws:cloudformation:{worker.REGION}:{ACCOUNT_B}:stack/authority-delta-customer-publisher/abc-123'
    outputs = {'DiscoveryRoleArn': f'arn:aws:iam::{ACCOUNT_B}:role/authority-delta-customer-discovery',
        'PublisherInvokeRoleArn': f'arn:aws:iam::{ACCOUNT_B}:role/authority-delta-customer-publish-invoke',
        'PublisherFunctionArn': f'arn:aws:lambda:{worker.REGION}:{ACCOUNT_B}:function:authority-delta-customer-publisher:live',
        'RuntimeInvokeRoleArn': f'arn:aws:iam::{ACCOUNT_B}:role/authority-delta-customer-runtime-invoke',
        'InvocationFunctionArn': f'arn:aws:lambda:{worker.REGION}:{ACCOUNT_B}:function:authority-delta-customer-invocation:live',
        'InvocationRoleArn': f'arn:aws:iam::{ACCOUNT_B}:role/authority-delta-customer-invocation',
        'CanaryFunctionArn': f'arn:aws:lambda:{worker.REGION}:{ACCOUNT_B}:function:authority-delta-customer-canary:live',
        'CanaryRoleArn': f'arn:aws:iam::{ACCOUNT_B}:role/authority-delta-customer-canary',
        'PublisherJournalTable': 'publisher-journal',
        'ExternalIdHash': hashlib.sha256(external_id.encode()).hexdigest()}
    binding = observed_binding(observed, {'stack_id': stack_id, 'outputs': outputs},
                               external_id)
    registry = build_registry(binding)
    return {'scope': worker.CONNECTOR_SCOPE, 'result': 'PASS', 'account': ACCOUNT_B,
        'region': worker.REGION, 'connector_stack_id': stack_id,
        'connector_outputs': outputs, 'observed_binding': binding,
        'registration_hash': registry['registrations'][0]['registration_hash'],
        'business_publication': 'NOT_RUN', 'policy_write': 'NOT_RUN',
        'live_canary': 'NOT_RUN'}


class CustomerWiringOperatorTests(unittest.TestCase):
    def environment(self):
        return {'AD_EXPECTED_ACCOUNT': worker.ACCOUNT, 'AD_REGION': worker.REGION,
            'CODEBUILD_BUILD_ID': 'authority-delta-deploy:wiring-test',
            'AD_SOURCE_SHA256': 'a' * 64, 'AD_ARTIFACT_BUCKET': 'account-a-bucket',
            'AD_REPORT_KEY': 'evidence/test/customer-wiring-result.json',
            'AD_CONNECTOR_REPORT_KEY': 'customer-wiring-input/test/report.json',
            'AD_CONNECTOR_REPORT_VERSION': 'report-version',
            'AD_CONNECTOR_REPORT_SHA256': 'b' * 64}

    def test_report_builds_one_exact_registration_and_rejects_tampering(self):
        report = connector_report()
        registry = worker.validate_connector_report(report)
        self.assertEqual(len(registry['registrations']), 1)
        self.assertEqual(registry['registrations'][0]['target_account_id'], ACCOUNT_B)
        changes = []
        changed = json.loads(json.dumps(report));changed['account'] = worker.ACCOUNT;changes.append(changed)
        changed = json.loads(json.dumps(report));changed['registration_hash'] = 'f' * 64;changes.append(changed)
        changed = json.loads(json.dumps(report));changed['connector_outputs']['PublisherFunctionArn'] += ':other';changes.append(changed)
        for value in changes:
            with self.assertRaises(ValueError):
                worker.validate_connector_report(value)

    def test_assume_customer_uses_only_discovery_role_and_external_id(self):
        registration = worker.validate_connector_report(connector_report())['registrations'][0]
        class Sts:
            request = None
            def assume_role(self, **values):
                self.request = values
                return {'AssumedRoleUser': {'Arn':
                    f'arn:aws:sts::{ACCOUNT_B}:assumed-role/authority-delta-customer-discovery/wiring'},
                    'Credentials': {'AccessKeyId': 'id', 'SecretAccessKey': 'secret',
                                    'SessionToken': 'token'}, 'ResponseMetadata': META}
        sts = Sts()
        session = type('Session', (), {'client': lambda self, name: sts})()
        customer, evidence = worker.assume_customer(session, registration,
            'authority-delta-deploy:wiring-test', session_factory=lambda values: values)
        self.assertEqual(sts.request['RoleArn'], registration['discovery_binding']['role_arn'])
        self.assertEqual(sts.request['ExternalId'], EXTERNAL_ID)
        self.assertEqual(sts.request['DurationSeconds'], 900)
        self.assertEqual(customer['SessionToken'], 'token')
        self.assertEqual(evidence['request']['request_id'], 'sts-assume-request')

    def test_canary_recovery_matches_only_exact_unused_failure(self):
        base = {'status': 'UNKNOWN', 'last_error':
            'Publisher invocation failed: Lambda FunctionError=Unhandled; '
            'remote=ValueError: Canary Lambda result differs'}
        self.assertEqual(worker.application_recovery_mode(base),
                         'CANARY_RESULT_CONTRACT')
        self.assertIsNone(worker.application_recovery_mode(
            dict(base, canary_result_recovery_attempts=1)))
        self.assertIsNone(worker.application_recovery_mode(
            dict(base, last_error='Publisher invocation failed: timeout')))
        self.assertIsNone(worker.application_recovery_mode(
            dict(base, status='VERIFIED')))

    def test_resource_scoped_policy_recovery_matches_only_exact_unused_failure(self):
        base = {'status': 'UNKNOWN', 'last_error':
            'Publisher invocation failed: Lambda FunctionError=Unhandled; '
            'remote=AccessDeniedException: An error occurred (AccessDeniedException) '
            'when calling the CreatePolicy operation: assumed-role/'
            'authority-delta-customer-publisher is not authorized to perform: '
            'bedrock-agentcore:ManageResourceScopedPolicy'}
        self.assertEqual(worker.application_recovery_mode(base),
                         'RESOURCE_SCOPED_POLICY_IAM')
        self.assertIsNone(worker.application_recovery_mode(
            dict(base, resource_scoped_policy_recovery_attempts=1)))
        self.assertIsNone(worker.application_recovery_mode(
            dict(base, last_error='CreatePolicy denied')))

    def test_gateway_policy_validation_recovery_matches_exact_unused_failure(self):
        base = {'status': 'UNKNOWN', 'last_error':
            'Publisher invocation failed: Lambda FunctionError=Unhandled; '
            'remote=AccessDeniedException: An error occurred (AccessDeniedException) '
            'when calling the CreatePolicy operation: Failed to confirm existence '
            'on AgentCore Gateway "authority-delta-gateway-test", please make sure '
            'you have "bedrock-agentcore:GetGateway" permissions'}
        self.assertEqual(worker.application_recovery_mode(base),
                         'GATEWAY_POLICY_VALIDATION_IAM')
        self.assertIsNone(worker.application_recovery_mode(dict(
            base, gateway_policy_validation_recovery_attempts=1)))
        self.assertIsNone(worker.application_recovery_mode(
            dict(base, last_error='CreatePolicy denied')))

    def test_failed_policy_target_recovery_matches_exact_unused_failure(self):
        base = {'status': 'UNKNOWN', 'last_error':
            'Publisher invocation failed: Lambda FunctionError=Unhandled; '
            'remote=ValueError: Owned candidate Policy entered a failed state'}
        self.assertEqual(worker.application_recovery_mode(base),
                         'FAILED_POLICY_TARGET_DISCOVERY')
        self.assertIsNone(worker.application_recovery_mode(dict(
            base, failed_policy_target_discovery_recovery_attempts=1)))
        self.assertIsNone(worker.application_recovery_mode(
            dict(base, last_error='Owned candidate Policy failed')))

    def test_policy_delete_response_recovery_matches_exact_unused_failure(self):
        base = {'status': 'UNKNOWN', 'last_error':
            'Publisher invocation failed: Lambda FunctionError=Unhandled; '
            'remote=ValueError: Failed candidate Policy delete lacks successful AWS evidence'}
        self.assertEqual(worker.application_recovery_mode(base),
                         'POLICY_DELETE_RESPONSE_CONTRACT')
        self.assertIsNone(worker.application_recovery_mode(dict(
            base, policy_delete_response_recovery_attempts=1)))
        self.assertIsNone(worker.application_recovery_mode(dict(
            base, last_error='Policy delete failed')))

    def test_policy_create_response_recovery_matches_exact_unused_failure(self):
        base = {'status': 'UNKNOWN', 'last_error':
            'Publisher invocation failed: Lambda FunctionError=Unhandled; '
            'remote=ValueError: Policy create lacks successful AWS evidence'}
        self.assertEqual(worker.application_recovery_mode(base),
                         'POLICY_CREATE_RESPONSE_CONTRACT')
        self.assertEqual(worker.application_recovery_mode(dict(
            base, policy_create_response_recovery_attempts=1)),
            'POLICY_CREATE_DISCOVERY_RECONCILIATION')
        self.assertIsNone(worker.application_recovery_mode(dict(
            base, last_error='Policy create failed')))

    def test_policy_create_discovery_recovery_is_consumed_once(self):
        base = {'status': 'UNKNOWN', 'last_error':
            'Publisher invocation failed: Lambda FunctionError=Unhandled; '
            'remote=ValueError: Policy create lacks successful AWS evidence',
            'policy_create_response_recovery_attempts': 1}
        self.assertEqual(worker.application_recovery_mode(base),
                         'POLICY_CREATE_DISCOVERY_RECONCILIATION')
        self.assertIsNone(worker.application_recovery_mode(dict(
            base, policy_create_discovery_recovery_attempts=1)))

    def test_policy_create_discovery_preflight_accepts_one_exact_unjournaled_policy(self):
        from test_business_application_aws import candidate_fixture
        candidate, registration = candidate_fixture()
        application_id = candidate['application_id']
        state = {'application_id': application_id, 'status': 'UNKNOWN',
            'attempt': 54, 'last_error':
                'Publisher invocation failed: Lambda FunctionError=Unhandled; '
                'remote=ValueError: Policy create lacks successful AWS evidence',
            'policy_create_response_recovery_attempts': 1,
            'enforcement_digest': candidate['enforcement_digest'],
            'candidate_ref': {'exact': 'patched-read'}}
        journal = {'status': 'CLOSED_PROVEN', 'candidate': candidate,
            'policy_id': None,
            'policy_name': 'AuthorityDeltaApp_' + candidate['enforcement_digest'][:16]}
        item = lambda value: {'pk': {'S': 'pk'}, 'sk': {'S': 'sk'},
            'version': {'N': '1'}, 'data': {'S': json.dumps(value)}}

        class AppDdb:
            def scan(self, **values):
                return {'Items': [item(state)], 'ResponseMetadata': {
                    'HTTPStatusCode': 200, 'RequestId': 'application-scan'}}

        class CustomerDdb:
            calls = 0
            def get_item(self, **values):
                self.calls += 1
                return {'Item': item(journal) if self.calls == 1 else None,
                    'ResponseMetadata': {'HTTPStatusCode': 200,
                                         'RequestId': 'journal-read'}}

        class Control:
            policy_id = 'policy-created-before-response-validation'
            def list_policies(self, **values):
                return {'policies': [{'policyId': self.policy_id,
                    'name': journal['policy_name']}], 'ResponseMetadata': {
                        'HTTPStatusCode': 200, 'RequestId': 'policy-list'}}
            def get_policy(self, **values):
                return {'policyId': self.policy_id,
                    'policyEngineId': registration['policy_engine_id'],
                    'name': journal['policy_name'], 'status': 'ACTIVE',
                    'definition': {'cedar': {'statement':
                        candidate['policy_binding']['statement']}},
                    'ResponseMetadata': {'HTTPStatusCode': 200,
                                         'RequestId': 'policy-read'}}

        app = type('Session', (), {'client': lambda self, name: AppDdb()})()
        customer_ddb, control = CustomerDdb(), Control()
        customer = type('Session', (), {'client': lambda self, name:
            customer_ddb if name == 'dynamodb' else control})()
        with (patch.object(worker, 'stack', return_value=object()),
              patch.object(worker, 'outputs', return_value={
                  'AppTable': 'app-table', 'DataBucket': 'data-bucket'}),
              patch.object(worker, '_read_candidate', return_value=(
                  candidate, {'request_id': 'candidate-read'})),
              patch.object(worker, 'all_records', return_value=[])):
            result = worker.application_recovery_evidence(app, customer,
                registration, {'PublisherJournalTable': 'journal-table'},
                application_id)
        self.assertEqual(result['recovery_mode'],
                         'POLICY_CREATE_DISCOVERY_RECONCILIATION')
        self.assertEqual(result['journal_status'], 'CLOSED_PROVEN')
        self.assertEqual(result['policy_count'], 1)

    def test_canary_recovery_operator_scripts_are_bounded_and_valid_bash(self):
        root = Path(__file__).resolve().parents[1]
        names = ('account_b_canary_request_id_fix.sh',
                 'account_a_canary_request_id_recovery.sh')
        for name in names:
            path = root / 'operator/ro07' / name
            subprocess.run(['bash', '-n', str(path)], check=True)
            source = path.read_text()
            self.assertIn('set -euo pipefail', source)
            self.assertIn('aws sts get-caller-identity', source)
        account_a = (root / 'operator/ro07' / names[1]).read_text()
        self.assertIn('application-84ed051249524be2adc7d0d46f0503c5', account_a)
        self.assertIn('--recovery-application-id "$application_id"', account_a)
        self.assertIn('READY_TO_CONTINUE_RO07_LIVE_ACCEPTANCE', account_a)

    def test_resource_scoped_policy_operator_scripts_are_bounded_valid_bash(self):
        root = Path(__file__).resolve().parents[1]
        names = ('account_b_resource_scoped_policy_fix.sh',
                 'account_a_resource_scoped_policy_recovery.sh')
        for name in names:
            path = root / 'operator/ro07' / name
            subprocess.run(['bash', '-n', str(path)], check=True)
            source = path.read_text()
            self.assertIn('set -euo pipefail', source)
            self.assertIn('aws sts get-caller-identity', source)
        account_b = (root / 'operator/ro07' / names[0]).read_text()
        self.assertIn('ManageResourceScopedPolicy', account_b)
        self.assertIn('ManageAdminPolicy', account_b)
        account_a = (root / 'operator/ro07' / names[1]).read_text()
        self.assertIn('--recovery-application-id "$application_id"', account_a)
        self.assertIn('READY_TO_CONTINUE_RO07_LIVE_ACCEPTANCE', account_a)

    def test_gateway_policy_validation_operator_scripts_are_bounded_and_fast(self):
        root = Path(__file__).resolve().parents[1]
        names = ('account_b_gateway_policy_validation_fix.sh',
                 'account_a_gateway_policy_validation_recovery.sh')
        for name in names:
            path = root / 'operator/ro07' / name
            subprocess.run(['bash', '-n', str(path)], check=True)
            source = path.read_text()
            self.assertIn('set -euo pipefail', source)
            self.assertIn('aws sts get-caller-identity', source)
        account_b = (root / 'operator/ro07' / names[0]).read_text()
        self.assertIn('bedrock-agentcore:GetGateway', account_b)
        self.assertIn('bedrock-agentcore:InvokeGateway', account_b)
        self.assertIn('ManageAdminPolicy', account_b)
        account_a = (root / 'operator/ro07' / names[1]).read_text()
        self.assertIn('--recovery-application-id "$application_id"', account_a)
        self.assertIn('seq 1 9', account_a)
        self.assertNotIn('seq 1 90', account_a)

    def test_failed_policy_target_operator_scripts_are_bounded_and_fast(self):
        root = Path(__file__).resolve().parents[1]
        names = ('account_b_gateway_target_read_fix.sh',
                 'account_a_failed_policy_target_recovery.sh')
        for name in names:
            path = root / 'operator/ro07' / name
            subprocess.run(['bash', '-n', str(path)], check=True)
            source = path.read_text()
            self.assertIn('set -euo pipefail', source)
            self.assertIn('aws sts get-caller-identity', source)
        account_b = (root / 'operator/ro07' / names[0]).read_text()
        self.assertIn('bedrock-agentcore:ListGatewayTargets', account_b)
        self.assertIn('bedrock-agentcore:GetGatewayTarget', account_b)
        self.assertIn('ManageAdminPolicy', account_b)
        account_a = (root / 'operator/ro07' / names[1]).read_text()
        self.assertIn('--recovery-application-id "$application_id"', account_a)
        self.assertIn('seq 1 9', account_a)
        self.assertNotIn('seq 1 90', account_a)

    def test_discovery_policy_read_operator_scripts_are_bounded_and_fast(self):
        root = Path(__file__).resolve().parents[1]
        names = ('account_b_discovery_policy_read_fix.sh',
                 'account_a_discovery_policy_read_recovery.sh')
        for name in names:
            path = root / 'operator/ro07' / name
            subprocess.run(['bash', '-n', str(path)], check=True)
            source = path.read_text()
            self.assertIn('set -euo pipefail', source)
            self.assertIn('aws sts get-caller-identity', source)
        account_b = (root / 'operator/ro07' / names[0]).read_text()
        self.assertIn('bedrock-agentcore:GetPolicy', account_b)
        self.assertIn('bedrock-agentcore:DeletePolicy', account_b)
        account_a = (root / 'operator/ro07' / names[1]).read_text()
        self.assertIn('--recovery-application-id "$application_id"', account_a)
        self.assertIn('seq 1 9', account_a)
        self.assertNotIn('seq 1 90', account_a)

    def test_policy_delete_contract_operator_scripts_are_bounded_and_fast(self):
        root = Path(__file__).resolve().parents[1]
        names = ('account_b_policy_delete_contract_fix.sh',
                 'account_a_policy_delete_response_recovery.sh')
        for name in names:
            path = root / 'operator/ro07' / name
            subprocess.run(['bash', '-n', str(path)], check=True)
            source = path.read_text()
            self.assertIn('set -euo pipefail', source)
            self.assertIn('aws sts get-caller-identity', source)
        account_b = (root / 'operator/ro07' / names[0]).read_text()
        self.assertIn("operation.http.get('responseCode') != 202", account_b)
        self.assertIn('ACCOUNT_B_POLICY_DELETE_CONTRACT_FIX_PASS', account_b)
        account_a = (root / 'operator/ro07' / names[1]).read_text()
        self.assertIn('--recovery-application-id "$application_id"', account_a)
        self.assertIn('seq 1 9', account_a)
        self.assertNotIn('seq 1 90', account_a)

    def test_policy_create_contract_operator_scripts_are_bounded_and_fast(self):
        root = Path(__file__).resolve().parents[1]
        names = ('account_b_policy_create_contract_fix.sh',
                 'account_a_policy_create_response_recovery.sh')
        for name in names:
            path = root / 'operator/ro07' / name
            subprocess.run(['bash', '-n', str(path)], check=True)
            source = path.read_text()
            self.assertIn('set -euo pipefail', source)
            self.assertIn('aws sts get-caller-identity', source)
        account_b = (root / 'operator/ro07' / names[0]).read_text()
        self.assertIn("operation.http.get('responseCode') != 202", account_b)
        self.assertIn('ACCOUNT_B_POLICY_CREATE_CONTRACT_FIX_PASS', account_b)
        account_a = (root / 'operator/ro07' / names[1]).read_text()
        self.assertIn('--recovery-application-id "$application_id"', account_a)
        self.assertIn('seq 1 9', account_a)
        self.assertNotIn('seq 1 90', account_a)
        self.assertIn('CURRENT_APPLICATION_STATE_NOT_RECOVERABLE_BY_V3',
                      account_a)
        self.assertIn('application_recovery_mode', account_a)

    def test_live_readback_must_match_report_and_remain_policy_ledger_empty(self):
        report = connector_report()
        registry = worker.validate_connector_report(report)
        binding = report['observed_binding']
        runtime = binding['runtime']
        observed = {'account': ACCOUNT_B, 'connection_id': binding['connection_id'],
            'target_id': binding['target_id'], 'target_name': binding['target_name'],
            'registry_hash': 'r' * 64, 'ledger_hash': 'l' * 64,
            'baseline': {'GatewayArn': binding['gateway_arn'],
                'GatewayIdentifier': binding['gateway_id'],
                'PolicyEngineId': binding['policy_engine_id'],
                'RequestRegistryTableName': binding['request_registry_table_name'],
                'SandboxLedgerTableName': binding['sandbox_ledger_table_name']},
            'runtimes': {'V2RuntimeId': runtime['runtime_id'],
                'V2RuntimeArn': runtime['runtime_arn'],
                'V2RuntimeVersion': runtime['runtime_version'],
                'V2EndpointName': runtime['endpoint_name'],
                'V2EndpointArn': runtime['endpoint_arn'],
                'V2ExecutionRoleArn': runtime['execution_role_arn']}}
        class Client:
            def get_function_configuration(self, FunctionName):
                return {'State': 'Active', 'LastUpdateStatus': 'Successful',
                    'FunctionArn': FunctionName, 'CodeSha256': 'code'}
            def list_policies(self, **values):
                return {'policies': []}
            def scan(self, **values):
                return {'Items': []}
        customer = type('Session', (), {'client': lambda self, name: Client()})()
        connector_stack = {'StackId': report['connector_stack_id'],
            'StackStatus': 'CREATE_COMPLETE', 'Outputs': [
                {'OutputKey': key, 'OutputValue': value}
                for key, value in report['connector_outputs'].items()]}
        with (patch.object(worker, 'assume_customer', return_value=(customer,
                  {'role_arn': registry['registrations'][0]['discovery_binding']['role_arn']})),
              patch.object(worker, 'observe_customer', return_value=observed),
              patch.object(worker, 'stack', return_value=connector_stack),
              patch.object(worker, 'verify_publisher_journal_permissions',
                           return_value={'actions': ['dynamodb:DeleteItem']})):
            result = worker.verify_customer(object(), report, registry, 'build')
        self.assertEqual(result['registration_hash'], report['registration_hash'])
        self.assertEqual(set(result['functions']),
                         {'PublisherFunctionArn', 'CanaryFunctionArn',
                          'InvocationFunctionArn'})
        self.assertEqual((result['policy_count'], result['ledger_count']), (0, 0))

    def test_execute_restores_empty_source_registry_after_business_deployment(self):
        report = connector_report()
        registry = worker.validate_connector_report(report)
        class Sts:
            def get_caller_identity(self):
                return {'Account': worker.ACCOUNT, 'Arn':
                    f'arn:aws:sts::{worker.ACCOUNT}:assumed-role/ReadinessOpsAuthorityDeltaDeployer/build'}
        session = type('Session', (), {'client': lambda self, name: Sts()})()
        environment = self.environment()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / 'services/business/adapter_registrations.json'
            path.parent.mkdir(parents=True)
            original = b'{"schema_version":"1.0","registrations":[]}\n'
            path.write_bytes(original)
            def business_executor(session, env, result, **kwargs):
                packaged = json.loads(path.read_text())
                self.assertEqual(packaged['registrations'][0]['registration_hash'],
                                 report['registration_hash'])
                result.update(result='PASS', approval_recorded=False,
                              state_unchanged=True, business_assessment_canary='PASS')
            with (patch.object(worker, 'load_connector_report',
                               return_value=(report, registry)),
                  patch.object(worker, 'verify_customer', return_value={
                      'registration_hash': report['registration_hash']}),
                  # This test isolates source-registry restoration. The real
                  # finalizer is exercised by test_wiring_composed_delivery.
                  patch.object(worker, 'verify_protected_baseline')):
                result = worker.execute(session, environment, {}, root=root,
                    business_executor=business_executor)
            self.assertEqual(path.read_bytes(), original)
        self.assertEqual(result['customer_registry'], 'VERIFIED_AND_DEPLOYED')
        self.assertEqual(result['policy_write'], 'NOT_RUN')
        self.assertEqual(result['human_workflow'], 'NOT_RUN')


if __name__ == '__main__':
    unittest.main()
