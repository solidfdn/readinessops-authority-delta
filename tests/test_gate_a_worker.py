"""Gate A worker integration against stateful, SDK-shape-checked AWS doubles.

The doubles execute the real fixed Runtime service, evaluator and sandbox tool.
They test orchestration and evidence boundaries; they do not claim a live AWS gate.
"""
from __future__ import annotations

import base64
import copy
from contextlib import redirect_stdout
from datetime import datetime, timezone
import hashlib
import io
import json
from pathlib import Path
import shutil
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from botocore.exceptions import ClientError
from botocore.session import Session as BotocoreSession
from botocore.validate import validate_parameters

from authority_delta.canonical import sha256_json
from authority_delta.registry import FixtureBundle
from scripts import gate_a as worker
from scripts.gate_a_state import JOURNAL_KEY, Journal
from scripts.build_registry_seed import build_transaction
from scripts.build_runtime_artifact import release_document
from services.sandbox.handler import invoke as invoke_sandbox, TOOL_PARAMETERS
from services.vendor_agent.runtime import VendorRuntimeService


ROOT = Path(__file__).resolve().parents[1]
BINDING = json.loads((ROOT / 'infra/environments/development.json').read_text())
NOW = datetime(2026, 9, 9, 1, 2, 3, tzinfo=timezone.utc)
META = {'RequestId': 'sdk-request-test', 'HTTPStatusCode': 200}
MODELS = BotocoreSession()


def failure(code, operation):
    return ClientError({'Error': {'Code': code, 'Message': 'injected test response'},
        'ResponseMetadata': META}, operation)


class AwsClient:
    """Validate every worker input using the pinned botocore service model."""
    def __init__(self, state, service):
        self.state, self.service = state, service
        self.model = MODELS.get_service_model(service)

    def __getattr__(self, method):
        operation = ''.join(part.title() for part in method.split('_'))
        shape = self.model.operation_model(operation).input_shape
        def call(**arguments):
            validate_parameters(arguments, shape)
            self.state.calls.append((self.service, method, copy.deepcopy(arguments)))
            return self.state.dispatch(self.service, method, arguments)
        return call


class StatefulAws:
    def __init__(self, root):
        self.root = root
        self.fixtures = FixtureBundle.load(ROOT / 'fixtures/decision_cases.json')
        self.output = BINDING['resources']
        self.calls, self.clients, self.objects, self.ledger_records = [], {}, {}, {}
        self.registry = {entry['Put']['Item']['request_id']['S']: entry['Put']['Item']
            for entry in build_transaction(self.fixtures, self.output['RequestRegistryTableName'])}
        self.active_policies, self.deleted = {}, []
        self.counter, self.tool_calls = 0, 0
        self.fail_after_permit = False
        self.fail_delete = False
        self.allow_wrong_principal = False
        self.final_write_fails = False
        self.create_failure = None
        self.create_attempts = []
        self.runtime_errors = []
        self.previous_status = 'FAILED'
        self.runtimes = {}
        self.artifacts = {}
        self.environment = {'AD_EXPECTED_ACCOUNT': worker.ACCOUNT, 'AD_REGION': worker.REGION,
            'CODEBUILD_BUILD_ID': 'authority-delta-deploy:current-build',
            'AD_ARTIFACT_BUCKET': BINDING['artifact_bucket'], 'AD_REPORT_KEY': 'evidence/test/gate-a-result.json',
            'AD_SOURCE_SHA256': 'a' * 64}
        self.seed_object(worker.G0_KEY, {'result': 'PASS', 'gate_0': 'PASS', 'account': worker.ACCOUNT,
            'region': worker.REGION, 'build_id': 'authority-delta-deploy:prior-build',
            'source_sha256': 'b' * 64, 'gateway_default_deny': {'observed_calls': 7, 'state_unchanged': True},
            'after': {'stable': {'gateway_arn': self.output['GatewayArn'],
                'sandbox_code_sha256': BINDING['sandbox_code_sha256']}},
            'model_invocation': {'status': 'PASS', 'strands_invocation': 'NOT_RUN'}}, worker.G0_VERSION)
        for release in ('V1', 'V2'):
            runtime_id = 'AuthorityDelta' + release + '-abcdefghij'
            arn = f'arn:aws:bedrock-agentcore:{worker.REGION}:{worker.ACCOUNT}:runtime/{runtime_id}'
            self.runtimes[release] = {'RuntimeId': runtime_id, 'RuntimeArn': arn,
                'RuntimeVersion': '1', 'EndpointName': 'fixed_v1',
                'EndpointArn': arn + '/runtime-endpoint/fixed_v1',
                'ExecutionRoleArn': f'arn:aws:iam::{worker.ACCOUNT}:role/authority-delta-{release.lower()}'}
            path = root / ('release-' + release + '.json')
            path.write_text(json.dumps(release_document(self.fixtures, release)))

    def client(self, name, **kwargs):
        if name in ('bedrock', 'bedrock-runtime'):
            raise AssertionError('Gate A must reuse prior model evidence, not invoke a model')
        if name not in self.clients:
            self.clients[name] = AwsClient(self, name)
        return self.clients[name]

    def seed_object(self, key, value, version=None):
        body = json.dumps(value).encode() if isinstance(value, dict) else value
        self.counter += 1
        item = {'Body': body, 'VersionId': version or 'version-' + str(self.counter),
            'ETag': '"' + hashlib.md5(body).hexdigest() + '"', 'Metadata': {}}
        self.objects.setdefault(key, []).append(item)
        return item

    def saved_report(self):
        return json.loads(self.objects[self.environment['AD_REPORT_KEY']][-1]['Body'])

    def runtime_environment(self, release):
        return {'AD_ACCOUNT_ID': worker.ACCOUNT, 'AD_REGION': worker.REGION,
            'AD_GATEWAY_URL': self.output['GatewayUrl'], 'AD_GATEWAY_ID': self.output['GatewayIdentifier'],
            'AD_REGISTRY_TABLE': self.output['RequestRegistryTableName'],
            'AD_EXPECTED_ROLE_NAME': self.runtimes[release]['ExecutionRoleArn'].split('/')[-1]}

    def build_artifact(self, fixtures, release, output_path):
        output_path.parent.mkdir(parents=True, exist_ok=True)
        # Artifact packaging and HTTP behavior have separate actual-ZIP tests.
        content = ('fixed-runtime-' + release).encode()
        output_path.write_bytes(content)
        digest = hashlib.sha256(content).hexdigest()
        result = {'path': str(output_path), 'sha256': digest, 'release_id': release,
            'release_definition_hash': sha256_json(fixtures.releases[release].as_contract()),
            'request_registry_snapshot_hash': fixtures.request_registry_snapshot_hash, 'size_bytes': len(content)}
        self.artifacts[release] = {**result, 'key': f'runtime/{digest}/{release.lower()}.zip'}
        return result

    def get_request(self, request_id):
        value = self.registry.get(request_id)
        return None if value is None else json.loads(value['payload']['S'])

    def put_execution_if_absent(self, key, record):
        if key in self.ledger_records:
            return False
        self.ledger_records[key] = copy.deepcopy(record)
        return True

    def get_execution(self, key):
        return copy.deepcopy(self.ledger_records.get(key))

    def ledger_items(self):
        return [{'business_key': {'S': key}, 'payload': {'S': json.dumps(value)}}
            for key, value in sorted(self.ledger_records.items())]

    def gateway(self, release, tool, arguments, mcp_id):
        self.tool_calls += 1
        request_id = next(iter(arguments.values()))
        if self.active_policies and self.fail_after_permit:
            self.fail_after_permit = False
            raise RuntimeError('Injected Runtime failure after permit creation')
        expected_principal = 'arn:aws:sts::' + worker.ACCOUNT + ':assumed-role/' + self.runtime_environment(release)['AD_EXPECTED_ROLE_NAME']
        permitted = any((json.dumps(expected_principal) in policy['definition']['cedar']['statement'] or self.allow_wrong_principal)
            and json.dumps(request_id) in policy['definition']['cedar']['statement']
            and 'AgentCore::Action::' + json.dumps(tool) in policy['definition']['cedar']['statement']
            for policy in self.active_policies.values())
        aws_id = 'gateway-request-' + str(self.tool_calls)
        if not permitted:
            return {'http_status': 200, 'headers': {'x-amzn-requestid': aws_id}, 'body': {'jsonrpc': '2.0', 'id': mcp_id,
                'error': {'code': -32002, 'message': 'Tool Execution Denied: Tool call not allowed due to policy enforcement [No policy applies to the request (denied by default).]'}}}
        context = SimpleNamespace(client_context=SimpleNamespace(custom={
            'bedrockAgentCoreToolName': tool, 'bedrockAgentCoreAwsRequestId': aws_id,
            'bedrockAgentCoreMcpMessageId': mcp_id, 'bedrockAgentCoreGatewayId': self.output['GatewayIdentifier'],
            'bedrockAgentCoreTargetId': 'target-0123456789'}))
        value = invoke_sandbox(arguments, context, self)
        return {'http_status': 200, 'headers': {'x-amzn-requestid': aws_id}, 'body': {'jsonrpc': '2.0', 'id': mcp_id,
            'result': {'isError': False, 'content': [{'type': 'text', 'text': json.dumps(value)}]}}}

    def invoke_runtime(self, arguments):
        release = next(k for k, value in self.runtimes.items() if value['RuntimeArn'] == arguments['agentRuntimeArn'])
        self.assert_endpoint(arguments, release)
        state = self
        class BoundSession:
            def client(self, name, **kwargs):
                if name == 'sts':
                    return SimpleNamespace(get_caller_identity=lambda: {'Account': worker.ACCOUNT,
                        'Arn': 'arn:aws:sts::' + worker.ACCOUNT + ':assumed-role/' + state.runtime_environment(release)['AD_EXPECTED_ROLE_NAME'] + '/runtime-session',
                        'ResponseMetadata': META})
                return state.client(name)
        application = VendorRuntimeService(release_path=self.root / ('release-' + release + '.json'),
            environment=self.runtime_environment(release), session=BoundSession(),
            gateway_probe=SimpleNamespace(call=lambda *args: self.gateway(release, *args)))
        status, result = application.invoke(json.loads(arguments['payload']))
        return {'statusCode': status, 'response': io.BytesIO(json.dumps(result).encode()), 'ResponseMetadata': META}

    def assert_endpoint(self, arguments, release):
        if arguments['qualifier'] != self.runtimes[release]['EndpointName']:
            raise AssertionError('Worker invoked an unfixed endpoint')

    def dispatch(self, service, method, args):
        if service == 's3':
            key = args['Key']
            versions = self.objects.get(key, [])
            if method == 'put_object':
                if key == self.environment['AD_REPORT_KEY'] and self.final_write_fails:
                    raise failure('AccessDenied', 'PutObject')
                latest = versions[-1] if versions else None
                if args.get('IfNoneMatch') == '*' and latest is not None or 'IfMatch' in args and (latest is None or latest['ETag'] != args['IfMatch']):
                    raise failure('PreconditionFailed', 'PutObject')
                value = self.seed_object(key, bytes(args['Body']))
                value['Metadata'] = args.get('Metadata', {})
                return {k: value[k] for k in ('VersionId', 'ETag')}
            if not versions:
                raise failure('NoSuchKey', method)
            value = next((v for v in versions if v['VersionId'] == args['VersionId']), None) if 'VersionId' in args else versions[-1]
            if value is None:
                raise failure('NoSuchKey', method)
            return {k: io.BytesIO(v) if k == 'Body' else copy.deepcopy(v) for k, v in value.items() if method != 'head_object' or k != 'Body'}
        if service == 'sts':
            return {'Account': worker.ACCOUNT, 'Arn': f'arn:aws:sts::{worker.ACCOUNT}:assumed-role/ReadinessOpsAuthorityDeltaDeployer/AWSCodeBuild-test', 'ResponseMetadata': META}
        if service == 'codebuild':
            return {'builds': [{'id': args['ids'][0], 'buildStatus': self.previous_status}]}
        if service == 'dynamodb':
            if method == 'get_item':
                item = self.registry.get(args['Key']['request_id']['S'])
                return {'ResponseMetadata': META, **({'Item': copy.deepcopy(item)} if item else {})}
            return {'Items': copy.deepcopy(list(self.registry.values()) if args['TableName'] == self.output['RequestRegistryTableName'] else self.ledger_items())}
        if service == 'lambda':
            return {'State': 'Active', 'LastUpdateStatus': 'Successful',
                'CodeSha256': base64.b64encode(bytes.fromhex(BINDING['sandbox_code_sha256'])).decode(),
                'Environment': {'Variables': {'CONNECTION_ID': 'conn-demo', 'REQUEST_REGISTRY_TABLE': self.output['RequestRegistryTableName'], 'SANDBOX_LEDGER_TABLE': self.output['SandboxLedgerTableName']}}}
        if service == 'cloudformation':
            if method == 'validate_template':
                return {'Description': 'SDK-validated fixed-runtime template test'}
            values = self.output if args['StackName'] == BINDING['application_stack'] else {release + k: v for release, binding in self.runtimes.items() for k, v in binding.items()}
            return {'Stacks': [{'StackStatus': 'CREATE_COMPLETE', 'CreationTime': NOW,
                'Outputs': [{'OutputKey': k, 'OutputValue': v} for k, v in values.items()]}]}
        if service == 'bedrock-agentcore':
            if method == 'stop_runtime_session':
                return {'statusCode': 200}
            if self.runtime_errors:
                code = self.runtime_errors.pop(0)
                if code == 'TimeoutError':
                    raise TimeoutError('Injected ambiguous Runtime timeout')
                raise failure(code, 'InvokeAgentRuntime')
            return self.invoke_runtime(args)
        if service == 'bedrock-agentcore-control':
            if method == 'get_gateway':
                return {'gatewayArn': self.output['GatewayArn'], 'gatewayUrl': self.output['GatewayUrl'], 'status': 'READY',
                    'authorizerType': 'AWS_IAM', 'policyEngineConfiguration': {'arn': self.output['PolicyEngineArn'], 'mode': 'ENFORCE'}, 'ResponseMetadata': META}
            if method == 'get_policy_engine':
                return {'status': 'ACTIVE', 'policyEngineArn': self.output['PolicyEngineArn'], 'ResponseMetadata': META}
            if method == 'list_gateway_targets':
                return {'items': [{'targetId': 'target-0123456789'}]}
            if method == 'get_gateway_target':
                return {'status': 'READY', 'name': 'VendorPaymentTools', 'gatewayArn': self.output['GatewayArn'],
                    'targetId': 'target-0123456789', 'ResponseMetadata': META,
                    'targetConfiguration': {'mcp': {'lambda': {'lambdaArn': self.output['SandboxToolFunctionArn'],
                        'toolSchema': {'inlinePayload': [{'name': tool, 'inputSchema': {'type': 'object', 'required': [argument], 'properties': {argument: {'type': 'string'}}}}
                            for tool, argument in TOOL_PARAMETERS.items()]}}}}}
            if method == 'get_agent_runtime_endpoint':
                value = next(v for v in self.runtimes.values() if v['RuntimeId'] == args['agentRuntimeId'])
                return {'status': 'READY', 'liveVersion': value['RuntimeVersion'], 'targetVersion': value['RuntimeVersion'],
                    'agentRuntimeArn': value['RuntimeArn'], 'agentRuntimeEndpointArn': value['EndpointArn'], 'name':value['EndpointName'], 'id':value['EndpointName'], 'createdAt': NOW, 'lastUpdatedAt': NOW}
            if method == 'get_agent_runtime':
                release = next(k for k, v in self.runtimes.items() if v['RuntimeId'] == args['agentRuntimeId'])
                value, artifact = self.runtimes[release], self.artifacts[release]
                version = self.objects[artifact['key']][-1]['VersionId']
                return {'status': 'READY', 'agentRuntimeArn': value['RuntimeArn'], 'agentRuntimeVersion': value['RuntimeVersion'],
                    'roleArn': value['ExecutionRoleArn'], 'createdAt': NOW, 'updatedAt': NOW,
                    'protocolConfiguration': {'serverProtocol': 'HTTP'}, 'environmentVariables': self.runtime_environment(release),
                    'agentRuntimeArtifact': {'codeConfiguration': {'code': {'s3': {'bucket': BINDING['artifact_bucket'], 'prefix': artifact['key'], 'versionId': version}},
                        'runtime': 'PYTHON_3_12', 'entryPoint': ['runtime.py']}}}
            if method == 'list_policies':
                return {'policies': copy.deepcopy(list(self.active_policies.values()))}
            if method == 'create_policy':
                self.create_attempts.append(copy.deepcopy(args))
                if self.create_failure in ('timeout_before_commit', 'always_timeout'):
                    if self.create_failure == 'timeout_before_commit':
                        self.create_failure = None
                    raise TimeoutError('Injected timeout with no create response')
                policy_id = 'AuthorityDeltaPolicy-abcdefghij'
                value = {k: copy.deepcopy(args[k]) for k in ('policyEngineId', 'name', 'definition')}
                value.update(policyId=policy_id, status='ACTIVE', enforcementMode='ACTIVE', createdAt=NOW, updatedAt=NOW)
                self.active_policies[policy_id] = value
                return copy.deepcopy(value)
            if method == 'get_policy':
                if args['policyId'] not in self.active_policies:
                    raise failure('ResourceNotFoundException', 'GetPolicy')
                return copy.deepcopy(self.active_policies[args['policyId']])
            if method == 'delete_policy':
                if self.fail_delete:
                    raise failure('AccessDeniedException', 'DeletePolicy')
                self.deleted.append(args['policyId'])
                self.active_policies.pop(args['policyId'])
                return {}
        raise AssertionError('Unexpected AWS operation: ' + service + '.' + method)


class GateAWorkerTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        for name in ('infra/environments/development.json', 'fixtures/decision_cases.json', 'infra/vendor-runtimes/template.json'):
            destination = self.root / name
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / name, destination)
        self.aws = StatefulAws(self.root)

    def run_worker(self):
        def runner(*args, **kwargs):
            return worker.GateA(*args, **kwargs, run=lambda *a, **k: None, sleep=lambda seconds: None)
        with patch.object(worker, 'build_runtime_artifact', self.aws.build_artifact), redirect_stdout(io.StringIO()):
            code = worker.run_worker(self.aws, self.aws.environment, root=self.root, runner=runner)
        path = self.root / 'evidence/aws/gate-a-result.json'
        return code, json.loads(path.read_text())

    def test_complete_worker_executes_fixed_services_and_persists_datetime_evidence(self):
        code, report = self.run_worker()
        self.assertEqual(code, 0, report.get('error'))
        self.assertEqual(report['gate_a'], 'PASS')
        self.assertEqual(report['gate_b'], 'NOT_RUN')
        self.assertEqual(report['cleanup']['status'], 'PASS')
        self.assertEqual(report, self.aws.saved_report())
        self.assertEqual(len(report['replay_observations']), 14)
        self.assertEqual(len(self.aws.ledger_records), 2)
        self.assertEqual(self.aws.active_policies, {})
        self.assertEqual(len(self.aws.deleted), 1)
        self.assertEqual(report['runtime_control_evidence']['V1']['runtime']['createdAt'], '2026-09-09T01:02:03Z')
        self.assertEqual(report['new_model_invocation'], 'NOT_RUN')
        self.assertFalse({'bedrock', 'bedrock-runtime'} & set(self.aws.clients))
        changed = [v for v in report['replay_observations'] if v['case_id'] == 'P-002']
        self.assertEqual([v['observation']['judgment'] for v in changed], ['HUMAN_REVIEW', 'ALLOW'])
        tests = {v['label']: v for v in report['authorization_tests']}
        self.assertEqual(tests['AUTH-02-OTHER-PRINCIPAL']['outcome'], 'DENY')
        self.assertFalse(tests['AUTH-02-IDEMPOTENT-REPEAT']['execution_evidence']['created'])
        self.assertTrue(report['checkpoints'])
        self.assertTrue(all(json.loads(versions[-1]['Body'])['result'] == 'IN_PROGRESS'
            for key, versions in self.aws.objects.items() if key.startswith('evidence/test/gate-a-result-')))

    def test_runtime_failure_after_permit_is_reported_and_finally_revoked(self):
        self.aws.fail_after_permit = True
        code, report = self.run_worker()
        self.assertEqual(code, 1)
        self.assertEqual(report['result'], 'FAIL')
        self.assertEqual(report['gate_a'], 'NOT_PASSED')
        self.assertEqual(report['cleanup']['status'], 'PASS')
        self.assertEqual(self.aws.active_policies, {})
        self.assertEqual(len(self.aws.deleted), 1)
        self.assertEqual(report, self.aws.saved_report())
        self.assertEqual(json.loads(self.aws.objects[JOURNAL_KEY][-1]['Body'])['status'], 'CLEAN')

    def test_cleanup_failure_never_promotes_gate_and_retains_recoverable_journal(self):
        self.aws.fail_delete = True
        code, report = self.run_worker()
        self.assertEqual(code, 1)
        self.assertEqual(report['result'], 'FAIL')
        self.assertEqual(report['gate_a'], 'NOT_PASSED')
        self.assertNotEqual(report['cleanup']['status'], 'PASS')
        self.assertEqual(len(self.aws.active_policies), 1)
        journal = json.loads(self.aws.objects[JOURNAL_KEY][-1]['Body'])
        self.assertEqual(journal['status'], 'DELETING')
        self.assertEqual(journal['policy_id'], next(iter(self.aws.active_policies)))
        self.assertEqual(report, self.aws.saved_report())

    def test_retry_recovers_owned_policy_before_new_permit_and_preserves_idempotency(self):
        self.aws.fail_delete = True
        self.assertEqual(self.run_worker()[0], 1)
        initial_ledger = copy.deepcopy(self.aws.ledger_records)
        self.aws.fail_delete = False
        self.aws.environment['CODEBUILD_BUILD_ID'] = 'authority-delta-deploy:recovery-build'
        self.aws.environment['AD_REPORT_KEY'] = 'evidence/test/recovery-result.json'
        self.aws.calls.clear()
        code, report = self.run_worker()
        self.assertEqual(code, 0, report.get('error'))
        self.assertEqual(report['previous_run_recovery']['status'], 'PASS')
        self.assertEqual(report['cleanup']['status'], 'PASS')
        self.assertEqual(self.aws.ledger_records, initial_ledger)
        methods = [method for service, method, arguments in self.aws.calls]
        self.assertLess(methods.index('delete_policy'), methods.index('create_policy'))
        self.assertEqual(self.aws.active_policies, {})

    def test_other_principal_allow_is_failure_even_when_idempotent_ledger_unchanged(self):
        self.aws.allow_wrong_principal = True
        code, report = self.run_worker()
        self.assertEqual(code, 1)
        self.assertEqual(report['gate_a'], 'NOT_PASSED')
        test = next(v for v in report['authorization_tests'] if v['label'] == 'AUTH-02-OTHER-PRINCIPAL')
        self.assertEqual(test['ledger_before_hash'], test['ledger_after_hash'])
        self.assertEqual(test['status'], 'FAIL')
        self.assertEqual(report['cleanup']['status'], 'PASS')

    def test_unknown_creation_is_reconciled_with_exact_token_and_immediately_revoked(self):
        self.aws.create_failure = 'timeout_before_commit'
        code, report = self.run_worker()
        self.assertEqual(code, 1)
        self.assertEqual(report['gate_a'], 'NOT_PASSED')
        self.assertEqual(report['cleanup']['status'], 'PASS')
        self.assertEqual(len(self.aws.create_attempts), 2)
        self.assertEqual(self.aws.create_attempts[0], self.aws.create_attempts[1])
        self.assertEqual(len(self.aws.deleted), 1)
        self.assertEqual(self.aws.active_policies, {})
        self.assertEqual(self.aws.ledger_records, {})

    def test_only_documented_provisioning_conflict_retries_the_same_runtime_session(self):
        self.aws.runtime_errors = ['RetryableConflictException'] * 2
        code, report = self.run_worker()
        self.assertEqual(code, 0, report.get('error'))
        first = report['runtime_calls'][0]
        self.assertEqual(len(first['invocation_attempt_errors']), 2)
        calls = [args for service, method, args in self.aws.calls if method == 'invoke_agent_runtime']
        self.assertEqual(calls[0], calls[1])
        self.assertEqual(calls[1], calls[2])
        for error in ('ConflictException', 'TimeoutError'):
            with self.subTest(error=error):
                self.aws = StatefulAws(self.root)
                self.aws.runtime_errors = [error]
                code, report = self.run_worker()
                self.assertEqual(code, 1)
                self.assertEqual(report['gate_a'], 'NOT_PASSED')
                self.assertEqual(len([call for call in self.aws.calls if call[1] == 'invoke_agent_runtime']), 1)
                self.assertEqual(len(report['runtime_calls'][0]['invocation_attempt_errors']), 1)

    def test_unresolved_creation_keeps_journal_and_never_claims_cleanup_success(self):
        self.aws.create_failure = 'always_timeout'
        code, report = self.run_worker()
        self.assertEqual(code, 1)
        self.assertEqual(report['gate_a'], 'NOT_PASSED')
        self.assertNotEqual(report['cleanup']['status'], 'PASS')
        journal = json.loads(self.aws.objects[JOURNAL_KEY][-1]['Body'])
        self.assertEqual(journal['status'], 'RECONCILING')
        self.assertTrue(journal['client_token'])
        self.assertEqual(self.aws.deleted, [])
        self.assertEqual(report, self.aws.saved_report())

    def test_active_previous_writer_blocks_recovery_and_does_not_delete_its_policy(self):
        self.aws.fail_delete = True
        self.assertEqual(self.run_worker()[0], 1)
        old_policy = copy.deepcopy(self.aws.active_policies)
        self.aws.fail_delete = False
        self.aws.previous_status = 'IN_PROGRESS'
        self.aws.environment['CODEBUILD_BUILD_ID'] = 'authority-delta-deploy:next-build'
        self.aws.calls.clear()
        code, report = self.run_worker()
        self.assertEqual(code, 1)
        self.assertEqual(report['gate_a'], 'NOT_PASSED')
        self.assertEqual(self.aws.active_policies, old_policy)
        self.assertFalse([call for call in self.aws.calls if call[1] in ('create_policy', 'delete_policy', 'invoke_agent_runtime')])

    def test_tampered_owned_policy_statement_is_preserved_and_blocks_recovery(self):
        self.aws.fail_delete = True
        self.assertEqual(self.run_worker()[0], 1)
        policy_id = next(iter(self.aws.active_policies))
        self.aws.active_policies[policy_id]['definition']['cedar']['statement'] = 'permit(principal, action, resource);'
        self.aws.fail_delete = False
        self.aws.environment['CODEBUILD_BUILD_ID'] = 'authority-delta-deploy:next-build'
        self.aws.calls.clear()
        code, report = self.run_worker()
        self.assertEqual(code, 1)
        self.assertEqual(report['gate_a'], 'NOT_PASSED')
        self.assertNotEqual(report['cleanup']['status'], 'PASS')
        self.assertIn(policy_id, self.aws.active_policies)
        self.assertFalse([call for call in self.aws.calls if call[1] in ('create_policy', 'delete_policy')])

    def test_foreign_policy_is_preserved_without_creating_or_deleting_any_permit(self):
        foreign = {'policyId': 'ForeignPolicy-abcdefghij', 'name': 'CustomerOwnedPolicy',
            'policyEngineId': self.aws.output['PolicyEngineId'], 'definition': {'cedar': {'statement': 'permit(principal, action, resource);'}}}
        self.aws.active_policies[foreign['policyId']] = foreign
        code, report = self.run_worker()
        self.assertEqual(code, 1)
        self.assertEqual(report['gate_a'], 'NOT_PASSED')
        self.assertEqual(self.aws.active_policies, {foreign['policyId']: foreign})
        self.assertFalse([call for call in self.aws.calls if call[1] in ('create_policy', 'delete_policy', 'invoke_agent_runtime')])

    def test_final_upload_failure_is_nonzero_and_keeps_prior_checkpoint_and_local_report(self):
        self.aws.final_write_fails = True
        code, report = self.run_worker()
        self.assertEqual(code, 1)
        self.assertEqual(report['cleanup']['status'], 'PASS')
        self.assertNotIn(self.aws.environment['AD_REPORT_KEY'], self.aws.objects)
        self.assertIn('evidence/test/gate-a-result-latest.json', self.aws.objects)

    def test_journal_uses_creation_and_update_compare_and_swap(self):
        first = Journal(self.aws.client('s3'), BINDING['artifact_bucket'])
        concurrent = Journal(self.aws.client('s3'), BINDING['artifact_bucket'])
        first.write({'status': 'PREPARED', 'writer': 'first'})
        with self.assertRaises(ClientError) as error:
            concurrent.write({'status': 'PREPARED', 'writer': 'concurrent'})
        self.assertEqual(error.exception.response['Error']['Code'], 'PreconditionFailed')
        stale = Journal(self.aws.client('s3'), BINDING['artifact_bucket'])
        first.write({'status': 'CREATED', 'writer': 'first'})
        with self.assertRaises(ClientError):
            stale.write({'status': 'CLEAN', 'writer': 'stale'})
        self.assertEqual(json.loads(self.aws.objects[JOURNAL_KEY][-1]['Body']), {'status': 'CREATED', 'writer': 'first'})


if __name__ == '__main__':
    unittest.main()
