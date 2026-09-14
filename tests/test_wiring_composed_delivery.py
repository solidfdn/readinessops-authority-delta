"""Real wiring/business control flow with local AWS doubles, never live evidence.

The old wiring test replaced the whole business executor with an already-PASS
report, including state_unchanged. That concealed the absent baseline finally.
These tests keep both real executors, proposal validation, Dynamo/S3 encoding,
versioned readback, CORS checks, final report persistence and exit status.
Only external services, artifact compilation and baseline observations are doubled.
"""
import copy
from contextlib import ExitStack, redirect_stdout
from datetime import datetime, timezone
import hashlib
import io
import json
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch

from botocore.exceptions import ClientError
import deploy_business as business
from scripts import deploy_customer_wiring as wiring
from check_connected_acceptance_readiness import validate_wiring_result
from authority_delta.business.storage import S3Blobs, encode
from support.business import observed
from test_customer_wiring_operator import connector_report


ROOT = Path(__file__).resolve().parents[1]


class ComposedDeliveryEnvironment:
    """Bounded service simulator. No AWS credentials or network calls are used."""

    def __init__(self, root, *, assessment='REVIEW_REQUIRED', bad_quote=False,
                 baseline_drift=False, baseline_unavailable=False,
                 cors_access_denied=False, final_save_failure=False,
                 assessment_sequence=None, recovery_application_id=None):
        self.root = root
        self.assessment = assessment
        self.bad_quote = bad_quote
        self.baseline_drift = baseline_drift
        self.baseline_unavailable = baseline_unavailable
        self.cors_access_denied = cors_access_denied
        self.final_save_failure = final_save_failure
        self.assessment_sequence = assessment_sequence or [assessment]
        self.dispatch_count = 0
        self.stored = {}
        self.items = {}
        self.calls = []
        self.observations = 0
        self.artifact_registries = []
        self.deployed = []
        self.parameters = {}
        self.current_ui_digest = None
        self.transport = connector_report()
        self.registry = wiring.validate_connector_report(self.transport)
        self.environment = {
            'AD_EXPECTED_ACCOUNT': wiring.ACCOUNT,
            'AD_REGION': wiring.REGION,
            'CODEBUILD_BUILD_ID': 'authority-delta-deploy:LOCAL-COMPOSITION',
            'AD_SOURCE_SHA256': 'a' * 64,
            'AD_ARTIFACT_BUCKET': 'local-artifacts',
            'AD_REPORT_KEY': 'evidence/local/customer-wiring-result.json',
            'AD_CONNECTOR_REPORT_KEY': 'customer-wiring-input/local/report.json',
            'AD_CONNECTOR_REPORT_VERSION': 'connector-version',
            'AD_CONNECTOR_REPORT_SHA256': hashlib.sha256(encode(self.transport)).hexdigest(),
        }
        if recovery_application_id:
            self.environment['AD_RECOVERY_APPLICATION_ID'] = recovery_application_id
        self.stored[('local-artifacts', self.environment['AD_CONNECTOR_REPORT_KEY'],
                     'connector-version')] = encode(self.transport)
        self.workspace = {
            'WorkspaceUrl': business.WORKSPACE_URL,
            'ReviewerUsername': 'okada',
            'UserPoolId': 'local-userpool',
            'ClientId': 'local-client',
            'AuthOrigin': 'https://auth.local.invalid',
            'ApiUrl': 'https://api.local.invalid',
            'ApiId': 'local-api',
            'SiteBucket': 'local-site',
        }
        self.resources = {
            'AnalysisRuntimeId': 'local-runtime',
            'AnalysisRuntimeVersion': '1',
            'AnalysisExecutionRoleArn': 'local-runtime-role',
            'ApiFunction': 'local-api-function',
            'WorkerFunction': 'local-worker-function',
            'DispatcherFunction': 'local-dispatcher-function',
            'ApplicationWorkerFunction': 'local-application-worker',
            'ApplicationDispatcherFunction': 'local-application-dispatcher',
            'InvocationGateFunction': 'local-invocation-gate',
            'InvocationWorkerFunction': 'local-invocation-worker',
            'JobsTable': 'local-jobs',
            'DataBucket': 'local-data',
        }
        self.baseline = {
            'stable': {'gateway': 'retained-gateway', 'mode': 'ENFORCE'},
            'policies': [], 'ledger': [],
            # The real evidence encoder must handle AWS datetime values.
            'observed_at': datetime(2026, 9, 12, 11, 0, tzinfo=timezone.utc),
        }
        for name in ('fixtures/decision_cases.json',
                     'infra/workbench/template.json', 'infra/business/template.json'):
            destination = root / name
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / name, destination)
        binding = root / 'infra/environments/development.json'
        binding.parent.mkdir(parents=True, exist_ok=True)
        binding.write_text(json.dumps({'artifact_bucket': 'local-artifacts'}))
        self.registry_path = root / 'services/business/adapter_registrations.json'
        self.registry_path.parent.mkdir(parents=True, exist_ok=True)
        self.original_registry = b'{"schema_version":"1.0","registrations":[]}\n'
        self.registry_path.write_bytes(self.original_registry)
        assets = root / 'services/workbench/assets'
        assets.mkdir(parents=True)
        manifest = {}
        for name, raw in {'index.html': b'<html>Local composition test</html>',
                          'app.js': b'/* Local test only */',
                          'app.css': b'body { color: navy; }'}.items():
            (assets / name).write_bytes(raw)
            manifest[name] = hashlib.sha256(raw).hexdigest()
        (assets / 'manifest.json').write_text(json.dumps(manifest))

    def client(self, name, **kwargs):
        self.calls.append(('client', name))
        return self

    def get_caller_identity(self):
        return {'Account': wiring.ACCOUNT, 'Arn':
                f'arn:aws:sts::{wiring.ACCOUNT}:assumed-role/'
                'ReadinessOpsAuthorityDeltaDeployer/local-composition'}

    def describe_stacks(self, StackName):
        values = self.workspace if StackName == business.WORKBENCH_STACK else self.resources
        return {'Stacks': [{'StackStatus': 'UPDATE_COMPLETE',
                            'Parameters': [{'ParameterKey': 'Existing', 'ParameterValue': 'keep'}],
                            'Outputs': [{'OutputKey': k, 'OutputValue': v}
                                        for k, v in values.items()]}]}

    def describe_stack_resource(self, **kwargs):
        return {'StackResourceDetail': {'PhysicalResourceId': 'local-authorizer'}}

    def admin_get_user(self, **kwargs):
        return {'UserStatus': 'CONFIRMED',
                'UserAttributes': [{'Name': 'sub', 'Value': 'retained-sub'}]}

    def validate_template(self, TemplateBody):
        json.loads(TemplateBody)
        return {}

    def run(self, command, **kwargs):
        assert command[:3] == ['aws', 'cloudformation', 'deploy']
        name = command[command.index('--stack-name') + 1]
        self.deployed.append(name)
        parameters = dict(v.split('=', 1) for v in command[command.index('--parameter-overrides') + 1:])
        self.parameters[name] = parameters
        if name == business.WORKBENCH_STACK:
            self.current_ui_digest = parameters['UiDigest']

    def build(self, destination, architecture, runtime, root):
        # Compiling locked dependencies is tested elsewhere. Keep the actual
        # injected registry bytes in the uploaded artifact for this boundary.
        registry = self.registry_path.read_bytes()
        self.artifact_registries.append(json.loads(registry))
        raw = encode({'local_artifact_only': architecture,
                      'runtime': runtime, 'registry': json.loads(registry)})
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(raw)
        return {'path': str(destination), 'sha256': hashlib.sha256(raw).hexdigest(),
                'size_bytes': len(raw), 'architecture': architecture}

    def put_object(self, Bucket, Key, Body, **kwargs):
        if self.final_save_failure and Key == self.environment['AD_REPORT_KEY']:
            raise ClientError({'Error': {'Code': 'AccessDenied',
                'Message': 'LOCAL evidence save denied'}}, 'PutObject')
        version = 'version-' + str(len(self.stored) + 1)
        self.stored[(Bucket, Key, version)] = bytes(Body)
        return {'VersionId': version}

    def get_object(self, Bucket, Key, VersionId):
        return {'VersionId': VersionId,
                'Body': io.BytesIO(self.stored[(Bucket, Key, VersionId)])}

    def get_agent_runtime(self, **kwargs):
        params = self.parameters[business.BUSINESS_STACK]
        return {
            'status': 'READY', 'roleArn': self.resources['AnalysisExecutionRoleArn'],
            'agentRuntimeVersion': self.resources['AnalysisRuntimeVersion'],
            'agentRuntimeArtifact': {'codeConfiguration': {'code': {'s3': {
                'bucket': 'local-artifacts', 'prefix': params['AnalysisArtifactKey'],
                'versionId': params['AnalysisArtifactVersionId']}}}},
            'environmentVariables': {'AD_ANALYSIS_MODEL_ID': 'apac.amazon.nova-pro-v1:0'},
        }

    def get_function_configuration(self, **kwargs):
        return {'State': 'Active', 'LastUpdateStatus': 'Successful'}

    def list_event_source_mappings(self, **kwargs):
        return {'EventSourceMappings': [
            {'State': 'Enabled', 'BatchSize': 1,
             'FunctionResponseTypes': ['ReportBatchItemFailures']} for _ in range(2)]}

    def transact_write_items(self, TransactItems):
        for item in TransactItems:
            put = item['Put']
            data = put['Item']
            key = (put['TableName'], data['pk']['S'], data['sk']['S'])
            assert key not in self.items
            self.items[key] = copy.deepcopy(data)
        return {}

    def get_item(self, TableName, Key, ConsistentRead):
        assert ConsistentRead
        key = (TableName, Key['pk']['S'], Key['sk']['S'])
        return {'Item': copy.deepcopy(self.items[key])}

    def invoke(self, FunctionName, **kwargs):
        if FunctionName == self.resources['ApiFunction']:
            return {'Payload': io.BytesIO(b'{"statusCode":401}')}
        assert FunctionName == self.resources['DispatcherFunction']
        # Simulate the external worker completing the real serialized job. The
        # deployment still retrieves, decodes and validates that persisted result.
        keys = [k for k, item in self.items.items() if k[2] == 'STATE'
                and json.loads(item['data']['S']).get('status') == 'QUEUED']
        key = keys[-1]
        item = self.items[key]
        job = json.loads(item['data']['S'])
        blobs = S3Blobs(self, self.resources['DataBucket'])
        source = json.loads(blobs.read(job['input_ref']))
        result = observed(source)
        result['runtime_evidence'] = {'request_id': 'LOCAL_SCRIPTED_RUNTIME_ONLY'}
        assessment = self.assessment_sequence[
            min(self.dispatch_count, len(self.assessment_sequence) - 1)]
        self.dispatch_count += 1
        if assessment == 'NEEDS_INPUT':
            result.update(status='NEEDS_INPUT', proposal=None,
                          failure_classification='MODEL_OUTPUT_CONTRACT',
                          diagnostic={'reason': 'LOCAL_MISSING_INPUT_HASH',
                                      'model_attempts': 3})
        if self.bad_quote:
            result['proposal']['findings'][0]['citations'][0]['quote'] = 'Fabricated quote.'
        result_ref = blobs.put('business/results/' + job['run_id'] + '.json', encode(result))
        job.update(status=assessment, attempt=1, result_ref=result_ref)
        if assessment == 'NEEDS_INPUT':
            job['diagnostics'] = 'The assessment could not produce a supported proposal.'
        item['data']['S'] = encode(job).decode()
        item['version']['N'] = '2'
        return {'Payload': io.BytesIO(b'{}')}

    def fetch(self, url):
        if url.startswith(self.workspace['ApiUrl']):
            return 401, b'{}'
        assert url.startswith(self.workspace['WorkspaceUrl'])
        name = url.removeprefix(self.workspace['WorkspaceUrl'])
        key = 'ui/' + self.current_ui_digest + '/' + name
        raw = next(raw for (bucket, object_key, _), raw in self.stored.items()
                   if bucket == self.workspace['SiteBucket'] and object_key == key)
        return 200, raw

    def browser_preflight(self, url, origin):
        # This is the observed AWS preflight form: no expose-headers header.
        return 200, {'access-control-allow-origin': origin,
                     'access-control-allow-methods': 'GET,OPTIONS,POST',
                     'access-control-allow-headers': 'authorization,content-type'}

    def get_api(self, ApiId):
        self.calls.append(('get_api', ApiId))
        assert ApiId == self.workspace['ApiId']
        if self.cors_access_denied:
            raise ClientError({'Error': {'Code': 'AccessDeniedException',
                                         'Message': 'LOCAL missing apigateway:GET permission'}},
                              'GetApi')
        return {'CorsConfiguration': {
            'AllowOrigins': [self.workspace['WorkspaceUrl'].rstrip('/')],
            'AllowMethods': ['GET', 'POST', 'OPTIONS'],
            'AllowHeaders': ['authorization', 'content-type'],
            'ExposeHeaders': ['x-request-id'],
        }}

    def observe_baseline(self, session, binding, fixtures):
        self.observations += 1
        if self.observations > 1 and self.baseline_unavailable:
            raise ValueError('LOCAL protected baseline readback unavailable')
        value = copy.deepcopy(self.baseline)
        if self.observations > 1 and self.baseline_drift:
            value['policies'] = [{'policyId': 'unexpected-policy'}]
        return value

    def execute_business(self, session, env, report, **kwargs):
        return business.execute(session, env, report, fetch=self.fetch,
                                sleep=lambda _: None, **kwargs)

    def invoke_main(self):
        with ExitStack() as patches:
            patches.enter_context(patch.dict('os.environ', self.environment, clear=True))
            patches.enter_context(patch('boto3.Session', return_value=self))
            patches.enter_context(patch.object(wiring, 'ROOT', self.root))
            # main -> real execute is retained; this adds only its dependency
            # injections. Do not replace a result with a preassembled PASS.
            real_execute = wiring.execute
            patches.enter_context(patch.object(wiring, 'execute', side_effect=
                lambda session, env, report: real_execute(
                    session, env, report, root=self.root, run=self.run,
                    business_executor=self.execute_business)))
            patches.enter_context(patch.object(wiring, 'verify_customer',
                return_value={'registration_hash': self.transport['registration_hash'],
                              'observed_registry_hash': 'c' * 64,
                              'observed_ledger_hash': 'd' * 64,
                              'connector_stack_id': self.transport['connector_stack_id'],
                              'policy_count': 0, 'ledger_count': 0,
                              'functions': {key: {'function_arn': self.transport['connector_outputs'][key],
                                                  'code_sha256': 'local-code-only'}
                                            for key in ('PublisherFunctionArn', 'CanaryFunctionArn',
                                                        'InvocationFunctionArn')}}))
            patches.enter_context(patch.object(business, 'build', side_effect=self.build))
            patches.enter_context(patch.object(business, 'resolve_analysis_model', return_value={
                'model_id': 'apac.amazon.nova-pro-v1:0', 'deployment_parameters': {}}))
            patches.enter_context(patch.object(business, 'observe_baseline', side_effect=self.observe_baseline))
            patches.enter_context(patch.object(business, 'browser_preflight', side_effect=self.browser_preflight))
            output = io.StringIO()
            with redirect_stdout(output):
                status = wiring.main()
        path = self.root / 'evidence/aws/customer-wiring-result.json'
        raw = path.read_bytes()
        report = json.loads(raw)
        stored = [body for (bucket, key, _), body in self.stored.items()
                  if bucket == self.environment['AD_ARTIFACT_BUCKET']
                  and key == self.environment['AD_REPORT_KEY']]
        assert stored == ([] if self.final_save_failure else [raw]), 'Final evidence persistence differs'
        assert self.registry_path.read_bytes() == self.original_registry
        return status, report, output.getvalue()


class WiringComposedDeliveryTests(unittest.TestCase):
    def execute(self, **options):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        environment = ComposedDeliveryEnvironment(Path(temporary.name), **options)
        status, report, output = environment.invoke_main()
        return environment, status, report, output

    def test_real_composed_success_checks_baseline_cors_and_persists_result(self):
        env, status, report, _ = self.execute()
        self.assertEqual(status, 0)
        self.assertEqual(report['result'], 'PASS')
        self.assertIs(report.get('state_unchanged'), True)
        self.assertEqual(env.observations, 2)
        self.assertEqual(report['baseline_before'], report['baseline_after'])
        self.assertEqual(report['customer_registry'], 'VERIFIED_AND_DEPLOYED')
        self.assertEqual(validate_wiring_result(report), report['customer_wiring'])
        self.assertEqual(report['business_canary']['status'], 'PASS')
        self.assertEqual(env.deployed, [business.BUSINESS_STACK, business.WORKBENCH_STACK])
        self.assertIn(('get_api', 'local-api'), env.calls)
        cors = report['delivery_checks']['browser_preflight']
        self.assertEqual(cors['configured_expose_headers'], ['x-request-id'])
        self.assertEqual(cors['actual_browser_header_access'], 'NOT_RUN')
        self.assertEqual(env.artifact_registries, [env.registry, env.registry])
        self.assertIs(report['approval_recorded'], False)
        self.assertEqual(report['policy_write'], 'NOT_RUN')

    def test_needs_input_preserves_diagnostics_and_verifies_baseline_before_exit(self):
        env, status, report, _ = self.execute(assessment='NEEDS_INPUT')
        self.assertEqual(status, 1)
        self.assertEqual(report['result'], 'FAIL')
        self.assertIn('Business assessment incomplete', report['error']['message'])
        self.assertEqual(report['business_canary']['job']['status'], 'NEEDS_INPUT')
        self.assertEqual(report['business_canary']['analysis']['diagnostic']['model_attempts'], 3)
        self.assertIs(report.get('state_unchanged'), True)
        self.assertEqual(env.observations, 2)
        self.assertEqual(report['baseline_before'], report['baseline_after'])
        self.assertEqual(env.deployed, [business.BUSINESS_STACK])
        self.assertNotIn(('get_api', 'local-api'), env.calls)

    def test_exact_recovery_retries_one_safe_model_contract_rejection(self):
        application_id = 'application-' + 'a' * 32
        env, status, report, _ = self.execute(
            assessment_sequence=['NEEDS_INPUT', 'REVIEW_REQUIRED'],
            recovery_application_id=application_id)
        self.assertEqual(status, 0)
        self.assertEqual(report['result'], 'PASS')
        self.assertEqual(env.dispatch_count, 2)
        self.assertEqual([item['status'] for item in
                          report['business_canary_attempts']],
                         ['NEEDS_INPUT', 'REVIEW_REQUIRED'])
        self.assertEqual(report['business_canary']['status'], 'PASS')
        self.assertIs(report['state_unchanged'], True)
        self.assertIs(report['approval_recorded'], False)

    def test_saved_model_success_with_fabricated_quote_still_fails(self):
        env, status, report, _ = self.execute(bad_quote=True)
        self.assertEqual(status, 1)
        self.assertEqual(report['result'], 'FAIL')
        self.assertIn('Quote must appear exactly', report['error']['message'])
        self.assertIs(report.get('state_unchanged'), True)
        self.assertEqual(env.deployed, [business.BUSINESS_STACK])

    def test_post_deployment_protected_policy_drift_cannot_leave_pass(self):
        env, status, report, _ = self.execute(baseline_drift=True)
        self.assertEqual(status, 1)
        self.assertEqual(report['result'], 'FAIL')
        self.assertIs(report.get('state_unchanged'), False)
        self.assertIn('Protected runtime baseline changed', report['state_error'])
        self.assertNotEqual(report['baseline_before']['policies'], report['baseline_after']['policies'])
        self.assertNotEqual(report.get('customer_registry'), 'VERIFIED_AND_DEPLOYED')

    def test_failed_final_observation_is_recorded_as_unverified_and_fails(self):
        env, status, report, _ = self.execute(baseline_unavailable=True)
        self.assertEqual(status, 1)
        self.assertEqual(report['result'], 'FAIL')
        self.assertIsNone(report.get('state_unchanged'))
        self.assertIn('baseline readback unavailable', report['state_error']['message'])
        self.assertEqual(env.observations, 2)

    def test_get_api_access_denied_is_not_hidden_by_successful_preflight(self):
        env, status, report, _ = self.execute(cors_access_denied=True)
        self.assertEqual(status, 1)
        self.assertEqual(report['result'], 'FAIL')
        self.assertEqual(report['error']['code'], 'AccessDeniedException')
        self.assertIs(report.get('state_unchanged'), True)
        self.assertIn(('get_api', 'local-api'), env.calls)
        self.assertNotIn('browser_preflight', report['delivery_checks'])

    def test_final_save_failure_retains_local_report_and_exits_nonzero(self):
        env, status, report, output = self.execute(final_save_failure=True)
        self.assertEqual(status, 1)
        self.assertIs(report['state_unchanged'], True)
        self.assertIn('ERROR saving customer wiring evidence', output)
        self.assertIn('LOCAL evidence save denied', output)
        self.assertEqual(env.observations, 2)


if __name__ == '__main__':
    unittest.main()
