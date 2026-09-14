"""Contracts for the offline foundation-to-connector-to-wiring start gate."""
from contextlib import redirect_stdout
import hashlib
import io
import json
from pathlib import Path
import tempfile
import unittest

from scripts import check_connected_acceptance_readiness as checker
from tests.test_customer_wiring_operator import ACCOUNT_B, EXTERNAL_ID, connector_report


BUILD = {
    'foundation': 'authority-delta-deploy:foundation-test',
    'connector': 'authority-delta-deploy:connector-test',
    'wiring': 'authority-delta-deploy:wiring-test'}


def raw(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'),
                       allow_nan=False) + '\n').encode()


def collected_launch(scope, account, name, source_sha):
    return {'schema_version': '1.0', 'scope': scope, 'account': account,
        'region': checker.REGION, 'bucket': name + '-bucket',
        'project': 'authority-delta-deploy', 'source_sha256': source_sha,
        'source_key': 'source/' + source_sha + '.zip',
        'source_version': name + '-source-version',
        'report_key': 'evidence/' + ('1' * 32) + '/' + name + '-result.json',
        'build_id': BUILD[name], 'report_version_id': name + '-report-version',
        'build_status': 'SUCCEEDED', 'collection_result': 'COLLECTED'}


def chain():
    source = {'foundation': 'a' * 64, 'connector': 'b' * 64, 'wiring': 'c' * 64}
    connector = connector_report(EXTERNAL_ID)
    binding = connector['observed_binding']
    runtime = binding['runtime']
    registry_hash, ledger_hash = 'd' * 64, 'e' * 64
    foundation = {'schema_version': '1.0', 'scope': checker.FOUNDATION_SCOPE,
        'result': 'PASS', 'account': ACCOUNT_B, 'region': checker.REGION,
        'caller_arn': f'arn:aws:iam::{ACCOUNT_B}:root',
        'build_id': BUILD['foundation'], 'source_sha256': source['foundation'],
        'bootstrap_stack_id': 'bootstrap-stack', 'baseline_stack_id': 'baseline-stack',
        'runtime_stack_id': 'runtime-stack',
        'baseline_artifact': {'bucket': 'foundation-bucket',
            'key': 'foundation/sandbox.zip', 'version_id': 'baseline-version',
            'sha256': '3' * 64, 'size_bytes': 10},
        'runtime_artifacts': {
            'V1': {'bucket': 'foundation-bucket', 'key': 'runtime/v1.zip',
                   'version_id': 'v1', 'sha256': '4' * 64, 'size_bytes': 10},
            'V2': {'bucket': 'foundation-bucket', 'key': 'runtime/v2.zip',
                   'version_id': 'v2', 'sha256': '5' * 64, 'size_bytes': 10}},
        'request_registry': {'count': 7, 'hash': registry_hash, 'seeded': True},
        'observed': {'connection_id': binding['connection_id'],
            'target_id': binding['target_id'], 'target_name': binding['target_name'],
            'registry_hash': registry_hash, 'ledger_hash': ledger_hash,
            'runtimes': {'V2RuntimeId': runtime['runtime_id'],
                'V2RuntimeArn': runtime['runtime_arn'],
                'V2RuntimeVersion': runtime['runtime_version'],
                'V2EndpointName': runtime['endpoint_name'],
                'V2EndpointArn': runtime['endpoint_arn'],
                'V2ExecutionRoleArn': runtime['execution_role_arn']}},
        'policy_count': 0, 'ledger_count': 0, 'connector': 'NOT_RUN',
        'policy_write': 'NOT_RUN', 'live_canary': 'NOT_RUN',
        'business_publication': 'NOT_RUN'}
    connector.update(schema_version='1.0',
        caller_arn=f'arn:aws:iam::{ACCOUNT_B}:root',
        build_id=BUILD['connector'], source_sha256=source['connector'],
        baseline_readback={'connection_id': binding['connection_id'],
            'target_id': binding['target_id'], 'target_name': binding['target_name'],
            'registry_hash': registry_hash, 'ledger_hash': ledger_hash,
            'api_evidence': {'gateway': {'request_id': 'gateway-request'}}},
        runtime_policy={'policy_hash': 'f' * 64},
        artifact={'bucket': 'connector-bucket',
            'key': 'customer-connector-code/lambda.zip',
            'sha256': '1' * 64, 'version_id': 'artifact-version',
            'size_bytes': 123},
        adapter_registry_ref={'bucket': 'connector-bucket',
            'key': 'customer-connector/registry.json',
            'version_id': 'registry-version', 'sha256': '2' * 64, 'size': 123})
    connector_raw = raw(connector)
    wiring_input_version = 'account-a-connector-input-version'
    wiring = {'schema_version': '1.2', 'scope': checker.WIRING_SCOPE,
        'result': 'PASS', 'account': checker.ACCOUNT_A, 'region': checker.REGION,
        'build_id': BUILD['wiring'], 'source_sha256': source['wiring'],
        'customer_registry': 'VERIFIED_AND_DEPLOYED',
        'business_assessment_canary': 'PASS', 'human_workflow': 'NOT_RUN',
        'policy_write': 'NOT_RUN', 'live_customer_canary': 'NOT_RUN',
        'approval_recorded': False, 'state_unchanged': True,
        'customer_wiring': {'target_account_id': ACCOUNT_B,
            'connector_report_sha256': hashlib.sha256(connector_raw).hexdigest(),
            'connector_report_version': wiring_input_version,
            'verification': {'connector_stack_id': connector['connector_stack_id'],
                'registration_hash': connector['registration_hash'],
                'observed_registry_hash': registry_hash,
                'observed_ledger_hash': ledger_hash,
                'policy_count': 0, 'ledger_count': 0,
                'functions': {'PublisherFunctionArn': {}, 'CanaryFunctionArn': {},
                              'InvocationFunctionArn': {}}}}}
    documents = {'foundation_launch': collected_launch(
            checker.FOUNDATION_SCOPE, ACCOUNT_B, 'foundation', source['foundation']),
        'foundation_report': foundation,
        'connector_launch': collected_launch(
            checker.CONNECTOR_SCOPE, ACCOUNT_B, 'connector', source['connector']),
        'connector_report': connector,
        'wiring_launch': collected_launch(
            checker.WIRING_SCOPE, checker.ACCOUNT_A, 'wiring', source['wiring']),
        'wiring_report': wiring}
    documents['connector_launch'].update(external_id=EXTERNAL_ID)
    documents['connector_launch'].update(
        external_id_hash=hashlib.sha256(EXTERNAL_ID.encode()).hexdigest(),
        source_application_worker_role_arn=checker.SOURCE_APPLICATION_WORKER_ROLE)
    documents['wiring_launch'].update(target_account_id=ACCOUNT_B,
        connector_report_key=('customer-wiring-input/' +
            hashlib.sha256(connector_raw).hexdigest() +
            '/customer-connector-result.json'),
        connector_report_sha256=hashlib.sha256(connector_raw).hexdigest(),
        connector_report_version=wiring_input_version,
        registration_hash=connector['registration_hash'])
    return documents, {name: raw(value) for name, value in documents.items()}


class ConnectedAcceptanceReadinessTests(unittest.TestCase):
    def test_exact_chain_is_ready_without_granting_authority_or_exposing_external_id(self):
        documents, raws = chain()
        report = checker.check_chain(documents, raws)
        self.assertEqual(report['status'], 'READY_FOR_AUTHENTICATED_ACCEPTANCE')
        self.assertEqual(report['live_acceptance'], 'NOT_RUN')
        self.assertEqual(report['runtime_authority'], 'NOT_APPLIED_BY_THIS_CHECKER')
        self.assertNotIn(EXTERNAL_ID, json.dumps(report))

    def test_existing_foundation_path_does_not_require_a_redundant_foundation_run(self):
        documents, raws = chain()
        for name in ('foundation_launch', 'foundation_report'):
            documents.pop(name)
            raws.pop(name)
        report = checker.check_chain(documents, raws)
        self.assertEqual(report['status'], 'READY_FOR_AUTHENTICATED_ACCEPTANCE')
        self.assertEqual(report['foundation_evidence'],
                         'NOT_SUPPLIED_CONNECTOR_AND_WIRING_READBACK_USED')

    def test_mixed_or_unsafe_evidence_fails_closed(self):
        changes = [
            lambda values: values['foundation_report'].__setitem__('policy_count', 1),
            lambda values: values['foundation_report']['observed'].__setitem__(
                'target_id', 'OTHER'),
            lambda values: values['connector_report'].__setitem__('account', checker.ACCOUNT_A),
            lambda values: values['connector_report'].__setitem__(
                'registration_hash', '9' * 64),
            lambda values: values['connector_launch'].__setitem__(
                'external_id_hash', '6' * 64),
            lambda values: values['wiring_report'].__setitem__('approval_recorded', True),
            lambda values: values['wiring_launch'].__setitem__(
                'connector_report_sha256', '8' * 64),
            lambda values: values['wiring_report']['customer_wiring']['verification'].__setitem__(
                'observed_ledger_hash', '7' * 64),
        ]
        for index, change in enumerate(changes):
            with self.subTest(case=index):
                documents, raws = chain()
                change(documents)
                raws = {name: raw(value) for name, value in documents.items()}
                with self.assertRaises(ValueError):
                    checker.check_chain(documents, raws)

    def test_duplicate_members_and_nonfinite_numbers_are_rejected(self):
        for value in (b'{"result":"PASS","result":"FAIL"}', b'{"value":NaN}'):
            with self.subTest(value=value), self.assertRaises(ValueError):
                checker.decode_document(value)

    def test_cli_writes_blocked_result_for_tampered_input(self):
        documents, _ = chain()
        documents['wiring_report']['approval_recorded'] = True
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            arguments = []
            for name, value in documents.items():
                path = root / (name + '.json')
                path.write_bytes(raw(value))
                arguments.extend(['--' + name.replace('_', '-'), str(path)])
            output = root / 'result.json'
            arguments.extend(['--output', str(output)])
            with redirect_stdout(io.StringIO()):
                self.assertEqual(checker.main(arguments), 1)
            report = json.loads(output.read_text())
            self.assertEqual((report['result'], report['status']),
                             ('BLOCKED', 'NOT_READY'))
            self.assertNotIn(EXTERNAL_ID, output.read_text())


if __name__ == '__main__':
    unittest.main()
