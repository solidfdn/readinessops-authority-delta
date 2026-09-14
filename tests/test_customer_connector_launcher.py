from contextlib import contextmanager, redirect_stdout
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from zipfile import ZipFile

from scripts import launch_customer_connector as launcher
from tests.test_customer_wiring_operator import connector_report


ACCOUNT_B = '111122223333'
BUILD_ID = 'authority-delta-deploy:11111111-2222-3333-4444-555555555555'


class CliDouble:
    def __init__(self, *, active=False, result='PASS', build_status='SUCCEEDED',
                 final_missing=False, unsafe=False):
        self.env, self.calls = {}, []
        self.active, self.result, self.build_status = active, result, build_status
        self.final_missing = final_missing
        self.unsafe = unsafe
        self.source_hash, self.source_entries, self.start_parameters = None, [], None
        self.external_id = None

    def run(self, *args, **kwargs):
        self.calls.append(args)
        action = args[:2]
        value = lambda name: args[args.index(name) + 1]
        if action == ('sts', 'get-caller-identity'):
            return {'Account': ACCOUNT_B, 'Arn': f'arn:aws:iam::{ACCOUNT_B}:root'}
        if action == ('iam', 'get-account-summary'):
            return {'SummaryMap': {'AccountMFAEnabled': 1}}
        if action == ('cloudformation', 'describe-stacks'):
            name = value('--stack-name')
            if name == 'authority-delta-bootstrap':
                outputs = {'ArtifactBucketName': 'customer-artifact-bucket',
                           'BuildProjectName': 'authority-delta-deploy'}
            elif name == 'authority-delta-customer-baseline':
                outputs = {'GatewayIdentifier': 'gateway-test'}
            elif name == 'authority-delta-vendor-runtimes':
                outputs = {'V2RuntimeId': 'runtime-test'}
            else:
                raise AssertionError(name)
            return {'Stacks': [{'StackStatus': 'CREATE_COMPLETE', 'Outputs': [
                {'OutputKey': key, 'OutputValue': item} for key, item in outputs.items()]}]}
        if action == ('codebuild', 'list-builds-for-project'):
            return {'ids': [BUILD_ID] if self.active else []}
        if action == ('codebuild', 'batch-get-builds'):
            return {'builds': [{'id': BUILD_ID,
                'currentPhase': 'BUILD' if self.active else 'COMPLETED',
                'buildStatus': 'IN_PROGRESS' if self.active else self.build_status,
                'logs': {}}]}
        if action == ('s3api', 'get-object'):
            if value('--key') == launcher.LATEST_KEY:
                raise launcher.DeploymentError('NoSuchKey')
            if self.final_missing:
                raise launcher.DeploymentError('NoSuchKey')
            path = Path(args[-1])
            path.parent.mkdir(parents=True, exist_ok=True)
            report = connector_report(self.external_id)
            binding = report['observed_binding']
            report.update(schema_version='1.0', account=ACCOUNT_B,
                build_id=BUILD_ID, source_sha256=self.source_hash,
                result=self.result, region=launcher.REGION,
                caller_arn=f'arn:aws:iam::{ACCOUNT_B}:root',
                baseline_readback={'connection_id': binding['connection_id'],
                    'target_id': binding['target_id'],
                    'target_name': binding['target_name'],
                    'registry_hash': 'c' * 64, 'ledger_hash': 'd' * 64,
                    'api_evidence': {}},
                runtime_policy={'policy_hash': 'e' * 64},
                artifact={'bucket': 'customer-artifact-bucket',
                    'key': 'customer-connector-code/lambda.zip',
                    'sha256': 'f' * 64, 'version_id': 'artifact-version',
                    'size_bytes': 123},
                adapter_registry_ref={'bucket': 'customer-artifact-bucket',
                    'key': 'customer-connector/registry.json',
                    'version_id': 'registry-version', 'sha256': 'a' * 64,
                    'size': 123})
            if self.unsafe:
                report['live_canary'] = 'PASS'
            path.write_text(json.dumps(report))
            return {'VersionId': 'report-version'}
        if action == ('s3api', 'put-object'):
            if '--metadata' in args:
                self.source_hash = value('--metadata').split('=', 1)[1]
                with ZipFile(value('--body')) as archive:
                    self.source_entries = archive.namelist()
            return {'VersionId': 'object-version'}
        if action == ('codebuild', 'start-build'):
            self.start_parameters = args
            variables = {item['name']: item['value'] for item in json.loads(
                value('--environment-variables-override'))}
            self.external_id = variables['AD_EXTERNAL_ID']
            return {'build': {'id': BUILD_ID}}
        raise AssertionError(action)


def budget_value(operation):
    if operation == 'describe-budget':
        return {'Budget': {'BudgetType': 'COST', 'TimeUnit': 'MONTHLY',
            'BudgetLimit': {'Unit': 'USD', 'Amount': '50'}}}
    return {'Notifications': [
        {'NotificationType': 'ACTUAL', 'Threshold': value}
        for value in (20, 50, 100)] + [
        {'NotificationType': 'FORECASTED', 'Threshold': 80}]}


class CustomerConnectorLauncherTests(unittest.TestCase):
    def test_new_release_after_collected_success_preserves_external_id(self):
        with self.context() as (root, cli, _):
            self.assertEqual(launcher.launch(cli, delay=lambda _: None), 0)
            path = root.parent / 'customer-connector-latest-launch.json'
            previous = json.loads(path.read_text())
            previous['bundle_version'] = '20260912-customer-connector-v2-principal-order'
            path.write_text(json.dumps(previous))
            cli.calls.clear()
            self.assertEqual(launcher.launch(cli, delay=lambda _: None), 0)
            current = json.loads(path.read_text())
            self.assertEqual(current['external_id'], previous['external_id'])
            self.assertEqual(current['recovered_from_build_id'], previous['build_id'])
            self.assertEqual(current['bundle_version'], launcher.BUNDLE_VERSION)
            self.assertEqual(sum(c[:2] == ('codebuild', 'start-build')
                                 for c in cli.calls), 1)

    def test_new_source_after_failed_build_preserves_external_id(self):
        with self.context(build_status='FAILED') as (root, cli, output):
            with self.assertRaises(launcher.DeploymentError):
                launcher.launch(cli, delay=lambda _: None)
            path = root.parent / 'customer-connector-latest-launch.json'
            previous = json.loads(path.read_text())
            previous['bundle_version'] = '20260911-customer-connector-v1'
            path.write_text(json.dumps(previous))
            cli.calls.clear()
            original_run = cli.run
            def run(*args, **kwargs):
                if args[:2] == ('codebuild', 'start-build'):
                    cli.build_status = 'SUCCEEDED'
                return original_run(*args, **kwargs)
            with patch.object(cli, 'run', side_effect=run):
                self.assertEqual(launcher.launch(cli, delay=lambda _: None), 0)
            current = json.loads(path.read_text())
            self.assertEqual(current['external_id'], previous['external_id'])
            self.assertEqual(current['recovered_from_build_id'], previous['build_id'])
            self.assertEqual(current['bundle_version'], launcher.BUNDLE_VERSION)
            self.assertTrue(any(c[:2] == ('s3api', 'put-object') and '--metadata' in c for c in cli.calls))
            self.assertEqual(sum(c[:2] == ('codebuild', 'start-build') for c in cli.calls), 1)

    @contextmanager
    def context(self, **settings):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / 'repo'
            root.mkdir()
            cli = CliDouble(**settings)
            with (patch.object(launcher, 'ROOT', root),
                  patch.object(launcher, 'budget',
                    side_effect=lambda cli, account, operation: budget_value(operation)),
                  redirect_stdout(io.StringIO()) as output):
                yield root, cli, output

    def test_actual_archive_and_start_are_bound_and_recoverable(self):
        with self.context() as (root, cli, output):
            self.assertEqual(launcher.launch(cli, delay=lambda _: None), 0)
            self.assertTrue({'buildspec.customer-connector.yml',
                'scripts/deploy_customer_connector.py',
                'scripts/launch_customer_connector.py',
                'infra/customer-publisher/template.json',
                'services/customer_publisher/handler.py'} <= set(cli.source_entries))
            args = cli.start_parameters
            value = lambda name: args[args.index(name) + 1]
            self.assertEqual(value('--buildspec-override'),
                             'buildspec.customer-connector.yml')
            self.assertEqual(value('--source-version'), 'object-version')
            variables = {item['name']: item['value'] for item in json.loads(
                value('--environment-variables-override'))}
            self.assertEqual(variables['AD_SOURCE_APPLICATION_WORKER_ROLE_ARN'],
                             launcher.SOURCE_ROLE)
            self.assertEqual(len(variables['AD_EXTERNAL_ID']), 32)
            record = json.loads((root.parent /
                'customer-connector-latest-launch.json').read_text())
            self.assertEqual(record['report_version_id'], 'report-version')
            self.assertEqual(sum(call[:2] == ('codebuild', 'start-build')
                                 for call in cli.calls), 1)
            self.assertIn('business_publication', output.getvalue())

    def test_same_saved_launch_resumes_without_upload_or_duplicate_build(self):
        with self.context() as (root, cli, output):
            launcher.launch(cli, delay=lambda _: None)
            path = root.parent / 'customer-connector-latest-launch.json'
            cli.calls.clear()
            self.assertEqual(launcher.launch(cli, resume=path,
                                             delay=lambda _: None), 0)
            actions = [call[:2] for call in cli.calls]
            self.assertNotIn(('codebuild', 'start-build'), actions)
            self.assertFalse(any(call[:2] == ('s3api', 'put-object') and
                '--metadata' in call for call in cli.calls))

    def test_failed_report_or_build_never_passes(self):
        for settings in ({'result': 'FAIL'}, {'build_status': 'FAILED'}):
            with self.subTest(settings=settings), self.context(**settings) as (_, cli, _):
                with self.assertRaises(launcher.DeploymentError):
                    launcher.launch(cli, delay=lambda _: None)

    def test_active_build_prevents_source_upload(self):
        with self.context(active=True) as (_, cli, _):
            with self.assertRaises(launcher.DeploymentError):
                launcher.launch(cli, delay=lambda _: None)
            self.assertNotIn(('codebuild', 'start-build'),
                             [call[:2] for call in cli.calls])
            self.assertFalse(any(call[:2] == ('s3api', 'put-object') and
                '--metadata' in call for call in cli.calls))

    def test_terminal_missing_report_has_explicit_same_source_recovery(self):
        with self.context(final_missing=True) as (root, cli, output):
            with self.assertRaises(launcher.DeploymentError):
                launcher.launch(cli, delay=lambda _: None)
            path = root.parent / 'customer-connector-latest-launch.json'
            previous = json.loads(path.read_text())
            self.assertIn('--recover', output.getvalue())
            cli.final_missing = False
            cli.calls.clear()
            self.assertEqual(launcher.launch(cli, recover=path,
                                             delay=lambda _: None), 0)
            current = json.loads(path.read_text())
            self.assertEqual(current['external_id'], previous['external_id'])
            self.assertEqual(current['source_version'], previous['source_version'])
            self.assertEqual(current['recovered_from_build_id'], previous['build_id'])
            self.assertEqual(sum(call[:2] == ('codebuild', 'start-build')
                                 for call in cli.calls), 1)
            self.assertFalse(any(call[:2] == ('s3api', 'put-object') and
                '--metadata' in call for call in cli.calls))

    def test_unsafe_success_report_is_not_marked_collected(self):
        with self.context(unsafe=True) as (root, cli, _):
            with self.assertRaises(launcher.DeploymentError):
                launcher.launch(cli, delay=lambda _: None)
            record = json.loads((root.parent /
                'customer-connector-latest-launch.json').read_text())
            self.assertNotEqual(record.get('collection_result'), 'COLLECTED')


if __name__ == '__main__':
    unittest.main()
