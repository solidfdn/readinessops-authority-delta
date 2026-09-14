"""Delivery contracts for the recoverable account-B foundation launcher."""
from contextlib import contextmanager, redirect_stdout
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from zipfile import ZipFile

from scripts import launch_customer_foundation as launcher


ACCOUNT_B = '111122223333'
BUILD_ID = 'authority-delta-deploy:foundation-test'


class CliDouble:
    def __init__(self, *, account=ACCOUNT_B, active=False, final_missing=False,
                 result='PASS', build_status='SUCCEEDED', unsafe=False):
        self.account, self.active = account, active
        self.final_missing, self.result = final_missing, result
        self.build_status = build_status
        self.unsafe = unsafe
        self.calls, self.start_parameters, self.source_entries = [], None, []
        self.source_hash = None

    def run(self, *args, **kwargs):
        self.calls.append(args)
        action = args[:2]
        value = lambda name: args[args.index(name) + 1]
        if action == ('sts', 'get-caller-identity'):
            return {'Account': self.account, 'Arn': f'arn:aws:iam::{self.account}:root'}
        if action == ('iam', 'get-account-summary'):
            return {'SummaryMap': {'AccountMFAEnabled': 1}}
        if action == ('cloudformation', 'validate-template'):
            return {}
        if action == ('cloudformation', 'deploy'):
            self.assertEqual(value('--stack-name'), launcher.BOOTSTRAP_STACK)
            return None
        if action == ('cloudformation', 'describe-stacks'):
            return {'Stacks': [{'StackStatus': 'CREATE_COMPLETE', 'Outputs': [
                {'OutputKey': 'ArtifactBucketName', 'OutputValue': 'customer-artifacts'},
                {'OutputKey': 'BuildProjectName', 'OutputValue': 'authority-delta-deploy'}]}]}
        if action == ('codebuild', 'list-builds-for-project'):
            return {'ids': [BUILD_ID] if self.active else []}
        if action == ('codebuild', 'batch-get-builds'):
            return {'builds': [{'id': BUILD_ID,
                'currentPhase': 'BUILD' if self.active else 'COMPLETED',
                'buildStatus': 'IN_PROGRESS' if self.active else self.build_status,
                'logs': {}}]}
        if action == ('s3api', 'put-object'):
            if '--metadata' in args:
                self.source_hash = value('--metadata').split('=', 1)[1]
                with ZipFile(value('--body')) as archive:
                    self.source_entries = archive.namelist()
            return {'VersionId': 'object-version'}
        if action == ('s3api', 'get-object'):
            if self.final_missing:
                raise launcher.DeploymentError('NoSuchKey')
            path = Path(args[-1])
            path.parent.mkdir(parents=True, exist_ok=True)
            state_hash = 'c' * 64
            report = {'schema_version': '1.0',
                'scope': launcher.SCOPE,
                'account': ACCOUNT_B, 'region': launcher.REGION,
                'caller_arn': f'arn:aws:iam::{ACCOUNT_B}:root',
                'build_id': BUILD_ID, 'source_sha256': self.source_hash,
                'result': self.result, 'bootstrap_stack_id': 'bootstrap',
                'baseline_stack_id': 'baseline', 'runtime_stack_id': 'runtimes',
                'baseline_artifact': {'bucket': 'customer-artifacts',
                    'key': 'foundation/sandbox.zip', 'version_id': 'sandbox-version',
                    'sha256': 'a' * 64, 'size_bytes': 10},
                'runtime_artifacts': {
                    'V1': {'bucket': 'customer-artifacts', 'key': 'runtime/v1.zip',
                           'version_id': 'v1', 'sha256': 'b' * 64, 'size_bytes': 10},
                    'V2': {'bucket': 'customer-artifacts', 'key': 'runtime/v2.zip',
                           'version_id': 'v2', 'sha256': 'c' * 64, 'size_bytes': 10}},
                'request_registry': {'count': 7, 'hash': state_hash,
                                     'seeded': True},
                'observed': {'connection_id': 'conn-demo',
                    'target_id': 'TARGET123', 'target_name': 'VendorPaymentTools',
                    'registry_hash': state_hash, 'ledger_hash': 'd' * 64,
                    'runtimes': {'V2RuntimeId': 'runtime-id',
                        'V2RuntimeArn': 'runtime-arn', 'V2RuntimeVersion': '2',
                        'V2EndpointName': 'fixed_v2',
                        'V2EndpointArn': 'endpoint-arn',
                        'V2ExecutionRoleArn': 'execution-role-arn'}},
                'policy_count': 0, 'ledger_count': 0, 'connector': 'NOT_RUN',
                'policy_write': 'NOT_RUN', 'live_canary': 'NOT_RUN',
                'business_publication': 'NOT_RUN'}
            if self.unsafe:
                report['policy_count'] = 1
            path.write_text(json.dumps(report))
            return {'VersionId': 'report-version'}
        if action == ('codebuild', 'start-build'):
            self.start_parameters = args
            return {'build': {'id': BUILD_ID}}
        raise AssertionError(action)

    def assertEqual(self, left, right):
        if left != right:
            raise AssertionError((left, right))


def budget_value(operation):
    if operation == 'describe-budget':
        return {'Budget': {'BudgetType': 'COST', 'TimeUnit': 'MONTHLY',
            'BudgetLimit': {'Unit': 'USD', 'Amount': '50'}}}
    return {'Notifications': [
        {'NotificationType': 'ACTUAL', 'Threshold': value}
        for value in (20, 50, 100)] + [
        {'NotificationType': 'FORECASTED', 'Threshold': 80}]}


class CustomerFoundationLauncherTests(unittest.TestCase):
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

    def test_actual_archive_bootstrap_and_bound_start(self):
        with self.context() as (root, cli, output):
            self.assertEqual(launcher.launch(cli, delay=lambda _: None), 0)
            self.assertTrue({'buildspec.customer-foundation.yml',
                'scripts/deploy_customer_foundation.py',
                'scripts/launch_customer_foundation.py',
                'infra/customer-baseline/template.json',
                'infra/vendor-runtimes/template.json'} <= set(cli.source_entries))
            actions = [call[:2] for call in cli.calls]
            self.assertLess(actions.index(('cloudformation', 'deploy')),
                            actions.index(('s3api', 'put-object')))
            args = cli.start_parameters
            value = lambda name: args[args.index(name) + 1]
            self.assertEqual(value('--buildspec-override'),
                             'buildspec.customer-foundation.yml')
            record = json.loads((root.parent /
                'customer-foundation-latest-launch.json').read_text())
            self.assertEqual(record['report_version_id'], 'report-version')
            self.assertIn('connector', output.getvalue())

    def test_resume_does_not_bootstrap_upload_or_start_again(self):
        with self.context() as (root, cli, _):
            launcher.launch(cli, delay=lambda _: None)
            path = root.parent / 'customer-foundation-latest-launch.json'
            cli.calls.clear()
            self.assertEqual(launcher.launch(cli, resume=path,
                                             delay=lambda _: None), 0)
            actions = [call[:2] for call in cli.calls]
            self.assertNotIn(('cloudformation', 'deploy'), actions)
            self.assertNotIn(('codebuild', 'start-build'), actions)
            self.assertFalse(any(call[:2] == ('s3api', 'put-object') and
                '--metadata' in call for call in cli.calls))

    def test_account_a_and_active_build_stop_before_source_upload(self):
        with self.context(account=launcher.ACCOUNT_A) as (_, cli, _):
            with self.assertRaises(launcher.DeploymentError):
                launcher.launch(cli, delay=lambda _: None)
            self.assertNotIn(('cloudformation', 'deploy'), [c[:2] for c in cli.calls])
        with self.context(active=True) as (_, cli, _):
            with self.assertRaises(launcher.DeploymentError):
                launcher.launch(cli, delay=lambda _: None)
            self.assertFalse(any(c[:2] == ('s3api', 'put-object') and
                '--metadata' in c for c in cli.calls))

    def test_missing_report_requires_explicit_same_source_recovery(self):
        with self.context(final_missing=True) as (root, cli, output):
            with self.assertRaises(launcher.DeploymentError):
                launcher.launch(cli, delay=lambda _: None)
            path = root.parent / 'customer-foundation-latest-launch.json'
            previous = json.loads(path.read_text())
            self.assertIn('--recover', output.getvalue())
            cli.final_missing = False
            cli.calls.clear()
            self.assertEqual(launcher.launch(cli, recover=path,
                                             delay=lambda _: None), 0)
            current = json.loads(path.read_text())
            self.assertEqual(current['source_version'], previous['source_version'])
            self.assertEqual(current['recovered_from_build_id'], previous['build_id'])

    def test_unsafe_success_report_is_not_marked_collected(self):
        with self.context(unsafe=True) as (root, cli, _):
            with self.assertRaises(launcher.DeploymentError):
                launcher.launch(cli, delay=lambda _: None)
            record = json.loads((root.parent /
                'customer-foundation-latest-launch.json').read_text())
            self.assertNotEqual(record.get('collection_result'), 'COLLECTED')


if __name__ == '__main__':
    unittest.main()
