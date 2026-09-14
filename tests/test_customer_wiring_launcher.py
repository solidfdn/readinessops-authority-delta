"""Delivery tests for the account-A customer wiring launcher."""
from contextlib import redirect_stdout
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from zipfile import ZipFile

from scripts import launch_customer_wiring as launcher
from tests.test_customer_wiring_operator import ACCOUNT_B, connector_report


ACCOUNT_A = '538522204923'
BUILD_ID = 'authority-delta-deploy:wiring-test'
BINDING = {'account': ACCOUNT_A, 'region': launcher.REGION,
    'artifact_bucket': 'account-a-bucket', 'project': 'authority-delta-deploy',
    'bootstrap_stack': 'authority-delta-bootstrap',
    'application_stack': 'authority-delta-customer-baseline',
    'resources': {'GatewayIdentifier': 'gateway-a'}}


class CliDouble:
    def __init__(self, *, account=ACCOUNT_A, active=False, final_missing=False,
                 unsafe=False):
        self.account, self.active, self.final_missing = account, active, final_missing
        self.unsafe = unsafe
        self.calls, self.source_entries, self.start_parameters = [], [], None
        self.source_hash, self.connector_digest = None, None

    def run(self, *args, **kwargs):
        self.calls.append(args)
        action = args[:2]
        value = lambda name: args[args.index(name) + 1]
        if action == ('sts', 'get-caller-identity'):
            return {'Account': self.account}
        if action == ('cloudformation', 'describe-stacks'):
            name = value('--stack-name')
            outputs = ({'ArtifactBucketName': BINDING['artifact_bucket'],
                        'BuildProjectName': BINDING['project']}
                       if name == BINDING['bootstrap_stack'] else BINDING['resources'])
            return {'Stacks': [{'StackStatus': 'CREATE_COMPLETE', 'Outputs': [
                {'OutputKey': key, 'OutputValue': item} for key, item in outputs.items()]}]}
        if action == ('codebuild', 'list-builds-for-project'):
            return {'ids': [BUILD_ID] if self.active else []}
        if action == ('codebuild', 'batch-get-builds'):
            return {'builds': [{'id': BUILD_ID,
                'buildStatus': 'IN_PROGRESS' if self.active else 'SUCCEEDED',
                'currentPhase': 'BUILD' if self.active else 'COMPLETED', 'logs': {}}]}
        if action == ('s3api', 'put-object'):
            if '--metadata' in args:
                if value('--key').startswith('source/'):
                    self.source_hash = value('--metadata').split('=', 1)[1]
                    with ZipFile(value('--body')) as archive:
                        self.source_entries = archive.namelist()
                elif value('--key').startswith('customer-wiring-input/'):
                    self.connector_digest = value('--metadata').split('=', 1)[1]
            return {'VersionId': 'object-version'}
        if action == ('codebuild', 'start-build'):
            self.start_parameters = args
            return {'build': {'id': BUILD_ID}}
        if action == ('s3api', 'get-object'):
            if self.final_missing:
                raise launcher.DeploymentError('NoSuchKey')
            registration_hash = connector_report()['registration_hash']
            result = {'schema_version': '1.2', 'scope': launcher.SCOPE,
                'account': ACCOUNT_A, 'region': launcher.REGION,
                'build_id': BUILD_ID, 'source_sha256': self.source_hash,
                'result': 'PASS', 'customer_registry': 'VERIFIED_AND_DEPLOYED',
                'business_assessment_canary': 'PASS', 'human_workflow': 'NOT_RUN',
                'policy_write': 'NOT_RUN', 'live_customer_canary': 'NOT_RUN',
                'approval_recorded': False, 'state_unchanged': True,
                'customer_wiring': {'target_account_id': ACCOUNT_B,
                    'connector_report_sha256': self.connector_digest,
                    'connector_report_version': 'object-version',
                    'verification': {'connector_stack_id': 'connector-stack',
                        'registration_hash': registration_hash,
                        'observed_registry_hash': 'c' * 64,
                        'observed_ledger_hash': 'd' * 64,
                        'policy_count': 0, 'ledger_count': 0,
                        'functions': {'PublisherFunctionArn': {},
                                      'CanaryFunctionArn': {},
                                      'InvocationFunctionArn': {}}}}}
            if self.unsafe:
                result['approval_recorded'] = True
            Path(args[-1]).write_text(json.dumps(result))
            return {'VersionId': 'report-version'}
        raise AssertionError(action)


class CustomerWiringLauncherTests(unittest.TestCase):
    def context(self, directory, **settings):
        root = Path(directory) / 'repo';root.mkdir()
        report = Path(directory) / 'connector.json'
        report.write_text(json.dumps(connector_report()))
        return root, report, CliDouble(**settings)

    def test_actual_archive_and_report_are_bound_to_one_build(self):
        with tempfile.TemporaryDirectory() as directory:
            root, report, cli = self.context(directory)
            with (patch.object(launcher, 'ROOT', root),
                  patch.object(launcher, 'binding', return_value=BINDING),
                  redirect_stdout(io.StringIO()) as output):
                self.assertEqual(launcher.launch(cli, connector_report=report,
                    delay=lambda _: None), 0)
            self.assertTrue({'buildspec.customer-wiring.yml',
                'scripts/deploy_customer_wiring.py',
                'scripts/launch_customer_wiring.py'} <= set(cli.source_entries))
            args = cli.start_parameters
            value = lambda name: args[args.index(name) + 1]
            self.assertEqual(value('--buildspec-override'), 'buildspec.customer-wiring.yml')
            variables = {item['name']: item['value'] for item in
                json.loads(value('--environment-variables-override'))}
            self.assertEqual(variables['AD_CONNECTOR_REPORT_VERSION'], 'object-version')
            self.assertIn('VERIFIED_AND_DEPLOYED', output.getvalue())

    def test_resume_has_no_upload_or_duplicate_start(self):
        with tempfile.TemporaryDirectory() as directory:
            root, report, cli = self.context(directory)
            with (patch.object(launcher, 'ROOT', root),
                  patch.object(launcher, 'binding', return_value=BINDING),
                  redirect_stdout(io.StringIO())):
                launcher.launch(cli, connector_report=report, delay=lambda _: None)
                path = root.parent / 'customer-wiring-latest-launch.json'
                cli.calls.clear()
                self.assertEqual(launcher.launch(cli, resume=path,
                    delay=lambda _: None), 0)
            actions = [call[:2] for call in cli.calls]
            self.assertNotIn(('codebuild', 'start-build'), actions)
            self.assertFalse(any(call[:2] == ('s3api', 'put-object') and
                                 '--metadata' in call for call in cli.calls))

    def test_repeating_same_command_collects_instead_of_running_another_canary(self):
        with tempfile.TemporaryDirectory() as directory:
            root, report, cli = self.context(directory)
            with (patch.object(launcher, 'ROOT', root),
                  patch.object(launcher, 'binding', return_value=BINDING),
                  redirect_stdout(io.StringIO())):
                launcher.launch(cli, connector_report=report, delay=lambda _: None)
                cli.calls.clear()
                self.assertEqual(launcher.launch(cli, connector_report=report, delay=lambda _: None),0)
            self.assertNotIn(('codebuild','start-build'),[call[:2] for call in cli.calls])
            self.assertFalse(any(call[:2] == ('s3api','put-object') and '--metadata' in call for call in cli.calls))

    def test_failed_model_diagnostics_are_visible_and_repeat_does_not_restart(self):
        with tempfile.TemporaryDirectory() as directory:
            root, report, cli = self.context(directory)
            original_run = cli.run
            def failing_run(*args, **kwargs):
                value = original_run(*args, **kwargs)
                if args[:2] == ('codebuild', 'batch-get-builds'):
                    value['builds'][0]['buildStatus'] = 'FAILED'
                if args[:2] == ('s3api', 'get-object'):
                    path = Path(args[-1])
                    failed = json.loads(path.read_text())
                    failed.update(result='FAIL', assessment_diagnostics={
                        'job_status': 'NEEDS_INPUT', 'attempt_count': 3,
                        'failure_classification': 'MODEL_OUTPUT_CONTRACT',
                        'validation_errors': [[{'path': 'actions.0.finding_ids',
                            'code': 'FINDING_REFERENCE', 'message': 'Action references an absent finding'}]]})
                    path.write_text(json.dumps(failed))
                return value
            with (patch.object(launcher, 'ROOT', root),
                  patch.object(launcher, 'binding', return_value=BINDING),
                  patch.object(cli, 'run', side_effect=failing_run),
                  redirect_stdout(io.StringIO()) as output):
                for _ in range(2):
                    with self.assertRaises(launcher.DeploymentError):
                        launcher.launch(cli, connector_report=report, delay=lambda _: None)
            self.assertEqual(sum(call[:2] == ('codebuild', 'start-build') for call in cli.calls), 1)
            self.assertIn('READINESSOPS_WIRING_FAILURE_DETAILS', output.getvalue())
            self.assertIn('MODEL_OUTPUT_CONTRACT', output.getvalue())
            self.assertIn('actions.0.finding_ids', output.getvalue())
            self.assertIn('Full report:', output.getvalue())
            record = json.loads((root.parent / 'customer-wiring-latest-launch.json').read_text())
            self.assertNotEqual(record.get('collection_result'), 'COLLECTED')

    def test_wrong_account_and_active_build_stop_before_report_upload(self):
        for settings in ({'account': ACCOUNT_B}, {'active': True}):
            with self.subTest(settings=settings), tempfile.TemporaryDirectory() as directory:
                root, report, cli = self.context(directory, **settings)
                with (patch.object(launcher, 'ROOT', root),
                      patch.object(launcher, 'binding', return_value=BINDING),
                      redirect_stdout(io.StringIO()), self.assertRaises(launcher.DeploymentError)):
                    launcher.launch(cli, connector_report=report, delay=lambda _: None)
                self.assertFalse(any(call[:2] == ('s3api', 'put-object')
                                     and '--metadata' in call for call in cli.calls))

    def test_unsafe_success_report_is_not_marked_collected(self):
        with tempfile.TemporaryDirectory() as directory:
            root, report, cli = self.context(directory, unsafe=True)
            with (patch.object(launcher, 'ROOT', root),
                  patch.object(launcher, 'binding', return_value=BINDING),
                  redirect_stdout(io.StringIO()),
                  self.assertRaises(launcher.DeploymentError)):
                launcher.launch(cli, connector_report=report, delay=lambda _: None)
            record = json.loads((root.parent /
                'customer-wiring-latest-launch.json').read_text())
            self.assertNotEqual(record.get('collection_result'), 'COLLECTED')


if __name__ == '__main__':
    unittest.main()
