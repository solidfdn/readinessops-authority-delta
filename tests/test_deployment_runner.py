from __future__ import annotations

from contextlib import redirect_stdout
import copy
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from scripts import launch_deployment as launch
from scripts import deploy_baseline as worker
from authority_delta.registry import FixtureBundle
from scripts.build_registry_seed import build_transaction

ROOT = Path(__file__).resolve().parents[1]


class SimulatedAwsCli:
    """Contract double: root STS AssumeRole fails; CodeBuild has separate service identity."""
    def __init__(self, *, fail_build=False, account=launch.ACCOUNT):
        self.calls = []
        self.fail_build = fail_build
        self.account = account
        self.source_hash = None

    def budgets(self, operation):
        if operation == 'describe-budget':
            return {'Budget': {'BudgetType': 'COST', 'TimeUnit': 'MONTHLY', 'BudgetLimit': {'Amount': '50', 'Unit': 'USD'}}}
        return {'Notifications': [{'NotificationType': kind, 'Threshold': value} for kind, value in [('ACTUAL', 20), ('ACTUAL', 50), ('FORECASTED', 80), ('ACTUAL', 100)]]}

    def run(self, *args, **kwargs):
        self.calls.append(args)
        action = args[:2]
        if action == ('sts', 'assume-role'):
            raise launch.DeploymentError('Roles may not be assumed by root accounts.')
        if action == ('sts', 'get-caller-identity'):
            return {'Account': self.account, 'Arn': f'arn:aws:iam::{self.account}:root'}
        if action == ('iam', 'get-account-summary'):
            return {'SummaryMap': {'AccountMFAEnabled': 1}}
        if action == ('cloudformation', 'validate-template'):
            return {'Capabilities': ['CAPABILITY_NAMED_IAM']}
        if action == ('cloudformation', 'deploy'):
            if args[args.index('--stack-name')+1] != launch.BOOTSTRAP_STACK:
                raise AssertionError('Root attempted application deployment.')
            return None
        if action == ('cloudformation', 'describe-stacks'):
            return {'Stacks': [{'StackStatus': 'UPDATE_COMPLETE', 'Outputs': [{'OutputKey': 'ArtifactBucketName', 'OutputValue': 'owned-build-artifacts'}, {'OutputKey': 'BuildProjectName', 'OutputValue': 'authority-delta-deploy'}]}]}
        if action == ('s3api', 'put-object'):
            self.source_hash = args[args.index('--metadata')+1].split('=', 1)[1]
            return {'VersionId': 'fixed-source-version'}
        if action == ('codebuild', 'start-build'):
            self.assert_source(args)
            return {'build': {'id': 'authority-delta-deploy:build-1'}}
        if action == ('codebuild', 'batch-get-builds'):
            return {'builds': [{'id': 'authority-delta-deploy:build-1', 'buildStatus': 'FAILED' if self.fail_build else 'SUCCEEDED', 'currentPhase': 'COMPLETED'}]}
        if action == ('s3api', 'get-object'):
            Path(args[-1]).write_text(json.dumps({'result': 'PASS', 'build_id': 'authority-delta-deploy:build-1', 'source_sha256': self.source_hash, 'gate_a': 'NOT_RUN'}))
            return {}
        raise AssertionError(f'Unexpected root operation: {action}')

    def assert_source(self, args):
        if args[args.index('--source-version')+1] != 'fixed-source-version':
            raise AssertionError('Source version was not bound.')


class DeploymentRunnerTests(unittest.TestCase):
    def test_root_recovery_launches_service_without_assume_role_or_application_writes(self):
        cli = SimulatedAwsCli()
        with tempfile.TemporaryDirectory() as directory, patch.object(launch, 'ROOT', Path(directory)), patch.object(launch, 'source_archive', side_effect=lambda path: (path.write_bytes(b'source'), 'hash')[1]), redirect_stdout(io.StringIO()) as output:
            launch.launch(cli)
            self.assertIn('AUTHORITY_DELTA_RESULT', output.getvalue())
            self.assertEqual(json.loads((Path(directory)/'evidence/aws/deployment-result.json').read_text())['gate_a'], 'NOT_RUN')
        self.assertNotIn(('sts', 'assume-role'), [c[:2] for c in cli.calls])
        self.assertFalse(any(c[0] in ('dynamodb', 'lambda', 'bedrock-agentcore-control') for c in cli.calls))

    def test_failed_build_never_prints_a_success_result(self):
        cli = SimulatedAwsCli(fail_build=True)
        with tempfile.TemporaryDirectory() as directory, patch.object(launch, 'ROOT', Path(directory)), patch.object(launch, 'source_archive', side_effect=lambda path: (path.write_bytes(b'source'), 'hash')[1]), redirect_stdout(io.StringIO()) as output:
            with self.assertRaises(launch.DeploymentError):
                launch.launch(cli)
            self.assertNotIn('AUTHORITY_DELTA_RESULT', output.getvalue())

    def test_wrong_account_stops_before_any_write(self):
        cli = SimulatedAwsCli(account='111122223333')
        with redirect_stdout(io.StringIO()), self.assertRaises(launch.DeploymentError):
            launch.launch(cli)
        self.assertFalse(any(c[:2] == ('cloudformation', 'deploy') for c in cli.calls))

    def test_worker_rejects_root_other_roles_and_wrong_account(self):
        environment = {'AD_EXPECTED_ACCOUNT': worker.ACCOUNT, 'AD_REGION': worker.REGION, 'CODEBUILD_BUILD_ID': 'authority-delta-deploy:build-1'}
        good = {'Account': worker.ACCOUNT, 'Arn': f'arn:aws:sts::{worker.ACCOUNT}:assumed-role/ReadinessOpsAuthorityDeltaDeployer/build-1'}
        worker.require_worker_identity(good, environment)
        for arn in (f'arn:aws:iam::{worker.ACCOUNT}:root', f'arn:aws:sts::{worker.ACCOUNT}:assumed-role/AnotherRole/build-1', 'arn:aws:sts::111122223333:assumed-role/ReadinessOpsAuthorityDeltaDeployer/build-1'):
            with self.subTest(arn=arn), self.assertRaises(ValueError):
                worker.require_worker_identity(dict(good, Arn=arn), environment)

    def test_absolute_seed_destination_outside_project_and_identical_replay(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)/'seed.json'
            command = [sys.executable, 'scripts/build_registry_seed.py', '--table-name', 'registry-table', '--output', str(output)]
            environment = dict(os.environ, PYTHONPATH=str(ROOT/'src'))
            subprocess.run(command, cwd=ROOT, env=environment, check=True, capture_output=True)
            original = output.read_bytes()
            subprocess.run(command, cwd=ROOT, env=environment, check=True, capture_output=True)
            self.assertEqual(output.read_bytes(), original)
            self.assertEqual(len(json.loads(original)), 7)

    def test_observed_state_must_match_instead_of_assuming_success(self):
        fixtures = FixtureBundle.load(ROOT/'fixtures/decision_cases.json')
        items = [t['Put']['Item'] for t in build_transaction(fixtures, 'registry-table')]
        args = dict(gateway={'status': 'READY', 'authorizerType': 'AWS_IAM', 'policyEngineConfiguration': {'mode': 'ENFORCE', 'arn': 'engine-arn'}}, engine={'status': 'ACTIVE', 'policyEngineArn': 'engine-arn'}, targets=[{'name': 'VendorPaymentTools', 'status': 'READY'}], policies=[], registry=items, ledger=[], expected_items=items)
        worker.validate_observed(**args)
        for key, value in [('ledger', [{'business_key': {'S': 'existing'}}]), ('policies', [{'policyId': 'existing'}]), ('registry', items[:-1]), ('targets', [])]:
            with self.subTest(key=key), self.assertRaises(ValueError):
                worker.validate_observed(**dict(args, **{key: value}))
        bad = copy.deepcopy(args)
        bad['gateway']['policyEngineConfiguration']['mode'] = 'LOG_ONLY'
        with self.assertRaises(ValueError):
            worker.validate_observed(**bad)


if __name__ == '__main__':
    unittest.main()
