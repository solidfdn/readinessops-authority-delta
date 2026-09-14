"""Local contracts for the account-B clean foundation worker."""
import copy
import hashlib
import tempfile
from pathlib import Path
import unittest
from unittest.mock import patch

from authority_delta.registry import FixtureBundle
from scripts import deploy_customer_foundation as worker


ACCOUNT_B = '111122223333'


class RegistryClient:
    def __init__(self, items=None):
        self.items = copy.deepcopy(items or [])
        self.writes = 0

    def scan(self, **values):
        return {'Items': copy.deepcopy(self.items)}

    def transact_write_items(self, TransactItems):
        self.writes += 1
        self.items = [copy.deepcopy(value['Put']['Item']) for value in TransactItems]


class RegistrySession:
    def __init__(self, client):
        self.value = client

    def client(self, name):
        self.assert_name = name
        return self.value


class CustomerFoundationOperatorTests(unittest.TestCase):
    def environment(self):
        return {'AD_EXPECTED_ACCOUNT': ACCOUNT_B, 'AD_REGION': worker.REGION,
            'CODEBUILD_BUILD_ID': 'authority-delta-deploy:foundation-test',
            'AD_SOURCE_SHA256': 'a' * 64,
            'AD_ARTIFACT_BUCKET': 'customer-artifacts'}

    def identity(self):
        return {'Account': ACCOUNT_B, 'Arn':
            f'arn:aws:sts::{ACCOUNT_B}:assumed-role/{worker.ROLE}/build'}

    def test_worker_rejects_account_a_root_foreign_role_and_wrong_source(self):
        self.assertEqual(worker.require_identity(self.identity(), self.environment()),
                         ACCOUNT_B)
        mutations = [
            ({'Account': worker.ACCOUNT_A, 'Arn':
              f'arn:aws:sts::{worker.ACCOUNT_A}:assumed-role/{worker.ROLE}/build'}, {}),
            ({'Account': ACCOUNT_B, 'Arn': f'arn:aws:iam::{ACCOUNT_B}:root'}, {}),
            ({'Account': ACCOUNT_B, 'Arn':
              f'arn:aws:sts::{ACCOUNT_B}:assumed-role/Foreign/build'}, {}),
            (self.identity(), {'AD_SOURCE_SHA256': 'not-a-digest'})]
        for identity, changes in mutations:
            with self.subTest(identity=identity, changes=changes), self.assertRaises(ValueError):
                worker.require_identity(identity, dict(self.environment(), **changes))

    def test_registry_is_seeded_once_and_changed_data_is_preserved(self):
        fixtures = FixtureBundle.load(worker.ROOT / 'fixtures/decision_cases.json')
        client = RegistryClient()
        session = RegistrySession(client)
        first = worker.ensure_registry(session, 'registry', fixtures)
        second = worker.ensure_registry(session, 'registry', fixtures)
        self.assertTrue(first['seeded'])
        self.assertFalse(second['seeded'])
        self.assertEqual(first['count'], 7)
        self.assertEqual(client.writes, 1)
        client.items[0]['payload']['S'] = '{}'
        with self.assertRaises(ValueError):
            worker.ensure_registry(session, 'registry', fixtures)
        self.assertEqual(client.writes, 1)

    def test_execute_deploys_only_foundation_then_requires_full_readback(self):
        class Sts:
            def get_caller_identity(_self):
                return self.identity()
        class Control:
            def list_policies(_self, **values):
                return {'policies': []}
        class Ddb:
            def scan(_self, **values):
                return {'Items': []}
        class Session:
            def client(_self, name):
                return {'sts': Sts(), 'bedrock-agentcore-control': Control(),
                        'dynamodb': Ddb()}[name]
        bootstrap = {'StackId': 'bootstrap', 'StackStatus': 'CREATE_COMPLETE',
            'Outputs': [{'OutputKey': 'ArtifactBucketName',
                         'OutputValue': 'customer-artifacts'}]}
        baseline_values = {'GatewayArn': 'gateway-arn', 'GatewayIdentifier': 'gateway',
            'GatewayUrl': 'https://gateway.example/mcp', 'PolicyEngineId': 'engine',
            'RequestRegistryTableName': 'registry', 'SandboxLedgerTableName': 'ledger'}
        baseline = {'StackId': 'baseline', 'StackStatus': 'CREATE_COMPLETE',
            'Outputs': [{'OutputKey': key, 'OutputValue': value}
                        for key, value in baseline_values.items()]}
        runtimes = {'StackId': 'runtimes', 'StackStatus': 'CREATE_COMPLETE',
            'Outputs': [
                {'OutputKey': 'V1RuntimeArn', 'OutputValue': 'runtime-v1'},
                {'OutputKey': 'V2RuntimeArn', 'OutputValue': 'runtime-v2'},
                {'OutputKey': 'V1ExecutionRoleArn', 'OutputValue': 'role-v1'},
                {'OutputKey': 'V2ExecutionRoleArn', 'OutputValue': 'role-v2'}]}
        observed = {'baseline_stack': baseline, 'runtime_stack': runtimes,
            'connection_id': 'conn-demo', 'target_id': 'target',
            'target_name': 'VendorPaymentTools', 'registry_hash': 'r' * 64,
            'ledger_hash': 'l' * 64, 'runtimes': {'V2RuntimeArn': 'runtime-v2'}}
        artifact_count = 0
        def build_artifact(fixtures, release, path):
            nonlocal artifact_count
            artifact_count += 1
            Path(path).parent.mkdir(parents=True, exist_ok=True)
            Path(path).write_bytes(release.encode())
            return {'path': str(path), 'sha256': hashlib.sha256(release.encode()).hexdigest(),
                'release_definition_hash': release.lower(),
                'request_registry_snapshot_hash': 'snapshot'}
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'fixtures').mkdir()
            # Loading is replaced; the sandbox entrypoint only needs to create its output.
            fixture = FixtureBundle.load(worker.ROOT / 'fixtures/decision_cases.json')
            calls = []
            def run(args, **values):
                calls.append(args)
                if args[1:] == ['scripts/build_sandbox_artifact.py']:
                    (root / 'dist').mkdir(exist_ok=True)
                    (root / 'dist/authority-delta-sandbox.zip').write_bytes(b'sandbox')
            upload_count = 0
            def upload(session, bucket, path, prefix):
                nonlocal upload_count
                upload_count += 1
                return {'bucket': bucket, 'key': f'{prefix}/{upload_count}.zip',
                    'version_id': f'v{upload_count}', 'sha256': 'a' * 64,
                    'size_bytes': 1}
            with (patch.object(worker, 'ROOT', root),
                  patch.object(worker.FixtureBundle, 'load', return_value=fixture),
                  patch.object(worker, 'stable_stack', side_effect=[bootstrap, baseline,
                      runtimes, bootstrap]),
                  patch.object(worker, 'ensure_registry', return_value={
                      'count': 7, 'hash': 'h' * 64, 'seeded': True}),
                  patch.object(worker, 'build_runtime_artifact', side_effect=build_artifact),
                  patch.object(worker, 'upload_versioned', side_effect=upload),
                  patch.object(worker, 'observe_customer', return_value=observed),
                  patch.object(worker, 'deploy_stack') as deploy):
                report = worker.execute(Session(), self.environment(), {}, run=run)
        self.assertEqual(report['result'], 'PASS')
        self.assertEqual(report['connector'], 'NOT_RUN')
        self.assertEqual(report['policy_write'], 'NOT_RUN')
        self.assertEqual(deploy.call_count, 2)
        self.assertEqual(artifact_count, 2)
        self.assertFalse(any('create-policy' in ' '.join(call) for call in calls))


if __name__ == '__main__':
    unittest.main()
