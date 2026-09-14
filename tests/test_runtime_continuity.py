"""Captured runtime observations plus synthetic report-chain CLI regression."""
import copy
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from scripts import check_connected_acceptance_readiness as checker
from tests.test_connected_acceptance_readiness import chain, raw

ROOT = Path(__file__).resolve().parents[1]
PROOF = ROOT / 'evidence/aws/20260912-customer-runtime-versions-user-reported.json'

def captured():
    return json.loads(PROOF.read_text())

def example():
    docs, _ = chain()
    proof = captured()
    f = docs['foundation_report']
    c = docs['connector_report']
    runtime = c['observed_binding']['runtime']
    f['observed']['runtimes']['V2RuntimeVersion'] = '1'
    # Synthetic chain retains its own identity; captured content tested separately.
    for label, version in [('foundation_runtime', '1'), ('connector_runtime', runtime['runtime_version'])]:
        p = proof[label]
        p.update(agentRuntimeId=runtime['runtime_id'], agentRuntimeArn=runtime['runtime_arn'],
                 roleArn=runtime['execution_role_arn'], agentRuntimeVersion=version)
    s3 = proof['foundation_runtime']['agentRuntimeArtifact']['codeConfiguration']['code']['s3']
    f['runtime_artifacts']['V2'].update(bucket=s3['bucket'], key=s3['prefix'], version_id=s3['versionId'])
    docs['runtime_transition'] = proof
    return docs

class RuntimeContinuityTests(unittest.TestCase):
    def test_captured_observations_bind_original_artifact(self):
        p = captured()
        old, new = p['foundation_runtime'], p['connector_runtime']
        s3 = old['agentRuntimeArtifact']['codeConfiguration']['code']['s3']
        f = {'observed': {'runtimes': {'V2RuntimeVersion': '1'}},
             'runtime_artifacts': {'V2': {'bucket': s3['bucket'], 'key': s3['prefix'], 'version_id': s3['versionId']}}}
        c = {'observed_binding': {'runtime': {'runtime_id': new['agentRuntimeId'], 'runtime_arn': new['agentRuntimeArn'],
            'runtime_version': '2', 'execution_role_arn': new['roleArn']}}}
        checker._validate_runtime_transition(f, c, p)
        for field in ('agentRuntimeArn', 'roleArn', 'status', 'environmentVariables',
                      'networkConfiguration', 'protocolConfiguration', 'metadataConfiguration',
                      'agentRuntimeArtifact', 'unknownNewConfiguration'):
            with self.subTest(field=field):
                bad = copy.deepcopy(p)
                bad['connector_runtime'][field] = {'changed': True}
                with self.assertRaises(ValueError):
                    checker._validate_runtime_transition(f, c, bad)
        f['runtime_artifacts']['V2']['version_id'] = 'different-object-version'
        with self.assertRaises(ValueError):
            checker._validate_runtime_transition(f, c, p)

    def test_proof_hash_and_no_authority(self):
        docs = example()
        result = checker.check_chain(docs, {k: raw(v) for k, v in docs.items()})
        self.assertEqual(result['bindings']['runtime_transition_sha256'], checker.digest(raw(docs['runtime_transition'])))
        self.assertEqual(result['live_acceptance'], 'NOT_RUN')
        for k in ('foundation_launch', 'foundation_report'):
            docs.pop(k)
        with self.assertRaises(ValueError):
            checker.check_chain(docs, {k: raw(v) for k, v in docs.items()})

    def test_real_cli_save_and_exit_without_aws(self):
        for scenario in ('pass', 'changed', 'missing'):
            with self.subTest(scenario=scenario), tempfile.TemporaryDirectory() as directory:
                docs = example()
                if scenario == 'changed':
                    docs['runtime_transition']['connector_runtime']['environmentVariables']['AD_REGION'] = 'wrong'
                elif scenario == 'missing':
                    docs.pop('runtime_transition')
                    docs['foundation_report']['observed']['runtimes']['V2RuntimeVersion'] = '999'
                root = Path(directory)
                args = [sys.executable, str(ROOT / 'scripts/check_connected_acceptance_readiness.py')]
                for name, value in docs.items():
                    path = root / (name + '.json')
                    path.write_bytes(raw(value))
                    args.extend(['--' + name.replace('_', '-'), str(path)])
                output = root / 'output.json'
                run = subprocess.run(args + ['--output', str(output)], capture_output=True, text=True)
                self.assertEqual(run.returncode, 0 if scenario == 'pass' else 1, run.stderr + run.stdout)
                result = json.loads(output.read_text())
                self.assertEqual(result['result'], 'PASS' if scenario == 'pass' else 'BLOCKED')
                self.assertEqual(result['aws_execution'], 'NOT_RUN_BY_THIS_CHECKER')
                if scenario != 'pass':
                    self.assertIn('error', json.loads(run.stdout))

if __name__ == '__main__':
    unittest.main()
