#!/usr/bin/env python3
"""Check the actual operator artifact offline; this is never an AWS gate result."""
import argparse
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time
import zipfile

ROOT = Path(__file__).resolve().parents[1]

def check_runtime_continuity_bundle(base_bundle, update_bundle, expected_source_commit):
    """Restore the delivered bundle and exercise the offline CLI, never AWS."""
    report = {'scope': 'LOCAL_RUNTIME_CONTINUITY_DELIVERY_NO_AWS', 'result': 'FAIL',
              'aws_execution': 'NOT_RUN', 'expected_source_commit': expected_source_commit}
    try:
        with tempfile.TemporaryDirectory() as directory:
            restored = Path(directory) / 'restored'
            run(['git', 'clone', '--branch', 'main', str(Path(base_bundle).resolve()), str(restored)], ROOT)
            run(['git', 'fetch', str(Path(update_bundle).resolve()), 'main'], restored)
            run(['git', 'merge', '--ff-only', 'FETCH_HEAD'], restored)
            actual = run(['git', 'rev-parse', 'HEAD'], restored).stdout.strip()
            if actual != expected_source_commit:
                raise ValueError('Delivered source commit differs')
            if run(['git', 'status', '--porcelain'], restored).stdout.strip():
                raise ValueError('Restored delivery is dirty')
            result = run([sys.executable, '-m', 'unittest',
                          'tests.test_connected_acceptance_readiness',
                          'tests.test_runtime_continuity', '-q'], restored)
            report.update(result='PASS', delivered_source_commit=actual,
                          tests=result.stderr.strip(),
                          update_sha256=hashlib.sha256(Path(update_bundle).read_bytes()).hexdigest(),
                          limitations='Synthetic report chain; user-reported real runtime observations. Live acceptance NOT_RUN.')
    except Exception as exc:
        report['error'] = {'type': type(exc).__name__, 'message': str(exc)}
    return report

def check_assessment_recovery_bundle(base_bundle, update_bundle, expected_source_commit,
                                     *, test_python=None, authority_lifecycle=False):
    """Review the actual incremental assessment repair, without live AWS calls.

    Python/Strands tests use the supplied interpreter. Compiled Lambda imports
    use the archive's own x86 dependencies. ARM bytes are inspected but cannot
    establish an ARM runtime execution result on an x86 host.
    """
    started = time.monotonic()
    python = str(Path(test_python or sys.executable).absolute())
    report = {
        'scope': ('LOCAL_AUTHORITY_LIFECYCLE_INCREMENTAL_DELIVERY_NO_LIVE_AWS'
                  if authority_lifecycle else
                  'LOCAL_ASSESSMENT_RECOVERY_INCREMENTAL_DELIVERY_NO_LIVE_AWS'),
        'result': 'FAIL', 'observed_at': datetime.now(timezone.utc).isoformat(),
        'aws_execution': 'NOT_RUN', 'live_model_execution': 'NOT_RUN',
        'arm_runtime_execution': 'NOT_RUN', 'test_python': python, 'checks': [],
        'limitations': [
            'AWS APIs and model responses in tests are local doubles or captured outputs.',
            'Fresh x86 archive imports do not prove the AWS CodeBuild image or ARM execution.',
            'Full regressions and live connected acceptance are separate gates.',
        ],
    }

    def passed(name, **details):
        report['checks'].append(dict(name=name, status='PASS', **details))
        print('[assessment delivery] ' + name + ': PASS', flush=True)

    try:
        base_bundle, update_bundle = Path(base_bundle).resolve(), Path(update_bundle).resolve()
        report['base_bundle_sha256'] = hashlib.sha256(base_bundle.read_bytes()).hexdigest()
        report['update_bundle_sha256'] = hashlib.sha256(update_bundle.read_bytes()).hexdigest()
        intended = run(['git', 'rev-parse', expected_source_commit + '^{commit}'], ROOT).stdout.strip()
        expected_tree = run(['git', 'rev-parse', intended + '^{tree}'], ROOT).stdout.strip()
        with tempfile.TemporaryDirectory(prefix='assessment-delivery-') as temporary:
            stage = Path(temporary)
            run(['git', 'clone', '--branch', 'main', str(base_bundle), 'repo'], stage)
            repo = stage / 'repo'
            base_commit = run(['git', 'rev-parse', 'HEAD'], repo).stdout.strip()
            run(['git', 'bundle', 'verify', str(update_bundle)], repo)
            run(['git', 'fetch', str(update_bundle), 'main'], repo)
            run(['git', 'merge', '--ff-only', 'FETCH_HEAD'], repo)
            actual = run(['git', 'rev-parse', 'HEAD'], repo).stdout.strip()
            actual_tree = run(['git', 'rev-parse', 'HEAD^{tree}'], repo).stdout.strip()
            run(['git', 'diff', '--exit-code', 'HEAD', '--'], repo)
            if actual != intended or actual_tree != expected_tree:
                raise ValueError('Incremental recovery source commit or tree differs')
            report.update(delivered_source_commit=actual, delivered_tree=actual_tree)
            passed('fresh_clone_incremental_fast_forward_matches_commit_and_tree',
                   base_commit=base_commit, source_commit=actual, tree=actual_tree)

            # Do not inherit AWS credentials/profile routing or the developer's
            # PYTHONPATH. HOME is left untouched; no remote CLI is run.
            env = {key: value for key, value in os.environ.items()
                   if not key.startswith('AWS_') and key not in ('PYTHONPATH', 'PYTHONHOME')}
            env.update(PYTHONPATH=os.pathsep.join(str(repo / name) for name in ('src', 'scripts', 'tests', '.')),
                       AWS_EC2_METADATA_DISABLED='true',
                       AWS_CONFIG_FILE=str(stage / 'absent-aws-config'),
                       AWS_SHARED_CREDENTIALS_FILE=str(stage / 'absent-aws-credentials'))
            modules = [
                'test_business_assessment_repair', 'test_business_field_revision', 'test_business_citation_revision', 'test_wiring_composed_delivery',
                'test_customer_wiring_launcher', 'test_customer_wiring_operator',
                'test_cors_exposure', 'test_runtime_policy_order',
                'test_customer_connector_launcher', 'test_business_aws_contracts',
                'test_business_connection', 'test_business_delegation',
                'test_application_authority_fence', 'test_business_application_aws',
                'test_authority_revocation', 'test_invocation_gate',
                'test_ro07_acceptance',
                'test_business_interchange', 'test_integrated_acceptance_evidence', 'test_business',
                'test_business_api_audit', 'test_d4_negative_acceptance',
            ]
            tests = run([python, '-m', 'unittest', *modules, '-q'], repo, env, timeout=180)
            passed('focused_recovery_composition_launcher_and_aws_contract_regressions',
                   modules=modules, output=tests.stderr.strip(),
                   interpreter=run([python, '--version'], repo, env).stdout.strip())
            changed = run(['git', 'diff', '--name-only', base_commit, actual],
                          repo).stdout.splitlines()
            ui_changed = any(name.startswith(('workbench/',
                'services/workbench/assets/')) for name in changed)
            if (repo / 'workbench/business-flow-test.mjs').exists() and ui_changed:
                ui_env = dict(env, AD_TEST_PYTHON=python)
                run(['npm', 'ci', '--offline', '--ignore-scripts'], repo / 'workbench', ui_env, timeout=90)
                ui = run(['node', 'business-flow-test.mjs'], repo / 'workbench', ui_env, timeout=60)
                passed('real_react_dom_events_to_handler_storage_and_acceptance_gate', output=ui.stdout.strip())
                run(['npm', 'run', 'build'], repo / 'workbench', ui_env, timeout=60)
                for name in ('app.js', 'app.css', 'index.html', 'manifest.json'):
                    if (repo/'workbench/dist'/name).read_bytes() != (repo/'services/workbench/assets'/name).read_bytes():
                        raise ValueError('Compiled UI differs from delivered source: ' + name)
                passed('compiled_ui_matches_delivered_sources')
            elif (repo / 'workbench/business-flow-test.mjs').exists():
                passed('unchanged_ui_reuses_preceding_qualified_assets',
                       changed_files=len(changed),
                       basis='No workbench source or delivered workbench asset changed')
            run([python, 'scripts/launch_customer_wiring.py', '--help'], repo, env)
            blocked_env = dict(env, PATH=str(stage / 'absent-cli'))
            blocked = subprocess.run([python, 'scripts/launch_customer_wiring.py',
                                      '--connector-report', str(stage / 'unused-report.json')],
                                     cwd=repo, env=blocked_env, text=True,
                                     capture_output=True, timeout=30)
            combined = blocked.stdout + blocked.stderr
            if blocked.returncode != 1 or 'ERROR:' not in combined or 'Traceback' in combined:
                raise ValueError('Delivered wiring launcher did not stop cleanly without AWS CLI')
            passed('delivered_launcher_missing_aws_cli_stops_cleanly', exit_status=blocked.returncode)

            built = run([python, 'scripts/build_business_artifacts.py'], repo, env, timeout=180)
            artifacts = json.loads(built.stdout)
            packaged = {
                'services/business_analysis/agent.py': 'services/business_analysis/agent.py',
                'services/business/handler.py': 'services/business/handler.py',
                'authority_delta/business/service.py': 'src/authority_delta/business/service.py',
                'authority_delta/business/contracts.py': 'src/authority_delta/business/contracts.py',
                'authority_delta/business/revocation.py': 'src/authority_delta/business/revocation.py',
                'authority_delta/business/invocation.py': 'src/authority_delta/business/invocation.py',
                'authority_delta/business/customer_publisher.py': 'src/authority_delta/business/customer_publisher.py',
                'services/business/requests.schema.json': 'services/business/requests.schema.json',
                'services/business/invocation_gate.py': 'services/business/invocation_gate.py',
                'services/customer_publisher/handler.py': 'services/customer_publisher/handler.py',
                'packages/contracts/business.openapi.json': 'packages/contracts/business.openapi.json',
            }
            archive_details = {}
            for kind in ('lambda', 'runtime'):
                artifact = artifacts[kind]
                archive_path = Path(artifact['path'])
                if hashlib.sha256(archive_path.read_bytes()).hexdigest() != artifact['sha256']:
                    raise ValueError('Built artifact digest differs: ' + kind)
                with zipfile.ZipFile(archive_path) as archive:
                    if archive.testzip() is not None:
                        raise ValueError('Built artifact is corrupt: ' + kind)
                    for destination, source in packaged.items():
                        if archive.read(destination) != (repo / source).read_bytes():
                            raise ValueError('Packaged recovery source differs: ' + destination)
                    if kind == 'runtime' and archive.read('runtime.py') != (repo / 'services/business_analysis/runtime.py').read_bytes():
                        raise ValueError('Packaged ARM runtime entrypoint differs')
                    if kind == 'lambda':
                        unpacked = stage / 'lambda-extracted'
                        unpacked.mkdir()
                        archive.extractall(unpacked)
                archive_details[kind] = {key: artifact[key] for key in
                    ('sha256', 'size_bytes', 'architecture')}
            passed('actual_offline_locked_business_archives_match_repair_sources',
                   artifacts=archive_details, inspected_members=sorted(packaged))

            # Isolated Python ignores the test venv site-packages. Imported
            # pydantic/Strands/native modules must come from the extracted ZIP.
            import_archive = '''import importlib,json,sys
from pathlib import Path
root=Path(sys.argv[1]).resolve()
sys.path.insert(0,str(root))
modules=['services.business_analysis.agent','services.business.handler','authority_delta.business.service','authority_delta.business.contracts','pydantic','strands']
for name in modules:
    module=importlib.import_module(name)
    if not Path(module.__file__).resolve().is_relative_to(root):
        raise RuntimeError('Import escaped the delivered Lambda archive: '+name)
print(json.dumps({'modules':modules,'scope':'LOCAL_X86_ARCHIVE_IMPORT_ONLY'}))
'''
            imported = run([python, '-I', '-S', '-c', import_archive, str(unpacked)],
                           stage, env, timeout=60)
            passed('extracted_x86_artifact_imports_its_own_fixed_dependencies',
                   **json.loads(imported.stdout))

            cloud_zip = stage / 'codebuild-source.zip'
            run([python, '-c', 'from pathlib import Path; import sys; '
                 'from scripts.launch_deployment import source_archive; '
                 'source_archive(Path(sys.argv[1]))', str(cloud_zip)], repo, env, timeout=120)
            cloud_names = [
                'scripts/deploy_customer_wiring.py', 'scripts/deploy_business.py',
                'scripts/launch_customer_wiring.py', 'services/business_analysis/agent.py',
                'src/authority_delta/business/contracts.py', 'src/authority_delta/business/service.py',
                'src/authority_delta/business/revocation.py',
                'src/authority_delta/business/invocation.py',
                'services/business/handler.py', 'services/business/invocation_gate.py',
                'services/business/application_worker.py',
                'services/business/requests.schema.json',
                'services/workbench/assets/app.js', 'services/workbench/assets/manifest.json',
                'services/customer_publisher/handler.py',
                'scripts/check_ro07_acceptance.py',
                'buildspec.customer-wiring.yml',
                'requirements-analysis-x86_64.lock', 'requirements-analysis-aarch64.lock',
            ]
            cloud_root = stage / 'codebuild-extracted'
            cloud_root.mkdir()
            with zipfile.ZipFile(cloud_zip) as archive:
                if archive.testzip() is not None:
                    raise ValueError('CodeBuild source archive is corrupt')
                for name in cloud_names:
                    if archive.read(name) != (repo / name).read_bytes():
                        raise ValueError('CodeBuild source entrypoint differs: ' + name)
                archive.extractall(cloud_root)
            import_worker = '''import importlib,json,sys
from pathlib import Path
root=Path(sys.argv[1]).resolve()
sys.path[:0]=[str(root/'src'),str(root/'scripts'),str(root)]
names=['deploy_customer_wiring','deploy_business','services.business_analysis.agent']
for name in names:
    module=importlib.import_module(name)
    if not Path(module.__file__).resolve().is_relative_to(root):
        raise RuntimeError('Import escaped the delivered CodeBuild source: '+name)
print(json.dumps({'modules':names,'scope':'SUPPLIED_TEST_INTERPRETER_NO_LIVE_AWS'}))
'''
            imported = run([python, '-I', '-c', import_worker, str(cloud_root)],
                           stage, env, timeout=60)
            passed('actual_codebuild_source_entries_and_worker_imports_match',
                   source_zip_sha256=hashlib.sha256(cloud_zip.read_bytes()).hexdigest(),
                   inspected_members=cloud_names, imports=json.loads(imported.stdout))
            report['result'] = 'PASS'
    except Exception as exc:
        report['error'] = {'type': type(exc).__name__, 'message': str(exc)[:7000]}
    report['elapsed_seconds'] = round(time.monotonic() - started, 3)
    return report

def check_budget_bundle(base_bundle, update_bundle, patterns=('test_customer_budget_profile.py', 'test_customer*launcher.py')):
    """Exercise the actual incremental CloudShell delivery, with offline AWS doubles."""
    with tempfile.TemporaryDirectory(prefix='budget-delivery-') as temporary:
        stage = Path(temporary)
        run(['git', 'clone', '--branch', 'main', str(base_bundle), 'repo'], stage)
        repo = stage / 'repo'
        run(['git', 'fetch', str(update_bundle), 'main'], repo)
        run(['git', 'merge', '--ff-only', 'FETCH_HEAD'], repo)
        intended = run(['git', 'rev-parse', 'HEAD'], ROOT).stdout.strip()
        if run(['git', 'rev-parse', 'HEAD'], repo).stdout.strip() != intended:
            raise ValueError('Incremental source commit mismatch')
        env = dict(os.environ, PYTHONPATH=str(repo / 'src'))
        for pattern in patterns:
            result = run([sys.executable, '-m', 'unittest', 'discover', '-s', 'tests', '-p', pattern, '-q'], repo, env, timeout=120)
            print(result.stderr.strip(), flush=True)
        run([sys.executable, 'scripts/launch_customer_connector.py', '--help'], repo, env)
        # Actual delivered entrypoint: missing CLI must stop cleanly, never deploy.
        blocked_env = dict(env, PATH=str(stage / 'absent-cli'))
        result = subprocess.run([sys.executable, 'scripts/prepare_customer_budget.py'],
            cwd=repo, env=blocked_env, text=True, capture_output=True)
        if result.returncode != 1 or 'STOP:' not in result.stderr or 'Traceback' in result.stderr:
            raise ValueError('Delivered entrypoint did not fail closed without AWS CLI')
        run([sys.executable, '-c', 'from pathlib import Path; from scripts.launch_deployment import source_archive; source_archive(Path("source.zip"))'], repo, env)
        with zipfile.ZipFile(repo / 'source.zip') as archive:
            for name in ('scripts/prepare_customer_budget.py', 'scripts/launch_customer_foundation.py', 'scripts/launch_customer_connector.py'):
                if archive.read(name) != (repo / name).read_bytes():
                    raise ValueError('Worker source mismatch: ' + name)
        print('BUDGET_INCREMENTAL_DELIVERY_PASS; AWS_NOT_RUN; source=' + intended)

def run(command, cwd, env=None, timeout=60):
    result = subprocess.run(command, cwd=cwd, env=env, text=True, capture_output=True, timeout=timeout)
    if result.returncode:
        raise RuntimeError(f'Command failed ({result.returncode}): {command[0:3]}\n{result.stderr[-5000:]}\n{result.stdout[-1500:]}')
    return result

def load(path):
    spec = importlib.util.spec_from_file_location('delivered_authority_delta_repair', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

def check(repair_path, base_path, expected_source_commit):
    started = time.monotonic()
    report = {'scope': 'LOCAL_OPERATOR_DELIVERY_REVIEW_NO_LIVE_AWS', 'result': 'FAIL',
        'observed_at': datetime.now(timezone.utc).isoformat(), 'aws_execution': 'NOT_RUN',
        'repair_sha256': hashlib.sha256(repair_path.read_bytes()).hexdigest(),
        'base_zip_sha256': hashlib.sha256(base_path.read_bytes()).hexdigest(), 'checks': []}
    def passed(name, **details):
        report['checks'].append(dict(name=name, status='PASS', **details))
        print(f'[local delivery] {name}: PASS', flush=True)
    try:
        with tempfile.TemporaryDirectory(prefix='ad-delivery-review-') as temporary:
            stage = Path(temporary); restored = stage / 'restored'; restored.mkdir()
            commit = load(repair_path).prepare_source(base_path, restored)
            report['delivered_source_commit'] = commit
            intended = run(['git', 'rev-parse', expected_source_commit], ROOT).stdout.strip()
            if commit != intended:
                raise ValueError('Delivery does not contain the intended source commit')
            expected = run(['git', 'ls-tree', '-r', '--name-only', commit], ROOT).stdout.splitlines()
            for name in expected:
                blob = subprocess.check_output(['git', 'show', f'{commit}:{name}'], cwd=ROOT)
                if not (restored / name).is_file() or (restored / name).read_bytes() != blob:
                    raise ValueError(f'Delivered source mismatch: {name}')
            passed('restored_delivery_matches_its_committed_source', tracked_files=len(expected))
            # Only the isolated child's test PATH changes; real HOME and credentials are untouched.
            cli_bin = stage / 'bin'; cli_bin.mkdir()
            fake_cli = cli_bin / 'aws'
            fake_cli.write_text(f'#!{sys.executable}\n' + (ROOT / 'tests/support/verification_cli_double.py').read_text())
            fake_cli.chmod(0o700)
            scenarios = [('PASS', 0), ('BLOCKED', 2), ('FAIL', 1), ('FINAL_MISSING', 1), ('WRONG_ACCOUNT', 1), ('ACTIVE_BUILD', 1)]
            for scenario, expected_exit in scenarios:
                scenario_dir = stage / scenario; scenario_dir.mkdir()
                operator_home = scenario_dir / 'operator'; operator_home.mkdir()
                shutil.copy2(base_path, operator_home / base_path.name)
                # Path.home is substituted solely to keep the test out of the real user's home.
                harness = 'import runpy,sys,tempfile; from pathlib import Path; from unittest.mock import patch; tempfile.tempdir=sys.argv[3];\nwith patch.object(Path,"home",return_value=Path(sys.argv[2])): runpy.run_path(sys.argv[1],run_name="__main__")'
                env = {'PATH': str(cli_bin) + os.pathsep + os.defpath, 'LANG': 'C.UTF-8',
                    'AD_TEST_SCENARIO': scenario, 'AD_TEST_STATE': str(scenario_dir), 'AWS_EC2_METADATA_DISABLED': 'true'}
                execution = subprocess.run([sys.executable, '-c', harness, str(repair_path), str(operator_home), str(scenario_dir)], cwd=operator_home, env=env, text=True, capture_output=True, timeout=60)
                if execution.returncode != expected_exit:
                    raise ValueError(f'{scenario}: exit {execution.returncode}, expected {expected_exit}\n{execution.stderr[-2500:]}\n{execution.stdout[-2500:]}')
                call_file = scenario_dir / 'calls.jsonl'
                calls = [json.loads(line) for line in call_file.read_text().splitlines()] if call_file.exists() else []
                if ['sts', 'get-caller-identity'] not in calls or 'Traceback (most recent call last)' in execution.stderr:
                    raise ValueError(f'{scenario}: workflow did not reach the intended check')
                starts = calls.count(['codebuild', 'start-build'])
                if starts != (0 if scenario in ('WRONG_ACCOUNT', 'ACTIVE_BUILD') else 1):
                    raise ValueError(f'{scenario}: unexpected start-build count {starts}')
                if ['sts', 'assume-role'] in calls or ['cloudformation', 'deploy'] in calls:
                    raise ValueError('Repair attempted root AssumeRole or baseline redeployment')
                if scenario in ('PASS', 'BLOCKED', 'FAIL'):
                    results = list(scenario_dir.glob('authority-delta-v3-*/evidence/aws/*/verification-result.json'))
                    if len(results) != 1 or json.loads(results[0].read_text())['result'] != scenario:
                        raise ValueError(f'{scenario}: result not recovered at operator endpoint')
                if scenario == 'FINAL_MISSING' and 'AUTHORITY_DELTA_PARTIAL_GATEWAY_EVIDENCE' not in execution.stdout:
                    raise ValueError('Gateway checkpoint was not recovered')
                marker = {'WRONG_ACCOUNT': 'Wrong AWS account.', 'ACTIVE_BUILD': 'already running', 'BLOCKED': 'BLOCKED:', 'FAIL': 'Verification is incomplete'}
                if scenario in marker and marker[scenario] not in execution.stdout:
                    raise ValueError(f'{scenario}: expected diagnostic was not recovered')
                passed('operator_process_' + scenario.lower(), exit_status=execution.returncode, build_starts=starts,
                    boundary='Real Python/launcher/AwsCli/archive processes; AWS CLI responses are a local double')
            # Reproduce the source subset uploaded to CodeBuild, not the developer checkout.
            bundle = stage / 'codebuild-source.zip'
            env = dict(os.environ, PYTHONPATH=str(restored / 'src'))
            run([sys.executable, '-c', 'from pathlib import Path; from scripts.launch_deployment import source_archive; source_archive(Path(__import__("sys").argv[1]))', str(bundle)], restored, env)
            cloud_source = stage / 'cloud-source'; cloud_source.mkdir()
            with zipfile.ZipFile(bundle) as archive:
                archive.extractall(cloud_source)
            fresh = stage / 'worker-env'
            run([sys.executable, '-m', 'venv', str(fresh)], cloud_source)
            python = fresh / 'bin/python'
            run([str(python), '-m', 'pip', 'install', '--no-index', '--find-links', 'vendor/wheels', '--require-hashes', '-r', 'requirements-deploy.lock'], cloud_source)
            cloud_env = {'PATH': os.defpath, 'LANG': 'C.UTF-8', 'PYTHONPATH': str(cloud_source / 'src'), 'AWS_EC2_METADATA_DISABLED': 'true'}
            run([str(python), '-c', 'from scripts import verify_aws; from authority_delta.registry import FixtureBundle; from pathlib import Path; assert len(FixtureBundle.load(Path("fixtures/decision_cases.json")).all_cases)==7'], cloud_source, cloud_env)
            passed('codebuild_source_imports_with_fresh_offline_locked_dependencies', python_version=run([str(python), '--version'], cloud_source).stdout.strip(), scope='Fresh venv and actual source subset; not an AWS CodeBuild image')
            tests = run([sys.executable, '-m', 'unittest', 'discover', '-s', 'tests', '-q'], restored, env)
            passed('restored_source_regressions_and_worker_persistence', output=tests.stderr.strip(), evidence='Real SDK Stubber shapes, observed Gateway failure envelope, datetime encoding, checkpoint/final save and readback; no live requests')
            report['result'] = 'PASS'
    except Exception as exc:
        report['error'] = {'type': type(exc).__name__, 'message': str(exc)[:7000]}
    report['elapsed_seconds'] = round(time.monotonic() - started, 3)
    return report

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repair', type=Path)
    parser.add_argument('--base-zip', type=Path)
    parser.add_argument('--assessment-recovery', action='store_true',
                        help='Check an incremental assessment recovery Git bundle')
    parser.add_argument('--authority-lifecycle', action='store_true',
                        help='Check the coordinated RO-07 authority-lifecycle Git bundle')
    parser.add_argument('--base-bundle', type=Path)
    parser.add_argument('--update-bundle', type=Path)
    parser.add_argument('--test-python', type=Path,
                        help='Python with fixed test dependencies; defaults to this interpreter')
    parser.add_argument('--report', type=Path, required=True)
    parser.add_argument('--expected-source-commit', required=True)
    args = parser.parse_args()
    if args.assessment_recovery or args.authority_lifecycle:
        if args.assessment_recovery and args.authority_lifecycle:
            parser.error('Select only one incremental delivery mode')
        if not args.base_bundle or not args.update_bundle or args.repair or args.base_zip:
            parser.error('Incremental delivery requires --base-bundle and --update-bundle; omit --repair and --base-zip')
        report = check_assessment_recovery_bundle(args.base_bundle, args.update_bundle,
            args.expected_source_commit, test_python=args.test_python,
            authority_lifecycle=args.authority_lifecycle)
    else:
        if not args.repair or not args.base_zip or args.base_bundle or args.update_bundle or args.test_python:
            parser.error('Legacy review requires --repair and --base-zip; bundle arguments require an incremental delivery mode')
        report = check(args.repair.resolve(), args.base_zip.resolve(), args.expected_source_commit)
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n')
    print(json.dumps({'result': report['result'], 'scope': report['scope'], 'error': report.get('error')}), flush=True)
    return 0 if report['result'] == 'PASS' else 1

if __name__ == '__main__':
    raise SystemExit(main())
