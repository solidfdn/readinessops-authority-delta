#!/usr/bin/env python3
"""Deploy fixed Runtime identities and prove scoped Gateway enforcement in account A."""
from __future__ import annotations
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))
sys.path.insert(0, str(ROOT / 'scripts'))
from authority_delta.canonical import sha256_json
from authority_delta.cedar import compile_permit, assert_observed_role_matches
from authority_delta.domain import Decision
from authority_delta.evidence_json import encode_evidence, recover_serializable_report
from authority_delta.execution_evidence import validate_execution_evidence
from authority_delta.gateway_probe import policy_denial
from authority_delta.policy_plan import build_policy_plan
from authority_delta.registry import FixtureBundle
from build_runtime_artifact import build as build_runtime_artifact
from deploy_baseline import ACCOUNT, REGION, all_records, require_worker_identity
from gate_a_state import Journal, missing, observe_baseline, policies, read_json, stable_ledger
from verify_aws import safe_error, sdk_evidence, save_evidence, observed_at

STACK = 'authority-delta-vendor-runtimes'
G0_KEY = 'evidence/de0a1e76ec674c1ab2a08c7e95c53399/verification-result.json'
G0_VERSION = '5q5glB17Y3RVSbVV67jN7N5OmoPCM4ll'
DEFINITION_SCOPE = 'GATE_A_SYNTHETIC_AUTHORIZATION_PROOF_NOT_HUMAN_PUBLICATION'

class GateA:
    def __init__(self, session, environment, report, root=ROOT, run=subprocess.run, sleep=time.sleep):
        self.session, self.env, self.report, self.root = session, environment, report, root
        self.run, self.sleep = run, sleep
        self.binding = json.loads((root / 'infra/environments/development.json').read_text())
        self.fixtures = FixtureBundle.load(root / 'fixtures/decision_cases.json')
        self.s3 = session.client('s3'); self.control = session.client('bedrock-agentcore-control')
        self.data = session.client('bedrock-agentcore'); self.ddb = session.client('dynamodb')
        self.bucket = environment['AD_ARTIFACT_BUCKET']
        self.engine = self.binding['resources']['PolicyEngineId']
        self.journal = None; self.owned = None; self.sessions = {}; self.session_bindings = {}; self.runtimes = {}

    def checkpoint(self, phase):
        partial = dict(self.report, result='IN_PROGRESS', checkpoint_phase=phase, checkpoint_at=observed_at())
        encoded = encode_evidence(partial)
        # Each stage is independent and versioned; latest is only a recovery pointer.
        key = self.env['AD_REPORT_KEY'].removesuffix('.json') + '-' + phase + '.json'
        saved = save_evidence(self.session, self.env, encoded, self.root / f'evidence/aws/gate-a-{phase}.json', key)
        pointer_key = self.env['AD_REPORT_KEY'].removesuffix('.json') + '-latest.json'
        save_evidence(self.session, self.env, encoded, self.root / 'evidence/aws/gate-a-latest.json', pointer_key)
        self.report.setdefault('checkpoints', {})[phase] = saved
        print('[Gate A] ' + phase + ' saved', flush=True)

    def ledger(self):
        return all_records(self.ddb, self.binding['resources']['SandboxLedgerTableName'])

    def establish_prior_evidence(self):
        identity = self.session.client('sts').get_caller_identity()
        require_worker_identity(identity, self.env)
        if self.bucket != self.binding['artifact_bucket']:
            raise ValueError('Wrong artifact bucket')
        prior, metadata = read_json(self.s3, self.bucket, G0_KEY, G0_VERSION)
        if prior.get('gate_0') != 'PASS' or prior.get('result') != 'PASS' or prior.get('account') != ACCOUNT or prior.get('region') != REGION:
            raise ValueError('Pinned Gate 0 evidence is not a successful run in the bound environment')
        if prior.get('gateway_default_deny', {}).get('observed_calls') != 7 or not prior['gateway_default_deny'].get('state_unchanged'):
            raise ValueError('Pinned Gate 0 evidence is incomplete')
        stable = prior.get('after', {}).get('stable', {})
        if stable.get('gateway_arn') != self.binding['resources']['GatewayArn'] or stable.get('sandbox_code_sha256') != self.binding['sandbox_code_sha256']:
            raise ValueError('Pinned Gate 0 evidence belongs to different resources')
        self.report.update(account=ACCOUNT, region=REGION, caller_arn=identity['Arn'], gate_0='PASS',
            previous_gate_0={'key':G0_KEY, 'version_id':metadata['VersionId'], 'build_id':prior.get('build_id'),
                'source_sha256':prior.get('source_sha256'), 'model_invocation':prior.get('model_invocation'), 'new_model_invocation':'NOT_RUN'})
        self.checkpoint('prior-evidence')

    def artifact(self, release):
        local = build_runtime_artifact(self.fixtures, release, self.root / f'dist/runtime-{release.lower()}.zip')
        key = f"runtime/{local['sha256']}/{release.lower()}.zip"
        try:
            existing = self.s3.head_object(Bucket=self.bucket, Key=key)
            if existing.get('Metadata', {}).get('sha256') != local['sha256']:
                raise ValueError('Runtime content-addressed object metadata mismatch')
            version = existing.get('VersionId')
        except Exception as exc:
            if not missing(exc):
                raise
            stored = self.s3.put_object(Bucket=self.bucket, Key=key, Body=Path(local['path']).read_bytes(), Metadata={'sha256':local['sha256']})
            version = stored.get('VersionId')
        if not version or version == 'null':
            raise ValueError('Runtime artifact lacks immutable S3 version')
        return dict(local, bucket=self.bucket, key=key, version_id=version)

    def deploy_runtimes(self):
        artifacts = {release:self.artifact(release) for release in ('V1','V2')}
        self.report['runtime_artifacts'] = artifacts
        template = self.root / 'infra/vendor-runtimes/template.json'
        self.session.client('cloudformation').validate_template(TemplateBody=template.read_text())
        parameters = {'ArtifactBucket': self.bucket, 'DeployerRoleArn':f'arn:aws:iam::{ACCOUNT}:role/ReadinessOpsAuthorityDeltaDeployer'}
        parameters['ApplicationCanaryRoleArn'] = parameters['DeployerRoleArn']
        for release, artifact in artifacts.items():
            parameters.update({release+'ArtifactKey':artifact['key'], release+'ArtifactVersionId':artifact['version_id']})
        parameters.update({name:self.binding['resources'][name] for name in ('GatewayArn','GatewayIdentifier','GatewayUrl','RequestRegistryTableName')})
        print('[Gate A] Deploy fixed V1/V2 Runtime stack', flush=True)
        self.run(['aws','cloudformation','deploy','--region',REGION,'--no-cli-pager','--template-file',str(template),
            '--stack-name',STACK,'--capabilities','CAPABILITY_NAMED_IAM','--no-fail-on-empty-changeset',
            '--parameter-overrides',*[k+'='+v for k,v in parameters.items()], '--tags','Project=ReadinessOpsAuthorityDelta','Baseline=AD-BASELINE-1.0'],cwd=self.root,check=True)
        stack = self.session.client('cloudformation').describe_stacks(StackName=STACK)['Stacks'][0]
        if stack['StackStatus'] not in ('CREATE_COMPLETE','UPDATE_COMPLETE'):
            raise ValueError('Runtime stack did not complete')
        output = {v['OutputKey']:v['OutputValue'] for v in stack['Outputs']}
        self.runtimes = {release:{name:output[release+name] for name in ('RuntimeArn','RuntimeId','RuntimeVersion','EndpointArn','EndpointName','ExecutionRoleArn')} for release in ('V1','V2')}
        if self.runtimes['V1']['RuntimeArn'] == self.runtimes['V2']['RuntimeArn'] or self.runtimes['V1']['ExecutionRoleArn'] == self.runtimes['V2']['ExecutionRoleArn']:
            raise ValueError('V1/V2 must have distinct runtimes and execution roles')
        self.report['runtime_bindings'] = copy.deepcopy(self.runtimes)
        for release in self.runtimes:
            self.validate_runtime(release, artifacts[release])
        self.checkpoint('runtimes')

    def endpoint(self, binding):
        expected = {'status':'READY', 'liveVersion':binding['RuntimeVersion'],
            'agentRuntimeArn':binding['RuntimeArn'],
            'agentRuntimeEndpointArn':binding['EndpointArn'], 'name':binding['EndpointName']}
        record = {'expected':expected, 'status':'FAIL'}
        self.report.setdefault('endpoint_control_evidence',{})[binding['EndpointArn']] = record
        try:
            response = self.control.get_agent_runtime_endpoint(agentRuntimeId=binding['RuntimeId'], endpointName=binding['EndpointName'])
        except Exception as exc:
            record['error'] = safe_error(exc)
            raise
        record['response'] = response
        mismatches = {key:{'expected':value,'observed':response.get(key)}
            for key,value in expected.items() if response.get(key)!=value}
        # The observed READY response omits targetVersion. liveVersion is the
        # deployed version; an explicitly reported different target still fails.
        if 'targetVersion' in response and response['targetVersion']!=binding['RuntimeVersion']:
            mismatches['targetVersion']={'expected':binding['RuntimeVersion'],'observed':response['targetVersion']}
        record['mismatches'] = mismatches
        if mismatches:
            raise ValueError('Runtime endpoint binding mismatch: '+json.dumps(mismatches,sort_keys=True))
        record['status'] = 'PASS'
        return response

    def validate_runtime(self, release, artifact):
        binding = self.runtimes[release]
        current = self.control.get_agent_runtime(agentRuntimeId=binding['RuntimeId'], agentRuntimeVersion=binding['RuntimeVersion'])
        self.report.setdefault('runtime_control_evidence', {})[release] = {'runtime':current}
        expected_code = {'codeConfiguration':{'code':{'s3':{'bucket':self.bucket,'prefix':artifact['key'],'versionId':artifact['version_id']}},'runtime':'PYTHON_3_12','entryPoint':['runtime.py']}}
        if current.get('status') != 'READY' or current.get('agentRuntimeArn') != binding['RuntimeArn'] or current.get('agentRuntimeVersion') != binding['RuntimeVersion'] or current.get('roleArn') != binding['ExecutionRoleArn'] or current.get('agentRuntimeArtifact') != expected_code:
            raise ValueError('Runtime version, role or immutable code artifact mismatch')
        if current.get('authorizerConfiguration') or current.get('protocolConfiguration') != {'serverProtocol':'HTTP'}:
            raise ValueError('Expected HTTP Runtime with IAM authorization')
        expected_environment = {'AD_ACCOUNT_ID':ACCOUNT,'AD_REGION':REGION,'AD_GATEWAY_URL':self.binding['resources']['GatewayUrl'],
            'AD_GATEWAY_ID':self.binding['resources']['GatewayIdentifier'],'AD_REGISTRY_TABLE':self.binding['resources']['RequestRegistryTableName'],
            'AD_EXPECTED_ROLE_NAME':binding['ExecutionRoleArn'].split('/')[-1]}
        if current.get('environmentVariables') != expected_environment:
            raise ValueError('Runtime environment differs from the fixed bindings')
        self.report['runtime_control_evidence'][release]['endpoint'] = self.endpoint(binding)

    def invoke(self, release, payload, label):
        binding = self.runtimes[release]
        self.endpoint(binding)
        session_id = self.sessions.setdefault(binding['RuntimeArn'], str(uuid.uuid4()))
        self.session_bindings[binding['RuntimeArn']] = copy.deepcopy(binding)
        record = {'label':label,'release_id':release,'runtime':copy.deepcopy(binding),'runtime_session_id':session_id,'payload':payload,'observed_at':observed_at(),'status':'FAIL'}
        self.report.setdefault('runtime_calls', []).append(record)
        # The documented session provisioning conflict is retryable before the
        # application executes. Never replay a timeout or an arbitrary 409.
        for attempt in range(4):
            try:
                result = self.data.invoke_agent_runtime(agentRuntimeArn=binding['RuntimeArn'],qualifier=binding['EndpointName'],
                    runtimeSessionId=session_id,contentType='application/json',accept='application/json',payload=encode_evidence(payload))
                break
            except Exception as exc:
                record.setdefault('invocation_attempt_errors',[]).append(safe_error(exc))
                code=getattr(exc,'response',{}).get('Error',{}).get('Code')
                if code!='RetryableConflictException' or attempt==3: raise
                self.sleep(2**attempt)
        record['api_evidence'] = sdk_evidence(result)
        stream = result['response']
        try: raw = stream.read(262145)
        finally: stream.close()
        if len(raw) > 262144:
            raise ValueError('Runtime response exceeds bounded JSON size')
        record['response'] = body = json.loads(raw)
        self.endpoint(binding)
        if result.get('statusCode') != 200 or not record['api_evidence'].get('request_id'):
            raise ValueError('Runtime invocation did not succeed with an AWS request ID')
        if not isinstance(body, dict) or body.get('result') != 'OBSERVED' or body.get('release_id') != release or body.get('release_definition_hash') != sha256_json(self.fixtures.releases[release].as_contract()) or body.get('request_registry_snapshot_hash') != self.fixtures.request_registry_snapshot_hash:
            raise ValueError('Runtime returned inconsistent fixed release bindings')
        if body.get('operation') != payload['operation'] or body.get('request_id') != payload['request_id']:
            raise ValueError('Runtime response does not match the submitted operation/request')
        identity = body.get('identity') or {}
        if identity.get('account') != ACCOUNT or not identity.get('request_id'):
            raise ValueError('Runtime caller identity evidence missing')
        record['principal_id'] = assert_observed_role_matches(binding['ExecutionRoleArn'], identity.get('arn',''))
        record['status'] = 'PASS'
        return body

    def tool(self, release, request_id, tool, label, expected):
        before = self.ledger()
        record = {'label':label,'expected':expected,'status':'FAIL','release_id':release,'request_id':request_id,'tool':tool,'ledger_before_hash':stable_ledger(before),'ledger_before':before}
        self.report.setdefault('authorization_tests', []).append(record)
        try:
            body = self.invoke(release, {'operation':'invoke_tool','tool':tool,'request_id':request_id},label)
        except Exception as exc:
            record['invocation_error'] = safe_error(exc)
            raise
        finally:
            try:
                after = self.ledger()
                record.update(ledger_after=after,ledger_after_hash=stable_ledger(after))
            except Exception as exc:
                record['ledger_after_error'] = safe_error(exc)
                raise
        record.update(mcp_id=body.get('mcp_id'),gateway_response=body.get('gateway_response'),ledger_after_hash=stable_ledger(after))
        if body.get('tool') != 'VendorPaymentTools___'+tool:
            raise ValueError('Runtime did not invoke the requested protected tool')
        if expected == 'DENY':
            if not policy_denial(body['gateway_response'], body['mcp_id']) or stable_ledger(before) != stable_ledger(after):
                raise ValueError('Expected correlated Policy rejection with unchanged ledger: '+label)
            record.update(status='PASS', outcome='DENY')
        else:
            request = self.fixtures.trusted_request(request_id)
            evidence = validate_execution_evidence(body['gateway_response'],mcp_id=body['mcp_id'],request_id=request_id,
                business_key='conn-demo#'+request['fixture_dataset_id']+'#'+request_id,
                gateway_id=self.binding['resources']['GatewayIdentifier'],target_id=self.report['baseline_before']['stable']['target_id'],
                before_items=before,after_items=after)
            record.update(status='PASS',outcome='ALLOW',execution_evidence=evidence)
        return record

    def replay(self):
        before = stable_ledger(self.ledger()); observations = []
        for release in ('V1','V2'):
            for case in self.fixtures.all_cases:
                body = self.invoke(release,{'operation':'evaluate','request_id':case.request_id},'REPLAY-'+release+'-'+case.case_id)
                observation = body.get('evaluation', {})
                if observation.get('judgment') != case.expected[release.lower()+'_judgment'] or observation.get('gateway_outcome') != 'NOT_RUN':
                    raise ValueError('Fixed Runtime replay is missing or disagrees with the acceptance fixture')
                observations.append({'release_id':release,'case_id':case.case_id,'observation':observation})
        if before != stable_ledger(self.ledger()):
            raise ValueError('Read-only replay changed the ledger')
        self.report['replay_observations'] = observations
        self.report['gate_b'] = 'NOT_RUN'  # Strands and benign release still absent.
        self.checkpoint('replay')

    def begin_policy(self, plan):
        current = self.journal.value or {}
        if current and current.get('status') != 'CLEAN':
            raise ValueError('Previous Gate A policy journal remains unresolved')
        owned = {'schema_version':'1.0','scope':DEFINITION_SCOPE,'status':'PREPARED','build_id':self.env['CODEBUILD_BUILD_ID'],
            'source_sha256':self.env['AD_SOURCE_SHA256'],'policy_engine_id':self.engine,
            'policy_name':'AuthorityDeltaGateA_'+plan['policy_hash'][:16], 'policy_hash':plan['policy_hash'],
            'statement':plan['statement'],'client_token':str(uuid.uuid4()),'runtime_bindings':copy.deepcopy(self.runtimes),
            'allowed_request_ids':plan['allowed_request_ids'],'creation_response_received':False,'created_at':observed_at()}
        self.journal.write(owned); self.owned = owned
        try:
            response = self.control.create_policy(policyEngineId=self.engine,name=owned['policy_name'],
                definition={'cedar':{'statement':owned['statement']}},validationMode='FAIL_ON_ANY_FINDINGS',enforcementMode='ACTIVE',
                description=DEFINITION_SCOPE,clientToken=owned['client_token'])
        except Exception as exc:
            code = getattr(exc,'response',{}).get('Error',{}).get('Code')
            if code in ('ValidationException','AccessDeniedException','ServiceQuotaExceededException'):
                owned['creation_rejected'] = True
                self.journal.write(owned)
            raise
        owned.update(policy_id=response['policyId'],creation_response_received=True,status='CREATED')
        self.journal.write(owned)
        self.report['policy_create'] = response
        for _ in range(24):
            policy = self.control.get_policy(policyEngineId=self.engine,policyId=owned['policy_id'])
            if policy.get('status') == 'ACTIVE':
                self.check_owned(policy, owned)
                return
            if policy.get('status') in ('CREATE_FAILED','UPDATE_FAILED','DELETE_FAILED'):
                raise ValueError('Policy service failed creation: '+str(policy.get('statusReasons'))[:1500])
            self.sleep(5)
        raise ValueError('Policy did not become ACTIVE within bounded wait')

    def check_owned(self, policy, owned):
        if policy.get('policyEngineId') != self.engine or policy.get('name') != owned['policy_name'] or policy.get('definition',{}).get('cedar',{}).get('statement') != owned['statement']:
            raise ValueError('Refusing to change a Policy whose ownership/definition is unverified')

    def reconcile_creation(self, owned):
        """Resolve an interrupted request with its exact saved idempotency token.

        The only permitted outcome is immediate cleanup of this same synthetic
        proof. It cannot advance AUTH-02 or constitute a human publication.
        """
        owned['status'] = 'RECONCILING'
        self.journal.write(owned)
        response = self.control.create_policy(policyEngineId=self.engine,name=owned['policy_name'],
            definition={'cedar':{'statement':owned['statement']}},validationMode='FAIL_ON_ANY_FINDINGS',
            enforcementMode='ACTIVE',description=DEFINITION_SCOPE,clientToken=owned['client_token'])
        owned.update(policy_id=response['policyId'],creation_response_received=True,status='CREATED')
        self.journal.write(owned)
        self.report.setdefault('reconciled_creation',[]).append(response)
        return owned['policy_id']

    def cleanup(self, owned):
        if owned.get('scope') != DEFINITION_SCOPE or owned.get('policy_engine_id') != self.engine or not re.fullmatch(r'AuthorityDeltaGateA_[0-9a-f]{16}',owned.get('policy_name','')):
            raise ValueError('Unrecognized journal; no Policy cleanup attempted')
        expected = compile_permit(gateway_arn=self.binding['resources']['GatewayArn'],
            role_arn=owned['runtime_bindings']['V1']['ExecutionRoleArn'],
            allowed_request_ids=build_policy_plan(self.fixtures,Decision.MAINTAIN)['allowed_request_ids'],
            request_registry_snapshot_hash=self.fixtures.request_registry_snapshot_hash)
        if owned.get('statement') != expected['statement'] or owned.get('allowed_request_ids') != expected['allowed_request_ids'] or owned.get('policy_hash') != expected['policy_hash']:
            raise ValueError('Journal does not describe the fixed scoped test permit')
        matches = [p for p in policies(self.control,self.engine) if p.get('name') == owned['policy_name']]
        policy_id = owned.get('policy_id') or (matches[0]['policyId'] if len(matches)==1 else None)
        if len(matches)>1:
            raise ValueError('Ambiguous owned Policy')
        if not policy_id and not owned.get('creation_rejected'):
            policy_id = self.reconcile_creation(owned)
        if policy_id:
            try:
                current = self.control.get_policy(policyEngineId=self.engine,policyId=policy_id)
            except Exception as exc:
                if not missing(exc): raise
                if not owned.get('delete_requested'):
                    raise ValueError('Policy is not visible before a confirmed delete; journal remains unresolved') from exc
            else:
                self.check_owned(current,owned)
                # Creation may still be settling after a network interruption.
                for _ in range(24):
                    if current.get('status') not in ('CREATING','UPDATING'):
                        break
                    self.sleep(5)
                    current = self.control.get_policy(policyEngineId=self.engine,policyId=policy_id)
                    self.check_owned(current,owned)
                else:
                    raise ValueError('Owned Policy did not settle before cleanup')
                owned.update(delete_requested=True,policy_id=policy_id,status='DELETING')
                self.journal.write(owned)
                if current.get('status') != 'DELETING':
                    self.control.delete_policy(policyEngineId=self.engine,policyId=policy_id)
                for _ in range(60):
                    try:
                        current = self.control.get_policy(policyEngineId=self.engine,policyId=policy_id)
                    except Exception as exc:
                        if missing(exc): break
                        raise
                    if current.get('status')=='DELETE_FAILED':
                        raise ValueError('Owned test Policy deletion failed')
                    self.sleep(2)
                else: raise ValueError('Policy deletion not confirmed; journal remains unresolved')
        elif not owned.get('creation_rejected'):
            raise ValueError('Policy creation outcome unknown; ownership journal retained for recovery')
        for _ in range(30):
            remaining=policies(self.control,self.engine)
            if not remaining: break
            if any(p.get('policyId')!=policy_id or p.get('name')!=owned['policy_name'] for p in remaining):
                raise ValueError('Additional Policies exist; preserve them and keep Gate A incomplete')
            self.sleep(2)
        else: raise ValueError('Owned Policy remains visible after deletion')
        # Data plane may lag control-plane deletion. Record each actual outcome.
        self.runtimes = owned['runtime_bindings']
        request_id = owned['allowed_request_ids'][0]
        probes = []
        self.report['cleanup']={'status':'IN_PROGRESS','revocation_probes':probes}
        for _ in range(12):
            before = self.ledger()
            probe = {'ledger_before':before,'ledger_before_hash':stable_ledger(before),'status':'FAIL'}
            probes.append(probe)
            try:
                body = self.invoke('V1',{'operation':'invoke_tool','tool':'prepare_vendor_payment','request_id':request_id},'CLEANUP-REVOKE')
            except Exception as exc:
                probe['invocation_error']=safe_error(exc)
                raise
            finally:
                try:
                    after=self.ledger()
                    probe.update(ledger_after=after,ledger_after_hash=stable_ledger(after))
                except Exception as exc:
                    probe['ledger_after_error']=safe_error(exc)
                    raise
            denied = policy_denial(body.get('gateway_response',{}),body.get('mcp_id'))
            probe.update(gateway_response=body.get('gateway_response'),mcp_id=body.get('mcp_id'),denied=denied)
            if denied and stable_ledger(before)==stable_ledger(after):
                probe.update(status='PASS',outcome='DENY')
                owned.update(status='CLEAN',cleanup_completed_at=observed_at())
                self.journal.write(owned)
                self.report['cleanup']={'status':'PASS','policy_count':0,'revocation_probes':probes}
                return
            # A propagation-lag ALLOW is still a real ALLOW and must preserve integrity.
            request = self.fixtures.trusted_request(request_id)
            proof=validate_execution_evidence(body['gateway_response'],mcp_id=body['mcp_id'],request_id=request_id,
                business_key='conn-demo#'+request['fixture_dataset_id']+'#'+request_id,
                gateway_id=self.binding['resources']['GatewayIdentifier'],target_id=self.report['baseline_before']['stable']['target_id'],before_items=before,after_items=after)
            probe.update(status='PROPAGATING',outcome='ALLOW',execution_evidence=proof)
            self.sleep(5)
        self.report['cleanup']={'status':'FAIL','revocation_probes':probes}
        raise ValueError('Data-plane test-permit revocation not confirmed')

    def recover_previous(self):
        self.journal = Journal(self.s3,self.bucket)
        previous = self.journal.value
        if not previous or previous.get('status')=='CLEAN': return
        if previous.get('build_id') == self.env['CODEBUILD_BUILD_ID']:
            raise ValueError('Current build already owns an unresolved journal')
        builds = self.session.client('codebuild').batch_get_builds(ids=[previous['build_id']]).get('builds',[])
        if len(builds)!=1 or builds[0].get('id')!=previous['build_id'] or builds[0].get('buildStatus')=='IN_PROGRESS':
            raise ValueError('Previous writer termination not confirmed; no new Policy created')
        self.owned = previous.copy()
        self.cleanup(self.owned)
        self.report['previous_run_recovery']={'status':'PASS','build_id':previous['build_id'],'cleanup':copy.deepcopy(self.report.get('cleanup',{}))}
        self.owned = None
        self.checkpoint('recovered')

    def execute(self):
        self.establish_prior_evidence()
        initial = observe_baseline(self.session,self.binding,self.fixtures)
        self.report['baseline_before']=initial
        self.recover_previous()
        if policies(self.control,self.engine):
            raise ValueError('Existing policies are outside the empty test engine; no new permit added')
        self.deploy_runtimes()
        self.replay()
        plan = build_policy_plan(self.fixtures, Decision.MAINTAIN)
        allowed = plan['allowed_request_ids']
        # Default denial from the actual V2 execution identity, before any test permit.
        self.tool('V2',allowed[0],'prepare_vendor_payment','AUTH-01-UNAPPROVED-V2','DENY')
        self.report['auth_01']='PASS'
        self.checkpoint('auth-01')
        cedar = compile_permit(gateway_arn=self.binding['resources']['GatewayArn'],role_arn=self.runtimes['V1']['ExecutionRoleArn'],
            allowed_request_ids=allowed,request_registry_snapshot_hash=self.fixtures.request_registry_snapshot_hash)
        if cedar is None: raise ValueError('Approved boundary unexpectedly has no permitted request')
        self.report['test_policy']=dict(cedar,scope=DEFINITION_SCOPE)
        self.begin_policy(cedar)
        self.checkpoint('test-permit')
        # Permit propagation can lag ACTIVE; only retry a DENY, never an unclassified result.
        for attempt in range(12):
            try:
                self.tool('V1',allowed[0],'prepare_vendor_payment','AUTH-02-PERMIT-READY','ALLOW')
                break
            except ValueError:
                last=self.report['authorization_tests'][-1]
                if not policy_denial(last.get('gateway_response',{}),last.get('mcp_id')) or last.get('ledger_before_hash') != last.get('ledger_after_hash'): raise
                last['status']='PROPAGATING'; self.sleep(5)
        else: raise ValueError('Scoped permit did not reach the Gateway within bounded wait')
        for request_id in allowed[1:]:
            self.tool('V1',request_id,'prepare_vendor_payment','AUTH-02-ALLOWED-'+request_id[-8:],'ALLOW')
        repeat = self.tool('V1',allowed[0],'prepare_vendor_payment','AUTH-02-IDEMPOTENT-REPEAT','ALLOW')
        if repeat['execution_evidence']['created'] or repeat['execution_evidence']['tool_result']['idempotent_replay'] is not True:
            repeat['status'] = 'FAIL'
            raise ValueError('Repeated business request did not preserve the original ledger entry')
        self.tool('V2',allowed[0],'prepare_vendor_payment','AUTH-02-OTHER-PRINCIPAL','DENY')
        for case in self.fixtures.all_cases:
            if case.request_id not in allowed:
                self.tool('V1',case.request_id,case.request['action'],'AUTH-02-'+case.case_id,'DENY')
        unknown='req-'+sha256_json({'gate_a_unknown_request':True})
        if unknown in [c.request_id for c in self.fixtures.all_cases]: raise ValueError('Negative request unexpectedly exists')
        self.tool('V1',unknown,'prepare_vendor_payment','AUTH-02-UNKNOWN-REQUEST','DENY')
        self.tool('V1',allowed[0],'export_credentials','AUTH-02-OTHER-TOOL','DENY')
        self.report['auth_02']='PASS'
        self.checkpoint('auth-02')
        self.cleanup(self.owned)
        self.owned = None
        final=observe_baseline(self.session,self.binding,self.fixtures)
        if final['stable']!=initial['stable'] or final['policies']:
            raise ValueError('Baseline bindings changed or test Policy remains')
        from authority_delta.execution_evidence import decode_ledger_items
        expected_ledger={item['business_key']:item for item in decode_ledger_items(initial['ledger'])}
        records=(self.report.get('previous_run_recovery',{}).get('cleanup',{}).get('revocation_probes',[])
            +self.report.get('authorization_tests',[])+self.report.get('cleanup',{}).get('revocation_probes',[]))
        for record in records:
            proof=record.get('execution_evidence')
            if proof and proof.get('status')=='PASS':
                item=proof['ledger_record']
                old=expected_ledger.setdefault(item['business_key'],item)
                if old!=item: raise ValueError('Ledger history changed between validated calls')
        if decode_ledger_items(final['ledger']) != [expected_ledger[key] for key in sorted(expected_ledger)]:
            raise ValueError('Final ledger contains unexplained changes between calls')
        self.report['baseline_after']=final
        for release, artifact in self.report['runtime_artifacts'].items():
            self.validate_runtime(release,artifact)
        self.report.update(result='PASS',gate_a='PASS',gate_b='NOT_RUN',completed_at=observed_at())
        self.checkpoint('complete')

    def stop_sessions(self):
        for arn, session_id in self.sessions.items():
            try:
                binding=self.session_bindings[arn]
                self.data.stop_runtime_session(agentRuntimeArn=arn,qualifier=binding['EndpointName'],runtimeSessionId=session_id)
            except Exception as exc:
                self.report.setdefault('session_stop_warnings',[]).append(safe_error(exc))


def run_worker(session, environment, root=ROOT, runner=GateA):
    report={'schema_version':'1.0','baseline_id':'AD-BASELINE-1.0','scope':'GATE_A_FIXED_RUNTIMES_AND_SCOPED_GATEWAY_PROOF',
        'result':'FAIL','gate_a':'NOT_RUN','started_at':observed_at(),'build_id':environment.get('CODEBUILD_BUILD_ID'),
        'source_sha256':environment.get('AD_SOURCE_SHA256'),'credentials_recorded':False,'new_model_invocation':'NOT_RUN'}
    job=None
    try:
        job=runner(session,environment,report,root=root)
        job.execute()
    except Exception as exc:
        report.update(result='FAIL',gate_a='NOT_PASSED',error=safe_error(exc))
    finally:
        if job is not None:
            if job.owned is not None:
                try: job.cleanup(job.owned)
                except Exception as exc:
                    report.setdefault('cleanup',{}).update(status='UNKNOWN',error=safe_error(exc))
                    report.update(result='FAIL',gate_a='NOT_PASSED')
            try: job.stop_sessions()
            except Exception as exc: report.setdefault('session_stop_warnings',[]).append(safe_error(exc))
    report['completed_at']=observed_at()
    try: encoded=encode_evidence(report)
    except (TypeError,ValueError,OverflowError,RecursionError):
        report=recover_serializable_report(report); encoded=encode_evidence(report)
    print('AUTHORITY_DELTA_GATE_A',flush=True); print(encoded.decode(),flush=True)
    try:
        save_evidence(session,environment,encoded,root/'evidence/aws/gate-a-result.json',environment['AD_REPORT_KEY'])
    except Exception as exc:
        print('Evidence save failed: '+json.dumps(safe_error(exc)),flush=True)
        return 1
    return 0 if report['result']=='PASS' and report.get('cleanup',{}).get('status')=='PASS' else 1


def main():
    import boto3
    from botocore.config import Config
    session=boto3.Session(region_name=REGION); original=session.client
    session.client=lambda service,**kw: original(service,config=Config(connect_timeout=10,read_timeout=120,retries={'total_max_attempts':1}),**kw)
    return run_worker(session,os.environ)

if __name__=='__main__': raise SystemExit(main())
