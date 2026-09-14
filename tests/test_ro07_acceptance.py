"""RO-07 final export gate; all AWS-looking values remain local fixtures."""
import copy
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
import uuid

from authority_delta.business.service import BusinessService
from authority_delta.business.invocation import InvocationGate
from authority_delta.business.acceptance import projected
from authority_delta.canonical import sha256_json
from scripts.check_ro07_acceptance import check
from support.business import ACTOR
import test_authority_revocation as revocation_contracts
import test_business_application_aws as aws_contracts
import test_business_delegation as d3


class LiveInvocation:
    def invoke(self, candidate, request_id):
        runtime = candidate['execution_binding']['runtime']
        evidence = {'runtime_request_id': 'aws-runtime-request',
            'runtime_session_id': 'aws-runtime-session',
            'principal': candidate['policy_binding']['principal_id'],
            'endpoint_before': {'request_id': 'aws-endpoint-before',
                'endpoint_arn': runtime['endpoint_arn'],
                'live_version': runtime['runtime_version']},
            'endpoint_after': {'request_id': 'aws-endpoint-after',
                'endpoint_arn': runtime['endpoint_arn'],
                'live_version': runtime['runtime_version']},
            'gateway_response': {'http_status': 200}, 'mcp_id': 'aws-mcp-id',
            'outcome': 'ALLOW', 'execution': {'status': 'PASS', 'outcome': 'ALLOW',
                'aws_request_id': 'aws-gateway-request', 'mcp_id': 'aws-mcp-id',
                'business_key': 'fixture-business-key',
                'tool_result': {'request_id': request_id}}}
        return {'schema_version': '1.0', 'kind': 'CUSTOMER_RUNTIME_INVOCATION',
            'status': 'EXECUTED', 'application_id': candidate['application_id'],
            'enforcement_digest': candidate['enforcement_digest'],
            'request_id': request_id, 'outcome': 'ALLOW',
            'evidence_hash': sha256_json(evidence), 'evidence': evidence,
            'invocation_transport': {'function_arn':
                candidate['invocation_binding']['function_arn'],
                'request_id': 'aws-invocation-lambda-request', 'http_status': 200,
                'executed_version': '7', 'invoke_role_arn':
                candidate['invocation_binding']['invoke_role_arn'],
                'assume_role_request_id': 'aws-invocation-assume-request'}}


class LiveRevocation:
    def revoke(self, candidate, request):
        result = revocation_contracts.raw_revocation_result(candidate, request)
        result['publisher_invocation']['request_id'] = 'aws-revoke-lambda-request'
        result['publisher_invocation']['assume_role_request_id'] = 'aws-revoke-assume-request'
        for item in result['outcomes']:
            evidence = item['evidence']
            evidence['runtime_request_id'] = 'aws-runtime-' + item['request_id'][-8:]
            evidence['endpoint_before']['request_id'] = 'aws-endpoint-before'
            evidence['endpoint_after']['request_id'] = 'aws-endpoint-after'
            item['evidence_hash'] = sha256_json(evidence)
        return result


def lifecycle_export():
    flow = d3.DelegationFlow(
        methodName='test_verified_canary_is_only_transition_to_applied_binding')
    flow.setUp()
    registration = aws_contracts.live_registration()
    flow.registration = registration
    app = BusinessService(flow.flow.db, flow.flow.blobs,
        clock=flow.flow.clock, adapters=[registration])
    flow.flow.app = app
    flow.app = app
    flow.publish()
    started = flow.start(flow.delegate(days=1))
    flow.worker(d3.ScriptedPublisher()).process(flow.message(started))
    candidate = flow.app.detail(ACTOR, flow.oid)['applications'][0]
    candidate = json.loads(flow.flow.blobs.read(candidate['candidate_ref']))
    request_id = next(item['request_id'] for item in candidate['expected_outcomes']
                      if item['expected_outcome'] == 'ALLOW')
    InvocationGate(flow.flow.db, flow.flow.blobs, LiveInvocation(), [registration],
                   flow.flow.clock).invoke(ACTOR, flow.oid,
        {'operation_id': uuid.uuid4().hex, 'request_id': request_id})
    stopped = flow.app.request_revocation(ACTOR, flow.oid, flow.command(
        application_id=started['application_id'], reason='Complete RO-07 fixture stop'))
    message = {key: stopped[key] for key in ('operation', 'object_id',
        'application_id', 'enforcement_digest', 'revocation_id',
        'revocation_digest')}
    revocation_contracts.RevocationWorker(flow.flow.db, flow.flow.blobs,
        LiveRevocation(), [registration], flow.flow.clock).process(message)
    return flow.app.export_acceptance_evidence(ACTOR, flow.oid)


class Ro07AcceptanceTests(unittest.TestCase):
    def test_exact_live_looking_lifecycle_export_passes_without_running_aws(self):
        result = check(lifecycle_export())
        self.assertEqual(result['status'], 'RO07_LIVE_AUTHORITY_LIFECYCLE_CONFIRMED')
        self.assertEqual(result['executed_invocation_count'], 1)
        self.assertGreater(result['denied_request_count'], 1)
        self.assertEqual(result['aws_execution'], 'NOT_RUN_BY_THIS_CHECKER')

    def test_local_or_missing_deny_transport_cannot_pass(self):
        value = lifecycle_export()
        document = value['revocations'][0]['document']
        document['publisher_result']['outcomes'][0]['evidence'][
            'runtime_request_id'] = 'LOCAL_SCRIPTED_RUNTIME_ONLY'
        document['publisher_result']['outcomes'][0]['evidence_hash'] = sha256_json(
            document['publisher_result']['outcomes'][0]['evidence'])
        value['revocations'][0] = projected(document)
        unsigned = {key: item for key, item in value.items()
                    if key != 'document_digest'}
        value['document_digest'] = sha256_json(unsigned)
        with self.assertRaisesRegex(ValueError, 'DENY'):
            check(value)

    def test_checker_bootstraps_the_vendored_canonical_json_wheel(self):
        root = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory() as folder:
            source = Path(folder) / 'acceptance.json'
            output = Path(folder) / 'result.json'
            source.write_text(json.dumps(lifecycle_export()), encoding='utf-8')
            completed = subprocess.run([sys.executable, '-S',
                str(root / 'scripts' / 'check_ro07_acceptance.py'),
                '--acceptance-export', str(source), '--output', str(output)],
                cwd=root, env=dict(os.environ, PYTHONPATH=''), text=True,
                capture_output=True)
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertEqual(json.loads(output.read_text(encoding='utf-8'))['status'],
                             'RO07_LIVE_AUTHORITY_LIFECYCLE_CONFIRMED')


if __name__ == '__main__':
    unittest.main()
