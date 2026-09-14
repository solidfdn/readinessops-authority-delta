"""Local contracts for D3 AWS transport, queue recovery and customer publisher."""
import copy
import io
import json
import unittest
import boto3
from botocore.stub import Stubber, ANY
from botocore.response import StreamingBody

from authority_delta.business.aws_application import (
    LambdaPublisher, PUBLISHER_FENCE_RECOVERY_DELAY_SECONDS,
    dispatch_application, dispatch_pending_applications)
from authority_delta.business.customer_publisher import (
    CustomerPolicyPublisher, LambdaCanaryProbe, PublisherInvocationFence,
    PUBLISHER_FENCE_SECONDS, VendorPaymentInvocationProbe,
    verified_invocation_candidate)
from authority_delta.business.delegation import registration_with_hash, verify_publisher_result
from authority_delta.business.service import BusinessService
from authority_delta.business.storage import encode
from authority_delta.cedar import principal_id_from_role_arn
from support.business import ACTOR, MemoryStore, vendor_registration
import test_business_delegation as d3


class QueueDouble:
    def __init__(self, fail=False):
        self.fail, self.calls = fail, []

    def send_message(self, **values):
        self.calls.append(values)
        if self.fail:
            raise RuntimeError('queue unavailable')
        return {'MessageId': 'message-1', 'ResponseMetadata': {
            'HTTPStatusCode': 200, 'RequestId': 'queue-request'}}


class LambdaDouble:
    def __init__(self, response):
        self.response, self.calls = response, []

    def invoke(self, **values):
        self.calls.append(values)
        raw = encode(self.response)
        return {'StatusCode': 200, 'ExecutedVersion': '7',
            'Payload': StreamingBody(io.BytesIO(raw), len(raw)),
            'ResponseMetadata': {'HTTPStatusCode': 200,
                                 'RequestId': 'publisher-request'}}


class StsDouble:
    def __init__(self, registration):
        self.registration, self.calls = registration, []

    def assume_role(self, **values):
        self.calls.append(values)
        role = self.registration['publisher_binding']['invoke_role_arn'].rsplit('/', 1)[1]
        return {'Credentials': {'AccessKeyId': 'ASIALOCAL',
            'SecretAccessKey': 'LOCAL_TEST_ONLY', 'SessionToken': 'LOCAL_TOKEN'},
            'AssumedRoleUser': {'AssumedRoleId': 'LOCAL:test',
                'Arn': (f"arn:aws:sts::{self.registration['target_account_id']}:assumed-role/"
                        f"{role}/{values['RoleSessionName']}")},
            'ResponseMetadata': {'HTTPStatusCode': 200,
                                 'RequestId': 'assume-request'}}


class MissingPolicy(Exception):
    response = {'Error': {'Code': 'ResourceNotFoundException'}}


class PolicyControl:
    def __init__(self, lose_first=False):
        self.policy = None
        self.lose_first = lose_first
        self.tokens = []
        self.deleted = []

    def create_policy(self, **values):
        self.tokens.append(values['clientToken'])
        if self.policy is None:
            self.policy = {'policyId': 'policy-customer-1',
                'name': values['name'], 'policyEngineId': values['policyEngineId'],
                'status': 'ACTIVE', 'enforcementMode': 'ACTIVE',
                'definition': copy.deepcopy(values['definition']),
                'ResponseMetadata': {'HTTPStatusCode': 202,
                                     'RequestId': 'create-request'}}
        if self.lose_first:
            self.lose_first = False
            raise TimeoutError('create response lost')
        return copy.deepcopy(self.policy)

    def get_policy(self, **values):
        if self.policy is None:
            raise MissingPolicy()
        response = copy.deepcopy(self.policy)
        response['ResponseMetadata'] = {'HTTPStatusCode': 200,
                                        'RequestId': 'get-request'}
        return response

    def delete_policy(self, **values):
        self.deleted.append(values['policyId'])
        self.policy = None
        return {'policyId': values['policyId'],
                'policyEngineId': values['policyEngineId'],
                'status': 'DELETING',
                'ResponseMetadata': {'HTTPStatusCode': 202,
                                     'RequestId': 'delete-request'}}

    def list_policies(self, **values):
        return {'policies': ([{'policyId': self.policy['policyId'],
            'name': self.policy['name']}] if self.policy else []),
            'ResponseMetadata': {'HTTPStatusCode': 200,
                                 'RequestId': 'list-request'}}


class FailedTargetDiscoveryPolicyControl(PolicyControl):
    """First create is the exact observed AWS failure; retry becomes ACTIVE."""
    def __init__(self, reason='Insufficient permissions to list targets on gateway with ID '):
        super().__init__()
        self.reason = reason
        self.creates = 0

    def create_policy(self, **values):
        self.creates += 1
        self.tokens.append(values['clientToken'])
        status = 'CREATE_FAILED' if self.creates == 1 else 'ACTIVE'
        policy_id = f'policy-customer-{self.creates}'
        self.policy = {'policyId': policy_id,
            'name': values['name'], 'policyEngineId': values['policyEngineId'],
            'status': status, 'enforcementMode': 'ACTIVE',
            'definition': copy.deepcopy(values['definition']),
            'ResponseMetadata': {'HTTPStatusCode': 202,
                                 'RequestId': f'create-request-{self.creates}'}}
        if status == 'CREATE_FAILED':
            self.policy['statusReasons'] = [self.reason]
        response = copy.deepcopy(self.policy)
        response['status'] = 'CREATING'
        return response


class ProbeDouble:
    def __init__(self, fail_allow=False):
        self.fail_allow, self.calls = fail_allow, []

    def run(self, request_id, expected):
        self.calls.append((request_id, expected))
        if self.fail_allow and expected == 'ALLOW':
            self.fail_allow = False
            raise ValueError('candidate canary failed')
        if expected == 'DENY':
            registration = live_registration()
            mcp_id = 'mcp-' + request_id[-16:]
            return {'runtime_request_id': 'runtime-' + request_id[-8:],
                'runtime_session_id': 'session-' + request_id[-8:],
                'principal': principal_id_from_role_arn(
                    registration['runtime']['execution_role_arn']),
                'endpoint_before': {'request_id': 'endpoint-before',
                    'endpoint_arn': registration['runtime']['endpoint_arn'],
                    'live_version': registration['runtime']['runtime_version']},
                'endpoint_after': {'request_id': 'endpoint-after',
                    'endpoint_arn': registration['runtime']['endpoint_arn'],
                    'live_version': registration['runtime']['runtime_version']},
                'gateway_response': {'http_status': 403,
                    'headers': {'x-amzn-requestid': 'gateway-request'},
                    'body': {'jsonrpc': '2.0', 'id': mcp_id,
                        'error': {'code': -32002,
                            'message': 'Tool Execution Denied: Tool call not allowed due to policy enforcement'}}},
                'mcp_id': mcp_id, 'outcome': 'DENY',
                'before_ledger_hash': 'a' * 64,
                'after_ledger_hash': 'a' * 64}
        return {'request_id': request_id, 'outcome': expected,
                'aws_request_id': 'probe-' + request_id[-8:]}


class EvidenceDouble:
    def registry_request(self, request_id):
        return {'fixture_dataset_id': 'fixture-local',
                'action': 'prepare_vendor_payment'}

    def ledger(self):
        return []


def live_registration():
    value = vendor_registration()
    value.pop('registration_hash')
    value['connection_mode'] = 'LIVE_CUSTOMER'
    value['source_authority'] = 'aws:confirmed-customer-registration'
    return registration_with_hash(value)


def candidate_fixture():
    flow = d3.DelegationFlow(methodName='test_no_registered_adapter_fails_closed')
    flow.setUp()
    registration = live_registration()
    flow.registration = registration
    flow.flow.app = BusinessService(flow.flow.db, flow.flow.blobs,
        clock=flow.flow.clock, adapters=[registration])
    flow.app, flow.oid = flow.flow.app, flow.flow.oid
    flow.publish()
    started = flow.start(flow.delegate())
    row = flow.flow.db.get('app', flow.oid,
                          'APPLICATION#' + started['application_id'])
    return (json.loads(flow.flow.blobs.read(row.value['candidate_ref'])),
            registration)


class ApplicationAwsContracts(unittest.TestCase):
    def _parked_application(self, error):
        db = MemoryStore()
        message = {'object_id': 'o-' + '1' * 32,
            'application_id': 'application-' + '2' * 32,
            'enforcement_digest': '3' * 64}
        state = dict(message, status='UNKNOWN', attempt=48,
            updated_at='2026-09-13T03:57:17+00:00', last_error=error)
        db.transact([
            ('app', message['object_id'],
             'APPLICATION#' + message['application_id'], state, None),
            ('jobs', 'APPLICATION_OUTBOX', message['application_id'], message, None)])
        return db, message

    def test_delete_item_denial_gets_one_delayed_recovery_and_then_parks(self):
        error = ('Publisher invocation failed: Lambda FunctionError=Unhandled; '
            'remote=ClientError: AccessDeniedException for assumed-role/'
            'authority-delta-customer-publisher while calling dynamodb:DeleteItem')
        db, message = self._parked_application(error)
        queue = QueueDouble()
        before = '2026-09-13T04:09:00+00:00'
        dispatch_pending_applications(db, queue, 'queue', clock=lambda: before)
        self.assertEqual(queue.calls, [])
        ready = '2026-09-13T04:10:17+00:00'
        dispatch_pending_applications(db, queue, 'queue', clock=lambda: ready)
        self.assertEqual(len(queue.calls), 1)
        state = db.get('app', message['object_id'],
            'APPLICATION#' + message['application_id']).value
        self.assertEqual(state['publisher_delete_item_recovery_attempts'], 1)
        self.assertEqual(state['publisher_delete_item_recovery_dispatched_at'], ready)
        # Recreate the durable outbox as the failed worker would. The recovery
        # token prevents another automatic send for the same observed cause.
        db.transact([('jobs', 'APPLICATION_OUTBOX', message['application_id'],
                     message, None)])
        dispatch_pending_applications(db, queue, 'queue', clock=lambda: ready)
        self.assertEqual(len(queue.calls), 1)

    def test_canary_result_contract_gets_one_delayed_recovery_and_then_parks(self):
        error = ('Publisher invocation failed: Lambda FunctionError=Unhandled; '
            'remote=ValueError: Canary Lambda result differs')
        db, message = self._parked_application(error)
        queue = QueueDouble()
        dispatch_pending_applications(db, queue, 'queue',
            clock=lambda: '2026-09-13T04:10:17+00:00')
        self.assertEqual(len(queue.calls), 1)
        state = db.get('app', message['object_id'],
            'APPLICATION#' + message['application_id']).value
        self.assertEqual(state['canary_result_recovery_attempts'], 1)
        self.assertEqual(state['canary_result_recovery_dispatched_at'],
                         '2026-09-13T04:10:17+00:00')
        db.transact([('jobs', 'APPLICATION_OUTBOX', message['application_id'],
                     message, None)])
        dispatch_pending_applications(db, queue, 'queue',
            clock=lambda: '2026-09-13T05:00:00+00:00')
        self.assertEqual(len(queue.calls), 1)

    def test_resource_scoped_policy_denial_gets_one_recovery_and_then_parks(self):
        error = ('Publisher invocation failed: Lambda FunctionError=Unhandled; '
            'remote=AccessDeniedException: An error occurred (AccessDeniedException) '
            'when calling the CreatePolicy operation: assumed-role/'
            'authority-delta-customer-publisher is not authorized to perform: '
            'bedrock-agentcore:ManageResourceScopedPolicy')
        db, message = self._parked_application(error)
        queue = QueueDouble()
        ready = '2026-09-13T04:10:17+00:00'
        dispatch_pending_applications(db, queue, 'queue', clock=lambda: ready)
        self.assertEqual(len(queue.calls), 1)
        state = db.get('app', message['object_id'],
            'APPLICATION#' + message['application_id']).value
        self.assertEqual(state['resource_scoped_policy_recovery_attempts'], 1)
        db.transact([('jobs', 'APPLICATION_OUTBOX', message['application_id'],
                     message, None)])
        dispatch_pending_applications(db, queue, 'queue',
            clock=lambda: '2026-09-13T05:00:00+00:00')
        self.assertEqual(len(queue.calls), 1)

    def test_gateway_policy_validation_denial_gets_one_recovery_then_parks(self):
        error = ('Publisher invocation failed: Lambda FunctionError=Unhandled; '
            'remote=AccessDeniedException: An error occurred (AccessDeniedException) '
            'when calling the CreatePolicy operation: Failed to confirm existence '
            'on AgentCore Gateway "authority-delta-gateway-test", please make sure '
            'you have "bedrock-agentcore:GetGateway" permissions')
        db, message = self._parked_application(error)
        queue = QueueDouble()
        ready = '2026-09-13T04:10:17+00:00'
        dispatch_pending_applications(db, queue, 'queue', clock=lambda: ready)
        self.assertEqual(len(queue.calls), 1)
        state = db.get('app', message['object_id'],
            'APPLICATION#' + message['application_id']).value
        self.assertEqual(state['gateway_policy_validation_recovery_attempts'], 1)
        db.transact([('jobs', 'APPLICATION_OUTBOX', message['application_id'],
                     message, None)])
        dispatch_pending_applications(db, queue, 'queue',
            clock=lambda: '2026-09-13T05:00:00+00:00')
        self.assertEqual(len(queue.calls), 1)

    def test_failed_policy_target_discovery_gets_one_recovery_then_parks(self):
        error = ('Publisher invocation failed: Lambda FunctionError=Unhandled; '
            'remote=ValueError: Owned candidate Policy entered a failed state')
        db, message = self._parked_application(error)
        queue = QueueDouble()
        ready = '2026-09-13T14:20:00+00:00'
        dispatch_pending_applications(db, queue, 'queue', clock=lambda: ready)
        self.assertEqual(len(queue.calls), 1)
        state = db.get('app', message['object_id'],
            'APPLICATION#' + message['application_id']).value
        self.assertEqual(state['failed_policy_target_discovery_recovery_attempts'], 1)
        db.transact([('jobs', 'APPLICATION_OUTBOX', message['application_id'],
                     message, None)])
        dispatch_pending_applications(db, queue, 'queue',
            clock=lambda: '2026-09-13T15:00:00+00:00')
        self.assertEqual(len(queue.calls), 1)

    def test_policy_delete_response_contract_recovers_immediately_once(self):
        error = ('Publisher invocation failed: Lambda FunctionError=Unhandled; '
            'remote=ValueError: Failed candidate Policy delete lacks successful AWS evidence')
        db, message = self._parked_application(error)
        queue = QueueDouble()
        dispatch_pending_applications(db, queue, 'queue',
            clock=lambda: '2026-09-13T03:57:17+00:00')
        self.assertEqual(len(queue.calls), 1)
        state = db.get('app', message['object_id'],
            'APPLICATION#' + message['application_id']).value
        self.assertEqual(state['policy_delete_response_recovery_attempts'], 1)
        db.transact([('jobs', 'APPLICATION_OUTBOX', message['application_id'],
                     message, None)])
        dispatch_pending_applications(db, queue, 'queue',
            clock=lambda: '2026-09-13T03:57:18+00:00')
        self.assertEqual(len(queue.calls), 1)

    def test_policy_create_response_contract_recovers_immediately_once(self):
        error = ('Publisher invocation failed: Lambda FunctionError=Unhandled; '
            'remote=ValueError: Policy create lacks successful AWS evidence')
        db, message = self._parked_application(error)
        queue = QueueDouble()
        dispatch_pending_applications(db, queue, 'queue',
            clock=lambda: '2026-09-13T15:58:37+00:00')
        self.assertEqual(len(queue.calls), 1)
        state = db.get('app', message['object_id'],
            'APPLICATION#' + message['application_id']).value
        self.assertEqual(state['policy_create_response_recovery_attempts'], 1)

    def test_policy_create_discovery_reconciliation_is_one_additional_exact_retry(self):
        error = ('Publisher invocation failed: Lambda FunctionError=Unhandled; '
            'remote=ValueError: Policy create lacks successful AWS evidence')
        db, message = self._parked_application(error)
        row = db.get('app', message['object_id'],
            'APPLICATION#' + message['application_id'])
        db.transact([('app', message['object_id'],
            'APPLICATION#' + message['application_id'], dict(row.value,
                policy_create_response_recovery_attempts=1), row.version)])
        queue = QueueDouble()
        dispatch_pending_applications(db, queue, 'queue',
            clock=lambda: '2026-09-13T17:20:00+00:00')
        self.assertEqual(len(queue.calls), 1)
        state = db.get('app', message['object_id'],
            'APPLICATION#' + message['application_id']).value
        self.assertEqual(state['policy_create_discovery_recovery_attempts'], 1)
        db.transact([('jobs', 'APPLICATION_OUTBOX', message['application_id'],
                     message, None)])
        dispatch_pending_applications(db, queue, 'queue',
            clock=lambda: '2026-09-13T17:20:01+00:00')
        self.assertEqual(len(queue.calls), 1)

    def test_delayed_recovery_restores_token_when_sqs_send_fails(self):
        error = ('Publisher invocation failed: Lambda FunctionError=Unhandled; '
            'remote=ClientError: AccessDeniedException for assumed-role/'
            'authority-delta-customer-publisher while calling dynamodb:DeleteItem')
        db, message = self._parked_application(error)
        with self.assertRaises(RuntimeError):
            dispatch_pending_applications(db, QueueDouble(fail=True), 'queue',
                clock=lambda: '2026-09-13T04:10:17+00:00')
        state = db.get('app', message['object_id'],
            'APPLICATION#' + message['application_id']).value
        self.assertEqual(state['publisher_delete_item_recovery_attempts'], 0)
        self.assertIsNone(state['publisher_delete_item_recovery_dispatched_at'])

    def test_lambda_function_error_retains_bounded_remote_root_cause(self):
        candidate, registration = candidate_fixture()
        client = LambdaDouble({})
        def failed(**values):
            raw = encode({'errorType': 'ClientError',
                'errorMessage': 'AccessDeniedException dynamodb:DeleteItem'})
            return {'StatusCode': 200, 'FunctionError': 'Unhandled',
                'Payload': StreamingBody(io.BytesIO(raw), len(raw)),
                'ResponseMetadata': {'HTTPStatusCode': 200,
                                     'RequestId': 'publisher-request'}}
        client.invoke = failed
        with self.assertRaisesRegex(ValueError,
                'remote=ClientError: AccessDeniedException dynamodb:DeleteItem'):
            LambdaPublisher(client, [registration], sts=StsDouble(registration),
                assumed_client=lambda credentials, region: client).publish(candidate)

    def test_customer_publisher_fence_prevents_overlap_and_stale_release(self):
        journal, now = MemoryStore(), ['2026-09-09T00:00:00+00:00']
        fence = PublisherInvocationFence(journal, lambda: now[0])
        digest = 'a' * 64
        fence.claim(digest, 'worker-1')
        with self.assertRaisesRegex(ValueError, 'still active'):
            fence.claim(digest, 'worker-2')
        now[0] = '2026-09-09T00:13:00+00:00'
        fence.claim(digest, 'worker-2')
        self.assertFalse(fence.release(digest, 'worker-1'))
        self.assertTrue(fence.release(digest, 'worker-2'))

    def test_customer_invocation_requires_exact_still_verified_b_journal(self):
        candidate, registration = candidate_fixture()
        journal = MemoryStore()
        publisher = CustomerPolicyPublisher(PolicyControl(), journal, ProbeDouble(),
            registration, lambda: '2026-09-09T00:01:00+00:00', sleep=lambda _: None)
        self.assertEqual(publisher.publish(candidate)['status'], 'VERIFIED')
        observed = verified_invocation_candidate(journal,
            candidate['application_id'], candidate['enforcement_digest'], registration)
        self.assertEqual(observed, candidate)
        row = journal.get('publisher', candidate['enforcement_digest'], 'STATE')
        journal.transact([('publisher', candidate['enforcement_digest'], 'STATE',
            dict(row.value, status='STOP_REQUESTED'), row.version)])
        with self.assertRaisesRegex(ValueError, 'active account-B authority'):
            verified_invocation_candidate(journal, candidate['application_id'],
                candidate['enforcement_digest'], registration)

    def test_committed_application_has_recoverable_outbox(self):
        flow = d3.DelegationFlow(methodName='test_no_registered_adapter_fails_closed')
        flow.setUp()
        flow.publish()
        started = flow.start(flow.delegate())
        message = {k: started[k] for k in (
            'object_id', 'application_id', 'enforcement_digest')}
        self.assertEqual(flow.flow.db.get('jobs', 'APPLICATION_OUTBOX',
                                         started['application_id']).value, message)
        queue = QueueDouble(fail=True)
        with self.assertRaises(RuntimeError):
            dispatch_pending_applications(flow.flow.db, queue, 'application-queue')
        self.assertIsNotNone(flow.flow.db.get('jobs', 'APPLICATION_OUTBOX',
                                              started['application_id']))
        queue.fail = False
        self.assertTrue(dispatch_application(flow.flow.db, queue,
                                             'application-queue', message))
        self.assertIsNone(flow.flow.db.get('jobs', 'APPLICATION_OUTBOX',
                                           started['application_id']))

    def test_lambda_publisher_invokes_only_registered_qualified_arn(self):
        candidate, registration = candidate_fixture()
        raw_result = d3.publisher_result(candidate)
        raw_result.pop('publisher_invocation')
        client = LambdaDouble(raw_result)
        result = LambdaPublisher(client, [registration], sts=StsDouble(registration),
            assumed_client=lambda credentials, region: client).publish(candidate)
        self.assertEqual(client.calls[0]['FunctionName'],
                         registration['publisher_binding']['function_arn'])
        request = json.loads(client.calls[0]['Payload'])
        self.assertEqual(request['operation'], 'PUBLISH')
        self.assertEqual(request['candidate'], candidate)
        self.assertEqual(result['publisher_invocation']['request_id'],
                         'publisher-request')
        verify_publisher_result(result, candidate)
        mutations = [
            lambda changed: changed['publisher_binding'].update(function_arn=
                changed['publisher_binding']['function_arn'].replace(':live', ':foreign')),
            lambda changed: changed['publisher_binding'].update(invoke_role_arn=
                changed['discovery_binding']['role_arn']),
            lambda changed: changed['publisher_binding'].update(
                external_id='foreign-external-id-00000000000001'),
        ]
        for mutate in mutations:
            changed = copy.deepcopy(candidate)
            mutate(changed)
            with self.assertRaises(ValueError):
                LambdaPublisher(client, [registration], sts=StsDouble(registration),
                    assumed_client=lambda credentials, region: client).publish(changed)
        self.assertEqual(len(client.calls), 1)

    def test_live_publisher_assumes_only_registered_role_with_external_id(self):
        candidate, registration = candidate_fixture()
        response = d3.publisher_result(candidate)
        response.pop('publisher_invocation')
        client, sts, created = LambdaDouble(response), StsDouble(registration), []
        def factory(credentials, region):
            created.append((credentials, region))
            return client
        result = LambdaPublisher(LambdaDouble(response), [registration], sts=sts,
                                 assumed_client=factory).publish(candidate)
        self.assertEqual(sts.calls, [{
            'RoleArn': registration['publisher_binding']['invoke_role_arn'],
            'RoleSessionName': 'authority-delta-' + candidate['application_id'].split('-', 1)[1][:16],
            'ExternalId': registration['publisher_binding']['external_id'],
            'DurationSeconds': 900}])
        self.assertEqual(created[0][1], registration['target_region'])
        self.assertEqual(result['publisher_invocation']['assume_role_request_id'],
                         'assume-request')
        verify_publisher_result(result, candidate)

    def test_live_publisher_fails_closed_without_sts_connector(self):
        candidate, registration = candidate_fixture()
        with self.assertRaises(ValueError):
            LambdaPublisher(LambdaDouble({}), [registration]).publish(candidate)

    def test_unknown_recovery_remains_durably_queued_until_confirmed(self):
        flow = d3.DelegationFlow(methodName='test_no_registered_adapter_fails_closed')
        flow.setUp()
        flow.publish()
        started = flow.start(flow.delegate())
        message = {k: started[k] for k in (
            'object_id', 'application_id', 'enforcement_digest')}
        queue = QueueDouble()
        dispatch_application(flow.flow.db, queue, 'application-queue', message)
        publisher = d3.ScriptedPublisher(publish=TimeoutError('unknown'),
                                         reconcile=TimeoutError('unknown'))
        worker = flow.worker(publisher)
        self.assertEqual(worker.process(message)['status'], 'UNKNOWN')
        self.assertIsNotNone(flow.flow.db.get('jobs', 'APPLICATION_OUTBOX',
                                              started['application_id']))
        dispatch_application(flow.flow.db, queue, 'application-queue', message)
        self.assertEqual(worker.process(message)['status'], 'UNKNOWN')
        self.assertIsNotNone(flow.flow.db.get('jobs', 'APPLICATION_OUTBOX',
                                              started['application_id']))
        dispatch_application(flow.flow.db, queue, 'application-queue', message)
        self.assertEqual(worker.process(message)['status'], 'UNKNOWN')
        self.assertIsNotNone(flow.flow.db.get('jobs', 'APPLICATION_OUTBOX',
                                              started['application_id']))
        state = flow.flow.db.get('app', started['object_id'],
            'APPLICATION#' + started['application_id']).value
        self.assertEqual(state['attempt'], 3)
        self.assertIsNone(state['next_attempt_at'])
        self.assertIsNotNone(flow.flow.db.get('app', started['object_id'],
            'APPLICATION#' + started['application_id']).value['lock_pk'])

    def test_customer_publisher_deny_first_active_readback_and_canary(self):
        candidate, registration = candidate_fixture()
        control, probe, journal = PolicyControl(), ProbeDouble(), MemoryStore()
        publisher = CustomerPolicyPublisher(control, journal, probe, registration,
            lambda: '2026-09-09T00:01:00+00:00', sleep=lambda _: None)
        result = publisher.publish(candidate)
        self.assertEqual(result['status'], 'VERIFIED')
        count = len(candidate['expected_outcomes'])
        self.assertEqual([outcome for _, outcome in probe.calls[:count]],
                         ['DENY'] * count)
        self.assertEqual([outcome for _, outcome in probe.calls[count:]],
                         [x['expected_outcome'] for x in sorted(
                             candidate['expected_outcomes'], key=lambda x: x['request_id'])])
        result['publisher_invocation'] = {'function_arn': registration[
            'publisher_binding']['function_arn'], 'request_id': 'invoke-request',
            'http_status': 200, 'executed_version': '7',
            'invoke_role_arn': registration['publisher_binding']['invoke_role_arn'],
            'assume_role_request_id': 'assume-request'}
        verify_publisher_result(result, candidate)
        self.assertEqual(publisher.publish(candidate)['status'], 'VERIFIED')
        self.assertEqual(len(control.tokens), 1)

    def test_failed_target_discovery_policy_is_deleted_and_rekeyed_once(self):
        candidate, registration = candidate_fixture()
        reason = ('Insufficient permissions to list targets on gateway with ID '
                  + registration['gateway_id'])
        control = FailedTargetDiscoveryPolicyControl(reason)
        probe, journal = ProbeDouble(), MemoryStore()
        publisher = CustomerPolicyPublisher(control, journal, probe, registration,
            lambda: '2026-09-13T14:20:00+00:00', sleep=lambda _: None)
        with self.assertRaisesRegex(ValueError, 'failed state'):
            publisher.publish(candidate)
        result = publisher.publish(candidate)
        self.assertEqual(result['status'], 'VERIFIED')
        self.assertEqual(control.deleted, ['policy-customer-1'])
        self.assertEqual(control.creates, 2)
        self.assertEqual(len(set(control.tokens)), 2)
        row = journal.get('publisher', candidate['enforcement_digest'], 'STATE').value
        self.assertEqual(row['failed_policy_target_discovery_recoveries'], 1)
        self.assertEqual(row['failed_policy_target_discovery_evidence']['status'],
                         'CREATE_FAILED')

    def test_failed_policy_recovery_rejects_a_different_aws_reason(self):
        candidate, registration = candidate_fixture()
        control = FailedTargetDiscoveryPolicyControl('different failure')
        journal = MemoryStore()
        publisher = CustomerPolicyPublisher(control, journal, ProbeDouble(), registration,
            lambda: '2026-09-13T14:20:00+00:00', sleep=lambda _: None)
        with self.assertRaisesRegex(ValueError, 'failed state'):
            publisher.publish(candidate)
        with self.assertRaisesRegex(ValueError, 'failed state'):
            publisher.publish(candidate)
        self.assertEqual(control.deleted, [])
        self.assertEqual(control.creates, 1)

    def test_delete_accepted_with_old_200_check_reconciles_from_absence(self):
        class OldContractControl(FailedTargetDiscoveryPolicyControl):
            def delete_policy(self, **values):
                response = super().delete_policy(**values)
                response['ResponseMetadata']['HTTPStatusCode'] = 200
                return response

        candidate, registration = candidate_fixture()
        reason = ('Insufficient permissions to list targets on gateway with ID '
                  + registration['gateway_id'])
        control = OldContractControl(reason)
        journal = MemoryStore()
        publisher = CustomerPolicyPublisher(control, journal, ProbeDouble(), registration,
            lambda: '2026-09-13T15:20:00+00:00', sleep=lambda _: None)
        with self.assertRaisesRegex(ValueError, 'failed state'):
            publisher.publish(candidate)
        with self.assertRaisesRegex(ValueError, 'delete lacks successful AWS evidence'):
            publisher.publish(candidate)
        row = journal.get('publisher', candidate['enforcement_digest'], 'STATE').value
        self.assertEqual(row['status'], 'FAILED_POLICY_DELETE_INTENT')
        self.assertIsNone(control.policy)
        result = publisher.publish(candidate)
        self.assertEqual(result['status'], 'VERIFIED')
        row = journal.get('publisher', candidate['enforcement_digest'], 'STATE').value
        self.assertTrue(row['failed_policy_target_discovery_evidence'][
            'policy_absent_readback'])

    def test_delete_policy_contract_rejects_non_202_without_losing_intent(self):
        class WrongStatusControl(FailedTargetDiscoveryPolicyControl):
            def delete_policy(self, **values):
                response = super().delete_policy(**values)
                response['status'] = 'DELETE_FAILED'
                return response

        candidate, registration = candidate_fixture()
        reason = ('Insufficient permissions to list targets on gateway with ID '
                  + registration['gateway_id'])
        journal = MemoryStore()
        publisher = CustomerPolicyPublisher(WrongStatusControl(reason), journal,
            ProbeDouble(), registration, lambda: '2026-09-13T15:20:00+00:00',
            sleep=lambda _: None)
        with self.assertRaisesRegex(ValueError, 'failed state'):
            publisher.publish(candidate)
        with self.assertRaisesRegex(ValueError, 'delete lacks successful AWS evidence'):
            publisher.publish(candidate)
        row = journal.get('publisher', candidate['enforcement_digest'], 'STATE').value
        self.assertEqual(row['status'], 'FAILED_POLICY_DELETE_INTENT')

    def test_create_accepted_with_old_200_check_reuses_same_policy_and_token(self):
        class OldContractControl(PolicyControl):
            def __init__(self):
                super().__init__()
                self.responses = 0

            def create_policy(self, **values):
                response = super().create_policy(**values)
                self.responses += 1
                if self.responses == 1:
                    response['ResponseMetadata']['HTTPStatusCode'] = 200
                return response

        candidate, registration = candidate_fixture()
        control, journal = OldContractControl(), MemoryStore()
        publisher = CustomerPolicyPublisher(control, journal, ProbeDouble(), registration,
            lambda: '2026-09-13T15:58:37+00:00', sleep=lambda _: None)
        with self.assertRaisesRegex(ValueError, 'create lacks successful AWS evidence'):
            publisher.publish(candidate)
        row = journal.get('publisher', candidate['enforcement_digest'], 'STATE').value
        self.assertEqual(row['status'], 'CLOSED_PROVEN')
        self.assertIsNone(row['policy_id'])
        self.assertIsNotNone(control.policy)
        result = publisher.publish(candidate)
        self.assertEqual(result['status'], 'VERIFIED')
        self.assertEqual(len(set(control.tokens)), 1)
        row = journal.get('publisher', candidate['enforcement_digest'], 'STATE').value
        self.assertEqual(row['policy_create_evidence']['http_status'], 202)

    def test_create_contract_rejects_wrong_identity_without_journaling_policy(self):
        class WrongIdentityControl(PolicyControl):
            def create_policy(self, **values):
                response = super().create_policy(**values)
                response['policyEngineId'] = 'another-engine'
                return response

        candidate, registration = candidate_fixture()
        journal = MemoryStore()
        publisher = CustomerPolicyPublisher(WrongIdentityControl(), journal,
            ProbeDouble(), registration, lambda: '2026-09-13T15:58:37+00:00',
            sleep=lambda _: None)
        with self.assertRaisesRegex(ValueError, 'create lacks successful AWS evidence'):
            publisher.publish(candidate)
        row = journal.get('publisher', candidate['enforcement_digest'], 'STATE').value
        self.assertEqual(row['status'], 'CLOSED_PROVEN')
        self.assertIsNone(row['policy_id'])

    def test_create_acceptance_allows_optional_mode_with_active_readback(self):
        class OptionalModeResponseControl(PolicyControl):
            def create_policy(self, **values):
                response = super().create_policy(**values)
                response.pop('enforcementMode')
                return response

        candidate, registration = candidate_fixture()
        publisher = CustomerPolicyPublisher(OptionalModeResponseControl(),
            MemoryStore(), ProbeDouble(), registration,
            lambda: '2026-09-13T17:30:00+00:00', sleep=lambda _: None)
        result = publisher.publish(candidate)
        self.assertEqual(result['status'], 'VERIFIED')

    def test_optional_readback_mode_is_proved_by_exact_input_and_canary(self):
        class OptionalModeReadbackControl(PolicyControl):
            def get_policy(self, **values):
                response = super().get_policy(**values)
                response.pop('enforcementMode')
                return response

        candidate, registration = candidate_fixture()
        publisher = CustomerPolicyPublisher(OptionalModeReadbackControl(),
            MemoryStore(), ProbeDouble(), registration,
            lambda: '2026-09-13T17:30:00+00:00', sleep=lambda _: None)
        result = publisher.publish(candidate)
        self.assertEqual(result['status'], 'VERIFIED')

    def test_log_only_readback_is_never_accepted_as_active_authority(self):
        class LogOnlyReadbackControl(PolicyControl):
            def get_policy(self, **values):
                response = super().get_policy(**values)
                response['enforcementMode'] = 'LOG_ONLY'
                return response

        candidate, registration = candidate_fixture()
        publisher = CustomerPolicyPublisher(LogOnlyReadbackControl(),
            MemoryStore(), ProbeDouble(), registration,
            lambda: '2026-09-13T17:30:00+00:00', sleep=lambda _: None)
        with self.assertRaisesRegex(ValueError,
                'Owned candidate Policy readback differs'):
            publisher.publish(candidate)

    def test_invocation_probe_uses_pinned_agentcore_shapes_and_policy_denial(self):
        registration = vendor_registration()
        binding = registration['runtime']
        control = boto3.client('bedrock-agentcore-control',
            region_name='ap-northeast-1', aws_access_key_id='LOCAL',
            aws_secret_access_key='LOCAL_TEST_ONLY')
        runtime = boto3.client('bedrock-agentcore', region_name='ap-northeast-1',
            aws_access_key_id='LOCAL', aws_secret_access_key='LOCAL_TEST_ONLY')
        endpoint = {'createdAt': '2026-09-09T00:00:00Z',
            'lastUpdatedAt': '2026-09-09T00:00:01Z',
            'liveVersion': binding['runtime_version'],
            'agentRuntimeEndpointArn': binding['endpoint_arn'],
            'agentRuntimeArn': binding['runtime_arn'], 'status': 'READY',
            'name': binding['endpoint_name'], 'id': binding['endpoint_name'],
            'ResponseMetadata': {'HTTPStatusCode': 200,
                                 'RequestId': 'endpoint-request'}}
        request_id = registration['profiles']['MAINTAIN']['expected_outcomes'][0]['request_id']
        mcp_id = 'mcp-policy-deny'
        denial = {'http_status': 403,
            'headers': {'x-amzn-requestid': 'gateway-request'},
            'body': {'jsonrpc': '2.0', 'id': mcp_id,
                'error': {'code': -32002,
                    'message': 'Tool Execution Denied: Tool call not allowed due to policy enforcement'}}}
        body = {'result': 'OBSERVED', 'release_id': binding['release_id'],
            'request_registry_snapshot_hash': registration['request_registry_snapshot_hash'],
            'operation': 'invoke_tool', 'request_id': request_id,
            'tool': registration['target_name'] + '___prepare_vendor_payment',
            'mcp_id': mcp_id, 'gateway_response': denial,
            'identity': {'account': registration['target_account_id'],
                'arn': 'arn:aws:sts::111122223333:assumed-role/authority-delta-vendor-v2-runtime/canary',
                'request_id': 'sts-request'}}
        raw = encode(body)
        invoke = {'agentRuntimeArn': binding['runtime_arn'],
            'qualifier': binding['endpoint_name'], 'runtimeSessionId': ANY,
            'contentType': 'application/json', 'accept': 'application/json',
            'payload': encode({'operation': 'invoke_tool',
                'tool': 'prepare_vendor_payment', 'request_id': request_id})}
        with Stubber(control) as controls, Stubber(runtime) as runtimes:
            controls.add_response('get_agent_runtime_endpoint', endpoint,
                {'agentRuntimeId': binding['runtime_id'],
                 'endpointName': binding['endpoint_name']})
            runtimes.add_response('invoke_agent_runtime', {'statusCode': 200,
                'contentType': 'application/json',
                'response': StreamingBody(io.BytesIO(raw), len(raw)),
                'ResponseMetadata': {'HTTPStatusCode': 200,
                                     'RequestId': 'runtime-request'}}, invoke)
            controls.add_response('get_agent_runtime_endpoint', endpoint,
                {'agentRuntimeId': binding['runtime_id'],
                 'endpointName': binding['endpoint_name']})
            runtimes.add_response('stop_runtime_session', {
                'runtimeSessionId': 'stopped', 'statusCode': 200},
                {'agentRuntimeArn': binding['runtime_arn'],
                 'qualifier': binding['endpoint_name'], 'runtimeSessionId': ANY,
                 'clientToken': ANY})
            evidence = VendorPaymentInvocationProbe(control, runtime,
                EvidenceDouble(), registration, sleep=lambda _: None).run(
                    request_id, 'DENY')
            self.assertEqual(evidence['outcome'], 'DENY')
            self.assertEqual(evidence['request_id'], request_id)
            self.assertEqual(evidence['runtime_request_id'], 'runtime-request')
            controls.assert_no_pending_responses()
            runtimes.assert_no_pending_responses()

    def test_lambda_canary_accepts_actual_probe_contract_and_rejects_missing_id(self):
        registration = vendor_registration()
        request_id = registration['profiles']['MAINTAIN'][
            'expected_outcomes'][0]['request_id']
        client = LambdaDouble({'request_id': request_id, 'outcome': 'DENY'})
        result = LambdaCanaryProbe(client, registration).run(request_id, 'DENY')
        self.assertEqual(result['request_id'], request_id)
        self.assertEqual(result['canary_invocation']['request_id'],
                         'publisher-request')
        with self.assertRaisesRegex(ValueError, 'Canary Lambda result differs'):
            LambdaCanaryProbe(LambdaDouble({'outcome': 'DENY'}), registration).run(
                request_id, 'DENY')

    def test_lost_create_response_reconciles_same_token(self):
        candidate, registration = candidate_fixture()
        control = PolicyControl(lose_first=True)
        publisher = CustomerPolicyPublisher(control, MemoryStore(), ProbeDouble(),
            registration, lambda: '2026-09-09T00:01:00+00:00', sleep=lambda _: None)
        with self.assertRaises(TimeoutError):
            publisher.publish(candidate)
        result = publisher.reconcile(candidate)
        self.assertEqual(result['status'], 'VERIFIED')
        self.assertEqual(len(control.tokens), 1)
        self.assertEqual(len(set(control.tokens)), 1)
        row = publisher.journal.get(
            'publisher', candidate['enforcement_digest'], 'STATE').value
        self.assertEqual(row['policy_create_recovery']['method'],
                         'EXACT_NAME_DISCOVERY_THEN_FULL_READBACK')

    def test_superseded_lost_create_is_discovered_and_closed_without_recreate(self):
        candidate, registration = candidate_fixture()
        control = PolicyControl(lose_first=True)
        publisher = CustomerPolicyPublisher(control, MemoryStore(), ProbeDouble(),
            registration, lambda: '2026-09-09T00:01:00+00:00', sleep=lambda _: None)
        with self.assertRaises(TimeoutError):
            publisher.publish(candidate)
        result = publisher.reconcile(candidate, require_closed=True)
        self.assertEqual(result['status'], 'RECOVERED_CLOSED')
        self.assertEqual(len(control.tokens), 1)
        self.assertEqual(control.deleted, ['policy-customer-1'])

    def test_failed_candidate_is_deleted_and_recovered_closed(self):
        candidate, registration = candidate_fixture()
        control = PolicyControl()
        publisher = CustomerPolicyPublisher(control, MemoryStore(),
            ProbeDouble(fail_allow=True), registration,
            lambda: '2026-09-09T00:01:00+00:00', sleep=lambda _: None)
        result = publisher.publish(candidate)
        self.assertEqual(result['status'], 'RECOVERED_CLOSED')
        self.assertEqual(control.deleted, ['policy-customer-1'])
        self.assertTrue(all(item['outcome'] == 'DENY'
                            for item in result['outcomes']))

    def test_templates_separate_application_policy_and_runtime_authority(self):
        from build_business_template import build as business_template
        from build_customer_publisher_template import build as customer_template
        business = business_template()
        worker = json.dumps(business['Resources']['ApplicationWorkerRole'])
        self.assertIn('sts:AssumeRole', worker)
        self.assertNotIn('CreatePolicy', worker)
        self.assertNotIn('InvokeAgentRuntime', worker)
        customer = customer_template()
        self.assertGreater(PUBLISHER_FENCE_SECONDS,
            customer['Resources']['PublisherFunction']['Properties']['Timeout'])
        self.assertGreater(
            business['Resources']['ApplicationWorkerFunction']['Properties']['Timeout'],
            customer['Resources']['PublisherFunction']['Properties']['Timeout'])
        self.assertGreater(
            business['Resources']['ApplicationQueue']['Properties']['VisibilityTimeout'],
            business['Resources']['ApplicationWorkerFunction']['Properties']['Timeout'])
        publisher = json.dumps(customer['Resources']['PublisherRole'])
        canary = json.dumps(customer['Resources']['CanaryRole'])
        application = json.dumps(business['Resources']['ApplicationWorkerRole'])
        self.assertIn('sts:AssumeRole', application)
        self.assertNotIn('lambda:InvokeFunction', application)
        self.assertIn('CreatePolicy', publisher)
        self.assertNotIn('InvokeAgentRuntime', publisher)
        self.assertIn('InvokeAgentRuntime', canary)
        self.assertNotIn('CreatePolicy', canary)
        invocation = json.dumps(customer['Resources']['InvocationRole'])
        self.assertIn('PublisherJournal', invocation)
        self.assertIn('InvokeAgentRuntime', invocation)
        discovery = json.dumps(customer['Resources']['DiscoveryRole'])
        invoke = json.dumps(customer['Resources']['PublishInvokeRole'])
        self.assertIn('sts:ExternalId', discovery)
        self.assertNotIn('CreatePolicy', discovery)
        self.assertIn('lambda:InvokeFunction', invoke)
        self.assertNotIn('GetAgentRuntime', invoke)

    def test_registry_builder_derives_profiles_and_rejects_account_a(self):
        from build_customer_adapter_registry import build
        source = vendor_registration()
        observed = {'schema_version': '1.0',
            'source_authority': 'aws:observed-binding-report-version-1',
            'connection_id': source['connection_id'],
            'target_account_id': source['target_account_id'],
            'target_region': source['target_region'],
            'gateway_arn': source['gateway_arn'], 'gateway_id': source['gateway_id'],
            'policy_engine_id': source['policy_engine_id'],
            'target_id': source['target_id'], 'target_name': source['target_name'],
            'runtime': source['runtime'],
            'discovery_role_arn': source['discovery_binding']['role_arn'],
            'publisher_invoke_role_arn': source['publisher_binding']['invoke_role_arn'],
            'external_id': source['publisher_binding']['external_id'],
            'publisher_function_arn': source['publisher_binding']['function_arn'],
            'runtime_invoke_role_arn': source['invocation_binding']['invoke_role_arn'],
            'invocation_function_arn': source['invocation_binding']['function_arn'],
            'canary_function_arn': source['probe_binding']['function_arn'],
            'request_registry_table_name': source['probe_binding']['request_registry_table_name'],
            'sandbox_ledger_table_name': source['probe_binding']['sandbox_ledger_table_name']}
        result = build(observed)
        self.assertEqual(len(result['registrations']), 1)
        self.assertEqual(set(result['registrations'][0]['profiles']),
                         {'MAINTAIN', 'NARROW'})
        changed = dict(observed, target_account_id='538522204923')
        with self.assertRaises(ValueError):
            build(changed)


if __name__ == '__main__':
    unittest.main()
