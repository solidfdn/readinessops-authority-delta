"""Account-B limited Policy publisher and VendorPayment canary probe.

Only a packaged LIVE_CUSTOMER registration is accepted.  The publisher owns
policies whose names are derived from an immutable candidate, journals every
phase before the next cloud mutation, and returns terminal evidence only after
control-plane readback plus the real Gateway/ledger canary.
"""
from __future__ import annotations

import copy
import json
import time
import uuid
from datetime import datetime, timedelta

from authority_delta.canonical import sha256_json
from authority_delta.cedar import assert_observed_role_matches
from authority_delta.execution_evidence import validate_execution_evidence
from authority_delta.gateway_probe import policy_denial
from authority_delta.adapters.vendor_payment_policy import compile_payment_permit
from .delegation import verify_registration
from .revocation import verify_revocation_request
from .storage import Conflict, encode


TERMINAL = ('VERIFIED', 'RECOVERED_CLOSED')
REVOCATION_STATES = ('STOP_REQUESTED', 'POLICY_DELETE_INTENT',
                     'POLICY_ABSENT', 'SUSPENDED_CONFIRMED')
PUBLISHER_FENCE_SECONDS = 720
FAILED_POLICY_TARGET_DISCOVERY_RECOVERIES = 1


def _missing(exc):
    return getattr(exc, 'response', {}).get('Error', {}).get('Code') in (
        'ResourceNotFoundException', 'NotFoundException')


def _policy_delete_evidence(response, policy_engine_id, policy_id):
    """Validate the pinned AgentCore DeletePolicy HTTP 202 contract."""
    metadata = response.get('ResponseMetadata', {})
    if (metadata.get('HTTPStatusCode') != 202
            or not metadata.get('RequestId')
            or response.get('policyEngineId') != policy_engine_id
            or response.get('policyId') != policy_id
            or response.get('status') != 'DELETING'):
        raise ValueError('Policy delete lacks successful AWS evidence')
    return {'policy_id': policy_id, 'policy_engine_id': policy_engine_id,
            'status': response['status'],
            'request_id': metadata['RequestId'], 'http_status': 202}


def _policy_create_evidence(response, policy_engine_id, policy_name,
                            policy_statement):
    """Validate the pinned AgentCore CreatePolicy HTTP 202 contract."""
    metadata = response.get('ResponseMetadata', {})
    policy_id = response.get('policyId')
    if (metadata.get('HTTPStatusCode') != 202
            or not metadata.get('RequestId')
            or not isinstance(policy_id, str) or not policy_id
            or response.get('policyEngineId') != policy_engine_id
            or response.get('name') != policy_name
            or response.get('status') not in ('CREATING', 'ACTIVE')
            or (response.get('enforcementMode') is not None
                and response.get('enforcementMode') != 'ACTIVE')
            or response.get('definition', {}).get('cedar', {}).get('statement')
                != policy_statement):
        raise ValueError('Policy create lacks successful AWS evidence')
    return {'policy_id': policy_id, 'policy_engine_id': policy_engine_id,
            'policy_name': policy_name, 'status': response['status'],
            'request_id': metadata['RequestId'], 'http_status': 202}


def verify_customer_candidate(candidate, registration):
    registration = verify_registration(registration)
    if registration['connection_mode'] != 'LIVE_CUSTOMER':
        raise ValueError('Customer publisher requires a live customer registration')
    if not isinstance(candidate, dict) or candidate.get('kind') != 'ENFORCEMENT_CANDIDATE':
        raise ValueError('Publisher candidate is invalid')
    digest = candidate.get('enforcement_digest')
    unsigned = {k: copy.deepcopy(v) for k, v in candidate.items()
                if k != 'enforcement_digest'}
    if not isinstance(digest, str) or sha256_json(unsigned) != digest:
        raise ValueError('Publisher candidate digest differs')
    expected = {
        'adapter_id': registration['adapter_id'],
        'adapter_version': registration['adapter_version'],
        'adapter_registration_hash': registration['registration_hash'],
        'connection_id': registration['connection_id'],
        'connection_mode': registration['connection_mode'],
        'publisher_binding': registration['publisher_binding'],
        'invocation_binding': registration['invocation_binding'],
        'probe_binding': registration['probe_binding'],
    }
    if any(candidate.get(key) != value for key, value in expected.items()):
        raise ValueError('Publisher candidate differs from the packaged registration')
    execution = candidate.get('execution_binding', {})
    if execution != {
        'target_account_id': registration['target_account_id'],
        'target_region': registration['target_region'],
        'gateway_arn': registration['gateway_arn'],
        'gateway_id': registration['gateway_id'],
        'policy_engine_id': registration['policy_engine_id'],
        'target_id': registration['target_id'],
        'target_name': registration['target_name'],
        'runtime': registration['runtime'],
        'request_registry_snapshot_hash': registration['request_registry_snapshot_hash'],
    }:
        raise ValueError('Publisher execution binding differs')
    profile = registration['profiles'].get(candidate.get('profile_id'))
    if profile is None or candidate.get('expected_outcomes') != profile['expected_outcomes']:
        raise ValueError('Publisher canary plan is not registered')
    expected_policy = compile_payment_permit(
        gateway_arn=registration['gateway_arn'],
        role_arn=registration['runtime']['execution_role_arn'],
        allowed_request_ids=profile['allowed_request_ids'],
        request_registry_snapshot_hash=registration['request_registry_snapshot_hash'],
        target_name=registration['target_name'])
    if candidate.get('policy_binding') != expected_policy:
        raise ValueError('Publisher policy binding differs')
    previous = candidate.get('previous_applied_binding')
    if previous and (previous.get('connection_id') != registration['connection_id']
            or not previous.get('policy_id')
            or previous.get('execution_binding', {}).get('policy_engine_id')
                != registration['policy_engine_id']):
        raise ValueError('Previous AppliedBinding is not owned by this connection')
    # A prior policy for the same runtime can affect DENY canaries.  Do not
    # pretend the candidate was isolated; a later migration design must bind a
    # distinct runtime or explicitly suspend and restore the prior policy.
    if previous and previous.get('execution_binding', {}).get('runtime') == registration['runtime']:
        raise ValueError('Previous policy overlaps the candidate canary runtime')
    return copy.deepcopy(candidate)


def verified_invocation_candidate(journal, application_id, enforcement_digest,
                                  registration):
    """Load the exact account-B journal entry that still owns active authority."""
    row = journal.get('publisher', enforcement_digest, 'STATE')
    if row is None:
        raise ValueError('Controlled invocation has no account-B publisher record')
    candidate = verify_customer_candidate(row.value.get('candidate'), registration)
    result = row.value.get('result')
    if (row.value.get('status') != 'VERIFIED'
            or candidate.get('application_id') != application_id
            or candidate.get('enforcement_digest') != enforcement_digest
            or not isinstance(result, dict)
            or result.get('status') != 'VERIFIED'
            or result.get('application_id') != application_id
            or result.get('enforcement_digest') != enforcement_digest):
        raise ValueError('Controlled invocation is not bound to active account-B authority')
    return candidate


class PublisherInvocationFence:
    """Prevent overlapping account-B publisher/revocation workers.

    The lease exceeds the publisher Lambda's hard timeout. A process killed at
    timeout therefore cannot overlap the recovery invocation that takes over.
    """

    def __init__(self, journal, clock):
        self.journal, self.clock = journal, clock

    def claim(self, enforcement_digest, owner):
        if (not isinstance(owner, str) or not owner
                or not isinstance(enforcement_digest, str)
                or len(enforcement_digest) != 64):
            raise ValueError('Publisher invocation fence identity is invalid')
        now = datetime.fromisoformat(self.clock())
        row = self.journal.get('publisher', enforcement_digest, 'WORKER_FENCE')
        if row is not None and now < datetime.fromisoformat(row.value['lease_until']):
            raise ValueError('Another account-B publisher invocation is still active')
        value = {'schema_version': '1.0', 'owner': owner,
            'claimed_at': now.isoformat(),
            'lease_until': (now + timedelta(seconds=PUBLISHER_FENCE_SECONDS)).isoformat()}
        try:
            self.journal.transact([('publisher', enforcement_digest,
                'WORKER_FENCE', value, row.version if row else None)])
        except Conflict as exc:
            raise ValueError('Another account-B publisher invocation won the fence') from exc
        return value

    def release(self, enforcement_digest, owner):
        row = self.journal.get('publisher', enforcement_digest, 'WORKER_FENCE')
        if row is None or row.value.get('owner') != owner:
            return False
        try:
            self.journal.transact([('publisher', enforcement_digest,
                'WORKER_FENCE', None, row.version)])
        except Conflict:
            return False
        return True


class DynamoCanaryEvidence:
    def __init__(self, client, registration):
        self.client = client
        self.registration = verify_registration(registration)

    def registry_request(self, request_id):
        table = self.registration['probe_binding']['request_registry_table_name']
        response = self.client.get_item(TableName=table,
            Key={'request_id': {'S': request_id}}, ConsistentRead=True)
        item = response.get('Item')
        if (not isinstance(item, dict)
                or set(item) != {'request_id', 'payload', 'fixture_snapshot_hash'}
                or item.get('request_id') != {'S': request_id}
                or item.get('fixture_snapshot_hash') != {
                    'S': self.registration['request_registry_snapshot_hash']}
                or set(item.get('payload', {})) != {'S'}):
            raise ValueError('Canary request registry read differs')
        value = json.loads(item['payload']['S'])
        if 'fixture_dataset_id' not in value or 'action' not in value:
            raise ValueError('Canary request is incomplete')
        return value

    def ledger(self):
        table = self.registration['probe_binding']['sandbox_ledger_table_name']
        items, args = [], {'TableName': table, 'ConsistentRead': True}
        while True:
            response = self.client.scan(**args)
            items.extend(response.get('Items', []))
            key = response.get('LastEvaluatedKey')
            if not key:
                return items
            args['ExclusiveStartKey'] = key


class VendorPaymentInvocationProbe:
    def __init__(self, control, runtime, evidence, registration, sleep=time.sleep):
        self.control, self.runtime, self.evidence = control, runtime, evidence
        self.registration = verify_registration(registration)
        self.sleep = sleep

    def endpoint(self):
        runtime = self.registration['runtime']
        response = self.control.get_agent_runtime_endpoint(
            agentRuntimeId=runtime['runtime_id'], endpointName=runtime['endpoint_name'])
        expected = {'status': 'READY', 'liveVersion': runtime['runtime_version'],
            'agentRuntimeArn': runtime['runtime_arn'],
            'agentRuntimeEndpointArn': runtime['endpoint_arn'],
            'name': runtime['endpoint_name']}
        metadata = response.get('ResponseMetadata', {})
        if (any(response.get(k) != v for k, v in expected.items())
                or response.get('targetVersion', runtime['runtime_version'])
                    != runtime['runtime_version']
                or metadata.get('HTTPStatusCode') != 200
                or not metadata.get('RequestId')):
            raise ValueError('Canary runtime endpoint differs')
        return {'request_id': metadata['RequestId'],
                'endpoint_arn': runtime['endpoint_arn'],
                'live_version': response['liveVersion']}

    def run(self, request_id, expected_outcome):
        registration, binding = self.registration, self.registration['runtime']
        request = self.evidence.registry_request(request_id)
        before = self.evidence.ledger()
        endpoint_before = self.endpoint()
        session_id = 'readinessops-canary-' + uuid.uuid4().hex
        response = None
        try:
            for attempt in range(4):
                try:
                    response = self.runtime.invoke_agent_runtime(
                        agentRuntimeArn=binding['runtime_arn'],
                        qualifier=binding['endpoint_name'], runtimeSessionId=session_id,
                        contentType='application/json', accept='application/json',
                        payload=encode({'operation': 'invoke_tool',
                            'tool': 'prepare_vendor_payment', 'request_id': request_id}))
                    break
                except Exception as exc:
                    if (getattr(exc, 'response', {}).get('Error', {}).get('Code')
                            != 'RetryableConflictException' or attempt == 3):
                        raise
                    self.sleep(2 ** attempt)
            stream = response['response']
            try:
                raw = stream.read(262145)
            finally:
                stream.close()
            metadata = response.get('ResponseMetadata', {})
            if (len(raw) > 262144 or response.get('statusCode') != 200
                    or metadata.get('HTTPStatusCode') != 200
                    or not metadata.get('RequestId')):
                raise ValueError('Canary runtime response could not be verified')
            body = json.loads(raw)
            identity = body.get('identity', {})
            if (body.get('result') != 'OBSERVED'
                    or body.get('release_id') != binding['release_id']
                    or body.get('request_registry_snapshot_hash')
                        != registration['request_registry_snapshot_hash']
                    or body.get('operation') != 'invoke_tool'
                    or body.get('request_id') != request_id
                    or body.get('tool') != registration['target_name']
                        + '___prepare_vendor_payment'
                    or identity.get('account') != registration['target_account_id']
                    or not identity.get('request_id')):
                raise ValueError('Canary runtime returned inconsistent bindings')
            principal = assert_observed_role_matches(
                binding['execution_role_arn'], identity.get('arn', ''))
            endpoint_after = self.endpoint()
            after = self.evidence.ledger()
            common = {'request_id': request_id,
                'runtime_request_id': metadata['RequestId'],
                'runtime_session_id': session_id, 'principal': principal,
                'endpoint_before': endpoint_before, 'endpoint_after': endpoint_after,
                'gateway_response': body.get('gateway_response'),
                'mcp_id': body.get('mcp_id')}
            if expected_outcome == 'DENY':
                if (not policy_denial(body.get('gateway_response', {}), body.get('mcp_id'))
                        or sha256_json(before) != sha256_json(after)):
                    raise ValueError('Canary did not prove Policy DENY with unchanged ledger')
                return {**common, 'outcome': 'DENY',
                    'before_ledger_hash': sha256_json(before),
                    'after_ledger_hash': sha256_json(after)}
            if expected_outcome != 'ALLOW':
                raise ValueError('Canary expected outcome is invalid')
            business_key = '#'.join((registration['connection_id'],
                                     request['fixture_dataset_id'], request_id))
            verified = validate_execution_evidence(body['gateway_response'],
                mcp_id=body['mcp_id'], request_id=request_id,
                business_key=business_key, gateway_id=registration['gateway_id'],
                target_id=registration['target_id'], before_items=before,
                after_items=after)
            return {**common, 'outcome': 'ALLOW', 'execution': verified}
        finally:
            try:
                self.runtime.stop_runtime_session(agentRuntimeArn=binding['runtime_arn'],
                    qualifier=binding['endpoint_name'], runtimeSessionId=session_id,
                    clientToken=str(uuid.uuid5(uuid.NAMESPACE_URL, session_id)))
            except Exception:
                pass


class LambdaCanaryProbe:
    """Invoke only the qualified canary Lambda; the publisher has no Runtime access."""

    def __init__(self, client, registration):
        self.client = client
        self.registration = verify_registration(registration)

    def run(self, request_id, expected_outcome):
        function_arn = self.registration['probe_binding']['function_arn']
        payload = encode({'schema_version': '1.0', 'request_id': request_id,
                          'expected_outcome': expected_outcome,
                          'registration_hash': self.registration['registration_hash']})
        response = self.client.invoke(FunctionName=function_arn,
            InvocationType='RequestResponse', Payload=payload)
        stream = response.get('Payload')
        if stream is None:
            raise ValueError('Canary invocation has no response stream')
        try:
            raw = stream.read(500_001)
        finally:
            stream.close()
        metadata = response.get('ResponseMetadata', {})
        if (len(raw) > 500_000 or response.get('StatusCode') != 200
                or metadata.get('HTTPStatusCode') != 200
                or not metadata.get('RequestId') or response.get('FunctionError')):
            raise ValueError('Canary Lambda invocation could not be confirmed')
        value = json.loads(raw)
        if (not isinstance(value, dict) or value.get('request_id') != request_id
                or value.get('outcome') != expected_outcome):
            raise ValueError('Canary Lambda result differs')
        value['canary_invocation'] = {'function_arn': function_arn,
            'request_id': metadata['RequestId'], 'http_status': response['StatusCode'],
            'executed_version': response.get('ExecutedVersion')
                or function_arn.rsplit(':', 1)[1]}
        return value


class CustomerPolicyPublisher:
    def __init__(self, control, journal, probe, registration, clock, sleep=time.sleep):
        self.control, self.journal, self.probe = control, journal, probe
        self.registration = verify_registration(registration)
        self.clock, self.sleep = clock, sleep

    def _key(self, candidate):
        return candidate['enforcement_digest'], 'STATE'

    def _read(self, candidate):
        return self.journal.get('publisher', *self._key(candidate))

    def _write(self, candidate, value, version):
        self.journal.transact([('publisher', *self._key(candidate), value, version)])
        return self._read(candidate)

    def _prepare(self, candidate):
        row = self._read(candidate)
        if row is not None:
            if row.value.get('candidate') != candidate:
                raise ValueError('Publisher journal candidate differs')
            return row
        value = {'schema_version': '1.0', 'status': 'PREPARED',
            'candidate': candidate, 'policy_id': None,
            'policy_name': 'AuthorityDeltaApp_' + candidate['enforcement_digest'][:16],
            'client_token': str(uuid.UUID(candidate['enforcement_digest'][:32])),
            'closed_evidence': None, 'outcome_evidence': None,
            'result': None, 'updated_at': self.clock()}
        if len(encode(value)) > 300_000:
            raise ValueError('Publisher journal candidate exceeds its bounded size')
        try:
            return self._write(candidate, value, None)
        except Conflict:
            return self._read(candidate)

    def _probe_all(self, candidate, closed):
        evidence = []
        for item in sorted(candidate['expected_outcomes'], key=lambda x: x['request_id']):
            expected = 'DENY' if closed else item['expected_outcome']
            observed = self.probe.run(item['request_id'], expected)
            evidence.append({'request_id': item['request_id'],
                'outcome': observed['outcome'], 'evidence_hash': sha256_json(observed),
                'evidence': observed})
        return evidence

    def _owned_policy(self, row):
        candidate = row.value['candidate']
        expected = candidate['policy_binding']['statement']
        policy = self.control.get_policy(
            policyEngineId=self.registration['policy_engine_id'],
            policyId=row.value['policy_id'])
        if (policy.get('policyEngineId') != self.registration['policy_engine_id']
                or policy.get('policyId') != row.value['policy_id']
                or policy.get('name') != row.value['policy_name']
                or (policy.get('enforcementMode') is not None
                    and policy.get('enforcementMode') != 'ACTIVE')
                or policy.get('definition', {}).get('cedar', {}).get('statement') != expected
                or policy.get('ResponseMetadata', {}).get('HTTPStatusCode') != 200
                or not policy.get('ResponseMetadata', {}).get('RequestId')):
            raise ValueError('Owned candidate Policy readback differs')
        return policy

    def _policy(self, row):
        for _ in range(24):
            policy = self._owned_policy(row)
            if policy.get('status') == 'ACTIVE':
                return policy
            if policy.get('status') in ('CREATE_FAILED', 'UPDATE_FAILED', 'DELETE_FAILED'):
                raise ValueError('Owned candidate Policy entered a failed state')
            self.sleep(5)
        raise ValueError('Owned candidate Policy did not become active')

    def _recover_failed_target_discovery_policy(self, row):
        """Delete only the exact failed candidate, re-prove DENY, and rekey once."""
        if (row.value.get('status') not in (
                'POLICY_CREATED', 'FAILED_POLICY_DELETE_INTENT')
                or row.value.get('failed_policy_target_discovery_recoveries', 0)
                    >= FAILED_POLICY_TARGET_DISCOVERY_RECOVERIES):
            return row
        expected_reason = ('Insufficient permissions to list targets on gateway with ID '
                           + self.registration['gateway_id'])
        evidence = copy.deepcopy(
            row.value.get('failed_policy_target_discovery_evidence'))
        absent = False
        try:
            policy = self._owned_policy(row)
        except Exception as exc:
            if not _missing(exc):
                raise
            policy, absent = None, True
            evidence = evidence or {'delete_requested': True,
                'delete_response_reconciled_from_absence': True}
        if policy is not None:
            if (policy.get('status') == 'CREATE_FAILED'
                    and policy.get('statusReasons') == [expected_reason]):
                if row.value['status'] == 'POLICY_CREATED':
                    evidence = {'policy_id': row.value['policy_id'],
                        'status': policy['status'],
                        'status_reasons': policy['statusReasons'],
                        'read_request_id': policy['ResponseMetadata']['RequestId'],
                        'delete_requested': True, 'delete_response': None}
                    row = self._write(row.value['candidate'], dict(row.value,
                        status='FAILED_POLICY_DELETE_INTENT',
                        failed_policy_target_discovery_evidence=evidence,
                        updated_at=self.clock()), row.version)
                response = self.control.delete_policy(
                    policyEngineId=self.registration['policy_engine_id'],
                    policyId=row.value['policy_id'])
                evidence['delete_response'] = _policy_delete_evidence(
                    response, self.registration['policy_engine_id'],
                    row.value['policy_id'])
                row = self._write(row.value['candidate'], dict(row.value,
                    failed_policy_target_discovery_evidence=evidence,
                    updated_at=self.clock()), row.version)
            elif (row.value['status'] == 'FAILED_POLICY_DELETE_INTENT'
                    and policy.get('status') == 'DELETING'):
                pass
            else:
                return row
        for _ in range(45):
            if absent:
                break
            try:
                self.control.get_policy(
                    policyEngineId=self.registration['policy_engine_id'],
                    policyId=row.value['policy_id'])
            except Exception as exc:
                if _missing(exc):
                    break
                raise
            self.sleep(2)
        else:
            raise ValueError('Failed candidate Policy deletion was not confirmed')
        closed = self._probe_all(row.value['candidate'], True)
        next_token = str(uuid.uuid5(uuid.UUID(row.value['client_token']),
                                    'gateway-target-discovery-recovery-v1'))
        evidence = dict(evidence or {}, policy_absent_readback=True)
        return self._write(row.value['candidate'], dict(row.value,
            status='CLOSED_PROVEN', policy_id=None, client_token=next_token,
            closed_evidence=closed, outcome_evidence=None, result=None,
            failed_policy_target_discovery_recoveries=
                row.value.get('failed_policy_target_discovery_recoveries', 0) + 1,
            failed_policy_target_discovery_evidence=evidence,
            updated_at=self.clock()), row.version)

    def _delete(self, row):
        if not row.value.get('policy_id'):
            return
        try:
            self._policy(row)
        except Exception as exc:
            if _missing(exc):
                return
            raise
        response = self.control.delete_policy(
            policyEngineId=self.registration['policy_engine_id'],
            policyId=row.value['policy_id'])
        _policy_delete_evidence(response, self.registration['policy_engine_id'],
                                row.value['policy_id'])
        for _ in range(60):
            try:
                self.control.get_policy(policyEngineId=self.registration['policy_engine_id'],
                                        policyId=row.value['policy_id'])
            except Exception as exc:
                if _missing(exc):
                    return
                raise
            self.sleep(2)
        raise ValueError('Candidate Policy deletion was not confirmed')

    def _find_owned(self, row):
        matches, args = [], {'policyEngineId': self.registration['policy_engine_id'],
                             'maxResults': 100}
        while True:
            response = self.control.list_policies(**args)
            metadata = response.get('ResponseMetadata', {})
            if (metadata.get('HTTPStatusCode') != 200
                    or not metadata.get('RequestId')):
                raise ValueError('Policy list lacks successful AWS evidence')
            matches.extend(item for item in response.get('policies', [])
                           if item.get('name') == row.value['policy_name'])
            token = response.get('nextToken')
            if not token:
                break
            args['nextToken'] = token
        if len(matches) > 1:
            raise ValueError('Owned candidate Policy name is ambiguous')
        return matches[0].get('policyId') if matches else None

    def _result(self, row, status, closed, outcomes):
        candidate = row.value['candidate']
        previous = candidate.get('previous_applied_binding')
        result = {'schema_version': '1.0', 'status': status,
            'application_id': candidate['application_id'],
            'enforcement_digest': candidate['enforcement_digest'],
            'policy_id': row.value.get('policy_id') or 'closed-' + candidate['enforcement_digest'][:24],
            'policy_name': row.value['policy_name'],
            'policy_hash': candidate['policy_binding']['policy_hash'],
            'observed_at': self.clock(),
            'checks': {'candidate_closed_before_write': bool(closed),
                'policy_active_readback': status == 'VERIFIED',
                'same_runtime_role_policy_for_canary': status == 'VERIFIED',
                'candidate_cleanup_readback': status == 'RECOVERED_CLOSED'},
            'previous_binding_status': ('RETIRED' if status == 'VERIFIED' and previous
                else 'PRESERVED' if status == 'RECOVERED_CLOSED' and previous else 'NONE'),
            'closed_outcomes': [{k: item[k] for k in ('request_id', 'outcome', 'evidence_hash')}
                                for item in closed],
            'outcomes': [{k: item[k] for k in ('request_id', 'outcome', 'evidence_hash')}
                         for item in outcomes]}
        return result

    def _previous_policy(self, candidate):
        previous = candidate.get('previous_applied_binding')
        if not previous:
            return None
        policy = self.control.get_policy(
            policyEngineId=self.registration['policy_engine_id'],
            policyId=previous['policy_id'])
        if (policy.get('policyEngineId') != self.registration['policy_engine_id']
                or policy.get('policyId') != previous['policy_id']
                or policy.get('name') != previous['policy_name']
                or policy.get('status') != 'ACTIVE'
                or (policy.get('enforcementMode') is not None
                    and policy.get('enforcementMode') != 'ACTIVE')
                or policy.get('definition', {}).get('cedar', {}).get('statement')
                    != previous['policy_binding']['statement']
                or policy.get('ResponseMetadata', {}).get('HTTPStatusCode') != 200
                or not policy.get('ResponseMetadata', {}).get('RequestId')):
            raise ValueError('Previous owned Policy readback differs')
        return policy

    def _retire_previous(self, row):
        candidate = row.value['candidate']
        previous = candidate.get('previous_applied_binding')
        if not previous:
            return self._write(candidate, dict(row.value,
                status='PREVIOUS_RETIRED', previous_retirement=None,
                updated_at=self.clock()), row.version)
        if row.value['status'] == 'CANDIDATE_VERIFIED':
            policy = self._previous_policy(candidate)
            intent = {'policy_id': previous['policy_id'],
                'policy_name': previous['policy_name'],
                'read_request_id': policy['ResponseMetadata']['RequestId'],
                'delete_requested': True, 'delete_request_id': None}
            row = self._write(candidate, dict(row.value,
                status='RETIRING_PREVIOUS', previous_retirement=intent,
                updated_at=self.clock()), row.version)
        intent = copy.deepcopy(row.value['previous_retirement'])
        try:
            self._previous_policy(candidate)
        except Exception as exc:
            if not _missing(exc) or not intent['delete_requested']:
                raise
        else:
            response = self.control.delete_policy(
                policyEngineId=self.registration['policy_engine_id'],
                policyId=previous['policy_id'])
            evidence = _policy_delete_evidence(response,
                self.registration['policy_engine_id'], previous['policy_id'])
            intent['delete_request_id'] = evidence['request_id']
            row = self._write(candidate, dict(row.value,
                previous_retirement=intent, updated_at=self.clock()), row.version)
        for _ in range(60):
            try:
                self.control.get_policy(policyEngineId=self.registration['policy_engine_id'],
                                        policyId=previous['policy_id'])
            except Exception as exc:
                if _missing(exc):
                    return self._write(candidate, dict(row.value,
                        status='PREVIOUS_RETIRED', updated_at=self.clock()), row.version)
                raise
            self.sleep(2)
        raise ValueError('Previous owned Policy retirement was not confirmed')

    def _recover_closed(self, row):
        candidate = row.value['candidate']
        if row.value['status'] in ('RETIRING_PREVIOUS', 'PREVIOUS_RETIRED'):
            raise ValueError('Previous Policy retirement requires verified reconciliation')
        if not row.value.get('policy_id'):
            policy_id = self._find_owned(row)
            if policy_id:
                row = self._write(candidate, dict(row.value,
                    status='POLICY_CREATED', policy_id=policy_id,
                    updated_at=self.clock()), row.version)
        self._delete(row)
        closed = self._probe_all(candidate, True)
        result = self._result(row, 'RECOVERED_CLOSED',
                              row.value.get('closed_evidence') or closed, closed)
        final = dict(row.value, status='RECOVERED_CLOSED', result=result,
                     outcome_evidence=closed, updated_at=self.clock())
        return self._write(candidate, final, row.version).value['result']

    def publish(self, candidate):
        candidate = verify_customer_candidate(candidate, self.registration)
        row = self._prepare(candidate)
        if row.value['status'] in REVOCATION_STATES:
            raise ValueError('Candidate publication is fenced by an authority revocation')
        if row.value['status'] in TERMINAL:
            return row.value['result']
        if row.value['status'] == 'PREPARED':
            closed = self._probe_all(candidate, True)
            row = self._write(candidate, dict(row.value, status='CLOSED_PROVEN',
                closed_evidence=closed, updated_at=self.clock()), row.version)
        if row.value['status'] in ('POLICY_CREATED',
                                    'FAILED_POLICY_DELETE_INTENT'):
            row = self._recover_failed_target_discovery_policy(row)
        if row.value['status'] == 'CLOSED_PROVEN':
            response = self.control.create_policy(
                policyEngineId=self.registration['policy_engine_id'],
                name=row.value['policy_name'],
                definition={'cedar': {'statement': candidate['policy_binding']['statement']}},
                validationMode='FAIL_ON_ANY_FINDINGS', enforcementMode='ACTIVE',
                description='READINESSOPS_VERIFIED_APPLICATION_CANDIDATE',
                clientToken=row.value['client_token'])
            evidence = _policy_create_evidence(response,
                self.registration['policy_engine_id'], row.value['policy_name'],
                candidate['policy_binding']['statement'])
            row = self._write(candidate, dict(row.value, status='POLICY_CREATED',
                policy_id=evidence['policy_id'], policy_create_evidence=evidence,
                updated_at=self.clock()), row.version)
        try:
            if row.value['status'] == 'POLICY_CREATED':
                self._policy(row)
                row = self._write(candidate, dict(row.value, status='POLICY_ACTIVE',
                    updated_at=self.clock()), row.version)
            if row.value['status'] == 'POLICY_ACTIVE':
                outcomes = self._probe_all(candidate, False)
                row = self._write(candidate, dict(row.value,
                    status='CANDIDATE_VERIFIED', outcome_evidence=outcomes,
                    updated_at=self.clock()), row.version)
            if row.value['status'] in ('CANDIDATE_VERIFIED', 'RETIRING_PREVIOUS'):
                row = self._retire_previous(row)
            outcomes = row.value['outcome_evidence']
            result = self._result(row, 'VERIFIED', row.value['closed_evidence'], outcomes)
            final = dict(row.value, status='VERIFIED', result=result,
                         outcome_evidence=outcomes, updated_at=self.clock())
            return self._write(candidate, final, row.version).value['result']
        except Exception:
            # A fully verified closed recovery is terminal.  Any uncertainty in
            # cleanup/probing propagates to account A as UNKNOWN with its lock held.
            return self._recover_closed(self._read(candidate))

    def reconcile(self, candidate, require_closed=False):
        candidate = verify_customer_candidate(candidate, self.registration)
        row = self._prepare(candidate)
        if row.value['status'] in REVOCATION_STATES:
            raise ValueError('Candidate reconciliation is fenced by an authority revocation')
        if row.value['status'] in TERMINAL:
            result = row.value['result']
            if require_closed and result['status'] != 'RECOVERED_CLOSED':
                if candidate.get('previous_applied_binding'):
                    raise ValueError('Retired previous Policy prevents closed reconciliation')
                return self._recover_closed(row)
            return result
        if require_closed:
            return self._recover_closed(row)
        # A successful asynchronous create may have returned before the journal
        # was written.  Recover the uniquely named Policy first, then prove its
        # complete identity through _policy().  Only an absent Policy permits a
        # same-token create retry, so recovery never depends on a second create
        # response and never creates duplicate authority.
        if row.value['status'] == 'CLOSED_PROVEN' and not row.value.get('policy_id'):
            policy_id = self._find_owned(row)
            if policy_id:
                row = self._write(candidate, dict(row.value,
                    status='POLICY_CREATED', policy_id=policy_id,
                    policy_create_recovery={
                        'method': 'EXACT_NAME_DISCOVERY_THEN_FULL_READBACK',
                        'policy_id': policy_id}, updated_at=self.clock()), row.version)
            else:
                response = self.control.create_policy(
                    policyEngineId=self.registration['policy_engine_id'],
                    name=row.value['policy_name'],
                    definition={'cedar': {'statement': candidate['policy_binding']['statement']}},
                    validationMode='FAIL_ON_ANY_FINDINGS', enforcementMode='ACTIVE',
                    description='READINESSOPS_VERIFIED_APPLICATION_CANDIDATE',
                    clientToken=row.value['client_token'])
                evidence = _policy_create_evidence(response,
                    self.registration['policy_engine_id'], row.value['policy_name'],
                    candidate['policy_binding']['statement'])
                row = self._write(candidate, dict(row.value, status='POLICY_CREATED',
                    policy_id=evidence['policy_id'], policy_create_evidence=evidence,
                    updated_at=self.clock()), row.version)
        return self.publish(candidate)

    def revoke(self, candidate, request):
        """Remove one exactly-owned verified Policy and prove the live DENY set.

        The delete intent is durably journaled before the AWS mutation.  A lost
        response is reconciled only against the same request and owned Policy.
        """
        candidate = verify_customer_candidate(candidate, self.registration)
        request = verify_revocation_request(request, candidate=candidate)
        row = self._read(candidate)
        if row is None or row.value.get('candidate') != candidate:
            raise ValueError('Revocation has no exact publisher journal candidate')
        if row.value['status'] == 'SUSPENDED_CONFIRMED':
            if row.value.get('revocation') != request:
                raise ValueError('Publisher journal is bound to another revocation')
            return row.value['revocation_result']
        if row.value['status'] not in ('VERIFIED', 'STOP_REQUESTED',
                                       'POLICY_DELETE_INTENT', 'POLICY_ABSENT'):
            raise ValueError('Only a verified applied candidate can be revoked')
        publication_result = row.value.get('result')
        if (not isinstance(publication_result, dict)
                or publication_result.get('status') != 'VERIFIED'
                or any(publication_result.get(k) != request[k]
                       for k in ('policy_id', 'policy_name', 'policy_hash'))):
            raise ValueError('Revocation differs from the verified publisher result')
        if row.value['status'] == 'VERIFIED':
            row = self._write(candidate, dict(row.value, status='STOP_REQUESTED',
                revocation=request, revocation_checks={
                    'owned_policy_readback': False,
                    'delete_intent_journaled': False,
                    'policy_absent_readback': False},
                delete_evidence=None, revocation_outcomes=None,
                revocation_result=None, updated_at=self.clock()), row.version)
        elif row.value.get('revocation') != request:
            raise ValueError('Publisher journal is bound to another revocation')

        if row.value['status'] == 'STOP_REQUESTED':
            policy = self._policy(row)
            read_id = policy['ResponseMetadata']['RequestId']
            checks = dict(row.value['revocation_checks'],
                          owned_policy_readback=True,
                          delete_intent_journaled=True)
            row = self._write(candidate, dict(row.value,
                status='POLICY_DELETE_INTENT', revocation_checks=checks,
                delete_evidence={'read_request_id': read_id,
                    'delete_requested': True, 'delete_request_id': None},
                updated_at=self.clock()), row.version)

        if row.value['status'] == 'POLICY_DELETE_INTENT':
            delete_evidence = copy.deepcopy(row.value['delete_evidence'])
            try:
                self._policy(row)
            except Exception as exc:
                if not _missing(exc) or not delete_evidence.get('delete_requested'):
                    raise
            else:
                response = self.control.delete_policy(
                    policyEngineId=self.registration['policy_engine_id'],
                    policyId=request['policy_id'])
                evidence = _policy_delete_evidence(response,
                    self.registration['policy_engine_id'], request['policy_id'])
                delete_evidence['delete_request_id'] = evidence['request_id']
                row = self._write(candidate, dict(row.value,
                    delete_evidence=delete_evidence, updated_at=self.clock()), row.version)
            for _ in range(60):
                try:
                    self.control.get_policy(
                        policyEngineId=self.registration['policy_engine_id'],
                        policyId=request['policy_id'])
                except Exception as exc:
                    if _missing(exc):
                        checks = dict(row.value['revocation_checks'],
                                      policy_absent_readback=True)
                        row = self._write(candidate, dict(row.value,
                            status='POLICY_ABSENT', revocation_checks=checks,
                            updated_at=self.clock()), row.version)
                        break
                    raise
                self.sleep(2)
            else:
                raise ValueError('Revoked Policy absence was not confirmed')

        if row.value['status'] == 'POLICY_ABSENT':
            outcomes = self._probe_all(candidate, True)
            result = {'schema_version': '1.0',
                'kind': 'AUTHORITY_REVOCATION_RESULT',
                'status': 'POLICY_REMOVED_DENY_CONFIRMED',
                'revocation_id': request['revocation_id'],
                'revocation_digest': request['digest'],
                'application_id': candidate['application_id'],
                'enforcement_digest': candidate['enforcement_digest'],
                'policy_id': request['policy_id'],
                'policy_name': request['policy_name'],
                'policy_hash': request['policy_hash'],
                'observed_at': self.clock(),
                'checks': copy.deepcopy(row.value['revocation_checks']),
                'outcomes': [{k: copy.deepcopy(item[k]) for k in (
                    'request_id', 'outcome', 'evidence_hash', 'evidence')}
                    for item in outcomes]}
            final = dict(row.value, status='SUSPENDED_CONFIRMED',
                         revocation_outcomes=outcomes,
                         revocation_result=result, updated_at=self.clock())
            return self._write(candidate, final, row.version).value['revocation_result']
        raise ValueError('Revocation journal did not reach a reconcilable phase')
