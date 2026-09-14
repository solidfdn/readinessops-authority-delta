"""AWS transport boundaries for queued enforcement applications.

The account-A worker can invoke only the qualified publisher Lambda registered
for the candidate.  It never receives AgentCore Policy permissions.  SQS
delivery is backed by a DynamoDB outbox so a failed immediate send is recoverable.
"""
from __future__ import annotations

import copy
import json
import re
from datetime import datetime, timedelta, timezone

from .delegation import verify_registration
from .storage import Conflict, encode


APPLICATION_ID = re.compile(r'^application-[0-9a-f]{32}$')
OBJECT_ID = re.compile(r'^o-[0-9a-f]{32}$')
DIGEST = re.compile(r'^[0-9a-f]{64}$')
REVOCATION_ID = re.compile(r'^revocation-[0-9a-f]{32}$')
MAX_AUTOMATIC_APPLICATION_ATTEMPTS = 3
PUBLISHER_FENCE_RECOVERY_DELAY_SECONDS = 780
MAX_PUBLISHER_FENCE_RECOVERIES = 1
MAX_PUBLISHER_DELETE_ITEM_RECOVERIES = 1
MAX_CANARY_RESULT_RECOVERIES = 1
MAX_RESOURCE_SCOPED_POLICY_RECOVERIES = 1
MAX_GATEWAY_POLICY_VALIDATION_RECOVERIES = 1
MAX_FAILED_POLICY_TARGET_DISCOVERY_RECOVERIES = 1
MAX_POLICY_DELETE_RESPONSE_RECOVERIES = 1
MAX_POLICY_CREATE_RESPONSE_RECOVERIES = 1
MAX_POLICY_CREATE_DISCOVERY_RECOVERIES = 1
REMOTE_FENCE_MARKERS = (
    'Publisher invocation failed:', 'remote=ValueError:',
    'Another account-B publisher invocation is still active')
PUBLISHER_DELETE_ITEM_MARKERS = (
    'Publisher invocation failed:', 'remote=ClientError:',
    'AccessDeniedException', 'authority-delta-customer-publisher',
    'dynamodb:DeleteItem')
CANARY_RESULT_MARKERS = (
    'Publisher invocation failed:', 'remote=ValueError:',
    'Canary Lambda result differs')
RESOURCE_SCOPED_POLICY_MARKERS = (
    'Publisher invocation failed:', 'remote=AccessDeniedException:',
    'CreatePolicy operation', 'authority-delta-customer-publisher',
    'bedrock-agentcore:ManageResourceScopedPolicy')
GATEWAY_POLICY_VALIDATION_MARKERS = (
    'Publisher invocation failed:', 'remote=AccessDeniedException:',
    'CreatePolicy operation', 'Failed to confirm existence on AgentCore Gateway',
    'bedrock-agentcore:GetGateway')
FAILED_POLICY_TARGET_DISCOVERY_MARKERS = (
    'Publisher invocation failed:', 'remote=ValueError:',
    'Owned candidate Policy entered a failed state')
POLICY_DELETE_RESPONSE_MARKERS = (
    'Publisher invocation failed:', 'remote=ValueError:',
    'Failed candidate Policy delete lacks successful AWS evidence')
POLICY_CREATE_RESPONSE_MARKERS = (
    'Publisher invocation failed:', 'remote=ValueError:',
    'Policy create lacks successful AWS evidence')
DELAYED_RECOVERY_COUNTERS = {
    'EXPIRED_REMOTE_FENCE': 'publisher_fence_recovery_attempts',
    'PUBLISHER_DELETE_ITEM_IAM': 'publisher_delete_item_recovery_attempts',
    'CANARY_RESULT_CONTRACT': 'canary_result_recovery_attempts',
    'RESOURCE_SCOPED_POLICY_IAM': 'resource_scoped_policy_recovery_attempts',
    'GATEWAY_POLICY_VALIDATION_IAM':
        'gateway_policy_validation_recovery_attempts',
    'FAILED_POLICY_TARGET_DISCOVERY':
        'failed_policy_target_discovery_recovery_attempts',
    'POLICY_DELETE_RESPONSE_CONTRACT':
        'policy_delete_response_recovery_attempts',
    'POLICY_CREATE_RESPONSE_CONTRACT':
        'policy_create_response_recovery_attempts',
    'POLICY_CREATE_DISCOVERY_RECONCILIATION':
        'policy_create_discovery_recovery_attempts'}


def _as_utc(value):
    parsed = datetime.fromisoformat(value.replace('Z', '+00:00'))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _automatic_recovery_mode(state, now):
    """Select only one bounded, evidence-specific delayed retry mode."""
    if (not isinstance(state, dict) or state.get('status') != 'UNKNOWN'
            or state.get('attempt', 0) < MAX_AUTOMATIC_APPLICATION_ATTEMPTS):
        return None
    error = state.get('last_error', '')
    if not isinstance(error, str):
        return None
    modes = (
        ('EXPIRED_REMOTE_FENCE', REMOTE_FENCE_MARKERS,
         MAX_PUBLISHER_FENCE_RECOVERIES),
        ('PUBLISHER_DELETE_ITEM_IAM', PUBLISHER_DELETE_ITEM_MARKERS,
         MAX_PUBLISHER_DELETE_ITEM_RECOVERIES),
        ('CANARY_RESULT_CONTRACT', CANARY_RESULT_MARKERS,
         MAX_CANARY_RESULT_RECOVERIES),
        ('RESOURCE_SCOPED_POLICY_IAM', RESOURCE_SCOPED_POLICY_MARKERS,
         MAX_RESOURCE_SCOPED_POLICY_RECOVERIES),
        ('GATEWAY_POLICY_VALIDATION_IAM', GATEWAY_POLICY_VALIDATION_MARKERS,
         MAX_GATEWAY_POLICY_VALIDATION_RECOVERIES),
        ('FAILED_POLICY_TARGET_DISCOVERY',
         FAILED_POLICY_TARGET_DISCOVERY_MARKERS,
         MAX_FAILED_POLICY_TARGET_DISCOVERY_RECOVERIES),
        ('POLICY_DELETE_RESPONSE_CONTRACT', POLICY_DELETE_RESPONSE_MARKERS,
         MAX_POLICY_DELETE_RESPONSE_RECOVERIES),
        ('POLICY_CREATE_RESPONSE_CONTRACT', POLICY_CREATE_RESPONSE_MARKERS,
         MAX_POLICY_CREATE_RESPONSE_RECOVERIES))
    for mode, markers, maximum in modes:
        counter = DELAYED_RECOVERY_COUNTERS[mode]
        if all(marker in error for marker in markers) and state.get(counter, 0) < maximum:
            try:
                ready_at = _as_utc(state['updated_at']) + timedelta(
                    seconds=(0 if mode in ('POLICY_DELETE_RESPONSE_CONTRACT',
                                           'POLICY_CREATE_RESPONSE_CONTRACT')
                             else PUBLISHER_FENCE_RECOVERY_DELAY_SECONDS))
            except (KeyError, TypeError, ValueError):
                return None
            if _as_utc(now) >= ready_at:
                return mode
    if (all(marker in error for marker in POLICY_CREATE_RESPONSE_MARKERS)
            and state.get('policy_create_response_recovery_attempts', 0) >= 1
            and state.get('policy_create_discovery_recovery_attempts', 0)
                < MAX_POLICY_CREATE_DISCOVERY_RECOVERIES):
        try:
            ready_at = _as_utc(state['updated_at'])
        except (KeyError, TypeError, ValueError):
            return None
        if _as_utc(now) >= ready_at:
            return 'POLICY_CREATE_DISCOVERY_RECONCILIATION'
    return None


def _claim_delayed_recovery(db, state_row, mode, now):
    counter = DELAYED_RECOVERY_COUNTERS[mode]
    claimed = dict(state_row.value,
        **{counter: state_row.value.get(counter, 0) + 1,
           counter.removesuffix('_attempts') + '_dispatched_at': now})
    db.transact([('app', claimed['object_id'],
        'APPLICATION#' + claimed['application_id'], claimed, state_row.version)])
    return db.get('app', claimed['object_id'],
                  'APPLICATION#' + claimed['application_id'])


def _restore_delayed_recovery(db, claimed_row, mode):
    counter = DELAYED_RECOVERY_COUNTERS[mode]
    restored = dict(claimed_row.value,
        **{counter: max(0, claimed_row.value.get(counter, 1) - 1),
           counter.removesuffix('_attempts') + '_dispatched_at': None})
    try:
        db.transact([('app', restored['object_id'],
            'APPLICATION#' + restored['application_id'], restored,
            claimed_row.version)])
    except Conflict:
        pass


def _publisher_failure(operation, response, raw):
    function_error = response.get('FunctionError')
    if not function_error:
        return None
    remote_type, remote_message = 'Unknown', 'No Lambda error document'
    try:
        failure = json.loads(raw)
        if isinstance(failure, dict):
            remote_type = str(failure.get('errorType') or remote_type)
            remote_message = str(failure.get('errorMessage') or remote_message)
    except (UnicodeDecodeError, json.JSONDecodeError, TypeError):
        pass
    return ValueError(
        f'{operation} failed: Lambda FunctionError={function_error}; '
        f'remote={remote_type}: {remote_message}'[:900])


def verify_application_message(value):
    if isinstance(value, dict) and value.get('operation') == 'REVOKE':
        if (set(value) != {'operation', 'object_id', 'application_id',
                           'enforcement_digest', 'revocation_id',
                           'revocation_digest'}
                or not OBJECT_ID.fullmatch(value.get('object_id', ''))
                or not APPLICATION_ID.fullmatch(value.get('application_id', ''))
                or not DIGEST.fullmatch(value.get('enforcement_digest', ''))
                or not REVOCATION_ID.fullmatch(value.get('revocation_id', ''))
                or not DIGEST.fullmatch(value.get('revocation_digest', ''))):
            raise ValueError('Revocation message is invalid')
        return copy.deepcopy(value)
    if (not isinstance(value, dict)
            or set(value) != {'object_id', 'application_id', 'enforcement_digest'}
            or not OBJECT_ID.fullmatch(value.get('object_id', ''))
            or not APPLICATION_ID.fullmatch(value.get('application_id', ''))
            or not DIGEST.fullmatch(value.get('enforcement_digest', ''))):
        raise ValueError('Application message is invalid')
    return copy.deepcopy(value)


def _outbox_id(message):
    return message.get('revocation_id', message['application_id'])


def dispatch_application(db, sqs, queue_url, message):
    """Send one committed application outbox record, then conditionally remove it."""
    message = verify_application_message(message)
    row = db.get('jobs', 'APPLICATION_OUTBOX', _outbox_id(message))
    if row is None:
        return False
    if row.value != message:
        raise ValueError('Application outbox differs from the requested message')
    response = sqs.send_message(QueueUrl=queue_url,
                                MessageBody=encode(message).decode('utf-8'))
    metadata = response.get('ResponseMetadata', {})
    if (metadata.get('HTTPStatusCode') != 200 or not metadata.get('RequestId')
            or not response.get('MessageId')):
        raise ValueError('Application queue send lacks successful AWS evidence')
    try:
        db.transact([('jobs', 'APPLICATION_OUTBOX', _outbox_id(message),
                      None, row.version)])
    except Conflict:
        pass
    return True


def dispatch_pending_applications(db, sqs, queue_url, *, clock=None):
    now = (clock or (lambda: datetime.now(timezone.utc).isoformat()))()
    failures = 0
    for row in db.query('jobs', 'APPLICATION_OUTBOX'):
        message = row.value
        state = None
        mode = None
        claimed = None
        try:
            if isinstance(message, dict) and message.get('operation') != 'REVOKE':
                state = db.get('app', message.get('object_id'),
                    'APPLICATION#' + str(message.get('application_id', '')))
                if (state is not None
                        and state.value.get('status') == 'UNKNOWN'
                        and state.value.get('attempt', 0)
                            >= MAX_AUTOMATIC_APPLICATION_ATTEMPTS):
                    mode = _automatic_recovery_mode(state.value, now)
                    if mode is None:
                        continue
                    claimed = _claim_delayed_recovery(db, state, mode, now)
            dispatch_application(db, sqs, queue_url, message)
        except Exception:
            if claimed is not None and mode is not None:
                _restore_delayed_recovery(db, claimed, mode)
            failures += 1
    if failures:
        raise RuntimeError('Application outbox dispatch incomplete; pending records retained')


class LambdaPublisher:
    """Strict port from account A to one qualified publisher function in account B."""

    def __init__(self, client, registrations, *, sts=None, assumed_client=None):
        self.client, self.sts, self.assumed_client = client, sts, assumed_client
        self.registrations = {}
        for raw in registrations:
            registration = verify_registration(raw)
            key = (registration['adapter_id'], registration['connection_id'])
            if key in self.registrations:
                raise ValueError('Publisher registration is duplicated')
            self.registrations[key] = registration

    def _registration(self, candidate):
        registration = self.registrations.get(
            (candidate.get('adapter_id'), candidate.get('connection_id')))
        if registration is None:
            raise ValueError('Candidate publisher is not registered')
        if (candidate.get('adapter_registration_hash') != registration['registration_hash']
                or candidate.get('publisher_binding') != registration['publisher_binding']
                or candidate.get('execution_binding', {}).get('target_account_id')
                    != registration['target_account_id']):
            raise ValueError('Candidate differs from its registered publisher binding')
        return registration

    def _publisher_client(self, registration, candidate):
        binding = registration['publisher_binding']
        if registration['connection_mode'] != 'LIVE_CUSTOMER':
            return self.client, 'LOCAL_NOT_ASSUMED'
        if self.sts is None or self.assumed_client is None:
            raise ValueError('Live customer publication requires the registered STS connector')
        session_name = 'authority-delta-' + candidate['application_id'].split('-', 1)[1][:16]
        response = self.sts.assume_role(RoleArn=binding['invoke_role_arn'],
            RoleSessionName=session_name, ExternalId=binding['external_id'],
            DurationSeconds=900)
        metadata = response.get('ResponseMetadata', {})
        role_name = binding['invoke_role_arn'].rsplit('/', 1)[1]
        expected_arn = (f"arn:aws:sts::{registration['target_account_id']}:assumed-role/"
                        f"{role_name}/{session_name}")
        credentials = response.get('Credentials', {})
        if (metadata.get('HTTPStatusCode') != 200 or not metadata.get('RequestId')
                or response.get('AssumedRoleUser', {}).get('Arn') != expected_arn
                or not all(credentials.get(name) for name in (
                    'AccessKeyId', 'SecretAccessKey', 'SessionToken'))):
            raise ValueError('Assumed publisher role identity is not exact successful AWS evidence')
        return self.assumed_client(credentials, registration['target_region']), metadata['RequestId']

    def _invoke(self, operation, candidate, require_closed=False):
        registration = self._registration(candidate)
        function_arn = registration['publisher_binding']['function_arn']
        client, assume_request_id = self._publisher_client(registration, candidate)
        payload = encode({'schema_version': '1.0', 'operation': operation,
                          'require_closed': require_closed,
                          'candidate': candidate})
        if len(payload) > 900_000:
            raise ValueError('Publisher request exceeds the bounded payload size')
        response = client.invoke(FunctionName=function_arn,
            InvocationType='RequestResponse', Payload=payload)
        metadata = response.get('ResponseMetadata', {})
        stream = response.get('Payload')
        if stream is None:
            raise ValueError('Publisher invocation has no response stream')
        try:
            raw = stream.read(900_001)
        finally:
            stream.close()
        failure = _publisher_failure('Publisher invocation', response, raw)
        if failure is not None:
            raise failure
        if (len(raw) > 900_000 or response.get('StatusCode') != 200
                or metadata.get('HTTPStatusCode') != 200
                or not metadata.get('RequestId')):
            raise ValueError('Publisher invocation could not be confirmed')
        result = json.loads(raw)
        if not isinstance(result, dict):
            raise ValueError('Publisher response must be one JSON object')
        result['publisher_invocation'] = {
            'function_arn': function_arn,
            'request_id': metadata['RequestId'],
            'http_status': response['StatusCode'],
            'executed_version': response.get('ExecutedVersion') or function_arn.rsplit(':', 1)[1],
            'invoke_role_arn': registration['publisher_binding']['invoke_role_arn'],
            'assume_role_request_id': assume_request_id,
        }
        return result

    def _invoke_revocation(self, candidate, revocation):
        registration = self._registration(candidate)
        function_arn = registration['publisher_binding']['function_arn']
        client, assume_request_id = self._publisher_client(registration, candidate)
        payload = encode({'schema_version': '1.0', 'operation': 'REVOKE',
                          'candidate': candidate, 'revocation': revocation})
        if len(payload) > 900_000:
            raise ValueError('Revocation request exceeds the bounded payload size')
        response = client.invoke(FunctionName=function_arn,
            InvocationType='RequestResponse', Payload=payload)
        metadata, stream = response.get('ResponseMetadata', {}), response.get('Payload')
        if stream is None:
            raise ValueError('Publisher revocation invocation has no response stream')
        try:
            raw = stream.read(900_001)
        finally:
            stream.close()
        failure = _publisher_failure('Publisher revocation invocation', response, raw)
        if failure is not None:
            raise failure
        if (len(raw) > 900_000 or response.get('StatusCode') != 200
                or metadata.get('HTTPStatusCode') != 200
                or not metadata.get('RequestId')):
            raise ValueError('Publisher revocation invocation could not be confirmed')
        result = json.loads(raw)
        if not isinstance(result, dict):
            raise ValueError('Publisher revocation response must be one JSON object')
        result['publisher_invocation'] = {'function_arn': function_arn,
            'request_id': metadata['RequestId'], 'http_status': response['StatusCode'],
            'executed_version': response.get('ExecutedVersion')
                or function_arn.rsplit(':', 1)[1],
            'invoke_role_arn': registration['publisher_binding']['invoke_role_arn'],
            'assume_role_request_id': assume_request_id}
        return result

    def publish(self, candidate):
        return self._invoke('PUBLISH', candidate)

    def reconcile(self, candidate, require_closed=False):
        return self._invoke('RECONCILE', candidate, require_closed=require_closed)

    def revoke(self, candidate, revocation):
        return self._invoke_revocation(candidate, revocation)
