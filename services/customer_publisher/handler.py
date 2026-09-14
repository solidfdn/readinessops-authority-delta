"""Qualified Lambda entrypoint for the account-B publisher."""
import os
import re
from datetime import datetime, timezone
from pathlib import Path

from authority_delta.business.customer_publisher import (
    CustomerPolicyPublisher, DynamoCanaryEvidence, LambdaCanaryProbe,
    PublisherInvocationFence,
    VendorPaymentInvocationProbe, verified_invocation_candidate,
    verify_customer_candidate)
from authority_delta.business.delegation import load_adapter_registry
from authority_delta.business.storage import DynamoStore
from authority_delta.canonical import sha256_json


def _registration(candidate):
    registrations = load_adapter_registry(
        Path(__file__).resolve().parents[1] / 'business' / 'adapter_registrations.json')
    matches = [value for value in registrations
               if value['adapter_id'] == candidate.get('adapter_id')
               and value['connection_id'] == candidate.get('connection_id')]
    if len(matches) != 1:
        raise ValueError('Candidate has no unique packaged customer registration')
    return matches[0]


def handler(event, context):
    if not isinstance(event, dict) or event.get('schema_version') != '1.0':
        raise ValueError('Publisher request is invalid')
    operation = event.get('operation')
    if operation == 'REVOKE':
        if set(event) != {'schema_version', 'operation', 'candidate', 'revocation'}:
            raise ValueError('Publisher request is invalid')
    elif (set(event) != {'schema_version', 'operation', 'require_closed', 'candidate'}
            or operation not in ('PUBLISH', 'RECONCILE')
            or type(event['require_closed']) is not bool
            or operation == 'PUBLISH' and event['require_closed']):
        raise ValueError('Publisher request is invalid')
    registration = _registration(event['candidate'])
    if os.environ.get('CONNECTION_ID') != registration['connection_id']:
        raise ValueError('Publisher deployment connection differs')
    candidate = verify_customer_candidate(event['candidate'], registration)
    import boto3
    from botocore.config import Config
    config = Config(connect_timeout=5, read_timeout=70,
                    retries={'total_max_attempts': 1})
    control = boto3.client('bedrock-agentcore-control',
                           region_name=registration['target_region'], config=config)
    dynamodb = boto3.client('dynamodb', region_name=registration['target_region'],
                            config=config)
    journal = DynamoStore(dynamodb, {'publisher': os.environ['PUBLISHER_JOURNAL_TABLE']})
    probe = LambdaCanaryProbe(boto3.client('lambda', config=config), registration)
    publisher = CustomerPolicyPublisher(control, journal, probe, registration,
        lambda: datetime.now(timezone.utc).isoformat())
    digest = candidate['enforcement_digest']
    owner = getattr(context, 'aws_request_id', None)
    clock = lambda: datetime.now(timezone.utc).isoformat()
    fence = PublisherInvocationFence(journal, clock)
    fence.claim(digest, owner)
    try:
        if operation == 'PUBLISH':
            return publisher.publish(candidate)
        if operation == 'REVOKE':
            return publisher.revoke(candidate, event['revocation'])
        return publisher.reconcile(candidate,
                                   require_closed=event['require_closed'])
    finally:
        fence.release(digest, owner)


def canary_handler(event, context):
    if (not isinstance(event, dict)
            or set(event) != {'schema_version', 'request_id', 'expected_outcome',
                              'registration_hash'}
            or event['schema_version'] != '1.0'
            or event['expected_outcome'] not in ('ALLOW', 'DENY')):
        raise ValueError('Canary request is invalid')
    candidates = [value for value in load_adapter_registry(
        Path(__file__).resolve().parents[1] / 'business' / 'adapter_registrations.json')
        if value['registration_hash'] == event['registration_hash']]
    if len(candidates) != 1:
        raise ValueError('Canary registration is not uniquely packaged')
    registration = candidates[0]
    if os.environ.get('CONNECTION_ID') != registration['connection_id']:
        raise ValueError('Canary deployment connection differs')
    import boto3
    from botocore.config import Config
    config = Config(connect_timeout=5, read_timeout=70,
                    retries={'total_max_attempts': 1})
    control = boto3.client('bedrock-agentcore-control',
                           region_name=registration['target_region'], config=config)
    runtime = boto3.client('bedrock-agentcore',
                           region_name=registration['target_region'], config=config)
    dynamodb = boto3.client('dynamodb', region_name=registration['target_region'],
                            config=config)
    evidence = DynamoCanaryEvidence(dynamodb, registration)
    return VendorPaymentInvocationProbe(control, runtime, evidence, registration).run(
        event['request_id'], event['expected_outcome'])


def invocation_handler(event, context):
    """Account-B runtime endpoint used only after the account-A gate accepts."""
    if (not isinstance(event, dict)
            or set(event) != {'schema_version', 'registration_hash', 'application_id',
                              'enforcement_digest', 'request_id'}
            or event.get('schema_version') != '1.0'):
        raise ValueError('Controlled invocation request is invalid')
    matches = [value for value in load_adapter_registry(
        Path(__file__).resolve().parents[1] / 'business' / 'adapter_registrations.json')
        if value['registration_hash'] == event['registration_hash']]
    if len(matches) != 1:
        raise ValueError('Controlled invocation registration is not uniquely packaged')
    registration = matches[0]
    allowed = {request_id for profile in registration['profiles'].values()
               for request_id in profile['allowed_request_ids']}
    if (event['request_id'] not in allowed
            or not re.fullmatch(r'application-[0-9a-f]{32}',
                                str(event['application_id']))
            or not re.fullmatch(r'[0-9a-f]{64}',
                                str(event['enforcement_digest']))):
        raise ValueError('Controlled invocation is outside the finite registered request set')
    if os.environ.get('CONNECTION_ID') != registration['connection_id']:
        raise ValueError('Controlled invocation deployment connection differs')
    import boto3
    from botocore.config import Config
    config = Config(connect_timeout=5, read_timeout=70,
                    retries={'total_max_attempts': 1})
    dynamodb = boto3.client('dynamodb',
                            region_name=registration['target_region'], config=config)
    journal = DynamoStore(dynamodb, {
        'publisher': os.environ['PUBLISHER_JOURNAL_TABLE']})
    verified_invocation_candidate(journal, event['application_id'],
                                  event['enforcement_digest'], registration)
    probe = VendorPaymentInvocationProbe(
        boto3.client('bedrock-agentcore-control',
                     region_name=registration['target_region'], config=config),
        boto3.client('bedrock-agentcore',
                     region_name=registration['target_region'], config=config),
        DynamoCanaryEvidence(dynamodb, registration),
        registration)
    evidence = probe.run(event['request_id'], 'ALLOW')
    return {'schema_version': '1.0', 'kind': 'CUSTOMER_RUNTIME_INVOCATION',
        'status': 'EXECUTED', 'application_id': event['application_id'],
        'enforcement_digest': event['enforcement_digest'],
        'request_id': event['request_id'], 'outcome': 'ALLOW',
        'evidence_hash': sha256_json(evidence), 'evidence': evidence}
