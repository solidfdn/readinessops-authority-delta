"""Application queue worker and durable outbox recovery.

This account-A Lambda has business-record access and permission to invoke only
the qualified customer publisher configured by the packaged adapter registry.
It has no AgentCore Policy write permission.
"""
import json
import os
from datetime import datetime, timezone
from pathlib import Path

from authority_delta.business.application import ApplicationWorker
from authority_delta.business.aws_application import (
    LambdaPublisher, dispatch_pending_applications)
from authority_delta.business.delegation import load_adapter_registry
from authority_delta.business.revocation import (RevocationWorker,
    request_due_expiries)
from authority_delta.business.invocation import dispatch_pending_invocations
from authority_delta.business.storage import DynamoStore, S3Blobs


def resources():
    import boto3
    from botocore.config import Config
    # The client must outlive the 600-second account-B publisher, while this
    # Lambda remains below its own 840-second hard timeout.
    config = Config(connect_timeout=5, read_timeout=650,
                    retries={'total_max_attempts': 1})
    db = DynamoStore(boto3.client('dynamodb', config=config), {
        'app': os.environ['APP_TABLE'], 'jobs': os.environ['JOBS_TABLE']})
    blobs = S3Blobs(boto3.client('s3', config=config), os.environ['DATA_BUCKET'])
    registry = load_adapter_registry(Path(__file__).parent / 'adapter_registrations.json')
    def assumed_client(credentials, region):
        return boto3.client('lambda', region_name=region, config=config,
            aws_access_key_id=credentials['AccessKeyId'],
            aws_secret_access_key=credentials['SecretAccessKey'],
            aws_session_token=credentials['SessionToken'])
    publisher = LambdaPublisher(boto3.client('lambda', config=config), registry,
        sts=boto3.client('sts', config=config), assumed_client=assumed_client)
    return db, blobs, publisher, registry, boto3


def dispatch_handler(event, context):
    db, blobs, _, _, boto3 = resources()
    request_due_expiries(db, blobs,
        lambda: datetime.now(timezone.utc).isoformat())
    sqs = boto3.client('sqs')
    dispatch_pending_applications(db, sqs, os.environ['APPLICATION_QUEUE_URL'])
    dispatch_pending_invocations(db, sqs, os.environ['INVOCATION_QUEUE_URL'])
    return {'status': 'DISPATCHED'}


def handler(event, context):
    db, blobs, publisher, registry, _ = resources()
    worker = ApplicationWorker(db, blobs, publisher, registry,
                               lambda: datetime.now(timezone.utc).isoformat())
    revocations = RevocationWorker(db, blobs, publisher, registry,
                                   lambda: datetime.now(timezone.utc).isoformat())
    failures = []
    for record in event.get('Records', []):
        message, arn = None, None
        try:
            arn = record.get('eventSourceARN')
            if (record.get('eventSource') != 'aws:sqs'
                    or arn not in (os.environ['APPLICATION_QUEUE_ARN'],
                                   os.environ['APPLICATION_DLQ_ARN'])):
                raise ValueError('Unexpected application queue source')
            message = json.loads(record['body'])
            selected = revocations if message.get('operation') == 'REVOKE' else worker
            selected.process(message)
        except Exception as exc:
            if arn == os.environ['APPLICATION_DLQ_ARN']:
                selected = (revocations if isinstance(message, dict)
                            and message.get('operation') == 'REVOKE' else worker)
                selected.delivery_failed(message, exc)
            else:
                failures.append({'itemIdentifier': record['messageId']})
    return {'batchItemFailures': failures}
