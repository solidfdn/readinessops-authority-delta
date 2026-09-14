"""SQS worker and scheduled outbox recovery; IAM excludes the business records table."""
import json
import os
from authority_delta.business.storage import DynamoStore, S3Blobs
from authority_delta.business.jobs import AssessmentWorker, RuntimeInvoker, dispatch_pending


def resources():
    import boto3
    from botocore.config import Config
    quick = Config(connect_timeout=5, read_timeout=15, retries={'total_max_attempts': 2})
    db = DynamoStore(boto3.client('dynamodb', config=quick), {'jobs': os.environ['JOBS_TABLE']})
    blobs = S3Blobs(boto3.client('s3', config=quick), os.environ['DATA_BUCKET'])
    return db, blobs, boto3


def dispatch_handler(event, context):
    db, _, boto3 = resources()
    dispatch_pending(db, boto3.client('sqs'), os.environ['QUEUE_URL'])
    return {'status': 'DISPATCHED'}


def handler(event, context):
    from botocore.config import Config
    db, blobs, boto3 = resources()
    binding = {k: os.environ['RUNTIME_' + k.upper()] for k in ('id', 'arn', 'version', 'endpoint', 'account', 'role_name', 'endpoint_arn')}
    invoke = RuntimeInvoker(boto3.client('bedrock-agentcore-control', config=Config(connect_timeout=5,read_timeout=15,retries={'total_max_attempts':2})),
                boto3.client('bedrock-agentcore', config=Config(connect_timeout=10, read_timeout=285, retries={'total_max_attempts': 1})), binding)
    worker = AssessmentWorker(db, blobs, invoke)
    failures = []
    for record in event.get('Records', []):
        try:
            arn = record.get('eventSourceARN')
            if record.get('eventSource') != 'aws:sqs' or arn not in (os.environ['QUEUE_ARN'], os.environ['DLQ_ARN']):
                raise ValueError('Unexpected queue source')
            worker.process(json.loads(record['body']), dead_letter=arn == os.environ['DLQ_ARN'])
        except Exception:
            failures.append({'itemIdentifier': record['messageId']})
    return {'batchItemFailures': failures}
