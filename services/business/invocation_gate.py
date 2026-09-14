"""JWT-authenticated normal execution entry; Runtime is never browser-invokable."""
import json
import logging
import os
import re
from datetime import datetime, timezone
from functools import lru_cache
from pathlib import Path

from authority_delta.business.delegation import load_adapter_registry
from authority_delta.business.invocation import (InvocationGate,
    InvocationRejected, InvocationWorker, LambdaRuntimeInvoker)
from authority_delta.business.storage import DynamoStore, S3Blobs


ROUTE = re.compile(r'/business/objects/(o-[0-9a-f]{32})/invocations'
                   r'(?:/([A-Za-z0-9_-]{16,80}))?')
LOGGER = logging.getLogger(__name__)
LOGGER.setLevel(logging.INFO)


@lru_cache(maxsize=1)
def gate():
    import boto3
    from botocore.config import Config
    # Worker calls may wait for the account-B invocation Lambda (300 seconds).
    # The API gate itself performs no remote invocation.
    config = Config(connect_timeout=5, read_timeout=330,
                    retries={'total_max_attempts': 1})
    db = DynamoStore(boto3.client('dynamodb', config=config), {
        'app': os.environ['APP_TABLE'], 'jobs': os.environ['JOBS_TABLE']})
    blobs = S3Blobs(boto3.client('s3', config=config), os.environ['DATA_BUCKET'])
    registrations = load_adapter_registry(Path(__file__).parent
                                          / 'adapter_registrations.json')
    def assumed(credentials, region):
        return boto3.client('lambda', region_name=region, config=config,
            aws_access_key_id=credentials['AccessKeyId'],
            aws_secret_access_key=credentials['SecretAccessKey'],
            aws_session_token=credentials['SessionToken'])
    invoker = LambdaRuntimeInvoker(boto3.client('lambda', config=config), registrations,
        sts=boto3.client('sts', config=config), assumed_client=assumed)
    return InvocationGate(db, blobs, invoker, registrations,
                          lambda: datetime.now(timezone.utc).isoformat())


def response(status, value):
    return {'statusCode': status, 'headers': {'Content-Type': 'application/json',
        'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff'},
        'body': json.dumps(value, ensure_ascii=False, allow_nan=False)}


def handler(event, context):
    result = None
    try:
        method = event.get('requestContext', {}).get('http', {}).get('method')
        if method not in ('GET', 'POST'):
            return response(404, {'code': 'NOT_FOUND', 'error': 'Not found'})
        match = ROUTE.fullmatch(event.get('rawPath', ''))
        claims = event.get('requestContext', {}).get('authorizer', {}).get(
            'jwt', {}).get('claims', {})
        scopes = str(claims.get('scope', '')).split()
        required_scope = ('authority-delta/publish' if method == 'POST'
                          else 'authority-delta/read')
        if (claims.get('token_use') != 'access'
                or claims.get('client_id') != os.environ['CLIENT_ID']
                or claims.get('sub') != os.environ['REVIEWER_SUB']
                or required_scope not in scopes):
            return response(403, {'code': 'AUTHORITY_REQUIRED',
                                  'error': 'Controlled invocation is not authorized'})
        if not match:
            return response(404, {'code': 'NOT_FOUND', 'error': 'Not found'})
        oid, operation_id = match.groups()
        actor = {'sub': claims['sub'],
                 'name': os.environ.get('REVIEWER_USERNAME', 'Reviewer')}
        if method == 'GET':
            if not operation_id:
                return response(404, {'code': 'NOT_FOUND', 'error': 'Not found'})
            result = gate().get(actor, oid, operation_id)
            return response(200, result)
        if operation_id:
            return response(404, {'code': 'NOT_FOUND', 'error': 'Not found'})
        raw = event.get('body') or '{}'
        if event.get('isBase64Encoded') or len(raw.encode()) > 4096:
            return response(422, {'code': 'INVALID_INPUT', 'error': 'Request is invalid'})
        def unique(items):
            value = {}
            for key, item in items:
                if key in value:
                    raise ValueError('Duplicate JSON member')
                value[key] = item
            return value
        body = json.loads(raw, object_pairs_hook=unique,
                          parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
        result = gate().accept(actor, oid, body)
        return response(202, result)
    except InvocationRejected as exc:
        return response(409, {'code': 'AUTHORITY_CLOSED', 'error': str(exc)})
    except (ValueError, TypeError, KeyError):
        return response(422, {'code': 'INVALID_INPUT', 'error': 'Request is invalid'})
    except Exception:
        return response(503, {'code': 'INVOCATION_UNCONFIRMED',
            'error': 'The invocation result could not be confirmed; retry the same operation ID'})


def worker_handler(event, context):
    current = gate()
    worker = InvocationWorker(current.db, current.blobs, current.invoker,
                              current.adapters.values(), current.clock)
    failures = []
    for record in event.get('Records', []):
        message, arn = None, None
        try:
            arn = record.get('eventSourceARN')
            if (record.get('eventSource') != 'aws:sqs'
                    or arn not in (os.environ['INVOCATION_QUEUE_ARN'],
                                   os.environ['INVOCATION_DLQ_ARN'])):
                raise ValueError('Unexpected invocation queue source')
            message = json.loads(record['body'])
            worker.process(message, dead_letter=arn == os.environ['INVOCATION_DLQ_ARN'])
        except Exception as exc:
            if arn == os.environ.get('INVOCATION_DLQ_ARN'):
                worker.delivery_failed(message, exc)
            else:
                failures.append({'itemIdentifier': record.get('messageId', '')})
            LOGGER.exception('CONTROLLED_INVOCATION_DELIVERY_FAILED')
    return {'batchItemFailures': failures}
