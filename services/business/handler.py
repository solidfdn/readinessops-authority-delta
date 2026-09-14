"""JWT-authorized business API. The caller identity never comes from a request body."""
import base64
import hashlib
import json
import logging
import os
import re
from functools import lru_cache
from pathlib import Path
from authority_delta.business.service import BusinessService, Problem
from authority_delta.business.storage import DynamoStore, S3Blobs, Conflict
from authority_delta.business.delegation import load_adapter_registry
from authority_delta.business.jobs import dispatch_one
from authority_delta.business.aws_application import dispatch_application

LOGGER = logging.getLogger(__name__)
LOGGER.setLevel(logging.INFO)
ROUTE = re.compile(
    r'/business/objects(?:/(o-[0-9a-f]{32})(?:/(evidence|runs|draft|review|publish|connection|delegation|applications|revocations|actions|outcomes|imports|interchange|acceptance-evidence)(?:/([A-Za-z0-9_-]+))?)?)?'
)


@lru_cache(maxsize=1)
def service():
    import boto3
    from botocore.config import Config
    config = Config(connect_timeout=4, read_timeout=8, retries={'total_max_attempts': 2})
    ddb = boto3.client('dynamodb', config=config)
    db = DynamoStore(ddb, {'app': os.environ['APP_TABLE'], 'jobs': os.environ['JOBS_TABLE']})
    blobs = S3Blobs(boto3.client('s3', config=config), os.environ['DATA_BUCKET'])
    sqs = boto3.client('sqs', config=config)
    registry = load_adapter_registry(Path(__file__).parent / 'adapter_registrations.json')
    return BusinessService(db, blobs,
        lambda rid: dispatch_one(db, sqs, os.environ['QUEUE_URL'], rid),
        adapters=registry,
        application_dispatch=lambda message: dispatch_application(
            db, sqs, os.environ['APPLICATION_QUEUE_URL'], message))


def reply(status, value):
    return {'statusCode': status, 'headers': {'Content-Type': 'application/json', 'Cache-Control': 'no-store',
            'X-Content-Type-Options': 'nosniff'}, 'body': json.dumps(value, ensure_ascii=False, allow_nan=False)}


def parse_body(event):
    raw = event.get('body') or '{}'
    if event.get('isBase64Encoded'):
        raw = base64.b64decode(raw, validate=True).decode('utf-8')
    if len(raw.encode()) > 2_800_000:
        raise Problem('Request is too large', 413)
    def pairs(items):
        result = {}
        for k, v in items:
            if k in result:
                raise ValueError('Duplicate JSON member')
            result[k] = v
        return result
    body = json.loads(raw, object_pairs_hook=pairs, parse_constant=lambda x: (_ for _ in ()).throw(ValueError('Non-finite number')))
    if not isinstance(body, dict):
        raise Problem('A JSON object is required')
    return body


@lru_cache(maxsize=1)
def validators():
    from jsonschema import Draft202012Validator
    doc = json.loads((Path(__file__).parent / 'requests.schema.json').read_text())
    return {name: Draft202012Validator({'$defs': doc['$defs'], **shape}) for name, shape in doc['commands'].items()}


def _digest(value):
    return hashlib.sha256(value.encode('utf-8')).hexdigest() if isinstance(value, str) and value else None


def _safe_request_id(value):
    return value if isinstance(value, str) and re.fullmatch(r'[A-Za-z0-9_-]{1,128}', value) else None


def _correlation_request_id(event, invocation_id=None):
    context = event.get('requestContext', {}) if isinstance(event, dict) else {}
    request_id = context.get('requestId') if isinstance(context, dict) else None
    return _safe_request_id(request_id) or _safe_request_id(invocation_id)


def _command_request_digest(event):
    try:
        if event.get('requestContext', {}).get('http', {}).get('method') != 'POST':
            return None
        request_id = parse_body(event).get('request_id')
        if not isinstance(request_id, str) or not re.fullmatch(r'[A-Za-z0-9_-]{16,128}', request_id):
            return None
        return _digest(request_id)
    except (Problem, ValueError, TypeError, KeyError, UnicodeError):
        return None


def _audit(event, response, invocation_id=None):
    """Emit one correlation record without tokens, payloads or plaintext identities."""
    context = event.get('requestContext', {}) if isinstance(event, dict) else {}
    http = context.get('http', {}) if isinstance(context, dict) else {}
    method = http.get('method', '') if isinstance(http, dict) else ''
    method = method if isinstance(method, str) and re.fullmatch(r'[A-Z]{1,10}', method) else 'UNKNOWN'
    path = event.get('rawPath', '') if isinstance(event, dict) else ''
    match = ROUTE.fullmatch(path) if isinstance(path, str) else None
    oid, resource, item = match.groups() if match else (None, None, None)
    authorizer = context.get('authorizer', {}) if isinstance(context, dict) else {}
    authorizer = authorizer if isinstance(authorizer, dict) else {}
    jwt = authorizer.get('jwt', {})
    jwt = jwt if isinstance(jwt, dict) else {}
    claims = jwt.get('claims', {})
    claims = claims if isinstance(claims, dict) else {}
    status = int(response.get('statusCode', 503))
    code = 'OK'
    if status >= 400:
        try:
            body = json.loads(response.get('body', '{}'))
            code = body.get('code') if isinstance(body, dict) and isinstance(body.get('code'), str) else 'FAILED'
        except (TypeError, ValueError):
            code = 'FAILED'
    record = {
        'schema_version': '1.0',
        'kind': 'BUSINESS_API_AUDIT',
        'request_id': _correlation_request_id(event, invocation_id),
        'method': method,
        'resource': ('objects' if match and resource is None else resource) if match else 'UNMATCHED',
        'has_item': bool(item),
        'object_id_sha256': _digest(oid),
        'subject_sha256': _digest(claims.get('sub')),
        'command_request_id_sha256': _command_request_digest(event),
        'http_status': status,
        'code': code,
        'result': 'SUCCESS' if status < 400 else ('REJECTED' if status < 500 else 'UNCONFIRMED'),
        'response_sha256': _digest(response.get('body')),
    }
    LOGGER.info(json.dumps(record, sort_keys=True, separators=(',', ':'), allow_nan=False))


def _dispatch(event, app, env):
    method = event.get('requestContext', {}).get('http', {}).get('method', '')
    # The HTTP API has an explicit unauthenticated OPTIONS route.  Browsers
    # must be able to complete this preflight before they can send the JWT.
    if method == 'OPTIONS':
        return reply(200, {})
    claims = event.get('requestContext', {}).get('authorizer', {}).get('jwt', {}).get('claims', {})
    if claims.get('token_use') != 'access' or claims.get('client_id') != env['CLIENT_ID'] or not claims.get('sub'):
        raise Problem('Sign in to continue', 401, 'SIGN_IN_REQUIRED')
    if claims['sub'] != env['REVIEWER_SUB']:
        raise Problem('Workspace access is not assigned to this account', 403, 'FORBIDDEN')
    path = event.get('rawPath', '')
    match = ROUTE.fullmatch(path)
    if not match:
        raise Problem('Not found', 404, 'NOT_FOUND')
    oid, resource, item = match.groups()
    required = ('read' if method == 'GET' else
                ('approve' if resource in ('review', 'delegation') else
                 'publish' if resource in ('publish', 'applications', 'revocations') else 'write'))
    if 'authority-delta/' + required not in str(claims.get('scope', '')).split():
        raise Problem('Sign in again to use the updated workspace permissions', 403, 'SCOPE_REQUIRED')
    actor = {'sub': claims['sub'], 'name': env.get('REVIEWER_USERNAME', 'Reviewer')}
    if method == 'GET':
        if not oid: return reply(200, {'objects': app.objects(actor)})
        if resource is None: return reply(200, app.detail(actor, oid))
        if resource == 'runs' and item: return reply(200, app.run(actor, oid, item))
        if resource == 'evidence' and item: return reply(200, app.original(actor, oid, item))
        if resource == 'interchange' and not item: return reply(200, app.export_interchange(actor, oid))
        if resource == 'acceptance-evidence' and not item:
            return reply(200, app.export_acceptance_evidence(actor, oid))
    if method == 'POST' and resource == 'actions' and item:
        body = parse_body(event)
        error = next(validators()['action_update'].iter_errors(body), None)
        if error:
            raise Problem('Request fields are invalid: ' + '.'.join(str(p) for p in error.path), 422)
        return reply(200, app.update_action(actor, oid, item, body))
    if method == 'POST' and not item:
        command = 'create' if not oid else resource
        if command not in validators() or command == 'action_update':
            raise Problem('Not found', 404, 'NOT_FOUND')
        body = parse_body(event)
        error = next(validators()[command].iter_errors(body), None)
        if error:
            raise Problem('Request fields are invalid: ' + '.'.join(str(p) for p in error.path), 422)
        functions = {'evidence': app.add_evidence, 'runs': app.start_run, 'draft': app.save_draft,
                     'review': app.review, 'publish': app.publish,
                     'connection': app.connect_adapter,
                     'delegation': app.approve_delegation,
                     'applications': app.start_application,
                     'revocations': app.request_revocation,
                     'outcomes': app.record_outcome,
                     'imports': app.import_interchange}
        result = app.create(actor, body) if command == 'create' else functions[command](actor, oid, body)
        return reply(202 if command in ('runs', 'applications', 'revocations') else 200, result)
    raise Problem('Not found', 404, 'NOT_FOUND')


def handle(event, app, env, invocation_id=None):
    try:
        response = _dispatch(event, app, env)
    except Problem as exc:
        response = reply(exc.status, {'error': str(exc), 'code': exc.code})
    except Conflict:
        response = reply(409, {'error': 'The record changed. Reload and try again.', 'code': 'STALE_VERSION'})
    except (ValueError, TypeError, KeyError):
        response = reply(400, {'error': 'The request could not be validated', 'code': 'INVALID_INPUT'})
    except Exception:
        response = reply(503, {'error': 'The workspace could not confirm this operation. Retry with the same request.', 'code': 'UNCONFIRMED'})
    request_id = _correlation_request_id(event, invocation_id)
    if request_id:
        # Safe browser-visible correlation only. Never expose a subject, token,
        # command ID, object ID or payload through response headers.
        response.setdefault('headers', {})['X-Request-ID'] = request_id
    try:
        _audit(event, response, invocation_id)
    except Exception:
        # Audit transport must never change an already determined API result.
        LOGGER.exception('BUSINESS_API_AUDIT_EMISSION_FAILED')
    return response


def handler(event, context):
    return handle(event, service(), os.environ, getattr(context, 'aws_request_id', None))
