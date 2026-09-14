"""Authenticated read-only view. This service cannot record or publish a decision."""
import json
import os
import boto3


def reply(status, body):
    return {'statusCode':status, 'headers':{'Content-Type':'application/json', 'Cache-Control':'no-store',
        'X-Content-Type-Options':'nosniff'}, 'body':json.dumps(body, ensure_ascii=False)}


def handler(event, context):
    if event.get('routeKey') != 'GET /review':
        return reply(404, {'error':'Not found'})
    claims = event.get('requestContext', {}).get('authorizer', {}).get('jwt', {}).get('claims', {})
    if claims.get('token_use') != 'access' or claims.get('client_id') != os.environ['CLIENT_ID'] or not claims.get('sub'):
        return reply(401, {'error':'Sign in to review this release'})
    if 'authority-delta/read' not in str(claims.get('scope', '')).split() or claims.get('username') != os.environ['REVIEWER_USERNAME']:
        return reply(403, {'error':'Review access required'})
    try:
        obj = boto3.client('s3').get_object(Bucket=os.environ['DATA_BUCKET'], Key=os.environ['DATA_KEY'], VersionId=os.environ['DATA_VERSION'])
        stream = obj['Body']
        try:
            raw = stream.read(2_000_001)
        finally:
            stream.close()
        if len(raw) > 2_000_000:
            raise ValueError('Review data exceeds bound')
        return reply(200, json.loads(raw))
    except Exception:
        # No AWS responses, identifiers or evidence content in public error text.
        return reply(503, {'error':'Review evidence is temporarily unavailable'})
