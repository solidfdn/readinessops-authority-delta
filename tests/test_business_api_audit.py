"""Safe correlation evidence for successful and rejected business API requests."""
import hashlib
import json
import unittest
from unittest.mock import patch

from services.business.handler import LOGGER, handle


class App:
    def objects(self, actor):
        return []


class BusinessApiAuditTests(unittest.TestCase):
    env = {'CLIENT_ID': 'client', 'REVIEWER_SUB': 'reviewer-private-id'}

    @staticmethod
    def event(path='/business/objects', sub='reviewer-private-id', body=None):
        return {
            'rawPath': path,
            'body': json.dumps(body or {}),
            'requestContext': {
                'requestId': 'gateway-request_123',
                'http': {'method': 'GET'},
                'authorizer': {'jwt': {'claims': {
                    'token_use': 'access', 'client_id': 'client', 'sub': sub,
                    'scope': 'authority-delta/read'}}},
            },
        }

    def observed(self, event):
        with self.assertLogs('services.business.handler', level='INFO') as logs:
            response = handle(event, App(), self.env, 'lambda-fallback')
        self.assertEqual(len(logs.records), 1)
        return response, json.loads(logs.records[0].getMessage())

    def test_success_has_gateway_correlation_and_hashed_subject(self):
        response, audit = self.observed(self.event())
        self.assertEqual(response['statusCode'], 200)
        self.assertEqual(response['headers']['X-Request-ID'],
                         'gateway-request_123')
        self.assertEqual(audit, {
            'schema_version': '1.0', 'kind': 'BUSINESS_API_AUDIT',
            'request_id': 'gateway-request_123', 'method': 'GET',
            'resource': 'objects', 'has_item': False,
            'object_id_sha256': None,
            'subject_sha256': hashlib.sha256(b'reviewer-private-id').hexdigest(),
            'command_request_id_sha256': None,
            'http_status': 200, 'code': 'OK', 'result': 'SUCCESS',
            'response_sha256': hashlib.sha256(response['body'].encode()).hexdigest(),
        })

    def test_rejection_never_logs_payload_path_or_plain_identity(self):
        secret = 'do-not-log-this-value'
        event = self.event('/business/objects/' + secret, sub='foreign-private-id',
                           body={'credential': secret})
        response, audit = self.observed(event)
        self.assertEqual(response['statusCode'], 403)
        self.assertEqual(audit['result'], 'REJECTED')
        self.assertEqual(audit['code'], 'FORBIDDEN')
        self.assertEqual(audit['resource'], 'UNMATCHED')
        encoded = json.dumps(audit)
        self.assertNotIn(secret, encoded)
        self.assertNotIn('foreign-private-id', encoded)
        self.assertNotIn('credential', encoded)

    def test_post_correlates_only_hashes_of_command_and_response(self):
        command_id = 'request_0123456789abcdef'
        event = self.event(body={'request_id': command_id, 'private': 'payload-secret'})
        event['requestContext']['http']['method'] = 'POST'
        response, audit = self.observed(event)
        self.assertEqual(response['statusCode'], 403)
        self.assertEqual(audit['command_request_id_sha256'],
                         hashlib.sha256(command_id.encode()).hexdigest())
        self.assertEqual(audit['response_sha256'],
                         hashlib.sha256(response['body'].encode()).hexdigest())
        encoded = json.dumps(audit)
        self.assertNotIn(command_id, encoded)
        self.assertNotIn('payload-secret', encoded)

    def test_invalid_gateway_request_id_uses_safe_lambda_id(self):
        event = self.event()
        event['requestContext']['requestId'] = 'unsafe request id\nsecond line'
        with self.assertLogs('services.business.handler', level='INFO') as logs:
            response = handle(event, App(), self.env, 'lambda-safe_456')
        self.assertEqual(response['statusCode'], 200)
        self.assertEqual(response['headers']['X-Request-ID'], 'lambda-safe_456')
        audit = json.loads(logs.records[0].getMessage())
        self.assertEqual(audit['request_id'], 'lambda-safe_456')

    def test_no_unsafe_correlation_header_is_returned(self):
        event = self.event()
        event['requestContext']['requestId'] = 'unsafe request id\nsecond line'
        with self.assertLogs('services.business.handler', level='INFO') as logs:
            response = handle(event, App(), self.env)
        audit = json.loads(logs.records[0].getMessage())
        self.assertNotIn('X-Request-ID', response['headers'])
        self.assertIsNone(audit['request_id'])

    def test_unconfirmed_response_is_correlated_without_exception_text(self):
        class FailingApp:
            def objects(self, actor):
                raise RuntimeError('private-upstream-diagnostic')
        event = self.event()
        with self.assertLogs('services.business.handler', level='INFO') as logs:
            response = handle(event, FailingApp(), self.env)
        self.assertEqual(response['statusCode'], 503)
        audit = json.loads(logs.records[0].getMessage())
        self.assertEqual(audit['result'], 'UNCONFIRMED')
        self.assertEqual(audit['code'], 'UNCONFIRMED')
        self.assertNotIn('private-upstream-diagnostic', logs.records[0].getMessage())

    def test_audit_transport_failure_does_not_change_success(self):
        with (patch.object(LOGGER, 'info', side_effect=RuntimeError('logging unavailable')),
              patch.object(LOGGER, 'exception') as failed):
            response = handle(self.event(), App(), self.env)
        self.assertEqual(response['statusCode'], 200)
        failed.assert_called_once_with('BUSINESS_API_AUDIT_EMISSION_FAILED')


if __name__ == '__main__':
    unittest.main()
