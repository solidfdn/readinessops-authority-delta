"""Private HAR/audit/export assembly for the D4 negative evidence contract."""
from contextlib import redirect_stdout
import io
import json
from pathlib import Path
import tempfile
import unittest

from scripts import assemble_d4_negative_browser_capture as assembler
from scripts import check_d4_negative_acceptance as checker


class D4NegativeBrowserCaptureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from test_d4_negative_acceptance import D4NegativeAcceptanceTests
        fixture = D4NegativeAcceptanceTests()
        fixture.setUp()
        cls.positive = fixture.positive
        cls.manifest = fixture.manifest

    def capture(self, root):
        capture = root / 'capture'
        snapshots = capture / 'snapshots'
        snapshots.mkdir(parents=True)
        entries = []
        audits = []
        cases = {}
        for name in checker.CASE_COUNTS:
            value = self.manifest['cases'][name]
            names = []
            for position, snapshot in enumerate(value['snapshots']):
                filename = f'{name}-snapshot-{position}.json'
                (snapshots / filename).write_text(json.dumps(snapshot))
                names.append(filename)
            mappings = []
            for exchange in value['exchanges']:
                request = exchange['request']
                response = exchange['response']
                correlation = request['gateway_request_id']
                header = ('X-Request-ID' if exchange['transport'] == 'BUSINESS_HANDLER'
                          else 'apigw-requestid')
                har_request = {
                    'method': request['method'],
                    'url': self.manifest['api_origin'] + request['path'],
                    'headers': [{'name': 'Authorization',
                                 'value': 'Bearer do-not-copy-private-token'}],
                    'cookies': [{'name': 'private-cookie', 'value': 'do-not-copy'}],
                }
                if request['body'] is not None:
                    har_request['postData'] = {
                        'mimeType': 'application/json', 'text': request['body']}
                entries.append({
                    'request': har_request,
                    'response': {
                        'status': response['status'],
                        'headers': [{'name': header, 'value': correlation}],
                        'content': {'mimeType': 'application/json',
                                    'text': response['body']},
                    },
                })
                mappings.append({
                    'har_entry_index': len(entries) - 1,
                    'subject_sha256': request['subject_sha256'],
                    'transport': exchange['transport'],
                })
                if exchange['audit'] is not None:
                    audits.append('[INFO] 2026-09-12 lambda-id '
                                  + json.dumps(exchange['audit']))
            cases[name] = {'snapshots': names, 'exchanges': mappings}
        index = {key: value for key, value in self.manifest.items()
                 if key not in {'scope', 'cases'}}
        index.update(scope=assembler.CAPTURE_SCOPE, har_file='browser.har.json',
                     audit_file='business-audit.json', cases=cases)
        (capture / 'index.json').write_text(json.dumps(index))
        (capture / 'browser.har.json').write_text(json.dumps({'log': {
            'version': '1.2', 'creator': {'name': 'test', 'version': '1'},
            'entries': entries}}))
        (capture / 'business-audit.json').write_text(json.dumps(audits))
        return capture

    def invoke(self, root, capture):
        positive = root / 'positive.json'
        observation = root / 'observations'
        result = root / 'result.json'
        positive.write_text(json.dumps(self.positive))
        with redirect_stdout(io.StringIO()):
            code = assembler.main([
                '--positive-result', str(positive),
                '--capture-dir', str(capture),
                '--observation-dir', str(observation),
                '--output', str(result),
            ])
        return code, observation, json.loads(result.read_text())

    def test_assembles_exact_directory_without_copying_headers_or_cookies(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            code, observation, result = self.invoke(root, self.capture(root))
            self.assertEqual(code, 0)
            self.assertEqual(result['result'], 'PASS')
            self.assertEqual(result['scope'], assembler.ASSEMBLY_SCOPE)
            self.assertEqual(checker.collect(observation), self.manifest)
            retained = ''.join(path.read_text() for path in
                               observation.rglob('exchange-*.json'))
            self.assertNotIn('do-not-copy-private-token', retained)
            self.assertNotIn('private-cookie', retained)
            self.assertNotIn('Authorization', retained)

    def test_missing_response_correlation_fails_without_partial_directory(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            capture = self.capture(root)
            har_path = capture / 'browser.har.json'
            har = json.loads(har_path.read_text())
            har['log']['entries'][0]['response']['headers'] = []
            har_path.write_text(json.dumps(har))
            code, observation, result = self.invoke(root, capture)
            self.assertEqual(code, 1)
            self.assertFalse(observation.exists())
            self.assertIn('correlation ID', result['error']['message'])

    def test_base64_har_body_and_unmapped_audit_fail_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            capture = self.capture(root)
            har_path = capture / 'browser.har.json'
            har = json.loads(har_path.read_text())
            har['log']['entries'][0]['response']['content']['encoding'] = 'base64'
            har_path.write_text(json.dumps(har))
            code, observation, result = self.invoke(root, capture)
            self.assertEqual(code, 1)
            self.assertFalse(observation.exists())
            self.assertIn('base64', result['error']['message'])

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            capture = self.capture(root)
            audit_path = capture / 'business-audit.json'
            audits = json.loads(audit_path.read_text())
            extra = dict(self.manifest['cases']['ro12_foreign_subject'][
                'exchanges'][0]['audit'], request_id='unmapped-request')
            audits.append(json.dumps(extra))
            audit_path.write_text(json.dumps(audits))
            code, observation, result = self.invoke(root, capture)
            self.assertEqual(code, 1)
            self.assertFalse(observation.exists())
            self.assertIn('unmapped records', result['error']['message'])

    def test_existing_output_is_never_overwritten(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            capture = self.capture(root)
            positive = root / 'positive.json'
            positive.write_text(json.dumps(self.positive))
            observation = root / 'observations'
            observation.mkdir()
            marker = observation / 'keep.txt'
            marker.write_text('keep')
            with self.assertRaisesRegex(ValueError, 'already exists'):
                assembler.assemble(capture, observation, self.positive)
            self.assertEqual(marker.read_text(), 'keep')


if __name__ == '__main__':
    unittest.main()
