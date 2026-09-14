#!/usr/bin/env python3
"""Assemble private D4 HAR/audit/export captures, then verify them offline.

This program performs no browser, AWS, API or human action. It accepts one
filtered browser HAR, an AWS CLI JSON array of CloudWatch audit messages and the
exact authenticated acceptance exports. Authorization headers and cookies are
input-only and are never copied to the assembled observation directory or result.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import re
import shutil
import sys
import tempfile
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from scripts import check_d4_negative_acceptance as checker


CAPTURE_SCOPE = 'PRIVATE_D4_BROWSER_HAR_AUDIT_EXPORT_CAPTURE'
ASSEMBLY_SCOPE = 'OFFLINE_D4_PRIVATE_BROWSER_CAPTURE_ASSEMBLY_NO_LIVE_ACTION_OR_PRODUCT_GATE'
MAX_CAPTURE_BYTES = 96_000_000
MAX_INDEX_BYTES = 300_000
MAX_HAR_BYTES = 48_000_000
MAX_AUDIT_BYTES = 8_000_000
SAFE_FILE = re.compile(r'[A-Za-z0-9][A-Za-z0-9._-]{0,127}\.json')
INDEX_KEYS = {'schema_version', 'scope', 'source_commit', 'account_a',
              'region', 'api_origin', 'reviewer_subject_sha256', 'har_file',
              'audit_file', 'cases'}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def _exact(value, keys, label):
    require(isinstance(value, dict) and set(value) == set(keys),
            label + ' fields differ')


def _regular(root, name, maximum, label):
    require(isinstance(name, str) and SAFE_FILE.fullmatch(name) is not None,
            label + ' filename is unsafe')
    path = root / name
    require(path.is_file() and not path.is_symlink(),
            label + ' is not a regular file')
    require(path.stat().st_size <= maximum, label + ' exceeds the bounded size')
    return path


def _headers(items, label):
    require(isinstance(items, list), label + ' headers are missing')
    values = {}
    for item in items:
        require(isinstance(item, dict)
                and isinstance(item.get('name'), str)
                and isinstance(item.get('value'), str),
                label + ' header shape differs')
        values.setdefault(item['name'].lower(), []).append(item['value'])
    return values


def _one_header(headers, names, label):
    found = [value for name in names for value in headers.get(name, [])]
    require(found and len(set(found)) == 1,
            label + ' has no single safe response correlation ID')
    request_id = found[0]
    require(re.fullmatch(r'[A-Za-z0-9_-]{1,128}', request_id) is not None,
            label + ' response correlation ID is unsafe')
    return request_id


def _har_exchange(entry, api_origin, mapping, audits, label):
    require(isinstance(entry, dict), label + ' HAR entry is not an object')
    request = entry.get('request')
    response = entry.get('response')
    require(isinstance(request, dict) and isinstance(response, dict),
            label + ' HAR request or response is missing')
    method = request.get('method')
    url = request.get('url')
    require(method in {'GET', 'POST'} and isinstance(url, str),
            label + ' HAR method or URL differs')
    expected_origin = urlsplit(api_origin)
    observed = urlsplit(url)
    require((observed.scheme, observed.netloc)
            == (expected_origin.scheme, expected_origin.netloc)
            and not observed.query and not observed.fragment,
            label + ' HAR URL is outside the exact API origin')
    path = observed.path
    require(checker.ROUTE.fullmatch(path) is not None,
            label + ' HAR path is not a normalized business route')

    post = request.get('postData')
    if method == 'POST':
        require(isinstance(post, dict) and isinstance(post.get('text'), str),
                label + ' HAR POST body was not retained')
        body = post['text']
    else:
        require(post is None, label + ' HAR GET unexpectedly carries a body')
        body = None

    status = response.get('status')
    content = response.get('content')
    require(type(status) is int and isinstance(content, dict)
            and isinstance(content.get('text'), str),
            label + ' HAR response status or body is missing')
    require(content.get('encoding') in (None, ''),
            label + ' HAR response body must not be base64 encoded')
    response_body = content['text']
    require(len((body or '').encode('utf-8')) <= checker.MAX_HTTP_BODY_BYTES
            and len(response_body.encode('utf-8')) <= checker.MAX_HTTP_BODY_BYTES,
            label + ' HAR body exceeds the bounded size')

    transport = mapping['transport']
    response_headers = _headers(response.get('headers'), label + ' response')
    if transport == 'BUSINESS_HANDLER':
        gateway_id = _one_header(response_headers, ('x-request-id',), label)
        audit = audits.pop(gateway_id, None)
        require(audit is not None, label + ' has no matching business audit')
    else:
        gateway_id = _one_header(
            response_headers,
            ('apigw-requestid', 'x-amzn-requestid', 'x-request-id'), label)
        require(gateway_id not in audits,
                label + ' authorizer rejection unexpectedly has a Lambda audit')
        audit = None
    return {
        'transport': transport,
        'request': {'gateway_request_id': gateway_id, 'method': method,
                    'path': path, 'body': body,
                    'subject_sha256': mapping['subject_sha256']},
        'response': {'status': status, 'body': response_body},
        'audit': audit,
    }


def _load_audits(path):
    raw = path.read_bytes()
    require(len(raw) <= MAX_AUDIT_BYTES, 'Audit capture exceeds the bounded size')
    value = checker._loads(raw, 'Audit capture')
    require(isinstance(value, list),
            'Audit capture must be an AWS CLI JSON array of log messages')
    records = {}
    for index, message in enumerate(value):
        require(isinstance(message, str),
                'Audit capture message is not a string')
        start = message.find('{')
        require(start >= 0, 'Audit capture message has no JSON record')
        record = checker._loads(message[start:].strip(),
                                'Audit capture message ' + str(index))
        require(isinstance(record, dict)
                and record.get('kind') == 'BUSINESS_API_AUDIT',
                'Audit capture contains a non-business record')
        request_id = record.get('request_id')
        require(isinstance(request_id, str)
                and re.fullmatch(r'[A-Za-z0-9_-]{1,128}', request_id)
                and request_id not in records,
                'Audit capture request ID is missing, unsafe or duplicated')
        records[request_id] = record
    return records


def _write_json(path, value):
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2,
                               allow_nan=False) + '\n', encoding='utf-8')


def assemble(capture_directory, destination, positive):
    capture = Path(capture_directory)
    output = Path(destination)
    require(capture.is_dir() and not capture.is_symlink(),
            'Capture input is not a regular directory')
    require(not output.exists(), 'Observation output already exists')
    index_path = capture / 'index.json'
    require(index_path.is_file() and not index_path.is_symlink(),
            'Capture index is not a regular file')
    index = checker.load(index_path, MAX_INDEX_BYTES)
    _exact(index, INDEX_KEYS, 'Capture index')
    require(index['schema_version'] == '1.0'
            and index['scope'] == CAPTURE_SCOPE
            and index['account_a'] == checker.ACCOUNT_A
            and index['region'] == checker.REGION
            and re.fullmatch(r'[0-9a-f]{40}', str(index['source_commit']))
            and re.fullmatch(r'https://[A-Za-z0-9.-]+', str(index['api_origin']))
            and checker._hash(index['reviewer_subject_sha256']),
            'Capture index binding differs')
    cases = index['cases']
    require(isinstance(cases, dict) and set(cases) == checker.CASES,
            'Capture index case set differs')

    har_path = _regular(capture, index['har_file'], MAX_HAR_BYTES,
                        'HAR capture')
    audit_path = _regular(capture, index['audit_file'], MAX_AUDIT_BYTES,
                          'Audit capture')
    require(index['har_file'] != index['audit_file'],
            'HAR and audit captures must be distinct')
    snapshots_root = capture / 'snapshots'
    require(snapshots_root.is_dir() and not snapshots_root.is_symlink(),
            'Snapshot capture is not a regular directory')
    require({item.name for item in capture.iterdir()}
            == {'index.json', index['har_file'], index['audit_file'], 'snapshots'},
            'Capture directory entries differ')

    har = checker.load(har_path, MAX_HAR_BYTES)
    log = har.get('log')
    entries = log.get('entries') if isinstance(log, dict) else None
    require(isinstance(entries, list), 'HAR capture has no log entries')
    audits = _load_audits(audit_path)
    total = sum(item.stat().st_size for item in capture.iterdir()
                if item.is_file())
    used_entries = set()
    snapshot_files = set()
    output_cases = {}
    for name, (snapshot_count, exchange_count) in checker.CASE_COUNTS.items():
        value = cases[name]
        _exact(value, {'snapshots', 'exchanges'}, name + ' capture')
        require(isinstance(value['snapshots'], list)
                and len(value['snapshots']) == snapshot_count
                and isinstance(value['exchanges'], list)
                and len(value['exchanges']) == exchange_count,
                name + ' capture count differs')
        snapshots = []
        for filename in value['snapshots']:
            require(filename not in snapshot_files,
                    'Snapshot capture file is reused')
            path = _regular(snapshots_root, filename, 5_500_000,
                            name + ' snapshot')
            snapshot_files.add(filename)
            total += path.stat().st_size
            require(total <= MAX_CAPTURE_BYTES,
                    'Capture directory exceeds the bounded size')
            snapshots.append(checker.load(path, 5_500_000))
        exchanges = []
        for position, mapping in enumerate(value['exchanges']):
            _exact(mapping, {'har_entry_index', 'subject_sha256', 'transport'},
                   name + ' exchange mapping')
            entry_index = mapping['har_entry_index']
            require(type(entry_index) is int and 0 <= entry_index < len(entries)
                    and entry_index not in used_entries,
                    name + ' HAR entry index is invalid or reused')
            require(mapping['transport'] in
                    {'BUSINESS_HANDLER', 'API_GATEWAY_AUTHORIZER'},
                    name + ' transport is invalid')
            subject = mapping['subject_sha256']
            require(subject is None or checker._hash(subject),
                    name + ' subject hash is invalid')
            used_entries.add(entry_index)
            exchanges.append(_har_exchange(
                entries[entry_index], index['api_origin'], mapping, audits,
                name + ' exchange ' + str(position)))
        output_cases[name] = {'snapshots': snapshots, 'exchanges': exchanges}
    require(used_entries == set(range(len(entries))),
            'HAR capture contains unmapped or missing entries')
    require(not audits, 'Audit capture contains unmapped records')
    require({item.name for item in snapshots_root.iterdir()} == snapshot_files,
            'Snapshot capture entries differ')

    observations = {key: index[key] for key in
        ('schema_version', 'source_commit', 'account_a', 'region', 'api_origin',
         'reviewer_subject_sha256')}
    observations['scope'] = checker.OBSERVATION_SCOPE
    observations['cases'] = output_cases
    result = checker.check(positive, observations)

    output.parent.mkdir(parents=True, exist_ok=True)
    stage = Path(tempfile.mkdtemp(prefix='.' + output.name + '-',
                                  dir=output.parent))
    try:
        _write_json(stage / 'metadata.json',
                    {key: value for key, value in observations.items()
                     if key != 'cases'})
        for name, value in output_cases.items():
            case_root = stage / name
            case_root.mkdir()
            for index_number, snapshot in enumerate(value['snapshots']):
                _write_json(case_root / f'snapshot-{index_number}.json', snapshot)
            for index_number, exchange in enumerate(value['exchanges']):
                _write_json(case_root / f'exchange-{index_number}.json', exchange)
        collected = checker.collect(stage)
        require(collected == observations,
                'Assembled observation directory does not round-trip exactly')
        checker.check(positive, collected)
        stage.rename(output)
    except Exception:
        shutil.rmtree(stage)
        raise
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--positive-result', type=Path, required=True)
    parser.add_argument('--capture-dir', type=Path, required=True)
    parser.add_argument('--observation-dir', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args(argv)
    result = {'schema_version': '1.0', 'scope': ASSEMBLY_SCOPE,
        'result': 'BLOCKED', 'status': 'NOT_READY',
        'checked_at': datetime.now(timezone.utc).isoformat(),
        'aws_execution': 'NOT_RUN_BY_THIS_ASSEMBLER',
        'browser_or_human_action': 'NOT_RUN_BY_THIS_ASSEMBLER',
        'product_ready': False, 'gates_promoted': False}
    try:
        positive = checker.load(args.positive_result, checker.MAX_POSITIVE_BYTES)
        verified = assemble(args.capture_dir, args.observation_dir, positive)
        result = dict(verified, scope=ASSEMBLY_SCOPE,
                      assembled_observation_scope=checker.OBSERVATION_SCOPE,
                      aws_execution='NOT_RUN_BY_THIS_ASSEMBLER',
                      browser_or_human_action='NOT_RUN_BY_THIS_ASSEMBLER')
    except (OSError, ValueError, TypeError, KeyError, IndexError,
            json.JSONDecodeError) as exc:
        result['error'] = {'type': type(exc).__name__,
                           'message': str(exc)[:1000]}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    _write_json(args.output, result)
    print(json.dumps({'scope': result['scope'], 'result': result['result'],
                      'status': result['status']}), flush=True)
    return 0 if result['result'] == 'PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
