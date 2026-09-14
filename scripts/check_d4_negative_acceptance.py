#!/usr/bin/env python3
"""Verify private D4 negative HTTP/audit/export evidence without live action.

The checker does not call AWS, a browser or the product API.  It consumes an
already-passed positive-path result plus a private observation file.  Raw request
and response bodies, subjects and logs remain input-only; the output contains only
safe hashes and cannot mark the product ready or promote a gate.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))

from authority_delta.business.acceptance import verify_acceptance_evidence


ACCOUNT_A = '538522204923'
REGION = 'ap-northeast-1'
POSITIVE_SCOPE = 'OFFLINE_D4_POSITIVE_PATH_EVIDENCE_NO_LIVE_ACTION_OR_PRODUCT_GATE'
OBSERVATION_SCOPE = 'PRIVATE_D4_NEGATIVE_HTTP_AUDIT_EXPORT_OBSERVATIONS'
CHECK_SCOPE = 'OFFLINE_D4_NEGATIVE_CORRELATION_NO_LIVE_ACTION_OR_PRODUCT_GATE'
MAX_POSITIVE_BYTES = 200_000
MAX_OBSERVATION_BYTES = 48_000_000
MAX_HTTP_BODY_BYTES = 3_000_000
INSTRUCTION_MARKER = 'D4_UNTRUSTED_INSTRUCTION_MARKER_20260912'
INSTRUCTION_TEXT = (ROOT / 'fixtures' / 'd4-instruction-boundary.txt').read_text(
    encoding='utf-8')
CASES = {
    'ro02_unreadable_evidence',
    'ro02_instruction_reconnect',
    'ro04_stale_revision',
    'ro04_old_receipt',
    'ro12_signed_out',
    'ro12_foreign_subject',
    'ro12_missing_scope',
    'ro12_replay_conflict',
}
CASE_COUNTS = {
    'ro02_unreadable_evidence': (3, 2),
    'ro02_instruction_reconnect': (3, 2),
    'ro04_stale_revision': (2, 1),
    'ro04_old_receipt': (2, 1),
    'ro12_signed_out': (2, 1),
    'ro12_foreign_subject': (2, 1),
    'ro12_missing_scope': (2, 1),
    'ro12_replay_conflict': (4, 3),
}
COLLECTIONS = ('evidence', 'assessments', 'decisions', 'actions', 'delegations',
               'applications', 'outcomes', 'imports', 'history')
AUDIT_KEYS = {'schema_version', 'kind', 'request_id', 'method', 'resource',
              'has_item', 'object_id_sha256', 'subject_sha256',
              'command_request_id_sha256', 'http_status', 'code', 'result',
              'response_sha256'}
ROUTE = re.compile(
    r'/business/objects(?:/(o-[0-9a-f]{32})(?:/(evidence|runs|draft|review|publish|connection|delegation|applications|actions|outcomes|imports|interchange|acceptance-evidence)(?:/([A-Za-z0-9_-]+))?)?)?'
)


def require(condition, message):
    if not condition:
        raise ValueError(message)


def _reject_constant(value):
    raise ValueError('Non-finite JSON number is not permitted: ' + value)


def _object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError('Duplicate JSON member is not permitted: ' + key)
        value[key] = item
    return value


def _loads(raw, label):
    try:
        return json.loads(raw, object_pairs_hook=_object,
                          parse_constant=_reject_constant)
    except (json.JSONDecodeError, UnicodeError) as exc:
        raise ValueError(label + ' is not strict JSON') from exc


def load(path, maximum):
    raw = Path(path).read_bytes()
    require(len(raw) <= maximum, 'Evidence input exceeds the bounded size')
    value = _loads(raw, 'Evidence input')
    require(isinstance(value, dict), 'Evidence input must be a JSON object')
    return value


def collect(directory):
    """Collect an exact private case directory; no request is sent by this step."""
    root = Path(directory)
    require(root.is_dir() and not root.is_symlink(),
            'Observation input is not a regular directory')
    expected_root = {'metadata.json', *CASES}
    require({item.name for item in root.iterdir()} == expected_root,
            'Observation directory entries differ')
    metadata_path = root / 'metadata.json'
    require(metadata_path.is_file() and not metadata_path.is_symlink(),
            'Observation metadata is not a regular file')
    metadata = load(metadata_path, MAX_POSITIVE_BYTES)
    _exact(metadata, {'schema_version', 'scope', 'source_commit', 'account_a',
                      'region', 'api_origin', 'reviewer_subject_sha256'},
           'Observation metadata')
    total = metadata_path.stat().st_size
    cases = {}
    for name, (snapshot_count, exchange_count) in CASE_COUNTS.items():
        case_root = root / name
        require(case_root.is_dir() and not case_root.is_symlink(),
                name + ' is not a regular directory')
        snapshot_names = [f'snapshot-{index}.json'
                          for index in range(snapshot_count)]
        exchange_names = [f'exchange-{index}.json'
                          for index in range(exchange_count)]
        require({item.name for item in case_root.iterdir()}
                == set(snapshot_names + exchange_names),
                name + ' directory entries differ')
        snapshots = []
        exchanges = []
        for filename in snapshot_names:
            path = case_root / filename
            require(path.is_file() and not path.is_symlink(),
                    name + ' snapshot is not a regular file')
            total += path.stat().st_size
            require(total <= MAX_OBSERVATION_BYTES,
                    'Observation directory exceeds the bounded size')
            snapshots.append(load(path, 5_500_000))
        for filename in exchange_names:
            path = case_root / filename
            require(path.is_file() and not path.is_symlink(),
                    name + ' exchange is not a regular file')
            total += path.stat().st_size
            require(total <= MAX_OBSERVATION_BYTES,
                    'Observation directory exceeds the bounded size')
            exchanges.append(load(path, 6_200_000))
        cases[name] = {'snapshots': snapshots, 'exchanges': exchanges}
    return dict(metadata, cases=cases)


def _sha(value):
    return hashlib.sha256(value.encode('utf-8')).hexdigest()


def _hash(value):
    return isinstance(value, str) and re.fullmatch(r'[0-9a-f]{64}', value) is not None


def _exact(value, keys, label):
    require(isinstance(value, dict) and set(value) == set(keys),
            label + ' fields differ')


def _documents(export, label):
    try:
        verified = verify_acceptance_evidence(export)
    except (ValueError, TypeError, KeyError) as exc:
        raise ValueError(label + ' acceptance export is invalid: ' + str(exc)) from exc
    docs = {name: [item['document'] for item in verified[name]]
            for name in COLLECTIONS}
    docs['object'] = verified['object']['document']
    return verified, docs


def _case(value, label, snapshots, exchanges):
    _exact(value, {'snapshots', 'exchanges'}, label)
    require(isinstance(value['snapshots'], list)
            and len(value['snapshots']) == snapshots,
            label + ' snapshot count differs')
    require(isinstance(value['exchanges'], list)
            and len(value['exchanges']) == exchanges,
            label + ' HTTP exchange count differs')
    checked = [_documents(item, label + ' snapshot ' + str(index))
               for index, item in enumerate(value['snapshots'])]
    object_ids = {item[0]['object_id'] for item in checked}
    require(len(object_ids) == 1, label + ' snapshots mix objects')
    observed = [_exchange(item, label + ' exchange ' + str(index))
                for index, item in enumerate(value['exchanges'])]
    oid = next(iter(object_ids))
    require(all(item['object_id'] == oid for item in observed),
            label + ' HTTP path differs from its exported object')
    return checked, observed


def _exchange(value, label):
    _exact(value, {'transport', 'request', 'response', 'audit'}, label)
    transport = value['transport']
    require(transport in {'BUSINESS_HANDLER', 'API_GATEWAY_AUTHORIZER'},
            label + ' transport is invalid')
    request = value['request']
    response = value['response']
    _exact(request, {'gateway_request_id', 'method', 'path', 'body',
                     'subject_sha256'}, label + ' request')
    _exact(response, {'status', 'body'}, label + ' response')
    gateway_id = request['gateway_request_id']
    method = request['method']
    require(isinstance(gateway_id, str)
            and re.fullmatch(r'[A-Za-z0-9_-]{1,128}', gateway_id),
            label + ' Gateway request ID is unsafe')
    require(method in {'GET', 'POST'}, label + ' method is invalid')
    match = ROUTE.fullmatch(str(request['path']))
    require(match is not None, label + ' path is not a normalized business route')
    oid, resource, item = match.groups()
    resource = 'objects' if resource is None else resource
    subject = request['subject_sha256']
    require(subject is None or _hash(subject), label + ' subject hash is invalid')
    body = request['body']
    if method == 'POST':
        require(isinstance(body, str)
                and len(body.encode('utf-8')) <= MAX_HTTP_BODY_BYTES,
                label + ' POST body is missing or unbounded')
        request_value = _loads(body, label + ' request body')
        require(isinstance(request_value, dict), label + ' request body is not an object')
    else:
        require(body is None, label + ' GET request must not carry a body')
        request_value = None
    response_body = response['body']
    require(type(response['status']) is int and 100 <= response['status'] <= 599,
            label + ' HTTP status is invalid')
    require(isinstance(response_body, str)
            and len(response_body.encode('utf-8')) <= MAX_HTTP_BODY_BYTES,
            label + ' response body is missing or unbounded')
    response_value = _loads(response_body, label + ' response body')
    require(isinstance(response_value, dict), label + ' response body is not an object')

    audit = value['audit']
    if transport == 'API_GATEWAY_AUTHORIZER':
        require(audit is None and response['status'] == 401 and subject is None,
                label + ' authorizer rejection contract differs')
    else:
        _exact(audit, AUDIT_KEYS, label + ' audit')
        command_id = request_value.get('request_id') if request_value else None
        command_hash = (_sha(command_id) if isinstance(command_id, str)
                        and re.fullmatch(r'[A-Za-z0-9_-]{16,128}', command_id)
                        else None)
        code = ('OK' if response['status'] < 400 else
                response_value.get('code') if isinstance(response_value.get('code'), str)
                else 'FAILED')
        result = ('SUCCESS' if response['status'] < 400 else
                  'REJECTED' if response['status'] < 500 else 'UNCONFIRMED')
        require(audit == {
            'schema_version': '1.0', 'kind': 'BUSINESS_API_AUDIT',
            'request_id': gateway_id, 'method': method, 'resource': resource,
            'has_item': bool(item), 'object_id_sha256': _sha(oid) if oid else None,
            'subject_sha256': subject,
            'command_request_id_sha256': command_hash,
            'http_status': response['status'], 'code': code, 'result': result,
            'response_sha256': _sha(response_body),
        }, label + ' audit does not match the exact HTTP exchange')
    return {'transport': transport, 'method': method, 'path': request['path'],
            'object_id': oid, 'resource': resource, 'item': item,
            'subject_sha256': subject, 'request': request,
            'request_value': request_value, 'response': response,
            'response_value': response_value, 'audit': audit}


def _same_digest(left, right, label):
    require(left[0]['document_digest'] == right[0]['document_digest'],
            label + ' changed authenticated state')


def _map(items, key):
    return {item[key]: item for item in items}


def _unchanged_collections(before, after, changed, label):
    for name in COLLECTIONS:
        if name not in changed:
            require(before[1][name] == after[1][name],
                    label + ' changed ' + name)


def _head_delta(before, after, allowed, label):
    left, right = before[1]['object'], after[1]['object']
    require({k: v for k, v in left.items() if k not in allowed}
            == {k: v for k, v in right.items() if k not in allowed},
            label + ' changed an unrelated object field')
    return left, right


def _one_new(before, after, collection, key, label):
    old = _map(before[1][collection], key)
    new = _map(after[1][collection], key)
    require(set(old).issubset(new) and all(new[item] == value for item, value in old.items())
            and len(new) == len(old) + 1,
            label + ' did not add exactly one immutable ' + collection + ' record')
    return new[next(iter(set(new) - set(old)))]


def _evidence_add(before, after, exchange, status, label):
    require(exchange['method'] == 'POST' and exchange['resource'] == 'evidence'
            and exchange['response']['status'] == 200,
            label + ' is not a successful evidence mutation')
    added = _one_new(before, after, 'evidence', 'evidence_id', label)
    event = _one_new(before, after, 'history', 'event_id', label)
    response = exchange['response_value']
    require(response.get('evidence_id') == added.get('evidence_id')
            and response.get('extraction_status') == status
            and added.get('extraction_status') == status,
            label + ' evidence status or identity differs')
    require(event.get('kind') == 'EVIDENCE_ADDED'
            and event.get('details', {}).get('evidence_id') == added['evidence_id']
            and event.get('details', {}).get('extraction_status') == status,
            label + ' history does not bind the evidence result')
    left, right = _head_delta(before, after,
        {'record_revision', 'data_revision', 'generation', 'approval'}, label)
    require((right.get('record_revision'), right.get('data_revision'), right.get('generation'))
            == (left.get('record_revision') + 1, left.get('data_revision') + 1,
                left.get('generation') + 1)
            and left.get('approval') is None and right.get('approval') is None,
            label + ' object revision transition differs')
    _unchanged_collections(before, after, {'evidence', 'history'}, label)
    return added


def _assert_code(exchange, status, code, label):
    require(exchange['transport'] == 'BUSINESS_HANDLER'
            and exchange['response']['status'] == status
            and exchange['response_value'].get('code') == code,
            label + ' HTTP result differs')


def _authority_empty_and_equal(before, after, label):
    for state in (before, after):
        head = state[1]['object']
        require(head.get('draft') is None and head.get('approval') is None
                and head.get('published_current') is None
                and head.get('applied_binding') is None
                and head.get('delegation_approval') is None
                and head.get('latest_application') is None,
                label + ' fixture already contains authority state')
        require(not state[1]['decisions'] and not state[1]['delegations']
                and not state[1]['applications'] and not state[1]['outcomes'],
                label + ' fixture contains authority records')


def check_positive(value):
    require(value.get('schema_version') == '1.0'
            and value.get('scope') == POSITIVE_SCOPE
            and value.get('result') == 'PASS'
            and value.get('status') == 'READY_FOR_NEGATIVE_UX_AND_JUDGE_ACCEPTANCE'
            and value.get('account_a') == ACCOUNT_A
            and re.fullmatch(r'[0-9]{12}', str(value.get('account_b', '')))
            and value['account_b'] != ACCOUNT_A
            and value.get('region') == REGION
            and value.get('product_ready') is False
            and value.get('gates_promoted') is False,
            'Positive-path result is not the exact D4 start gate')
    required = {'RO_02_LIVE_INPUT_BOUNDARY', 'RO_04_STALE_SCREEN_NEGATIVE',
                'RO_12_AUTH_REPLAY_AND_RECONNECTION'}
    require(required.issubset(set(value.get('remaining_required', []))),
            'Positive-path result does not retain the negative requirements')
    return value['account_b']


def check(positive, observations):
    account_b = check_positive(positive)
    _exact(observations, {'schema_version', 'scope', 'source_commit', 'account_a',
                          'region', 'api_origin', 'reviewer_subject_sha256', 'cases'},
           'Observation manifest')
    reviewer = observations.get('reviewer_subject_sha256')
    require(observations.get('schema_version') == '1.0'
            and observations.get('scope') == OBSERVATION_SCOPE
            and observations.get('account_a') == ACCOUNT_A
            and observations.get('region') == REGION
            and re.fullmatch(r'[0-9a-f]{40}', str(observations.get('source_commit', '')))
            and re.fullmatch(r'https://[A-Za-z0-9.-]+', str(observations.get('api_origin', '')))
            and _hash(reviewer), 'Observation manifest binding differs')
    cases = observations['cases']
    require(isinstance(cases, dict) and set(cases) == CASES,
            'Observation case set differs')

    unreadable, exchanges = _case(cases['ro02_unreadable_evidence'],
                                  'RO-02 unreadable', 3, 2)
    _authority_empty_and_equal(unreadable[0], unreadable[1], 'RO-02 unreadable')
    added = _evidence_add(unreadable[0], unreadable[1], exchanges[0],
                          'NEEDS_INPUT', 'RO-02 unreadable add')
    _assert_code(exchanges[1], 422, 'NEEDS_INPUT', 'RO-02 unreadable run')
    require(exchanges[1]['resource'] == 'runs'
            and exchanges[1]['request_value'].get('evidence_ids') == [added['evidence_id']],
            'RO-02 unreadable run did not select only the unreadable evidence')
    _same_digest(unreadable[1], unreadable[2], 'RO-02 unreadable run rejection')

    instruction, exchanges = _case(cases['ro02_instruction_reconnect'],
                                   'RO-02 instruction/reconnect', 3, 2)
    before, queued, recovered = instruction
    _authority_empty_and_equal(before, recovered, 'RO-02 instruction/reconnect')
    start, read = exchanges
    require(start['transport'] == 'BUSINESS_HANDLER' and start['method'] == 'POST'
            and start['resource'] == 'runs' and start['response']['status'] == 202,
            'RO-02 instruction Run start differs')
    run_id = start['response_value'].get('run_id')
    require(isinstance(run_id, str) and re.fullmatch(r'run-[0-9a-f]{32}', run_id),
            'RO-02 instruction Run ID is invalid')
    # Assessments share object_id, so identify the single new Run explicitly.
    old_runs = {item['state']['run_id'] for item in before[1]['assessments']}
    queued_runs = {item['state']['run_id']: item for item in queued[1]['assessments']}
    require(set(queued_runs) == old_runs | {run_id},
            'RO-02 instruction Run was not added exactly once')
    before_runs = {item['state']['run_id']: item
                   for item in before[1]['assessments']}
    require(all(queued_runs[item] == value for item, value in before_runs.items()),
            'RO-02 instruction Run changed an earlier assessment')
    new_assessment = queued_runs[run_id]
    event = _one_new(before, queued, 'history', 'event_id',
                     'RO-02 instruction Run')
    require(new_assessment['state'].get('status') == 'QUEUED'
            and new_assessment.get('analysis') is None
            and event.get('kind') == 'ASSESSMENT_QUEUED'
            and event.get('details', {}).get('run_id') == run_id,
            'RO-02 instruction queued state differs')
    selected = start['request_value'].get('evidence_ids')
    evidence = {item['evidence_id']: item for item in before[1]['evidence']}
    require(isinstance(selected, list) and len(selected) == 1
            and selected[0] in evidence
            and evidence[selected[0]].get('text') == INSTRUCTION_TEXT
            and new_assessment['input_snapshot']['evidence'][0].get('text')
                == INSTRUCTION_TEXT
            and INSTRUCTION_MARKER in INSTRUCTION_TEXT,
            'RO-02 instruction marker is not bound to the Run input')
    left, right = _head_delta(before, queued,
        {'record_revision', 'generation', 'latest_run', 'draft', 'approval'},
        'RO-02 instruction Run')
    require(right.get('record_revision') == left.get('record_revision') + 1
            and right.get('generation') == left.get('generation') + 1
            and right.get('latest_run') == run_id
            and left.get('draft') is None and right.get('draft') is None
            and left.get('approval') is None and right.get('approval') is None,
            'RO-02 instruction Run head transition differs')
    _unchanged_collections(before, queued, {'assessments', 'history'},
                           'RO-02 instruction Run')
    require(read['transport'] == 'BUSINESS_HANDLER' and read['method'] == 'GET'
            and read['resource'] == 'runs' and read['item'] == run_id
            and read['response']['status'] == 200
            and read['response_value'].get('run_id') == run_id
            and read['response_value'].get('status') == 'REVIEW_REQUIRED',
            'RO-12 reconnect did not read the same completed Run')
    require(queued[1]['object'] == recovered[1]['object']
            and queued[1]['history'] == recovered[1]['history'],
            'RO-12 reconnect changed the object head or history')
    for name in COLLECTIONS:
        if name != 'assessments':
            require(queued[1][name] == recovered[1][name],
                    'RO-12 reconnect changed ' + name)
    final_runs = {item['state']['run_id']: item for item in recovered[1]['assessments']}
    require(set(final_runs) == set(queued_runs)
            and final_runs[run_id]['state'].get('status') == 'REVIEW_REQUIRED'
            and final_runs[run_id].get('analysis') is not None,
            'RO-12 reconnect export does not contain the same completed Run')
    require(all(final_runs[item] == value for item, value in before_runs.items()),
            'RO-12 reconnect changed an earlier assessment')
    expected_read = dict(final_runs[run_id]['state'])
    expected_read['analysis'] = final_runs[run_id]['analysis']
    expected_read['context'] = final_runs[run_id]['input_snapshot']['context']
    expected_read['mode'] = final_runs[run_id]['input_snapshot']['mode']
    expected_read['selected_evidence_ids'] = [item['evidence_id'] for item in
        final_runs[run_id]['input_snapshot']['evidence']]
    require(read['response_value'] == expected_read,
            'RO-12 reconnect HTTP body differs from the exported Run')

    stale, exchanges = _case(cases['ro04_stale_revision'],
                             'RO-04 stale revision', 2, 1)
    _assert_code(exchanges[0], 409, 'STALE_VERSION', 'RO-04 stale revision')
    require(exchanges[0]['resource'] == 'review'
            and exchanges[0]['request_value'].get('expected_revision')
                != stale[0][1]['object'].get('record_revision'),
            'RO-04 stale request did not carry an old revision')
    _same_digest(stale[0], stale[1], 'RO-04 stale revision rejection')

    old_receipt, exchanges = _case(cases['ro04_old_receipt'],
                                   'RO-04 old receipt', 2, 1)
    _assert_code(exchanges[0], 409, 'APPROVAL_REQUIRED', 'RO-04 old receipt')
    head = old_receipt[0][1]['object']
    current, draft = head.get('published_current'), head.get('draft')
    require(exchanges[0]['resource'] == 'publish' and current and draft
            and head.get('approval') is None
            and exchanges[0]['request_value'].get('receipt_id') == current.get('receipt_id')
            and draft.get('revision') > current.get('revision')
            and draft.get('digest') != current.get('digest'),
            'RO-04 old receipt is not bound to a later edited revision')
    _same_digest(old_receipt[0], old_receipt[1], 'RO-04 old receipt rejection')

    signed_out, exchanges = _case(cases['ro12_signed_out'],
                                  'RO-12 signed out', 2, 1)
    require(exchanges[0]['transport'] == 'API_GATEWAY_AUTHORIZER'
            and exchanges[0]['method'] == 'GET',
            'RO-12 signed-out request did not stop at the authorizer')
    _same_digest(signed_out[0], signed_out[1], 'RO-12 signed-out rejection')

    foreign, exchanges = _case(cases['ro12_foreign_subject'],
                               'RO-12 foreign subject', 2, 1)
    _assert_code(exchanges[0], 403, 'FORBIDDEN', 'RO-12 foreign subject')
    require(exchanges[0]['method'] == 'GET'
            and exchanges[0]['subject_sha256'] not in {None, reviewer},
            'RO-12 foreign subject hash is not distinct')
    _same_digest(foreign[0], foreign[1], 'RO-12 foreign-subject rejection')

    missing, exchanges = _case(cases['ro12_missing_scope'],
                               'RO-12 missing scope', 2, 1)
    _assert_code(exchanges[0], 403, 'SCOPE_REQUIRED', 'RO-12 missing scope')
    require(exchanges[0]['method'] == 'POST'
            and exchanges[0]['subject_sha256'] == reviewer,
            'RO-12 missing-scope request is not the reviewer mutation path')
    _same_digest(missing[0], missing[1], 'RO-12 missing-scope rejection')

    replay, exchanges = _case(cases['ro12_replay_conflict'],
                              'RO-12 replay/conflict', 4, 3)
    first, duplicate, conflict = exchanges
    for item in (first, duplicate, conflict):
        require(item['method'] == 'POST' and item['resource'] == 'evidence'
                and item['subject_sha256'] == reviewer,
                'RO-12 replay/conflict is not one reviewer evidence mutation')
    require(first['request']['body'] == duplicate['request']['body']
            and first['response'] == duplicate['response']
            and first['request']['gateway_request_id']
                != duplicate['request']['gateway_request_id'],
            'RO-12 replay did not recover the exact request and response')
    request_id = first['request_value'].get('request_id')
    require(isinstance(request_id, str)
            and duplicate['request_value'].get('request_id') == request_id
            and conflict['request_value'].get('request_id') == request_id
            and conflict['request_value'] != first['request_value'],
            'RO-12 request conflict does not reuse the ID with different input')
    _evidence_add(replay[0], replay[1], first, 'READY', 'RO-12 first mutation')
    _same_digest(replay[1], replay[2], 'RO-12 replay')
    _assert_code(conflict, 409, 'REQUEST_CONFLICT', 'RO-12 request conflict')
    _same_digest(replay[2], replay[3], 'RO-12 request conflict')

    groups = (unreadable, instruction, stale, old_receipt,
              signed_out, foreign, missing, replay)
    for group in groups:
        for state in group:
            owner = state[1]['object'].get('owner_sub')
            require(isinstance(owner, str) and _sha(owner) == reviewer,
                    'Acceptance export owner differs from the reviewer binding')
    all_objects = sorted({_sha(group[0][0]['object_id']) for group in groups})
    return {'schema_version': '1.0', 'scope': CHECK_SCOPE, 'result': 'PASS',
        'status': 'READY_FOR_REMAINING_BROWSER_AND_RELEASE_ACCEPTANCE',
        'checked_at': datetime.now(timezone.utc).isoformat(),
        'aws_execution': 'NOT_RUN_BY_THIS_CHECKER',
        'browser_or_human_action': 'NOT_RUN_BY_THIS_CHECKER',
        'product_ready': False, 'gates_promoted': False,
        'account_a': ACCOUNT_A, 'account_b': account_b, 'region': REGION,
        'source_commit': observations['source_commit'],
        'api_origin_sha256': _sha(observations['api_origin']),
        'reviewer_subject_sha256': reviewer,
        'object_id_sha256': all_objects,
        'verified': ['RO_02_UNREADABLE_INPUT_AND_INSTRUCTION_DATA_BOUNDARY',
            'RO_04_STALE_REVISION_AND_OLD_RECEIPT_STATE_INVARIANCE',
            'RO_12_AUTH_REJECTION_REPLAY_CONFLICT_AND_RUN_RECOVERY'],
        'remaining_required': ['LIVE_BROWSER_RO_02_04_12_OBSERVATION',
            'BROWSER_UX', 'JUDGE_ACCESS_AND_FIVE_MINUTE_DEMO',
            'RELEVANT_ORIGINAL_GATES_AND_GD', 'AUTHORIZED_SUBMISSION_CHECKS']}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--positive-result', type=Path, required=True)
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument('--observations', type=Path)
    source.add_argument('--observation-dir', type=Path)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args(argv)
    result = {'schema_version': '1.0', 'scope': CHECK_SCOPE, 'result': 'BLOCKED',
        'status': 'NOT_READY', 'checked_at': datetime.now(timezone.utc).isoformat(),
        'aws_execution': 'NOT_RUN_BY_THIS_CHECKER',
        'browser_or_human_action': 'NOT_RUN_BY_THIS_CHECKER',
        'product_ready': False, 'gates_promoted': False}
    try:
        observations = (load(args.observations, MAX_OBSERVATION_BYTES)
                        if args.observations else collect(args.observation_dir))
        result = check(load(args.positive_result, MAX_POSITIVE_BYTES), observations)
    except (OSError, ValueError, TypeError, KeyError, IndexError,
            json.JSONDecodeError) as exc:
        result['error'] = {'type': type(exc).__name__,
                           'message': str(exc)[:1000]}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, ensure_ascii=False, indent=2,
                                      allow_nan=False) + '\n', encoding='utf-8')
    print(json.dumps({'scope': result['scope'], 'result': result['result'],
                      'status': result['status']}), flush=True)
    return 0 if result['result'] == 'PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
