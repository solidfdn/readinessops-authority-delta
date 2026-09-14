#!/usr/bin/env python3
"""Verify exported RO-07 invoke→stop evidence without performing an AWS action."""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
VENDORED_RFC8785 = ROOT / 'vendor' / 'wheels' / 'rfc8785-0.1.4-py3-none-any.whl'
if VENDORED_RFC8785.is_file():
    sys.path.insert(0, str(VENDORED_RFC8785))
sys.path.insert(0, str(ROOT / 'src'))

from authority_delta.business.acceptance import verify_acceptance_evidence
from authority_delta.canonical import sha256_json
from authority_delta.gateway_probe import policy_denial


SCOPE = 'OFFLINE_RO07_EXPORTED_LIVE_AUTHORITY_LIFECYCLE_NO_AWS_ACTION'
MAX_INPUT_BYTES = 5_500_000
HASH = re.compile(r'^[0-9a-f]{64}$')


def require(condition, message):
    if not condition:
        raise ValueError(message)


def _object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError('Duplicate JSON member is not permitted: ' + key)
        value[key] = item
    return value


def load(path):
    raw = Path(path).read_bytes()
    require(len(raw) <= MAX_INPUT_BYTES, 'Acceptance export exceeds the bounded size')
    value = json.loads(raw, object_pairs_hook=_object,
        parse_constant=lambda value: (_ for _ in ()).throw(
            ValueError('Non-finite JSON number is not permitted: ' + value)))
    require(isinstance(value, dict), 'Acceptance export must be one JSON object')
    return value


def _documents(export, name):
    return [item['document'] for item in export[name]]


def _aws_identifier(value):
    return isinstance(value, str) and bool(value) and not value.startswith('LOCAL_')


def check(raw):
    export = verify_acceptance_evidence(raw)
    require(export.get('schema_version') == '1.1',
            'RO-07 export must include lifecycle schema 1.1')
    head = export['object']['document']
    applications = _documents(export, 'applications')
    revocations = _documents(export, 'revocations')
    invocations = _documents(export, 'invocations')
    history = _documents(export, 'history')
    control = head.get('authority_control')
    require(isinstance(control, dict)
            and control.get('entry_status') == 'CLOSED'
            and control.get('status') == 'SUSPENDED_CONFIRMED'
            and control.get('policy_status') == 'REMOVED'
            and control.get('deny_status') == 'CONFIRMED'
            and control.get('runtime_authority_active') is False
            and head.get('application_status') == 'SUSPENDED_CONFIRMED',
            'Final authority is not closed with Policy removal and live DENY confirmed')
    application_id = control.get('application_id')
    application = next((item for item in applications
        if item['state'].get('application_id') == application_id), None)
    require(application is not None and application['state'].get('status') == 'VERIFIED',
            'Confirmed suspension lacks its historically verified application')
    candidate = application['candidate']
    require(candidate.get('connection_mode') == 'LIVE_CUSTOMER',
            'RO-07 evidence is not from the registered live customer connection')
    revocation = next((item for item in revocations
        if item['state'].get('revocation_id') == control.get('revocation_id')), None)
    require(revocation is not None
            and revocation['state'].get('status') == 'SUSPENDED_CONFIRMED',
            'Final control lacks the exact confirmed revocation record')
    request, removed = revocation['request'], revocation.get('publisher_result')
    require(isinstance(removed, dict)
            and removed.get('status') == 'POLICY_REMOVED_DENY_CONFIRMED'
            and removed.get('application_id') == application_id
            and removed.get('enforcement_digest') == candidate.get('enforcement_digest')
            and all(removed.get('checks', {}).get(name) is True for name in
                    ('owned_policy_readback', 'delete_intent_journaled',
                     'policy_absent_readback')),
            'Account-B Policy removal evidence is incomplete')
    publisher = removed.get('publisher_invocation', {})
    require(_aws_identifier(publisher.get('request_id'))
            and _aws_identifier(publisher.get('assume_role_request_id')),
            'Revocation was not transported through confirmed live AWS requests')
    registered = {item['request_id'] for item in candidate['expected_outcomes']}
    outcomes = removed.get('outcomes', [])
    require({item.get('request_id') for item in outcomes} == registered,
            'Revocation DENY proof does not cover the complete registered request set')
    for item in outcomes:
        evidence = item.get('evidence', {})
        runtime = candidate['execution_binding']['runtime']
        require(item.get('outcome') == 'DENY'
                and HASH.fullmatch(str(item.get('evidence_hash', '')))
                and item.get('evidence_hash') == sha256_json(evidence)
                and evidence.get('outcome') == 'DENY'
                and evidence.get('principal') == candidate['policy_binding']['principal_id']
                and _aws_identifier(evidence.get('runtime_request_id'))
                and evidence.get('before_ledger_hash') == evidence.get('after_ledger_hash')
                and all(isinstance(endpoint, dict)
                    and endpoint.get('endpoint_arn') == runtime['endpoint_arn']
                    and endpoint.get('live_version') == runtime['runtime_version']
                    and _aws_identifier(endpoint.get('request_id'))
                    for endpoint in (evidence.get('endpoint_before'),
                                     evidence.get('endpoint_after')))
                and policy_denial(evidence.get('gateway_response', {}),
                                  evidence.get('mcp_id')),
                'A registered request lacks real DENY and unchanged-ledger evidence')
    executed = []
    allowed = {item['request_id'] for item in candidate['expected_outcomes']
               if item['expected_outcome'] == 'ALLOW'}
    for item in invocations:
        state, result = item['state'], item.get('result')
        if (state.get('application_id') != application_id
                or state.get('status') != 'EXECUTED' or not isinstance(result, dict)):
            continue
        evidence, transport = (result.get('evidence', {}),
                               result.get('invocation_transport', {}))
        execution = evidence.get('execution', {}) if isinstance(evidence, dict) else {}
        runtime = candidate['execution_binding']['runtime']
        endpoints = (evidence.get('endpoint_before'), evidence.get('endpoint_after'))
        if (state.get('request_id') in allowed
                and result.get('outcome') == 'ALLOW'
                and result.get('evidence_hash') == sha256_json(evidence)
                and execution.get('status') == 'PASS'
                and execution.get('outcome') == 'ALLOW'
                and execution.get('tool_result', {}).get('request_id') == state['request_id']
                and evidence.get('principal') == candidate['policy_binding']['principal_id']
                and _aws_identifier(evidence.get('runtime_request_id'))
                and _aws_identifier(execution.get('aws_request_id'))
                and _aws_identifier(transport.get('request_id'))
                and _aws_identifier(transport.get('assume_role_request_id'))
                and all(isinstance(endpoint, dict)
                    and endpoint.get('endpoint_arn') == runtime['endpoint_arn']
                    and endpoint.get('live_version') == runtime['runtime_version']
                    and _aws_identifier(endpoint.get('request_id'))
                    for endpoint in endpoints)):
            executed.append(item)
    require(executed, 'No exact live normal invocation completed under this authority')
    accepted_at = min(item['state']['accepted_at'] for item in executed)
    require(datetime.fromisoformat(accepted_at)
            <= datetime.fromisoformat(request['requested_at']),
            'Normal invocation was not accepted before the authority entry closed')
    require(any(item.get('kind') == 'AWS_AUTHORITY_STOP_REQUESTED'
                and item.get('details', {}).get('revocation_id') == request['revocation_id']
                for item in history),
            'Authenticated stop/expiry history is missing')
    return {'schema_version': '1.0', 'scope': SCOPE, 'result': 'PASS',
        'status': 'RO07_LIVE_AUTHORITY_LIFECYCLE_CONFIRMED',
        'checked_at': datetime.now(timezone.utc).isoformat(),
        'aws_execution': 'NOT_RUN_BY_THIS_CHECKER',
        'source_evidence': 'AUTHENTICATED_AWS_ORIGIN_EXPORT',
        'object_id': export['object_id'], 'application_id': application_id,
        'revocation_id': request['revocation_id'],
        'executed_invocation_count': len(executed),
        'denied_request_count': len(outcomes),
        'document_digest': export['document_digest']}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--acceptance-export', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args(argv)
    result = {'schema_version': '1.0', 'scope': SCOPE, 'result': 'BLOCKED',
        'status': 'NOT_CONFIRMED', 'checked_at': datetime.now(timezone.utc).isoformat(),
        'aws_execution': 'NOT_RUN_BY_THIS_CHECKER'}
    try:
        result = check(load(args.acceptance_export))
    except (OSError, ValueError, TypeError, KeyError, IndexError,
            json.JSONDecodeError) as exc:
        result['error'] = {'type': type(exc).__name__, 'message': str(exc)[:1200]}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, ensure_ascii=False, indent=2,
                                      allow_nan=False) + '\n', encoding='utf-8')
    print(json.dumps({'scope': result['scope'], 'result': result['result'],
                      'status': result['status']}), flush=True)
    return 0 if result['result'] == 'PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
