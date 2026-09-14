#!/usr/bin/env python3
"""Check connected positive-path evidence before final negative/UX acceptance.

This offline checker performs no AWS, browser or human operation and never marks
ReadinessOps product-ready. It verifies that one payment object and one separate
non-payment object carry the required authenticated, version-bound positive path.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))

from authority_delta.business.acceptance import verify_acceptance_evidence


ACCOUNT_A = '538522204923'
REGION = 'ap-northeast-1'
READINESS_SCOPE = 'OFFLINE_CONNECTED_ACCEPTANCE_REPORT_CHAIN_NO_LIVE_ACTION'
CHECK_SCOPE = 'OFFLINE_D4_POSITIVE_PATH_EVIDENCE_NO_LIVE_ACTION_OR_PRODUCT_GATE'
MAX_INPUT_BYTES = 5_500_000


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


def load(path):
    raw = Path(path).read_bytes()
    require(len(raw) <= MAX_INPUT_BYTES, 'Evidence input exceeds the bounded size')
    value = json.loads(raw, object_pairs_hook=_object, parse_constant=_reject_constant)
    require(isinstance(value, dict), 'Evidence input must be a JSON object')
    return value


def documents(export, name):
    verified = verify_acceptance_evidence(export)
    return verified, {key: [item['document'] for item in verified[key]]
                      for key in ('evidence', 'assessments', 'decisions', 'actions',
                                  'delegations', 'applications', 'outcomes', 'history')}


def check_readiness(value):
    require(value.get('schema_version') == '1.0'
            and value.get('scope') == READINESS_SCOPE
            and value.get('result') == 'PASS'
            and value.get('status') == 'READY_FOR_AUTHENTICATED_ACCEPTANCE'
            and value.get('account_a') == ACCOUNT_A
            and re.fullmatch(r'[0-9]{12}', str(value.get('account_b', '')))
            and value['account_b'] != ACCOUNT_A
            and value.get('region') == REGION
            and value.get('live_acceptance') == 'NOT_RUN'
            and value.get('runtime_authority') == 'NOT_APPLIED_BY_THIS_CHECKER',
            'Connected readiness report is not the exact safe start gate')
    bindings = value.get('bindings')
    require(isinstance(bindings, dict)
            and re.fullmatch(r'[0-9a-f]{64}', str(bindings.get('registration_hash', ''))),
            'Connected readiness registration binding is missing')
    return value['account_b'], bindings['registration_hash']


def check_payment(export, items, account_b, registration_hash):
    head = export['object']['document']
    adapters = [item for item in export['available_adapters']
                if item.get('adapter_id') == 'vendor_payment'
                and item.get('connection_mode') == 'LIVE_CUSTOMER']
    require(len(adapters) == 1
            and adapters[0].get('target_account_id') == account_b
            and adapters[0].get('target_region') == REGION
            and adapters[0].get('registration_hash') == registration_hash,
            'Payment export does not use the readiness-bound live customer adapter')
    modes = {item['state']['run_id']: item['input_snapshot'].get('mode')
             for item in items['assessments']}
    first_run = (items['decisions'][0]['decision_pack'].get('run_id')
                 if items['decisions'] else None)
    require(modes.get(first_run) == 'INITIAL' and 'REASSESSMENT' in modes.values(),
            'Payment export lacks initial and reassessment runs')
    require(len(items['decisions']) >= 2,
            'Payment export lacks an official decision and later republication')
    require(any(item.get('status') == 'COMPLETED'
                and item.get('resolution_evidence')
                and item.get('reassessment_run_id') for item in items['actions']),
            'Payment export lacks an evidence-backed Action and linked reassessment')
    terminal = {item['state'].get('status') for item in items['applications']}
    require({'RECOVERED_CLOSED', 'VERIFIED'}.issubset(terminal),
            'Payment export lacks both closed recovery and verified application')
    verified = [item for item in items['applications']
                if item['state'].get('status') == 'VERIFIED']
    require(any({entry.get('outcome') for entry in item['publisher_result']['outcomes']}
                == {'ALLOW', 'DENY'}
                and {entry.get('outcome') for entry in item['publisher_result']['closed_outcomes']}
                == {'DENY'} for item in verified),
            'Payment export lacks deny-first and finite ALLOW/DENY canary evidence')
    verified_ids = {item['state']['application_id'] for item in verified}
    require(any(outcome.get('target', {}).get('kind') == 'AWS_APPLICATION'
                and outcome['target'].get('id') in verified_ids
                for outcome in items['outcomes']),
            'Payment export lacks a business Outcome bound to a verified application')
    applied = head.get('applied_binding')
    current = head.get('published_current')
    require(head.get('application_status') == 'VERIFIED'
            and applied and applied.get('runtime_authority_active') is True
            and current and applied.get('publication_id') == current.get('publication_id'),
            'Payment export does not show the current publication as verified and applied')
    required_events = {'EVIDENCE_ADDED', 'ASSESSMENT_QUEUED', 'HUMAN_APPROVE',
        'DECISION_PUBLISHED', 'ACTION_COMPLETED', 'AWS_DELEGATION_APPROVED',
        'AWS_APPLICATION_STARTED', 'OUTCOME_RECORDED'}
    require(required_events.issubset({item.get('kind') for item in items['history']}),
            'Payment authenticated history is incomplete')


def check_nonpayment(export, items):
    head = export['object']['document']
    require(export['object_id'] != '' and items['evidence'] and items['assessments']
            and items['decisions'], 'Non-payment common workflow is incomplete')
    first_run = items['decisions'][0]['decision_pack'].get('run_id')
    modes = {item['state']['run_id']: item['input_snapshot'].get('mode')
             for item in items['assessments']}
    require(modes.get(first_run) == 'INITIAL',
            'Non-payment workflow does not begin with an initial assessment')
    proposal = items['decisions'][-1]['decision_pack'].get('proposal', {})
    require({item.get('perspective') for item in proposal.get('decision_items', [])}
            == {'GOVERNANCE', 'VALUE', 'MODEL_ROUTING', 'PORTFOLIO'},
            'Non-payment decision does not contain all four perspectives')
    context = ' '.join(str(head.get(name, '')).lower()
                       for name in ('name', 'purpose', 'question'))
    customer_data_sharing = all(word in context for word in ('customer', 'data', 'shar'))
    require(customer_data_sharing
            and not any(word in context for word in ('payment', 'bank', 'amount', 'usd')),
            'Non-payment export is not the required customer-data-sharing scenario')
    require(not items['delegations'] and not items['applications']
            and head.get('applied_binding') is None
            and head.get('application_status') == 'NOT_APPLIED',
            'Non-payment common path incorrectly claims an execution adapter or authority')
    require({'OBJECT_CREATED', 'EVIDENCE_ADDED', 'ASSESSMENT_QUEUED',
             'HUMAN_APPROVE', 'DECISION_PUBLISHED'}.issubset(
                {item.get('kind') for item in items['history']}),
            'Non-payment authenticated publication history is incomplete')


def check(connected, payment, nonpayment):
    account_b, registration_hash = check_readiness(connected)
    payment, payment_items = documents(payment, 'payment')
    nonpayment, nonpayment_items = documents(nonpayment, 'nonpayment')
    require(payment['object_id'] != nonpayment['object_id'],
            'Payment and non-payment evidence must be separate objects')
    check_payment(payment, payment_items, account_b, registration_hash)
    check_nonpayment(nonpayment, nonpayment_items)
    return {'schema_version': '1.0', 'scope': CHECK_SCOPE, 'result': 'PASS',
        'status': 'READY_FOR_NEGATIVE_UX_AND_JUDGE_ACCEPTANCE',
        'checked_at': datetime.now(timezone.utc).isoformat(),
        'aws_execution': 'NOT_RUN_BY_THIS_CHECKER',
        'browser_or_human_action': 'NOT_RUN_BY_THIS_CHECKER',
        'product_ready': False, 'gates_promoted': False,
        'account_a': ACCOUNT_A, 'account_b': account_b, 'region': REGION,
        'payment_object_id': payment['object_id'],
        'payment_document_digest': payment['document_digest'],
        'nonpayment_object_id': nonpayment['object_id'],
        'nonpayment_document_digest': nonpayment['document_digest'],
        'verified': ['CONNECTED_READINESS_BINDING',
            'INITIAL_REASSESSMENT_REPUBLICATION',
            'ACTION_RESOLUTION_REASSESSMENT',
            'DISTINCT_DELEGATION_APPLICATION_OUTCOME',
            'DENY_FIRST_ALLOW_DENY_AND_CLOSED_RECOVERY',
            'NONPAYMENT_COMMON_PATH_NO_ADAPTER_AUTHORITY'],
        'remaining_required': ['RO_02_LIVE_INPUT_BOUNDARY',
            'RO_04_STALE_SCREEN_NEGATIVE', 'RO_12_AUTH_REPLAY_AND_RECONNECTION',
            'BROWSER_UX', 'JUDGE_ACCESS_AND_FIVE_MINUTE_DEMO',
            'RELEVANT_ORIGINAL_GATES_AND_GD', 'AUTHORIZED_SUBMISSION_CHECKS']}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--connected-readiness', type=Path, required=True)
    parser.add_argument('--payment-export', type=Path, required=True)
    parser.add_argument('--nonpayment-export', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args(argv)
    result = {'schema_version': '1.0', 'scope': CHECK_SCOPE, 'result': 'BLOCKED',
        'status': 'NOT_READY', 'checked_at': datetime.now(timezone.utc).isoformat(),
        'aws_execution': 'NOT_RUN_BY_THIS_CHECKER',
        'browser_or_human_action': 'NOT_RUN_BY_THIS_CHECKER',
        'product_ready': False, 'gates_promoted': False}
    try:
        result = check(load(args.connected_readiness), load(args.payment_export),
                       load(args.nonpayment_export))
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
