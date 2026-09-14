#!/usr/bin/env python3
"""Build the one packaged VendorPayment registration from observed account-B values.

This tool does not discover or deploy AWS resources.  Its input is the bounded
output of the customer deployment/verification step.  Profiles and Cedar are
derived from the fixed fixture and adapter; callers cannot supply either.
"""
import argparse
import json
from pathlib import Path

from authority_delta.business.delegation import registration_with_hash
from authority_delta.decisions import Decision
from authority_delta.policy_plan import build_policy_plan
from authority_delta.registry import FixtureBundle


ROOT = Path(__file__).resolve().parents[1]
ACCOUNT_A = '538522204923'


def build(value, root=ROOT):
    required = {'schema_version', 'source_authority', 'connection_id',
        'target_account_id', 'target_region', 'gateway_arn', 'gateway_id',
        'policy_engine_id', 'target_id', 'target_name', 'runtime',
        'discovery_role_arn', 'publisher_invoke_role_arn', 'external_id',
        'publisher_function_arn', 'runtime_invoke_role_arn',
        'invocation_function_arn', 'canary_function_arn',
        'request_registry_table_name', 'sandbox_ledger_table_name'}
    if not isinstance(value, dict) or set(value) != required:
        raise ValueError('Observed customer binding fields differ')
    if value['schema_version'] != '1.0' or value['target_account_id'] == ACCOUNT_A:
        raise ValueError('A distinct observed account-B binding is required')
    fixtures = FixtureBundle.load(root / 'fixtures/decision_cases.json')
    profiles = {}
    for decision in (Decision.MAINTAIN, Decision.NARROW):
        plan = build_policy_plan(fixtures, decision)
        profiles[decision.value] = {
            'boundary_parameters': plan['resulting_boundary'],
            'allowed_request_ids': plan['allowed_request_ids'],
            'expected_outcomes': [{'request_id': item['request_id'],
                'expected_outcome': item['expected_policy_outcome']}
                for item in plan['expected_outcomes']]}
    registration = registration_with_hash({'schema_version': '1.0',
        'status': 'ACTIVE', 'connection_mode': 'LIVE_CUSTOMER',
        'adapter_id': 'vendor_payment', 'adapter_version': '1.0.0',
        'connection_id': value['connection_id'],
        'source_authority': value['source_authority'],
        'target_account_id': value['target_account_id'],
        'target_region': value['target_region'],
        'gateway_arn': value['gateway_arn'], 'gateway_id': value['gateway_id'],
        'policy_engine_id': value['policy_engine_id'],
        'target_id': value['target_id'], 'target_name': value['target_name'],
        'runtime': value['runtime'],
        'discovery_binding': {'role_arn': value['discovery_role_arn'],
            'external_id': value['external_id']},
        'publisher_binding': {'function_arn': value['publisher_function_arn'],
            'invoke_role_arn': value['publisher_invoke_role_arn'],
            'external_id': value['external_id']},
        'invocation_binding': {'function_arn': value['invocation_function_arn'],
            'invoke_role_arn': value['runtime_invoke_role_arn'],
            'external_id': value['external_id']},
        'probe_binding': {'function_arn': value['canary_function_arn'],
            'request_registry_table_name': value['request_registry_table_name'],
            'sandbox_ledger_table_name': value['sandbox_ledger_table_name']},
        'request_registry_snapshot_hash': fixtures.request_registry_snapshot_hash,
        'forbidden_tool_ids': ['export_credentials', 'update_vendor_bank'],
        'profiles': profiles})
    return {'schema_version': '1.0', 'registrations': [registration]}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--observed-binding', required=True)
    parser.add_argument('--output', required=True)
    args = parser.parse_args()
    observed = json.loads(Path(args.observed_binding).read_text(encoding='utf-8'))
    result = build(observed)
    output = Path(args.output)
    output.write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8')
    print(f'{output} registration={result["registrations"][0]["registration_hash"]}')


if __name__ == '__main__':
    main()
