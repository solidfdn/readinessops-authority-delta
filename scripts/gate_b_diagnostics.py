"""Render saved semantic failures without running analysis or changing acceptance."""


def mapping(value):
    return value if isinstance(value, dict) else {}


def semantic_diagnostics(report):
    """Support old reports too; absent observations remain absent, never inferred PASS."""
    report = mapping(report)
    calls = report.get('analysis_calls', [])
    calls = calls if isinstance(calls, list) else []
    patches = mapping(report.get('patches'))
    acceptance = mapping(report.get('semantic_acceptance'))
    result = {}
    for label in ('semantic', 'benign'):
        patch = mapping(patches.get(label))
        call = next((mapping(c) for c in reversed(calls)
                     if mapping(c).get('label') == label), {})
        if not patch and not call:
            continue
        response = mapping(call.get('response'))
        proposal = mapping(response.get('proposal'))
        attempts = response.get('attempts', [])
        attempts = attempts if isinstance(attempts, list) else []
        check = mapping(acceptance.get(label))
        result[label] = {
            'runtime_call_status': call.get('status'),
            'runtime_result': response.get('result'),
            'model_id': response.get('model_id'),
            'runtime_error': response.get('error'),
            'proposal_attempt_count': len(attempts),
            'proposal_attempt_errors': [mapping(a).get('error') for a in attempts if mapping(a).get('status')=='REJECTED'],
            'analysis_status': patch.get('analysis_status'),
            'analysis_error': patch.get('analysis_error'),
            'patch_status': patch.get('status'),
            'affected_case_ids': patch.get('affected_case_ids'),
            'expected_case_ids': check.get('expected_case_ids'),
            'acceptance_status': check.get('status'),
            'reads': response.get('reads'),
            'proposal_recommendation': proposal.get('recommendation'),
            'rejected_proposal': proposal if response.get('result')=='HOLD' or patch.get('analysis_status')=='REJECTED' else None,
            'checkpoint': (mapping(report.get('checkpoints')).get(label + '-analysis') or mapping(report.get('checkpoints')).get(label + '-runtime-hold')),
        }
    return result
