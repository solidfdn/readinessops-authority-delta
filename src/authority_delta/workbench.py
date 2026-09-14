"""Build a review view from a pinned successful report, never from expected answers."""
import copy
from .analysis import EvidenceReader, prepare_analysis, attach_analysis
from .canonical import sha256_json
from .domain import Decision
from .policy_plan import build_policy_plan
from .replay import replay_from_contract


def review_document(report, fixtures, location):
    if any(report.get(k) != 'PASS' for k in ('result', 'semantic_runtime_proof', 'sem_01', 'sem_02')):
        raise ValueError('Successful semantic and benign evidence required')
    if report.get('state_unchanged') is not True or report.get('baseline_id') != fixtures.raw['baseline_id']:
        raise ValueError('Read-only baseline evidence required')
    if not all(location.get(k) for k in ('bucket', 'key', 'version_id')):
        raise ValueError('Pinned evidence version required')
    comparisons = {}
    for label, release in [('semantic', 'V2'), ('benign', 'V1-BENIGN')]:
        source = report['analysis_inputs'][label]
        EvidenceReader(source)
        before = replay_from_contract(source['replays']['before'])
        candidate = replay_from_contract(source['replays']['candidate'])
        if before.release_id != 'V1' or candidate.release_id != release:
            raise ValueError('Unexpected comparison releases')
        rebuilt = prepare_analysis(fixtures, before, candidate)
        for key, value in rebuilt.items():
            if key != 'input_hash' and source.get(key) != value:
                raise ValueError('Analysis input differs from trusted fixture or replay')
        calls = [c for c in report['analysis_calls'] if c.get('label') == label]
        if len(calls) != 1 or calls[0].get('status') != 'PASS':
            raise ValueError('Missing successful analysis call')
        call = calls[0]; response = call['response']
        if call.get('input_hash') != source['input_hash'] or response.get('input_hash') != source['input_hash']:
            raise ValueError('Analysis call input mismatch')
        if not call.get('api_evidence', {}).get('request_id') or response.get('result') != 'OBSERVED':
            raise ValueError('Missing live runtime evidence')
        if response.get('model_id') != report['analysis_model']['model_id'] or not response.get('model_calls'):
            raise ValueError('Missing model evidence')
        if any(c.get('http_status') != 200 or not c.get('request_id') for c in response['model_calls']):
            raise ValueError('Invalid model request evidence')
        patch = attach_analysis(source=source, before=before, candidate=candidate,
            proposal=response['proposal'], reads=response['reads'],
            decision_pack_id='DP-demo', boundary_version=1)
        if patch.get('analysis_status') != 'VALIDATED' or patch != report['patches'][label]:
            raise ValueError('Saved analysis does not reproduce validated patch')
        old = {o.case_id:o for o in before.observations}; new = {o.case_id:o for o in candidate.observations}
        comparisons[label] = {'before_release': before.release_id, 'candidate_release': candidate.release_id,
            'patch': patch, 'definitions': source['definitions'],
            'cases': [{'case_id': c.case_id, 'request': copy.deepcopy(c.request),
                'before': old[c.case_id].judgment.value, 'candidate': new[c.case_id].judgment.value,
                'evidence_refs': list(old[c.case_id].evidence_refs + new[c.case_id].evidence_refs)} for c in fixtures.cases],
            'model_id': response['model_id'], 'runtime_request_id': call['api_evidence']['request_id'],
            'proposal_attempt_count': len(response.get('attempts', [])) or None}
    # These are boundary-based forecasts, never presented as actual Gateway calls.
    previews = {d.value: build_policy_plan(fixtures, d) for d in Decision}
    result = {'schema_version':'1.0', 'baseline_id': fixtures.raw['baseline_id'],
        'mode':'REVIEW_PREVIEW_ONLY', 'approval_recorded':False, 'publication_status':'NOT_RUN',
        'connection_id': fixtures.raw.get('connection_id', 'development-account-a'),
        'connection_scope':'Single AWS development account; customer connection pending',
        'account': report['account'], 'region': report['region'], 'build_id': report['build_id'],
        'observed_at': report['completed_at'], 'source':copy.deepcopy(location),
        'source_report_hash':sha256_json(report), 'comparisons':comparisons, 'previews':previews,
        'auxiliary_cases':[{'case_id': c.case_id, 'request': copy.deepcopy(c.request)} for c in fixtures.auxiliary_cases]}
    result['document_hash'] = sha256_json(result)
    from .adapters.vendor_payment_view import presentation, ADAPTER
    from .readiness import build_workspace
    profile = presentation(fixtures)
    workspace = build_workspace(result, profile, {ADAPTER.adapter_id: ADAPTER})
    result['presentation'] = profile
    result['workspace'] = workspace
    result.pop('document_hash')
    result['document_hash'] = sha256_json(result)
    return result
