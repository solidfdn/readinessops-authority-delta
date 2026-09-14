"""Import a pinned Gate A report without executing agents or copying test expectations."""
from .canonical import sha256_json
from .domain import Judgment
from .replay import ReplayEvidence, ReplayObservation
from .analysis import AnalysisRejected


def import_gate_a(report, *, fixtures, location, account, region):
    if any(report.get(k) != 'PASS' for k in ('result', 'gate_a', 'auth_01', 'auth_02')):
        raise AnalysisRejected('Gate A did not pass')
    if report.get('cleanup', {}).get('status') != 'PASS':
        raise AnalysisRejected('Gate A cleanup is not confirmed')
    if report.get('account') != account or report.get('region') != region:
        raise AnalysisRejected('Gate A account/region mismatch')
    if report.get('baseline_id') != fixtures.raw['baseline_id']:
        raise AnalysisRejected('Gate A baseline mismatch')
    if not all(isinstance(location.get(k), str) and location[k] not in ('', 'null') for k in ('bucket', 'key', 'version_id')):
        raise AnalysisRejected('A pinned S3 object version is required')
    calls = report.get('runtime_calls')
    if not isinstance(calls, list):
        raise AnalysisRejected('Full Runtime observations are required')
    replays = {}
    for release in ('V1', 'V2'):
        binding = report.get('runtime_bindings', {}).get(release, {})
        prefix = f'arn:aws:bedrock-agentcore:{region}:{account}:runtime/'
        if not isinstance(binding.get('RuntimeArn'), str) or not binding['RuntimeArn'].startswith(prefix):
            raise AnalysisRejected('Runtime ARN does not bind this environment')
        if not binding.get('RuntimeVersion') or not binding.get('EndpointName') or binding.get('EndpointArn') != binding['RuntimeArn'] + '/runtime-endpoint/' + binding['EndpointName']:
            raise AnalysisRejected('Fixed Runtime endpoint binding missing')
        role = binding.get('ExecutionRoleArn', '')
        if not role.startswith(f'arn:aws:iam::{account}:role/'):
            raise AnalysisRejected('Execution role binding missing')
        observations = []
        for case in fixtures.cases:
            matched = [c for c in calls if c.get('label') == 'REPLAY-' + release + '-' + case.case_id]
            if len(matched) != 1:
                raise AnalysisRejected('Missing or duplicated replay call')
            call = matched[0]
            body = call.get('response', {})
            expected_payload = {'operation': 'evaluate', 'request_id': case.request_id}
            if call.get('status') != 'PASS' or call.get('release_id') != release or call.get('runtime') != binding or call.get('payload') != expected_payload:
                raise AnalysisRejected('Replay call binding mismatch')
            if not call.get('api_evidence', {}).get('request_id'):
                raise AnalysisRejected('AWS request ID missing')
            if any(body.get(k) != v for k, v in {'result':'OBSERVED', 'release_id':release, 'operation':'evaluate', 'request_id':case.request_id,
                'release_definition_hash':sha256_json(fixtures.releases[release].as_contract()),
                'request_registry_snapshot_hash':fixtures.request_registry_snapshot_hash}.items()):
                raise AnalysisRejected('Runtime response binding mismatch')
            identity = body.get('identity', {})
            role_name = role.rsplit('/', 1)[-1]
            if identity.get('account') != account or not identity.get('request_id') or not identity.get('arn', '').startswith(f'arn:aws:sts::{account}:assumed-role/{role_name}/'):
                raise AnalysisRejected('Runtime execution identity mismatch')
            evaluation = body.get('evaluation', {})
            if evaluation.get('gateway_outcome') != 'NOT_RUN':
                raise AnalysisRejected('Replay was not read-only')
            try:
                judgment = Judgment(evaluation.get('judgment'))
            except ValueError as exc:
                raise AnalysisRejected('Malformed judgment') from exc
            ref = f"s3://{location['bucket']}/{location['key']}?versionId={location['version_id']}#runtime_calls/{calls.index(call)}"
            observations.append(ReplayObservation(case.case_id, case.request_id, release, judgment, (ref,)))
        replays[release] = ReplayEvidence('1.0', fixtures.raw['baseline_id'], release,
            sha256_json(fixtures.releases[release].as_contract()), fixtures.request_registry_snapshot_hash, tuple(observations))
    if report['runtime_bindings']['V1']['ExecutionRoleArn'] == report['runtime_bindings']['V2']['ExecutionRoleArn']:
        raise AnalysisRejected('V1/V2 identities are not distinct')
    return replays
