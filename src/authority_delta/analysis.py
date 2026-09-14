"""Read-only analysis boundary. Model text can explain evidence, never grant authority."""
from __future__ import annotations

import copy
import json
from typing import Any

from .canonical import sha256_json
from .delta import build_decision_patch
from .domain import Judgment
from .replay import ReplayEvidence


class AnalysisRejected(ValueError):
    pass


def prepare_analysis(fixtures, before: ReplayEvidence, candidate: ReplayEvidence):
    """Select only source definitions, requests and observed facts, never test answers."""
    required = {case.case_id: case.request_id for case in fixtures.cases}
    for replay in (before, candidate):
        if replay.release_id not in fixtures.releases:
            raise AnalysisRejected("Unknown release")
        if replay.baseline_id != fixtures.raw['baseline_id'] or replay.schema_version != '1.0':
            raise AnalysisRejected("Replay baseline/version mismatch")
        if replay.release_definition_hash != sha256_json(fixtures.releases[replay.release_id].as_contract()):
            raise AnalysisRejected("Replay definition mismatch")
        if replay.request_registry_snapshot_hash != fixtures.request_registry_snapshot_hash:
            raise AnalysisRejected("Replay registry mismatch")
        ids = [item.case_id for item in replay.observations]
        if len(ids) != len(set(ids)) or set(ids) - required.keys():
            raise AnalysisRejected("Duplicate or unexpected observation")
        for item in replay.observations:
            if item.release_id != replay.release_id or item.request_id != required[item.case_id]:
                raise AnalysisRejected("Observation binding mismatch")
            if not item.evidence_refs or any(not isinstance(ref, str) or not ref for ref in item.evidence_refs):
                raise AnalysisRejected("Observation lacks evidence references")
    source = {
        'schema_version': '1.0', 'baseline_id': fixtures.raw['baseline_id'],
        'before_release_id': before.release_id, 'candidate_release_id': candidate.release_id,
        'definitions': {r.release_id: fixtures.releases[r.release_id].as_contract() for r in (before, candidate)},
        'approved_boundary': fixtures.approved_boundary.as_contract(),
        'requests': [{'case_id': c.case_id, 'request_id': c.request_id, 'request': copy.deepcopy(c.request)} for c in fixtures.cases],
        'replays': {'before': before.as_contract(), 'candidate': candidate.as_contract()},
    }
    source['input_hash'] = sha256_json(source)
    return source


class EvidenceReader:
    """No network, runtime invocation, publication, arbitrary paths or mutable handles."""
    def __init__(self, source):
        self._source = copy.deepcopy(source)
        digest = self._source.pop('input_hash')
        if sha256_json(self._source) != digest:
            raise AnalysisRejected("Analysis input digest mismatch")
        self._source['input_hash'] = digest
        self.reads = []

    def definitions(self):
        self.reads.append('definitions')
        return copy.deepcopy({'input_hash':self._source['input_hash'], 'definitions':self._source['definitions'], 'approved_boundary':self._source['approved_boundary'], 'manifests':self._source.get('manifests', {})})

    def observations(self):
        self.reads.append('observations')
        before={o['case_id']:o for o in self._source['replays']['before']['observations']}
        candidate={o['case_id']:o for o in self._source['replays']['candidate']['observations']}
        # Lossless join of observed data; no expected answers or changed-case filtering.
        return copy.deepcopy({'input_hash':self._source['input_hash'],
            'before_release_id':self._source['before_release_id'],
            'candidate_release_id':self._source['candidate_release_id'],
            'cases':{r['case_id']:{'request':r['request'], 'request_id':r['request_id'],
                'before':before.get(r['case_id']), 'candidate':candidate.get(r['case_id'])}
                for r in self._source['requests']}})

    def requests(self):
        self.reads.append('requests')
        return copy.deepcopy(self._source['requests'])


def _text(value, name):
    if not isinstance(value, str) or not 1 <= len(value.strip()) <= 3000 or not any(c.isalnum() for c in value):
        raise AnalysisRejected('Invalid ' + name)


def attach_analysis(*, source, before, candidate, proposal, reads,
                    decision_pack_id, boundary_version):
    """Verify every claimed change/counterexample and citation against complete replays.

    Validation is structural and factual, not a guarantee of the prose's quality.
    A human still decides whether to retain, narrow or reject authority.
    """
    patch = build_decision_patch(decision_pack_id=decision_pack_id,
        boundary_version=boundary_version, before=before, candidate=candidate)
    patch['analysis_status'] = 'REJECTED'
    try:
        EvidenceReader(source)  # immutable input digest check
        if source['replays'] != {'before': before.as_contract(), 'candidate': candidate.as_contract()}:
            raise AnalysisRejected('Analysis input does not bind these replays')
        required = {item['case_id'] for item in source['requests']}
        if any({o.case_id for o in replay.observations} != required for replay in (before, candidate)):
            raise AnalysisRejected('Incomplete replay coverage')
        if patch['status'] == 'HOLD':
            raise AnalysisRejected('Unknown or inconsistent replay evidence')
        if not {'definitions', 'observations', 'requests'} <= set(reads):
            raise AnalysisRejected('Agent did not read all evidence categories')
        keys = {'input_hash', 'summary', 'changes', 'counterexamples', 'recommendation', 'maintain_proposal'}
        if not isinstance(proposal, dict) or set(proposal) != keys:
            raise AnalysisRejected('Unexpected analysis schema')
        if proposal['input_hash'] != source['input_hash']:
            raise AnalysisRejected('Analysis input hash mismatch')
        _text(proposal['summary'], 'summary')
        _text(proposal['maintain_proposal'], 'maintain proposal')
        if len(proposal['maintain_proposal'].strip()) < 32:
            raise AnalysisRejected('Maintain proposal must explain how the approved boundary is retained')
        expected_rec = 'HUMAN_REVIEW' if patch['changes'] else 'NO_DECISION_CHANGE'
        if proposal['recommendation'] != expected_rec:
            raise AnalysisRejected('Recommendation disagrees with observed changes')
        by_case = {item['case_id']: item for item in patch['changes']}
        if not isinstance(proposal['changes'], list):
            raise AnalysisRejected('Changes must be a list')
        seen = set()
        for item in proposal['changes']:
            if not isinstance(item, dict) or set(item) != {'case_id', 'before_judgment', 'after_judgment', 'reason', 'definition_fields', 'evidence_refs'}:
                raise AnalysisRejected('Unexpected change schema')
            cid = item['case_id']
            if not isinstance(cid, str) or cid not in required:
                raise AnalysisRejected('Unknown change case_id: '+repr(cid))
            if cid in seen:
                raise AnalysisRejected('Duplicate change case_id: '+cid)
            if cid not in by_case:
                old_observation=next(o for o in before.observations if o.case_id==cid)
                new_observation=next(o for o in candidate.observations if o.case_id==cid)
                facts=next(r['request'] for r in source['requests'] if r['case_id']==cid)
                raise AnalysisRejected(f'Case {cid} is unchanged: observed before={old_observation.judgment.value}, candidate={new_observation.judgment.value}. Remove this case from changes. Request facts: '+json.dumps(facts,sort_keys=True))
            seen.add(cid)
            observed = by_case[cid]
            for key in ('before_judgment', 'after_judgment'):
                if item[key] != observed[key]:
                    raise AnalysisRejected(f'Case {cid}: {key} claimed={item[key]!r}, observed={observed[key]!r}. Copy the observed judgment without changing it.')
            _text(item['reason'], 'reason')
            refs = item['evidence_refs']
            if not isinstance(refs, list) or not refs or not all(isinstance(r, str) for r in refs) or not set(refs) <= set(observed['evidence_refs']):
                raise AnalysisRejected(f'Unsupported evidence citation for {cid}; observed references: '+json.dumps(observed['evidence_refs']))
            old = source['definitions'][before.release_id]
            new = source['definitions'][candidate.release_id]
            fields = item['definition_fields']
            if not isinstance(fields, list) or not fields or not all(isinstance(f, str) for f in fields):
                raise AnalysisRejected('Missing definition change citation')
            if any(f in ('release_id', 'description_change_only') or f not in old or f not in new or old[f] == new[f] for f in fields):
                raise AnalysisRejected('Definition field did not change')
        if seen != set(by_case):
            raise AnalysisRejected('Model omitted an observed change')
        counterexamples = proposal['counterexamples']
        if not isinstance(counterexamples, list) or not counterexamples:
            raise AnalysisRejected('Missing unchanged counterexample')
        unchanged = {o.case_id: o for o in before.observations if o.case_id not in by_case}
        counter_seen = set()
        for item in counterexamples:
            if not isinstance(item, dict) or set(item) != {'case_id', 'reason', 'evidence_refs'}:
                raise AnalysisRejected('Unexpected counterexample schema')
            cid = item['case_id']
            if not isinstance(cid, str) or cid in counter_seen or cid not in unchanged:
                raise AnalysisRejected('Counterexample is not an unchanged observation')
            counter_seen.add(cid)
            _text(item['reason'], 'counterexample reason')
            other = next(o for o in candidate.observations if o.case_id == cid)
            allowed = set(unchanged[cid].evidence_refs + other.evidence_refs)
            refs = item['evidence_refs']
            if not isinstance(refs, list) or not refs or not all(isinstance(r, str) for r in refs) or not set(refs) <= allowed:
                raise AnalysisRejected('Unsupported counterexample citation')
        patch.update(analysis_status='VALIDATED', analysis_evidence_hash=sha256_json(proposal),
            analysis=copy.deepcopy(proposal), analysis_input_hash=source['input_hash'])
    except (AnalysisRejected, KeyError, TypeError, ValueError, StopIteration) as exc:
        patch.update(status='HOLD', recommendation='HOLD', analysis_error=str(exc))
    return patch
