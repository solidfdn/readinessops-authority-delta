import copy
from dataclasses import replace
from pathlib import Path
import unittest

from authority_delta.analysis import AnalysisRejected, EvidenceReader, prepare_analysis, attach_analysis
from authority_delta.delta import build_decision_patch
from authority_delta.registry import FixtureBundle
from authority_delta.replay import run_replay
from authority_delta.domain import Judgment

ROOT = Path(__file__).resolve().parents[1]

class AnalysisTests(unittest.TestCase):
    def setUp(self):
        self.fixtures = FixtureBundle.load(ROOT / 'fixtures/decision_cases.json')
        self.before = run_replay(self.fixtures, 'V1')
        self.candidate = run_replay(self.fixtures, 'V2')
        self.source = prepare_analysis(self.fixtures, self.before, self.candidate)

    def proposal(self, candidate=None):
        candidate = candidate or self.candidate
        source = prepare_analysis(self.fixtures, self.before, candidate)
        patch = build_decision_patch(decision_pack_id='DP-test', boundary_version=1, before=self.before, candidate=candidate)
        old, new = self.fixtures.releases['V1'].as_contract(), self.fixtures.releases[candidate.release_id].as_contract()
        fields = [k for k in old if k not in ('release_id', 'description_change_only') and old[k] != new[k]]
        changes = [dict(change, definition_fields=fields) for change in patch['changes']]
        unchanged = next(o for o in self.before.observations if o.case_id not in patch['affected_case_ids'])
        return {'input_hash':source['input_hash'], 'summary':'Local test explanation, not an LLM observation.', 'changes':changes,
            'counterexamples':[{'case_id':unchanged.case_id,'reason':'Observed judgment did not change.', 'evidence_refs':list(unchanged.evidence_refs)}],
            'maintain_proposal':'Retain the approved boundary; this proposal grants no authority.', 'recommendation':'HUMAN_REVIEW' if changes else 'NO_DECISION_CHANGE'}

    def attach(self, proposal, candidate=None, reads=None):
        candidate = candidate or self.candidate
        return attach_analysis(source=prepare_analysis(self.fixtures, self.before, candidate), before=self.before, candidate=candidate,
            proposal=proposal, reads=['definitions','observations','requests'] if reads is None else reads,
            decision_pack_id='DP-test',boundary_version=1)

    def test_valid_observed_delta(self):
        out = self.attach(self.proposal())
        self.assertEqual(out['analysis_status'], 'VALIDATED')
        self.assertEqual(out['affected_case_ids'], ['P-002'])
        self.assertEqual(out['status'], 'REVIEW_REQUIRED')

    def test_benign_zero_changes(self):
        benign = run_replay(self.fixtures, 'V1-BENIGN')
        out = self.attach(self.proposal(benign), benign)
        self.assertEqual(out['status'], 'NO_DECISION_CHANGE')
        self.assertEqual(out['affected_case_ids'], [])

    def test_input_excludes_expectations_and_mutation_isolated(self):
        self.assertNotIn('expected', repr(self.source))
        reader = EvidenceReader(self.source)
        value = reader.definitions(); value.clear()
        self.assertTrue(reader.definitions())
        self.assertFalse(hasattr(reader,'invoke_runtime'))
        self.assertFalse(hasattr(reader,'publish'))

    def test_unknown_and_missing_hold_even_when_other_case_changed(self):
        for candidate in [replace(self.candidate, observations=self.candidate.observations[:-1]),
            replace(self.candidate, observations=self.candidate.observations[:-1] + (replace(self.candidate.observations[-1], judgment=Judgment.UNKNOWN),))]:
            with self.subTest(candidate=candidate):
                out=self.attach(self.proposal(),candidate)
                self.assertEqual(out['status'],'HOLD')
                self.assertEqual(out['recommendation'],'HOLD')
                self.assertEqual(out['analysis_status'],'REJECTED')

    def test_duplicate_replay_rejected(self):
        duplicate=replace(self.candidate,observations=self.candidate.observations[:-1]+(self.candidate.observations[0],))
        with self.assertRaises(AnalysisRejected):prepare_analysis(self.fixtures,self.before,duplicate)
        self.assertEqual(build_decision_patch(decision_pack_id='d',boundary_version=1,before=self.before,candidate=duplicate)['status'],'HOLD')

    def test_malformed_or_unsupported_proposals_hold(self):
        original=self.proposal()
        def change(key,value):
            p=copy.deepcopy(original);p['changes'][0][key]=value;return p
        invalid=[{},None,dict(original,input_hash='0'*64),dict(original,changes=[]),
            dict(original,recommendation='ALLOW'),dict(original,counterexamples=[]),
            change('evidence_refs',['made-up-evidence']),change('definition_fields',['release_id']),
            change('after_judgment','DO_NOT_DELEGATE'),change('case_id','P-001'),change('reason',''),
            dict(original,changes=original['changes']*2),dict(original,publish=True)]
        for proposal in invalid:
            with self.subTest(proposal=proposal):self.assertEqual(self.attach(proposal)['status'],'HOLD')

    def test_skipped_tool_read_holds(self):
        self.assertEqual(self.attach(self.proposal(),reads=['observations'])['status'],'HOLD')

    def test_modified_input_hash_rejected(self):
        self.source['requests'].clear()
        with self.assertRaises(AnalysisRejected):EvidenceReader(self.source)

    def test_joined_observations_keep_each_case_facts_and_replays_together(self):
        source=copy.deepcopy(self.source)
        source['replays']['candidate']['observations'].reverse()
        from authority_delta.canonical import sha256_json
        source.pop('input_hash');source['input_hash']=sha256_json(source)
        reader=EvidenceReader(source);joined=reader.observations()
        self.assertEqual(len(joined['cases']),6)
        for case in source['requests']:
            row=joined['cases'][case['case_id']]
            self.assertEqual(row['request'],case['request'])
            self.assertEqual(row['before']['case_id'],case['case_id'])
            self.assertEqual(row['candidate']['case_id'],case['case_id'])
        self.assertNotIn('expected',repr(joined));self.assertNotIn('changed_case',repr(joined))
        joined['cases'].clear();self.assertEqual(len(reader.observations()['cases']),6)

    def test_cannot_attach_to_different_replays(self):
        out=attach_analysis(source=self.source,before=self.before,candidate=run_replay(self.fixtures,'V1-BENIGN'),
            proposal=self.proposal(),reads=['definitions','observations','requests'],decision_pack_id='d',boundary_version=1)
        self.assertEqual(out['status'],'HOLD')

if __name__ == '__main__':unittest.main()
