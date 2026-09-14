import copy
import unittest
import test_gate_a_worker as support
from authority_delta.import_replay import import_gate_a
from authority_delta.analysis import AnalysisRejected, prepare_analysis

class ImportReplayTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.helper=support.GateAWorkerTests();cls.helper.setUp()
        code,cls.report=cls.helper.run_worker()
        if code:raise RuntimeError('Local Gate A double failed')
        cls.fixtures=cls.helper.aws.fixtures
        cls.location={'bucket':'test-bucket','key':'evidence/test/report.json','version_id':'fixed-version'}

    @classmethod
    def tearDownClass(cls):cls.helper.doCleanups()

    def load(self,report):
        return import_gate_a(report,fixtures=self.fixtures,location=self.location,account=support.BINDING['account'],region=support.BINDING['region'])

    def test_full_worker_output_roundtrip_without_expected_answers(self):
        replays=self.load(self.report)
        source=prepare_analysis(self.fixtures,replays['V1'],replays['V2'])
        self.assertEqual(len(replays['V1'].observations),6)
        self.assertNotIn('expected',repr(source))
        self.assertIn('versionId=fixed-version',repr(source))

    def test_missing_duplicate_or_modified_calls_rejected(self):
        p=copy.deepcopy(self.report)
        index=next(i for i,c in enumerate(p['runtime_calls']) if c['label'].startswith('REPLAY-'))
        variants=[]
        q=copy.deepcopy(p);q['runtime_calls'].pop(index);variants.append(q)
        q=copy.deepcopy(p);q['runtime_calls'].append(q['runtime_calls'][index]);variants.append(q)
        for path,value in [(('response','release_definition_hash'),'0'*64),(('response','request_id'),'other'),(('response','evaluation','gateway_outcome'),'ALLOW'),(('response','identity','arn'),'arn:aws:sts::wrong:assumed-role/other/session'),(('api_evidence','request_id'),None)]:
            q=copy.deepcopy(p);target=q['runtime_calls'][index]
            for key in path[:-1]:target=target[key]
            target[path[-1]]=value;variants.append(q)
        for q in variants:
            with self.subTest(report=q.get('build_id')):
                with self.assertRaises(AnalysisRejected):self.load(q)

    def test_summary_is_insufficient(self):
        with self.assertRaises(AnalysisRejected):self.load({'result':'PASS','gate_a':'PASS','auth_01':'PASS','auth_02':'PASS','cleanup':{'status':'PASS'}})

if __name__=='__main__':unittest.main()
