"""Regress the user's real READY responses, including absent targetVersion."""
import copy
import json
from pathlib import Path
from types import SimpleNamespace
import unittest
from scripts.gate_a import GateA
from authority_delta.evidence_json import encode_evidence

OBSERVATIONS=json.loads((Path(__file__).resolve().parents[1]/'evidence/aws/20260909-endpoints-user-reported.json').read_text())['observations']

class EndpointObservedTests(unittest.TestCase):
    def job(self, observation, response):
        binding=dict(observation['expected'],RuntimeId=observation['expected']['RuntimeArn'].split('/')[-1])
        job=GateA.__new__(GateA)
        job.report={}
        job.control=SimpleNamespace(get_agent_runtime_endpoint=lambda **kwargs:copy.deepcopy(response))
        return job,binding

    def test_observed_ready_without_target_is_accepted_and_preserved(self):
        for observation in OBSERVATIONS:
            job,binding=self.job(observation,observation['actual'])
            self.assertEqual(job.endpoint(binding),observation['actual'])
            saved=json.loads(encode_evidence(job.report))['endpoint_control_evidence'][binding['EndpointArn']]
            self.assertEqual(saved['status'],'PASS')
            self.assertNotIn('targetVersion',saved['response'])

    def test_matching_explicit_target_is_accepted(self):
        o=OBSERVATIONS[0];job,binding=self.job(o,dict(o['actual'],targetVersion='1'))
        job.endpoint(binding)

    def test_mismatch_or_missing_live_version_stays_closed_with_actual_evidence(self):
        o=OBSERVATIONS[0]
        variants=[dict(o['actual'],**{key:value}) for key,value in (
            ('targetVersion','2'),('targetVersion',None),('liveVersion','2'),
            ('status','UPDATING'),('name','DEFAULT'),('agentRuntimeArn','wrong'),('agentRuntimeEndpointArn','wrong'))]
        absent=copy.deepcopy(o['actual']);absent.pop('liveVersion');variants.append(absent)
        for response in variants:
            with self.subTest(response=response):
                job,binding=self.job(o,response)
                with self.assertRaisesRegex(ValueError,'binding mismatch'):
                    job.endpoint(binding)
                saved=json.loads(encode_evidence(job.report))['endpoint_control_evidence'][binding['EndpointArn']]
                self.assertEqual(saved['status'],'FAIL')
                self.assertEqual(saved['response'],response)
                self.assertTrue(saved['mismatches'])
