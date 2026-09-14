import copy
import unittest
from scripts.deploy_customer_connector import runtime_policy_matches


class RuntimePolicyOrderTests(unittest.TestCase):
    def setUp(self):
        deployer = 'arn:aws:iam::062788795311:role/ReadinessOpsAuthorityDeltaDeployer'
        canary = 'arn:aws:iam::062788795311:role/authority-delta-customer-canary'
        invocation = 'arn:aws:iam::062788795311:role/authority-delta-customer-invocation'
        runtime = 'arn:aws:bedrock-agentcore:ap-northeast-1:062788795311:runtime/authority_delta_vendor_v2-CkJuzbCxaF'
        self.expected = {'Version': '2012-10-17', 'Statement': [
            {'Sid': 'PermitOnlyDeploymentCanaryAndInvocation', 'Effect': 'Allow',
             'Principal': {'AWS': [deployer, canary, invocation]},
             'Action': ['bedrock-agentcore:InvokeAgentRuntime', 'bedrock-agentcore:StopRuntimeSession'], 'Resource': runtime},
            {'Sid': 'DenyOtherCallers', 'Effect': 'Deny', 'Principal': '*',
             'Action': ['bedrock-agentcore:' + name for name in (
                 'InvokeAgentRuntime', 'InvokeAgentRuntimeForUser', 'InvokeAgentRuntimeCommand',
                 'InvokeAgentRuntimeCommandShell', 'InvokeAgentRuntimeWithWebSocketStream',
                 'InvokeAgentRuntimeWithWebSocketStreamForUser', 'StopRuntimeSession')],
             'Resource': runtime, 'Condition': {'ArnNotEquals': {'aws:PrincipalArn': [deployer, canary, invocation]}}}]}
        self.observed = copy.deepcopy(self.expected)
        self.observed['Statement'][0]['Principal']['AWS'].reverse()

    def test_user_observed_order_passes_without_mutating_evidence(self):
        original = copy.deepcopy(self.observed)
        self.assertNotEqual(self.observed, self.expected)
        self.assertTrue(runtime_policy_matches(self.observed, self.expected))
        self.assertEqual(self.observed, original)
        self.observed['Statement'][1]['Condition']['ArnNotEquals']['aws:PrincipalArn'].reverse()
        self.assertTrue(runtime_policy_matches(self.observed, self.expected))

    def test_real_authorization_differences_still_fail(self):
        changes = [
            lambda p: p['Statement'][0]['Principal']['AWS'].append('*'),
            lambda p: p['Statement'][0]['Principal']['AWS'].pop(),
            lambda p: p['Statement'][0]['Principal']['AWS'].append(p['Statement'][0]['Principal']['AWS'][0]),
            lambda p: p['Statement'][0].update(Resource='*'),
            lambda p: p['Statement'][0]['Action'].append('bedrock-agentcore:*'),
            lambda p: p['Statement'][1].update(Effect='Allow'),
            lambda p: p['Statement'][1]['Condition']['ArnNotEquals']['aws:PrincipalArn'].append('*'),
            lambda p: p['Statement'].pop(),
        ]
        for change in changes:
            value = copy.deepcopy(self.observed)
            change(value)
            with self.subTest(value=value):
                self.assertFalse(runtime_policy_matches(value, self.expected))
