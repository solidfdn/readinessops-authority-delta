from __future__ import annotations

import json
from pathlib import Path
import unittest

from scripts.build_registry_seed import build_transaction
from authority_delta.registry import FixtureBundle


ROOT = Path(__file__).resolve().parents[1]


def _actions(document: dict[str, object]) -> set[str]:
    found: set[str] = set()
    for statement in document["Statement"]:
        value = statement["Action"]
        found.update(value if isinstance(value, list) else [value])
    return found


class InfrastructureContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.template = json.loads((ROOT / "infra/customer-baseline/template.json").read_text(encoding="utf-8"))
        cls.resources = cls.template["Resources"]

    def test_gateway_is_iam_authenticated_and_policy_enforced(self) -> None:
        gateway = self.resources["Gateway"]["Properties"]
        self.assertEqual(gateway["AuthorizerType"], "AWS_IAM")
        self.assertEqual(gateway["ProtocolType"], "MCP")
        self.assertEqual(gateway["PolicyEngineConfiguration"]["Mode"], "ENFORCE")

    def test_initial_stack_has_no_permit_policy(self) -> None:
        policy_resources = [
            value for value in self.resources.values()
            if value["Type"] == "AWS::BedrockAgentCore::Policy"
        ]
        self.assertEqual(policy_resources, [])

    def test_gateway_role_has_required_policy_permissions_and_one_target(self) -> None:
        role = self.resources["GatewayExecutionRole"]["Properties"]
        actions = _actions(role["Policies"][0]["PolicyDocument"])
        self.assertTrue({
            "bedrock-agentcore:GetPolicyEngine",
            "bedrock-agentcore:AuthorizeAction",
            "bedrock-agentcore:PartiallyAuthorizeActions",
            "lambda:InvokeFunction",
        } <= actions)
        invoke_statement = next(
            item for item in role["Policies"][0]["PolicyDocument"]["Statement"]
            if item["Sid"] == "InvokeOnlySandboxTarget"
        )
        self.assertEqual(invoke_statement["Resource"], {"Fn::GetAtt": ["SandboxToolFunction", "Arn"]})

    def test_sandbox_role_cannot_write_registry(self) -> None:
        role = self.resources["SandboxToolRole"]["Properties"]
        statements = role["Policies"][0]["PolicyDocument"]["Statement"]
        registry = next(item for item in statements if item["Sid"] == "ReadImmutableRegistry")
        self.assertEqual(registry["Action"], "dynamodb:GetItem")

    def test_all_three_finite_tools_are_inline(self) -> None:
        inline = self.resources["SandboxToolsTarget"]["Properties"]["TargetConfiguration"]["Mcp"]["Lambda"]["ToolSchema"]["InlinePayload"]
        self.assertEqual(
            [item["Name"] for item in inline],
            ["prepare_vendor_payment", "update_vendor_bank", "export_credentials"],
        )

    def test_registry_seed_is_idempotent_and_refuses_same_id_with_new_payload(self) -> None:
        fixtures = FixtureBundle.load(ROOT / "fixtures/decision_cases.json")
        transaction = build_transaction(fixtures, "registry-table")
        self.assertEqual(len(transaction), 7)
        for operation in transaction:
            put = operation["Put"]
            self.assertEqual(put["TableName"], "registry-table")
            self.assertEqual(
                put["ConditionExpression"],
                "attribute_not_exists(request_id) OR payload = :payload",
            )
            self.assertEqual(put["Item"]["payload"], put["ExpressionAttributeValues"][":payload"])

    def test_g0_preflight_is_read_only_and_fails_on_account_mismatch(self) -> None:
        script = (ROOT / "scripts/aws_g0_preflight.sh").read_text(encoding="utf-8")
        self.assertIn("sts get-caller-identity", script)
        self.assertIn("EXPECTED_AWS_ACCOUNT_ID", script)
        self.assertIn('if [[ "${ACTUAL_ACCOUNT_ID}" != "${EXPECTED_ACCOUNT_ID}" ]]', script)
        self.assertIn("cloudformation describe-type", script)
        self.assertIn("cloudformation validate-template", script)
        self.assertIn("bedrock-agentcore-control list-gateways", script)
        self.assertIn("bedrock-agentcore-control list-policy-engines", script)
        self.assertNotIn("create-stack", script)
        self.assertNotIn("deploy", script)
        self.assertNotIn("create-policy-engine", script)

    def test_bootstrap_role_can_only_be_assumed_by_owned_codebuild_project(self) -> None:
        bootstrap = json.loads((ROOT / "infra/bootstrap/template.json").read_text(encoding="utf-8"))
        role = bootstrap["Resources"]["DeploymentRole"]["Properties"]
        self.assertEqual(role["MaxSessionDuration"], 3600)
        self.assertEqual(
            role["ManagedPolicyArns"],
            [{"Fn::Sub": "arn:${AWS::Partition}:iam::aws:policy/PowerUserAccess"}],
        )
        trust = role['AssumeRolePolicyDocument']['Statement']
        self.assertEqual(len(trust), 1)
        self.assertEqual(trust[0]['Principal'], {'Service': 'codebuild.amazonaws.com'})
        self.assertEqual(trust[0]['Condition']['StringEquals']['aws:SourceAccount'], {'Ref': 'AWS::AccountId'})
        self.assertIn('project/${BuildProjectName}', trust[0]['Condition']['StringEquals']['aws:SourceArn']['Fn::Sub'])
        project = bootstrap['Resources']['DeploymentProject']['Properties']
        self.assertEqual(project['ServiceRole'], {'Fn::GetAtt': ['DeploymentRole', 'Arn']})
        self.assertEqual(project['ConcurrentBuildLimit'], 1)
        self.assertEqual(project['TimeoutInMinutes'], 25)

    def test_bootstrap_role_cannot_manage_arbitrary_iam_roles(self) -> None:
        bootstrap = json.loads((ROOT / "infra/bootstrap/template.json").read_text(encoding="utf-8"))
        statements = bootstrap["Resources"]["DeploymentRole"]["Properties"]["Policies"][0]["PolicyDocument"]["Statement"]
        iam_management = next(item for item in statements if item["Sid"] == "ManageOnlyProjectRoles")
        pass_role = next(item for item in statements if item["Sid"] == "PassOnlyProjectRolesToRequiredServices")
        self.assertNotIn("*", iam_management["Resource"])
        self.assertNotIn("*", pass_role["Resource"])
        self.assertEqual(
            set(pass_role["Condition"]["StringEquals"]["iam:PassedToService"]),
            {"lambda.amazonaws.com", "bedrock-agentcore.amazonaws.com"},
        )


if __name__ == "__main__":
    unittest.main()
