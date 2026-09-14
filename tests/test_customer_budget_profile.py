import copy
import json
import unittest
from unittest.mock import patch
from scripts import prepare_customer_budget as setup
from scripts import launch_customer_foundation as foundation
from scripts import launch_customer_connector as connector


class BudgetTests(unittest.TestCase):
    def setUp(self):
        self.account, self.amount, self.mfa, self.email = setup.ACCOUNT, '30', 1, setup.EMAIL
        self.calls = []
        self.items = [setup.notification('ACTUAL', 85), setup.notification('ACTUAL', 100), setup.notification('FORECASTED', 100)]
        for item in self.items:
            item.pop('ThresholdType')

    def aws(self, *args):
        self.calls.append(args)
        if args[:2] == ('sts', 'get-caller-identity'):
            return {'Account': self.account}
        if args[:2] == ('iam', 'get-account-summary'):
            return {'SummaryMap': {'AccountMFAEnabled': self.mfa}}
        value = lambda flag: json.loads(args[args.index(flag) + 1])
        if args[1] == 'describe-budget':
            return {'Budget': {'BudgetType': 'COST', 'TimeUnit': 'MONTHLY', 'BudgetLimit': {'Unit': 'USD', 'Amount': self.amount}}}
        if args[1] == 'describe-notifications-for-budget':
            return {'Notifications': copy.deepcopy(self.items)}
        if args[1] == 'describe-subscribers-for-notification':
            return {'Subscribers': [{'SubscriptionType': 'EMAIL', 'Address': self.email}]}
        if args[1] == 'update-notification':
            old, new = value('--old-notification'), value('--new-notification')
            matches = [i for i, item in enumerate(self.items) if (item['NotificationType'], item['Threshold']) == (old['NotificationType'], old['Threshold'])]
            self.assertEqual(len(matches), 1)
            self.items[matches[0]] = new
            return {}
        if args[1] == 'create-notification':
            self.items.append(value('--notification'))
            return {}
        raise AssertionError(args)

    def test_observed_state_and_idempotent_repeat(self):
        with patch.object(setup, 'aws', side_effect=self.aws):
            setup.prepare()
            self.assertEqual(sum(c[1] == 'update-notification' for c in self.calls), 2)
            self.assertEqual(sum(c[1] == 'create-notification' for c in self.calls), 1)
            self.calls.clear()
            setup.prepare()
            self.assertFalse(any(c[1].startswith(('update-', 'create-', 'delete-')) for c in self.calls))

    def test_invalid_prerequisites_stop_before_write(self):
        for attr, value in [('account', connector.ACCOUNT_A), ('amount', '50'), ('mfa', 0), ('email', 'other@example.com')]:
            with self.subTest(attr=attr):
                self.setUp()
                setattr(self, attr, value)
                with patch.object(setup, 'aws', side_effect=self.aws), self.assertRaises(RuntimeError):
                    setup.prepare()
                self.assertFalse(any(c[1].startswith(('update-', 'create-', 'delete-')) for c in self.calls))

    def test_absolute_threshold_rejected(self):
        self.items[0]['ThresholdType'] = 'ABSOLUTE_VALUE'
        with patch.object(setup, 'aws', side_effect=self.aws), self.assertRaises(RuntimeError):
            setup.prepare()

    def test_partial_update_resumes(self):
        self.items[0] = setup.notification('ACTUAL', 50)
        with patch.object(setup, 'aws', side_effect=self.aws):
            setup.prepare()
        self.assertEqual(sum(c[1] == 'update-notification' for c in self.calls), 1)

    def test_both_launchers_accept_30_reject_50(self):
        class Cli:
            def run(_, *args):
                return self.aws(*args)
        self.items = [setup.notification('ACTUAL', n) for n in (20, 50, 100)] + [setup.notification('FORECASTED', 80)]
        for module in (foundation, connector):
            with patch.object(module, 'budget', side_effect=lambda cli, account, op: self.aws('budgets', op)):
                self.amount = '30'
                self.assertEqual(module.guard(Cli()), setup.ACCOUNT)
                self.amount = '50'
                with self.assertRaises(module.DeploymentError):
                    module.guard(Cli())

    def test_account_a_unchanged(self):
        self.assertEqual(connector.budget_profile(connector.ACCOUNT_A), ('ReadinessOps-Authority-Delta', 50.0))
        self.assertEqual(connector.budget_profile(setup.ACCOUNT), (setup.NAME, 30.0))
