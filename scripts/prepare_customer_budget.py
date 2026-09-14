#!/usr/bin/env python3
"""Reconcile only the confirmed account-B budget alerts; never deploy resources."""
import json
import subprocess
import sys

ACCOUNT = '062788795311'
NAME = 'readinessops-validation-monthly'
EMAIL = 'okada.shinji@solid-fdn.co.jp'


def aws(*args):
    result = subprocess.run(['aws', *args, '--region', 'us-east-1',
        '--output', 'json', '--no-cli-pager', '--cli-connect-timeout', '10',
        '--cli-read-timeout', '30'], text=True, capture_output=True)
    if result.returncode:
        raise RuntimeError(result.stderr.strip())
    return json.loads(result.stdout) if result.stdout.strip() else {}


def budget(operation, *args):
    return aws('budgets', operation, '--account-id', ACCOUNT, '--budget-name', NAME, *args)


def notification(kind, threshold):
    return {'NotificationType': kind, 'ComparisonOperator': 'GREATER_THAN',
            'Threshold': threshold, 'ThresholdType': 'PERCENTAGE'}


def read_notifications():
    items = budget('describe-notifications-for-budget')['Notifications']
    values = {}
    for item in items:
        if (item.get('ComparisonOperator') != 'GREATER_THAN'
                or item.get('ThresholdType', 'PERCENTAGE') != 'PERCENTAGE'):
            raise RuntimeError('Unexpected notification comparison or threshold type; no normalization allowed.')
        key = (item['NotificationType'], float(item['Threshold']))
        if key in values:
            raise RuntimeError('Duplicate notification.')
        values[key] = item
    return values


def prepare():
    if aws('sts', 'get-caller-identity').get('Account') != ACCOUNT:
        raise RuntimeError('Wrong account. No budget change started.')
    if aws('iam', 'get-account-summary').get('SummaryMap', {}).get('AccountMFAEnabled') != 1:
        raise RuntimeError('Root MFA required. No budget change started.')
    value = budget('describe-budget')['Budget']
    if (value.get('BudgetType'), value.get('TimeUnit'),
        value.get('BudgetLimit', {}).get('Unit'),
        float(value.get('BudgetLimit', {}).get('Amount', -1))) != ('COST', 'MONTHLY', 'USD', 30.0):
        raise RuntimeError('Expected existing monthly USD 30 budget; amount is never changed.')
    current = read_notifications()
    required = {('ACTUAL', 20.0), ('ACTUAL', 50.0), ('ACTUAL', 100.0), ('FORECASTED', 80.0)}
    allowed = required | {('ACTUAL', 85.0), ('FORECASTED', 100.0)}
    if (not set(current) <= allowed or ('ACTUAL', 100.0) not in current
            or sum(k in current for k in [('ACTUAL', 85.0), ('ACTUAL', 50.0)]) != 1
            or sum(k in current for k in [('FORECASTED', 100.0), ('FORECASTED', 80.0)]) != 1):
        raise RuntimeError('Unrecognized budget state; preserve it and stop.')
    # Preflight every existing subscriber before any write; preserve update subscribers.
    for kind, threshold in current:
        recipients = budget('describe-subscribers-for-notification', '--notification',
                           json.dumps(notification(kind, threshold))).get('Subscribers', [])
        if not any(r.get('SubscriptionType') == 'EMAIL' and r.get('Address') == EMAIL for r in recipients):
            raise RuntimeError('Expected email subscriber absent; no budget change started.')
    for kind, old, new in [('ACTUAL', 85, 50), ('FORECASTED', 100, 80)]:
        if (kind, old) in current:
            budget('update-notification', '--old-notification', json.dumps(notification(kind, old)),
                   '--new-notification', json.dumps(notification(kind, new)))
    if ('ACTUAL', 20.0) not in current:
        budget('create-notification', '--notification', json.dumps(notification('ACTUAL', 20)),
               '--subscribers', json.dumps([{'SubscriptionType': 'EMAIL', 'Address': EMAIL}]))
    if set(read_notifications()) != required:
        raise RuntimeError('Final budget alert readback differs; do not deploy. Rerun safely to reconcile.')
    print('BUDGET_READY: account 062788795311; USD 30/month; actual 20/50/100%, forecast 80%.')
    print('Budget alerts do not enforce a spending cap. No infrastructure deployed.')


if __name__ == '__main__':
    try:
        prepare()
    except (RuntimeError, KeyError, ValueError, OSError) as exc:
        print('STOP: ' + str(exc), file=sys.stderr)
        sys.exit(1)
