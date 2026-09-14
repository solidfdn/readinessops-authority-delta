"""Regression for the user-returned DynamoDB empty sort-key ValidationException."""
import json
import unittest
import boto3
from botocore.stub import Stubber
from authority_delta.business.storage import DynamoStore
from authority_delta.business.jobs import dispatch_pending


class QueryRegression(unittest.TestCase):
    def setUp(self):
        self.client = boto3.client('dynamodb', region_name='ap-northeast-1',
                                   aws_access_key_id='LOCAL', aws_secret_access_key='LOCAL_TEST_ONLY')
        self.store = DynamoStore(self.client, {'jobs': 'JobsTable', 'app': 'AppTable'})

    def test_partition_only_outbox_and_owner_index(self):
        # The old code fails these SDK request assertions before reaching any response.
        for table, pk in [('jobs', 'OUTBOX'), ('app', 'OWNER#local-reviewer')]:
            with self.subTest(table=table), Stubber(self.client) as stub:
                stub.add_response('query', {'Items': []}, {
                    'TableName': self.store.tables[table], 'ConsistentRead': True,
                    'KeyConditionExpression': 'pk = :p',
                    'ExpressionAttributeValues': {':p': {'S': pk}}})
                self.assertEqual(self.store.query(table, pk), [])
                stub.assert_no_pending_responses()

    def test_real_adapter_dispatch_query_get_send_and_conditional_delete(self):
        message = {'run_id': 'run-local', 'input_hash': 'a' * 64}
        item = {'pk': {'S': 'OUTBOX'}, 'sk': {'S': 'run-local'},
                'data': {'S': json.dumps(message)}, 'version': {'N': '1'}}
        sqs = boto3.client('sqs', region_name='ap-northeast-1',
                           aws_access_key_id='LOCAL', aws_secret_access_key='LOCAL_TEST_ONLY')
        with Stubber(self.client) as ddb, Stubber(sqs) as queue:
            ddb.add_response('query', {'Items': [item]}, {
                'TableName': 'JobsTable', 'ConsistentRead': True, 'KeyConditionExpression': 'pk = :p',
                'ExpressionAttributeValues': {':p': {'S': 'OUTBOX'}}})
            ddb.add_response('get_item', {'Item': item}, {
                'TableName': 'JobsTable', 'ConsistentRead': True,
                'Key': {'pk': {'S': 'OUTBOX'}, 'sk': {'S': 'run-local'}}})
            queue.add_response('send_message', {'MessageId': 'local-only'}, {
                'QueueUrl': 'https://sqs.ap-northeast-1.amazonaws.com/123456789012/local',
                'MessageBody': json.dumps(message, sort_keys=True, separators=(',', ':'))})
            ddb.add_response('transact_write_items', {}, {'TransactItems': [{'Delete': {
                'TableName': 'JobsTable', 'ConditionExpression': '#v = :v',
                'ExpressionAttributeNames': {'#v': 'version'},
                'ExpressionAttributeValues': {':v': {'N': '1'}},
                'Key': {'pk': {'S': 'OUTBOX'}, 'sk': {'S': 'run-local'}}}}]})
            dispatch_pending(self.store, sqs, 'https://sqs.ap-northeast-1.amazonaws.com/123456789012/local')
            ddb.assert_no_pending_responses(); queue.assert_no_pending_responses()

    def test_prefix_and_pagination_preserve_exact_partition(self):
        for prefix in ['', 'EVIDENCE#']:
            with self.subTest(prefix=prefix), Stubber(self.client) as stub:
                args = {'TableName': 'AppTable', 'ConsistentRead': True,
                        'KeyConditionExpression': 'pk = :p',
                        'ExpressionAttributeValues': {':p': {'S': 'object-local'}}}
                if prefix:
                    args['KeyConditionExpression'] += ' AND begins_with(sk, :s)'
                    args['ExpressionAttributeValues'][':s'] = {'S': prefix}
                cursor = {'pk': {'S': 'object-local'}, 'sk': {'S': 'EVIDENCE#one'}}
                item = dict(cursor, data={'S': '{"value":1}'}, version={'N': '1'})
                stub.add_response('query', {'Items': [item], 'LastEvaluatedKey': cursor}, args)
                stub.add_response('query', {'Items': [item]}, dict(args, ExclusiveStartKey=cursor))
                self.assertEqual(len(self.store.query('app', 'object-local', prefix)), 2)
                stub.assert_no_pending_responses()

    def test_result_bound_is_retained(self):
        item = {'data': {'S': '{}'}, 'version': {'N': '1'}}
        with Stubber(self.client) as stub:
            stub.add_response('query', {'Items': [item, item]}, {
                'TableName': 'JobsTable', 'ConsistentRead': True, 'KeyConditionExpression': 'pk = :p',
                'ExpressionAttributeValues': {':p': {'S': 'OUTBOX'}}})
            with self.assertRaisesRegex(ValueError, 'Result limit reached'):
                self.store.query('jobs', 'OUTBOX', limit=1)


if __name__ == '__main__':
    unittest.main()
