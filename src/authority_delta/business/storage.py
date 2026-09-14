"""Versioned records, conditional transactions and immutable blob references."""
from __future__ import annotations
import hashlib
import json
from dataclasses import dataclass


class Conflict(Exception):
    pass


def encode(value):
    return json.dumps(value, ensure_ascii=False, separators=(',', ':'), sort_keys=True, allow_nan=False).encode()


@dataclass
class Row:
    value: dict
    version: int


class DynamoStore:
    def __init__(self, client, tables):
        self.client, self.tables = client, tables

    def get(self, table, pk, sk):
        item = self.client.get_item(TableName=self.tables[table], Key={'pk': {'S': pk}, 'sk': {'S': sk}}, ConsistentRead=True).get('Item')
        return Row(json.loads(item['data']['S']), int(item['version']['N'])) if item else None

    def query(self, table, pk, prefix='', limit=500):
        args = dict(TableName=self.tables[table], ConsistentRead=True,
                    KeyConditionExpression='pk = :p',
                    ExpressionAttributeValues={':p': {'S': pk}})
        # An unfiltered partition query has no sort-key predicate. DynamoDB
        # rejects an empty string used as a key operand, even in begins_with.
        if prefix:
            args['KeyConditionExpression'] += ' AND begins_with(sk, :s)'
            args['ExpressionAttributeValues'][':s'] = {'S': prefix}
        result = []
        while True:
            page = self.client.query(**args)
            result.extend(Row(json.loads(i['data']['S']), int(i['version']['N'])) for i in page.get('Items', []))
            if len(result) > limit:
                raise ValueError('Result limit reached; narrow the requested collection')
            if not page.get('LastEvaluatedKey'):
                return result
            args['ExclusiveStartKey'] = page['LastEvaluatedKey']

    def transact(self, writes):
        items = []
        for table, pk, sk, value, expected in writes:
            expr = 'attribute_not_exists(pk)' if expected is None else '#v = :v'
            spec = {'TableName': self.tables[table], 'ConditionExpression': expr}
            if expected is not None:
                spec.update(ExpressionAttributeNames={'#v': 'version'}, ExpressionAttributeValues={':v': {'N': str(expected)}})
            if value is None:
                spec['Key'] = {'pk': {'S': pk}, 'sk': {'S': sk}}
                items.append({'Delete': spec})
            else:
                raw = encode(value)
                if len(raw) > 320000:
                    raise ValueError('Record exceeds its storage limit')
                spec['Item'] = {'pk': {'S': pk}, 'sk': {'S': sk}, 'version': {'N': str((expected or 0) + 1)}, 'data': {'S': raw.decode()}}
                items.append({'Put': spec})
        try:
            self.client.transact_write_items(TransactItems=items)
        except self.client.exceptions.TransactionCanceledException as exc:
            reasons = exc.response.get('CancellationReasons', [])
            if any(r.get('Code') == 'ConditionalCheckFailed' for r in reasons):
                raise Conflict('This record changed; reload before continuing') from exc
            raise


class S3Blobs:
    def __init__(self, client, bucket):
        self.client, self.bucket = client, bucket

    def put(self, key, raw, content_type='application/json'):
        if not key.startswith('business/'):
            raise ValueError('Unexpected business evidence prefix')
        response = self.client.put_object(Bucket=self.bucket, Key=key, Body=raw, ContentType=content_type)
        version = response.get('VersionId')
        if not version or version == 'null':
            raise ValueError('Immutable evidence version is missing')
        ref = {'bucket': self.bucket, 'key': key, 'version_id': version, 'sha256': hashlib.sha256(raw).hexdigest(), 'size': len(raw)}
        # A write response alone is not receipt persistence proof.
        if self.read(ref) != raw:
            raise ValueError('Evidence readback differs')
        return ref

    def read(self, ref, maximum=3_000_000):
        if ref.get('bucket') != self.bucket or not ref.get('key', '').startswith('business/') or not ref.get('version_id'):
            raise ValueError('Unexpected evidence binding')
        obj = self.client.get_object(Bucket=self.bucket, Key=ref['key'], VersionId=ref['version_id'])
        body = obj['Body']
        try:
            raw = body.read(maximum + 1)
        finally:
            body.close()
        if len(raw) > maximum or len(raw) != ref['size'] or hashlib.sha256(raw).hexdigest() != ref['sha256']:
            raise ValueError('Evidence integrity differs')
        return raw
