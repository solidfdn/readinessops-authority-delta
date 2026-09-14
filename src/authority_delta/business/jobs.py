"""Durable outbox and one bounded analysis attempt; no business-state writes."""
import json
import uuid
import time
from datetime import datetime, timedelta
from .contracts import check_snapshot, validate_proposal
from .storage import Conflict, encode
from .service import now


def dispatch_one(db, sqs, queue_url, run_id):
    row = db.get('jobs', 'OUTBOX', run_id)
    if not row:
        return
    sqs.send_message(QueueUrl=queue_url, MessageBody=encode(row.value).decode())
    try:
        db.transact([('jobs', 'OUTBOX', run_id, None, row.version)])
    except Conflict:
        pass  # Another sender removed the same outbox; the job claim prevents duplicate work.


def dispatch_pending(db, sqs, queue_url):
    failures = 0
    for row in db.query('jobs', 'OUTBOX'):
        try:
            dispatch_one(db, sqs, queue_url, row.value['run_id'])
        except Exception:
            failures += 1
    if failures:
        raise RuntimeError('Outbox dispatch incomplete; pending records retained')


class AssessmentWorker:
    def __init__(self, db, blobs, invoke, clock=now):
        self.db, self.blobs, self.invoke, self.clock = db, blobs, invoke, clock

    def process(self, message, dead_letter=False):
        if set(message) != {'run_id', 'input_hash'}:
            raise ValueError('Invalid queued analysis binding')
        rid = message['run_id']
        row = self.db.get('jobs', rid, 'STATE')
        if not row or row.value['input_hash'] != message['input_hash']:
            raise ValueError('Queued job does not match its saved input')
        if row.value['status'] not in ('QUEUED', 'RUNNING'):
            return
        if row.value['status'] == 'RUNNING':
            if datetime.fromisoformat(row.value['lease_until']) > datetime.fromisoformat(self.clock()):
                # Do not acknowledge the only recoverable queue message while an attempt is unknown.
                raise RuntimeError('An assessment attempt is still running')
            expired = dict(row.value, status='FAILED', completed_at=self.clock(), error='The assessment was interrupted. Start a new assessment to retry.')
            self.db.transact([('jobs', rid, 'STATE', expired, row.version)])
            return
        if dead_letter:
            failed = dict(row.value, status='FAILED', completed_at=self.clock(), error='The queued assessment could not start. Start a new assessment to retry.')
            self.db.transact([('jobs', rid, 'STATE', failed, row.version)])
            return
        claim = dict(row.value, status='RUNNING', started_at=self.clock(), attempt=row.value['attempt'] + 1,
                     lease_until=(datetime.fromisoformat(self.clock()) + timedelta(seconds=420)).isoformat(), claim_id=uuid.uuid4().hex)
        self.db.transact([('jobs', rid, 'STATE', claim, row.version)])
        final = dict(claim)
        try:
            source = json.loads(self.blobs.read(claim['input_ref']))
            check_snapshot(source)
            if source['input_hash'] != claim['input_hash'] or source['object_id'] != claim['object_id']:
                raise ValueError('Saved job input differs')
            result = self.invoke(source)
            if result.get('input_hash') != source['input_hash']:
                raise ValueError('Runtime response does not match the submitted input')
            if result.get('status') == 'VALIDATED':
                result['proposal'] = validate_proposal(result.get('proposal'), source, result.get('reads', []))
                if not result.get('model_calls') or any(c.get('http_status') != 200 or not c.get('request_id') for c in result['model_calls']):
                    raise ValueError('Model call evidence is missing')
                final['status'] = 'REVIEW_REQUIRED'
            else:
                final['status'] = 'NEEDS_INPUT'
                if result.get('failure_classification') in ('MODEL_OUTPUT_CONTRACT', 'ASSESSMENT_EXECUTION'):
                    final['error'] = 'The assessment could not produce a valid proposal. Your selected evidence is saved.'
                else:
                    final['error'] = 'The assessment could not produce a supported proposal. Review the selected evidence and try again.'
            final['result_ref'] = self.blobs.put('business/results/' + rid + '/' + claim['claim_id'] + '.json', encode(result))
        except Exception as exc:
            metadata = getattr(exc, 'response', {}).get('ResponseMetadata', {})
            final['diagnostics'] = {'type': type(exc).__name__, 'message': str(exc)[:1600],
                                    'aws_request_id': metadata.get('RequestId'), 'http_status': metadata.get('HTTPStatusCode')}
            if 'result' in locals():
                try:
                    final['result_ref'] = self.blobs.put('business/results/' + rid + '/' + claim['claim_id'] + '-unaccepted.json', encode(result))
                except Exception as save_error:
                    final['diagnostics']['save_error_type'] = type(save_error).__name__
            final.update(status='FAILED', error='Assessment failed; the fixed input is retained. Start a new assessment to retry.', error_type=type(exc).__name__)
        final['completed_at'] = self.clock()
        self.db.transact([('jobs', rid, 'STATE', final, row.version + 1)])


class RuntimeInvoker:
    def __init__(self, control, runtime, binding, sleep=time.sleep):
        self.control, self.runtime, self.binding, self.sleep = control, runtime, binding, sleep

    def endpoint(self):
        b = self.binding
        ep = self.control.get_agent_runtime_endpoint(agentRuntimeId=b['id'], endpointName=b['endpoint'])
        expected = {'status': 'READY', 'liveVersion': b['version'], 'agentRuntimeArn': b['arn'],
                    'agentRuntimeEndpointArn': b['endpoint_arn'], 'name': b['endpoint']}
        if any(ep.get(k) != v for k, v in expected.items()) or ep.get('targetVersion', b['version']) != b['version']:
            raise ValueError('Business runtime endpoint differs from the fixed deployment')
        metadata = ep.get('ResponseMetadata', {})
        if metadata.get('HTTPStatusCode') != 200 or not metadata.get('RequestId'):
            raise ValueError('Runtime endpoint read lacks successful AWS evidence')
        return {'request_id': metadata['RequestId'], 'live_version': ep['liveVersion'], 'endpoint_arn': ep['agentRuntimeEndpointArn']}

    def __call__(self, source):
        b = self.binding
        before = self.endpoint()
        sid = 'readinessops-' + uuid.uuid4().hex
        try:
            for attempt in range(4):
                try:
                    response = self.runtime.invoke_agent_runtime(agentRuntimeArn=b['arn'], qualifier=b['endpoint'], runtimeSessionId=sid,
                                contentType='application/json', accept='application/json', payload=encode(source))
                    break
                except Exception as exc:
                    if getattr(exc, 'response', {}).get('Error', {}).get('Code') != 'RetryableConflictException' or attempt == 3:
                        raise
                    self.sleep(3)
            stream = response['response']
            try:
                raw = stream.read(1_000_001)
            finally:
                stream.close()
            metadata = response.get('ResponseMetadata', {})
            if len(raw) > 1_000_000 or metadata.get('HTTPStatusCode') != 200 or response.get('statusCode') != 200 or not metadata.get('RequestId'):
                raise ValueError('Runtime response could not be verified')
            result = json.loads(raw)
            identity = result.get('identity', {})
            expected_role = 'arn:aws:sts::' + b['account'] + ':assumed-role/' + b['role_name'] + '/'
            if identity.get('account') != b['account'] or not identity.get('arn', '').startswith(expected_role) or not identity.get('request_id'):
                raise ValueError('Analysis execution identity could not be verified: ' + json.dumps(result.get('error', {}))[:1600])
            if result.get('model_id') != 'apac.amazon.nova-pro-v1:0':
                raise ValueError('Analysis used a different model binding')
            result['runtime_evidence'] = {'request_id': metadata['RequestId'], 'http_status': response['statusCode'], 'session_id': sid,
                                          'runtime_arn': b['arn'], 'version': b['version'], 'endpoint': b['endpoint'],
                                          'endpoint_before': before, 'endpoint_after': self.endpoint()}
            return result
        finally:
            try:
                self.runtime.stop_runtime_session(agentRuntimeArn=b['arn'], qualifier=b['endpoint'], runtimeSessionId=sid)
            except Exception:
                pass  # Runtime also has a bounded idle/max lifetime; no publication authority exists.
