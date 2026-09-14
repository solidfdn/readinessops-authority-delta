"""Authenticated business commands. Approval, official publication and AWS application differ."""
from __future__ import annotations
import base64
import copy
import json
import re
import uuid
from datetime import datetime, timedelta, timezone
from authority_delta.canonical import sha256_json
from .acceptance import build_acceptance_evidence
from .delegation import (build_delegation_receipt, build_enforcement_candidate,
                         public_registration, verify_delegation_receipt,
                         verify_enforcement_candidate, verify_publisher_result,
                         verify_registration)
from .contracts import (PERSPECTIVES, PROMPT_VERSION, check_snapshot,
                        legacy_decision_item_registry, prior_decision_items,
                        validate_proposal)
from .evidence import extract
from .interchange import (build_interchange, build_outcome, verify_interchange,
                          verify_outcome)
from .revocation import (build_revocation_request, revocation_message,
                         revocation_state, verify_revocation_request,
                         verify_revocation_result)
from .storage import Conflict, encode


class Problem(Exception):
    def __init__(self, message, status=400, code='INVALID_INPUT'):
        super().__init__(message)
        self.status, self.code = status, code


def now():
    return datetime.now(timezone.utc).isoformat()


def text(value, name, low=1, high=4000):
    if not isinstance(value, str) or not low <= len(value.strip()) <= high or '\x00' in value:
        raise Problem(f'{name}: enter between {low} and {high} characters')
    return value.strip()


def uid(prefix):
    return prefix + '-' + uuid.uuid4().hex


class BusinessService:
    def __init__(self, db, blobs, dispatch=None, clock=now, adapters=None,
                 application_dispatch=None):
        self.db, self.blobs, self.dispatch, self.clock = db, blobs, dispatch, clock
        self.application_dispatch = application_dispatch
        self.adapters = {}
        for raw in adapters or []:
            registration = verify_registration(raw)
            key = (registration['adapter_id'], registration['connection_id'])
            if key in self.adapters:
                raise ValueError('Adapter registration is duplicated')
            self.adapters[key] = registration

    def _adapter(self, adapter_id, connection_id):
        registration = self.adapters.get((adapter_id, connection_id))
        if registration is None:
            raise Problem('The requested AWS execution adapter is not registered', 409,
                          'ADAPTER_NOT_REGISTERED')
        try:
            return verify_registration(registration)
        except ValueError as exc:
            raise Problem('The registered AWS execution adapter failed integrity checks', 409,
                          'ADAPTER_INTEGRITY_FAILED') from exc

    def registered_adapters(self):
        return [public_registration(v) for _, v in sorted(self.adapters.items())]

    def _object_adapters(self, head):
        binding = head.get('execution_connection')
        if not binding:
            return []
        registered = self.adapters.get((binding['adapter_id'], binding['connection_id']))
        if (not registered or registered['adapter_version'] != binding['adapter_version']
                or registered['registration_hash'] != binding['registration_hash']):
            return []
        return [public_registration(registered)]

    def connect_adapter(self, actor, oid, body):
        """Bind one registered execution connection explicitly; never grant authority."""
        h = self._head(actor, oid)
        op = self._operation(actor, 'connection:' + oid, body)
        if op[2] is not None:
            return op[2]
        self._version(h, body)
        registration = self._adapter(body.get('adapter_id'), body.get('connection_id'))
        binding = {k: registration[k] for k in
                   ('adapter_id', 'adapter_version', 'connection_id', 'registration_hash')}
        if any(body.get(k) != v for k, v in binding.items()):
            raise Problem('The selected execution connection changed; reload it', 409,
                          'CONNECTION_STALE')
        if h.value.get('execution_connection') or h.value.get('delegation_approval') or h.value.get('latest_application'):
            raise Problem('This object already has an execution binding; preserve its authority history',
                          409, 'CONNECTION_ALREADY_BOUND')
        reason = text(body.get('reason'), 'Connection purpose', high=1600)
        response = {'object_id': oid, 'execution_connection': binding,
                    'runtime_authority_changed': False}
        return self._commit(op, [('app', oid, 'HEAD', dict(h.value, execution_connection=binding), h.version),
            self._event(oid, actor, 'EXECUTION_CONNECTION_SELECTED', {
                **binding, 'reason': reason, 'runtime_authority_changed': False})], response)

    def _head(self, actor, oid):
        if not re.fullmatch(r'o-[0-9a-f]{32}', oid):
            raise Problem('Object not found', 404, 'NOT_FOUND')
        row = self.db.get('app', oid, 'HEAD')
        if row is None or row.value['owner_sub'] != actor['sub']:
            raise Problem('Object not found', 404, 'NOT_FOUND')
        return row

    def _operation(self, actor, op, body):
        rid = body.get('request_id', '')
        if not re.fullmatch(r'[A-Za-z0-9_-]{16,80}', rid):
            raise Problem('A valid request identifier is required')
        key = ('app', 'OP#' + actor['sub'], rid)
        digest = sha256_json({'operation': op, 'body': body})
        existing = self.db.get(*key)
        if existing:
            if existing.value['fingerprint'] != digest:
                raise Problem('This request identifier was already used for different input', 409, 'REQUEST_CONFLICT')
            return key, digest, existing.value['response']
        return key, digest, None

    def _commit(self, op, writes, response):
        key, digest, _ = op
        try:
            self.db.transact(writes + [(*key, {'fingerprint': digest, 'response': response}, None)])
        except Conflict:
            winner = self.db.get(*key)
            if winner and winner.value['fingerprint'] == digest:
                return winner.value['response']
            raise Problem('The record changed. Reload and review the latest version.', 409, 'STALE_VERSION')
        return response

    def _version(self, row, body):
        if type(body.get('expected_revision')) is not int or body['expected_revision'] != row.version:
            raise Problem('The record changed. Reload before continuing.', 409, 'STALE_VERSION')

    def _event(self, oid, actor, kind, details):
        eid = uid('event')
        value = {'event_id': eid, 'object_id': oid, 'kind': kind, 'at': self.clock(),
                 'actor_sub': actor['sub'], 'actor_name': actor['name'], 'details': details}
        return ('app', oid, 'EVENT#' + value['at'] + '#' + eid, value, None)

    def objects(self, actor):
        rows = self.db.query('app', 'OWNER#' + actor['sub'], 'OBJECT#')
        objects = []
        for r in rows:
            h = self._head(actor, r.value['object_id'])
            objects.append(dict(h.value, record_revision=h.version))
        return sorted(objects, key=lambda x: x['created_at'], reverse=True)

    def create(self, actor, body):
        op = self._operation(actor, 'create', body)
        if op[2] is not None:
            return op[2]
        oid = uid('o')
        item_registry = [{'decision_item_id': uid('di'), 'perspective': perspective}
                         for perspective in PERSPECTIVES]
        value = {'schema_version': '1.2', 'object_id': oid, 'workspace_id': 'solifan',
                 'name': text(body.get('name'), 'Name', high=160),
                 'purpose': text(body.get('purpose'), 'Purpose', high=1600),
                 'question': text(body.get('question'), 'Question', high=4000),
                 'owner': text(body.get('owner'), 'Responsible person', high=160),
                 'goals': text(body.get('goals', ''), 'Goal / measurement', low=0, high=1600),
                 'owner_sub': actor['sub'], 'created_at': self.clock(), 'data_revision': 1,
                 'generation': 1, 'latest_run': None, 'draft': None, 'approval': None,
                 'decision_item_registry': item_registry,
                 'published_current': None, 'applied_binding': None, 'application_status': 'NOT_APPLIED',
                 'delegation_generation': 0, 'delegation_approval': None,
                 'latest_application': None, 'execution_connection': None,
                 'authority_control': None}
        return self._commit(op, [('app', oid, 'HEAD', value, None),
            ('app', 'OWNER#' + actor['sub'], 'OBJECT#' + oid, {'object_id': oid}, None),
            self._event(oid, actor, 'OBJECT_CREATED', {'name': value['name']})], {'object_id': oid})

    def add_evidence(self, actor, oid, body):
        h = self._head(actor, oid)
        op = self._operation(actor, 'evidence:' + oid, body)
        if op[2] is not None:
            return op[2]
        self._version(h, body)
        if len(self.db.query('app', oid, 'EVIDENCE#')) >= 40:
            raise Problem('This object has reached its forty-document limit; create a separate assessment object')
        try:
            raw = base64.b64decode(body.get('content_base64', ''), validate=True)
            parsed = extract(body.get('filename'), raw)
        except (ValueError, TypeError) as exc:
            raise Problem(str(exc)) from exc
        stored_evidence = self.db.query('app', oid, 'EVIDENCE#')
        if sum(len(r.value['text'].encode()) for r in stored_evidence) + len(parsed['text'].encode()) > 1_000_000:
            raise Problem('This object has reached its extracted-text limit; create a separate assessment object')
        eid = uid('e')
        ref = self.blobs.put('business/evidence/' + oid + '/' + eid, raw, parsed['content_type'])
        value = {'evidence_id': eid, 'object_id': oid, 'title': text(body.get('title') or body['filename'], 'Evidence title', high=160),
                 'filename': body['filename'], 'source': text(body.get('source', 'User supplied'), 'Source', high=1000),
                 'original': ref, 'text': parsed['text'], 'text_hash': sha256_json(parsed['text']),
                 'extraction_status': parsed['status'], 'extraction_method': parsed['method'], 'reason': parsed['reason'],
                 'ingested_at': self.clock(), 'uploaded_by': actor['sub'], 'source_occurred_at': None, 'effective_at': None}
        updated = dict(h.value, data_revision=h.value['data_revision'] + 1, generation=h.value['generation'] + 1, approval=None)
        return self._commit(op, [('app', oid, 'HEAD', updated, h.version), ('app', oid, 'EVIDENCE#' + eid, value, None),
            self._event(oid, actor, 'EVIDENCE_ADDED', {'evidence_id': eid, 'title': value['title'], 'extraction_status': parsed['status']})],
            {'evidence_id': eid, 'extraction_status': parsed['status'], 'reason': parsed['reason']})

    def _prior_publication(self, head):
        current = head.value['published_current']
        if current is None:
            return None
        try:
            row = self.db.get('app', head.value['object_id'], 'PUBLICATION#' + current['publication_id'])
            if row is None or row.value != current:
                raise ValueError('Current publication does not match its committed record')
            publication = json.loads(self.blobs.read(current['ref']))
            if publication != {k: v for k, v in current.items() if k != 'ref'}:
                raise ValueError('Current publication differs from its pinned document')
            decision = json.loads(self.blobs.read(publication['decision_ref']))
            receipt = json.loads(self.blobs.read(publication['receipt_ref']))
            if (decision.get('object_id') != head.value['object_id']
                    or decision.get('pack_id') != publication['pack_id']
                    or decision.get('revision') != publication['revision']
                    or decision.get('digest') != publication['digest']
                    or sha256_json({k: v for k, v in decision.items() if k != 'digest'}) != publication['digest']):
                raise ValueError('Published decision differs from its pinned digest')
            if (receipt.get('kind') != 'BUSINESS_DECISION_ONLY'
                    or receipt.get('receipt_id') != publication['receipt_id']
                    or receipt.get('object_id') != head.value['object_id']
                    or receipt.get('pack_id') != publication['pack_id']
                    or receipt.get('revision') != publication['revision']
                    or receipt.get('digest') != publication['digest']
                    or receipt.get('decision') != 'APPROVE'
                    or receipt.get('runtime_authority_granted') is not False):
                raise ValueError('Published approval differs from its pinned decision')
            return {'publication_ref': copy.deepcopy(current['ref']), 'publication': publication,
                    'decision': decision, 'receipt': receipt}
        except (KeyError, TypeError, ValueError) as exc:
            raise Problem('Prior publication integrity could not be verified', 409, 'INTEGRITY_FAILED') from exc

    def start_run(self, actor, oid, body):
        h = self._head(actor, oid)
        op = self._operation(actor, 'run:' + oid, body)
        if op[2] is not None:
            self._try_dispatch(op[2]['run_id'])
            return op[2]
        self._version(h, body)
        if h.value['latest_run']:
            previous = self._job(h.value['latest_run'])
            if previous and previous.value['status'] in ('QUEUED', 'RUNNING'):
                raise Problem('An assessment is already running. Open its progress instead.', 409, 'RUN_ACTIVE')
        if len(self.db.query('app', oid, 'RUN#')) >= 60:
            raise Problem('Run limit reached for this object; export its history and start another object')
        ids = body.get('evidence_ids')
        if not isinstance(ids, list) or not 1 <= len(ids) <= 8 or not all(isinstance(i, str) for i in ids) or len(set(ids)) != len(ids):
            raise Problem('Select one to eight evidence records')
        evidence = []
        for eid in ids:
            row = self.db.get('app', oid, 'EVIDENCE#' + eid)
            if row is None or row.value['object_id'] != oid:
                raise Problem('Selected evidence is not part of this object')
            e = row.value
            if e['extraction_status'] != 'READY':
                raise Problem('Selected evidence needs a readable replacement', 422, 'NEEDS_INPUT')
            self.blobs.read(e['original'])
            evidence.append(e)
        item_registry = copy.deepcopy(h.value.get('decision_item_registry')
                                      or legacy_decision_item_registry(oid))
        source = {'schema_version': '1.2', 'mode': 'REASSESSMENT' if h.value['published_current'] else 'INITIAL',
                  'object_id': oid, 'data_revision': h.value['data_revision'],
                  'context': {k: h.value[k] for k in ('name', 'purpose', 'question', 'owner', 'goals')},
                  'decision_item_registry': item_registry,
                  'evidence': evidence, 'prompt_version': PROMPT_VERSION,
                  'model_id': 'apac.amazon.nova-pro-v1:0', 'source_authority': 'aws:solifan'}
        prior = self._prior_publication(h)
        if prior is not None:
            source['prior_publication'] = prior
        source['input_hash'] = sha256_json(source)
        try:
            check_snapshot(source)
        except ValueError as exc:
            raise Problem(str(exc)) from exc
        run_id = uid('run')
        ref = self.blobs.put('business/inputs/' + run_id + '.json', encode(source))
        job = {'run_id': run_id, 'object_id': oid, 'owner_sub': actor['sub'], 'status': 'QUEUED',
               'created_at': self.clock(), 'input_ref': ref, 'input_hash': source['input_hash'],
               'data_revision': h.value['data_revision'], 'attempt': 0, 'result_ref': None, 'error': None}
        updated = dict(h.value, latest_run=run_id, draft=None, approval=None,
                       decision_item_registry=item_registry, generation=h.value['generation'] + 1)
        linked = []
        action_writes = []
        selected = set(ids)
        for row in self.db.query('app', oid, 'ACTION#'):
            action = row.value
            resolution = {e['evidence_id'] for e in action.get('resolution_evidence', [])}
            if (action.get('status') == 'COMPLETED' and resolution
                    and resolution.issubset(selected)
                    and action.get('reassessment_run_id') is None):
                action = dict(action, reassessment_run_id=run_id,
                              reassessment_input_hash=source['input_hash'],
                              updated_at=self.clock())
                action_writes.append(('app', oid, 'ACTION#' + action['action_id'],
                                      action, row.version))
                linked.append(action['action_id'])
        result = self._commit(op, [('app', oid, 'HEAD', updated, h.version),
            ('app', oid, 'RUN#' + run_id, {'run_id': run_id, 'created_at': job['created_at']}, None),
            ('jobs', run_id, 'STATE', job, None), ('jobs', 'OUTBOX', run_id, {'run_id': run_id, 'input_hash': source['input_hash']}, None),
            *action_writes,
            self._event(oid, actor, 'ASSESSMENT_QUEUED', {
                'run_id': run_id, 'evidence_ids': ids,
                'linked_completed_action_ids': linked})],
            {'run_id': run_id, 'status': 'QUEUED',
             'linked_completed_action_ids': linked})
        self._try_dispatch(result['run_id'])
        return result

    def _try_dispatch(self, run_id):
        if self.dispatch:
            try:
                self.dispatch(run_id)
            except Exception:
                pass  # The committed outbox remains available to the scheduled dispatcher.

    def _job(self, run_id):
        row = self.db.get('jobs', run_id, 'STATE')
        if row and row.value['status'] in ('QUEUED', 'RUNNING'):
            stamp = datetime.fromisoformat(self.clock())
            deadline = (datetime.fromisoformat(row.value['lease_until']) if row.value['status'] == 'RUNNING'
                        else datetime.fromisoformat(row.value['created_at']) + timedelta(minutes=10))
            if stamp >= deadline:
                failed = dict(row.value, status='FAILED', completed_at=self.clock(), error='The assessment exceeded its recovery window. Its input is retained; start a new assessment to retry.')
                try:
                    self.db.transact([('jobs', run_id, 'STATE', failed, row.version)])
                except Conflict:
                    pass
                row = self.db.get('jobs', run_id, 'STATE')
        return row

    def _run_source(self, actor, oid, run_id):
        self._head(actor, oid)
        job = self._job(run_id)
        if not job or job.value['object_id'] != oid or job.value['owner_sub'] != actor['sub']:
            raise Problem('Assessment not found', 404, 'NOT_FOUND')
        return job, json.loads(self.blobs.read(job.value['input_ref']))

    def run(self, actor, oid, run_id):
        job, source = self._run_source(actor, oid, run_id)
        result = dict(job.value)
        if result['result_ref']:
            result['analysis'] = json.loads(self.blobs.read(result['result_ref']))
        result['context'] = source['context']
        result['mode'] = source['mode']
        result['selected_evidence_ids'] = [e['evidence_id'] for e in source['evidence']]
        if source['mode'] == 'REASSESSMENT':
            publication = source['prior_publication']['publication']
            result['comparison_baseline'] = {
                'publication_id': publication['publication_id'],
                'decision_digest': publication['digest'],
                'pack_id': publication['pack_id'],
                'revision': publication['revision'],
                'decision_items': prior_decision_items(source),
            }
        return result

    def save_draft(self, actor, oid, body):
        h = self._head(actor, oid)
        op = self._operation(actor, 'draft:' + oid, body)
        if op[2] is not None:
            return op[2]
        self._version(h, body)
        run_id = body.get('run_id')
        job, source = self._run_source(actor, oid, run_id)
        if h.value['latest_run'] != run_id or job.value['status'] != 'REVIEW_REQUIRED' or job.value['data_revision'] != h.value['data_revision']:
            raise Problem('Use the latest completed assessment for the current evidence', 409, 'ASSESSMENT_STALE')
        try:
            proposal = validate_proposal(body.get('proposal'), source)
        except (ValueError, TypeError) as exc:
            raise Problem('Draft is invalid: ' + str(exc)[:450], 422) from exc
        revision = h.value['draft']['revision'] + 1 if h.value['draft'] else 1
        pack_id = 'pack-' + run_id[4:]
        value = {'schema_version': '1.2', 'kind': 'BUSINESS_DECISION', 'pack_id': pack_id, 'revision': revision,
                 'object_id': oid, 'run_id': run_id, 'input_hash': source['input_hash'], 'data_revision': h.value['data_revision'],
                 'proposal': proposal, 'edited_by': actor['sub'], 'edited_at': self.clock(),
                 'change_reason': text(body.get('change_reason'), 'Review note', high=1600), 'source_authority': 'aws:solifan'}
        value['digest'] = sha256_json(value)
        ref = self.blobs.put('business/decisions/' + pack_id + '/' + str(revision) + '.json', encode(value))
        draft = {'pack_id': pack_id, 'revision': revision, 'digest': value['digest'], 'ref': ref, 'run_id': run_id, 'data_revision': value['data_revision']}
        updated = dict(h.value, draft=draft, approval=None, generation=h.value['generation'] + 1)
        return self._commit(op, [('app', oid, 'HEAD', updated, h.version), ('app', oid, 'PACK#' + pack_id + '#' + str(revision).zfill(6), draft, None),
            self._event(oid, actor, 'DECISION_DRAFT_SAVED', {'pack_id': pack_id, 'revision': revision, 'digest': value['digest'], 'note': value['change_reason']})], draft)

    def review(self, actor, oid, body):
        h = self._head(actor, oid)
        op = self._operation(actor, 'review:' + oid, body)
        if op[2] is not None:
            return op[2]
        self._version(h, body)
        draft = h.value['draft']
        if not draft or body.get('digest') != draft['digest'] or draft['data_revision'] != h.value['data_revision']:
            raise Problem('Review the saved draft for the current evidence', 409, 'DRAFT_STALE')
        decision = body.get('decision')
        if decision not in ('APPROVE', 'REJECT', 'RETURN'):
            raise Problem('Choose approve, reject or return for revision')
        note = text(body.get('reason'), 'Decision reason', high=1600)
        pack = json.loads(self.blobs.read(draft['ref']))
        if pack['digest'] != draft['digest'] or sha256_json({k: v for k, v in pack.items() if k != 'digest'}) != draft['digest']:
            raise Problem('Draft integrity could not be verified', 409, 'INTEGRITY_FAILED')
        receipt_id = uid('receipt')
        stamp = self.clock()
        days = body.get('valid_days', 7)
        if type(days) is not int or not 1 <= days <= 30:
            raise Problem('Approval validity must be between one and thirty days')
        generation = h.value['generation'] + 1
        receipt = {'schema_version': '1.2', 'kind': 'BUSINESS_DECISION_ONLY', 'receipt_id': receipt_id,
                   'object_id': oid, 'pack_id': draft['pack_id'], 'revision': draft['revision'], 'digest': draft['digest'],
                   'input_hash': pack['input_hash'], 'generation': generation, 'decision': decision,
                   'reason': note, 'approver_sub': actor['sub'], 'approver_name': actor['name'], 'at': stamp,
                   'expires_at': (datetime.fromisoformat(stamp) + timedelta(days=days)).isoformat(),
                   'runtime_authority_granted': False}
        ref = self.blobs.put('business/receipts/' + receipt_id + '.json', encode(receipt))
        recorded = dict(receipt, ref=ref)
        updated = dict(h.value, generation=generation, approval=recorded if decision == 'APPROVE' else None)
        return self._commit(op, [('app', oid, 'HEAD', updated, h.version), ('app', oid, 'RECEIPT#' + receipt_id, recorded, None),
            self._event(oid, actor, 'HUMAN_' + decision, {'receipt_id': receipt_id, 'digest': draft['digest'], 'reason': note})], recorded)

    def publish(self, actor, oid, body):
        h = self._head(actor, oid)
        op = self._operation(actor, 'publish:' + oid, body)
        if op[2] is not None:
            return op[2]
        self._version(h, body)
        approval = h.value['approval']
        draft = h.value['draft']
        if not approval or not draft or approval['receipt_id'] != body.get('receipt_id') or approval['generation'] != h.value['generation']:
            raise Problem('The current saved draft needs a valid approval', 409, 'APPROVAL_REQUIRED')
        if approval['decision'] != 'APPROVE' or approval['digest'] != draft['digest'] or draft['data_revision'] != h.value['data_revision']:
            raise Problem('Approval no longer matches the current draft', 409, 'APPROVAL_STALE')
        if datetime.fromisoformat(approval['expires_at']) <= datetime.fromisoformat(self.clock()):
            raise Problem('Approval expired; review the draft again', 409, 'APPROVAL_EXPIRED')
        stored = json.loads(self.blobs.read(approval['ref']))
        if stored != {k: v for k, v in approval.items() if k != 'ref'}:
            raise Problem('Approval receipt integrity differs', 409, 'INTEGRITY_FAILED')
        pack = json.loads(self.blobs.read(draft['ref']))
        if (pack.get('digest') != draft['digest']
                or sha256_json({k: v for k, v in pack.items() if k != 'digest'}) != draft['digest']):
            raise Problem('Decision Pack integrity differs', 409, 'INTEGRITY_FAILED')
        _, source = self._run_source(actor, oid, pack.get('run_id'))
        if source.get('input_hash') != pack.get('input_hash'):
            raise Problem('Decision Pack input snapshot differs', 409, 'INTEGRITY_FAILED')
        baseline_evidence_ids = sorted(e['evidence_id'] for e in source['evidence'])
        current = h.value['published_current']
        if current and current['receipt_id'] == approval['receipt_id']:
            raise Problem('This approval is already the official version', 409, 'ALREADY_PUBLISHED')
        latest_application = h.value.get('latest_application')
        if latest_application and latest_application.get('status') in ('APPLYING', 'CANARY', 'UNKNOWN'):
            raise Problem('Resolve the current AWS application before publishing another decision',
                          409, 'APPLICATION_UNRESOLVED')
        control = h.value.get('authority_control')
        if control and control.get('status') in ('STOP_REQUESTED', 'UNKNOWN'):
            raise Problem('Complete the current AWS authority removal before publishing another decision',
                          409, 'REVOCATION_UNRESOLVED')
        if (control and control.get('status') == 'VERIFIED'
                and control.get('entry_status') == 'OPEN'
                and control.get('runtime_authority_active') is True):
            raise Problem('Stop the current AWS authority before publishing another decision',
                          409, 'ACTIVE_AUTHORITY_STOP_REQUIRED')
        proposals = pack.get('proposal', {}).get('actions', [])
        if len(self.db.query('app', oid, 'ACTION#')) + len(proposals) > 60:
            raise Problem('Action limit reached for this object', 409, 'ACTION_LIMIT')
        publication_id = uid('pub')
        publication = {'schema_version': '1.2', 'publication_id': publication_id, 'object_id': oid,
                       'pack_id': draft['pack_id'], 'revision': draft['revision'], 'digest': draft['digest'],
                       'receipt_id': approval['receipt_id'], 'receipt_ref': approval['ref'], 'decision_ref': draft['ref'],
                       'source_authority': 'aws:solifan', 'published_by': actor['sub'], 'publisher_name': actor['name'], 'at': self.clock(),
                       'previous_publication_id': current['publication_id'] if current else None,
                       'application_status': 'NOT_APPLIED'}
        ref = self.blobs.put('business/publications/' + publication_id + '.json', encode(publication))
        published = dict(publication, ref=ref)
        findings = {f['finding_id']: f for f in pack.get('proposal', {}).get('findings', [])}
        action_writes = []
        action_ids = []
        for index, proposal in enumerate(proposals):
            action_id = uid('action')
            action_ids.append(action_id)
            finding_evidence_ids = sorted({citation['evidence_id']
                for finding_id in proposal['finding_ids']
                for citation in findings[finding_id]['citations']})
            action = {'schema_version': '1.2', 'kind': 'OPERATIONAL_ACTION',
                      'action_id': action_id, 'object_id': oid,
                      'publication_id': publication_id,
                      'publication_digest': publication['digest'],
                      'pack_id': publication['pack_id'],
                      'pack_revision': publication['revision'],
                      'source_action_index': index,
                      'title': proposal['title'], 'description': proposal['description'],
                      'finding_ids': copy.deepcopy(proposal['finding_ids']),
                      'baseline_evidence_ids': baseline_evidence_ids,
                      'finding_evidence_ids': finding_evidence_ids,
                      'status': 'PROPOSED', 'owner': None, 'due_on': None,
                      'resolution_note': None, 'resolution_evidence': [],
                      'reassessment_run_id': None, 'reassessment_input_hash': None,
                      'created_at': self.clock(), 'updated_at': self.clock(),
                      'created_by': actor['sub'],
                      'source': 'PUBLISHED_DECISION_ACTION_PROPOSAL'}
            action_writes.append(('app', oid, 'ACTION#' + action_id, action, None))
        applied = h.value.get('applied_binding')
        application_status = ('VERIFIED_PREVIOUS_PUBLICATION' if applied else 'NOT_APPLIED')
        updated = dict(h.value, published_current=published,
                       delegation_generation=h.value.get('delegation_generation', 0) + 1,
                       delegation_approval=None, application_status=application_status)
        return self._commit(op, [('app', oid, 'HEAD', updated, h.version),
            ('app', oid, 'PUBLICATION#' + publication_id, published, None),
            *action_writes,
            self._event(oid, actor, 'DECISION_PUBLISHED', {
                'publication_id': publication_id, 'receipt_id': approval['receipt_id'],
                'digest': draft['digest'], 'proposed_action_ids': action_ids})], published)

    def update_action(self, actor, oid, action_id, body):
        """Assign and progress a published action; completion requires new evidence."""
        h = self._head(actor, oid)
        if not re.fullmatch(r'action-[0-9a-f]{32}', action_id):
            raise Problem('Action not found', 404, 'NOT_FOUND')
        op = self._operation(actor, 'action:' + oid + ':' + action_id, body)
        if op[2] is not None:
            return op[2]
        self._version(h, body)
        row = self.db.get('app', oid, 'ACTION#' + action_id)
        if row is None or row.value.get('object_id') != oid:
            raise Problem('Action not found', 404, 'NOT_FOUND')
        if (type(body.get('expected_action_revision')) is not int
                or body['expected_action_revision'] != row.version):
            raise Problem('The action changed. Reload before continuing.', 409,
                          'ACTION_STALE')
        current = row.value['status']
        target = body.get('status')
        transitions = {
            'PROPOSED': {'ACTIVE', 'CANCELLED'},
            'ACTIVE': {'ACTIVE', 'IN_PROGRESS', 'COMPLETED', 'CANCELLED'},
            'IN_PROGRESS': {'ACTIVE', 'IN_PROGRESS', 'COMPLETED', 'CANCELLED'},
            'COMPLETED': set(), 'CANCELLED': set()}
        if target not in transitions.get(current, set()):
            raise Problem('This action status transition is not allowed', 409,
                          'ACTION_STATE_INVALID')
        reason = text(body.get('reason'), 'Action update reason', high=1600)
        owner = body.get('owner')
        due_on = body.get('due_on')
        if target != 'CANCELLED':
            owner = text(owner, 'Action owner', high=160)
            if not isinstance(due_on, str) or not re.fullmatch(r'[0-9]{4}-[0-9]{2}-[0-9]{2}', due_on):
                raise Problem('Action due date must use YYYY-MM-DD')
            try:
                datetime.strptime(due_on, '%Y-%m-%d')
            except ValueError as exc:
                raise Problem('Action due date is invalid') from exc
        else:
            owner = row.value.get('owner')
            due_on = row.value.get('due_on')
        ids = body.get('resolution_evidence_ids', [])
        if (not isinstance(ids, list) or len(ids) > 8
                or len(set(ids)) != len(ids) or not all(isinstance(v, str) for v in ids)):
            raise Problem('Resolution evidence selection is invalid')
        resolution = []
        if target == 'COMPLETED':
            if not ids:
                raise Problem('Completed actions require resolution evidence', 422,
                              'RESOLUTION_EVIDENCE_REQUIRED')
            if set(ids) & set(row.value.get('baseline_evidence_ids', [])):
                raise Problem('Use newly added evidence to resolve this action', 422,
                              'NEW_RESOLUTION_EVIDENCE_REQUIRED')
            for evidence_id in ids:
                evidence_row = self.db.get('app', oid, 'EVIDENCE#' + evidence_id)
                if (evidence_row is None or evidence_row.value.get('object_id') != oid
                        or evidence_row.value.get('extraction_status') != 'READY'):
                    raise Problem('Resolution evidence is unavailable or unreadable', 422,
                                  'RESOLUTION_EVIDENCE_INVALID')
                evidence = evidence_row.value
                self.blobs.read(evidence['original'])
                resolution.append({k: copy.deepcopy(evidence[k]) for k in
                    ('evidence_id', 'title', 'text_hash', 'original')})
        elif ids:
            raise Problem('Resolution evidence is accepted only when completing an action')
        stamp = self.clock()
        updated_action = dict(row.value, status=target, owner=owner, due_on=due_on,
                              updated_at=stamp)
        if target == 'COMPLETED':
            updated_action.update(resolution_note=reason,
                                  resolution_evidence=resolution,
                                  completed_at=stamp)
        elif target == 'CANCELLED':
            updated_action.update(cancellation_reason=reason, cancelled_at=stamp)
        response = {'action_id': action_id, 'status': target,
                    'action_revision': row.version + 1,
                    'resolution_evidence_ids': ids}
        event_kind = {'ACTIVE': 'ACTION_ACTIVATED', 'IN_PROGRESS': 'ACTION_IN_PROGRESS',
                      'COMPLETED': 'ACTION_COMPLETED',
                      'CANCELLED': 'ACTION_CANCELLED'}[target]
        return self._commit(op, [('app', oid, 'HEAD', dict(h.value), h.version),
            ('app', oid, 'ACTION#' + action_id, updated_action, row.version),
            self._event(oid, actor, event_kind, {
                'action_id': action_id, 'from_status': current, 'to_status': target,
                'reason': reason, 'resolution_evidence_ids': ids})], response)

    def record_outcome(self, actor, oid, body):
        """Record a business outcome without asserting or changing AWS authority."""
        h = self._head(actor, oid)
        op = self._operation(actor, 'outcome:' + oid, body)
        if op[2] is not None:
            return op[2]
        self._version(h, body)
        current = h.value.get('published_current')
        if current is None:
            raise Problem('Publish an official decision before recording an outcome', 409,
                          'PUBLICATION_REQUIRED')
        self._prior_publication(h)
        if len(self.db.query('app', oid, 'OUTCOME#')) >= 60:
            raise Problem('Outcome limit reached for this object', 409, 'OUTCOME_LIMIT')
        target = body.get('target')
        if not isinstance(target, dict):
            raise Problem('Outcome target is invalid')
        kind = target.get('kind')
        target_id = target.get('id')
        expected_digest = None
        if kind == 'DECISION_PUBLICATION':
            row = self.db.get('app', oid, 'PUBLICATION#' + str(target_id))
            if (row is None or row.value.get('object_id') != oid
                    or target_id != current['publication_id']):
                raise Problem('Outcome publication target is unavailable', 422,
                              'OUTCOME_TARGET_INVALID')
            expected_digest = row.value['digest']
        elif kind == 'AWS_APPLICATION':
            row = self.db.get('app', oid, 'APPLICATION#' + str(target_id))
            if (row is None or row.value.get('object_id') != oid
                    or row.value.get('publication_id') != current['publication_id']):
                raise Problem('Outcome application target is unavailable', 422,
                              'OUTCOME_TARGET_INVALID')
            if row.value.get('status') not in ('VERIFIED', 'RECOVERED_CLOSED'):
                raise Problem('Wait for the application result before recording an outcome', 409, 'OUTCOME_APPLICATION_PENDING')
            if row.value['status'] != 'VERIFIED' and body.get('authority_result') == 'ALLOW':
                raise Problem('A closed application cannot support an ALLOW outcome', 422, 'OUTCOME_RESULT_INVALID')
            expected_digest = row.value['enforcement_digest']
        elif kind == 'TRACE':
            if not re.fullmatch(r'[A-Za-z0-9._:/-]{8,200}', str(target_id)):
                raise Problem('Outcome trace target is invalid', 422,
                              'OUTCOME_TARGET_INVALID')
        else:
            raise Problem('Outcome target kind is invalid', 422,
                          'OUTCOME_TARGET_INVALID')
        if expected_digest is not None and target.get('digest') != expected_digest:
            raise Problem('Outcome target digest differs from the saved record', 409,
                          'OUTCOME_TARGET_STALE')
        outcome_id = uid('outcome')
        try:
            outcome = build_outcome(outcome_id=outcome_id, object_record=h.value,
                publication=current, target=target,
                authority_result=body.get('authority_result'),
                business_result=body.get('business_result'),
                metrics=body.get('metrics'), actor=actor, recorded_at=self.clock())
            verify_outcome(outcome)
        except (TypeError, ValueError) as exc:
            raise Problem('Outcome is invalid: ' + str(exc)[:450], 422) from exc
        ref = self.blobs.put('business/outcomes/' + outcome_id + '.json', encode(outcome))
        if json.loads(self.blobs.read(ref)) != outcome:
            raise Problem('Outcome readback differs', 409, 'INTEGRITY_FAILED')
        recorded = dict(outcome, ref=ref)
        response = {'outcome_id': outcome_id, 'digest': outcome['digest'],
                    'publication_id': current['publication_id'],
                    'metric_count': len(outcome['metrics']),
                    'runtime_authority_changed': False}
        return self._commit(op, [('app', oid, 'HEAD', dict(h.value), h.version),
            ('app', oid, 'OUTCOME#' + outcome_id, recorded, None),
            self._event(oid, actor, 'OUTCOME_RECORDED', {
                'outcome_id': outcome_id, 'publication_id': current['publication_id'],
                'target': outcome['target'],
                'authority_result': outcome['authority_result'],
                'metric_count': len(outcome['metrics']),
                'runtime_authority_changed': False})], response)

    def export_interchange(self, actor, oid):
        """Return a deterministic, digest-bound export of the current publication."""
        h = self._head(actor, oid)
        prior = self._prior_publication(h)
        if prior is None:
            raise Problem('Publish an official decision before exporting', 409,
                          'PUBLICATION_REQUIRED')
        publication = prior['publication']
        outcomes = []
        for row in self.db.query('app', oid, 'OUTCOME#'):
            if row.value.get('publication_id') != publication['publication_id']:
                continue
            try:
                stored = json.loads(self.blobs.read(row.value['ref']))
                if stored != {k: v for k, v in row.value.items() if k != 'ref'}:
                    raise ValueError('Outcome record differs from its fixed document')
                outcomes.append(verify_outcome(stored))
            except (KeyError, TypeError, ValueError) as exc:
                raise Problem('Outcome integrity could not be verified', 409,
                              'INTEGRITY_FAILED') from exc
        return build_interchange(workspace_id=h.value['workspace_id'], object_id=oid,
            authority_source=publication['source_authority'],
            decision_pack=prior['decision'], publication=publication, outcomes=outcomes)

    def import_interchange(self, actor, oid, body):
        """Persist an external fixed snapshot without changing the AWS canonical record."""
        h = self._head(actor, oid)
        op = self._operation(actor, 'import:' + oid, body)
        if op[2] is not None:
            return op[2]
        self._version(h, body)
        try:
            document = verify_interchange(body.get('document'))
        except (TypeError, ValueError) as exc:
            raise Problem('Interchange document is invalid: ' + str(exc)[:450], 422,
                          'INTERCHANGE_INVALID') from exc
        authority = document['authority_source']
        if authority == 'aws:solifan':
            raise Problem('This workspace cannot import its own editable authority as an external copy',
                          409, 'OWN_AUTHORITY_IMPORT_REJECTED')
        pack_id = document['pack_id']
        binding_key = 'IMPORT_PACK#' + pack_id
        binding = self.db.get('app', oid, binding_key)
        identity = {'pack_id': pack_id, 'authority_source': authority,
                    'source_workspace_id': document['source_workspace_id'],
                    'source_object_id': document['source_object_id']}
        if binding and binding.value != identity:
            raise Problem('This Decision Pack identifier is already bound to another issuer or object',
                          409, 'PACK_AUTHORITY_CONFLICT')
        if self.db.query('app', oid, 'PACK#' + pack_id + '#'):
            raise Problem('This Decision Pack identifier belongs to the local editable authority',
                          409, 'PACK_AUTHORITY_CONFLICT')
        revision_key = ('IMPORT_REV#' + sha256_json({
            'pack_id': pack_id, 'revision': document['pack_revision']}))
        existing = self.db.get('app', oid, revision_key)
        if existing:
            if existing.value.get('document_digest') != document['document_digest']:
                raise Problem('This Decision Pack revision already has different fixed content',
                              409, 'IMPORT_REVISION_CONFLICT')
            response = {'import_id': existing.value['import_id'],
                        'document_digest': document['document_digest'],
                        'already_imported': True, 'canonical_decision_changed': False,
                        'runtime_authority_changed': False,
                        'transport_status': 'FILE_INTERCHANGE_ONLY'}
            return self._commit(op, [], response)
        outcome_writes = []
        for outcome in document['outcomes']:
            key = 'IMPORT_OUTCOME#' + outcome['outcome_id']
            previous = self.db.get('app', oid, key)
            outcome_binding = {'outcome_id': outcome['outcome_id'],
                'authority_source': authority, 'source_object_id': document['source_object_id'],
                'digest': outcome['digest']}
            if previous and previous.value != outcome_binding:
                raise Problem('An Outcome identifier is already bound to different content or issuer',
                              409, 'OUTCOME_AUTHORITY_CONFLICT')
            if self.db.get('app', oid, 'OUTCOME#' + outcome['outcome_id']):
                raise Problem('An Outcome identifier belongs to the local editable authority',
                              409, 'OUTCOME_AUTHORITY_CONFLICT')
            if previous is None:
                outcome_writes.append(('app', oid, key, outcome_binding, None))
        import_id = uid('import')
        ref = self.blobs.put('business/imports/' + import_id + '.json', encode(document))
        if json.loads(self.blobs.read(ref)) != document:
            raise Problem('Imported document readback differs', 409, 'INTEGRITY_FAILED')
        recorded = {'import_id': import_id, **identity,
                    'pack_revision': document['pack_revision'],
                    'decision_digest': document['decision_digest'],
                    'document_digest': document['document_digest'],
                    'outcome_count': len(document['outcomes']), 'ref': ref,
                    'imported_by': actor['sub'], 'imported_at': self.clock(),
                    'canonical_decision_changed': False,
                    'runtime_authority_changed': False,
                    'transport_status': 'FILE_INTERCHANGE_ONLY'}
        response = {'import_id': import_id,
                    'document_digest': document['document_digest'],
                    'already_imported': False, 'canonical_decision_changed': False,
                    'runtime_authority_changed': False,
                    'transport_status': 'FILE_INTERCHANGE_ONLY'}
        writes = [('app', oid, 'HEAD', dict(h.value), h.version)]
        if binding is None:
            writes.append(('app', oid, binding_key, identity, None))
        writes.extend([('app', oid, revision_key, recorded, None), *outcome_writes,
            self._event(oid, actor, 'INTERCHANGE_IMPORTED', {
                'import_id': import_id, 'authority_source': authority,
                'source_object_id': document['source_object_id'], 'pack_id': pack_id,
                'pack_revision': document['pack_revision'],
                'document_digest': document['document_digest'],
                'outcome_count': len(document['outcomes']),
                'canonical_decision_changed': False,
                'runtime_authority_changed': False,
                'transport_status': 'FILE_INTERCHANGE_ONLY'})])
        return self._commit(op, writes, response)

    def approve_delegation(self, actor, oid, body):
        """Authorize an attempt to apply one registered profile to the current publication."""
        h = self._head(actor, oid)
        op = self._operation(actor, 'delegation:' + oid, body)
        if op[2] is not None:
            return op[2]
        self._version(h, body)
        current = h.value.get('published_current')
        if (current is None or body.get('publication_id') != current['publication_id']
                or body.get('publication_digest') != current['digest']):
            raise Problem('Select the current official publication for AWS delegation', 409,
                          'PUBLICATION_STALE')
        self._prior_publication(h)
        registration = self._adapter(body.get('adapter_id'), body.get('connection_id'))
        if body.get('adapter_version') != registration['adapter_version']:
            raise Problem('The selected adapter version is not registered', 409,
                          'ADAPTER_NOT_REGISTERED')
        binding = {k: registration[k] for k in ('adapter_id', 'adapter_version', 'connection_id', 'registration_hash')}
        if h.value.get('execution_connection') != binding:
            raise Problem('Select this execution connection explicitly for this business object first',
                          409, 'OBJECT_CONNECTION_REQUIRED')
        profile_id = body.get('profile_id')
        if profile_id not in registration['profiles']:
            raise Problem('The selected AWS delegation profile is not registered', 409,
                          'PROFILE_NOT_REGISTERED')
        latest_application = h.value.get('latest_application')
        if latest_application and latest_application.get('status') in ('APPLYING', 'CANARY', 'UNKNOWN'):
            raise Problem('Resolve the current AWS application before approving another delegation',
                          409, 'APPLICATION_UNRESOLVED')
        control = h.value.get('authority_control')
        if control and control.get('status') in ('STOP_REQUESTED', 'UNKNOWN'):
            raise Problem('Complete the current AWS authority removal before approving another delegation',
                          409, 'REVOCATION_UNRESOLVED')
        if len(self.db.query('app', oid, 'DELEGATION#')) >= 60:
            raise Problem('Delegation receipt limit reached for this object', 409,
                          'DELEGATION_LIMIT')
        reason = text(body.get('reason'), 'Delegation reason', high=1600)
        valid_days = body.get('valid_days', 7)
        if type(valid_days) is not int or not 1 <= valid_days <= 30:
            raise Problem('Delegation validity must be between one and thirty days')
        generation = h.value.get('delegation_generation', 0) + 1
        receipt = build_delegation_receipt(receipt_id=uid('delegation'),
            object_record=h.value, publication=current, publication_ref=current['ref'],
            registration=registration, profile_id=profile_id, actor=actor, reason=reason,
            valid_days=valid_days, approved_at=self.clock(), approval_generation=generation)
        ref = self.blobs.put('business/delegations/' + receipt['receipt_id'] + '.json',
                             encode(receipt))
        if json.loads(self.blobs.read(ref)) != receipt:
            raise Problem('Delegation receipt readback differs', 409, 'INTEGRITY_FAILED')
        recorded = dict(receipt, ref=ref)
        applied = h.value.get('applied_binding')
        active_control = (control and control.get('status') == 'VERIFIED'
                          and control.get('entry_status') == 'OPEN'
                          and control.get('runtime_authority_active') is True)
        status = ('VERIFIED' if active_control and applied
                  and applied['publication_id'] == current['publication_id']
                  else 'DELEGATION_APPROVED')
        updated = dict(h.value, delegation_generation=generation,
                       delegation_approval=recorded, application_status=status)
        response = {'delegation_receipt_id': receipt['receipt_id'],
                    'delegation_receipt_digest': receipt['digest'],
                    'publication_id': receipt['publication_id'], 'profile_id': profile_id,
                    'runtime_authority_active': False, 'expires_at': receipt['expires_at']}
        return self._commit(op, [('app', oid, 'HEAD', updated, h.version),
            ('app', oid, 'DELEGATION#' + receipt['receipt_id'], recorded, None),
            self._event(oid, actor, 'AWS_DELEGATION_APPROVED', {
                'delegation_receipt_id': receipt['receipt_id'],
                'publication_id': current['publication_id'],
                'adapter_id': registration['adapter_id'],
                'connection_id': registration['connection_id'], 'profile_id': profile_id,
                'runtime_authority_active': False})], response)

    def start_application(self, actor, oid, body):
        """Commit a single-writer application candidate; execution stays asynchronous."""
        h = self._head(actor, oid)
        op = self._operation(actor, 'applications:' + oid, body)
        if op[2] is not None:
            self._try_application_dispatch(op[2])
            return op[2]
        self._version(h, body)
        recorded = h.value.get('delegation_approval')
        if recorded is None or body.get('delegation_receipt_id') != recorded['receipt_id']:
            raise Problem('The current publication needs an explicit AWS delegation approval',
                          409, 'DELEGATION_REQUIRED')
        current = h.value.get('published_current')
        if current is None:
            raise Problem('Publish an official decision before AWS application', 409,
                          'PUBLICATION_REQUIRED')
        latest_application = h.value.get('latest_application')
        if latest_application and latest_application.get('status') in ('APPLYING', 'CANARY', 'UNKNOWN'):
            raise Problem('Another AWS application owns this connection and policy engine',
                          409, 'APPLICATION_ACTIVE')
        control = h.value.get('authority_control')
        if control and control.get('status') in ('STOP_REQUESTED', 'UNKNOWN'):
            raise Problem('Complete the current AWS authority removal before starting another application',
                          409, 'REVOCATION_UNRESOLVED')
        if len(self.db.query('app', oid, 'APPLICATION#')) >= 60:
            raise Problem('AWS application limit reached for this object', 409,
                          'APPLICATION_LIMIT')
        registration = self._adapter(recorded['adapter_id'], recorded['connection_id'])
        lock_pk = 'AUTHORITY#' + registration['connection_id'] + '#' + registration['policy_engine_id']
        if self.db.get('app', lock_pk, 'WRITER') is not None:
            raise Problem('Another AWS application owns this connection and policy engine',
                          409, 'APPLICATION_ACTIVE')
        try:
            stored = json.loads(self.blobs.read(recorded['ref']))
            if stored != {k: v for k, v in recorded.items() if k != 'ref'}:
                raise ValueError('Delegation record differs from its receipt')
            receipt = verify_delegation_receipt(stored, object_record=h.value,
                publication=current, registration=registration,
                current_generation=h.value.get('delegation_generation'), at=self.clock())
        except (KeyError, TypeError, ValueError) as exc:
            raise Problem('AWS delegation receipt integrity could not be verified', 409,
                          'DELEGATION_INTEGRITY_FAILED') from exc
        application_id = uid('application')
        stamp = self.clock()
        previous = (h.value.get('applied_binding') if control
                    and control.get('status') == 'VERIFIED'
                    and control.get('entry_status') == 'OPEN'
                    and control.get('runtime_authority_active') is True else None)
        candidate = build_enforcement_candidate(application_id=application_id,
            receipt=receipt, receipt_ref=recorded['ref'], publication=current,
            publication_ref=current['ref'],
            previous_applied_binding=previous, created_at=stamp)
        candidate_ref = self.blobs.put('business/applications/' + application_id +
                                       '/candidate.json', encode(candidate))
        if json.loads(self.blobs.read(candidate_ref)) != candidate:
            raise Problem('AWS application candidate readback differs', 409, 'INTEGRITY_FAILED')
        lock = {'application_id': application_id, 'object_id': oid,
                'enforcement_digest': candidate['enforcement_digest'],
                'connection_id': registration['connection_id'],
                'policy_engine_id': registration['policy_engine_id'], 'acquired_at': stamp}
        state = {'application_id': application_id, 'object_id': oid, 'status': 'APPLYING',
                 'created_at': stamp, 'updated_at': stamp, 'attempt': 0,
                 'candidate_ref': candidate_ref,
                 'enforcement_digest': candidate['enforcement_digest'],
                 'delegation_receipt_id': receipt['receipt_id'],
                 'delegation_receipt_digest': receipt['digest'],
                 'publication_id': current['publication_id'],
                 'publication_digest': current['digest'],
                 'connection_id': registration['connection_id'],
                 'policy_engine_id': registration['policy_engine_id'],
                 'lock_pk': lock_pk, 'lease_until': None,
                 'next_attempt_at': None, 'result_ref': None,
                 'last_error': None}
        summary = {'application_id': application_id, 'status': 'APPLYING',
                   'enforcement_digest': candidate['enforcement_digest'],
                   'publication_id': current['publication_id'], 'updated_at': stamp}
        updated = dict(h.value, latest_application=summary, application_status='APPLYING')
        response = {'object_id': oid, 'application_id': application_id, 'status': 'APPLYING',
                    'enforcement_digest': candidate['enforcement_digest'],
                    'runtime_authority_active': False}
        message = {k: response[k] for k in (
            'object_id', 'application_id', 'enforcement_digest')}
        try:
            result = self._commit(op, [('app', oid, 'HEAD', updated, h.version),
                ('app', oid, 'APPLICATION#' + application_id, state, None),
                ('app', lock_pk, 'WRITER', lock, None),
                ('jobs', 'APPLICATION_OUTBOX', application_id, message, None),
                self._event(oid, actor, 'AWS_APPLICATION_STARTED', {
                    'application_id': application_id,
                    'delegation_receipt_id': receipt['receipt_id'],
                    'enforcement_digest': candidate['enforcement_digest'],
                    'runtime_authority_active': False})], response)
        except Problem as exc:
            if exc.code == 'STALE_VERSION' and self.db.get('app', lock_pk, 'WRITER'):
                raise Problem('Another AWS application owns this connection and policy engine',
                              409, 'APPLICATION_ACTIVE') from exc
            raise
        self._try_application_dispatch(result)
        return result

    def stop_application(self, actor, oid, application_id, body):
        """Close the controlled entry immediately and queue exact Policy removal."""
        h = self._head(actor, oid)
        if not re.fullmatch(r'application-[0-9a-f]{32}', application_id):
            raise Problem('AWS application not found', 404, 'NOT_FOUND')
        op = self._operation(actor, 'stop:' + oid + ':' + application_id, body)
        if op[2] is not None:
            self._try_application_dispatch(op[2])
            return op[2]
        self._version(h, body)
        applied = h.value.get('applied_binding')
        application = self.db.get('app', oid, 'APPLICATION#' + application_id)
        if (not applied or application is None
                or applied.get('application_id') != application_id
                or applied.get('enforcement_digest')
                    != application.value.get('enforcement_digest')
                or application.value.get('status') != 'VERIFIED'):
            raise Problem('Only the current verified AWS application can be stopped', 409,
                          'APPLICATION_NOT_ACTIVE')
        control = h.value.get('authority_control')
        if (control and control.get('application_id') == application_id
                and control.get('status') != 'VERIFIED'):
            if control.get('status') == 'SUSPENDED_CONFIRMED':
                raise Problem('This AWS authority is already suspended', 409,
                              'ALREADY_SUSPENDED')
            raise Problem('This AWS authority removal is already in progress', 409,
                          'REVOCATION_UNRESOLVED')
        if len(self.db.query('app', oid, 'REVOCATION#')) >= 60:
            raise Problem('AWS authority revocation limit reached for this object', 409,
                          'REVOCATION_LIMIT')
        candidate = json.loads(self.blobs.read(application.value['candidate_ref']))
        if (candidate.get('enforcement_digest') != applied['enforcement_digest']
                or sha256_json({k: v for k, v in candidate.items()
                                if k != 'enforcement_digest'})
                    != candidate.get('enforcement_digest')):
            raise Problem('AWS application candidate integrity could not be verified', 409,
                          'INTEGRITY_FAILED')
        reason = text(body.get('reason'), 'Stop reason', high=1600)
        generation = h.value.get('delegation_generation', 0) + 1
        request = build_revocation_request(revocation_id=uid('revocation'),
            candidate=candidate, applied_binding=applied, trigger='MANUAL',
            reason=reason, actor=actor, requested_at=self.clock(),
            invalidated_generation=generation)
        request_ref = self.blobs.put('business/revocations/' + request['revocation_id']
            + '/request.json', encode(request))
        if json.loads(self.blobs.read(request_ref)) != request:
            raise Problem('AWS revocation request readback differs', 409, 'INTEGRITY_FAILED')
        state = revocation_state(request, request_ref, applied,
                                 application.value['lock_pk'])
        message = revocation_message(request)
        authority_control = {'schema_version': '1.0',
            'revocation_id': request['revocation_id'],
            'revocation_digest': request['digest'], 'application_id': application_id,
            'entry_status': 'CLOSED', 'status': 'STOP_REQUESTED',
            'trigger': 'MANUAL', 'requested_at': request['requested_at'],
            'updated_at': request['requested_at'], 'policy_status': 'REMOVAL_PENDING',
            'deny_status': 'NOT_CONFIRMED', 'runtime_authority_active': False,
            'last_error': None}
        updated = dict(h.value, delegation_generation=generation,
                       delegation_approval=None, application_status='STOP_REQUESTED',
                       authority_control=authority_control)
        response = {**message, 'status': 'STOP_REQUESTED',
                    'entry_status': 'CLOSED',
                    'policy_status': 'REMOVAL_PENDING',
                    'deny_status': 'NOT_CONFIRMED',
                    'runtime_authority_active': False}
        result = self._commit(op, [('app', oid, 'HEAD', updated, h.version),
            ('app', oid, 'REVOCATION#' + request['revocation_id'], state, None),
            ('jobs', 'APPLICATION_OUTBOX', request['revocation_id'], message, None),
            self._event(oid, actor, 'AWS_AUTHORITY_STOP_REQUESTED', {
                'revocation_id': request['revocation_id'],
                'application_id': application_id, 'trigger': 'MANUAL',
                'entry_status': 'CLOSED', 'policy_status': 'REMOVAL_PENDING',
                'deny_status': 'NOT_CONFIRMED',
                'runtime_authority_active': False, 'reason': reason})], response)
        self._try_application_dispatch(result)
        return result

    def request_revocation(self, actor, oid, body):
        return self.stop_application(actor, oid, body.get('application_id'), body)

    def _try_application_dispatch(self, response):
        if self.application_dispatch:
            try:
                if response.get('operation') == 'REVOKE':
                    message = {k: response[k] for k in ('operation', 'object_id',
                        'application_id', 'enforcement_digest', 'revocation_id',
                        'revocation_digest')}
                else:
                    message = {'object_id': response['object_id'],
                        'application_id': response['application_id'],
                        'enforcement_digest': response['enforcement_digest']}
                state = self.db.get('app', response['object_id'],
                    ('REVOCATION#' + response['revocation_id'])
                    if response.get('operation') == 'REVOKE'
                    else ('APPLICATION#' + response['application_id']))
                active = (('STOP_REQUESTED', 'REVOKING', 'UNKNOWN')
                          if response.get('operation') == 'REVOKE'
                          else ('APPLYING', 'CANARY', 'UNKNOWN'))
                if state and state.value.get('status') in active:
                    outbox = self.db.get('jobs', 'APPLICATION_OUTBOX',
                                         response.get('revocation_id', response['application_id']))
                    if outbox is None:
                        self.db.transact([('jobs', 'APPLICATION_OUTBOX',
                            response.get('revocation_id', response['application_id']),
                            message, None)])
                self.application_dispatch(message)
            except Exception:
                pass  # The committed application and writer lock are the durable outbox.

    def export_acceptance_evidence(self, actor, oid):
        """Export the authenticated object history after verifying every fixed blob.

        This is a read-only evidence operation. Connector ExternalIds are redacted
        by the portable acceptance contract after the source chain is verified.
        """
        h = self._head(actor, oid)
        rows = self.db.query('app', oid)

        evidence = []
        for row in self.db.query('app', oid, 'EVIDENCE#'):
            item = copy.deepcopy(row.value)
            raw = self.blobs.read(item['original'])
            if (item.get('object_id') != oid
                    or item.get('text_hash') != sha256_json(item.get('text'))
                    or len(raw) != item['original'].get('size')):
                raise Problem('Evidence integrity could not be verified', 409,
                              'INTEGRITY_FAILED')
            evidence.append(item)

        assessments = []
        for pointer in self.db.query('app', oid, 'RUN#'):
            run_id = pointer.value.get('run_id')
            state = self.db.get('jobs', run_id, 'STATE')
            if state is None or state.value.get('object_id') != oid:
                raise Problem('Assessment history is incomplete', 409,
                              'INTEGRITY_FAILED')
            try:
                snapshot = json.loads(self.blobs.read(state.value['input_ref']))
                check_snapshot(snapshot)
                if snapshot['input_hash'] != state.value['input_hash']:
                    raise ValueError('Assessment input binding differs')
                analysis = None
                if state.value.get('result_ref') is not None:
                    analysis = json.loads(self.blobs.read(state.value['result_ref']))
                    if analysis.get('input_hash') != state.value['input_hash']:
                        raise ValueError('Assessment result binding differs')
                    validate_proposal(analysis.get('proposal'), snapshot,
                                      set(analysis.get('reads', [])))
                assessments.append({'object_id': oid,
                    'state': copy.deepcopy(state.value),
                    'input_snapshot': snapshot, 'analysis': analysis})
            except (KeyError, TypeError, ValueError) as exc:
                raise Problem('Assessment integrity could not be verified', 409,
                              'INTEGRITY_FAILED') from exc

        decisions = []
        publications = {}
        for row in self.db.query('app', oid, 'PUBLICATION#'):
            recorded = row.value
            try:
                publication = json.loads(self.blobs.read(recorded['ref']))
                if publication != {k: v for k, v in recorded.items() if k != 'ref'}:
                    raise ValueError('Publication record differs from its document')
                decision = json.loads(self.blobs.read(publication['decision_ref']))
                receipt = json.loads(self.blobs.read(publication['receipt_ref']))
                if (decision.get('object_id') != oid
                        or decision.get('digest') != publication.get('digest')
                        or sha256_json({k: v for k, v in decision.items()
                                       if k != 'digest'}) != decision.get('digest')
                        or receipt.get('object_id') != oid
                        or receipt.get('receipt_id') != publication.get('receipt_id')
                        or receipt.get('digest') != publication.get('digest')
                        or receipt.get('decision') != 'APPROVE'
                        or receipt.get('runtime_authority_granted') is not False):
                    raise ValueError('Publication authority chain differs')
                source = next((item['input_snapshot'] for item in assessments
                               if item['state']['run_id'] == decision.get('run_id')), None)
                if source is None or decision.get('input_hash') != source.get('input_hash'):
                    raise ValueError('Published decision input is missing')
                validate_proposal(decision.get('proposal'), source)
            except (KeyError, TypeError, ValueError) as exc:
                raise Problem('Publication integrity could not be verified', 409,
                              'INTEGRITY_FAILED') from exc
            publications[publication['publication_id']] = recorded
            decisions.append({'object_id': oid, 'publication': publication,
                              'decision_pack': decision,
                              'approval_receipt': receipt})
        ordered_decisions = []
        remaining = list(decisions)
        previous_id = None
        while remaining:
            matches = [item for item in remaining
                       if item['publication'].get('previous_publication_id') == previous_id]
            if len(matches) != 1:
                raise Problem('Publication history is not one continuous chain', 409,
                              'INTEGRITY_FAILED')
            item = matches[0]
            ordered_decisions.append(item)
            remaining.remove(item)
            previous_id = item['publication']['publication_id']
        decisions = ordered_decisions

        delegations = []
        delegation_sources = {}
        for row in self.db.query('app', oid, 'DELEGATION#'):
            recorded = row.value
            try:
                raw = json.loads(self.blobs.read(recorded['ref']))
                if raw != {k: v for k, v in recorded.items() if k != 'ref'}:
                    raise ValueError('Delegation record differs from its receipt')
                publication = publications[raw['publication_id']]
                registration = self._adapter(raw['adapter_id'], raw['connection_id'])
                verified = verify_delegation_receipt(raw, object_record=h.value,
                    publication=publication, registration=registration)
            except (KeyError, TypeError, ValueError) as exc:
                raise Problem('Delegation integrity could not be verified', 409,
                              'INTEGRITY_FAILED') from exc
            delegation_sources[verified['receipt_id']] = dict(verified,
                                                               ref=recorded['ref'])
            delegations.append(verified)

        applications = []
        application_sources = {}
        for row in self.db.query('app', oid, 'APPLICATION#'):
            state = row.value
            try:
                receipt = delegation_sources[state['delegation_receipt_id']]
                publication = publications[state['publication_id']]
                candidate = json.loads(self.blobs.read(state['candidate_ref']))
                candidate = verify_enforcement_candidate(candidate,
                    receipt=receipt, publication=publication)
                result = None
                if state.get('result_ref') is not None:
                    result = json.loads(self.blobs.read(state['result_ref']))
                    result = verify_publisher_result(result, candidate)
                    if result['status'] != state['status']:
                        raise ValueError('Application result status differs')
                applications.append({'object_id': oid, 'state': copy.deepcopy(state),
                                     'candidate': candidate,
                                     'publisher_result': result})
                application_sources[state['application_id']] = candidate
            except (KeyError, TypeError, ValueError) as exc:
                raise Problem('Application integrity could not be verified', 409,
                              'INTEGRITY_FAILED') from exc

        revocations = []
        for row in self.db.query('app', oid, 'REVOCATION#'):
            state = row.value
            try:
                candidate = application_sources[state['application_id']]
                applied = state['applied_binding']
                if sha256_json({k: v for k, v in applied.items() if k != 'digest'}) != applied.get('digest'):
                    raise ValueError('Revocation AppliedBinding digest differs')
                request = verify_revocation_request(
                    json.loads(self.blobs.read(state['request_ref'])),
                    candidate=candidate, applied_binding=applied)
                if request['digest'] != state['revocation_digest']:
                    raise ValueError('Revocation state differs from its request')
                result = None
                if state.get('result_ref') is not None:
                    result = verify_revocation_result(
                        json.loads(self.blobs.read(state['result_ref'])), request, candidate)
                revocations.append({'object_id': oid, 'state': copy.deepcopy(state),
                    'request': request, 'publisher_result': result})
            except (KeyError, TypeError, ValueError) as exc:
                raise Problem('Revocation integrity could not be verified', 409,
                              'INTEGRITY_FAILED') from exc

        outcomes = []
        for row in self.db.query('app', oid, 'OUTCOME#'):
            try:
                raw = json.loads(self.blobs.read(row.value['ref']))
                if raw != {k: v for k, v in row.value.items() if k != 'ref'}:
                    raise ValueError('Outcome record differs from its document')
                outcomes.append(verify_outcome(raw))
            except (KeyError, TypeError, ValueError) as exc:
                raise Problem('Outcome integrity could not be verified', 409,
                              'INTEGRITY_FAILED') from exc

        imports = []
        for row in self.db.query('app', oid, 'IMPORT_REV#'):
            try:
                document = verify_interchange(json.loads(self.blobs.read(row.value['ref'])))
                if document['document_digest'] != row.value['document_digest']:
                    raise ValueError('Imported document binding differs')
                imports.append({'object_id': oid, 'record': copy.deepcopy(row.value),
                                'document': document})
            except (KeyError, TypeError, ValueError) as exc:
                raise Problem('Imported record integrity could not be verified', 409,
                              'INTEGRITY_FAILED') from exc

        actions = [dict(row.value, record_revision=row.version)
                   for row in self.db.query('app', oid, 'ACTION#')]
        invocations = []
        for row in self.db.query('app', oid, 'INVOCATION#'):
            state = row.value
            try:
                result = None
                if state.get('status') == 'EXECUTED' and state.get('result_ref'):
                    result = json.loads(self.blobs.read(state['result_ref']))
                invocations.append({'object_id': oid,
                    'state': copy.deepcopy(state), 'result': result})
            except (KeyError, TypeError, ValueError) as exc:
                raise Problem('Invocation integrity could not be verified', 409,
                              'INTEGRITY_FAILED') from exc
        history = sorted((copy.deepcopy(row.value) for row in rows
                          if 'event_id' in row.value),
                         key=lambda item: (item['at'], item['event_id']))
        object_record = dict(h.value, record_revision=h.version)
        try:
            return build_acceptance_evidence(object_record=object_record,
                evidence=sorted(evidence, key=lambda item: item['evidence_id']),
                assessments=sorted(assessments,
                    key=lambda item: (item['state']['created_at'], item['state']['run_id'])),
                decisions=decisions,
                actions=sorted(actions, key=lambda item: item['action_id']),
                delegations=sorted(delegations, key=lambda item: item['receipt_id']),
                applications=sorted(applications,
                    key=lambda item: item['state']['application_id']),
                revocations=sorted(revocations,
                    key=lambda item: item['state']['revocation_id']),
                invocations=sorted(invocations,
                    key=lambda item: item['state']['operation_id']),
                outcomes=sorted(outcomes, key=lambda item: item['outcome_id']),
                imports=sorted(imports, key=lambda item: item['record']['import_id']),
                history=history,
                available_adapters=self._object_adapters(h.value))
        except (KeyError, TypeError, ValueError) as exc:
            raise Problem('Acceptance export integrity could not be verified', 409,
                          'INTEGRITY_FAILED') from exc

    def detail(self, actor, oid):
        h = self._head(actor, oid)
        items = [r.value for r in self.db.query('app', oid)]
        evidence = [v for v in items if 'evidence_id' in v and 'original' in v]
        history = sorted([v for v in items if 'event_id' in v], key=lambda x: x['at'], reverse=True)
        runs = []
        for v in items:
            if set(v) == {'run_id', 'created_at'}:
                job = self._job(v['run_id'])
                if job:
                    runs.append(job.value)
        actions = [dict(r.value, record_revision=r.version)
                   for r in self.db.query('app', oid, 'ACTION#')]
        outcomes = [dict(r.value, record_revision=r.version)
                    for r in self.db.query('app', oid, 'OUTCOME#')]
        imports = [dict(r.value, record_revision=r.version)
                   for r in self.db.query('app', oid, 'IMPORT_REV#')]
        invocation_records = []
        for value in (v for v in items if v.get('kind') == 'CONTROLLED_INVOCATION'):
            result_value = None
            if value.get('status') == 'EXECUTED' and value.get('result_ref'):
                result_value = json.loads(self.blobs.read(value['result_ref']))
            invocation_records.append(dict(value, result=result_value))
        result = {'object': dict(h.value, record_revision=h.version), 'evidence': evidence, 'history': history,
                  'runs': sorted(runs, key=lambda x: x['created_at'], reverse=True),
                  'publications': [v for v in items if 'publication_id' in v and 'decision_ref' in v],
                  'receipts': [v for v in items if v.get('kind') == 'BUSINESS_DECISION_ONLY'],
                  'delegation_receipts': [v for v in items if v.get('kind') == 'AWS_DELEGATION_AUTHORITY'],
                  'applications': [v for v in items if 'application_id' in v and 'candidate_ref' in v],
                  'revocations': [v for v in items if v.get('kind') == 'AUTHORITY_REVOCATION'],
                  'invocations': invocation_records,
                  'action_records': sorted(actions, key=lambda x: x['created_at'], reverse=True),
                  'outcome_records': sorted(outcomes, key=lambda x: x['recorded_at'], reverse=True),
                  'imported_records': sorted(imports, key=lambda x: x['imported_at'], reverse=True),
                  'available_adapters': self._object_adapters(h.value),
                  'registered_adapters': self.registered_adapters()}
        result['draft'] = json.loads(self.blobs.read(h.value['draft']['ref'])) if h.value['draft'] else None
        result['official_decision'] = json.loads(self.blobs.read(h.value['published_current']['decision_ref'])) if h.value['published_current'] else None
        return result

    def original(self, actor, oid, eid):
        self._head(actor, oid)
        row = self.db.get('app', oid, 'EVIDENCE#' + eid)
        if not row:
            raise Problem('Evidence not found', 404, 'NOT_FOUND')
        e = row.value
        return {'filename': e['filename'], 'content_base64': base64.b64encode(self.blobs.read(e['original'])).decode()}
