"""Version-fixed Decision Pack and Outcome interchange contracts.

Imported documents are immutable references.  They never become this AWS
workspace's editable or published canonical decision.
"""
from __future__ import annotations

import copy
import math
import re

from authority_delta.canonical import sha256_json


AUTHORITY_PATTERN = re.compile(r'^(aws|snowflake):[A-Za-z0-9._:/-]{1,180}$')
TARGET_KINDS = {'DECISION_PUBLICATION', 'AWS_APPLICATION', 'TRACE'}
AUTHORITY_RESULTS = {'ALLOW', 'DENY', 'ERROR'}
MEASUREMENT_STATES = {'MEASURED', 'NOT_MEASURED'}
MEASUREMENT_BASES = {'OBSERVED', 'ESTIMATED'}


def _plain_text(value, name, low=1, high=1000):
    if (not isinstance(value, str) or not low <= len(value.strip()) <= high
            or '\x00' in value):
        raise ValueError(f'{name} is invalid')
    return value.strip()


def validate_authority(value):
    if not isinstance(value, str) or not AUTHORITY_PATTERN.fullmatch(value):
        raise ValueError('authority_source is invalid')
    return value


def normalize_metrics(values):
    if not isinstance(values, list) or len(values) > 16:
        raise ValueError('metrics must contain at most sixteen items')
    result = []
    for raw in values:
        if not isinstance(raw, dict):
            raise ValueError('metric must be an object')
        state = raw.get('measurement_status')
        if state not in MEASUREMENT_STATES:
            raise ValueError('metric measurement_status is invalid')
        metric = {
            'name': _plain_text(raw.get('name'), 'metric name', high=160),
            'measurement_status': state,
            'source': _plain_text(raw.get('source'), 'metric source', high=1000),
        }
        if state == 'MEASURED':
            value = raw.get('value')
            if (isinstance(value, bool) or not isinstance(value, (int, float))
                    or not math.isfinite(value)):
                raise ValueError('measured metric value must be finite')
            if raw.get('basis') not in MEASUREMENT_BASES:
                raise ValueError('measured metric basis is invalid')
            metric.update(value=value,
                          unit=_plain_text(raw.get('unit'), 'metric unit', high=80),
                          period=_plain_text(raw.get('period'), 'metric period', high=160),
                          basis=raw['basis'])
            if raw.get('reason') not in (None, ''):
                raise ValueError('measured metric cannot carry an unmeasured reason')
        else:
            if any(key in raw for key in ('value', 'unit', 'period', 'basis')):
                raise ValueError('unmeasured metric cannot imply a value, unit, period or basis')
            metric['reason'] = _plain_text(raw.get('reason'), 'unmeasured reason', high=700)
        allowed = set(metric)
        if set(raw) != allowed:
            raise ValueError('metric contains unexpected fields')
        result.append(metric)
    return result


def build_outcome(*, outcome_id, object_record, publication, target, authority_result,
                  business_result, metrics, actor, recorded_at):
    if not isinstance(target, dict) or set(target) - {'kind', 'id', 'digest'}:
        raise ValueError('outcome target is invalid')
    if target.get('kind') not in TARGET_KINDS:
        raise ValueError('outcome target kind is invalid')
    normalized_target = {
        'kind': target['kind'],
        'id': _plain_text(target.get('id'), 'outcome target id', high=200),
    }
    if target.get('digest') is not None:
        if not re.fullmatch(r'[0-9a-f]{64}', str(target['digest'])):
            raise ValueError('outcome target digest is invalid')
        normalized_target['digest'] = target['digest']
    if authority_result not in AUTHORITY_RESULTS:
        raise ValueError('outcome authority result is invalid')
    value = {
        'schema_version': '1.2', 'kind': 'BUSINESS_OUTCOME',
        'outcome_id': outcome_id, 'object_id': object_record['object_id'],
        'workspace_id': object_record['workspace_id'],
        'authority_source': publication['source_authority'],
        'publication_id': publication['publication_id'],
        'pack_id': publication['pack_id'], 'pack_revision': publication['revision'],
        'decision_digest': publication['digest'], 'target': normalized_target,
        'authority_result': authority_result,
        'business_result': _plain_text(business_result, 'business result', high=1600),
        'metrics': normalize_metrics(metrics),
        'recorded_by': actor['sub'], 'recorded_at': recorded_at,
    }
    value['digest'] = sha256_json(value)
    return value


def verify_outcome(value, authority=None, source_object_id=None, pack=None):
    if not isinstance(value, dict) or value.get('kind') != 'BUSINESS_OUTCOME':
        raise ValueError('outcome kind is invalid')
    required = {'schema_version', 'kind', 'outcome_id', 'object_id', 'workspace_id',
                'authority_source', 'publication_id', 'pack_id', 'pack_revision',
                'decision_digest', 'target', 'authority_result', 'business_result',
                'metrics', 'recorded_by', 'recorded_at', 'digest'}
    if set(value) != required or value.get('schema_version') != '1.2':
        raise ValueError('outcome fields are invalid')
    if not re.fullmatch(r'outcome-[0-9a-f]{32}', str(value.get('outcome_id'))):
        raise ValueError('outcome identifier is invalid')
    if (not re.fullmatch(r'o-[A-Za-z0-9_-]{8,80}', str(value.get('object_id')))
            or not re.fullmatch(r'[A-Za-z0-9._:-]{1,80}', str(value.get('workspace_id')))
            or not re.fullmatch(r'pub-[A-Za-z0-9_-]{8,80}', str(value.get('publication_id')))
            or not re.fullmatch(r'pack-[A-Za-z0-9_-]{8,80}', str(value.get('pack_id')))
            or type(value.get('pack_revision')) is not int
            or value['pack_revision'] < 1
            or not re.fullmatch(r'[0-9a-f]{64}', str(value.get('decision_digest')))):
        raise ValueError('outcome version binding is invalid')
    target = value.get('target')
    if (isinstance(target, dict)
            and target.get('kind') in {'DECISION_PUBLICATION', 'AWS_APPLICATION'}
            and 'digest' not in target):
        raise ValueError('saved outcome target requires a digest')
    validate_authority(value.get('authority_source'))
    normalized = build_outcome(outcome_id=value['outcome_id'],
        object_record={'object_id': value['object_id'], 'workspace_id': value['workspace_id']},
        publication={'source_authority': value['authority_source'],
                     'publication_id': value['publication_id'], 'pack_id': value['pack_id'],
                     'revision': value['pack_revision'], 'digest': value['decision_digest']},
        target=value['target'], authority_result=value['authority_result'],
        business_result=value['business_result'], metrics=value['metrics'],
        actor={'sub': value['recorded_by']}, recorded_at=value['recorded_at'])
    if normalized != value or sha256_json({k: v for k, v in value.items() if k != 'digest'}) != value['digest']:
        raise ValueError('outcome digest differs')
    if authority is not None and value['authority_source'] != authority:
        raise ValueError('outcome authority differs')
    if source_object_id is not None and value['object_id'] != source_object_id:
        raise ValueError('outcome object differs')
    if pack is not None and (value['pack_id'], value['pack_revision'], value['decision_digest']) != pack:
        raise ValueError('outcome Decision Pack binding differs')
    return copy.deepcopy(value)


def build_interchange(*, workspace_id, object_id, authority_source, decision_pack,
                      publication, outcomes):
    validate_authority(authority_source)
    clean_publication = {k: copy.deepcopy(v) for k, v in publication.items()
                         if k not in ('ref', 'decision_ref', 'receipt_ref')}
    value = {
        'schema_version': '1.2', 'kind': 'READINESSOPS_INTERCHANGE',
        'authority_source': authority_source,
        'source_workspace_id': workspace_id, 'source_object_id': object_id,
        'pack_id': decision_pack['pack_id'], 'pack_revision': decision_pack['revision'],
        'decision_digest': decision_pack['digest'],
        'decision_pack': copy.deepcopy(decision_pack),
        'publication': clean_publication,
        'outcomes': sorted((copy.deepcopy(v) for v in outcomes),
                           key=lambda v: v['outcome_id']),
        'transport_status': 'FILE_INTERCHANGE_ONLY',
    }
    value['document_digest'] = sha256_json(value)
    return value


def verify_interchange(value):
    if not isinstance(value, dict):
        raise ValueError('interchange document must be an object')
    required = {'schema_version', 'kind', 'authority_source', 'source_workspace_id',
                'source_object_id', 'pack_id', 'pack_revision', 'decision_digest',
                'decision_pack', 'publication', 'outcomes', 'transport_status',
                'document_digest'}
    if (set(value) != required or value.get('schema_version') != '1.2'
            or value.get('kind') != 'READINESSOPS_INTERCHANGE'
            or value.get('transport_status') != 'FILE_INTERCHANGE_ONLY'):
        raise ValueError('interchange fields are invalid')
    authority = validate_authority(value.get('authority_source'))
    if (not re.fullmatch(r'[A-Za-z0-9._:-]{1,80}', str(value.get('source_workspace_id')))
            or not re.fullmatch(r'o-[A-Za-z0-9_-]{8,80}', str(value.get('source_object_id')))
            or not re.fullmatch(r'pack-[A-Za-z0-9_-]{8,80}', str(value.get('pack_id')))
            or type(value.get('pack_revision')) is not int
            or value['pack_revision'] < 1
            or not re.fullmatch(r'[0-9a-f]{64}', str(value.get('decision_digest')))):
        raise ValueError('interchange identity or version is invalid')
    if sha256_json({k: v for k, v in value.items() if k != 'document_digest'}) != value.get('document_digest'):
        raise ValueError('interchange digest differs')
    pack = value.get('decision_pack')
    if not isinstance(pack, dict) or pack.get('kind') != 'BUSINESS_DECISION':
        raise ValueError('Decision Pack is invalid')
    if (pack.get('source_authority') != authority
            or pack.get('object_id') != value['source_object_id']
            or (pack.get('pack_id'), pack.get('revision'), pack.get('digest')) !=
               (value['pack_id'], value['pack_revision'], value['decision_digest'])
            or sha256_json({k: v for k, v in pack.items() if k != 'digest'}) != pack.get('digest')):
        raise ValueError('Decision Pack binding or digest differs')
    publication = value.get('publication')
    if not isinstance(publication, dict) or set(publication) & {'ref', 'decision_ref', 'receipt_ref'}:
        raise ValueError('publication contains a mutable reference')
    if (publication.get('source_authority') != authority
            or publication.get('object_id') != value['source_object_id']
            or (publication.get('pack_id'), publication.get('revision'), publication.get('digest')) !=
               (value['pack_id'], value['pack_revision'], value['decision_digest'])):
        raise ValueError('publication binding differs')
    outcomes = value.get('outcomes')
    if not isinstance(outcomes, list) or len(outcomes) > 32:
        raise ValueError('interchange outcomes are invalid')
    ids = [item.get('outcome_id') for item in outcomes if isinstance(item, dict)]
    if len(ids) != len(outcomes) or len(ids) != len(set(ids)):
        raise ValueError('interchange outcome identifiers are duplicated')
    for outcome in outcomes:
        verify_outcome(outcome, authority, value['source_object_id'],
                       (value['pack_id'], value['pack_revision'], value['decision_digest']))
    return copy.deepcopy(value)
