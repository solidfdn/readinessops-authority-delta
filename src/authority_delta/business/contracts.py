"""One typed proposal contract shared by model feedback, service and UI schema."""
from __future__ import annotations
import hashlib
import re
from typing import Annotated, Literal
from pydantic import BaseModel, ConfigDict, Field
from authority_delta.canonical import sha256_json
from .storage import encode

PERSPECTIVES = ('GOVERNANCE', 'VALUE', 'MODEL_ROUTING', 'PORTFOLIO')
PROMPT_VERSION = 'readinessops-business-1.2.2'
LEGACY_PROMPT_VERSIONS = ('readinessops-business-1.2.0', 'readinessops-business-1.2.1')
MAX_SNAPSHOT_BYTES = 262144  # Exact business Runtime HTTP input limit.
DECISION_ITEM_ID = re.compile(r'^di-[A-Za-z0-9_-]{16,80}$')


class Strict(BaseModel):
    model_config = ConfigDict(extra='forbid')


class Citation(Strict):
    evidence_id: str = Field(description='Exact evidence_id returned by read_evidence, never a new identifier.')
    quote: str = Field(min_length=3, max_length=800, description='Exact contiguous text from that evidence. Never paraphrase, infer absence, or invent a quotation. For an unsupported NEEDS_INPUT item use an empty citations list.')


class Finding(Strict):
    finding_id: str = Field(pattern=r'^F-[0-9]{2}$')
    kind: Literal['GAP', 'RISK']
    title: str = Field(min_length=3, max_length=160)
    description: str = Field(min_length=8, max_length=2000)
    severity: Literal['LOW', 'MEDIUM', 'HIGH', 'UNKNOWN']
    severity_reason: str = Field(min_length=3, max_length=700)
    citations: list[Citation] = Field(max_length=8)


class Action(Strict):
    title: str = Field(min_length=3, max_length=200)
    description: str = Field(min_length=5, max_length=1500)
    finding_ids: list[str] = Field(min_length=1, max_length=12)


class DecisionItem(Strict):
    # The server binds this ID to the object's registry.  Perspective describes
    # the current type; it is not the durable identity of the item.
    decision_item_id: str | None = Field(default=None, pattern=r'^di-[A-Za-z0-9_-]{16,80}$')
    perspective: Literal['GOVERNANCE', 'VALUE', 'MODEL_ROUTING', 'PORTFOLIO']
    question: str = Field(min_length=3, max_length=700)
    recommendation: Literal['CONTINUE', 'REVISE', 'STOP', 'EXPAND', 'NEEDS_INPUT']
    rationale: str = Field(min_length=8, max_length=2200)
    conditions: str = Field(max_length=1600)
    reassessment_conditions: str = Field(min_length=3, max_length=1000)
    citations: list[Citation] = Field(max_length=8)


class DecisionImpact(Strict):
    decision_item_id: str = Field(pattern=r'^di-[A-Za-z0-9_-]{16,80}$')
    status: Literal['AFFECTED', 'UNCHANGED', 'UNKNOWN']
    reason: str = Field(min_length=8, max_length=1600)
    citations: list[Citation] = Field(max_length=8)
    unknowns: list[Annotated[str, Field(min_length=3, max_length=700)]] = Field(max_length=8)


class ReassessmentComparison(Strict):
    compared_publication_id: str = Field(pattern=r'^pub-[0-9a-f]{32}$')
    compared_decision_digest: str = Field(pattern=r'^[0-9a-f]{64}$')
    impacts: list[DecisionImpact] = Field(min_length=4, max_length=4)


class ProposalContent(Strict):
    """Model-authored content; transport/input binding belongs to the server."""
    summary: str = Field(min_length=8, max_length=2400)
    findings: list[Finding] = Field(max_length=16)
    actions: list[Action] = Field(max_length=16)
    decision_items: list[DecisionItem] = Field(min_length=4, max_length=4)
    reassessment: ReassessmentComparison | None = None
    missing_information: list[str] = Field(max_length=16)


class Proposal(ProposalContent):
    """Accepted wire contract retains its mandatory, verified input digest."""
    input_hash: str = Field(pattern=r'^[0-9a-f]{64}$')


class ProposalValidationError(ValueError):
    """All independent content defects, with stable paths for bounded repair."""
    def __init__(self, issues):
        self.issues = issues
        super().__init__('; '.join(f"{x['path']}: {x['message']}" for x in issues))


def legacy_decision_item_registry(object_id):
    """Deterministic migration IDs for objects created before an item registry existed."""
    return [{'decision_item_id': 'di-' + hashlib.sha256(
                ('readinessops:legacy-item:' + object_id + ':' + perspective).encode()).hexdigest()[:32],
             'perspective': perspective} for perspective in PERSPECTIVES]


def snapshot_item_registry(source):
    registry = source.get('decision_item_registry')
    if registry is None and source.get('prompt_version') in LEGACY_PROMPT_VERSIONS:
        registry = legacy_decision_item_registry(source.get('object_id', ''))
    if (not isinstance(registry, list) or len(registry) != len(PERSPECTIVES)
            or any(not isinstance(x, dict) or set(x) != {'decision_item_id', 'perspective'} for x in registry)):
        raise ValueError('Decision Item registry is missing or malformed')
    ids = [x['decision_item_id'] for x in registry]
    perspectives = [x['perspective'] for x in registry]
    if (len(set(ids)) != len(ids) or any(not isinstance(x, str) or not DECISION_ITEM_ID.fullmatch(x) for x in ids)
            or sorted(perspectives) != sorted(PERSPECTIVES)):
        raise ValueError('Decision Item registry has invalid or duplicate bindings')
    return registry


def prior_decision_items(source):
    """Return the pinned prior items with explicit IDs, including legacy records."""
    registry = {x['perspective']: x['decision_item_id'] for x in snapshot_item_registry(source)}
    try:
        items = source['prior_publication']['decision']['proposal']['decision_items']
        if not isinstance(items, list) or len(items) != len(PERSPECTIVES):
            raise ValueError('Prior Decision Item set is incomplete')
        normalized = []
        for original in items:
            item = dict(original)
            expected = registry[item['perspective']]
            if item.get('decision_item_id') not in (None, expected):
                raise ValueError('Prior Decision Item ID differs from the object registry')
            item['decision_item_id'] = expected
            normalized.append(item)
        if len({x['decision_item_id'] for x in normalized}) != len(PERSPECTIVES):
            raise ValueError('Prior Decision Item IDs are not distinct')
        return normalized
    except (KeyError, TypeError, AttributeError) as exc:
        raise ValueError('Prior Decision Items are malformed') from exc


def check_prior_publication(prior, object_id, source_authority):
    """Check historical context, never authorize a new decision or AWS action."""
    try:
        publication, decision, receipt = (prior[k] for k in ('publication', 'decision', 'receipt'))
        for document, ref in ((publication, prior['publication_ref']),
                              (decision, publication['decision_ref']),
                              (receipt, publication['receipt_ref'])):
            raw = encode(document)
            if (not all(isinstance(ref[k], str) and ref[k] for k in ('bucket', 'key', 'version_id'))
                    or ref['sha256'] != hashlib.sha256(raw).hexdigest()
                    or type(ref['size']) is not int or ref['size'] != len(raw)):
                raise ValueError('Prior publication reference mismatch')
        for field in ('object_id', 'pack_id', 'revision', 'digest'):
            if not publication[field] == decision[field] == receipt[field]:
                raise ValueError('Prior publication decision binding mismatch')
        if (publication['object_id'] != object_id
                or publication['source_authority'] != source_authority
                or decision['source_authority'] != source_authority
                or receipt['receipt_id'] != publication['receipt_id']
                or receipt['input_hash'] != decision['input_hash']
                or decision['kind'] != 'BUSINESS_DECISION'
                or receipt['kind'] != 'BUSINESS_DECISION_ONLY'
                or receipt['decision'] != 'APPROVE'
                or receipt['runtime_authority_granted'] is not False):
            raise ValueError('Prior publication authority or object mismatch')
        if decision['digest'] != sha256_json({k: v for k, v in decision.items() if k != 'digest'}):
            raise ValueError('Prior decision digest mismatch')
    except (KeyError, TypeError, AttributeError) as exc:
        raise ValueError('Malformed prior publication context') from exc
    # Expiry and current HEAD generation deliberately are not freshness checks:
    # this is an immutable historical judgment, not a transferable live receipt.


def check_snapshot(source):
    if source.get('schema_version') != '1.2' or source.get('mode') not in ('INITIAL', 'REASSESSMENT'):
        raise ValueError('Unsupported business assessment input')
    core = {k: v for k, v in source.items() if k != 'input_hash'}
    if source.get('input_hash') != sha256_json(core):
        raise ValueError('Input snapshot digest mismatch')
    if len(encode(source)) > MAX_SNAPSHOT_BYTES:
        raise ValueError('Assessment input exceeds the runtime byte limit; select fewer documents')
    if source.get('prompt_version') not in (*LEGACY_PROMPT_VERSIONS, PROMPT_VERSION):
        raise ValueError('Unsupported business assessment prompt version')
    snapshot_item_registry(source)
    prior = source.get('prior_publication')
    if source['mode'] == 'REASSESSMENT':
        if not isinstance(prior, dict):
            raise ValueError('Reassessment requires a pinned prior publication; start a new assessment')
        check_prior_publication(prior, source['object_id'], source['source_authority'])
        prior_decision_items(source)
    elif prior is not None:
        raise ValueError('Initial assessment cannot carry a prior publication')
    evidence = source.get('evidence', [])
    if not 1 <= len(evidence) <= 8 or len({e['evidence_id'] for e in evidence}) != len(evidence):
        raise ValueError('Select between one and eight distinct evidence records')
    if sum(len(e.get('text', '').encode()) for e in evidence) > 120000:
        raise ValueError('Selected evidence exceeds the analysis text limit')
    for e in evidence:
        if e['extraction_status'] != 'READY' or not e['text'].strip():
            raise ValueError('Selected evidence needs readable text')
        if sha256_json(e['text']) != e['text_hash']:
            raise ValueError('Extracted text digest mismatch')


def validate_proposal(value, source, reads=None):
    check_snapshot(source)
    p = Proposal.model_validate(value).model_dump(mode='json')
    return _validate_parsed_proposal(p, source, reads)


def _validate_parsed_proposal(p, source, reads=None):
    """Semantic checks on parsed content; public acceptance always uses validate_proposal."""
    issues = []

    def reject(path, code, message):
        issues.append({'path': path, 'code': code, 'message': message})

    if p['input_hash'] != source['input_hash']:
        reject('input_hash', 'INPUT_BINDING', 'Proposal does not refer to this input snapshot')
    if sorted(x['perspective'] for x in p['decision_items']) != sorted(PERSPECTIVES):
        reject('decision_items', 'PERSPECTIVE_SET', 'Use each of the four decision perspectives exactly once')
    registry = {x['perspective']: x['decision_item_id'] for x in snapshot_item_registry(source)}
    for i, item in enumerate(p['decision_items']):
        expected = registry[item['perspective']]
        if item['decision_item_id'] is None and source['prompt_version'] == PROMPT_VERSION:
            reject(f'decision_items.{i}.decision_item_id', 'ITEM_ID_REQUIRED', 'Current proposal must include every server-issued Decision Item ID')
        if item['decision_item_id'] not in (None, expected):
            reject(f'decision_items.{i}.decision_item_id', 'ITEM_BINDING', 'Decision Item ID does not match the object registry')
        elif item['decision_item_id'] is None:
            item['decision_item_id'] = expected
    if len({x['decision_item_id'] for x in p['decision_items']}) != len(PERSPECTIVES):
        reject('decision_items', 'ITEM_ID_SET', 'Decision Item IDs must be distinct')
    if reads is not None and not {'context', 'evidence'}.issubset(reads):
        reject('reads', 'READS_REQUIRED', 'Read both the business context and all selected evidence')
    evidence = {e['evidence_id']: e for e in source['evidence']}
    ids = [f['finding_id'] for f in p['findings']]
    if len(ids) != len(set(ids)):
        reject('findings', 'FINDING_ID_SET', 'Finding identifiers must be distinct')
    for i, a in enumerate(p['actions']):
        if not set(a['finding_ids']).issubset(ids):
            reject(f'actions.{i}.finding_ids', 'MISSING_FINDING',
                   'Action refers to a missing finding; reference only a finding_id present in findings, or supply that finding with supported content')
    total = 0

    def check_citations(citations, path):
        nonlocal total
        for i, citation in enumerate(citations):
            if (citation['evidence_id'] not in evidence
                    or citation['quote'] not in evidence[citation['evidence_id']]['text']):
                reject(f'{path}.{i}', 'EXACT_QUOTE_REQUIRED',
                       'Quote must appear exactly in the cited selected evidence; use a verbatim substring from read_evidence, or remove the citation and retain explicit uncertainty for a GAP/NEEDS_INPUT item')
            else:
                total += 1

    for collection in ('findings', 'decision_items'):
        for i, item in enumerate(p[collection]):
            citations = item['citations']
            path = f'{collection}.{i}.citations'
            if not citations and item.get('kind') != 'GAP' and item.get('recommendation') != 'NEEDS_INPUT':
                reject(path, 'CITATION_REQUIRED', 'A substantive finding or recommendation needs source citations')
            check_citations(citations, path)

    comparison = p['reassessment']
    if source['mode'] == 'INITIAL':
        if comparison is not None:
            reject('reassessment', 'INITIAL_COMPARISON', 'Initial assessment cannot claim a prior-decision comparison')
    else:
        if comparison is None:
            reject('reassessment', 'COMPARISON_REQUIRED', 'Reassessment must compare every pinned prior Decision Item')
            raise ProposalValidationError(issues)
        prior = source['prior_publication']
        publication = prior['publication']
        if (comparison['compared_publication_id'] != publication['publication_id']
                or comparison['compared_decision_digest'] != publication['digest']):
            reject('reassessment', 'PRIOR_BINDING', 'Reassessment comparison refers to another publication or decision')
        prior_by_id = {x['decision_item_id']: x for x in prior_decision_items(source)}
        current_by_id = {x['decision_item_id']: x for x in p['decision_items']}
        impacts = comparison['impacts']
        impact_by_id = {x['decision_item_id']: x for x in impacts}
        if len(impact_by_id) != len(impacts) or set(impact_by_id) != set(prior_by_id) or set(current_by_id) != set(prior_by_id):
            reject('reassessment.impacts', 'IMPACT_ITEM_SET', 'Reassessment must cover the exact pinned Decision Item set once')
        for i, impact in enumerate(impacts):
            item_id = impact['decision_item_id']
            path = f'reassessment.impacts.{i}'
            check_citations(impact['citations'], path + '.citations')
            if not impact['citations']:
                reject(path + '.citations', 'IMPACT_CITATION_REQUIRED', 'Each impact classification needs selected-evidence citations')
            if item_id not in current_by_id or item_id not in prior_by_id:
                continue  # Already rejected the binding; do not compare unrelated items.
            if impact['status'] == 'UNKNOWN':
                if not impact['unknowns'] or current_by_id[item_id]['recommendation'] != 'NEEDS_INPUT':
                    reject(path, 'UNKNOWN_REQUIRES_INPUT', 'Unknown impact must remain explicit and require input')
            elif impact['status'] == 'UNCHANGED':
                if impact['unknowns']:
                    reject(path + '.unknowns', 'UNCERTAINTY_IS_NOT_UNCHANGED', 'An impact with unresolved uncertainty cannot be unchanged')
                for field in ('recommendation', 'conditions', 'reassessment_conditions'):
                    if current_by_id[item_id][field] != prior_by_id[item_id][field]:
                        reject(path + '.' + field, 'UNCHANGED_BOUNDARY', 'Unchanged impact cannot alter the prior decision boundary')
    if not total:
        reject('citations', 'EVIDENCE_QUOTE_REQUIRED', 'Explain the available evidence with at least one exact source quotation')
    if issues:
        raise ProposalValidationError(issues)
    return p
