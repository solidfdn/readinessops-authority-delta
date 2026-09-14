"""Shared ReadinessOps object/evidence/findings/action/history projection.

Consumes an already-validated review and a trusted adapter presentation. No
payment fields, tool names or monetary limits belong to this shared layer.
This projection does not create an approval receipt or execute a publication.
"""
import copy
from .canonical import sha256_json
from .adapter_contract import verify_boundary

def build_workspace(review,profile,registered):
    d=copy.deepcopy(review);digest=d.pop('document_hash',None)
    if not digest or sha256_json(d)!=digest:raise ValueError('Review document integrity mismatch')
    source=d['source']
    if not all(source.get(k) for k in ('bucket','key','version_id')):raise ValueError('Fixed evidence source required')
    if d.get('approval_recorded') is not False or d.get('publication_status')!='NOT_RUN':
        raise ValueError('This import requires evidence before human approval/publication')
    if not profile.get('object_id') or not profile.get('object_name'):raise ValueError('Governance object required')
    if profile.get('adapter_id') not in registered:raise ValueError('Unknown business adapter')
    column_ids=[x['id'] for x in profile['columns']]
    if not column_ids or len(column_ids)!=len(set(column_ids)):raise ValueError('Unique display columns required')
    for comparison in d['comparisons'].values():
        cases={c['case_id'] for c in comparison['cases']}
        if len(cases)!=len(comparison['cases']):raise ValueError('Duplicate observed case')
        if any(cid not in profile['rows'] or set(profile['rows'][cid])!=set(column_ids) for cid in cases):
            raise ValueError('Adapter presentation does not cover observed cases')
        changes=comparison['patch']['analysis']['changes']
        if len({c['case_id'] for c in changes})!=len(changes) or any(c['case_id'] not in cases for c in changes):
            raise ValueError('Finding does not identify one observed case')
    for decision in ('MAINTAIN','NARROW'):
        binding=verify_boundary(profile['boundaries'][decision],registered)
        if binding['adapter_id']!=profile['adapter_id'] or binding['adapter_version']!=profile['adapter_version']:
            raise ValueError('Presentation and boundary adapter differ')
    if profile['boundaries']['REJECT'] is not None:raise ValueError('Rejection cannot carry a new boundary')
    decisions=[x['id'] for x in profile['decisions']]
    if sorted(decisions)!=['MAINTAIN','NARROW','REJECT']:raise ValueError('All human decisions must be represented once')
    old=set(d['previews']['MAINTAIN']['allowed_request_ids']);narrow=set(d['previews']['NARROW']['allowed_request_ids'])
    if not narrow<=old or d['previews']['REJECT']['allowed_request_ids']:raise ValueError('Decision expands authority')
    oid=profile['object_id'];evidence=[];findings=[];actions=[];history=[]
    for label,comparison in d['comparisons'].items():
        comparison_evidence=[]
        patch=comparison['patch']
        if patch.get('analysis_status')!='VALIDATED':raise ValueError('Validated analysis required')
        for release,definition in comparison['definitions'].items():
            eid='ev-'+sha256_json({'release':release,'definition':definition})[:20]
            comparison_evidence.append(eid)
            if not any(x['evidence_id']==eid for x in evidence):
                evidence.append({'evidence_id':eid,'object_id':oid,'kind':'RELEASE_DEFINITION','title':release+' definition',
                    'content_hash':sha256_json(definition),'source':source,'content':definition})
        eid='ev-'+sha256_json({'source':source,'label':label,'cases':comparison['cases']})[:20]
        evidence.append({'evidence_id':eid,'object_id':oid,'kind':'OBSERVATION','title':comparison['before_release']+' → '+comparison['candidate_release']+' observations',
            'content_hash':sha256_json(comparison['cases']),'source':source,'content':comparison['cases']})
        comparison_evidence.append(eid)
        for change in patch['analysis']['changes']:
            fid='finding-'+sha256_json({'object_id':oid,'change':change,'source':source})[:16]
            aid='action-'+fid.removeprefix('finding-')
            findings.append({'finding_id':fid,'object_id':oid,'kind':'DELEGATION_GAP','state':'OPEN',
                'case_id':change['case_id'],'title':'An earlier judgment no longer holds',
                'description':change['reason'],'before':change['before_judgment'],'candidate':change['after_judgment'],
                'evidence_ids':list(comparison_evidence),'evidence_refs':change['evidence_refs'],'action_id':aid,
                'risk':'The candidate may act outside the previously approved decision boundary.'})
            actions.append({'action_id':aid,'object_id':oid,'finding_id':fid,'state':'REVIEW_REQUIRED',
                'title':'Reassess the candidate delegation boundary','description':patch['analysis']['maintain_proposal'],
                'evidence_ids':list(comparison_evidence),'route':'review'})
        history.append({'event_id':'event-'+sha256_json({'source':source,'label':label})[:16],
            'kind':'ANALYSIS_OBSERVED','label':comparison['before_release']+' → '+comparison['candidate_release'],
            'recorded_at':d['observed_at'],'time_basis':'Saved report completion',
            'status':patch['status'],'request_id':comparison['runtime_request_id'],'evidence_ids':list(comparison_evidence)})
    workspace={'schema_version':'1.1','product':'ReadinessOps','edition':'AWS','module':'Authority Delta',
        'objects':[{'object_id':oid,'name':profile['object_name'],'purpose':profile['purpose'],
            'state':'REVIEW_REQUIRED' if findings else 'ASSESSED','connection_id':d['connection_id'],
            'sample':profile['sample'],'sample_label':profile['sample_label'],'adapter_id':profile['adapter_id'],
            'adapter_version':profile['adapter_version'],'boundary':profile['boundaries']['MAINTAIN']}],
        'evidence':evidence,'findings':findings,'actions':actions,'history':history,
        'decisions':[],'publications':[],'review_document_hash':digest,
        'capabilities':{'evidence_import':'PINNED_AWS_REPORT','assessment':'OBSERVED_STRANDS_ANALYSIS',
            'decision_recording':'NOT_IMPLEMENTED','policy_publication':'NOT_IMPLEMENTED'}}
    workspace['workspace_hash']=sha256_json(workspace)
    return workspace
