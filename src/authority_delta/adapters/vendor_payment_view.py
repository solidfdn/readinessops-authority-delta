"""Trusted presentation and boundary schema for the VendorPayment sample."""
from .vendor_payment import BoundaryDefinition
from ..adapter_contract import BoundaryAdapter

BOUNDARY_SCHEMA={'type':'object','additionalProperties':False,'required':['max_amount_minor','currency','require_known_vendor','require_po_match','verified_changed_bank_methods','forbidden_actions'],
    'properties':{'max_amount_minor':{'type':'integer','minimum':0},'currency':{'type':'string','minLength':1},
        'require_known_vendor':{'type':'boolean'},'require_po_match':{'type':'boolean'},
        'verified_changed_bank_methods':{'type':'array','uniqueItems':True,'items':{'type':'string','minLength':1}},
        'forbidden_actions':{'type':'array','uniqueItems':True,'items':{'type':'string','minLength':1}}}}

def validate_boundary(value):
    from jsonschema import Draft202012Validator
    Draft202012Validator(BOUNDARY_SCHEMA).validate(value)
    return BoundaryDefinition.from_mapping(value).as_contract()

ADAPTER=BoundaryAdapter('vendor_payment','1.0.0',BOUNDARY_SCHEMA,validate_boundary)

def presentation(fixtures):
    def amount(b):return f"{b.currency} {b.max_amount_minor/100:,.0f}"
    old,new=fixtures.approved_boundary,fixtures.narrow_boundary
    return {'adapter_id':ADAPTER.adapter_id,'adapter_version':ADAPTER.version,
        'object_id':'vendor-payment-agent','object_name':'Vendor payment preparation',
        'purpose':'Prepare vendor payments within an approved delegation boundary.',
        'sample':True,'sample_label':'VendorPayment · synthetic demonstration',
        'columns':[{'id':'action','label':'Requested action'},{'id':'amount','label':'Amount'}],
        'rows':{c.case_id:{'action':c.request['action'].replace('_',' '),
            'amount':f"{c.request.get('currency','')} {c.request['amount_minor']/100:,.0f}" if 'amount_minor' in c.request else '—'} for c in fixtures.all_cases},
        'decisions':[
            {'id':'MAINTAIN','title':'Keep the approved boundary','text':f'Retain the {amount(old)} limit and independent bank verification.'},
            {'id':'NARROW','title':'Restrict delegation','text':f'Retain verification and reduce the limit from {amount(old)} to {amount(new)}.'},
            {'id':'REJECT','title':'Reject the candidate release','text':'Keep the existing release and grant no new candidate permission.'}],
        'boundary_note':'A release review does not approve an individual payment. Requests outside the chosen boundary still need human handling.',
        'preview_summaries':{'MAINTAIN':f'Independent bank verification remains required. Limit: {amount(old)}.',
            'NARROW':f'Independent bank verification remains required. Limit: {amount(new)}.',
            'REJECT':'No new candidate permission. The current release remains in place.'},
        'boundaries':{'MAINTAIN':ADAPTER.binding(old.as_contract()),'NARROW':ADAPTER.binding(new.as_contract()),'REJECT':None}}
