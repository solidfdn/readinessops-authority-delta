"""Derive the public API description from the same enforced command schema."""
import json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]


def command_contract():
    """Refresh proposal definitions from the runtime validator without touching commands."""
    from authority_delta.business.contracts import Proposal
    path=ROOT/'services/business/requests.schema.json'
    commands=json.loads(path.read_text())
    proposal=Proposal.model_json_schema(ref_template='#/$defs/{model}')
    definitions=proposal.pop('$defs')
    definitions['Proposal']=proposal
    commands['$defs']=definitions
    return commands


def build():
    commands=command_contract()
    def refs(v):
        if isinstance(v,dict):return {k:(x.replace('#/$defs/','#/components/schemas/') if k=='$ref' else refs(x)) for k,x in v.items()}
        return [refs(x) for x in v] if isinstance(v,list) else v
    schemas={**refs(commands['$defs']),**{k+'Request':refs(v) for k,v in commands['commands'].items()}}
    schemas['controlledInvocationRequest']={'type':'object','properties':{
        'operation_id':{'type':'string','pattern':'^[A-Za-z0-9_-]{16,80}$'},
        'request_id':{'type':'string','pattern':'^req-[0-9a-f]{64}$'}},
        'required':['operation_id','request_id'],'additionalProperties':False}
    spec={'openapi':'3.1.0','info':{'title':'ReadinessOps Business API','version':'1.2.0'},'servers':[{'url':'https://ycebapd6i7.execute-api.ap-northeast-1.amazonaws.com'}],
          'components':{'schemas':schemas,'securitySchemes':{'Cognito':{'type':'oauth2','flows':{'authorizationCode':{'authorizationUrl':'https://authority-delta-538522204923-review.auth.ap-northeast-1.amazoncognito.com/oauth2/authorize','tokenUrl':'https://authority-delta-538522204923-review.auth.ap-northeast-1.amazoncognito.com/oauth2/token','scopes':{'authority-delta/'+s:s for s in ['read','write','approve','publish']}}}}}},'paths':{}}
    for command in commands['commands']:
        if command == 'action_update':
            path='/business/objects/{object_id}/actions/{action_id}'
        else:
            path='/business/objects'+('' if command=='create' else '/{object_id}/'+command)
        scope='approve' if command in ('review','delegation') else 'publish' if command in ('publish','applications','revocations') else 'write'
        op={'operationId':command,'security':[{'Cognito':['authority-delta/read','authority-delta/'+scope]}],
            'requestBody':{'required':True,'content':{'application/json':{'schema':{'$ref':'#/components/schemas/'+command+'Request'}}}},
            'responses':{('202' if command in ('runs','applications','revocations') else '200'):{'description':'Saved command result; same request_id replays it'},'401':{'description':'Sign in required'},'403':{'description':'Workspace or scope not assigned'},'409':{'description':'Stale state or conflicting request'},'422':{'description':'Input rejected'},'503':{'description':'Unconfirmed; retry the same request_id'}}}
        if command!='create':
            op['parameters']=[{'name':'object_id','in':'path','required':True,'schema':{'type':'string','pattern':'^o-[0-9a-f]{32}$'}}]
            if command == 'action_update':
                op['parameters'].append({'name':'action_id','in':'path','required':True,
                    'schema':{'type':'string','pattern':'^action-[0-9a-f]{32}$'}})
        spec['paths'].setdefault(path,{})['post']=op
    for path,operation in [('/business/objects','listObjects'),('/business/objects/{object_id}','getObject'),('/business/objects/{object_id}/runs/{run_id}','getAssessment'),('/business/objects/{object_id}/evidence/{evidence_id}','getOriginal')]:
        op={'operationId':operation,'security':[{'Cognito':['authority-delta/read']}],'responses':{'200':{'description':'Authorized saved record'},'401':{'description':'Sign in required'},'404':{'description':'Record not assigned or unavailable'}}}
        op['parameters']=[{'name':p[1:-1],'in':'path','required':True,'schema':{'type':'string'}} for p in path.split('/') if p.startswith('{')]
        spec['paths'].setdefault(path,{})['get']=op
    export={'operationId':'exportInterchange','security':[{'Cognito':['authority-delta/read']}],
            'parameters':[{'name':'object_id','in':'path','required':True,
                           'schema':{'type':'string','pattern':'^o-[0-9a-f]{32}$'}}],
            'responses':{'200':{'description':'Digest-bound current Decision Pack and Outcome export'},
                         '401':{'description':'Sign in required'},
                         '404':{'description':'Record not assigned or unavailable'},
                         '409':{'description':'No publication or stored integrity mismatch'}}}
    spec['paths'].setdefault('/business/objects/{object_id}/interchange',{})['get']=export
    acceptance={**export,'operationId':'exportAcceptanceEvidence',
        'responses':{'200':{'description':'Redacted digest-bound authenticated object history'},
                     '401':{'description':'Sign in required'},
                     '404':{'description':'Record not assigned or unavailable'},
                     '409':{'description':'Stored evidence integrity mismatch'}}}
    spec['paths'].setdefault('/business/objects/{object_id}/acceptance-evidence',{})['get']=acceptance
    invocation_parameters=[{'name':'object_id','in':'path','required':True,
        'schema':{'type':'string','pattern':'^o-[0-9a-f]{32}$'}}]
    spec['paths']['/business/objects/{object_id}/invocations']={'post':{
        'operationId':'controlledInvocation',
        'security':[{'Cognito':['authority-delta/read','authority-delta/publish']}],
        'parameters':invocation_parameters,
        'requestBody':{'required':True,'content':{'application/json':{'schema':{
            '$ref':'#/components/schemas/controlledInvocationRequest'}}}},
        'responses':{'202':{'description':'Durably accepted at an exact live authority generation'},
            '401':{'description':'Sign in required'},
            '403':{'description':'Workspace or scope not assigned'},
            '409':{'description':'Authority closed, changed or request outside its finite set'},
            '422':{'description':'Input rejected'},
            '503':{'description':'Acceptance unconfirmed; retry the same operation_id'}}}}
    spec['paths']['/business/objects/{object_id}/invocations/{operation_id}']={'get':{
        'operationId':'getControlledInvocation',
        'security':[{'Cognito':['authority-delta/read']}],
        'parameters':invocation_parameters+[{'name':'operation_id','in':'path',
            'required':True,'schema':{'type':'string','pattern':'^[A-Za-z0-9_-]{16,80}$'}}],
        'responses':{'200':{'description':'Accepted, unknown or executed invocation record'},
            '401':{'description':'Sign in required'},
            '403':{'description':'Workspace or scope not assigned'},
            '404':{'description':'Record not assigned or unavailable'},
            '409':{'description':'Invocation operation unavailable'}}}}
    return spec


if __name__=='__main__':
    commands=command_contract()
    (ROOT/'services/business/requests.schema.json').write_text(json.dumps(commands,indent=2)+'\n')
    (ROOT/'packages/contracts/business.openapi.json').write_text(json.dumps(build(),indent=2)+'\n')
