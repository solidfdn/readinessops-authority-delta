"""Standalone operator test double; deliberately independent of repository files."""
import json,os,sys
from pathlib import Path
args=sys.argv[1:];op=tuple(args[:2]);state=Path(os.environ['AD_TEST_STATE']);mode=os.environ['AD_TEST_SCENARIO']
def value(flag):return args[args.index(flag)+1]
def emit(data):print(json.dumps(data));raise SystemExit(0)
def fail(message):print(message,file=sys.stderr);raise SystemExit(1)
assert value('--region')=='ap-northeast-1' and value('--output')=='json'
assert '--no-cli-pager' in args and '--no-cli-auto-prompt' in args
with (state/'calls.jsonl').open('a') as f:f.write(json.dumps(op)+'\n')
account='538522204923'
outputs={'WorkspaceUrl':'https://dtest.cloudfront.net/','UserPoolId':'ap-northeast-1_test','ReviewerUsername':'okada'}
version='Qld5q0Clx65Y1ODuSsaby8n3HM9Fhfu5'
if op==('sts','get-caller-identity'):emit({'Account':'111122223333' if mode=='WRONG_ACCOUNT' else account})
if op==('s3api','get-object'):
    assert value('--bucket')=='authority-delta-bootstrap-artifactbucket-6ebtk8mvvqyp'
    assert value('--key')=='evidence/6df3ab24c122455a819c8d46e42a9bfd/workbench-result.json'
    assert value('--version-id')==version and value('--expected-bucket-owner')==account
    if mode=='MISSING_REPORT':fail('NoSuchVersion: local injected failure')
    report={'scope':'AUTHENTICATED_REVIEW_WORKBENCH_NO_APPROVAL_OR_PUBLICATION','baseline_id':'AD-BASELINE-1.0',
        'account':account,'region':'ap-northeast-1','result':'FAIL' if mode=='FAILED_REPORT' else 'PASS',
        'deployment':'PASS','state_unchanged':True,'resources':outputs}
    Path(args[args.index('--expected-bucket-owner')+2]).write_text(json.dumps(report))
    emit({'VersionId':'wrong-version' if mode=='WRONG_VERSION' else version})
if op==('cloudformation','describe-stacks'):
    assert value('--stack-name')=='authority-delta-workbench'
    if mode=='STACK_DRIFT':outputs['UserPoolId']='ap-northeast-1_other'
    emit({'Stacks':[{'StackId':f'arn:aws:cloudformation:ap-northeast-1:{account}:stack/authority-delta-workbench/test',
        'StackStatus':'CREATE_COMPLETE','Outputs':[{'OutputKey':k,'OutputValue':v} for k,v in outputs.items()]}]})
if op==('cognito-idp','admin-get-user'):
    assert value('--user-pool-id')=='ap-northeast-1_test' and value('--username')=='okada'
    emit({'UserStatus':'CONFIRMED' if mode=='CONFIRMED' or (state/'password-done').exists() else 'FORCE_CHANGE_PASSWORD'})
if op==('cognito-idp','admin-set-user-password'):
    with open(value('--cli-input-json').removeprefix('file://')) as f:
        body=json.load(f);f.seek(0);assert body==json.load(f)
    assert body=={'UserPoolId':'ap-northeast-1_test','Username':'okada','Password':'LocalPassword123','Permanent':True}
    if mode=='PASSWORD_DENIED':fail('An error occurred (AccessDeniedException) when calling the AdminSetUserPassword operation: '+body['Password'])
    if mode=='PASSWORD_POLICY' and not (state/'policy-once').exists():
        (state/'policy-once').touch();fail('An error occurred (InvalidPasswordException) when calling the AdminSetUserPassword operation: '+body['Password'])
    (state/'password-done').touch()
    if mode=='PASSWORD_AMBIGUOUS':fail('Unknown output type: '+body['Password'])
    emit({})
fail('Unexpected operation: '+repr(op))
