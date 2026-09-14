#!/usr/bin/env python3
"""Recover sign-in from a pinned S3 report and live stack, using stdlib and AWS CLI."""
import getpass,json,os,re,subprocess,tempfile
from pathlib import Path
from launch_workbench import setup_password, DeploymentError

ACCOUNT='538522204923'
REGION='ap-northeast-1'
BUCKET='authority-delta-bootstrap-artifactbucket-6ebtk8mvvqyp'
REPORT_KEY='evidence/6df3ab24c122455a819c8d46e42a9bfd/workbench-result.json'
REPORT_VERSION='Qld5q0Clx65Y1ODuSsaby8n3HM9Fhfu5'
SCOPE='AUTHENTICATED_REVIEW_WORKBENCH_NO_APPROVAL_OR_PUBLICATION'
STACK='authority-delta-workbench'

class ReadCli:
    def __init__(self):
        self.env=dict(os.environ,AWS_DEFAULT_REGION=REGION,AWS_DEFAULT_OUTPUT='json',AWS_PAGER='',AWS_CLI_AUTO_PROMPT='off',AWS_MAX_ATTEMPTS='2')

    def run(self,*args):
        if args[:2] not in {('sts','get-caller-identity'),('s3api','get-object'),
            ('cloudformation','describe-stacks'),('cognito-idp','admin-get-user')}:
            raise DeploymentError('This recovery permits only evidence/configuration reads and initial password setup.')
        response=subprocess.run(['aws',*args,'--region',REGION,'--output','json','--no-cli-pager',
            '--no-cli-auto-prompt','--cli-connect-timeout','10','--cli-read-timeout','30'],
            env=self.env,capture_output=True,text=True,timeout=75)
        if response.returncode:
            # No passwords or credentials are arguments to these read operations.
            raise DeploymentError(' '.join(args[:2])+': '+(response.stderr or 'AWS command failed').strip()[:1500])
        return json.loads(response.stdout or '{}')

def recover(cli):
    print('Authority Delta sign-in recovery V2: read saved AWS evidence; no local launch record required.',flush=True)
    if cli.run('sts','get-caller-identity').get('Account')!=ACCOUNT:
        raise DeploymentError('Wrong AWS account. No password changed.')
    with tempfile.TemporaryDirectory(prefix='ad-signin-report-') as directory:
        target=Path(directory)/'workbench-result.json'
        saved=cli.run('s3api','get-object','--bucket',BUCKET,'--key',REPORT_KEY,
            '--version-id',REPORT_VERSION,'--expected-bucket-owner',ACCOUNT,str(target))
        if saved.get('VersionId')!=REPORT_VERSION:
            raise DeploymentError('Saved report version does not match the completed deployment.')
        if target.stat().st_size>2_000_000:raise DeploymentError('Unexpected report size.')
        report=json.loads(target.read_text())
    required={'scope':SCOPE,'baseline_id':'AD-BASELINE-1.0','account':ACCOUNT,'region':REGION,
        'result':'PASS','deployment':'PASS','state_unchanged':True}
    if any(report.get(k)!=v for k,v in required.items()):
        raise DeploymentError('Pinned report does not prove successful deployment. No password changed.')
    response=cli.run('cloudformation','describe-stacks','--stack-name',STACK)
    stacks=response.get('Stacks',[])
    if len(stacks)!=1:raise DeploymentError('Expected exactly one workbench stack.')
    stack=stacks[0]
    if stack.get('StackStatus') not in ('CREATE_COMPLETE','UPDATE_COMPLETE'):
        raise DeploymentError('Workbench stack is not ready. No password changed.')
    if not str(stack.get('StackId','')).startswith(f'arn:aws:cloudformation:{REGION}:{ACCOUNT}:stack/{STACK}/'):
        raise DeploymentError('Unexpected workbench stack account or Region.')
    outputs={o['OutputKey']:o['OutputValue'] for o in stack.get('Outputs',[])}
    if not outputs or outputs!=report.get('resources'):
        raise DeploymentError('Live workbench bindings differ from saved deployment. No password changed.')
    if not re.fullmatch(r'https://[a-z0-9]+\.cloudfront\.net/',outputs.get('WorkspaceUrl','')):
        raise DeploymentError('Unexpected workspace URL.')
    print('SAVED_DEPLOYMENT: PASS; live workspace bindings match.',flush=True)
    setup_password(cli,outputs)
    print('WORKSPACE_URL: '+outputs['WorkspaceUrl'],flush=True)
    print('SIGN_IN_USERNAME: '+outputs['ReviewerUsername'],flush=True)
    print('Open the URL and sign in. Approval and publication remain pending.',flush=True)
    return 0

def main():
    try:return recover(ReadCli())
    except (DeploymentError,OSError,ValueError,KeyError,TypeError,EOFError,KeyboardInterrupt,subprocess.TimeoutExpired) as exc:
        print('ERROR: '+str(exc));return 1

if __name__=='__main__':raise SystemExit(main())
