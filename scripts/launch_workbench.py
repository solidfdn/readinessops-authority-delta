#!/usr/bin/env python3
"""One deployment and result collection; a password is set locally after success."""
import argparse,getpass,json,os,re,shlex,subprocess,sys,tempfile,uuid
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'scripts'))
from launch_deployment import AwsCli,DeploymentError,source_archive,stack_outputs,show_failure_details
from launch_verification import wait_terminal
from launch_gate_b import write_record
SCOPE='AUTHENTICATED_REVIEW_WORKBENCH_NO_APPROVAL_OR_PUBLICATION'


def password_error_category(stderr):
    """Return only fixed labels; CLI validation errors can echo the password."""
    allowed={'AccessDeniedException','AccessDenied','NotAuthorizedException',
        'InvalidPasswordException','InvalidParameterException',
        'PasswordHistoryPolicyViolationException','UserNotFoundException',
        'ResourceNotFoundException','TooManyRequestsException','InternalErrorException',
        'ExpiredToken','ExpiredTokenException','InvalidClientTokenId',
        'UnrecognizedClientException','OperationNotEnabledException'}
    match=re.search(r'An error occurred \(([A-Za-z]+)\) when calling the AdminSetUserPassword operation',stderr or '')
    if match and match[1] in allowed:return match[1]
    for pattern,label in [
        ('Unable to load paramfile','CLI_INPUT_FILE_ERROR'),
        ('Error parsing parameter','CLI_INPUT_ERROR'),
        ('Invalid JSON','CLI_INPUT_ERROR'),
        ('Parameter validation failed','CLI_PARAMETER_VALIDATION'),
        ('Unknown output type','CLI_OUTPUT_CONFIGURATION'),
        ('Unable to locate credentials','CREDENTIALS_UNAVAILABLE'),
        ('Could not connect to the endpoint','ENDPOINT_CONNECTION_ERROR'),
        ('SSL validation failed','TLS_VALIDATION_ERROR'),
        ('Read timeout','AWS_READ_TIMEOUT')]:
        if pattern in (stderr or ''):return label
    return 'UNCLASSIFIED_CLI_ERROR'


def set_password_command(cli,pool,username,password,run):
    """Use a seekable anonymous memory file; never a disk file or argv secret."""
    if not hasattr(os,'memfd_create'):
        raise DeploymentError('Password setup needs Linux CloudShell (anonymous memory file unavailable).')
    fd=os.memfd_create('authority-delta-password',os.MFD_CLOEXEC)
    try:
        os.fchmod(fd,0o600)
        body=json.dumps({'UserPoolId':pool,'Username':username,'Password':password,'Permanent':True}).encode()
        with os.fdopen(os.dup(fd),'wb') as stream:stream.write(body)
        os.lseek(fd,0,os.SEEK_SET)
        body=None
        env=dict(cli.env,AWS_PAGER='',AWS_CLI_AUTO_PROMPT='off',AWS_DEFAULT_OUTPUT='json')
        result=run(['aws','cognito-idp','admin-set-user-password','--cli-input-json',f'file:///proc/self/fd/{fd}',
            '--region',cli.env['AWS_DEFAULT_REGION'],'--output','json','--no-cli-pager','--no-cli-auto-prompt',
            '--cli-connect-timeout','10','--cli-read-timeout','30'],
            stdin=subprocess.DEVNULL,capture_output=True,text=True,env=env,timeout=45,pass_fds=(fd,))
        if result.returncode:
            # Do not return stdout/stderr or attach the CompletedProcess to an exception.
            return password_error_category(result.stderr)
        return None
    except subprocess.TimeoutExpired:
        return 'AWS_READ_TIMEOUT'
    except OSError:
        return 'LOCAL_COMMAND_ERROR'
    finally:
        os.ftruncate(fd,0)
        os.close(fd)


def validate_record(record,binding):
    if record.get('scope')!=SCOPE:raise DeploymentError('Not a workbench launch record')
    for key,expected in [('account',binding['account']),('region',binding['region']),('bucket',binding['artifact_bucket']),('project',binding['project'])]:
        if record.get(key)!=expected:raise DeploymentError('Launch record does not match this environment')
    for key,pattern in [('build_id',re.escape(binding['project'])+r':[A-Za-z0-9_-]+'),('report_key',r'evidence/[0-9a-f]{32}/workbench-result\.json'),('source_sha256',r'[0-9a-f]{64}')]:
        if not re.fullmatch(pattern,record.get(key,'')):raise DeploymentError('Invalid '+key)
    if not record.get('source_version') or record['source_version']=='null':raise DeploymentError('Source version missing')


def setup_password(cli,outputs,*,prompt=getpass.getpass,run=subprocess.run):
    pool=outputs['UserPoolId'];username=outputs['ReviewerUsername']
    if username!='okada' or not re.fullmatch(r'ap-northeast-1_[A-Za-z0-9]+',pool):raise DeploymentError('Unexpected reviewer binding')
    user=cli.run('cognito-idp','admin-get-user','--user-pool-id',pool,'--username',username)
    if user.get('UserStatus')=='CONFIRMED':return
    if user.get('UserStatus')!='FORCE_CHANGE_PASSWORD':raise DeploymentError('Reviewer needs an administrator check; existing password was not changed')
    print('Create your workbench sign-in password (username: okada). Input is hidden and is not saved to logs.',flush=True)
    for attempt in range(3):
        password=prompt('New password (12+ characters, upper/lowercase and a number): ')
        if len(password)<12 or len(password)>256 or not re.search('[A-Z]',password) or not re.search('[a-z]',password) or not re.search('[0-9]',password) or re.search(r'\s',password) or not password.isprintable():
            print('Use 12–256 characters with upper/lowercase and a number, without spaces or control characters.');continue
        if password!=prompt('Confirm password: '):print('Passwords do not match.');continue
        try:
            error=set_password_command(cli,pool,username,password,run)
        finally:password=None
        if error:
            print('PASSWORD_SETUP_ERROR: '+error,flush=True)
            if error in ('InvalidPasswordException','PasswordHistoryPolicyViolationException'):
                print('Cognito rejected that password. Choose another password.');continue
            # A timeout/output-format failure can follow a successful AWS write.
            # Reconcile current status before asking for a new password or failing.
            user=cli.run('cognito-idp','admin-get-user','--user-pool-id',pool,'--username',username)
            if user.get('UserStatus')=='CONFIRMED':
                print('SIGN_IN_READY: Cognito confirms password setup; no retry needed.',flush=True);return
            raise DeploymentError('Password was not confirmed. Share PASSWORD_SETUP_ERROR above; do not redeploy or share your password.')
        user=cli.run('cognito-idp','admin-get-user','--user-pool-id',pool,'--username',username)
        if user.get('UserStatus')!='CONFIRMED':raise DeploymentError('Password confirmation is not yet visible. Resume the same build.')
        return
    raise DeploymentError('Password setup not completed. Resume the same build; deployment is retained.')


def collect(cli,record,path,*,password_setup=setup_password):
    print('Build ID: '+record['build_id'],flush=True)
    launcher='launch_workspace_update.py' if record.get('update_existing') else 'launch_workbench.py'
    print('Resume this build: '+shlex.join(['python3',str(ROOT/'scripts'/launcher),'--resume',str(path)]),flush=True)
    build=wait_terminal(cli,record['build_id'],limit=210)
    target=path.parent/'workbench-result.json'
    try:downloaded=cli.run('s3api','get-object','--bucket',record['bucket'],'--key',record['report_key'],str(target))
    except DeploymentError:
        show_failure_details(cli,build);raise DeploymentError('No final workbench report. Use the saved resume command to recover this build.')
    result=json.loads(target.read_text())
    if any(result.get(k)!=record[k] for k in ('scope','build_id','source_sha256')) or not downloaded.get('VersionId') or downloaded['VersionId']=='null':
        raise DeploymentError('Downloaded report is not bound to this build')
    record.update(report_version_id=downloaded['VersionId'],collection_result='COLLECTED',build_status=build.get('buildStatus'))
    write_record(path,record)
    print('AUTHORITY_DELTA_WORKBENCH_RESULT',flush=True)
    print(json.dumps({k:v for k,v in result.items() if k not in ('baseline_before','baseline_after')},indent=2),flush=True)
    print('Full report: '+str(target),flush=True)
    print(f"Evidence: s3://{record['bucket']}/{record['report_key']} (version {downloaded['VersionId']})",flush=True)
    if build.get('buildStatus')!='SUCCEEDED' or result.get('result')!='PASS' or result.get('state_unchanged') is not True:
        show_failure_details(cli,build);raise DeploymentError('Workbench deployment is incomplete; successful semantic evidence remains saved')
    outputs=stack_outputs(cli,'authority-delta-workbench')
    if outputs!=result.get('resources'):raise DeploymentError('Workspace bindings changed after this build')
    password_setup(cli,outputs)
    print('WORKSPACE_URL: '+outputs['WorkspaceUrl'],flush=True)
    print('SIGN_IN_USERNAME: '+outputs['ReviewerUsername'],flush=True)
    print('Open this URL and sign in with the password you set. Approval/publication remains a later step.',flush=True)
    return 0


def launch(cli,resume=None,*,password_setup=setup_password,update_existing=False):
    binding=json.loads((ROOT/'infra/environments/development.json').read_text())
    print('Authority Delta Workbench 20260909-v2',flush=True)
    if cli.run('sts','get-caller-identity').get('Account')!=binding['account']:raise DeploymentError('Wrong account. No workbench operation started.')
    if resume:
        path=Path(resume).resolve();record=json.loads(path.read_text());validate_record(record,binding)
        return collect(cli,record,path,password_setup=password_setup)
    bootstrap=stack_outputs(cli,binding['bootstrap_stack']);baseline=stack_outputs(cli,binding['application_stack'])
    if any(baseline.get(k)!=v for k,v in binding['resources'].items()):raise DeploymentError('Baseline bindings changed')
    bucket,project=bootstrap['ArtifactBucketName'],bootstrap['BuildProjectName']
    if bucket!=binding['artifact_bucket'] or project!=binding['project']:raise DeploymentError('Deployment bindings changed')
    ids=cli.run('codebuild','list-builds-for-project','--project-name',project,'--sort-order','DESCENDING','--max-items','5').get('ids',[])
    if ids and any(b.get('buildStatus')=='IN_PROGRESS' for b in cli.run('codebuild','batch-get-builds','--ids',*ids).get('builds',[])):
        raise DeploymentError('A build is active. Resume its saved record.')
    run_id=uuid.uuid4().hex
    with tempfile.TemporaryDirectory(prefix='ad-review-source-') as tmp:
        archive=Path(tmp)/'source.zip';digest=source_archive(archive);key='source/'+digest+'.zip'
        uploaded=cli.run('s3api','put-object','--bucket',bucket,'--key',key,'--body',str(archive),'--metadata','sha256='+digest)
    version=uploaded.get('VersionId')
    if not version or version=='null':raise DeploymentError('Source has no immutable version')
    report_key='evidence/'+run_id+'/workbench-result.json'
    variables=[{'name':'AD_REPORT_KEY','value':report_key,'type':'PLAINTEXT'},{'name':'AD_SOURCE_SHA256','value':digest,'type':'PLAINTEXT'}]
    started=cli.run('codebuild','start-build','--project-name',project,'--source-location-override',bucket+'/'+key,'--source-version',version,
        '--buildspec-override','buildspec.workbench.yml','--timeout-in-minutes-override','25',
        '--environment-variables-override',json.dumps(variables),'--idempotency-token',run_id)
    record={'schema_version':'1.0','scope':SCOPE,'build_id':started['build']['id'],'account':binding['account'],'region':binding['region'],
        'project':project,'bucket':bucket,'report_key':report_key,'source_sha256':digest,'source_version':version,'update_existing':update_existing}
    validate_record(record,binding);path=ROOT/'evidence/aws'/run_id/'launch.json';write_record(path,record)
    return collect(cli,record,path,password_setup=password_setup)


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--resume');args=parser.parse_args()
    try:return launch(AwsCli(),args.resume)
    except (DeploymentError,OSError,ValueError,KeyError,TypeError,EOFError,KeyboardInterrupt,subprocess.TimeoutExpired) as exc:
        print('ERROR: '+str(exc));return 1

if __name__=='__main__':raise SystemExit(main())
