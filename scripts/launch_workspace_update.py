#!/usr/bin/env python3
"""Update the existing ReadinessOps workspace; retain its confirmed sign-in."""
import argparse,json,subprocess,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'scripts'))
from launch_deployment import AwsCli,DeploymentError,stack_outputs
from launch_workbench import launch

WORKSPACE_URL='https://d3rn3hqm0ax5ux.cloudfront.net/'

def update(cli,resume=None):
    binding=json.loads((ROOT/'infra/environments/development.json').read_text())
    if cli.run('sts','get-caller-identity').get('Account')!=binding['account']:
        raise DeploymentError('Wrong account. No workspace update started.')
    before=stack_outputs(cli,'authority-delta-workbench')
    if before.get('WorkspaceUrl')!=WORKSPACE_URL or before.get('ReviewerUsername')!='okada':
        raise DeploymentError('Existing workspace binding differs. No update started.')
    def confirmed(outputs):
        if outputs!=before:raise DeploymentError('Workspace identity changed. Existing password was not modified.')
        user=cli.run('cognito-idp','admin-get-user','--user-pool-id',outputs['UserPoolId'],'--username',outputs['ReviewerUsername'])
        if user.get('UserStatus')!='CONFIRMED':
            raise DeploymentError('Existing reviewer sign-in is not confirmed. No password operation is performed by this updater.')
    confirmed(before)
    print('ReadinessOps AWS workspace update. Existing sign-in retained; saved analysis reused.',flush=True)
    return launch(cli,resume,password_setup=lambda cli,outputs:confirmed(outputs),update_existing=True)

def main():
    parser=argparse.ArgumentParser();parser.add_argument('--resume');args=parser.parse_args()
    try:return update(AwsCli(),args.resume)
    except (DeploymentError,OSError,ValueError,KeyError,TypeError,EOFError,KeyboardInterrupt,subprocess.TimeoutExpired) as exc:
        print('ERROR: '+str(exc));return 1

if __name__=='__main__':raise SystemExit(main())
