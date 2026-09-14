"""Recovery regression coverage. Local CLI double, not live AWS proof."""
import contextlib,io,json,os,shutil,subprocess,sys,tempfile,unittest
from pathlib import Path
import launch_workbench as launcher
from build_workbench_signin_recovery import build
ROOT=Path(__file__).resolve().parents[1]

class RecoveryTests(unittest.TestCase):
    def test_errors_are_allowlisted_and_never_echo_values(self):
        secret='ExampleSensitive12'
        for message,expected in [
            ('An error occurred (AccessDeniedException) when calling the AdminSetUserPassword operation: '+secret,'AccessDeniedException'),
            ('Parameter validation failed: '+secret,'CLI_PARAMETER_VALIDATION'),
            ('Unable to load paramfile file:///dev/stdin '+secret,'CLI_INPUT_FILE_ERROR'),
            (secret,'UNCLASSIFIED_CLI_ERROR')]:
            self.assertEqual(launcher.password_error_category(message),expected)

    def test_whitespace_and_mismatch_never_call_aws_write(self):
        class Cli:
            def run(self,*args):return {'UserStatus':'FORCE_CHANGE_PASSWORD'}
        answers=iter(['LeadingInternal space123','CorrectSecret12','DifferentSecret12','Tab\tSecret123'])
        with contextlib.redirect_stdout(io.StringIO()) as capture,self.assertRaises(launcher.DeploymentError):
            launcher.setup_password(Cli(),{'UserPoolId':'ap-northeast-1_test','ReviewerUsername':'okada'},
                prompt=lambda _:next(answers),run=lambda *a,**kw:self.fail('Invalid input reached AWS'))
        self.assertIn('Passwords do not match',capture.getvalue())
        self.assertNotIn('CorrectSecret12',capture.getvalue())

    def test_actual_recovery_process_works_with_no_prior_files(self):
        results=[]
        with tempfile.TemporaryDirectory(prefix='ad-signin-empty-') as tmp:
            tmp=Path(tmp)
            entry=tmp/'Authority_Delta_Workbench_SignIn_V2.py';build(entry)
            binary=tmp/'bin';binary.mkdir();fake=binary/'aws'
            fake.write_text('#!'+sys.executable+'\n'+(ROOT/'tests/support/signin_recovery_cli_double.py').read_text());fake.chmod(0o700)
            for mode,code in [('CONFIRMED',0),('PASSWORD_REQUIRED',0),('PASSWORD_DENIED',1),('PASSWORD_AMBIGUOUS',0),('PASSWORD_POLICY',0),('WRONG_ACCOUNT',1),('WRONG_VERSION',1),('FAILED_REPORT',1),('MISSING_REPORT',1),('STACK_DRIFT',1)]:
                state=tmp/mode;state.mkdir();empty=state/'empty';empty.mkdir()
                env=dict(os.environ,PATH=str(binary)+os.pathsep+os.environ['PATH'],AD_TEST_STATE=str(state),AD_TEST_SCENARIO=mode)
                env.pop('PYTHONPATH',None)
                outcome=subprocess.run([sys.executable,'-I',str(entry)],cwd=empty,env=env,text=True,capture_output=True,
                    input='LocalPassword123\nLocalPassword123\n'*2,timeout=30)
                self.assertEqual(outcome.returncode,code,mode+': '+outcome.stdout+outcome.stderr)
                self.assertNotIn('LocalPassword123',outcome.stdout+outcome.stderr)
                calls=[json.loads(line) for line in (state/'calls.jsonl').read_text().splitlines()]
                allowed=[['sts','get-caller-identity'],['s3api','get-object'],['cloudformation','describe-stacks'],['cognito-idp','admin-get-user'],['cognito-idp','admin-set-user-password']]
                self.assertTrue(all(x in allowed for x in calls))
                if mode in ('CONFIRMED','WRONG_ACCOUNT','WRONG_VERSION','FAILED_REPORT','MISSING_REPORT','STACK_DRIFT'):
                    self.assertNotIn(['cognito-idp','admin-set-user-password'],calls)
                if mode=='PASSWORD_DENIED':self.assertIn('PASSWORD_SETUP_ERROR: AccessDeniedException',outcome.stdout)
                if mode=='PASSWORD_AMBIGUOUS':self.assertEqual(calls.count(['cognito-idp','admin-set-user-password']),1)
                if mode=='PASSWORD_POLICY':self.assertEqual(calls.count(['cognito-idp','admin-set-user-password']),2)
                if code==0:self.assertIn('WORKSPACE_URL: https://dtest.cloudfront.net/',outcome.stdout)
                self.assertEqual(list(empty.iterdir()),[])
                results.append(mode)
        self.assertEqual(len(results),10)

if __name__=='__main__':unittest.main()
