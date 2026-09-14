"""Actual workbench operator file/launcher validation with an isolated AWS CLI double."""
import hashlib,json,os,shutil,subprocess,sys,tempfile
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]

def check(entrypoint,*,update_existing=False):
    entrypoint=Path(entrypoint).resolve();checks=[]
    with tempfile.TemporaryDirectory(prefix='ad-review-delivery-') as work:
        work=Path(work);home=work/'operator';home.mkdir();binary=work/'bin';binary.mkdir()
        shutil.copy2(ROOT.parent/'outputs/ReadinessOps_Authority_Delta_AWS_Verification_V2.zip',home)
        shutil.copy2(ROOT.parent/'upload/Authority_Delta_Analysis_Dependencies.zip',home)
        fake=binary/'aws';fake.write_text('#!'+sys.executable+'\n'+(ROOT/'tests/support/workbench_cli_double.py').read_text());fake.chmod(0o700)
        harness='import runpy,sys,tempfile;from pathlib import Path;from unittest.mock import patch;script,home,tmp=sys.argv[1:];sys.argv=[script];tempfile.tempdir=tmp;\nwith patch.object(Path,"home",return_value=Path(home)):runpy.run_path(script,run_name="__main__")'
        scenarios=[('PASS',0),('FAIL',1),('FINAL_MISSING',1),('WRONG_ACCOUNT',1),('ACTIVE_BUILD',1),('CLEANUP_UNCONFIRMED',1),('REPORT_MISMATCH',1),('PASSWORD_REQUIRED',1 if update_existing else 0)]
        if update_existing:scenarios.append(('WORKSPACE_CHANGED',1))
        for scenario,code in scenarios:
            stage=work/scenario;stage.mkdir();env=dict(os.environ,PATH=str(binary)+os.pathsep+os.environ['PATH'],AD_TEST_STATE=str(stage),AD_TEST_SCENARIO=scenario,AD_TEST_UPDATE='1' if update_existing else '0')
            original_dirs=set((home/'readinessops-work').glob('workspace-update-*'))
            result=subprocess.run([sys.executable,'-c',harness,str(entrypoint),str(home),str(stage)],env=env,capture_output=True,text=True,input="LocalPassword123\nLocalPassword123\n",timeout=120)
            if result.returncode!=code:raise ValueError(scenario+' unexpected exit: '+result.stdout[-2000:]+result.stderr[-1000:])
            if scenario=='FAIL' and 'Evidence binding changed' not in result.stdout:
                raise ValueError('Operator lost the failure reason')
            if 'LocalPassword123' in result.stdout+result.stderr:raise ValueError('Password leaked to output')
            prepared=list(set((home/'readinessops-work').glob('workspace-update-*'))-original_dirs) if update_existing else list(stage.glob('authority-delta-workbench-*'))
            if not prepared:raise ValueError('Operator did not restore source')
            source=prepared[0]
            if scenario=='PASS':
                head=subprocess.check_output(['git','rev-parse','HEAD'],cwd=ROOT,text=True).strip()
                names=subprocess.check_output(['git','ls-tree','-r','--name-only',head],cwd=ROOT,text=True).splitlines()
                for name in names:
                    expected=subprocess.check_output(['git','show',head+':'+name],cwd=ROOT)
                    if (source/name).read_bytes()!=expected:raise ValueError('Restored source mismatch: '+name)
                launch=next((source/'evidence/aws').glob('*/launch.json'))
                before=(stage/'calls.jsonl').read_text().count('start-build')
                launcher='launch_workspace_update.py' if update_existing else 'launch_workbench.py'
                resume=subprocess.run([sys.executable,str(source/'scripts'/launcher),'--resume',str(launch)],cwd=source,env=env,capture_output=True,text=True,timeout=20)
                if resume.returncode or (stage/'calls.jsonl').read_text().count('start-build')!=before:raise ValueError('Resume created a build or failed')
                checks.append('same_build_resume')
            if scenario in ('WRONG_ACCOUNT','ACTIVE_BUILD') and 'start-build' in (stage/'calls.jsonl').read_text():raise ValueError('Guard did not prevent launch')
            if update_existing:
                calls=(stage/'calls.jsonl').read_text()
                if 'admin-set-user-password' in calls:raise ValueError('Updater attempted a password mutation')
                if scenario in ('PASSWORD_REQUIRED','WORKSPACE_CHANGED') and 'start-build' in calls:raise ValueError('Existing workspace guard failed')
                if not source.is_relative_to(home/'readinessops-work'):raise ValueError('Update source still uses ephemeral /tmp')
            checks.append(scenario)
            print('Local operator '+scenario+': PASS',flush=True)
    return {'scope':'LOCAL_OPERATOR_PROCESS_TEST_NO_LIVE_AWS','result':'PASS','checks':checks,'entrypoint_sha256':hashlib.sha256(entrypoint.read_bytes()).hexdigest()}

if __name__=='__main__':
    update='--update-existing' in sys.argv[2:]
    value=check(sys.argv[1],update_existing=update);path=ROOT/'evidence/local'/('workspace-update-delivery.json' if update else 'workbench-delivery.json');path.write_text(json.dumps(value,indent=2)+'\n');print(json.dumps(value,indent=2))
