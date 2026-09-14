"""Actual distributed operator restoration, CLI process and interrupted-build recovery."""
import hashlib,json,os,shutil,subprocess,sys,tempfile
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
def check(entrypoint):
 entrypoint=Path(entrypoint).resolve();checks=[];source_commit=subprocess.check_output(['git','rev-parse','HEAD'],cwd=ROOT,text=True).strip()
 with tempfile.TemporaryDirectory(prefix='readinessops-delivery-') as tmp:
  work=Path(tmp);binary=work/'bin';binary.mkdir();fake=binary/'aws';fake.write_text('#!'+sys.executable+'\n'+(ROOT/'tests/support/business_cli_double.py').read_text());fake.chmod(0o700)
  harness='import runpy,sys;from pathlib import Path;from unittest.mock import patch;script,home=sys.argv[1:];sys.argv=[script];\nwith patch.object(Path,"home",return_value=Path(home)):runpy.run_path(script,run_name="__main__")'
  scenarios=[('PASS',0),('RECOVER_V1',0),('FAIL',1),('WRONG_ACCOUNT',1),('ACTIVE_BUILD',1),('SIGN_IN_UNCONFIRMED',1),('REPORT_MISMATCH',1),('STATE_CHANGED',1),('FINAL_MISSING',1),('START_RESPONSE_LOST',0)]
  for scenario,code in scenarios:
   stage=work/scenario;stage.mkdir();home=stage/'operator';home.mkdir();shutil.copy2(ROOT.parent/'outputs/ReadinessOps_Authority_Delta_AWS_Verification_V2.zip',home);shutil.copy2(ROOT.parent/'upload/Authority_Delta_Analysis_Dependencies.zip',home)
   env=dict(os.environ,PATH=str(binary)+os.pathsep+os.environ['PATH'],AD_TEST_STATE=str(stage),AD_TEST_SCENARIO=scenario)
   if scenario=='RECOVER_V1':
    binding=json.loads((ROOT/'infra/environments/development.json').read_text())
    old={'scope':'READINESSOPS_BUSINESS_WORKFLOW_DEPLOYMENT_NO_HUMAN_APPROVAL','bundle_version':'20260909-business-v1','account':binding['account'],'region':binding['region'],'bucket':binding['artifact_bucket'],'project':binding['project'],'report_key':'evidence/f8bf4b664c5b48fda8620d64b9629e54/business-result.json','source_sha256':'705c6651fbe5739cc046644a22bf6dbf4292d6a60bb5d7e9672bb5b2f1e01fd8','source_version':'old-version','build_id':'authority-delta-deploy:02244729-c866-4424-885b-6fe8d0209dd6'}
    (stage/'remote-launch.json').write_text(json.dumps(old))
   command=[sys.executable,'-c',harness,str(entrypoint),str(home)]
   result=subprocess.run(command,env=env,capture_output=True,text=True,timeout=90)
   if result.returncode!=code:raise ValueError(scenario+' unexpected exit: '+result.stdout[-2500:]+result.stderr[-1500:])
   calls=(stage/'calls.jsonl').read_text();prepared=next((home/'readinessops-work').glob('business-workflow-*'))
   if 'admin-set-user-password' in calls or 'assume-role' in calls:raise ValueError('Operator altered credentials')
   if scenario in ('WRONG_ACCOUNT','ACTIVE_BUILD','SIGN_IN_UNCONFIRMED') and 'start-build' in calls:raise ValueError('Launch guard failed')
   if scenario=='FAIL' and 'Pinned runtime code differs' not in result.stdout:raise ValueError('Failure reason lost')
   if scenario=='FINAL_MISSING' and 'Last saved checkpoint:' not in result.stdout:raise ValueError('Partial recovery lost')
   if scenario=='RECOVER_V1':
    variables=json.loads((stage/'build.json').read_text())
    if variables.get('AD_RECOVER_BUSINESS_CANARY')!='1' or calls.count('start-build')!=1:raise ValueError('Pinned failed canary recovery was not selected once')
    resumed=subprocess.run(command,env=env,capture_output=True,text=True,timeout=90)
    if resumed.returncode or (stage/'calls.jsonl').read_text().count('start-build')!=1:raise ValueError('V2 recovery duplicated a build')
   if scenario=='PASS':
    names=subprocess.check_output(['git','ls-tree','-r','--name-only',source_commit],cwd=ROOT,text=True).splitlines()
    for name in names:
     expected=subprocess.check_output(['git','show',source_commit+':'+name],cwd=ROOT)
     if (prepared/name).read_bytes()!=expected:raise ValueError('Restored source mismatch: '+name)
    before=calls.count('start-build');pointer=home/'readinessops-work/business-latest-launch.json';pointer.unlink()
    # Simulate lost local record: the same downloaded file restores the saved remote launch.
    resumed=subprocess.run(command,env=env,capture_output=True,text=True,timeout=90)
    if resumed.returncode or (stage/'calls.jsonl').read_text().count('start-build')!=before:raise ValueError('Remote recovery created a duplicate or failed: '+resumed.stdout[-1500:]+resumed.stderr)
    checks.extend(['exact_committed_source_restoration','remote_record_recovery_without_new_build'])
   checks.append(scenario);print('Local distribution '+scenario+': PASS',flush=True)
 return {'scope':'LOCAL_OPERATOR_PROCESS_TEST_NO_LIVE_AWS','result':'PASS','source_commit':source_commit,'entrypoint_sha256':hashlib.sha256(entrypoint.read_bytes()).hexdigest(),'checks':checks}
if __name__=='__main__':
 value=check(sys.argv[1]);path=ROOT/'evidence/local/business-delivery.json';path.write_text(json.dumps(value,indent=2)+'\n');print(json.dumps(value,indent=2))
