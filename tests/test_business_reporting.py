"""Worker failures must retain diagnostics and serialize AWS datetime fields."""
import json,unittest
from datetime import datetime,timezone
from unittest.mock import patch
from deploy_business import run_worker
class Reporting(unittest.TestCase):
 def test_failure_report_is_serialized_saved_and_returns_failure(self):
  saved=[]
  def execute(session,env,report,root):
   report['observed_aws_time']=datetime(2026,9,9,tzinfo=timezone.utc)
   raise ValueError('Pinned model/runtime mismatch')
  def save(session,env,raw,path,key):saved.append(json.loads(raw));return {'version_id':'local-test'}
  env={'CODEBUILD_BUILD_ID':'authority-delta-deploy:local','AD_SOURCE_SHA256':'0'*64,'AD_REPORT_KEY':'evidence/'+'1'*32+'/business-result.json'}
  with patch('deploy_business.save_evidence',side_effect=save):self.assertEqual(run_worker(None,env,executor=execute),1)
  self.assertEqual(len(saved),1);self.assertEqual(saved[0]['result'],'FAIL');self.assertFalse(saved[0]['approval_recorded']);self.assertIn('mismatch',saved[0]['error']['message']);self.assertIsInstance(saved[0]['observed_aws_time'],str)
 def test_final_save_failure_is_never_pass(self):
  def execute(session,env,report,root):report['result']='PASS'
  env={'AD_REPORT_KEY':'evidence/local/business-result.json'}
  with patch('deploy_business.save_evidence',side_effect=RuntimeError('Storage unavailable')):self.assertEqual(run_worker(None,env,executor=execute),1)
