"""Inspect actual ARM wheels and run x86 packaged HTTP process; no live AWS."""
import json,os,socket,subprocess,sys,tempfile,time,unittest,urllib.request
from pathlib import Path
from zipfile import ZipFile
from scripts.build_analysis_runtime import build
ROOT=Path(__file__).resolve().parents[1]

class AnalysisPackageTests(unittest.TestCase):
    def test_package_and_http_unknown_hold(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);artifact=build(root/'runtime.zip','x86_64')
            with ZipFile(artifact['path']) as z:z.extractall(root/'app')
            # Disable the development venv/site-packages: otherwise an omitted
            # adapter can be imported from the editable local repository.
            process=subprocess.Popen([sys.executable,'-S','runtime.py'],cwd=root/'app',stdout=subprocess.DEVNULL,stderr=subprocess.PIPE,env=dict(os.environ,PYTHONPATH=str(root/'app')))
            try:
                for attempt in range(50):
                    try:
                        with urllib.request.urlopen('http://127.0.0.1:8080/ping',timeout=1) as r:self.assertEqual(json.load(r),{'status':'Healthy'})
                        break
                    except OSError:
                        if process.poll() is not None:raise RuntimeError(process.stderr.read().decode())
                        time.sleep(.1)
                else:self.fail('HTTP runtime did not start')
                request=urllib.request.Request('http://127.0.0.1:8080/invocations',data=b'{"input_hash":"wrong"}',headers={'Content-Type':'application/json'})
                with urllib.request.urlopen(request,timeout=10) as r:self.assertEqual(json.load(r)['result'],'HOLD')
            finally:process.terminate();process.wait(timeout=5);process.stderr.close()

    def test_analysis_role_has_no_execution_or_publication_permission(self):
        template=json.loads((ROOT/'infra/analysis-runtime/template.json').read_text())
        statements=template['Resources']['AnalysisExecutionRole']['Properties']['Policies'][0]['PolicyDocument']['Statement']
        actions=[a for s in statements for a in (s['Action'] if isinstance(s['Action'],list) else [s['Action']])]
        self.assertFalse([a for a in actions if a.startswith(('dynamodb:','lambda:','bedrock-agentcore:'))])
        self.assertIn('bedrock:InvokeModel',actions)

if __name__=='__main__':unittest.main()
