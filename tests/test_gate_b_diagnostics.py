"""Saved failure diagnostics, including legacy summaries and the operator snippet."""
import copy
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from scripts.gate_b_diagnostics import semantic_diagnostics
from scripts.launch_gate_b import compact_report

ROOT = Path(__file__).resolve().parents[1]
BUILD = 'authority-delta-deploy:4186d536-a5f8-4bf9-9015-2b697b32fcdb'


class DiagnosticsTests(unittest.TestCase):
    def report(self, reason):
        # Synthetic rejection; the actual failed proposal is not yet retrieved.
        return {'build_id': BUILD, 'result': 'FAIL', 'semantic_runtime_proof': 'NOT_RUN',
                'patches': {'semantic': {'analysis_status': 'REJECTED', 'status': 'HOLD',
                                        'analysis_error': reason, 'affected_case_ids': ['P-002']}},
                'analysis_calls': [{'label': 'semantic', 'status': 'PASS', 'response': {
                    'result': 'OBSERVED', 'proposal': {'recommendation': 'unverified'},
                    'reads': ['definitions', 'observations', 'requests']}}]}

    def test_legacy_reports_expose_reasons_without_rewriting_gate_status(self):
        for reason in ('Unsupported evidence citation', 'Definition field did not change',
                       'Agent did not read all evidence categories', 'Analysis input hash mismatch'):
            with self.subTest(reason=reason):
                report = self.report(reason);original = copy.deepcopy(report)
                compact = compact_report(report, build_status='FAILED')
                self.assertEqual(compact['analysis_diagnostics']['semantic']['analysis_error'],reason)
                self.assertEqual(compact['semantic_runtime_proof'],'NOT_RUN')
                self.assertIsNone(compact['analysis_diagnostics']['semantic']['acceptance_status'])
                self.assertNotIn('benign',compact['analysis_diagnostics'])
                self.assertEqual(report,original)

    def test_no_diagnostic_evidence_is_not_a_pass(self):
        self.assertEqual(semantic_diagnostics({}),{})
        self.assertEqual(semantic_diagnostics({'analysis_calls':None,'patches':None}),{})
        self.assertEqual(semantic_diagnostics({'analysis_calls':[None]}),{})

    def test_exact_operator_snippet_runs_without_aws_or_project_imports(self):
        script=(ROOT/'scripts/read_gate_b_failure.sh').read_text()
        code=script.split("python3 - <<'PY'\n",1)[1].rsplit('\nPY',1)[0]
        report=self.report('Unsupported evidence citation')
        with tempfile.TemporaryDirectory() as directory:
            fixture=Path(directory)/'report.json';fixture.write_text(json.dumps(report))
            # Execute the exact snippet; redirect only its fixed Path.read_text target.
            harness=('from pathlib import Path\nfrom unittest.mock import patch\n'
                     'original=Path.read_text\n'
                     'def read(path,*a,**kw):\n'
                     '    if str(path) != '+repr('/tmp/authority-delta-gate-b-6y8n0r56/evidence/aws/64fe9cd81aaf42149c10a5855cc579d9/gate-b-result.json')+': raise AssertionError("Unexpected read")\n'
                     '    return original(Path('+repr(str(fixture))+'),*a,**kw)\n'
                     'with patch.object(Path,"read_text",read):\n'
                     '    exec('+repr(code)+')\n')
            result=subprocess.run([sys.executable,'-c',harness],cwd=directory,env={'PATH':'/nonexistent'},capture_output=True,text=True,timeout=5)
            self.assertEqual(result.returncode,0,result.stderr)
            output=json.loads(result.stdout)
            self.assertEqual(output['patches'],report['patches'])
            self.assertEqual(output['analyses'][0]['proposal'],report['analysis_calls'][0]['response']['proposal'])
            report['build_id']='different';fixture.write_text(json.dumps(report))
            result=subprocess.run([sys.executable,'-c',harness],cwd=directory,env={'PATH':'/nonexistent'},capture_output=True,text=True,timeout=5)
            self.assertEqual(result.returncode,1)
            self.assertEqual(result.stdout,'')


if __name__=='__main__':unittest.main()
