import importlib.util
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest
from zipfile import ZipFile

PATH=Path(__file__).resolve().parents[1]/'scripts/collect_analysis_dependencies.py'
spec=importlib.util.spec_from_file_location('collector',PATH)
c=importlib.util.module_from_spec(spec);spec.loader.exec_module(c)

class CollectorTests(unittest.TestCase):
    def test_actual_entrypoint_success_and_download_failure(self):
        # Process boundary double: verifies CLI/ZIP/error behavior, not PyPI or SDK compatibility.
        pip_double = '''import sys, os, struct
from pathlib import Path
from zipfile import ZipFile
if os.environ.get("AD_TEST_DOWNLOAD_FAIL"):
    print("injected offline failure", file=sys.stderr);sys.exit(1)
p=Path(sys.argv[sys.argv.index("--dest")+1]);arch=p.name
with ZipFile(p/"strands_agents-1.51.0-py3-none-any.whl","w") as z:z.writestr("strands/__init__.py", "")
'''
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);(root/'pip.py').write_text(pip_double)
            env=dict(os.environ,PYTHONPATH=str(root))
            output=root/'result.zip'
            command=[sys.executable,str(PATH),'--output',str(output)]
            success=subprocess.run(command,env=env,capture_output=True,text=True,timeout=20)
            self.assertEqual(success.returncode,0,success.stderr)
            self.assertTrue(output.exists())
            self.assertIn('not Gate B PASS',success.stdout)
            with ZipFile(output) as z:self.assertEqual(set(json.loads(z.read('manifest.json'))['wheels']),set(c.TARGETS))
            output.unlink()
            failure=subprocess.run(command,env=dict(env,AD_TEST_DOWNLOAD_FAIL='1'),capture_output=True,text=True,timeout=20)
            self.assertEqual(failure.returncode,1)
            self.assertFalse(output.exists())
            self.assertIn('injected offline failure',failure.stderr)

    def fake(self,args,**kwargs):
        target=Path(args[args.index('--dest')+1]);arch=target.name
        with ZipFile(target/'strands_agents-1.51.0-py3-none-any.whl','w') as z:z.writestr('strands/__init__.py','')
        raw=bytearray(20);raw[:6]=b'\x7fELF\x02\x01';raw[18:20]=struct.pack('<H',c.TARGETS[arch])
        with ZipFile(target/f'native-1-cp312-cp312-manylinux2014_{arch}.whl','w') as z:z.writestr('native.so',raw)
        return subprocess.CompletedProcess(args,0,'','')

    def test_collect_both_targets_and_manifest(self):
        with tempfile.TemporaryDirectory() as d:
            path=c.collect(Path(d)/'result.zip',run=self.fake)
            with ZipFile(path) as z:
                m=json.loads(z.read('manifest.json'))
                self.assertEqual(set(m['wheels']),set(c.TARGETS))
                self.assertEqual(m['scope'],'CANDIDATE_DEPENDENCIES_NOT_GATE_B_PROOF')
            with self.assertRaises(ValueError):c.collect(path,run=self.fake)

    def test_download_failure_does_not_publish_zip(self):
        with tempfile.TemporaryDirectory() as d:
            path=Path(d)/'result.zip'
            with self.assertRaises(RuntimeError):c.collect(path,run=lambda args,**kw:subprocess.CompletedProcess(args,1,'','blocked'))
            self.assertFalse(path.exists())

    def test_wrong_architecture_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'x86_64';p.mkdir();self.fake(['--dest',str(p)])
            with self.assertRaises(ValueError):c.inspect_wheels(p,'aarch64')

if __name__=='__main__':unittest.main()
