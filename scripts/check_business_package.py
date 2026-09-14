"""Fresh package import and actual bounded PDF extraction, separate from AWS evidence."""
import json,os,subprocess,sys,tempfile,zipfile
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'scripts'))
from build_business_artifacts import build
CODE=r'''
import io,json,sys
from pathlib import Path
import pypdf
from pypdf import PdfWriter
from pypdf.generic import DictionaryObject,NameObject,DecodedStreamObject
from authority_delta.business.evidence import extract
from services.business.handler import validators,handle
from services.business.worker import handler
from services.business_analysis.agent import assess
assert Path(pypdf.__file__).is_relative_to(Path.cwd())
writer=PdfWriter();page=writer.add_blank_page(width=612,height=792)
font=DictionaryObject({NameObject('/Type'):NameObject('/Font'),NameObject('/Subtype'):NameObject('/Type1'),NameObject('/BaseFont'):NameObject('/Helvetica')})
page[NameObject('/Resources')]=DictionaryObject({NameObject('/Font'):DictionaryObject({NameObject('/F1'):writer._add_object(font)})})
stream=DecodedStreamObject();stream.set_data(b'BT /F1 12 Tf 50 700 Td (Owner approval is required for external data sharing.) Tj ET');page[NameObject('/Contents')]=writer._add_object(stream)
buf=io.BytesIO();writer.write(buf);parsed=extract('policy.pdf',buf.getvalue());assert parsed['status']=='READY',parsed;assert 'Owner approval' in parsed['text']
writer.encrypt('local-test');buf=io.BytesIO();writer.write(buf);assert extract('encrypted.pdf',buf.getvalue())['status']=='NEEDS_INPUT'
blank=PdfWriter();blank.add_blank_page(width=612,height=792);buf=io.BytesIO();blank.write(buf);assert extract('scan-only.pdf',buf.getvalue())['status']=='NEEDS_INPUT'
assert extract('broken.pdf',b'%PDF-broken')['status']=='NEEDS_INPUT';assert extract('text.txt',b'Confirm the accountable owner decision.')['status']=='READY'
assert extract('bad.json',b'{bad json')['status']=='NEEDS_INPUT'
for name in ['../file.txt','folder\\file.txt']:
 try:extract(name,b'data')
 except ValueError:pass
 else:raise AssertionError('Path-like filename accepted')
assert set(validators())=={'create','evidence','runs','draft','review','publish','connection','delegation','applications','revocations','action_update','outcomes','imports'}
assert handle({},None,{'CLIENT_ID':'local'})['statusCode']==401
print(json.dumps({'result':'PASS','checks':['fresh_imports','packaged_request_schema','text_pdf','encrypted_pdf_needs_input','scan_pdf_needs_input','broken_pdf_needs_input','utf8_txt','invalid_json_needs_input','filename_boundary','unauthenticated_api']}))
'''
def check():
 with tempfile.TemporaryDirectory(prefix='readinessops-package-') as folder:
  path=Path(folder);archive=path/'business.zip';artifact=build(archive)
  unpack=path/'fresh';unpack.mkdir()
  with zipfile.ZipFile(archive) as z:z.extractall(unpack)
  env=dict(os.environ,PYTHONPATH=str(unpack));result=subprocess.run([sys.executable,'-S','-c',CODE],cwd=unpack,env=env,capture_output=True,text=True,timeout=45)
  if result.returncode:raise ValueError(result.stdout+result.stderr)
  value=json.loads(result.stdout);value.update(scope='LOCAL_DISTRIBUTION_PACKAGE_NO_LIVE_AWS',artifact=artifact);return value
if __name__=='__main__':
 value=check();path=ROOT/'evidence/local/business-package.json';path.parent.mkdir(parents=True,exist_ok=True);path.write_text(json.dumps(value,indent=2)+'\n');print(json.dumps(value,indent=2))
