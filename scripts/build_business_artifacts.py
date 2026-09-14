"""Build pinned Lambda and AgentCore artifacts without network dependency resolution."""
import hashlib,json,sys
from pathlib import Path
from zipfile import ZipFile,ZipInfo,ZIP_DEFLATED
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'src'))
from collect_analysis_dependencies import inspect_wheels
from build_runtime_artifact import STAMP
ROOT=Path(__file__).resolve().parents[1]

def build(destination, architecture='x86_64', runtime=False, root=ROOT):
    manifest=json.loads((root/'vendor/analysis/manifest.json').read_text())
    folder=root/'vendor/analysis'/architecture
    if inspect_wheels(folder,architecture)!=manifest['wheels'][architecture]:raise ValueError('Locked dependency content differs')
    files={}
    for item in manifest['wheels'][architecture]:
        with ZipFile(folder/item['file']) as z:
            for info in z.infolist():
                if info.is_dir() or '.data/scripts/' in info.filename:continue
                if '.data/' in info.filename or info.filename in files:raise ValueError('Unsupported wheel layout')
                files[info.filename]=z.read(info)
    pdf=json.loads((root/'vendor/business/manifest.json').read_text());pdfzip=root/'vendor/business'/pdf['archive']
    if hashlib.sha256(pdfzip.read_bytes()).hexdigest()!=pdf['sha256']:raise ValueError('PDF dependency digest differs')
    with ZipFile(pdfzip) as z:
        for name in z.namelist():
            if name in files:raise ValueError('PDF dependency path collision')
            files[name]=z.read(name)
    for base in ['src/authority_delta','services/business','services/business_analysis',
                 'services/customer_publisher']:
        for path in (root/base).rglob('*'):
            if path.is_file() and path.suffix in ('.py','.json'):
                files[path.relative_to(root).as_posix().removeprefix('src/')]=path.read_bytes()
    files['services/__init__.py']=b''
    for path in (root/'packages/contracts').glob('*.json'):files[path.relative_to(root).as_posix()]=path.read_bytes()
    if runtime:files['runtime.py']=(root/'services/business_analysis/runtime.py').read_bytes()
    total=sum(map(len,files.values()))
    if total>240_000_000:raise ValueError('Artifact exceeds the bounded uncompressed size')
    destination=Path(destination);destination.parent.mkdir(parents=True,exist_ok=True)
    with ZipFile(destination,'w',ZIP_DEFLATED) as z:
        for name,raw in sorted(files.items()):
            i=ZipInfo(name,STAMP);i.compress_type=ZIP_DEFLATED;i.external_attr=0o100644<<16;z.writestr(i,raw)
    return {'path':str(destination),'sha256':hashlib.sha256(destination.read_bytes()).hexdigest(),'size_bytes':destination.stat().st_size,'uncompressed_bytes':total,'architecture':architecture}

if __name__=='__main__':
    print(json.dumps({'lambda':build(ROOT/'dist/business-lambda.zip'),'runtime':build(ROOT/'dist/business-runtime.zip','aarch64',True)},indent=2))
