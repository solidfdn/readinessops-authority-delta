"""Build analysis ZIP from locked wheels, verifying native architecture before packaging."""
import hashlib
import json
from pathlib import Path, PurePosixPath
from zipfile import ZipFile,ZIP_DEFLATED,ZipInfo
from collect_analysis_dependencies import inspect_wheels
from build_runtime_artifact import STAMP
ROOT=Path(__file__).resolve().parents[1]

def build(destination,architecture='aarch64',root=ROOT):
    folder=root/'vendor/analysis'/architecture
    manifest=json.loads((root/'vendor/analysis/manifest.json').read_text())
    if inspect_wheels(folder,architecture)!=manifest['wheels'][architecture]:raise ValueError('Dependency manifest mismatch')
    files={}
    for item in manifest['wheels'][architecture]:
        with ZipFile(folder/item['file']) as z:
            for info in z.infolist():
                if info.is_dir():continue
                name=info.filename
                if name in files:raise ValueError('Dependency file collision')
                if '.data/scripts/' in name:continue  # Optional CLI entrypoints are not imported by the service.
                if '.data/' in name:raise ValueError('Unsupported wheel install layout')
                files[name]=z.read(info)
    for folder_name in ('src/authority_delta','services/analysis_agent'):
        for p in (root/folder_name).rglob('*.py'):
            name=p.relative_to(root).as_posix().removeprefix('src/')
            files[name]=p.read_bytes()
    files['services/__init__.py']=b'';files['services/analysis_agent/__init__.py']=b''
    files['runtime.py']=(root/'services/analysis_agent/runtime.py').read_bytes()
    destination=Path(destination);destination.parent.mkdir(parents=True,exist_ok=True)
    with ZipFile(destination,'w',ZIP_DEFLATED) as z:
        for name,data in sorted(files.items()):
            info=ZipInfo(name,STAMP);info.compress_type=ZIP_DEFLATED;info.external_attr=0o100644<<16;z.writestr(info,data)
    return {'path':str(destination),'sha256':hashlib.sha256(destination.read_bytes()).hexdigest(),'size_bytes':destination.stat().st_size}

if __name__=='__main__':print(json.dumps(build(ROOT/'dist/analysis-runtime.zip'),indent=2))
