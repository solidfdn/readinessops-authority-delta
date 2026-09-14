"""Reuse the tested source-restoration format, then launch the new review worker."""
from pathlib import Path
import hashlib
from build_gate_b_entrypoint import build,ROOT

def build_operator(destination,*,update_existing=False):
    destination=Path(destination)
    result=build(ROOT.parent/'outputs/ReadinessOps_Authority_Delta_AWS_Verification_V2.zip',destination)
    text=destination.read_text().replace('scripts/launch_gate_b.py','scripts/launch_workbench.py').replace('Authority Delta Gate B prepared.','Authority Delta Workbench prepared.').replace('prefix="authority-delta-gate-b-"','prefix="authority-delta-workbench-"')
    if update_existing:
        text=text.replace('scripts/launch_workbench.py','scripts/launch_workspace_update.py')
        text=text.replace('Authority Delta Workbench prepared.','ReadinessOps AWS workspace update prepared.')
        text=text.replace('directory = Path(tempfile.mkdtemp(prefix="authority-delta-workbench-"))',
            'work_root = Path.home() / "readinessops-work"\n        work_root.mkdir(mode=0o700, exist_ok=True)\n        directory = Path(tempfile.mkdtemp(prefix="workspace-update-", dir=work_root))')
    compile(text,str(destination),'exec');destination.write_text(text)
    result.update(sha256=hashlib.sha256(destination.read_bytes()).hexdigest(),size=destination.stat().st_size)
    return result

if __name__=='__main__':print(build_operator(ROOT.parent/'outputs/ReadinessOps_AWS_Workspace_Update.py',update_existing=True))
