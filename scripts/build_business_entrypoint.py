"""Package committed business workflow using the already tested offline restoration format."""
import hashlib
from pathlib import Path
from build_workbench_entrypoint import build_operator,ROOT

def build_business(destination):
    destination=Path(destination);result=build_operator(destination,update_existing=True)
    text=destination.read_text().replace('scripts/launch_workspace_update.py','scripts/launch_business.py').replace('ReadinessOps AWS workspace update prepared.','ReadinessOps AWS business workflow prepared.').replace('prefix="workspace-update-"','prefix="business-workflow-"')
    text=text.replace('If the connection is interrupted, use the resume command printed by the launcher. Keep this prepared directory.','If disconnected, rerun this same operator to recover the existing build. Your password stays the same.')
    compile(text,str(destination),'exec');destination.write_text(text)
    result.update(sha256=hashlib.sha256(destination.read_bytes()).hexdigest(),size=destination.stat().st_size)
    return result
if __name__=='__main__':print(build_business(ROOT.parent/'outputs/ReadinessOps_AWS_Business_Workflow.py'))
