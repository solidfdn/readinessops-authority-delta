"""Generate a stdlib-only operator, with no prepared-directory dependencies."""
import ast,hashlib
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]

def build(destination):
    password_source=(ROOT/'scripts/launch_workbench.py').read_text()
    tree=ast.parse(password_source)
    names={'password_error_category','set_password_command','setup_password'}
    functions=[ast.get_source_segment(password_source,n) for n in tree.body if isinstance(n,ast.FunctionDef) and n.name in names]
    if len(functions)!=3:raise ValueError('Password helper set changed')
    recovery=(ROOT/'scripts/workbench_signin_recovery.py').read_text()
    marker='from launch_workbench import setup_password, DeploymentError'
    if recovery.count(marker)!=1:raise ValueError('Standalone import marker changed')
    code=recovery.replace(marker,'class DeploymentError(RuntimeError):\n    pass\n\n'+'\n\n'.join(functions))
    compile(code,'Authority_Delta_Workbench_SignIn_V2.py','exec')
    path=Path(destination);path.write_text(code)
    return {'path':str(path),'sha256':hashlib.sha256(path.read_bytes()).hexdigest(),'size':path.stat().st_size}

if __name__=='__main__':print(build(ROOT.parent/'outputs/Authority_Delta_Workbench_SignIn_V2.py'))
