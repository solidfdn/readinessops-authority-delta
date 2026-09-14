"""Typed business-boundary bindings, independent of any particular business."""
from dataclasses import dataclass
from collections.abc import Callable, Mapping
import copy,re
from .canonical import sha256_json

@dataclass(frozen=True)
class BoundaryAdapter:
    adapter_id: str
    version: str
    schema: dict
    validate: Callable

    def binding(self, parameters):
        if not re.fullmatch(r'[a-z][a-z0-9_-]{0,63}',self.adapter_id):raise ValueError('Invalid adapter identity')
        if not re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+',self.version):raise ValueError('Exact adapter version required')
        checked=self.validate(copy.deepcopy(parameters))
        # Validation is not a silent permission or data rewrite.
        if sha256_json(checked)!=sha256_json(parameters):raise ValueError('Boundary validator changed parameters')
        value={'schema_version':'1.1','adapter_id':self.adapter_id,'adapter_version':self.version,
            'adapter_schema_hash':sha256_json(self.schema),'parameters':checked}
        value['boundary_hash']=sha256_json(value)
        return value

def verify_boundary(value,registered:Mapping[str,BoundaryAdapter]):
    if not isinstance(value,dict) or set(value)!={'schema_version','adapter_id','adapter_version','adapter_schema_hash','parameters','boundary_hash'}:
        raise ValueError('Unexpected boundary contract')
    adapter=registered.get(value['adapter_id'])
    if adapter is None:raise ValueError('Unsupported business adapter')
    expected=adapter.binding(value['parameters'])
    if expected!=value:raise ValueError('Boundary adapter version, schema or content mismatch')
    return expected
