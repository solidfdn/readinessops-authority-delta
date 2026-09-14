"""Synthetic staged responses through the real Strands SDK, never live evidence."""
import copy
import json
from strands.models.model import Model
from support.business import proposal


def responses(source):
    draft = proposal(source)
    impacts = {x['decision_item_id']: x for x in draft['reassessment']['impacts']}
    steps = [('read_snapshot', {})]
    for item in draft['decision_items']:
        value = {k: v for k, v in item.items() if k not in ('decision_item_id', 'perspective', 'citations')}
        impact = impacts[item['decision_item_id']]
        value.update(citation_ids=['q0'] if item['citations'] else [],
                     impact_status=impact['status'], impact_reason=impact['reason'],
                     impact_citation_ids=['q0'], unknowns=impact['unknowns'])
        steps.append(('ItemOutput', value))
    header = {k: copy.deepcopy(draft[k]) for k in ('summary', 'findings', 'actions', 'missing_information')}
    for finding in header['findings']:
        finding['citation_ids'] = ['q0'] if finding.pop('citations') else []
    steps.append(('HeaderOutput', header))
    return steps


class StagedModel(Model):
    def __init__(self, steps):
        self.steps = copy.deepcopy(steps)
        self.calls = []
        self.schemas = []
    def update_config(self, **kw): pass
    def get_config(self): return {}
    async def structured_output(self, *a, **kw):
        raise AssertionError('Use the actual SDK tool loop')
        yield
    async def stream(self, messages, tool_specs=None, system_prompt=None, **kw):
        i = len(self.calls)
        self.calls.append(copy.deepcopy(messages))
        self.schemas.append(copy.deepcopy(tool_specs))
        name, value = self.steps[min(i, len(self.steps)-1)]
        yield {'messageStart': {'role': 'assistant'}}
        yield {'contentBlockStart': {'contentBlockIndex': 0, 'start': {'toolUse': {'toolUseId': 'local-'+str(i), 'name': name}}}}
        yield {'contentBlockDelta': {'contentBlockIndex': 0, 'delta': {'toolUse': {'input': json.dumps(value)}}}}
        yield {'contentBlockStop': {'contentBlockIndex': 0}}
        yield {'messageStop': {'stopReason': 'tool_use'}}
