#!/usr/bin/env bash
# Read the completed local report only. No imports from a repo or AWS calls.
python3 - <<'PY'
import json
from pathlib import Path
p = Path('/tmp/authority-delta-gate-b-6y8n0r56/evidence/aws/64fe9cd81aaf42149c10a5855cc579d9/gate-b-result.json')
r = json.loads(p.read_text())
if r.get('build_id') != 'authority-delta-deploy:4186d536-a5f8-4bf9-9015-2b697b32fcdb':
    raise SystemExit('Different build report; no analysis run.')
print(json.dumps({'error': r.get('error'), 'patches': r.get('patches'), 'analyses': [{'label': c.get('label'), 'proposal': c.get('response', {}).get('proposal'), 'reads': c.get('response', {}).get('reads')} for c in r.get('analysis_calls', [])]}, ensure_ascii=False, indent=2))
PY
