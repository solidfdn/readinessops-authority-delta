"""Local render fixture from real business service; no AWS/human evidence."""
import json,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path[:0]=[str(ROOT),str(ROOT/'src'),str(ROOT/'scripts'),str(ROOT/'tests')]
from test_business import Flow
from support.business import ACTOR


def build(path=None):
    f=Flow();f.setUp();r=f.approve();approved=f.app.detail(ACTOR,f.oid);f.app.publish(ACTOR,f.oid,f.command(receipt_id=r['receipt_id']));published=f.app.detail(ACTOR,f.oid)
    eid=f.evidence('A new external recipient will receive customer data. Human review is still required.')
    rid=f.app.start_run(ACTOR,f.oid,f.command(evidence_ids=[eid]))['run_id'];f.work(rid)
    reassessment=f.app.detail(ACTOR,f.oid);reassessment_run=f.app.run(ACTOR,f.oid,rid)
    path=Path(path) if path else ROOT/'workbench/.test/business.json';path.parent.mkdir(exist_ok=True)
    value={'scope':'LOCAL_SERVICE_RENDER_FIXTURE','approved':approved,'published':published,'reassessment':reassessment,'reassessment_run':reassessment_run}
    path.write_text(json.dumps(value));return value


if __name__ == '__main__':
    build()
