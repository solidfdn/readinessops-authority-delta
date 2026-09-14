"""Local-only prior-publication input binding; no human or AWS acceptance claims."""
import copy
import hashlib
import json
import unittest

import test_business as existing
from authority_delta.business.contracts import (PROMPT_VERSION, check_snapshot,
                                                legacy_decision_item_registry,
                                                prior_decision_items,
                                                validate_proposal)
from authority_delta.business.service import Problem
from authority_delta.business.storage import encode
from authority_delta.canonical import sha256_json
from services.business_analysis.agent import assess
from support.business import ACTOR, proposal


class PriorPublicationInput(unittest.TestCase):
    def setUp(self):
        self.flow = existing.Flow(methodName="test_nonpayment_cycle_and_new_input_preserves_official_history")
        self.flow.setUp()

    def publish(self):
        f = self.flow
        receipt = f.approve()
        publication = f.app.publish(ACTOR, f.oid, f.command(receipt_id=receipt["receipt_id"]))
        return publication

    def prepare(self):
        publication = self.publish()
        eid = self.flow.evidence("New processing rules require another review before external sharing.")
        return publication, eid

    def start(self, eid):
        f = self.flow
        result = f.app.start_run(ACTOR, f.oid, f.command(evidence_ids=[eid]))
        job = f.db.get("jobs", result["run_id"], "STATE").value
        return json.loads(f.blobs.read(job["input_ref"]))

    def replace_publication(self, publication):
        f = self.flow
        body = {k: v for k, v in publication.items() if k != "ref"}
        ref = f.blobs.put("business/publications/" + body["publication_id"] + ".json", encode(body))
        current = dict(body, ref=ref)
        head = f.db.get("app", f.oid, "HEAD")
        record = f.db.get("app", f.oid, "PUBLICATION#" + body["publication_id"])
        f.db.transact([("app", f.oid, "HEAD", dict(head.value, published_current=current), head.version),
                       ("app", f.oid, "PUBLICATION#" + body["publication_id"], current, record.version)])
        return current

    def assert_start_rejected_without_queue(self, eid, message=None):
        f = self.flow
        before = copy.deepcopy(f.db.rows)
        with self.assertRaises((Problem, ValueError, KeyError)) as caught:
            self.start(eid)
        if message:
            self.assertIn(message, str(caught.exception))
        self.assertEqual(f.db.rows, before, "An invalid prior binding must not enqueue or advance business state")

    def test_reassessment_pins_complete_publication_after_evidence_edit(self):
        published, eid = self.prepare()
        f = self.flow
        source = self.start(eid)
        prior = source["prior_publication"]
        self.assertEqual(source["mode"], "REASSESSMENT")
        self.assertEqual(source["prompt_version"], PROMPT_VERSION)
        self.assertEqual(len(source["decision_item_registry"]), 4)
        self.assertEqual(len({x["decision_item_id"] for x in source["decision_item_registry"]}), 4)
        self.assertEqual(prior["publication_ref"], published["ref"])
        self.assertEqual(prior["publication"], {k: v for k, v in published.items() if k != "ref"})
        self.assertEqual(prior["receipt"], json.loads(f.blobs.read(published["receipt_ref"])))
        self.assertEqual(prior["decision"], json.loads(f.blobs.read(published["decision_ref"])))
        self.assertEqual(prior["decision"]["digest"], published["digest"])
        self.assertFalse(prior["receipt"]["runtime_authority_granted"])
        self.assertEqual(f.app.detail(ACTOR, f.oid)["object"]["published_current"], published)
        self.assertGreater(f.app.detail(ACTOR, f.oid)["object"]["generation"], prior["receipt"]["generation"])
        check_snapshot(source)

    def test_missing_or_corrupt_prior_blob_never_queues(self):
        for field in ("ref", "receipt_ref", "decision_ref"):
            for failure in ("missing", "corrupt"):
                with self.subTest(field=field, failure=failure):
                    self.setUp()
                    published, eid = self.prepare()
                    ref = published[field]
                    key = (ref["key"], ref["version_id"])
                    if failure == "missing":
                        del self.flow.blobs.data[key]
                    else:
                        self.flow.blobs.data[key] = b"{}"
                    self.assert_start_rejected_without_queue(eid)

    def test_cross_object_publication_with_valid_blob_hashes_is_rejected(self):
        published, eid = self.prepare()
        changed = dict(published, object_id="o-" + "b" * 32)
        self.replace_publication(changed)
        self.assert_start_rejected_without_queue(eid, "binding mismatch")

    def test_head_publication_must_equal_its_stored_document(self):
        published, eid = self.prepare()
        f = self.flow
        head = f.db.get("app", f.oid, "HEAD")
        changed = dict(published, publisher_name="Not the recorded publisher")
        f.db.transact([("app", f.oid, "HEAD", dict(head.value, published_current=changed), head.version)])
        self.assert_start_rejected_without_queue(eid)

    def test_expired_receipt_is_retained_only_as_historical_reference(self):
        published, eid = self.prepare()
        self.flow.clock.advance(8 * 86400)
        source = self.start(eid)
        self.assertEqual(source["prior_publication"]["receipt"]["receipt_id"], published["receipt_id"])
        self.assertFalse(source["prior_publication"]["receipt"]["runtime_authority_granted"])
        self.assertIsNone(self.flow.app.detail(ACTOR, self.flow.oid)["object"]["applied_binding"])
        check_snapshot(source)

    def test_outer_input_hash_binds_prior_contents(self):
        _, eid = self.prepare()
        source = self.start(eid)
        changed = copy.deepcopy(source)
        changed["prior_publication"]["publication"]["publisher_name"] = "Changed historical name"
        self.assertNotEqual(source["input_hash"], sha256_json({k: v for k, v in changed.items() if k != "input_hash"}))
        with self.assertRaises(ValueError):
            check_snapshot(changed)

    def test_unbound_legacy_reassessment_is_not_accepted(self):
        from deploy_business import canary_input
        initial = canary_input("local")
        initial["prompt_version"] = "readinessops-business-1.2.0"
        initial["input_hash"] = sha256_json({k: v for k, v in initial.items() if k != "input_hash"})
        check_snapshot(initial)
        for version in ("readinessops-business-1.2.0", "readinessops-business-1.2.1"):
            changed = dict(initial, mode="REASSESSMENT", prompt_version=version)
            changed["input_hash"] = sha256_json({k: v for k, v in changed.items() if k != "input_hash"})
            with self.subTest(version=version), self.assertRaises(ValueError):
                check_snapshot(changed)

    def test_oversized_prior_bundle_is_rejected_before_queue(self):
        published, eid = self.prepare()
        f = self.flow
        decision = json.loads(f.blobs.read(published["decision_ref"]))
        decision["change_reason"] = "x" * 270000
        decision["digest"] = sha256_json({k: v for k, v in decision.items() if k != "digest"})
        decision_ref = f.blobs.put(published["decision_ref"]["key"], encode(decision))
        receipt = json.loads(f.blobs.read(published["receipt_ref"]))
        receipt["digest"] = decision["digest"]
        receipt_ref = f.blobs.put(published["receipt_ref"]["key"], encode(receipt))
        self.replace_publication(dict(published, digest=decision["digest"], decision_ref=decision_ref, receipt_ref=receipt_ref))
        self.assert_start_rejected_without_queue(eid, "runtime byte limit")

    def test_read_context_supplies_the_pinned_prior_to_real_strands_tool_loop(self):
        published, eid = self.prepare()
        source = self.start(eid)
        draft = proposal(source)
        draft.pop('input_hash')
        from support.staged_model import StagedModel, responses
        model = StagedModel(responses(source))
        result = assess(source, model=model)
        self.assertEqual(result["status"], "VALIDATED")
        self.assertEqual(result["reads"], ["context", "evidence"])
        messages = json.dumps(model.calls, ensure_ascii=False)
        self.assertIn("prior_publication", messages)
        self.assertIn(published["publication_id"], messages)
        self.assertIn(published["digest"], messages)

    def test_related_unrelated_and_unknown_impacts_are_distinct(self):
        _, eid = self.prepare()
        source = self.start(eid)
        related = validate_proposal(proposal(source), source)
        impacts = {x["decision_item_id"]: x for x in related["reassessment"]["impacts"]}
        governance = next(x for x in related["decision_items"] if x["perspective"] == "GOVERNANCE")
        self.assertEqual(impacts[governance["decision_item_id"]]["status"], "AFFECTED")

        unrelated = copy.deepcopy(related)
        for impact in unrelated["reassessment"]["impacts"]:
            impact["status"] = "UNCHANGED"
        self.assertTrue(all(x["status"] == "UNCHANGED" for x in validate_proposal(unrelated, source)["reassessment"]["impacts"]))

        unknown = copy.deepcopy(related)
        target = governance["decision_item_id"]
        next(x for x in unknown["decision_items"] if x["decision_item_id"] == target)["recommendation"] = "NEEDS_INPUT"
        item = next(x for x in unknown["reassessment"]["impacts"] if x["decision_item_id"] == target)
        item.update(status="UNKNOWN", unknowns=["The changed rule does not identify its approving authority."])
        self.assertEqual(validate_proposal(unknown, source)["reassessment"]["impacts"][0]["status"], "UNKNOWN")

    def test_reassessment_rejects_foreign_missing_or_fabricated_comparison(self):
        _, eid = self.prepare()
        source = self.start(eid)
        valid = proposal(source)
        changes = [
            lambda p: p["reassessment"].update(compared_publication_id="pub-" + "b" * 32),
            lambda p: p["reassessment"].update(compared_decision_digest="b" * 64),
            lambda p: p["decision_items"][0].pop("decision_item_id"),
            lambda p: p["reassessment"]["impacts"][0].update(decision_item_id="di-" + "b" * 32),
            lambda p: p["reassessment"]["impacts"].pop(),
            lambda p: p["reassessment"]["impacts"][0]["citations"][0].update(quote="A fabricated quotation."),
        ]
        for change in changes:
            candidate = copy.deepcopy(valid)
            change(candidate)
            with self.subTest(change=changes.index(change)), self.assertRaises(ValueError):
                validate_proposal(candidate, source)

        hidden_change = copy.deepcopy(valid)
        hidden_change["reassessment"]["impacts"][0]["status"] = "UNCHANGED"
        hidden_change["decision_items"][0]["recommendation"] = "STOP"
        with self.assertRaisesRegex(ValueError, "Unchanged impact"):
            validate_proposal(hidden_change, source)

    def test_legacy_prior_items_receive_registry_ids_without_reusing_perspective_as_id(self):
        _, eid = self.prepare()
        source = self.start(eid)
        source.pop("decision_item_registry")
        source["prompt_version"] = "readinessops-business-1.2.1"
        prior = source["prior_publication"]
        for item in prior["decision"]["proposal"]["decision_items"]:
            item.pop("decision_item_id", None)
        prior["decision"]["digest"] = sha256_json({k: v for k, v in prior["decision"].items() if k != "digest"})
        prior["receipt"]["digest"] = prior["decision"]["digest"]
        prior["publication"]["digest"] = prior["decision"]["digest"]

        def rebound(ref, document):
            raw = encode(document)
            return dict(ref, sha256=hashlib.sha256(raw).hexdigest(), size=len(raw))

        prior["publication"]["decision_ref"] = rebound(prior["publication"]["decision_ref"], prior["decision"])
        prior["publication"]["receipt_ref"] = rebound(prior["publication"]["receipt_ref"], prior["receipt"])
        prior["publication_ref"] = rebound(prior["publication_ref"], prior["publication"])
        source["input_hash"] = sha256_json({k: v for k, v in source.items() if k != "input_hash"})
        check_snapshot(source)
        normalized = prior_decision_items(source)
        expected = {x["decision_item_id"] for x in legacy_decision_item_registry(source["object_id"])}
        self.assertEqual({x["decision_item_id"] for x in normalized}, expected)
        self.assertTrue(all(x["decision_item_id"] != x["perspective"] for x in normalized))
        self.assertEqual({x["decision_item_id"] for x in validate_proposal(proposal(source), source)["decision_items"]}, expected)


if __name__ == "__main__":
    unittest.main()
