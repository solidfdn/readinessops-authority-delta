"""Local race regressions; these are not live revocation or RO-07 evidence."""
import copy
import unittest

import test_business_delegation as d3


class AuthorityFence(unittest.TestCase):
    def setUp(self):
        self.f = d3.DelegationFlow('test_no_registered_adapter_fails_closed')
        self.f.setUp()
        self.f.publish()

    def start(self, days=1):
        return self.f.message(self.f.start(self.f.delegate(days=days)))

    def head(self):
        return self.f.flow.db.get('app', self.f.oid, 'HEAD')

    def invalidate(self):
        h = self.head()
        self.f.flow.db.transact([('app', self.f.oid, 'HEAD',
            dict(h.value, delegation_generation=h.value['delegation_generation'] + 1,
                 delegation_approval=None), h.version)])

    def assert_closed(self, result):
        self.assertEqual(result['status'], 'RECOVERED_CLOSED')
        self.assertIsNone(self.head().value['applied_binding'])
        self.assertIsNone(self.f.flow.db.get('app', result['lock_pk'], 'WRITER'))

    def assert_unknown(self, result):
        self.assertEqual(result['status'], 'UNKNOWN')
        self.assertIsNone(self.head().value['applied_binding'])
        self.assertIsNotNone(self.f.flow.db.get('app', result['lock_pk'], 'WRITER'))

    def test_queued_expiry_cancels_without_calling_publisher(self):
        message = self.start()
        self.f.flow.clock.advance(86400)
        publisher = d3.ScriptedPublisher()
        result = self.f.worker(publisher).process(message)
        self.assertEqual(result['status'], 'CANCELLED')
        self.assertEqual(publisher.calls, [])
        self.assertIsNone(self.f.flow.db.get('app', result['lock_pk'], 'WRITER'))

    def test_queued_generation_invalidation_cancels_without_calling_publisher(self):
        message = self.start()
        self.invalidate()
        publisher = d3.ScriptedPublisher()
        self.assertEqual(self.f.worker(publisher).process(message)['status'], 'CANCELLED')
        self.assertEqual(publisher.calls, [])

    def test_current_receipt_pointer_is_required_even_when_generation_matches(self):
        message = self.start()
        h = self.head()
        self.f.flow.db.transact([('app', self.f.oid, 'HEAD',
            dict(h.value, delegation_approval=None), h.version)])
        publisher = d3.ScriptedPublisher()
        self.assertEqual(self.f.worker(publisher).process(message)['status'], 'CANCELLED')
        self.assertEqual(publisher.calls, [])

    def test_missing_current_generation_cannot_bypass_the_fence(self):
        message = self.start()
        h = self.head()
        changed = dict(h.value)
        changed.pop('delegation_generation')
        self.f.flow.db.transact([('app', self.f.oid, 'HEAD', changed, h.version)])
        publisher = d3.ScriptedPublisher()
        self.assertEqual(self.f.worker(publisher).process(message)['status'], 'CANCELLED')
        self.assertEqual(publisher.calls, [])

    def test_current_receipt_corruption_still_allows_closed_recovery(self):
        message = self.start()
        self.f.worker(d3.ScriptedPublisher(publish=TimeoutError('response lost'))).process(message)
        h = self.head()
        changed = copy.deepcopy(h.value)
        changed['delegation_approval']['expires_at'] = '2026-10-09T00:00:00+00:00'
        self.f.flow.db.transact([('app', self.f.oid, 'HEAD', changed, h.version)])
        publisher = d3.ScriptedPublisher(reconcile='RECOVERED_CLOSED')
        self.assert_closed(self.f.worker(publisher).process(message))
        self.assertTrue(publisher.calls[0][2])

    def test_receipt_is_not_authority_before_its_approval_time(self):
        message = self.start()
        self.f.flow.clock.advance(-1)
        publisher = d3.ScriptedPublisher()
        self.assertEqual(self.f.worker(publisher).process(message)['status'], 'CANCELLED')
        self.assertEqual(publisher.calls, [])

    def test_unknown_expired_candidate_can_only_reconcile_closed(self):
        message = self.start()
        self.f.worker(d3.ScriptedPublisher(publish=TimeoutError('response lost'))).process(message)
        self.f.flow.clock.advance(86400)
        publisher = d3.ScriptedPublisher(reconcile='RECOVERED_CLOSED')
        self.assert_closed(self.f.worker(publisher).process(message))
        self.assertEqual(publisher.calls, [('reconcile', message['enforcement_digest'], True)])

    def test_unknown_invalidated_generation_can_still_be_recovered_closed(self):
        message = self.start()
        self.f.worker(d3.ScriptedPublisher(publish=TimeoutError('response lost'))).process(message)
        self.invalidate()
        publisher = d3.ScriptedPublisher(reconcile='RECOVERED_CLOSED')
        self.assert_closed(self.f.worker(publisher).process(message))
        self.assertTrue(publisher.calls[0][2])

    def test_expiry_during_publisher_call_closes_before_terminal_commit(self):
        message = self.start()
        outer = self
        class Publisher(d3.ScriptedPublisher):
            def publish(self, candidate):
                outer.f.flow.clock.advance(86400)
                return super().publish(candidate)
        publisher = Publisher(reconcile='RECOVERED_CLOSED')
        self.assert_closed(self.f.worker(publisher).process(message))
        self.assertEqual([call[0] for call in publisher.calls], ['publish', 'reconcile'])
        self.assertTrue(publisher.calls[-1][2])

    def test_invalidation_during_publisher_call_closes_before_terminal_commit(self):
        message = self.start()
        outer = self
        class Publisher(d3.ScriptedPublisher):
            def publish(self, candidate):
                outer.invalidate()
                return super().publish(candidate)
        publisher = Publisher(reconcile='RECOVERED_CLOSED')
        self.assert_closed(self.f.worker(publisher).process(message))
        self.assertTrue(publisher.calls[-1][2])

    def test_closed_request_with_allow_result_remains_unknown_and_locked(self):
        message = self.start()
        self.f.worker(d3.ScriptedPublisher(publish=TimeoutError('response lost'))).process(message)
        self.f.flow.clock.advance(86400)
        self.assert_unknown(self.f.worker(d3.ScriptedPublisher()).process(message))

    def test_closed_request_with_lost_response_remains_unknown_and_locked(self):
        message = self.start()
        self.f.worker(d3.ScriptedPublisher(publish=TimeoutError('response lost'))).process(message)
        self.f.flow.clock.advance(86400)
        self.assert_unknown(self.f.worker(d3.ScriptedPublisher(
            reconcile=TimeoutError('closure unconfirmed'))).process(message))

    def test_expiry_during_result_storage_is_rechecked_at_commit(self):
        message = self.start()
        blobs = self.f.flow.blobs
        original = blobs.put
        def put(key, raw, *args, **kwargs):
            result = original(key, raw, *args, **kwargs)
            if key.endswith('/publisher-result.json'):
                self.f.flow.clock.advance(86400)
            return result
        blobs.put = put
        self.assert_unknown(self.f.worker(d3.ScriptedPublisher()).process(message))
        blobs.put = original
        self.assert_closed(self.f.worker(d3.ScriptedPublisher(
            reconcile='RECOVERED_CLOSED')).process(message))

    def test_invalidated_candidate_keeps_still_valid_previous_binding(self):
        first = self.start(days=30)
        self.f.worker(d3.ScriptedPublisher()).process(first)
        prior = copy.deepcopy(self.head().value['applied_binding'])
        second = self.start()
        self.f.flow.clock.advance(86400)
        publisher = d3.ScriptedPublisher()
        self.assertEqual(self.f.worker(publisher).process(second)['status'], 'CANCELLED')
        self.assertEqual(self.head().value['applied_binding'], prior)
        self.assertEqual(publisher.calls, [])

    def test_changed_lock_identity_is_never_released_by_late_worker(self):
        message = self.start()
        outer = self
        class Publisher(d3.ScriptedPublisher):
            def publish(self, candidate):
                db = outer.f.flow.db
                state = db.get('app', outer.f.oid, 'APPLICATION#' + candidate['application_id'])
                lock = db.get('app', state.value['lock_pk'], 'WRITER')
                db.transact([('app', state.value['lock_pk'], 'WRITER',
                    dict(lock.value, enforcement_digest='0' * 64), lock.version)])
                return super().publish(candidate)
        self.assert_unknown(self.f.worker(Publisher()).process(message))


if __name__ == '__main__':
    unittest.main()
