"""Offline publisher composition against the real stdlib WebUI consumer."""
import hashlib
import os
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

import continuation_publish as pub


class PublisherTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name).resolve()
        source = Path(os.environ.get('HERMES_TEST_CONTINUATION_SOURCE',
            '/Users/charles/hermes-webui-verity-resume/api/post_restart_continuation.py'))
        self.assertTrue(source.is_file(), 'Set HERMES_TEST_CONTINUATION_SOURCE to the real consumer source')
        inventory = {}
        for name in pub.FILES:
            p = self.root / name
            p.parent.mkdir(exist_ok=True)
            p.write_bytes(source.read_bytes() if name.endswith('post_restart_continuation.py') else b'# fixture\n')
            inventory[name] = {'sha256': hashlib.sha256(p.read_bytes()).hexdigest(), 'executable': False}
        self.manifest = {'services': {'webui': {'repo': str(self.root), 'commit': 'a' * 40, 'inventory': inventory}}}
        self.consumer = pub.load_consumer(self.manifest)
        self.deployment = pub.deployment_binding(self.manifest)
        self.store = self.root / 'private'
        pub.initialize(self.consumer, self.store, self.deployment)
        self.kw = dict(admission_id='a' * 32, controller_operation_id='controller-1',
                       deployment=self.deployment, binding={'session_id': 's'}, message='Resume', runtime_adapter='legacy-journal')

    def request(self):
        return pub.publish_request(self.consumer, self.store, **self.kw)

    def test_actual_consumer_release_binding_and_inventory(self):
        with patch.dict(os.environ, HERMES_WEBUI_CONTINUATION_DIR=str(self.store)):
            self.assertEqual(self.consumer.release_binding(), self.deployment)
        (self.root / 'api/routes.py').write_text('changed')
        with self.assertRaisesRegex(RuntimeError, 'inventory'):
            pub.deployment_binding(self.manifest)
        (self.root / 'api/post_restart_continuation.py').write_text('raise AssertionError("must not execute")')
        with self.assertRaisesRegex(RuntimeError, 'inventory'):
            pub.load_consumer(self.manifest)

    def test_request_retry_immutable_and_private(self):
        r = self.request()
        self.assertEqual(self.request(), r)
        self.assertEqual((self.store / 'request.json').stat().st_mode & 0o777, 0o600)
        self.kw['message'] = 'Other'
        with self.assertRaisesRegex(RuntimeError, 'Immutable'):
            self.request()
        with self.assertRaisesRegex(RuntimeError, 'different release'):
            pub.initialize(self.consumer, self.store, {})

    def test_terminal_owner_cannot_be_rebound(self):
        r = self.request()
        proof = {'health': 'ok', 'deep_health': 'ok', 'process_identity': {'webui': {'child': {'pid': 123}}}}
        h = {'status': 'ok', 'server_started_at': 1234}
        t = pub.publish_terminal(self.consumer, self.store, r, proof, h)
        self.assertEqual(pub.publish_terminal(self.consumer, self.store, r, proof, h), t)
        proof['process_identity']['webui']['child']['pid'] = 456
        with self.assertRaisesRegex(RuntimeError, 'another owner'):
            pub.publish_terminal(self.consumer, self.store, r, proof, h)

    def test_partial_terminal_and_claim_fail_closed(self):
        r = self.request()
        p = self.store / (self.kw['admission_id'] + '.claim.json')
        p.write_text('{'); p.chmod(0o600)
        with self.assertRaises(ValueError):
            pub.receipt_status(self.consumer, self.store, r)
        self.assertEqual(p.read_text(), '{')

    def test_real_worker_receipt_required_not_thread_start(self):
        r = self.request()
        op = r['operation_admission_id']
        with self.consumer.Store(self.store) as store, store.locked():
            store.write(op + '.claim.json', {'request_digest': pub.digest(r)})
            store.write(op + '.result.json', {'operation_admission_id': op, 'stream_id': 'stream'})
        self.assertEqual(pub.receipt_status(self.consumer, self.store, r)['status'], 'claimed_not_confirmed')
        called = []
        worker = self.consumer.WorkerReceipt(self.store, op).wrap(lambda *a: called.append(True), lambda: self.fail('receipt failed'))
        worker(None, None, None, None, 'stream')
        self.assertEqual(called, [True])
        self.assertEqual(pub.receipt_status(self.consumer, self.store, r), {'status': 'worker_entered', 'stream_id': 'stream'})

    def test_identical_human_text_new_uid_is_intervention(self):
        with sqlite3.connect(self.root / 'state.db') as db:
            db.execute('CREATE TABLE messages (id INTEGER PRIMARY KEY, session_id TEXT, role TEXT, message_uid TEXT, content TEXT)')
            db.execute("INSERT INTO messages VALUES (1,'s','user','u1','same')")
        first = pub.human_anchor(self.root, 's')
        with sqlite3.connect(self.root / 'state.db') as db:
            db.execute("INSERT INTO messages VALUES (2,'s','user','u2','same')")
        self.assertNotEqual(first, pub.human_anchor(self.root, 's'))


if __name__ == '__main__':
    unittest.main()
