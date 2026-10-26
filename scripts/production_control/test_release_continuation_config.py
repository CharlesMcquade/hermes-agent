"""Finite build-time continuation configuration and routing override fences."""
import base64
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
import time
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))
import release_workflow as workflow
import select_for_user_restart as selector


class ContinuationBuildConfigTests(unittest.TestCase):
    def test_disabled_is_unchanged(self):
        self.assertEqual(workflow.continuation_environment({}), {})

    def test_exact_finite_environment(self):
        with tempfile.TemporaryDirectory(dir=os.environ.get('TMPDIR')) as temp:
            root = Path(temp).resolve()
            cfg = {'continuation_dir': str(root / 'operation' / 'continuation'),
                   'output': str(root / 'release'), 'agent_repo': str(root / 'agent'),
                   'webui_repo': str(root / 'webui'), 'scratch': str(root / 'scratch'),
                   'controls': str(root / 'controls')}
            result = workflow.continuation_environment(cfg)
            self.assertEqual(result, {'HERMES_WEBUI_CONTINUATION_DIR': cfg['continuation_dir'],
                                     'HERMES_WEBUI_RUNTIME_ADAPTER': 'legacy-direct',
                                     'HERMES_WEBUI_CHAT_BACKEND': 'legacy'})
            self.assertTrue(set(result).issubset(selector.ROUTING_KEYS))

    def test_overlap_and_alias_rejected(self):
        with tempfile.TemporaryDirectory(dir=os.environ.get('TMPDIR')) as temp:
            root = Path(temp).resolve()
            protected = root / 'release'; protected.mkdir()
            for directory in (protected, protected / 'subdir', root):
                with self.subTest(directory=directory), self.assertRaises(RuntimeError):
                    workflow.continuation_environment({'continuation_dir': str(directory),
                                                       'output': str(protected)})
            (root / 'alias').symlink_to(protected, target_is_directory=True)
            with self.assertRaises(RuntimeError):
                workflow.continuation_environment({'continuation_dir': str(root / 'alias' / 'subdir')})

    def test_relative_path_rejected(self):
        with self.assertRaises(RuntimeError):
            workflow.continuation_environment({'continuation_dir': 'relative/continuation'})


class RecoveryFenceStateTests(unittest.TestCase):
    """Fixture-based proof of the read-only recovery-authorization verifier."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=os.environ.get('TMPDIR'))
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name).resolve()
        self.base = root / 'maintenance'; self.base.mkdir()
        self.output = root / 'releases' / 'r2'; self.output.mkdir(parents=True)
        self.old = b'{"release_id":"old"}'
        self.foreign_new = b'{"release_id":"foreign-new"}'
        self.candidate = b'{"release_id":"my-candidate"}'
        (self.base / 'production-release.json').write_bytes(self.old)
        (self.output / 'release.json').write_bytes(self.candidate)
        self.receipt = {'operation_id': 'op-x', 'deadline': 1.0,
                        'old': {'data': base64.b64encode(self.old).decode()},
                        'new': {'data': base64.b64encode(self.foreign_new).decode()}}
        raw = json.dumps(self.receipt).encode()
        self.pin = hashlib.sha256(raw).hexdigest()
        (self.base / 'pending-user-restart.json').write_bytes(raw)
        self.txn = {'transaction': {'phase': 'verified', 'pending_restart_sha256': self.pin}}
        (self.base / 'activation-transaction.json').write_bytes(json.dumps(self.txn).encode())
        self.cfg = {'baseline': str(self.base / 'production-release.json'),
                    'output': str(self.output)}

    def test_expired_foreign_fence_is_authorized(self):
        state = workflow.recovery_fence_state(self.cfg, self.pin)
        self.assertEqual(state, {'operation_id': 'op-x', 'deadline': 1.0})

    def test_unexpired_fence_refused(self):
        raw = (self.base / 'pending-user-restart.json').read_bytes()
        receipt = json.loads(raw); receipt['deadline'] = time.time() + 999
        raw = json.dumps(receipt).encode()
        (self.base / 'pending-user-restart.json').write_bytes(raw)
        self.assertIsNone(workflow.recovery_fence_state(self.cfg, hashlib.sha256(raw).hexdigest()))

    def test_pin_old_candidate_or_fence_mismatch_refused(self):
        self.assertIsNone(workflow.recovery_fence_state(self.cfg, '0' * 64))
        (self.base / 'production-release.json').write_bytes(b'{"release_id":"other"}')
        self.assertIsNone(workflow.recovery_fence_state(self.cfg, self.pin))
        (self.base / 'production-release.json').write_bytes(self.old)
        (self.output / 'release.json').write_bytes(self.foreign_new)
        self.assertIsNone(workflow.recovery_fence_state(self.cfg, self.pin))
        (self.output / 'release.json').write_bytes(b'{"release_id":"distinct"}')
        self.txn['transaction']['pending_restart_sha256'] = 'f' * 64
        (self.base / 'activation-transaction.json').write_bytes(json.dumps(self.txn).encode())
        self.assertIsNone(workflow.recovery_fence_state(self.cfg, self.pin))


if __name__ == '__main__':
    unittest.main()
