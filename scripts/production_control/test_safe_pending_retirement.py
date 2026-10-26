"""Crash injection at every destructive retirement boundary; no host calls."""
import copy
from contextlib import nullcontext
import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import safe_pending_retirement as retirement


class Crash(BaseException):
    pass


class FakeController:
    def __init__(self, root):
        self.base = root
        self.manifest_path = root / 'selected.json'
        self.transaction_path = root / 'transaction.json'
        self.identity = {'webui': {'child': {'pid': 100}}, 'agent': {'child': {'pid': 200}}}
        self.old, self.new = {'release': 'old'}, {'release': 'new'}
        self.manifest_path.write_text(json.dumps(self.old))
        self.record = {'operation_id': 'pending-operation', 'deadline': 1,
                       'old': retirement.encode(self.manifest_path.read_bytes()),
                       'new': retirement.encode(json.dumps(self.new).encode())}
        (root / 'receipt.json').write_text(json.dumps(self.record))
        self.pin = retirement.sha((root / 'receipt.json').read_bytes())
        (root / 'result.json').write_text(json.dumps({'status': 'expired', 'operation_id': 'pending-operation'}))
        self.original = {'phase': 'verified', 'operation_id': 'earlier-activation',
                         'reload': False, 'authorization': 'verified-live-fallback',
                         'pending_restart_sha256': self.pin, 'other': {'must': 'survive'}}
        self.write_txn(self.original)
        self.pending = SimpleNamespace(RECEIPT='receipt.json', RESULT='result.json', decode=retirement.decode, load=self.load)

    def write_txn(self, txn):
        self.transaction_path.write_text(json.dumps({'schema_version': 2, 'control_refresh_sha256': 'refresh',
            'sha256': retirement.sha(json.dumps(txn, sort_keys=True, separators=(',', ':')).encode()), 'transaction': txn}))

    def read_transaction(self):
        envelope = json.loads(self.transaction_path.read_bytes())
        txn = envelope['transaction']
        assert envelope['schema_version'] == 2 and envelope['control_refresh_sha256'] == 'refresh'
        assert envelope['sha256'] == retirement.sha(json.dumps(txn, sort_keys=True, separators=(',', ':')).encode())
        return txn

    def load(self, c, pin):
        assert retirement.sha((self.base / 'receipt.json').read_bytes()) == pin
        assert self.read_transaction()['pending_restart_sha256'] == pin
        return self.record, self.old, self.new, lambda: None

    def retained_file(self, path):
        return Path(path).read_bytes(), None

    def locked(self): return nullcontext()
    def refresh_admission(self): return lambda: None
    def clock(self): return 100
    def validate_manifest(self, value): return value
    def check_revocation(self, value): pass
    def preflight(self, value): pass
    def definitions(self, value): return {}
    def snapshot(self, *args): return {'process_identity': copy.deepcopy(self.identity), 'health': 'ok', 'deep_health': 'ok'}


class RetirementTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name).resolve()
        self.c = FakeController(self.root)
        self.archive = self.root / 'archive'
        self.writer = SimpleNamespace(atomic_write=lambda path, raw: path.write_bytes(raw))
        self.modules = patch.dict(sys.modules, restart_production=self.writer)
        self.modules.start(); self.addCleanup(self.modules.stop)

    def run_retire(self, **kwargs):
        return retirement.retire(self.c, self.c.pending, self.c.pin, self.archive, **kwargs)

    def assert_retired(self):
        self.assertFalse((self.root / 'receipt.json').exists())
        self.assertFalse((self.root / 'result.json').exists())
        expected = dict(self.c.original); expected.pop('pending_restart_sha256')
        self.assertEqual(self.c.read_transaction(), expected)

    def test_roundtrip_retains_schema_hash_and_previous_operation(self):
        self.run_retire(); self.run_retire()
        self.assert_retired()

    def test_resume_after_each_unlink_and_transaction_write(self):
        for point in ('result.json', 'receipt.json', 'transaction.json'):
            with self.subTest(point=point), tempfile.TemporaryDirectory(dir=self.root) as tmp:
                c = FakeController(Path(tmp)); archive = Path(tmp) / 'archive'
                real_unlink = Path.unlink
                def unlink(path, *args, **kwargs):
                    result = real_unlink(path, *args, **kwargs)
                    if path.name == point: raise Crash()
                    return result
                def write(path, raw):
                    path.write_bytes(raw)
                    if point == 'transaction.json': raise Crash()
                with patch.object(Path, 'unlink', unlink), patch.object(self.writer, 'atomic_write', write):
                    with self.assertRaises(Crash): retirement.retire(c, c.pending, c.pin, archive)
                retirement.retire(c, c.pending, c.pin, archive)
                self.assertNotIn('pending_restart_sha256', c.read_transaction())
                self.assertEqual(c.read_transaction()['operation_id'], 'earlier-activation')

    def journal_only(self):
        def stop(*args, **kwargs): raise Crash()
        with self.assertRaises(Crash): self.run_retire(checkpoint=stop)

    def test_foreign_bytes_never_overwritten_or_unlinked(self):
        for name in ('receipt.json', 'result.json', 'transaction.json', 'selected.json'):
            with self.subTest(name=name):
                self.journal_only()
                path = self.root / name
                original = path.read_bytes(); path.write_bytes(b'foreign')
                with self.assertRaises(RuntimeError): self.run_retire()
                self.assertEqual(path.read_bytes(), b'foreign')
                path.write_bytes(original)

    def test_missing_files_only_after_journal(self):
        (self.root / 'receipt.json').unlink()
        with self.assertRaises(FileNotFoundError): self.run_retire()
        self.assertIn('pending_restart_sha256', self.c.read_transaction())

    def test_changed_owner_refuses_resumed_retirement(self):
        self.journal_only()
        self.c.identity['agent']['child']['pid'] += 1
        with self.assertRaisesRegex(RuntimeError, 'owner changed'): self.run_retire()
        self.assertTrue((self.root / 'receipt.json').exists())

    def test_candidate_verified_result_must_match_live_owner(self):
        self.c.manifest_path.write_text(json.dumps(self.c.new))
        (self.root / 'result.json').write_text(json.dumps({'status': 'verified', 'operation_id': 'pending-operation',
            'receipt_sha256': self.c.pin, 'selected': 'new', 'process_identity': {}, 'candidate_identity': {}}))
        with self.assertRaisesRegex(RuntimeError, 'owner changed'): self.run_retire()
        self.assertFalse((self.archive / 'retirement.json').exists())


class InstalledProtocolCompositionTests(unittest.TestCase):
    def fixture(self, stage=True):
        # Development-source Controller/watchdog, with the existing syscall-free
        # native fixture. Never import the installed maintenance controller.
        from test_pending_user_restart import PendingTests
        fixture = PendingTests()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        if stage:
            fixture.stage()
        return fixture

    def test_actual_controller_schema_and_watchdog_retire_then_prepare(self):
        import watchdog
        f = self.fixture()
        f.clock.sleep(61)
        before = f.c.read_transaction()
        retirement.retire(f.c, watchdog, f.pin, f.base / 'archive')
        expected = dict(before); expected.pop('pending_restart_sha256')
        self.assertEqual(f.c.read_transaction(), expected)
        f.stage()  # Installed prepare guard now accepts the unfenced baseline.
        self.assertEqual(f.c.read_transaction()['pending_restart_sha256'], f.pin)
        self.assertEqual(f.host.calls, [])

    def test_actual_pending_partial_prepare_requires_select_to_complete_fence(self):
        import watchdog
        f = self.fixture(stage=False)
        with patch.object(f.c, 'save_transaction', side_effect=Crash()):
            with self.assertRaises(Crash): f.stage()
        f.pin = watchdog.digest((f.base / watchdog.RECEIPT).read_bytes())
        with f.c.locked():
            with self.assertRaisesRegex(RuntimeError, 'fence drift'):
                watchdog.load(f.c, f.pin)
            watchdog.load(f.c, f.pin, allow_unfenced=True)
        watchdog.select(f.c, f.pin)
        self.assertEqual(f.c.read_transaction()['pending_restart_sha256'], f.pin)
        self.assertEqual(f.host.calls, [])


if __name__ == '__main__': unittest.main()
