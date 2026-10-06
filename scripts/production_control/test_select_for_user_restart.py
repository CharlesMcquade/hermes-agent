"""Disposable transaction-kernel tests; NOT live UI/controller acceptance."""
import contextlib
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parent

def load(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / (name + '.py'))
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

s = load('select_for_user_restart')
r = load('restart_production')


class Fixture:
    def __init__(self, base):
        self.base = base
        self.manifest_path = base / 'production-release.json'
        self.transaction_path = base / 'activation-transaction.json'
        self.phase = 'rolled_back'
        self.pid = 101
        self.reject_candidate = False
        self.in_lock = False
        self.admitted = 0
        self.preflight_count = 0
        for name in ('old', 'candidate'):
            m = {'schema_version': 2, 'release_id': name, 'labels': {'agent': 'a', 'webui': 'w'}, 'services': {}}
            (self.manifest_path if name == 'old' else base / 'candidate.json').write_text(json.dumps(m))
        self.transaction_path.write_text(json.dumps({'schema_version': 2, 'transaction': {'phase': self.phase}}))
        (base / 'control.lock').touch()
        for role in ('agent', 'webui'):
            (base / (role + '.plist')).write_bytes(b'exact plist bytes')

    @contextlib.contextmanager
    def locked(self):
        st = (self.base / 'control.lock').stat()
        with r.control_lock(self.base, (st.st_dev, st.st_ino)):
            self.in_lock = True
            try:
                yield
            finally:
                self.in_lock = False

    def refresh_admission(self):
        assert self.in_lock
        self.admitted += 1
        return lambda: None

    def read_transaction(self):
        return {'phase': self.phase}

    def retained_file(self, path):
        st = path.stat()
        return path.read_bytes(), (st.st_ino, st.st_mtime_ns)

    def validate_manifest(self, m):
        return m

    def plist_path(self, m, role):
        return self.base / (role + '.plist')

    def definitions(self, m, saved):
        return saved

    def candidate_definitions(self, old, new, saved, reload):
        assert reload is False
        return saved

    def check_revocation(self, m):
        if self.reject_candidate and m['release_id'] == 'candidate':
            raise s.SelectionRefused('revoked')

    def preflight(self, m):
        self.preflight_count += 1

    def snapshot(self, m, d):
        return {'pids': {'agent': self.pid, 'webui': 102}}


class SelectionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=os.environ.get('TMPDIR'))
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.c = Fixture(self.base)
        self.old = self.c.manifest_path.read_bytes()
        self.new = (self.base / 'candidate.json').read_bytes()
        self.transaction = self.c.transaction_path.read_bytes()
        self.kw = dict(atomic_write=r.atomic_write, save_json=r.save_json,
                       route_gate=lambda *a: lambda: None, approve=True)

    def run_select(self, **overrides):
        kw = dict(self.kw, **overrides)
        return s.select_locked(self.c, self.base / 'candidate.json', s.digest(self.old),
                               s.digest(self.new), self.base / 'backup.json',
                               self.base / 'receipt.json', **kw)

    def test_rolled_back_terminal_selection_preserves_transaction_and_pids(self):
        result = self.run_select()
        self.assertEqual(result['status'], 'selected_pending_user_restart')
        self.assertEqual(result['pids'], {'agent': 101, 'webui': 102})
        self.assertEqual(self.c.manifest_path.read_bytes(), self.new)
        self.assertEqual(self.c.transaction_path.read_bytes(), self.transaction)
        self.assertTrue((self.base / 'backup.json').exists())
        self.assertEqual(self.c.admitted, 1)

    def test_dry_run_no_writes(self):
        self.assertEqual(self.run_select(approve=False)['status'], 'checked')
        self.assertEqual(self.c.manifest_path.read_bytes(), self.old)
        self.assertFalse((self.base / 'backup.json').exists())

    def test_nonterminal_and_failed_rollback_refused(self):
        for phase in ('prepared', 'rollback_started', 'rollback_failed'):
            self.c.phase = phase
            with self.assertRaises(s.SelectionRefused):
                self.run_select()
            self.assertEqual(self.c.manifest_path.read_bytes(), self.old)

    def test_admission_refusal_preserves_everything(self):
        def refuse():
            raise s.SelectionRefused('native refresh refusal')
        self.c.refresh_admission = refuse
        with self.assertRaisesRegex(s.SelectionRefused, 'native refresh'):
            self.run_select()
        self.assertFalse((self.base / 'backup.json').exists())

    def test_route_refusal_precedes_backup(self):
        def gate(*args):
            raise s.SelectionRefused('watchdog ownership')
        with self.assertRaisesRegex(s.SelectionRefused, 'watchdog'):
            self.run_select(route_gate=gate)
        self.assertFalse((self.base / 'backup.json').exists())
        self.assertEqual(self.c.manifest_path.read_bytes(), self.old)

    def test_cas_refuses_changed_selector(self):
        self.c.manifest_path.write_bytes(b'changed')
        with self.assertRaisesRegex(s.SelectionRefused, 'CAS'):
            self.run_select()
        self.assertEqual(self.c.manifest_path.read_bytes(), b'changed')

    def test_candidate_revoked(self):
        self.c.reject_candidate = True
        with self.assertRaisesRegex(s.SelectionRefused, 'revoked'):
            self.run_select()
        self.assertEqual(self.c.manifest_path.read_bytes(), self.old)

    def test_mutation_during_gate_refused(self):
        def gate(*args):
            self.c.transaction_path.write_bytes(b'changed')
            return lambda: None
        with self.assertRaisesRegex(s.SelectionRefused, 'Pinned input'):
            self.run_select(route_gate=gate)
        self.assertFalse((self.base / 'backup.json').exists())

    def test_pid_change_before_publish_refused(self):
        def gate(*args):
            self.c.pid += 1
            return lambda: None
        with self.assertRaisesRegex(s.SelectionRefused, 'PIDs'):
            self.run_select(route_gate=gate)
        self.assertEqual(self.c.manifest_path.read_bytes(), self.old)

    def test_receipt_failure_restores_exact_fallback(self):
        def save(path, data):
            if path.name == 'receipt.json':
                raise OSError('receipt disk full')
            r.save_json(path, data)
        with self.assertRaisesRegex(OSError, 'disk full'):
            self.run_select(save_json=save)
        self.assertEqual(self.c.manifest_path.read_bytes(), self.old)
        self.assertEqual(self.c.transaction_path.read_bytes(), self.transaction)

    def test_receipt_write_then_failure_does_not_leave_success(self):
        def save(path, data):
            r.save_json(path, data)
            if path.name == 'receipt.json':
                raise OSError('post-write receipt failure')
        with self.assertRaisesRegex(OSError, 'post-write'):
            self.run_select(save_json=save)
        self.assertEqual(self.c.manifest_path.read_bytes(), self.old)
        receipt = self.base / 'receipt.json'
        self.assertFalse(receipt.exists() and
                         json.loads(receipt.read_bytes()).get('status') == 'selected_pending_user_restart')

    def test_replace_then_fsync_failure_restores(self):
        def write(path, data):
            r.atomic_write(path, data)
            if data == self.new:
                raise OSError('post-rename fsync')
        with self.assertRaisesRegex(OSError, 'post-rename'):
            self.run_select(atomic_write=write)
        self.assertEqual(self.c.manifest_path.read_bytes(), self.old)

    def test_rollback_never_overwrites_unrelated_selector(self):
        def write(path, data):
            r.atomic_write(path, b'unrelated')
            raise OSError('race')
        with self.assertRaisesRegex(s.SelectionRefused, 'Rollback CAS refused'):
            self.run_select(atomic_write=write)
        self.assertEqual(self.c.manifest_path.read_bytes(), b'unrelated')

    def test_existing_backup_refused(self):
        (self.base / 'backup.json').write_bytes(b'keep')
        with self.assertRaisesRegex(s.SelectionRefused, 'Output already'):
            self.run_select()
        self.assertEqual((self.base / 'backup.json').read_bytes(), b'keep')

    def test_no_public_route_bypass(self):
        root = self.base / 'source'
        (root / 'api').mkdir(parents=True)
        (root / 'hermes_cli').mkdir()
        (root / 'api/routes.py').write_text('UI fixture')
        (root / 'hermes_cli/gateway_launchd.py').write_text('refresh_ok = _gw().refresh_launchd_plist_if_needed()\nplist_path.write_text(new_plist')
        (root / 'watchdog.py').write_text('c.listener_ownership(manifest, jobs)\nc.host.kickstart')
        old = {'release_id': 'old', 'native_host': True, 'services': {
            role: {'repo': str(root), 'argv': ['old']} for role in ('agent', 'webui')}}
        new = json.loads(json.dumps(old))
        new['services']['webui']['argv'] = ['new']
        result = s.audit_routes(old, new, root)
        self.assertEqual(len(result['blockers']), 3)
        self.assertFalse(result['changed'])
        # Even byte-preserving argv cannot bless an unaudited CLI path.
        self.assertEqual(s.audit_routes(old, old, root)['status'], 'blocked')


if __name__ == '__main__':
    unittest.main()
