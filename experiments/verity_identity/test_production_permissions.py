"""Disposable filesystem/fault tests. Never sign, launchctl, or call permission APIs."""
import json
import os
from pathlib import Path
import plistlib
import struct
import tempfile
import unittest
from unittest.mock import patch

import verify_production_permissions as h


def macho():
    header = struct.pack('<8I', 0xFEEDFACF, 0x0100000C, 0, 2, 1, 16, 0, 0)
    return header + struct.pack('<4I', 0x1D, 16, 48, 16) + b'S' * 16


class FakeLive:
    def __init__(self, error=None):
        self.error, self.events = error, []

    def absent(self, target):
        self.events.append('absent')
        return True

    def bootstrap(self, target, root):
        self.events.append('bootstrap')
        assert (root / 'bootstrap-intent.json').exists()
        assert (root / 'swap-receipt.json').exists()
        if self.error == 'bootstrap':
            raise OSError('fixture partial bootstrap')
        result = dict(event='permission', name='Camera', status='denied', allowed=False,
                      requested=False, error_type=None)
        (root / 'agent.out').write_text('\n'.join(json.dumps(r) for r in [
            dict(event='worker-ready', pid=999999, ppid=999998, pgid=999997, nonce='fixture'),
            dict(event='worker-complete', exit_code=0, results=[result]),
            dict(event='service-exit', status=0)]))

    def identity(self, root, p):
        if self.error == 'identity':
            raise ValueError('fixture wrong identity')
        return True

    def exited(self, p):
        return {'exit_code': 0}

    def cleanup(self, target, root):
        self.events.append('cleanup')
        if self.error == 'cleanup':
            raise ValueError('fixture unknown tree')
        return True


class PermissionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='permission-unit-')
        self.addCleanup(self.temp.cleanup)
        self.top = Path(self.temp.name).resolve()
        self.home = self.top / 'home'
        self.home.mkdir(mode=0o700)
        (self.home / '.hermes/experiments').mkdir(parents=True, mode=0o700)
        (self.home / 'Applications').mkdir(mode=0o700)
        self.base = self.top / 'maintenance'
        self.base.mkdir(mode=0o700)
        (self.base / 'control.lock').touch(mode=0o600)
        self.app = self.home / 'Applications/Verity.app'
        (self.app / 'Contents/MacOS').mkdir(parents=True, mode=0o700)
        (self.app / 'Contents/Resources').mkdir(mode=0o700)
        (self.app / h.BINARY).write_bytes(macho())
        (self.app / h.BINARY).chmod(0o700)
        _, stage = h.helpers()
        (self.app / 'Contents/Info.plist').write_bytes(plistlib.dumps(stage.production_info_plist()))
        (self.app / h.SETTINGS).write_text('{"production":true}')
        self.python_home = self.top / 'runtime'
        (self.python_home / 'bin').mkdir(parents=True, mode=0o700)
        self.python = self.python_home / 'bin/python3.11'
        self.python.write_bytes(b'non-executable fixture bytes; never execute')
        self.python.chmod(0o700)
        self.bridge = self.top / 'bridge'
        self.bridge.mkdir(mode=0o700)
        self.root = self.home / '.hermes/experiments/new-permissions'
        self.before = h.tree(self.app)
        self.calls = []
        self.baseline_patch = patch.object(h, 'baseline', return_value=({}, {}))
        self.baseline_patch.start()
        self.addCleanup(self.baseline_patch.stop)
        # A global tripwire catches accidental subprocess/signing/permission work.
        self.process_patch = patch.object(h.subprocess, 'run', side_effect=AssertionError('offline subprocess'))
        self.process_patch.start()
        self.addCleanup(self.process_patch.stop)

    def runner(self, args, **kwargs):
        self.calls.append(args)
        self.assertEqual(args[0], '/usr/bin/codesign')
        self.assertTrue('--verify' in args or '--sign' in args)

    def prepare(self, **kwargs):
        return h.prepare(self.root, self.base, self.home, self.python, self.bridge,
                         'Camera', 'permissions-check', python_home=self.python_home,
                         approve_sign=True, runner=self.runner, **kwargs)

    def run_harness(self, adapter=None):
        return h.run(self.root, live=True, runner=self.runner, adapter=adapter or FakeLive(),
                     dependency=lambda *_: True)

    def recover(self):
        return h.recover(self.root, live=True, runner=self.runner, adapter=FakeLive(),
                         dependency=lambda *_: True)

    def test_prepare_is_only_staging_and_child_is_independent(self):
        self.prepare()
        self.assertEqual(h.tree(self.app), self.before)
        h.preflight(self.root, self.runner)
        self.assertFalse((self.root / 'GO').exists())
        self.assertFalse((self.root / 'permission-python').is_symlink())
        self.assertNotEqual((self.root / 'permission-python').stat().st_ino, self.python.stat().st_ino)
        source = (self.root / 'production_launcher.py').read_text()
        compile(source, 'sealed-launcher', 'exec')
        for forbidden in ('restart_production', 'AXFocusedApplication', 'AXUIElementCreateSystemWide',
                          'network_control', "'.env'", 'startUpdatingLocation', 'scanForPeripherals'):
            self.assertNotIn(forbidden, source)
        settings = json.loads((self.root / 'Verity.app' / h.SETTINGS).read_text())
        self.assertNotIn('bootstrap_environment', settings)
        self.assertEqual(settings['base'], str(self.root))
        self.assertIn("PYTHONHOME=config['python_home']", source)
        self.assertIn("'-S', '-s', '-P', '-u'", source)

    def test_live_opt_in_precedes_reads(self):
        with self.assertRaisesRegex(ValueError, '--live'):
            h.run(self.root)
        with self.assertRaisesRegex(ValueError, '--live'):
            h.recover(self.root)
        with self.assertRaisesRegex(ValueError, '--approve-sign'):
            h.prepare(self.root, self.base, self.home, self.python, self.bridge, 'Camera', 'permissions-check')
        self.assertFalse(self.root.exists())

    def test_success_exact_restore_and_permission_denial_is_completed(self):
        self.prepare()
        adapter = FakeLive()
        result = self.run_harness(adapter)
        self.assertEqual(result['status'], 'completed')
        self.assertFalse(result['results'][0]['allowed'])
        self.assertTrue(result['restored'] and result['cleanup_verified'])
        self.assertEqual(result['worker_exit'], 0)
        self.assertEqual(h.tree(self.app), self.before)
        self.assertTrue((self.root / 'retired.app').exists())
        self.assertEqual(adapter.events, ['absent', 'bootstrap', 'cleanup'])
        self.assertEqual(self.recover()['status'], 'restored')

    def test_unknown_dependency_refuses_before_swap(self):
        self.prepare()
        with self.assertRaisesRegex(ValueError, 'dependency'):
            h.run(self.root, live=True, runner=self.runner, adapter=FakeLive(), dependency=lambda *_: None)
        self.assertFalse((self.root / 'swap-receipt.json').exists())
        self.assertEqual(h.tree(self.app), self.before)

    def test_missing_lock_refused_without_creation(self):
        self.prepare()
        (self.base / 'control.lock').unlink()
        with self.assertRaises(Exception):
            self.run_harness()
        self.assertFalse((self.base / 'control.lock').exists())
        self.assertFalse((self.root / 'swap-receipt.json').exists())

    def test_copy_failure_retains_evidence_and_original(self):
        install, _ = h.helpers()
        copy = install.copy_tree
        def failed(source, destination, **kwargs):
            copy(source, destination, **kwargs)
            raise OSError('after copy')
        with patch.object(install, 'copy_tree', side_effect=failed):
            with self.assertRaises(OSError):
                self.prepare()
        self.assertEqual(h.tree(self.app), self.before)
        self.assertTrue((self.root / 'prepare-start.json').exists())
        self.assertFalse((self.root / 'prepared.json').exists())

    def test_swap_rename_after_success_failure_restores(self):
        for index in (1, 2):
            with self.subTest(index=index):
                fixture = PermissionTests()
                fixture.setUp()
                try:
                    fixture.prepare()
                    move, count = h.move, [0]
                    def failed(source, destination):
                        move(source, destination)
                        count[0] += 1
                        if count[0] == index:
                            raise OSError('rename succeeded then fsync failed')
                    with patch.object(h, 'move', side_effect=failed):
                        result = fixture.run_harness()
                    self.assertTrue(result['restored'])
                    self.assertEqual(result['status'], 'failed')
                    self.assertEqual(h.tree(fixture.app), fixture.before)
                finally:
                    fixture.doCleanups()

    def test_bootstrap_and_identity_failure_cleanup_before_restore(self):
        for boundary in ('bootstrap', 'identity'):
            with self.subTest(boundary=boundary):
                fixture = PermissionTests()
                fixture.setUp()
                try:
                    fixture.prepare()
                    adapter = FakeLive(boundary)
                    result = fixture.run_harness(adapter)
                    self.assertEqual(result['status'], 'failed')
                    self.assertTrue(result['restored'])
                    self.assertIn('cleanup', adapter.events)
                    self.assertEqual(h.tree(fixture.app), fixture.before)
                finally:
                    fixture.doCleanups()

    def test_cleanup_failure_retains_original_then_explicit_recovery(self):
        self.prepare()
        result = self.run_harness(FakeLive('cleanup'))
        self.assertFalse(result['restored'])
        self.assertFalse(result['cleanup_verified'])
        self.assertTrue((self.root / 'original.app').exists())
        self.assertEqual(self.recover()['status'], 'restored')
        self.assertEqual(h.tree(self.app), self.before)

    def test_report_failure_happens_after_restore(self):
        self.prepare()
        durable = h.durable
        def failed(root, name, value):
            if name == 'result.json':
                raise OSError('report write blocked')
            return durable(root, name, value)
        with patch.object(h, 'durable', side_effect=failed):
            with self.assertRaises(OSError):
                self.run_harness()
        self.assertEqual(h.tree(self.app), self.before)
        self.assertTrue((self.root / 'swap-receipt.json').exists())
        self.assertEqual(self.recover()['status'], 'restored')

    def test_receipt_failure_never_moves_original(self):
        self.prepare()
        with patch.object(h, 'durable', side_effect=OSError('before receipt')):
            with self.assertRaises(OSError):
                self.run_harness()
        self.assertEqual(h.tree(self.app), self.before)
        self.assertFalse((self.root / 'original.app').exists())

    def test_finalpath_verify_failure_restores(self):
        self.prepare()
        verifier, called = h.verify_signature, [False]
        def failed(app, runner=None):
            if app == self.app and (self.root / 'original.app').exists() and not called[0]:
                called[0] = True
                raise ValueError('bad temporary signature')
            return verifier(app, runner)
        with patch.object(h, 'verify_signature', side_effect=failed):
            result = self.run_harness()
        self.assertTrue(result['restored'])
        self.assertEqual(result['status'], 'failed')

    def test_existing_destinations_and_signed_settings_drift_refused(self):
        self.prepare()
        (self.root / 'GO').write_text('unexpected')
        with self.assertRaises(ValueError):
            self.run_harness()
        self.assertEqual(h.tree(self.app), self.before)
        (self.root / 'Verity.app' / h.SETTINGS).write_text('{"base":"/real"}')
        with self.assertRaises(ValueError):
            h.preflight(self.root, self.runner)

    def test_completed_scalar_protocol_not_requesting_only(self):
        r = dict(event='permission', name='Camera', status='requesting', allowed=None,
                 requested=True, error_type=None)
        with self.assertRaisesRegex(ValueError, 'No completed'):
            h.sanitize([r], 'Camera')
        r['status'] = 'secret unexpected value'
        with self.assertRaises(ValueError):
            h.sanitize([r], 'Camera')
        r['status'] = 'authorized'
        self.assertEqual(h.sanitize([r], 'Camera'), [r])
        r['status'] = {'private': 'object'}
        with self.assertRaises((ValueError, TypeError)):
            h.sanitize([r], 'Camera')

    def test_default_dependency_checker_is_used_before_and_after(self):
        self.prepare()
        install, _ = h.helpers()
        with patch.object(install, 'no_live_native_dependency', return_value=True) as dependency:
            result = h.run(self.root, live=True, runner=self.runner, adapter=FakeLive())
        self.assertTrue(result['restored'])
        self.assertGreaterEqual(dependency.call_count, 3)
        for call in dependency.call_args_list:
            self.assertEqual(call.args, (self.base, {}))

    def test_missing_process_receipts_cannot_claim_cleanup(self):
        self.prepare()
        self.assertFalse(h.process_tree_gone(self.root))

    def test_unknown_worker_and_existing_prepare_root_refused(self):
        with self.assertRaises(ValueError):
            h.prepare(self.root, self.base, self.home, self.python, self.bridge,
                      'arbitrary', 'permissions-check', python_home=self.python_home,
                      approve_sign=True, runner=self.runner)
        self.assertFalse(self.root.exists())
        self.prepare()
        with self.assertRaises(ValueError):
            self.prepare()

    def test_bare_worker_cannot_replay_an_old_go_receipt(self):
        import contextlib
        import io
        import sys
        plan = self.prepare()
        config = dict(plan['config'], abi=list(sys.version_info[:2]))
        (self.root / 'GO').write_text('{}')
        with patch.object(sys, 'argv', ['fixture', '--worker']), patch.dict(os.environ, {
            'HOME': str(self.root / 'home'), 'HERMES_HOME': str(self.root / 'state')
        }), contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaisesRegex(ValueError, 'Gate is not for this live worker'):
                h.worker(config)

    def test_interrupt_is_failure_with_ordinary_restoration(self):
        self.prepare()
        adapter = FakeLive()
        with patch.object(adapter, 'identity', side_effect=KeyboardInterrupt()):
            result = self.run_harness(adapter)
        self.assertEqual(result['error_type'], 'KeyboardInterrupt')
        self.assertTrue(result['restored'])
        self.assertEqual(h.tree(self.app), self.before)

    def test_code_payload_only_signature_may_change(self):
        a = macho()
        self.assertEqual(h.code_payload(a), h.code_payload(a[:-16] + b'T' * 16))
        self.assertNotEqual(h.code_payload(a), h.code_payload(a[:8] + b'X' + a[9:]))


if __name__ == '__main__':
    unittest.main()
