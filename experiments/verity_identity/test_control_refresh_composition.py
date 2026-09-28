"""Real split-deployment lifecycle; OS/signature observations are fixture adapters.

The parent replay can set OLD_CONTROL_SOURCE to a frozen copy of actual installed
v1. Default repository controls exercise their retained schema-1 route. No test
executes applications, native binaries, or service-manager commands.
"""
import base64
import importlib.util
import json
import os
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

import install_production_native as install
import stage_production_native as stage
import refresh_production_controls as refresh
from test_upgrade_return_composition import ServiceFixture
from test_restart_control import Clock, FakeHost

OLD_CONTROL_SOURCE = stage.CONTROL


class ControlRefreshCompositionTests(unittest.TestCase):
    def load_bundle(self, version):
        modules = {}
        for name in ('production_launcher', 'restart_production', 'native_identity',
                     'control_refresh', 'watchdog', 'approved_restart_job'):
            path = version / (name + '.py')
            if not path.exists():
                continue
            spec = importlib.util.spec_from_file_location(name, path)
            module = importlib.util.module_from_spec(spec)
            with patch.dict(sys.modules, modules), patch.object(sys, 'dont_write_bytecode', True):
                spec.loader.exec_module(module)
            self.assertEqual(Path(module.__file__), path)
            modules[name] = module
        return modules

    def setUp(self):
        f = self.f = ServiceFixture()
        # First installation genuinely contains the old control implementation.
        with patch.object(stage, 'CONTROL', OLD_CONTROL_SOURCE):
            f.setUp()
            self.addCleanup(f.doCleanups)
            f.go()
        self.root_raw = (f.base / install.RECEIPT).read_bytes()
        self.root_pin = stage.digest(self.root_raw)
        self.v1 = f.base / 'control-versions/native-v1'
        self.old = self.load_bundle(self.v1)  # Before the refresh/fence exists.
        self.old_controller = self.old['restart_production'].Controller(f.base, owner=lambda: 1)
        self.clock = Clock()
        self.plists = {r: Path(f.manifest['services'][r]['plist_path']) for r in stage.ROLES}
        self.host = FakeHost(self)
        self.host.service = lambda target: target.rsplit('.', 1)[-1]
        self.host.verify_native_signature = lambda *_: True
        self.host.verify_native_bundle = lambda *_: True
        self.host.process_identity = self.process_identity
        self.host.listener = lambda _: {self.host.jobs['webui']['pid'] + int(self.native_job('webui'))}
        self.native_path = f.root / 'stage/candidate-release.json'
        self.native = json.loads(self.native_path.read_bytes())
        home = patch.dict(os.environ, HOME=str(f.home), HERMES_HOME=str(f.root / 'state'),
                          HERMES_WEBUI_STATE_DIR=str(f.root / 'webui-state'))
        home.start()
        self.addCleanup(home.stop)
        self.write_gateway(101)
        # Real legacy restart produces an actual terminal transaction to retain.
        legacy = stage.Controller(f.base, self.host, stage.Controller(f.base).preflight_fn,
            self.clock, self.clock, self.clock.sleep, owner=lambda: 1, timeout=5, stable_seconds=1)
        self.assertEqual(legacy.restart(yes=True)['status'], 'verified')
        self.original_transaction = legacy.transaction_path.read_bytes()
        self.original_wrappers = {n: install.snapshot(f.base / n) for n in
                                  ('restart_production.py','watchdog.py','approved_restart_job.py')}
        app = f.home / 'Applications/Verity.app'
        launcher = f.base / 'production_launcher.py'
        self.unchanged_artifacts = {p: install.tree(p) for p in (app, self.v1)}
        self.unchanged_identities = {p: (p.stat().st_dev, p.stat().st_ino) for p in (app, launcher)}
        self.launcher = install.snapshot(launcher)
        self.fresh = f.root / 'refresh-stage'
        # Refresh preparation must never use the first-install signature/compiler adapter.
        with patch.object(stage, 'run', side_effect=AssertionError('native call during refresh')):
            report = refresh.stage(self.fresh, f.base, f.home, original_stage=f.root / 'stage',
                root_sha256=self.root_pin, version_name='fenced-v2')
        self.version = Path(report['version'])
        self.stage_pin = stage.digest((self.fresh / 'control-refresh-stage.json').read_bytes())
        if getattr(self, 'prepare_only', False):
            return
        refresh.install(self.fresh, f.base, f.home, stage_sha256=self.stage_pin,
                        root_sha256=self.root_pin, approve=True)
        self.refresh_raw = (f.base / 'native-control-refresh-receipt.json').read_bytes()
        self.refresh_pin = stage.digest(self.refresh_raw)
        self.modules = self.load_bundle(self.version)
        scope = patch.dict(sys.modules, self.modules)
        scope.start()
        self.addCleanup(scope.stop)
        self.module = self.modules['restart_production']
        self.c = self.new_controller()
        self.assert_artifacts_unchanged()

    def new_controller(self):
        return self.module.Controller(self.f.base, self.host, self.modules['production_launcher'].preflight,
            self.clock, self.clock, self.clock.sleep, owner=lambda: 1, timeout=5, stable_seconds=1,
            control_refresh_sha256=self.refresh_pin)

    def native_job(self, role):
        return self.host.jobs[role]['argv'] == [self.native['native_host']['executable'], role]

    def process_identity(self, pid):
        for role, job in self.host.jobs.items():
            native = self.native_job(role)
            count = 3 if native and role == 'agent' else 2
            if pid not in range(job['pid'], job['pid'] + count):
                continue
            delta = pid - job['pid']
            if native and delta == 0:
                argv, parent = job['argv'], 1
            elif native and role == 'agent' and delta == 2:
                command = self.native['services']['agent']['argv']
                argv, parent = command[6:], job['pid'] + 1
            elif native:
                argv, parent = self.native['services'][role]['argv'], job['pid']
            elif delta == 0:
                argv, parent = self.native['services'][role]['argv'], 1
            else:
                argv, parent = self.native['services'][role]['argv'][6:], job['pid']
            return dict(pid=pid, ppid=parent, uid=os.getuid(), executable=str(Path(argv[0]).resolve()),
                        argv=argv, start_time=self.host.started)
        raise AssertionError('Unexpected fixture PID')

    def write_gateway(self, pid):
        manifest = json.loads(self.f.selected.read_bytes())
        if self.native_job('agent'):
            pid += 1  # host -> timestamp wrapper -> actual gateway
        state = Path(manifest['state_dir'])
        state.mkdir(exist_ok=True)
        install.save_json(state / 'gateway_state.json', dict(pid=pid, gateway_state='running',
            code_sha=manifest['services']['agent']['commit'], updated_at=self.clock()))

    def assert_artifacts_unchanged(self):
        self.assertEqual((self.f.base / install.RECEIPT).read_bytes(), self.root_raw)
        for path, expected in self.unchanged_artifacts.items():
            self.assertEqual(install.tree(path), expected)
        for path, expected in self.unchanged_identities.items():
            self.assertEqual((path.stat().st_dev, path.stat().st_ino), expected)
        self.assertEqual(install.snapshot(self.f.base / 'production_launcher.py'), self.launcher)

    def assert_old_fenced(self):
        raw = self.c.transaction_path.read_bytes()
        calls = list(self.host.calls)
        old = self.old['restart_production']
        with patch.dict(sys.modules, self.old):
            self.old_controller.host = self.host
            with self.assertRaisesRegex(old.ControlError, 'Unsupported transaction schema'):
                self.old_controller.restart(yes=True)
            with old.control_lock(self.f.base):
                with self.assertRaisesRegex(old.ControlError, 'Unsupported transaction schema'):
                    self.old_controller.recover_locked()
            result = self.old['watchdog'].tick(self.old_controller)
            self.assertEqual(result['status'], 'blocked')
            self.assertIn('Unsupported transaction schema', result['error'])
            # This module and its imported restart main were retained before refresh.
            with patch.object(old, 'Controller', return_value=self.old_controller):
                with self.assertRaisesRegex(old.ControlError, 'Unsupported transaction schema'):
                    self.old['approved_restart_job'].main([
                        '--base', str(self.f.base), '--restart', '--reload', '--yes'], owner=lambda: 1)
        self.assertEqual(self.c.transaction_path.read_bytes(), raw)
        self.assertEqual(self.host.calls, calls)

    def activate(self):
        result = self.c.restart(candidate=self.native_path, reload=True, yes=True)
        self.assertEqual(result['status'], 'verified')
        proof = result['process_identity']['agent']
        self.assertIn('wrapper', proof)
        self.assertEqual(proof['child']['ppid'], proof['wrapper']['pid'])
        self.assertEqual(proof['wrapper']['ppid'], proof['host']['pid'])
        return result

    def return_exact(self):
        return self.c.restart(reload=True, yes=True, return_baseline=self.root_pin,
                              return_control_refresh_sha256=self.refresh_pin)

    def restore(self):
        return refresh.restore(self.fresh, self.f.base, self.f.home, stage_sha256=self.stage_pin,
            root_sha256=self.root_pin, refresh_sha256=self.refresh_pin, approve=True,
            dependency_check=lambda *_: True)

    def test_real_refresh_activation_exact_return_and_restore(self):
        self.f.preserved()
        self.assert_old_fenced()
        self.activate()
        native_bytes = self.f.selected.read_bytes()
        self.assert_old_fenced()
        with self.assertRaises(Exception):
            self.restore()
        self.assertEqual(self.return_exact()['status'], 'verified')
        txn = self.c.read_transaction()
        self.assertEqual(txn['baseline_sha256'], self.root_pin)
        self.assertEqual(txn['control_refresh_sha256'], self.refresh_pin)
        self.assertEqual(base64.b64decode(txn['manifest']), native_bytes)
        self.f.preserved()
        self.assert_old_fenced()
        self.restore()
        self.assertEqual(self.c.transaction_path.read_bytes(), self.original_transaction)
        for name, record in self.original_wrappers.items():
            self.assertEqual(install.snapshot(self.f.base / name), record)
        self.assertEqual((self.f.base / 'native-control-refresh-receipt.json').read_bytes(), self.refresh_raw)
        self.assert_artifacts_unchanged()
        calls = list(self.host.calls)
        # A retained v2 object must not revive after undo made schema1 visible.
        with self.assertRaises(Exception):
            self.c.restart(yes=True)
        self.assertEqual(self.host.calls, calls)
        self.restore()  # explicit idempotent post-return restoration
        self.assertEqual(self.c.transaction_path.read_bytes(), self.original_transaction)

    def test_existing_lock_orders_old_restart_and_refresh(self):
        f = ControlRefreshCompositionTests()
        f.prepare_only = True
        f.setUp()
        self.addCleanup(f.doCleanups)
        old = f.old['restart_production']
        calls = list(f.host.calls)
        kwargs = dict(stage_sha256=f.stage_pin, root_sha256=f.root_pin, approve=True)
        # An admitted old consumer owns the inode. Refresh must refuse immediately.
        with old.control_lock(f.f.base):
            with self.assertRaisesRegex(Exception, 'owns control.lock'):
                refresh.install(f.fresh, f.f.base, f.f.home, **kwargs)
            self.assertFalse((f.f.base / refresh.JOURNAL).exists())
            self.assertEqual((f.f.base / refresh.TRANSACTION).read_bytes(), f.original_transaction)
        self.assertEqual(f.host.calls, calls)
        with patch.dict(sys.modules, f.old):
            retained = old.Controller(f.f.base, f.host, f.old['production_launcher'].preflight,
                f.clock, f.clock, f.clock.sleep, owner=lambda: 1, timeout=5, stable_seconds=1)
            self.assertEqual(retained.restart(yes=True)['status'], 'verified')
            latest = retained.transaction_path.read_bytes()
            result = refresh.install(f.fresh, f.f.base, f.f.home, **kwargs)
            self.assertEqual(result['status'], 'installed')
            receipt = json.loads((f.f.base / refresh.RECEIPT).read_bytes())
            self.assertEqual(base64.b64decode(receipt['original_transaction']['data']), latest)
            calls = list(f.host.calls)
            fenced = retained.transaction_path.read_bytes()
            with self.assertRaisesRegex(old.ControlError, 'Unsupported transaction schema'):
                retained.restart(yes=True)
            self.assertEqual(f.host.calls, calls)
            self.assertEqual(retained.transaction_path.read_bytes(), fenced)
        f.assert_artifacts_unchanged()

    def test_interrupted_native_fallback_is_fenced_and_recovers_once(self):
        class PowerLoss(BaseException):
            pass
        self.activate()
        native_bytes = self.f.selected.read_bytes()
        native_plists = {s: p.read_bytes() for s,p in self.plists.items()}
        real_write = self.module.atomic_write
        hit = []
        def interrupt(path, data):
            real_write(path, data)
            if Path(path) == self.f.selected and not hit:
                hit.append(True)
                raise PowerLoss()
        with patch.object(self.module, 'atomic_write', side_effect=interrupt):
            with self.assertRaises(PowerLoss):
                self.return_exact()
        self.assertEqual(hit, [True])
        self.assertEqual(self.c.read_transaction()['phase'], 'prepared')
        self.assertEqual(base64.b64decode(self.c.read_transaction()['manifest']), native_bytes)
        self.assert_old_fenced()
        self.c = self.new_controller()
        with self.module.control_lock(self.f.base):
            self.assertEqual(self.c.recover_locked()['status'], 'rolled_back')
        self.assertEqual(self.f.selected.read_bytes(), native_bytes)
        self.assertEqual({s:p.read_bytes() for s,p in self.plists.items()}, native_plists)
        self.assertEqual(json.loads(self.c.transaction_path.read_bytes())['schema_version'], 2)
        self.assert_old_fenced()
        calls = list(self.host.calls)
        with self.module.control_lock(self.f.base):
            self.assertIsNone(self.c.recover_locked())
        self.assertEqual(self.host.calls, calls)
        self.assert_artifacts_unchanged()


if __name__ == '__main__':
    unittest.main()
