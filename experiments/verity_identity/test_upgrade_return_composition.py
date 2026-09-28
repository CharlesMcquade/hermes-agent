"""Real install/stage/upgrade/controller/return/restore composition, fixture OS only."""
import base64
import importlib.util
import inspect
import json
import os
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

import install_production_native as install
import stage_production_native as stage
import test_install_production_native as installing
from test_restart_control import Clock, FakeHost


class ServiceFixture(unittest.TestCase):
    setUp = installing.InstallTests.setUp
    save = installing.InstallTests.save
    runner = installing.InstallTests.runner
    go = installing.InstallTests.go
    verifier = installing.InstallTests.verifier
    preserved = installing.InstallTests.preserved

    def stage(self, **changes):
        # Real frozen runtime/source validation and served asset hashes, no app imports.
        source = Path(self.manifest['services']['webui']['repo'])
        (source / 'static').mkdir(exist_ok=True)
        for name in ('boot.js', 'ui.js', 'panels.js', 'embed-host.js', 'i18n.js'):
            (source / 'static' / name).write_bytes(b'asset')
        self.manifest['services']['webui']['inventory'] = stage.inventory(source)
        self.save()
        return installing.InstallTests.stage(self, **changes)


class UpgradeReturnTests(unittest.TestCase):
    def setUp(self):
        f = self.f = ServiceFixture()
        f.setUp()
        self.addCleanup(f.doCleanups)
        f.go()
        self.root_raw = (f.base / install.RECEIPT).read_bytes()
        self.root_pin = stage.digest(self.root_raw)
        self.fresh = f.root / 'fresh-stage'
        f.stage(root=self.fresh, control_id='native-v2', runner=self.native_fixture)
        install.upgrade(self.fresh, f.base, f.home, original_stage=f.root / 'stage',
                        root_sha256=self.root_pin, approve=True, runner=self.native_fixture,
                        dependency_check=lambda *_: True)
        self.upgrade_raw = (f.base / install.UPGRADE_RECEIPT).read_bytes()
        self.upgrade_pin = stage.digest(self.upgrade_raw)
        self.version = f.base / 'control-versions/native-v2'
        self.module = self.load_controller(self.version)
        modules = {'restart_production': self.module}
        # Real bundle-local imports, matching the installed wrapper's sys.path.
        scope = patch.dict(sys.modules, modules)
        scope.start()
        self.addCleanup(scope.stop)
        for name in ('native_identity', 'production_launcher', 'watchdog', 'approved_restart_job'):
            spec = importlib.util.spec_from_file_location(name, self.version / (name + '.py'))
            module = importlib.util.module_from_spec(spec)
            with patch.object(sys, 'dont_write_bytecode', True):
                spec.loader.exec_module(module)
            sys.modules[name] = module
        home = patch.dict(os.environ, HOME=str(f.home), HERMES_HOME=str(f.root / 'state'),
                          HERMES_WEBUI_STATE_DIR=str(f.root / 'webui-state'))
        home.start()
        self.addCleanup(home.stop)
        self.clock = Clock()
        self.plists = {s: Path(f.manifest['services'][s]['plist_path']) for s in stage.ROLES}
        self.host = FakeHost(self)
        self.host.service = lambda target: target.rsplit('.', 1)[-1]
        self.host.verify_native_signature = lambda *_: True
        self.host.verify_native_bundle = lambda *_: True
        self.host.process_identity = self.process_identity
        self.host.listener = lambda _: {self.host.jobs['webui']['pid'] + int(self.native_job('webui'))}
        self.native = json.loads((self.fresh / 'candidate-release.json').read_bytes())
        import production_launcher
        self.c = self.module.Controller(f.base, self.host, production_launcher.preflight,
            self.clock, self.clock, self.clock.sleep, owner=lambda: 1, timeout=5, stable_seconds=1)
        self.write_gateway(101)
        self.assertEqual(self.c.restart(candidate=self.fresh / 'candidate-release.json',
                                       reload=True, yes=True)['status'], 'verified')
        # Semantically identical, noncanonical current bytes must remain a valid fallback.
        self.c.manifest_path.write_bytes(b'\n' + self.c.manifest_path.read_bytes())
        self.current = self.selection()
        self.artifacts = {p: install.tree(p) for p in (self.version,
            f.base / 'control-versions/native-v1', f.home / 'Applications/Verity.app',
            f.home / 'Applications/Verity.upgrade-v1.app')}

    def load_controller(self, version):
        spec = importlib.util.spec_from_file_location('actual_installed_return', version / 'restart_production.py')
        module = importlib.util.module_from_spec(spec)
        with patch.object(sys, 'dont_write_bytecode', True):
            spec.loader.exec_module(module)
        self.assertEqual(Path(module.__file__), version / 'restart_production.py')
        return module

    def native_fixture(self, argv, **kwargs):
        self.assertIn(argv[0], ('/usr/bin/xcrun', '/usr/bin/codesign'))
        self.assertTrue(Path(argv[-1]).is_relative_to(self.f.root))
        if argv[0] == '/usr/bin/xcrun':
            Path(argv[-1]).write_bytes(b'fixture compiler output, not native code')
            Path(argv[-1]).chmod(0o700)

    def native_job(self, role):
        return self.host.jobs[role]['argv'] == [self.native['native_host']['executable'], role]

    def process_identity(self, pid):
        for role, job in self.host.jobs.items():
            if pid in (job['pid'], job['pid'] + 1):
                child = pid != job['pid']
                argv = self.native['services'][role]['argv'] if child else job['argv']
                return dict(pid=pid, ppid=job['pid'] if child else 1, uid=os.getuid(),
                            executable=str(Path(argv[0]).resolve()), argv=argv, start_time=self.host.started)
        raise AssertionError('Unexpected fixture PID')

    def write_gateway(self, pid):
        manifest = json.loads(self.f.selected.read_bytes())
        state = Path(manifest['state_dir'])
        state.mkdir(exist_ok=True)
        install.save_json(state / 'gateway_state.json', dict(pid=pid, gateway_state='running',
            code_sha=manifest['services']['agent']['commit'], updated_at=self.clock()))

    def selection(self):
        return self.f.selected.read_bytes(), {s: p.read_bytes() for s, p in self.plists.items()}

    def return_exact(self):
        kwargs = dict(reload=True, yes=True, return_baseline=self.root_pin)
        # The old implementation's meaningful refusal, not a missing-keyword TypeError.
        if 'return_upgrade_sha256' in inspect.signature(self.c.restart).parameters:
            kwargs['return_upgrade_sha256'] = self.upgrade_pin
        try:
            return self.c.restart(**kwargs)
        except self.module.ControlError as exc:
            if 'return_upgrade_sha256' not in kwargs:
                self.fail('actual v2 controller cannot return retained baseline: ' + str(exc))
            raise

    def restore(self):
        return install.restore_upgraded_wrappers(self.f.base, self.f.home,
            root_sha256=self.root_pin, upgrade_sha256=self.upgrade_pin, approve=True,
            runner=self.native_fixture, dependency_check=lambda *_: True)

    def test_real_upgraded_return_then_exact_wrapper_restore(self):
        with self.assertRaisesRegex(self.module.ControlError, 'Wrong installed control identity'):
            self.c.restart(reload=True, yes=True, return_baseline=self.root_pin)
        with self.assertRaises(RuntimeError):
            self.restore()
        self.assertEqual(self.return_exact()['status'], 'verified')
        txn = self.c.read_transaction()
        self.assertEqual(txn['baseline_sha256'], self.root_pin)
        self.assertEqual(txn['upgrade_sha256'], self.upgrade_pin)
        self.assertEqual(base64.b64decode(txn['manifest']), self.current[0])
        self.assertEqual({s: base64.b64decode(b) for s, b in txn['plists'].items()}, self.current[1])
        self.f.preserved()
        transaction = self.c.transaction_path.read_bytes()
        self.restore()
        self.assertEqual(self.c.transaction_path.read_bytes(), transaction)
        self.assertEqual((self.f.base / install.RECEIPT).read_bytes(), self.root_raw)
        self.assertEqual((self.f.base / install.UPGRADE_RECEIPT).read_bytes(), self.upgrade_raw)
        for name, record in self.f.originals.items():
            self.assertEqual(install.snapshot(self.f.base / name), record)
        for path, tree in self.artifacts.items():
            self.assertEqual(install.tree(path), tree)
        self.c.snapshot(self.c.load(), self.c.definitions(self.c.load()))


    def test_hostile_provenance_and_boundary_mutations_never_publish(self):
        cases = ('pin', 'pin-format', 'root-pin', 'checksum', 'phase', 'root-lineage',
                 'original-report', 'new-version', 'new-home', 'stage-hash', 'stage-alias',
                 'candidate-hash', 'rollback', 'tree-path', 'retained-inode', 'control',
                 'extra-control', 'wrapper', 'current', 'mode', 'symlink', 'pending',
                 'missing-stage', 'wrong-executor', 'v1-executor', 'unsafe-ancestor',
                 'preflight:receipt', 'journal:receipt', 'prepared:receipt',
                 'preflight:control', 'journal:wrapper', 'prepared:app',
                 'prepared:extra', 'prepared:retained', 'prepared:stage')
        for case in cases:
            with self.subTest(case=case):
                if case != cases[0]:
                    self.doCleanups()
                    self.setUp()
                path = self.f.base / install.UPGRADE_RECEIPT
                envelope = json.loads(path.read_bytes())
                payload, plan = envelope['payload'], envelope['payload']['plan']
                if case == 'pin':
                    self.upgrade_pin = '0' * 64
                elif case == 'pin-format':
                    self.upgrade_pin = self.upgrade_pin.upper()
                elif case == 'root-pin':
                    self.root_pin = '0' * 64
                elif case == 'phase':
                    payload['phase'] = 'recover_wrappers'
                elif case == 'root-lineage':
                    plan['root_sha256'] = '0' * 64
                elif case == 'original-report':
                    plan['original_report']['candidate_sha256'] = '0' * 64
                elif case == 'new-version':
                    plan['new_report']['final_control_version'] = str(self.version.parent / '../native-v2')
                elif case == 'new-home':
                    plan['new_report']['final_bundle'] = str(self.f.root / 'other.app')
                elif case == 'stage-hash':
                    plan['new_stage_sha256'] = '0' * 64
                elif case == 'stage-alias':
                    alias = self.f.root / 'stage-alias'
                    alias.symlink_to(self.fresh, target_is_directory=True)
                    plan['new_stage'] = str(alias)
                elif case == 'candidate-hash':
                    plan['new_report']['candidate_sha256'] = '0' * 64
                elif case == 'rollback':
                    plan['new_report']['rollback_sha256'] = plan['original_report']['rollback_sha256']
                elif case == 'tree-path':
                    plan['v2_tree']['../escape'] = plan['v2_tree']['.']
                elif case == 'retained-inode':
                    plan['v1_identity'][1] += 1
                elif case == 'control':
                    target = self.version / 'watchdog.py'
                    target.chmod(0o644)
                    target.write_bytes(target.read_bytes() + b'\n')
                    target.chmod(0o444)
                elif case == 'extra-control':
                    self.version.chmod(0o755)
                    (self.version / 'extra.py').write_bytes(b'extra')
                    self.version.chmod(0o555)
                elif case == 'wrapper':
                    (self.f.base / 'watchdog.py').write_bytes(b'foreign wrapper')
                elif case == 'current':
                    candidate = json.loads(self.f.selected.read_bytes())
                    candidate['release_id'] = 'foreign'
                    self.f.selected.write_bytes(stage.encoded(candidate))
                elif case == 'mode':
                    path.chmod(0o644)
                elif case == 'symlink':
                    target = path.with_name('receipt-copy')
                    path.rename(target)
                    path.symlink_to(target)
                elif case == 'pending':
                    self.c.save_transaction(self.c.read_transaction(), 'prepared')
                elif case == 'missing-stage':
                    (self.fresh / 'stage-report.json').unlink()
                elif case in ('wrong-executor', 'v1-executor'):
                    directory = self.f.base / 'control-versions/native-v1'
                    if case == 'wrong-executor':
                        directory = self.f.root / 'checkout-copy'
                        directory.mkdir()
                        (directory / 'restart_production.py').write_bytes((self.version / 'restart_production.py').read_bytes())
                    module = self.load_controller(directory)
                    self.c.__class__ = module.Controller
                elif case == 'unsafe-ancestor':
                    self.version.parent.chmod(0o777)
                # Explicit hostile newly reviewed pins exercise semantic validation,
                # not just the outer hash. This never occurs in the success path.
                changed = stage.encoded(envelope) != self.upgrade_raw
                if changed or case == 'checksum':
                    envelope['sha256'] = '0' * 64 if case == 'checksum' else stage.digest(stage.encoded(payload))
                    path.chmod(0o644)
                    path.write_bytes(stage.encoded(envelope))
                    path.chmod(0o444)
                    self.upgrade_pin = stage.digest(path.read_bytes())
                before, txn, calls = self.selection(), self.c.transaction_path.read_bytes(), list(self.host.calls)
                hit = []
                method = {'preflight': 'preflight_fn', 'journal': 'journal',
                          'prepared': 'save_transaction'}.get(case.split(':')[0])
                original = getattr(self.c, method) if method else None
                def mutate(*args, **kwargs):
                    result = original(*args, **kwargs)
                    if hit:
                        return result
                    hit.append(case)
                    kind = case.split(':')[1]
                    if kind == 'extra':
                        target = self.f.home / 'Applications/Verity.app/Contents/extra'
                        target.write_bytes(b'extra')
                    elif kind == 'retained':
                        target = self.f.home / 'Applications/Verity.upgrade-v1.app'
                        target.rename(target.with_name('moved-v1.app'))
                    else:
                        target = {'receipt': path, 'control': self.version / 'watchdog.py',
                                  'wrapper': self.f.base / 'watchdog.py',
                                  'app': self.f.home / 'Applications/Verity.app/Contents/Info.plist',
                                  'stage': self.fresh / 'stage-report.json'}[kind]
                        mode = target.stat().st_mode & 0o777
                        target.chmod(0o600)
                        target.write_bytes(target.read_bytes() + b'\n')
                        target.chmod(mode)
                    return result
                from contextlib import nullcontext
                with patch.object(self.c, method, side_effect=mutate) if method else nullcontext():
                    with self.assertRaises((RuntimeError, OSError, ValueError)):
                        self.return_exact()
                self.assertEqual(self.selection(), before)
                self.assertEqual(self.host.calls, calls)
                if method:
                    self.assertEqual(hit, [case])
                if case.startswith('prepared:'):
                    self.assertEqual(self.c.read_transaction()['phase'], 'prepared')
                    self.assertEqual(base64.b64decode(self.c.read_transaction()['manifest']), before[0])
                else:
                    self.assertEqual(self.c.transaction_path.read_bytes(), txn)

    def test_real_upgraded_return_failure_and_interruption_recover_once(self):
        class PowerLoss(BaseException):
            pass
        for case in ('failed-return', 'failed-fallback', 'manifest-before', 'manifest-after',
                     'agent-before', 'agent-after', 'webui-before', 'webui-after',
                     'reload-before', 'reload-after'):
            with self.subTest(case=case):
                if case != 'failed-return':
                    self.doCleanups()
                    self.setUp()
                first = self.host.kicks + 1
                if case.startswith('failed'):
                    self.host.fail_kicks = {first, first + 1} if case == 'failed-fallback' else {first}
                    result = self.return_exact()
                    self.assertEqual(result['status'], 'rollback_failed' if case == 'failed-fallback' else 'rolled_back')
                else:
                    hit = []
                    write, reload_job = self.module.atomic_write, self.host.reload
                    def interrupt_write(path, data):
                        target = {'manifest': self.f.selected, **self.plists}.get(case.split('-')[0])
                        match = path == target and not hit
                        if match:
                            hit.append(case)
                            if case.endswith('before'):
                                raise PowerLoss()
                        write(path, data)
                        if match:
                            raise PowerLoss()
                    def interrupt_reload(*args):
                        if not case.startswith('reload') or hit:
                            return reload_job(*args)
                        hit.append(case)
                        if case.endswith('after'):
                            reload_job(*args)
                        raise PowerLoss()
                    with patch.object(self.module, 'atomic_write', side_effect=interrupt_write), \
                            patch.object(self.host, 'reload', side_effect=interrupt_reload):
                        with self.assertRaises(PowerLoss):
                            self.return_exact()
                    self.assertEqual(hit, [case])
                    with self.module.control_lock(self.f.base):
                        self.assertEqual(self.c.recover_locked()['status'], 'rolled_back')
                self.assertEqual(self.selection(), self.current)
                calls = list(self.host.calls)
                with self.module.control_lock(self.f.base):
                    if case == 'failed-fallback':
                        with self.assertRaises(self.module.ControlError):
                            self.c.recover_locked()
                    else:
                        self.assertIsNone(self.c.recover_locked())
                self.assertEqual(self.host.calls, calls)
                with self.assertRaises(RuntimeError):
                    self.restore()
                self.assertEqual((self.f.base / install.RECEIPT).read_bytes(), self.root_raw)
                self.assertEqual((self.f.base / install.UPGRADE_RECEIPT).read_bytes(), self.upgrade_raw)
                for path, tree in self.artifacts.items():
                    self.assertEqual(install.tree(path), tree)

if __name__ == '__main__':
    unittest.main()
