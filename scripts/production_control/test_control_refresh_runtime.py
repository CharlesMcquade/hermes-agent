"""Offline runtime fences; run only in a guarded subprocess with isolated HOME.

Deployment records here are fixture inputs, not installation evidence. The
composition suite owns real first-install/refresh/restore coverage.
"""
import base64
import importlib.util
import json
import os
from pathlib import Path
import stat
import sys
import unittest
from unittest.mock import patch

import control_refresh as refresh
import restart_production as control
import test_native_migration as fixtures
import watchdog


def record(path):
    return dict(data=base64.b64encode(path.read_bytes()).decode(),
                mode=stat.S_IMODE(path.stat().st_mode), uid=path.stat().st_uid)


def put(path, raw, mode=0o600):
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        path.chmod(0o600)
    path.write_bytes(raw)
    path.chmod(mode)


def module_at(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    with patch.object(sys, 'dont_write_bytecode', True):
        spec.loader.exec_module(module)
    return module


def malformed_backups(raw):
    """Checksum-correct records: envelope integrity must not mask bad backups."""
    import copy
    import plistlib
    body = json.loads(raw)['transaction']
    cases: list[tuple[str, str | None, object]] = [('both-missing', None, None)]
    for field in ('manifest', 'plists'):
        cases.extend((field + '-' + name, field, value) for name, value in (
            ('missing', None), ('type', 17), ('empty', '' if field == 'manifest' else {})))
    b64 = lambda value: base64.b64encode(value).decode()
    cases.extend([
        ('manifest-base64', 'manifest', '!'),
        ('manifest-json', 'manifest', b64(b'not json')),
        ('manifest-object', 'manifest', b64(b'[]')),
        ('manifest-shape', 'manifest', b64(b'{}')),
        ('plists-services', 'plists', {'agent': body['plists']['agent']}),
        ('plist-type', 'plists', dict(body['plists'], agent=17)),
        ('plist-base64', 'plists', dict(body['plists'], agent='!')),
        ('plist-bytes', 'plists', dict(body['plists'], agent=b64(b'not plist'))),
        ('plist-object', 'plists', dict(body['plists'], agent=b64(plistlib.dumps([])))),
        ('plist-shape', 'plists', dict(body['plists'], agent=b64(plistlib.dumps({})))),
    ])
    # These remain checksum-correct and change only one backed-up plist. The
    # original terminal transaction came from a real fixture legacy restart.
    for service in ('agent', 'webui'):
        definition = plistlib.loads(base64.b64decode(body['plists'][service], validate=True))
        argv = definition['ProgramArguments']
        assert len(argv) == 3 and argv[-1] == service
        for name, replacement in (
            ('missing-launcher', [argv[0], service]),
            ('wrong-launcher', [argv[0], '/wrong/production_launcher.py', service]),
            ('relative-launcher', [argv[0], 'production_launcher.py', service]),
            ('extra-argument', [argv[0], argv[1], '--extra', service]),
        ):
            changed = dict(definition, ProgramArguments=replacement)
            cases.append((service + '-' + name, 'plists',
                          dict(body['plists'], **{service: b64(plistlib.dumps(changed))})))
    for name, field, value in cases:
        txn = copy.deepcopy(body)
        if field is None:
            txn.pop('manifest')
            txn.pop('plists')
        elif value is None:
            txn.pop(field)
        else:
            txn[field] = value
        envelope = dict(schema_version=1, transaction=txn,
                        sha256=refresh.digest(json.dumps(txn, sort_keys=True, separators=(',', ':')).encode()))
        yield name, refresh.encoded(envelope)


def filesystem_state(root):
    """Membership, bytes and identities at refusal, before any fixture repair."""
    return {str(p.relative_to(root)): (p.stat().st_dev, p.stat().st_ino,
            p.stat().st_mode, p.stat().st_uid, None if p.is_dir() else p.read_bytes())
            for p in (root, *root.rglob('*'))}


class RefreshRuntimeTests(unittest.TestCase):
    def setUp(self):
        self.f = fixtures.NativeMigrationTests()
        self.f.setUp()
        self.addCleanup(self.f.doCleanups)
        self.base, self.host = self.f.base, self.f.host
        self.home = self.base / 'home'
        self.home.mkdir()
        env = patch.dict(os.environ, HOME=str(self.home), HERMES_HOME=str(self.home / 'state'),
                         HERMES_WEBUI_STATE_DIR=str(self.home / 'webui'))
        env.start()
        self.addCleanup(env.stop)
        app = self.home / 'Applications/Verity.app'
        app.parent.mkdir()
        Path(self.f.new['native_host']['bundle']).rename(app)
        self.app = app
        self.f.new['native_host'].update(bundle=str(app), executable=str(app / 'Contents/MacOS/VerityServiceHost'))
        for service in control.SERVICES:
            self.f.new['launchd_overrides'][service]['ProgramArguments'] = [self.f.new['native_host']['executable'], service]
        self.original = self.f.c.manifest_path.read_bytes()
        self.legacy = self.f.saved()
        self.v1 = self.base / 'control-versions/v1'
        self.version = self.base / 'control-refresh-versions/v2'
        self.original_stage = self.base / 'original-stage'
        source = Path(__file__).parent
        hashes = []
        for directory, names in ((self.v1, refresh.CONTROL_FILES[:-1]), (self.version, refresh.CONTROL_FILES)):
            directory.mkdir(parents=True)
            inventory = {}
            for name in names:
                raw = (source / name).read_bytes()
                put(directory / name, raw, 0o444)
                inventory[name] = refresh.digest(raw)
            put(directory / 'control-receipt.json', refresh.encoded(inventory), 0o444)
            directory.chmod(0o555)
            hashes.append(inventory)
        wrappers, replacements = {}, {}
        for name in (*refresh.MANAGEMENT, 'production_launcher.py'):
            path = self.base / name
            if not path.exists():
                put(path, ('fixture original ' + name).encode(), 0o755)
            wrappers[name] = record(path)
            replacements[name] = wrappers[name]['data']
        baseline = {str(path): record(path) for path in (self.f.c.manifest_path, *self.f.plists.values())}
        report = dict(status='staged_not_activated', activation_ready=False,
                      selected_sha256=refresh.digest(self.original),
                      candidate_sha256=refresh.digest(refresh.encoded(self.f.new)),
                      rollback_sha256={**{s + '.plist': dict(sha256=refresh.digest(raw), executable=False)
                                          for s, raw in self.legacy.items()},
                                       **{'maintenance/' + n: dict(sha256=refresh.digest(base64.b64decode(r['data'])), executable=False)
                                          for n, r in wrappers.items()}},
                      final_base=str(self.base), final_bundle=str(app),
                      final_control_version=str(self.v1), control_sha256=hashes[0])
        self.root = dict(base=str(self.base), home=str(self.home), phase='installed', report=report,
                         wrappers=wrappers, replacements=replacements, baseline=baseline)
        put(self.base / 'native-install-receipt.json', refresh.encoded(dict(schema_version=1, receipt=self.root,
            sha256=refresh.digest(refresh.encoded(self.root)))))
        self.root_pin = refresh.digest((self.base / 'native-install-receipt.json').read_bytes())
        put(self.original_stage / 'stage-report.json', refresh.encoded(report))
        put(self.original_stage / 'candidate-release.json', refresh.encoded(self.f.new))
        # An actual terminal legacy restart precedes the fixture fence.
        self.assertEqual(self.f.c.restart(yes=True)['status'], 'verified')
        self.old_txn = self.f.c.transaction_path.read_bytes()
        stage = dict(schema_version=1, kind='native-control-refresh-stage', base=str(self.base),
                     home=str(self.home), root_sha256=self.root_pin, original_stage=str(self.original_stage),
                     original_stage_sha256=refresh.digest(refresh.encoded(report)), version=str(self.version),
                     control_sha256=hashes[1], app_tree={str(p.relative_to(app)): dict(
                         mode=stat.S_IMODE(p.stat().st_mode), uid=p.stat().st_uid,
                         sha256=None if p.is_dir() else refresh.digest(p.read_bytes()))
                         for p in (app, *app.rglob('*'))},
                     app_identity=[app.stat().st_dev, app.stat().st_ino],
                     launcher=record(self.base / 'production_launcher.py'),
                     launcher_identity=[(self.base / 'production_launcher.py').stat().st_dev,
                                        (self.base / 'production_launcher.py').stat().st_ino])
        self.receipt = dict(schema_version=1, kind='native-control-refresh', stage=stage,
                            stage_sha256=refresh.digest(refresh.encoded(stage)),
                            original_transaction=record(self.f.c.transaction_path),
                            lock_identity=[(self.base / 'control.lock').stat().st_dev,
                                           (self.base / 'control.lock').stat().st_ino])
        self.pin = refresh.digest(refresh.encoded(self.receipt))
        put(self.base / refresh.RECEIPT, refresh.encoded(self.receipt), 0o444)
        for name, text in refresh.new_wrappers(self.base, self.version, self.pin).items():
            put(self.base / name, text.encode(), wrappers[name]['mode'])
        fence = dict(json.loads(self.old_txn), schema_version=2, control_refresh_sha256=self.pin)
        put(self.f.c.transaction_path, refresh.encoded(fence))
        self.module = module_at('fixture_refresh_controller', self.version / 'restart_production.py')
        self.c = self.make_controller(self.pin)
        self.old = self.f.c
        self.protected = {p: (p.read_bytes(), p.stat().st_ino, p.stat().st_mode)
                          for p in (*self.v1.iterdir(), self.base / 'native-install-receipt.json',
                                    self.base / 'production_launcher.py',
                                    *(p for p in self.app.rglob('*') if p.is_file()))}

    def make_controller(self, pin):
        return self.module.Controller(self.base, self.host, self.old.preflight_fn if hasattr(self, 'old') else self.f.c.preflight_fn,
                                      self.f.clock, self.f.clock, self.f.clock.sleep,
                                      owner=lambda: 1, timeout=5, stable_seconds=1, control_refresh_sha256=pin)

    def activate(self):
        put(self.f.candidate, refresh.encoded(self.f.new))
        return self.c.restart(candidate=self.f.candidate, reload=True, yes=True)

    def exact_return(self):
        return self.c.restart(reload=True, yes=True, return_baseline=self.root_pin,
                              return_control_refresh_sha256=self.pin)

    def test_malformed_original_backups_refuse_runtime_before_writes(self):
        for name, raw in malformed_backups(self.old_txn):
            with self.subTest(case=name):
                self.receipt['original_transaction']['data'] = base64.b64encode(raw).decode()
                self.pin = refresh.digest(refresh.encoded(self.receipt))
                put(self.base / refresh.RECEIPT, refresh.encoded(self.receipt), 0o444)
                for wrapper, text in refresh.new_wrappers(self.base, self.version, self.pin).items():
                    put(self.base / wrapper, text.encode(), self.root['wrappers'][wrapper]['mode'])
                put(self.c.transaction_path, refresh.encoded(dict(json.loads(raw),
                    schema_version=2, control_refresh_sha256=self.pin)))
                # Rebind a retained object: admission, not a stale pin, must reject.
                self.c.control_refresh_sha256 = self.pin
                for run in (lambda: refresh.load(self.base, self.pin, self.version / 'restart_production.py'),
                            lambda: self.c.restart(yes=True), self.c.recover_locked):
                    before, calls = filesystem_state(self.base), list(self.host.calls)
                    with patch.object(self.module, 'atomic_write', wraps=self.module.atomic_write) as writes:
                        try:
                            with self.assertRaisesRegex((ValueError, self.module.ControlError), 'transaction|backup'):
                                run()
                        finally:
                            writes.assert_not_called()
                            self.assertEqual(filesystem_state(self.base), before)
                            self.assertEqual(self.host.calls, calls)

    def test_activation_exact_return_and_old_runtime_fence(self):
        self.assertEqual(self.activate()['status'], 'verified')
        self.assertEqual(watchdog.tick(self.c, grace=0)['status'], 'healthy')
        before = self.c.transaction_path.read_bytes()
        calls = list(self.host.calls)
        with self.assertRaisesRegex(control.ControlError, 'Unsupported transaction schema'):
            self.old.restart(yes=True)
        with control.control_lock(self.base), self.assertRaises(control.ControlError):
            self.old.recover_locked()
        self.assertEqual(watchdog.tick(self.old)['status'], 'blocked')
        self.assertEqual(self.c.transaction_path.read_bytes(), before)
        self.assertEqual(self.host.calls, calls)
        self.assertEqual(self.exact_return()['status'], 'verified')
        self.assertEqual((self.c.manifest_path.read_bytes(), self.f.saved()), (self.original, self.legacy))
        txn = self.c.read_transaction()
        self.assertEqual(txn['control_refresh_sha256'], self.pin)
        self.assertEqual(txn['baseline_sha256'], self.root_pin)
        self.assertEqual(json.loads(self.c.transaction_path.read_bytes())['schema_version'], 2)
        for p, expected in self.protected.items():
            self.assertEqual((p.read_bytes(), p.stat().st_ino, p.stat().st_mode), expected)

    def test_missing_wrong_and_schema1_fences_refuse_retained_objects(self):
        before = self.c.transaction_path.read_bytes()
        for bad in (None, self.old_txn, refresh.encoded(dict(json.loads(before), control_refresh_sha256='0' * 64))):
            with self.subTest(bad=bad):
                if bad is None:
                    self.c.transaction_path.unlink()
                else:
                    put(self.c.transaction_path, bad)
                calls = list(self.host.calls)
                for run in (lambda: self.c.restart(yes=True), self.c.recover_locked):
                    with self.assertRaises(self.module.ControlError):
                        run()
                self.assertEqual(watchdog.tick(self.c)['status'], 'blocked')
                self.assertEqual(self.host.calls, calls)
                self.assertEqual(self.c.transaction_path.read_bytes() if bad else None, bad)
        for pin in (None, 'A' * 64, 'x'):
            with self.subTest(pin=pin), self.assertRaises(self.module.ControlError):
                self.make_controller(pin)
        put(self.c.transaction_path, before)
        self.assertIsNone(self.c.recover_locked())
        # A saved object may not use retained committed artifacts after wrapper undo.
        for name in refresh.MANAGEMENT:
            put(self.base / name, base64.b64decode(self.root['replacements'][name]), self.root['wrappers'][name]['mode'])
        with self.assertRaises(self.module.ControlError):
            self.c.restart(yes=True)
        self.assertEqual(watchdog.tick(self.c)['status'], 'blocked')

    def test_refreshed_executor_requires_pin_even_without_markers(self):
        for path in (self.base / refresh.RECEIPT, self.c.transaction_path):
            path.unlink()
        with self.assertRaises(self.module.ControlError):
            self.make_controller(None)
        with self.assertRaises((self.module.ControlError, OSError)):
            self.c.restart(yes=True)

    def test_provenance_drift_refuses_before_any_host_action(self):
        cases = ('receipt', 'control', 'control-mode', 'v1', 'launcher', 'app', 'extra', 'lock', 'missing-lock')
        for index, case in enumerate(cases):
            with self.subTest(case=case):
                if index:
                    self.doCleanups()
                    self.setUp()
                target = {'receipt': self.base / refresh.RECEIPT, 'control': self.version / 'watchdog.py',
                          'control-mode': self.version / 'watchdog.py', 'v1': self.v1 / 'watchdog.py',
                          'launcher': self.base / 'production_launcher.py',
                          'app': self.app / 'Contents/Info.plist', 'lock': self.base / 'control.lock',
                          'missing-lock': self.base / 'control.lock'}.get(case)
                if case == 'extra':
                    self.version.chmod(0o755)
                    put(self.version / 'foreign', b'x', 0o444)
                    self.version.chmod(0o555)
                elif case == 'control-mode':
                    target.chmod(0o644)
                elif case in ('lock', 'missing-lock'):
                    target.rename(self.base / 'old-lock')
                    if case == 'lock':
                        put(target, b'')
                else:
                    put(target, target.read_bytes() + b'\n', stat.S_IMODE(target.stat().st_mode))
                before = self.c.transaction_path.read_bytes()
                calls = list(self.host.calls)
                with self.assertRaises((self.module.ControlError, OSError)):
                    self.c.restart(yes=True)
                self.assertEqual(self.host.calls, calls)
                self.assertEqual(self.c.transaction_path.read_bytes(), before)
                if case == 'missing-lock':
                    self.assertFalse(target.exists())

    def test_native_fallback_recovery_remains_schema2_and_one_attempt(self):
        self.assertEqual(self.activate()['status'], 'verified')
        native = self.c.manifest_path.read_bytes(), self.f.saved()
        class PowerLoss(BaseException):
            pass
        write = self.module.atomic_write
        def interrupt(path, raw):
            write(path, raw)
            if path == self.c.manifest_path:
                raise PowerLoss()
        with patch.object(self.module, 'atomic_write', side_effect=interrupt), self.assertRaises(PowerLoss):
            self.exact_return()
        self.assertEqual(self.c.read_transaction()['phase'], 'prepared')
        fence = self.c.transaction_path.read_bytes()
        self.assertEqual(watchdog.tick(self.old)['status'], 'blocked')
        self.assertEqual(self.c.transaction_path.read_bytes(), fence)
        with self.c.locked():
            self.assertEqual(self.c.recover_locked()['status'], 'rolled_back')
            calls = list(self.host.calls)
            self.assertIsNone(self.c.recover_locked())
        self.assertEqual(self.host.calls, calls)
        self.assertEqual((self.c.manifest_path.read_bytes(), self.f.saved()), native)
        self.assertEqual(json.loads(self.c.transaction_path.read_bytes())['control_refresh_sha256'], self.pin)

    def test_observation_closure_covers_files_and_directory_identity(self):
        seen = []
        def read(path):
            seen.append(path)
            return path.read_bytes()
        _, replacements, unchanged = refresh.load(self.base, self.pin, Path(self.module.__file__), read=read)
        self.assertEqual(set(replacements), set(self.root['replacements']))
        self.assertIn(self.base / 'control.lock', seen)
        self.assertNotIn(self.c.transaction_path, seen)
        self.assertNotIn(self.c.manifest_path, seen)
        unchanged()
        put(self.original_stage / 'candidate-release.json', refresh.encoded(self.f.new))
        with self.assertRaises(ValueError):
            unchanged()

    def test_publication_races_preserve_selection_and_fence(self):
        for index, stage in enumerate(('preflight', 'journal', 'prepared')):
            with self.subTest(stage=stage):
                if index:
                    self.doCleanups()
                    self.setUp()
                self.assertEqual(self.activate()['status'], 'verified')
                native = self.c.manifest_path.read_bytes(), self.f.saved()
                before = self.c.transaction_path.read_bytes()
                calls = list(self.host.calls)
                method = {'preflight': 'preflight_fn', 'journal': 'journal', 'prepared': 'save_transaction'}[stage]
                original, fired = getattr(self.c, method), []
                def race(*args, **kwargs):
                    result = original(*args, **kwargs)
                    if not fired:
                        fired.append(stage)
                        path = self.version / 'watchdog.py'
                        put(path, path.read_bytes() + b'\n', 0o444)
                    return result
                with patch.object(self.c, method, side_effect=race), self.assertRaises((ValueError, self.module.ControlError)):
                    self.exact_return()
                self.assertEqual(fired, [stage])
                self.assertEqual(self.host.calls, calls)
                self.assertEqual((self.c.manifest_path.read_bytes(), self.f.saved()), native)
                if stage == 'prepared':
                    self.assertEqual(self.c.read_transaction()['phase'], 'prepared')
                    self.assertEqual(json.loads(self.c.transaction_path.read_bytes())['schema_version'], 2)
                else:
                    self.assertEqual(self.c.transaction_path.read_bytes(), before)

    def test_failed_return_has_bounded_schema2_fallback(self):
        self.assertEqual(self.activate()['status'], 'verified')
        native = self.c.manifest_path.read_bytes(), self.f.saved()
        first = self.host.kicks + 1
        self.host.fail_kicks = {first, first + 1}
        self.assertEqual(self.exact_return()['status'], 'rollback_failed')
        self.assertEqual((self.c.manifest_path.read_bytes(), self.f.saved()), native)
        self.assertEqual(self.c.read_transaction()['phase'], 'rollback_failed')
        calls = list(self.host.calls)
        with self.c.locked(), self.assertRaises(self.module.ControlError):
            self.c.recover_locked()
        self.assertEqual(watchdog.tick(self.c)['status'], 'blocked')
        self.assertEqual(self.host.calls, calls)
        self.assertEqual(json.loads(self.c.transaction_path.read_bytes())['schema_version'], 2)

    def test_generated_wrappers_forward_pinned_arguments_without_launcher(self):
        import types
        wrappers = refresh.new_wrappers(self.base, self.version, self.pin)
        self.assertEqual(set(wrappers), set(refresh.MANAGEMENT))
        for name, text in wrappers.items():
            called = []
            module = types.ModuleType(name[:-3])
            def main(args):
                called.append(args)
                return {'status': 'verified'}
            module.main = main
            with patch.dict(sys.modules, {name[:-3]: module}), patch.object(sys, 'path', list(sys.path)), patch.object(
                    sys, 'argv', [str(self.base / name), '--restart', '--reload']), self.assertRaises(SystemExit) as exit:
                exec(compile(text, str(self.base / name), 'exec'), {})
            self.assertEqual(exit.exception.code, 0)
            self.assertEqual(called, [['--base', str(self.base), '--control-refresh-sha256', self.pin,
                                      '--restart', '--reload']])

    def test_readonly_main_and_lock_race_fail_before_host_or_lock_creation(self):
        self.c.transaction_path.unlink()
        calls = list(self.host.calls)
        with patch.object(self.module, 'Controller', return_value=self.c), self.assertRaises(self.module.ControlError):
            self.module.main(['--base', str(self.base), '--control-refresh-sha256', self.pin])
        self.assertEqual(self.host.calls, calls)
        path = self.base / 'control.lock'
        original = self.module.control_lock
        def race(base, expected_identity=None):
            path.unlink()
            return original(base, expected_identity=expected_identity)
        with patch.object(self.module, 'control_lock', side_effect=race), self.assertRaises(FileNotFoundError):
            self.c.restart(yes=True)
        self.assertFalse(path.exists())
        self.assertEqual(self.host.calls, calls)

    def test_cli_pin_pairing_and_duplicate_overrides(self):
        args = ['--base', str(self.base), '--restart', '--reload', '--yes', '--return-baseline', self.root_pin]
        with patch.object(self.module, 'Controller') as factory:
            for extra in (['--control-refresh-sha256', self.pin] * 2,
                          ['--return-control-refresh-sha256', self.pin] * 2,
                          ['--return-control-refresh-sha256', self.pin, '--return-upgrade-sha256', self.pin],
                          ['--return-control-refresh-sha256', self.pin, '--control-refresh-sha256', '0' * 64]):
                with self.subTest(extra=extra), self.assertRaises(SystemExit):
                    self.module.main(args + extra)
            factory.assert_not_called()
            self.module.main(args + ['--return-control-refresh-sha256', self.pin])
            self.assertEqual(factory.call_args.kwargs['control_refresh_sha256'], self.pin)
            self.assertEqual(factory.return_value.restart.call_args.kwargs['return_control_refresh_sha256'], self.pin)
        with patch.object(watchdog, 'Controller') as factory, self.assertRaises(SystemExit):
            watchdog.main(['--control-refresh-sha256', self.pin] * 2)
        factory.assert_not_called()


if __name__ == '__main__':
    unittest.main()
