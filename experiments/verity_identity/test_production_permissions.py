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

    def restorable(self, root, p):
        return True

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
        import socket
        for name in ('socket', 'create_connection', 'getaddrinfo', 'gethostbyname'):
            tripwire = patch.object(socket, name, side_effect=AssertionError('offline network'))
            tripwire.start()
            self.addCleanup(tripwire.stop)

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

    def test_local_network_request_prepares_and_preflights_offline(self):
        self.assertIn('Local Network', h.NAMES)
        h.prepare(self.root, self.base, self.home, self.python, self.bridge,
                  'Local Network', 'permissions-request', python_home=self.python_home,
                  approve_sign=True, runner=self.runner)
        plan, _, _ = h.preflight(self.root, self.runner)
        self.assertEqual(plan['config']['name'], 'Local Network')
        self.assertEqual(h.tree(self.app), self.before)

    def test_local_network_modes_refuse_before_preparation_or_worker_activity(self):
        import sys
        import socket
        for mode in ('permissions-check', 'invalid', ''):
            with self.subTest(mode=mode), patch.object(h, 'helpers') as helpers, \
                    patch.object(socket, 'socket') as connect:
                with self.assertRaises(ValueError):
                    h.prepare(self.root, self.base, self.home, self.python, self.bridge,
                              'Local Network', mode, approve_sign=True)
                config = dict(root=str(self.root), name='Local Network', mode=mode)
                with patch.object(sys, 'argv', ['fixture', '--worker']):
                    with self.assertRaises(ValueError):
                        h.worker(config)
                with self.assertRaises(ValueError):
                    h.launcher_source(config)
                helpers.assert_not_called()
                connect.assert_not_called()
                self.assertFalse(self.root.exists())
        self.assertEqual(self.calls, [])
        self.assertEqual(h.tree(self.app), self.before)
        with patch.object(socket, 'socket') as connect:
            with self.assertRaises(ValueError):
                h.local_network(None, False)
            connect.assert_not_called()

    def test_local_network_has_no_cli_endpoint_override(self):
        import contextlib
        import io
        with patch.object(h, 'prepare') as prepare, contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit) as exited:
                h.main(['prepare', '--root', str(self.root), '--worker', 'Local Network',
                        '--mode', 'permissions-request', '--endpoint', '127.0.0.1:80'])
            self.assertEqual(exited.exception.code, 2)
            prepare.assert_not_called()
        self.assertFalse(self.root.exists())

    def test_local_network_preflight_refuses_check_only_config(self):
        plan = self.prepare()
        plan['config'].update(name='Local Network', mode='permissions-check')
        (self.root / 'prepared.json').write_text(json.dumps(plan))
        with self.assertRaisesRegex(ValueError, 'requires permissions-request'):
            h.preflight(self.root, self.runner)
        self.assertEqual(h.tree(self.app), self.before)

    def test_local_network_source_and_sealed_worker_connect_once_without_payload(self):
        import contextlib
        import io
        import socket
        import sys
        from types import SimpleNamespace
        from unittest.mock import Mock
        plan = self.prepare()
        config = dict(plan['config'], name='Local Network', mode='permissions-request',
                      abi=list(sys.version_info[:2]))
        nonce = b'x' * 24
        ready = dict(event='worker-ready', pid=os.getpid(), ppid=os.getppid(),
                     pgid=os.getpgrp(), nonce=nonce.hex())
        (self.root / 'GO').write_text(json.dumps(ready))

        class PrivateSocketError(OSError):
            pass

        for sealed in (False, True):
            for error, error_type in ((None, None), (TimeoutError('private'), 'TimeoutError'),
                                     (ConnectionRefusedError('private'), 'ConnectionRefusedError'),
                                     (PermissionError('private'), 'PermissionError'),
                                     (PrivateSocketError('private'), 'OSError')):
                with self.subTest(sealed=sealed, error_type=error_type):
                    events = []

                    class Connection:
                        # Deliberately no send/recv/discovery methods: any use fails.
                        def __enter__(self):
                            events.append('enter')
                            return self

                        def settimeout(self, timeout):
                            events.append(('timeout', timeout))

                        def connect(self, endpoint):
                            events.append(('connect', endpoint))
                            self_outer.assertEqual(os.environ['HOME'], str(self_outer.root / 'home'))
                            if error:
                                raise error

                        def __exit__(self, kind, value, tb):
                            events.append(('closed', kind))

                    self_outer = self
                    probe = SimpleNamespace(FILE_PATHS={})
                    probe.permission = lambda name, status, allowed, requested, error_type: probe.emit(
                        'permission', name=name, status=status, allowed=allowed,
                        requested=requested, error_type=error_type)
                    spec = SimpleNamespace(loader=SimpleNamespace(exec_module=Mock()))
                    output = io.StringIO()
                    with patch.object(socket, 'socket', return_value=Connection()) as factory, \
                            patch.object(socket, 'getaddrinfo', side_effect=AssertionError('DNS')), \
                            patch.object(socket, 'gethostbyname', side_effect=AssertionError('DNS')), \
                            patch.object(h.importlib.util, 'spec_from_file_location', return_value=spec), \
                            patch.object(h.importlib.util, 'module_from_spec', return_value=probe), \
                            patch.object(os, 'urandom', return_value=nonce), \
                            patch.object(sys, 'argv', ['fixture', '--worker']), \
                            patch.object(sys, 'path', list(sys.path)), \
                            patch.dict(os.environ, {'HOME': str(self.root / 'home'),
                                                    'HERMES_HOME': str(self.root / 'state')}), \
                            contextlib.redirect_stdout(output):
                        if sealed:
                            with self.assertRaises(SystemExit) as exited:
                                exec(compile(h.launcher_source(config), 'sealed-launcher', 'exec'), {})
                            self.assertEqual(exited.exception.code, 0)
                        else:
                            self.assertEqual(h.worker(config), 0)
                    factory.assert_called_once_with(socket.AF_INET, socket.SOCK_STREAM)
                    self.assertEqual(events, ['enter', ('timeout', 5.0),
                                              ('connect', ('10.101.0.2', 80)),
                                              ('closed', type(error) if error else None)])
                    result = json.loads(output.getvalue().splitlines()[-1])
                    self.assertEqual(result, dict(event='worker-complete', exit_code=0, results=[
                        dict(event='permission', name='Local Network',
                             status='tcp_failed' if error else 'tcp_connected', allowed=None,
                             requested=True, error_type=error_type)]))
                    self.assertNotIn('private', output.getvalue())

    def test_local_network_sanitizer_never_accepts_authorization_or_unsanitized_errors(self):
        record = dict(event='permission', name='Local Network', status='tcp_connected',
                      allowed=None, requested=True, error_type=None)
        self.assertEqual(h.sanitize([record], 'Local Network'), [record])
        for delta in ({'allowed': True}, {'allowed': False}, {'requested': False},
                      {'status': 'authorized'}, {'status': 'requesting'},
                      {'status': 'tcp_failed'}, {'error_type': 'OSError'},
                      {'status': 'tcp_failed', 'error_type': 'private'},
                      {'name': 'Accessibility Finder role'}):
            with self.subTest(delta=delta), self.assertRaises(ValueError):
                h.sanitize([dict(record, **delta)], 'Local Network')
        with self.assertRaises(ValueError):
            h.sanitize([dict(record, name='Camera')], 'Camera')

    def test_location_diagnostic_request_admission(self):
        self.assertIn('Location Diagnostic', h.NAMES)
        h.validate_worker('Location Diagnostic', 'permissions-request')

    def location_fixture(self, sealed=False, outcome='timeout', bundle_kind='foreign', initial=0,
                         enabled=True):
        import contextlib
        import io
        import sys
        import weakref
        from types import SimpleNamespace as NS
        from unittest.mock import Mock
        state = NS(now=0.0, status=initial, callback_status=0, pumps=0, requests=0,
                   manager=None, detached=False, thread=object())
        outer = self

        class NSObject:
            @classmethod
            def alloc(cls):
                return cls()

            def init(self):
                return self

        class Manager(NSObject):
            @staticmethod
            def locationServicesEnabled():
                return enabled

            def authorizationStatus(self=None):
                return state.status if self is None else state.callback_status

            def init(self):
                outer.assertIs(loop.thread, state.thread)
                state.manager = self
                return self

            def setDelegate_(self, delegate):
                self.delegate = weakref.ref(delegate) if delegate else None
                state.detached = delegate is None

            def requestWhenInUseAuthorization(self):
                state.requests += 1
                outer.assertEqual(state.requests, 1)
                self.delegate().locationManagerDidChangeAuthorization_(self)

        class Loop:
            thread = state.thread

            def runUntilDate_(self, interval):
                outer.assertGreater(interval, 0)
                outer.assertLessEqual(interval, 0.1)
                outer.assertIs(self.thread, state.thread)
                outer.assertIsNotNone(state.manager.delegate())
                state.pumps += 1
                state.now += 100  # Fake time: bounded timeout, never sleep.
                if outcome == 'change':
                    state.status = 2
                elif outcome == 'callback':
                    state.callback_status = 4  # Class status intentionally still 0.
                    state.manager.delegate().locationManagerDidChangeAuthorization_(state.manager)
                elif outcome == 'unknown':
                    state.callback_status = 999999
                    state.manager.delegate().locationManagerDidChangeAuthorization_(state.manager)

        loop = Loop()
        def usage(key):
            self.assertEqual(key, 'NSLocationUsageDescription')
            return 'private usage text' if bundle_kind != 'empty' else ''
        bundle = None if bundle_kind == 'missing' else NS(
            bundleIdentifier=lambda: 'com.charles.verity' if bundle_kind == 'expected' else 'private.bundle',
            bundlePath=lambda: str(self.home / 'Applications/Verity.app') if bundle_kind == 'expected'
            else '/private/unrelated/path', objectForInfoDictionaryKey_=usage)
        modules = dict(Foundation=NS(NSObject=NSObject, NSBundle=NS(mainBundle=lambda: bundle),
                                    NSThread=NS(isMainThread=lambda: True),
                                    NSRunLoop=NS(currentRunLoop=lambda: loop),
                                    NSDate=NS(dateWithTimeIntervalSinceNow_=lambda value: value)),
                       CoreLocation=NS(CLLocationManager=Manager),
                       AppKit=NS(NSRunningApplication=NS(currentApplication=lambda: NS(
                           activationPolicy=lambda: 2, isActive=lambda: False))))
        config = dict(root=str(self.root), home=str(self.home), name='Location Diagnostic',
                      mode='permissions-request', abi=list(sys.version_info[:2]), bridge=str(self.bridge))
        self.root.mkdir(exist_ok=True)
        (self.root / 'permissions_probe.py').write_bytes(b'never imported fixture')
        config['probe_sha256'] = h.sha((self.root / 'permissions_probe.py').read_bytes())
        nonce = b'x' * 24
        ready = dict(event='worker-ready', pid=os.getpid(), ppid=os.getppid(),
                     pgid=os.getpgrp(), nonce=nonce.hex())
        (self.root / 'GO').write_text(json.dumps(ready))
        probe = NS(FILE_PATHS={})  # No native(), permission(), networking or other APIs.
        spec = NS(loader=NS(exec_module=Mock()))
        output = io.StringIO()
        with patch.dict(sys.modules, modules), \
                patch.object(h.importlib.util, 'spec_from_file_location', return_value=spec), \
                patch.object(h.importlib.util, 'module_from_spec', return_value=probe), \
                patch.object(h.time, 'monotonic', side_effect=lambda: state.now), \
                patch.object(h.time, 'sleep', side_effect=AssertionError('real sleep')), \
                patch.object(h.subprocess, 'Popen', side_effect=AssertionError('spawn')), \
                patch.object(h.C, 'CDLL', side_effect=AssertionError('native library')), \
                patch.object(os, 'urandom', return_value=nonce), \
                patch.object(sys, 'argv', ['fixture', '--worker']), \
                patch.object(sys, 'path', list(sys.path)), \
                patch.dict(os.environ, HOME=str(self.root / 'home'), HERMES_HOME=str(self.root / 'state')), \
                contextlib.redirect_stdout(output):
            if sealed:
                with self.assertRaises(SystemExit) as exited:
                    exec(compile(h.launcher_source(config), 'sealed-location', 'exec'), {})
                self.assertEqual(exited.exception.code, 0)
            else:
                self.assertEqual(h.worker(config), 0)
        self.assertNotIn('private', output.getvalue())
        events = [json.loads(line) for line in output.getvalue().splitlines()]
        self.assertEqual(len(events), 2)
        self.assertEqual(events[-1]['exit_code'], 0)
        result = events[-1]['results'][0]
        self.assertEqual(h.sanitize([result], 'Location Diagnostic'), [result])
        if state.requests:
            self.assertTrue(state.detached)
        return result, state

    def test_location_source_and_generated_initial_callback_is_not_completion(self):
        for sealed in (False, True):
            for outcome in ('timeout', 'unknown'):
                with self.subTest(sealed=sealed, outcome=outcome):
                    result, state = self.location_fixture(sealed, outcome)
                    d = result['diagnostics']
                    self.assertEqual(result['error_type'], 'ConsentTimeout')
                    self.assertEqual(result['status'], 'not_determined')
                    self.assertIsNone(result['allowed'])
                    self.assertEqual(d['first_callback'], 0)
                    self.assertEqual(d['last_callback'], 0 if outcome == 'timeout' else -2)
                    self.assertEqual(d['callback_count'], 1 if outcome == 'timeout' else 6)
                    self.assertEqual(d['loop_pump_count'], 5)
                    self.assertEqual(state.requests, 1)
                    self.assertGreaterEqual(state.now, 445)

    def test_location_source_and_generated_callback_or_status_change_completes(self):
        for sealed in (False, True):
            for outcome in ('change', 'callback'):
                with self.subTest(sealed=sealed, outcome=outcome):
                    result, state = self.location_fixture(sealed, outcome)
                    d = result['diagnostics']
                    self.assertIsNone(result['error_type'])
                    self.assertEqual(d['loop_pump_count'], 1)
                    self.assertEqual(d['callback_count'], 2 if outcome == 'callback' else 1)
                    self.assertEqual(d['last_callback'], 4 if outcome == 'callback' else 0)
                    self.assertEqual(d['final_status'], 0 if outcome == 'callback' else 2)
                    self.assertEqual(result['status'], 'not_determined' if outcome == 'callback' else 'denied')
                    self.assertEqual(state.requests, 1)

    def test_location_metadata_always_boolean_even_without_main_bundle(self):
        for sealed in (False, True):
            for kind in ('expected', 'foreign', 'empty', 'missing'):
                with self.subTest(sealed=sealed, bundle=kind):
                    result, _ = self.location_fixture(sealed, 'change', kind)
                    d = result['diagnostics']
                    for key in ('worker_main_bundle_present', 'worker_main_bundle_id_expected',
                                'worker_main_bundle_path_expected', 'worker_macos_usage_string_present',
                                'worker_main_thread', 'worker_is_active', 'services_enabled'):
                        self.assertIs(type(d[key]), bool)
                    self.assertEqual(d['worker_main_bundle_present'], kind != 'missing')
                    self.assertEqual(d['worker_main_bundle_id_expected'], kind == 'expected')
                    self.assertEqual(d['worker_main_bundle_path_expected'], kind == 'expected')
                    self.assertEqual(d['worker_macos_usage_string_present'], kind in ('expected', 'foreign'))
                    self.assertEqual(d['worker_activation_policy'], 2)
                    self.assertFalse(d['worker_is_active'])

    def test_location_no_redundant_request_and_services_disabled(self):
        for sealed in (False, True):
            for initial, enabled, label in ((4, True, 'authorized_when_in_use'),
                                            (0, False, 'services_disabled'), (9999, True, 'unknown')):
                with self.subTest(sealed=sealed, initial=initial, enabled=enabled):
                    result, state = self.location_fixture(sealed, initial=initial, enabled=enabled)
                    self.assertEqual(result['status'], label)
                    self.assertFalse(result['requested'])
                    self.assertEqual(state.requests, 0)
                    self.assertEqual(result['diagnostics']['callback_count'], 0)
                    self.assertIsNone(result['diagnostics']['first_callback'])

    def test_location_metadata_closed_allowlist_source_and_generated(self):
        import ast
        result, _ = self.location_fixture()
        module = ast.parse(h.launcher_source(dict(name='Location Diagnostic', mode='permissions-request')))
        module.body.pop()  # Definitions only; never enter supervisor/worker here.
        namespace = {}
        exec(compile(module, 'sealed-definitions', 'exec'), namespace)
        for sanitize in (h.sanitize, namespace['sanitize']):
            for key, value in result['diagnostics'].items():
                for invalid in ('private text', {'private': 'content'}, [], 1000001, 1.5):
                    with self.subTest(key=key, invalid=invalid), self.assertRaises((ValueError, TypeError)):
                        sanitize([dict(result, diagnostics=dict(result['diagnostics'], **{key: invalid}))],
                                 'Location Diagnostic')
                if type(value) is bool:
                    with self.assertRaises(ValueError):
                        sanitize([dict(result, diagnostics=dict(result['diagnostics'], **{key: 1}))],
                                 'Location Diagnostic')
            for delta in ({'arbitrary': 'private'}, {'worker_main_bundle_path': '/private/path'}):
                with self.assertRaises(ValueError):
                    sanitize([dict(result, diagnostics=dict(result['diagnostics'], **delta))], 'Location Diagnostic')
            for key in result['diagnostics']:
                d = dict(result['diagnostics'])
                del d[key]
                with self.assertRaises(ValueError):
                    sanitize([dict(result, diagnostics=d)], 'Location Diagnostic')
            with self.assertRaises(ValueError):
                sanitize([dict(result, name='Location')], 'Location')  # Original contract unchanged.

    def test_location_invalid_modes_before_mutations_or_activity(self):
        import ast
        import contextlib
        import io
        import sys
        module = ast.parse(h.launcher_source(dict(name='Location Diagnostic', mode='permissions-request')))
        module.body.pop()
        namespace = {}
        exec(compile(module, 'sealed-definitions', 'exec'), namespace)
        for mode in ('permissions-check', 'invalid', ''):
            with self.subTest(mode=mode), patch.object(h, 'helpers') as helpers:
                with self.assertRaises(ValueError):
                    h.prepare(self.root, self.base, self.home, self.python, self.bridge,
                              'Location Diagnostic', mode, approve_sign=True)
                config = dict(root=str(self.root), name='Location Diagnostic', mode=mode)
                for worker in (h.worker, namespace['worker']):
                    output = io.StringIO()
                    with patch.object(sys, 'argv', ['fixture', '--worker']), contextlib.redirect_stdout(output):
                        with self.assertRaises(ValueError):
                            worker(config)
                    self.assertEqual(output.getvalue(), '')
                with self.assertRaises(ValueError):
                    h.launcher_source(config)
                helpers.assert_not_called()
                self.assertFalse(self.root.exists())
        with self.assertRaises(ValueError):
            h.location_diagnostic(None, False, {})  # Before native imports.
        self.assertEqual(self.calls, [])

    def test_location_timeout_report_exact_restore_offline(self):
        # Produce the diagnostic using bridge mocks, then feed it through real run/report logic.
        result, _ = self.location_fixture()
        for item in self.root.iterdir():
            item.unlink()
        self.root.rmdir()
        h.prepare(self.root, self.base, self.home, self.python, self.bridge,
                  'Location Diagnostic', 'permissions-request', python_home=self.python_home,
                  approve_sign=True, runner=self.runner)
        h.preflight(self.root, self.runner)
        adapter = FakeLive()
        bootstrap = adapter.bootstrap
        def diagnostic_bootstrap(target, root):
            bootstrap(target, root)
            events = h.records(root)
            events[1]['results'] = [result]
            (root / 'agent.out').write_text('\n'.join(json.dumps(event) for event in events))
        with patch.object(adapter, 'bootstrap', side_effect=diagnostic_bootstrap):
            report = self.run_harness(adapter)
        self.assertEqual(report['status'], 'incomplete')
        self.assertTrue(report['restored'] and report['cleanup_verified'])
        self.assertEqual(report['results'], [result])
        self.assertEqual(h.tree(self.app), self.before)
        self.assertEqual(json.loads((self.root / 'result.json').read_text()), report)
        self.assertEqual(self.recover()['status'], 'restored')

    def test_location_preflight_rejects_check_mode_before_swap(self):
        plan = self.prepare()
        plan['config'].update(name='Location Diagnostic', mode='permissions-check')
        (self.root / 'prepared.json').write_text(json.dumps(plan))
        with self.assertRaisesRegex(ValueError, 'requires permissions-request'):
            h.preflight(self.root, self.runner)
        self.assertEqual(h.tree(self.app), self.before)
        self.assertFalse((self.root / 'swap-receipt.json').exists())

    def test_location_diagnostic_static_api_surface(self):
        import ast
        import inspect
        source = inspect.getsource(h.location_diagnostic)
        generated = h.launcher_source(dict(name='Location Diagnostic', mode='permissions-request')).decode()
        for text in (source, generated):
            for forbidden in ('requestLocation', 'startUpdatingLocation', 'requestAlwaysAuthorization',
                              'activateWithOptions', 'setActivationPolicy', 'sharedApplication', 'activeApplication'):
                self.assertNotIn(forbidden, text)
        tree = ast.parse(source)
        attributes = {n.attr for n in ast.walk(tree) if isinstance(n, ast.Attribute)}
        self.assertNotIn('location', attributes)
        self.assertNotIn('Popen', attributes)
        self.assertNotIn('run', attributes)
        self.assertNotIn('socket', attributes)
        self.assertNotIn('connect', attributes)
        self.assertNotIn('runningApplicationsWithBundleIdentifier_', attributes)
        self.assertEqual(source.count('requestWhenInUseAuthorization()'), 1)

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

    def test_default_dependency_checker_is_used_for_admission_and_prebootstrap(self):
        self.prepare()
        install, _ = h.helpers()
        with patch.object(install, 'no_live_native_dependency', return_value=True) as dependency:
            result = h.run(self.root, live=True, runner=self.runner, adapter=FakeLive())
        self.assertTrue(result['restored'])
        self.assertEqual(dependency.call_count, 2)
        for call in dependency.call_args_list:
            self.assertEqual(call.args, (self.base, {}))

    def test_missing_process_receipts_cannot_claim_cleanup(self):
        self.prepare()
        with self.assertRaises(AssertionError):
            h.process_tree_gone(self.root)

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

    def test_empty_process_receipts_use_independent_census(self):
        self.prepare()
        # Current process proves the census is not an empty/error response.
        census = {os.getpid(): (os.getuid(), os.getpgrp())}
        record = dict(pid=os.getpid(), uid=os.getuid(), executable='/fixture/observer',
                      argv=['/fixture/observer'])
        with patch.object(h, 'process_census', return_value=census, create=True), \
                patch.object(h, 'kernel_identity', return_value=record, create=True):
            self.assertTrue(h.process_tree_gone(self.root))

    def test_real_cleanup_adapter_bootstrap_failure_restores_without_records(self):
        self.prepare()
        adapter = h.Live()
        from types import SimpleNamespace
        def command(*args):
            if args[0] == 'print':
                return SimpleNamespace(returncode=113, stdout='', stderr='Could not find service')
            return SimpleNamespace(returncode=5, stdout='', stderr='fixture bootstrap error')
        census = {os.getpid(): (os.getuid(), os.getpgrp())}
        record = dict(pid=os.getpid(), uid=os.getuid(), executable='/fixture/observer',
                      argv=['/fixture/observer'])
        def once(predicate, seconds):
            self.assertTrue(predicate(), 'Cleanup must independently prove absence')
            return True
        with patch.object(adapter, 'command', side_effect=command), \
                patch.object(h, 'process_census', return_value=census, create=True), \
                patch.object(h, 'kernel_identity', return_value=record, create=True), \
                patch.object(h, 'wait', side_effect=once):
            result = self.run_harness(adapter)
        self.assertEqual(result['status'], 'failed')
        self.assertTrue(result['cleanup_verified'] and result['restored'])
        self.assertEqual(h.tree(self.app), self.before)

    def test_legacy_service_loss_after_cleanup_does_not_block_restore(self):
        self.prepare()
        install, _ = h.helpers()
        adapter = FakeLive()
        def dependency(*args):
            if 'cleanup' in adapter.events:
                raise ValueError('legacy service stopped independently')
            return True
        with patch.object(install, 'no_live_native_dependency', side_effect=dependency):
            result = h.run(self.root, live=True, runner=self.runner, adapter=adapter)
        self.assertTrue(result['restored'])
        self.assertEqual(h.tree(self.app), self.before)

    def test_recovery_cleans_experiment_before_baseline_drift_refusal(self):
        self.prepare()
        self.run_harness(FakeLive('cleanup'))
        adapter = FakeLive()
        with patch.object(h, 'baseline', side_effect=ValueError('legacy drift')):
            with self.assertRaisesRegex(ValueError, 'legacy drift'):
                h.recover(self.root, live=True, runner=self.runner, adapter=adapter,
                          dependency=lambda *_: True)
        self.assertIn('cleanup', adapter.events)
        self.assertTrue((self.root / 'original.app').exists())

    def test_census_distinguishes_exited_zombie_and_unreadable_live_process(self):
        self.prepare()
        from types import SimpleNamespace
        census = {os.getpid(): (os.getuid(), os.getpgrp())}
        for state, expected in [('Z', True), ('S', False), ('', False)]:
            with self.subTest(state=state), \
                    patch.object(h, 'process_census', return_value=census), \
                    patch.object(h, 'kernel_identity', side_effect=ValueError('unreadable')), \
                    patch.object(h.subprocess, 'run', return_value=SimpleNamespace(returncode=0, stdout=state)):
                self.assertEqual(h.process_tree_gone(self.root), expected)

    def test_census_refuses_live_artifact_users_and_unknown_scans(self):
        self.prepare()
        census = {os.getpid(): (os.getuid(), os.getpgrp())}
        paths = [str(self.app / h.BINARY), str(self.root / 'permission-python'), '/fixture/python']
        for exe in paths:
            record = dict(pid=os.getpid(), uid=os.getuid(), executable=exe,
                          argv=[exe, str(self.root / 'production_launcher.py')])
            with self.subTest(exe=exe), patch.object(h, 'process_census', return_value=census), \
                    patch.object(h, 'kernel_identity', return_value=record):
                self.assertFalse(h.process_tree_gone(self.root))
        with patch.object(h, 'process_census', side_effect=OSError('census unavailable')):
            with self.assertRaises(OSError):
                h.process_tree_gone(self.root)

    def test_restoration_refuses_remaining_artifact_users(self):
        self.prepare()
        adapter = FakeLive()
        with patch.object(adapter, 'restorable', return_value=False):
            result = self.run_harness(adapter)
        self.assertFalse(result['restored'])
        self.assertTrue((self.root / 'original.app').exists())

    def test_bootout_timeout_still_verifies_absence(self):
        self.prepare()
        adapter = h.Live()
        with patch.object(adapter, 'command', side_effect=OSError('bootout spawn')), \
                patch.object(adapter, 'absent', return_value=True), \
                patch.object(h, 'process_tree_gone', return_value=True) as scan:
            self.assertTrue(adapter.cleanup('fixture', self.root))
        scan.assert_called_once_with(self.root)

    def test_code_payload_only_signature_may_change(self):
        a = macho()
        self.assertEqual(h.code_payload(a), h.code_payload(a[:-16] + b'T' * 16))
        self.assertNotEqual(h.code_payload(a), h.code_payload(a[:8] + b'X' + a[9:]))


if __name__ == '__main__':
    unittest.main()
