"""Offline guard suite. Run directly with an approved Python, -I -B.

Tripwires are installed BEFORE harness/helper imports. No signing, native API,
process observation, service execution, or network is permitted by this suite.
The retained executable is read/copied as data only; labs are retained as evidence.
"""
import ctypes
import importlib.util
import importlib.abc
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import unittest
from unittest.mock import patch
import uuid


def forbidden(*args, **kwargs):
    raise AssertionError('OFFLINE TRIPWIRE: native/process/network operation')


class NoApplications(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if fullname.split('.')[0] in {'hermes_cli', 'gateway', 'tools', 'run_agent', 'hermes_state', 'server'}:
            raise AssertionError('OFFLINE TRIPWIRE: application import ' + fullname)
        return None


sys.meta_path.insert(0, NoApplications())
GUARDS = [patch.object(subprocess, name, forbidden) for name in ('Popen', 'run', 'call', 'check_call', 'check_output')]
GUARDS += [patch.object(socket, 'socket', forbidden), patch.object(socket, 'create_connection', forbidden),
           patch.object(ctypes, 'CDLL', forbidden), patch.object(ctypes, 'PyDLL', forbidden),
           patch.object(os, 'system', forbidden), patch.object(os, 'kill', forbidden),
           patch.object(os, 'killpg', forbidden), patch.object(os, 'getpgid', forbidden)]
for guard in GUARDS:
    guard.start()
sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location('control_lab', Path(__file__).with_name('verify_control_refresh_live.py'))
h = importlib.util.module_from_spec(spec)
spec.loader.exec_module(h)


class IsolationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.root = h.SCRATCH / ('verity-control-live-' + uuid.uuid4().hex)
        cls.result = h.build(cls.root, 49271)
        cls.pin = cls.result['build_sha256']
        print('OFFLINE_EVIDENCE=' + json.dumps(cls.result), flush=True)

    def test_build_and_preflight_have_no_native_side_effects(self):
        report = h.preflight(self.root, self.pin)
        self.assertFalse(self.result['live_executed'])
        self.assertEqual(report['presign_sha256'], h.digest(h.HOST.read_bytes()))
        self.assertFalse((self.root / 'native-live-report.json').exists())

    def test_default_live_refuses_before_read_or_import(self):
        with patch.object(h, 'preflight', forbidden), patch.object(h, 'helpers', forbidden):
            with self.assertRaisesRegex(ValueError, 'Explicit --live'):
                h.live(Path('/not-a-lab'), 'not-a-pin')

    def test_unsafe_roots_before_helpers(self):
        for root in (Path('/tmp/verity-control-live-' + 'a' * 32), self.root, h.SCRATCH / 'wrong-name'):
            with self.subTest(root=root), patch.object(h, 'helpers', forbidden):
                with self.assertRaises(ValueError):
                    h.build(root, 49271)

    def test_bad_port_before_retained_artifact_read(self):
        root = h.SCRATCH / ('verity-control-live-' + uuid.uuid4().hex)
        for port in (None, 0, 65536, True, '49271'):
            with self.subTest(port=port), patch.object(h, 'helpers', forbidden):
                with self.assertRaises(ValueError):
                    h.build(root, port)
        self.assertFalse(root.exists())

    def test_wrong_pin(self):
        for pin in (None, 'A' * 64, '0' * 64):
            with self.subTest(pin=pin), self.assertRaises(ValueError):
                h.preflight(self.root, pin)

    def test_unexpected_import_file_rejected(self):
        path = self.root / 'sitecustomize.py'
        path.write_text('raise RuntimeError("must not import")\n')
        try:
            with self.assertRaisesRegex(ValueError, 'Unexpected lab files'):
                h.preflight(self.root, self.pin)
        finally:
            path.unlink()

    def test_symlink_even_with_same_bytes_rejected(self):
        path = self.root / 'agent.plist'
        saved = path.read_bytes()
        replacement = self.root / 'saved-plist'
        replacement.write_bytes(saved)
        path.unlink()
        path.symlink_to(replacement)
        try:
            with self.assertRaisesRegex(ValueError, 'symlink'):
                h.preflight(self.root, self.pin)
        finally:
            path.unlink()
            path.write_bytes(saved)
            replacement.unlink()

    def test_manifest_drift_refuses_before_live_helpers(self):
        path = self.root / 'production-release.json'
        original = path.read_bytes()
        altered = json.loads(original)
        altered['health_url'] = 'http://example.com/health'
        path.write_bytes(h.encoded(altered))
        try:
            with patch.object(h, 'helpers', forbidden):
                with self.assertRaisesRegex(ValueError, 'artifact drift'):
                    h.live(self.root, self.pin, approved=True)
        finally:
            path.write_bytes(original)

    def test_exact_synthetic_topology_and_environment(self):
        manifest = json.loads((self.root / 'production-release.json').read_bytes())
        agent = manifest['services']['agent']
        argv = agent['argv']
        self.assertEqual(len(argv), 12)
        self.assertEqual(argv[1:4], ['-m', 'hermes_cli.stderr_timestamp', '--error-log'])
        self.assertEqual(argv[5:], ['--', sys.executable, '-m', 'hermes_cli.main', 'gateway', 'run', '--external-supervisor'])
        self.assertEqual(agent['env']['PYTHONPATH'], str(self.root / 'agent'))
        for role in h.ROLES:
            item = manifest['services'][role]
            self.assertEqual(set(item), {'repo', 'cwd', 'commit', 'argv', 'inventory', 'plist_path', 'env'})
            for key in ('HOME', 'HERMES_HOME', 'TMPDIR'):
                self.assertTrue(Path(item['env'][key]).is_relative_to(self.root))
        self.assertTrue(manifest['health_url'].startswith('http://127.0.0.1:'))
        self.assertEqual((self.root / 'production_launcher.py').read_bytes(),
                         (h.SOURCE / 'scripts/production_control/production_launcher.py').read_bytes())
        for p in self.root.rglob('*.py'):
            compile(p.read_bytes(), str(p), 'exec')

    def test_writable_controls_refused(self):
        path = self.root / 'restart_production.py'
        path.chmod(0o644)
        try:
            with self.assertRaisesRegex(ValueError, 'stay sealed'):
                h.preflight(self.root, self.pin)
        finally:
            path.chmod(0o444)

    def test_machine_code_parser_refuses_non_native(self):
        with self.assertRaises(ValueError):
            h.machine_code(b'not a native binary')


if __name__ == '__main__':
    unittest.main(verbosity=2)
