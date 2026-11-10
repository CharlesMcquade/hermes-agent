"""Bootstrap-pointer activation and rollback tests with disposable paths."""
import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile
import unittest
from unittest.mock import patch
from types import SimpleNamespace

import verity_bootstrap_activation as activation


class ActivationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name) / 'maintenance'
        self.base.mkdir()
        self.bootstrap_root = self.base / 'bootstrap-runtime-v1'
        self.new_python = self.bootstrap_root / 'venv/bin/python'
        self.old_python = '/old/runtime/venv/bin/python'
        self.compatibility = self.base / 'bootstrap-link'
        self.compatibility.symlink_to(self.old_python)
        self.dependency = self.base / 'BOOTSTRAP-DEPENDENCY.json'
        self.dependency.write_text(json.dumps({
            'role': 'fixture compatibility', 'path': str(self.compatibility),
            'target': self.old_python, 'source_inventory_verified': True,
            'preserve_until_signed_launcher_migration': True,
        }))
        self.dependency.chmod(0o444)
        self.watchdog = self.base / 'watchdog.py'
        self.watchdog_raw = (
            '#!/bin/sh\nexec ' + self.old_python +
            ' -B ' + str(self.watchdog) +
            ' >> ' + str(self.base / 'watchdog.log 2>&1') + '\n'
        ).encode()
        (self.base / 'webui-watchdog.sh').write_bytes(self.watchdog_raw)
        self.watchdog_wrapper = self.base / 'webui-watchdog.sh'
        self.manager = self.base / 'service-manager.json'
        self.manager.write_bytes(json.dumps({'webui_restart_preflight': [
            self.old_python, str(self.base / 'production_launcher.py'),
            'webui', '--check']}).encode())
        self.manifest = self.base / 'production-release.json'
        self.manifest.write_text('{}\n')
        self.output = self.base / 'activation-evidence'
        self.runtime_checks = []

    def descriptor(self, root):
        return {'payload': {'python': str(self.new_python)}}

    def fake_run(self, argv, **kwargs):
        if argv[0] == '/bin/sh':
            return SimpleNamespace(returncode=0, stdout='')
        role = argv[4]
        self.runtime_checks.append(argv[0])
        return SimpleNamespace(returncode=0,
                               stdout='production runtime OK: ' + role)

    def make_plan(self):
        with patch.object(activation.bootstrap, 'verify', side_effect=self.descriptor), \
                patch.object(activation, 'native_identity', return_value=None):
            return activation.plan(
                self.bootstrap_root, self.compatibility, self.dependency,
                self.watchdog_wrapper, self.manager, self.output, self.manifest)

    def plan_pin(self):
        return activation.bootstrap.digest((self.output / activation.PLAN_NAME).read_bytes())

    def snapshot(self):
        return {
            'link': os.readlink(self.compatibility),
            'dependency': self.dependency.read_bytes(),
            'watchdog': self.watchdog_wrapper.read_bytes(),
            'manager': self.manager.read_bytes(),
        }

    def test_activation_readback_and_four_preflight_checks(self):
        self.make_plan()
        self.assertEqual(self.snapshot()['link'], self.old_python)
        with patch.object(activation.bootstrap, 'verify', side_effect=self.descriptor), \
                patch.object(activation, 'native_identity', return_value=None), \
                patch.object(activation.subprocess, 'run', side_effect=self.fake_run):
            result = activation.apply(self.output / activation.PLAN_NAME, True, self.plan_pin())
        self.assertEqual(result['status'], 'activated')
        self.assertEqual(result['preflight_checks'], ['webui', 'webui', 'agent', 'agent'])
        self.assertEqual(self.snapshot()['link'], str(self.new_python))
        self.assertEqual(self.runtime_checks, [str(self.new_python)] * 4)
        self.assertEqual(json.loads(self.dependency.read_text())['target'], str(self.new_python))
        self.assertEqual(self.watchdog_wrapper.read_text(),
                         '#!/bin/sh\nexec ' + str(self.new_python) + ' -B '
                         + str(self.watchdog) + ' >> '
                         + str(self.base / 'watchdog.log') + ' 2>&1\n')
        self.assertEqual(json.loads(self.manager.read_text())['webui_restart_preflight'][0],
                         str(self.new_python))
        self.assertEqual(self.dependency.stat().st_mode & 0o777, 0o444)

    def test_generated_wrapper_has_real_shell_semantics(self):
        self.make_plan()
        with patch.object(activation.bootstrap, 'verify', side_effect=self.descriptor), \
                patch.object(activation, 'native_identity', return_value=None), \
                patch.object(activation.subprocess, 'run', side_effect=self.fake_run):
            activation.apply(self.output / activation.PLAN_NAME, True, self.plan_pin())
        result = subprocess.run(['/bin/sh', str(self.watchdog_wrapper)],
                                capture_output=True, timeout=10)
        self.assertNotEqual(result.returncode, 0)  # No sentinel interpreter exists here.
        # The wrapper's redirection is real: its interpreter error is logged at
        # the documented destination, not silently hidden from this assertion.
        message = (self.base / 'watchdog.log').read_text(errors='replace')
        self.assertNotIn('exec: exec:', message)
        self.assertNotIn("exec: exec: not found", message)
        self.assertIn(str(self.new_python), message)

    def test_changed_input_never_mutates_pointer(self):
        self.make_plan()
        self.watchdog_wrapper.write_bytes(self.watchdog_wrapper.read_bytes() + b'\n')
        before = self.snapshot()
        with patch.object(activation.bootstrap, 'verify', side_effect=self.descriptor), \
                patch.object(activation, 'native_identity', return_value=None):
            with self.assertRaisesRegex(RuntimeError, 'changed since planning'):
                activation.apply(self.output / activation.PLAN_NAME, True, self.plan_pin())
        self.assertEqual(self.snapshot(), before)

    def test_partial_failure_restores_every_pointer(self):
        self.make_plan()
        before = self.snapshot()
        real = activation.bootstrap.atomic_write
        def fail_after_wrapper(path, raw, mode):
            real(path, raw, mode)
            if path == self.watchdog_wrapper:
                raise RuntimeError('injected wrapper publication failure')
        with patch.object(activation.bootstrap, 'verify', side_effect=self.descriptor), \
                patch.object(activation, 'native_identity', return_value=None), \
                patch.object(activation.subprocess, 'run', side_effect=self.fake_run), \
                patch.object(activation.bootstrap, 'atomic_write', side_effect=fail_after_wrapper):
            with self.assertRaisesRegex(RuntimeError, 'wrapper publication failure'):
                activation.apply(self.output / activation.PLAN_NAME, True, self.plan_pin())
        self.assertEqual(self.snapshot(), before)

    def test_selected_manifest_change_refuses_before_any_input_change(self):
        self.make_plan()
        self.manifest.write_text('{"changed": true}\n')
        before = self.snapshot()
        with patch.object(activation.bootstrap, 'verify', side_effect=self.descriptor), \
                patch.object(activation, 'native_identity', return_value=None):
            with self.assertRaisesRegex(RuntimeError, 'Selected application manifest changed'):
                activation.apply(self.output / activation.PLAN_NAME, True, self.plan_pin())
        self.assertEqual(self.snapshot(), before)

    def test_apply_requires_approval_before_any_input_change(self):
        self.make_plan()
        before = self.snapshot()
        with self.assertRaisesRegex(RuntimeError, 'approve'):
            activation.apply(self.output / activation.PLAN_NAME, False, self.plan_pin())
        self.assertEqual(self.snapshot(), before)


if __name__ == '__main__':
    unittest.main()
