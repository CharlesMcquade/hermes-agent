"""Offline counterexamples, not a maintenance implementation or live proof.

Run directly with -I -B and disposable HOME/HERMES_HOME/state/TMPDIR.
No test discovery, application imports, subprocesses, or native observations.
"""
from contextlib import ExitStack, redirect_stdout
import importlib
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch


class MaintenanceBoundaryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.guards = ExitStack()
        cls.addClassCleanup(cls.guards.close)

        def forbidden(*args, **kwargs):
            raise AssertionError('Offline boundary: external operation forbidden')

        # Installed before importing any production-control code.
        for target in ('subprocess.Popen', 'subprocess.run', 'os.system',
                       'os.execve', 'os.execv', 'os.posix_spawn', 'os.fork',
                       'os.kill', 'ctypes.CDLL', 'ctypes.PyDLL',
                       'socket.socket', 'socket.create_connection'):
            cls.guards.enter_context(patch(target, side_effect=forbidden))
        scratch = Path(os.environ['TMPDIR']).resolve(strict=True)
        for key in ('HOME', 'HERMES_HOME', 'HERMES_WEBUI_STATE_DIR'):
            if not Path(os.environ[key]).resolve(strict=True).is_relative_to(scratch):
                raise AssertionError('Disposable state must be inside TMPDIR')
        controls = Path(__file__).resolve().parents[2] / 'scripts/production_control'
        cls.guards.enter_context(patch.object(sys, 'path', [str(controls), *sys.path]))
        cls.controller = importlib.import_module('restart_production')
        cls.launcher = importlib.import_module('production_launcher')

    def test_unlocked_launcher_reaches_exec_at_each_app_rename_boundary(self):
        """The real launcher attempts exec despite the real controller lock."""
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            app, retained, pending = (base / n for n in ('Verity.app', 'v1.app', 'v2.app'))
            app.mkdir()
            pending.mkdir()
            runtime = base / 'runtime'
            runtime.mkdir()
            (runtime / 'fixture.txt').write_text('no application code')
            executable = str(Path(sys.executable).resolve())
            item = dict(repo=str(runtime), inventory=self.launcher.inventory(runtime),
                        argv=[executable, '-c', 'raise SystemExit(0)'], cwd=str(runtime),
                        commit='fixture', env_files=[], probe_modules=[])
            manifest = base / 'production-release.json'
            manifest.write_text(json.dumps(dict(schema_version=2, services={'agent': item})))
            lock = base / 'control.lock'
            lock.touch(mode=0o600)
            identity = (lock.stat().st_dev, lock.stat().st_ino)

            class ExecIntercepted(Exception):
                pass

            with self.controller.control_lock(base):
                for boundary in ('before_retention', 'after_retention', 'after_publication'):
                    with self.subTest(boundary=boundary):
                        if boundary == 'after_retention':
                            app.rename(retained)
                        elif boundary == 'after_publication':
                            pending.rename(app)
                        with patch.object(sys, 'argv', ['launcher', 'agent', '--manifest', str(manifest)]), \
                             patch.object(os, 'chdir') as chdir, \
                             patch.object(os, 'execve', side_effect=ExecIntercepted) as execute, \
                             redirect_stdout(io.StringIO()):
                            with self.assertRaises(ExecIntercepted):
                                self.launcher.main()
                            execute.assert_called_once()
                            self.assertEqual(execute.call_args.args[:2], (executable, item['argv']))
                            chdir.assert_called_once_with(str(runtime))
                        self.assertEqual((lock.stat().st_dev, lock.stat().st_ino), identity)

    def test_preimported_controller_is_not_revoked_by_lock_or_replacement(self):
        """A retained entry point remains usable after maintenance releases flock."""
        retained_main = self.controller.main  # Import predates maintenance ownership.
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            lock = base / 'control.lock'
            lock.touch(mode=0o600)
            wrapper = base / 'restart_production.py'
            wrapper.write_text('v1 fixture wrapper')
            identity = (lock.stat().st_dev, lock.stat().st_ino)
            # Observe entry into the existing controller, without process reads.
            with patch.object(self.controller.Controller, 'load', return_value={}) as load, \
                 patch.object(self.controller.Controller, 'preflight'), \
                 patch.object(self.controller.Controller, 'definitions', return_value={}), \
                 patch.object(self.controller.Controller, 'loaded'):
                with self.controller.control_lock(base):
                    with self.assertRaises(self.controller.ControlError):
                        retained_main(['--base', str(base)])
                    load.assert_not_called()
                    self.controller.atomic_write(wrapper, b'v2 fixture wrapper')
                self.assertEqual(retained_main(['--base', str(base)]),
                                 {'status': 'checked', 'changed': False})
                load.assert_called_once()
            self.assertEqual(wrapper.read_bytes(), b'v2 fixture wrapper')
            self.assertEqual((lock.stat().st_dev, lock.stat().st_ino), identity)


if __name__ == '__main__':
    unittest.main(verbosity=2)
