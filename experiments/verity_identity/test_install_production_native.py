"""Offline install tests; no native commands, app imports or real state access."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import unittest
from unittest.mock import patch

import stage_production_native as stage
import install_production_native as install
from test_stage_production_native import StageTests


class InstallTests(unittest.TestCase):
    def setUp(self):
        StageTests.setUp(self)
        (self.home / 'Applications').mkdir()
        (self.base / 'control-versions').mkdir()
        self.originals = {}
        for index, name in enumerate(stage.wrappers(self.base, self.base / 'control-versions/old')):
            (self.base / name).chmod(0o700 if index % 2 else 0o640)
            self.originals[name] = install.snapshot(self.base / name)
        # Real independent source/runtime fixtures, not application imports.
        for role in stage.ROLES:
            source = self.root / ('source-' + role)
            runtime = self.root / ('runtime-' + role)
            source.mkdir()
            runtime.mkdir()
            (source / 'tiny.py').write_text('VALUE = 7\n')
            (runtime / 'python').write_text('#!/bin/sh\nexec ' + sys.executable + ' "$@"\n')
            (runtime / 'python').chmod(0o700)
            self.manifest['services'][role].update(
                repo=str(source), cwd=str(source), argv=[str(runtime / 'python'), '-m', 'tiny'],
                inventory=stage.inventory(source), runtimes=[dict(root=str(runtime), inventory=stage.inventory(runtime))],
                env_files=[], env={'HERMES_HOME': str(self.root / 'state')}, probe_modules=[])
        self.save()
        self.stage()
        self.selected_before = self.selected.read_bytes()
        self.plists_before = {r: Path(self.manifest['services'][r]['plist_path']).read_bytes() for r in stage.ROLES}

    save = StageTests.save
    stage = StageTests.stage
    runner = StageTests.runner

    def verifier(self, argv, **kwargs):
        self.assertEqual(argv[:3], ['/usr/bin/codesign', '--verify', '--strict'])
        self.assertIn(Path(argv[-1]), [self.root / 'stage/Verity.app', self.home / 'Applications/Verity.app'])

    def go(self):
        return install.install(self.root / 'stage', self.base, self.home, approve=True, runner=self.verifier)

    def restore(self, **kwargs):
        return install.restore(self.base, self.home, approve=True,
                               dependency_check=kwargs.get('dependency_check', lambda *_: True))

    def preserved(self):
        self.assertEqual(self.selected.read_bytes(), self.selected_before)
        for r in stage.ROLES:
            self.assertEqual(Path(self.manifest['services'][r]['plist_path']).read_bytes(), self.plists_before[r])
        self.assertEqual((self.base / 'candidate-release.json').read_text(), 'unrelated pending candidate')

    def test_install_preserves_legacy_and_runs_installed_synthetic_check(self):
        self.assertEqual(self.go()['status'], 'installed')
        self.preserved()
        # Remove the stage: installed execution cannot rely on experiment artifacts.
        shutil.rmtree(self.root / 'stage')
        env = {'HOME': str(self.home), 'HERMES_HOME': str(self.root / 'state'),
               'PATH': '/usr/bin:/bin', 'PYTHONDONTWRITEBYTECODE': '1',
               'TMPDIR': str(self.root / 'bootstrap-tmp')}
        for role in stage.ROLES:
            result = subprocess.run([sys.executable, '-B', str(self.base / 'production_launcher.py'), role, '--check'],
                                    env=env, cwd=self.home, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn('production runtime OK: ' + role, result.stdout)
        self.assertEqual(self.restore()['status'], 'restored_artifacts_retained')
        for n, record in self.originals.items():
            self.assertEqual(install.snapshot(self.base / n), record)
        self.assertTrue((self.home / 'Applications/Verity.app').is_dir())

    def test_fail_after_each_publication_and_restore_exact_modes(self):
        # Each subcase has its own stage/home; injected error occurs after real rename.
        for target in self.originals:
            with self.subTest(target=target):
                fixture = InstallTests()
                fixture.setUp()
                try:
                    write = install.atomic_write
                    def fail(path, data):
                        write(path, data)
                        if Path(path) == fixture.base / target:
                            raise OSError('injected after publication')
                    with patch.object(install, 'atomic_write', side_effect=fail):
                        with self.assertRaises(OSError):
                            fixture.go()
                    fixture.restore()
                    fixture.preserved()
                    for n, record in fixture.originals.items():
                        self.assertEqual(install.snapshot(fixture.base / n), record)
                finally:
                    fixture.doCleanups()

    def test_partial_artifact_copy_is_retained_and_wrappers_recover(self):
        copy = install.copy_tree
        def fail(source, destination, **kwargs):
            copy(source, destination, **kwargs)
            if destination == self.home / 'Applications/Verity.app':
                raise OSError('interrupted after app copy')
        with patch.object(install, 'copy_tree', side_effect=fail):
            with self.assertRaises(OSError):
                self.go()
        self.restore()
        for name, record in self.originals.items():
            self.assertEqual(install.snapshot(self.base / name), record)
        self.assertTrue((self.home / 'Applications/Verity.app').exists())

    def test_restore_interruption_is_retryable(self):
        self.go()
        write = install.atomic_write
        target = self.base / 'production_launcher.py'
        def fail(path, data):
            write(path, data)
            if Path(path) == target:
                raise OSError('interrupted restore')
        with patch.object(install, 'atomic_write', side_effect=fail):
            with self.assertRaises(OSError):
                self.restore()
        self.restore()
        for name, record in self.originals.items():
            self.assertEqual(install.snapshot(self.base / name), record)

    def test_wrong_home_and_drift_refuse_before_receipt(self):
        with self.assertRaises(Exception):
            install.install(self.root / 'stage', self.base, self.root, approve=True, runner=self.verifier)
        self.selected.write_bytes(self.selected_before + b' ')
        with self.assertRaises(Exception):
            self.go()
        self.assertFalse((self.base / install.RECEIPT).exists())

    def test_unresolved_activation_and_existing_install_refused(self):
        controller = install.Controller(self.base)
        controller.save_transaction(dict(reload=False, operation_id='test', authorization='same-release-restart'), 'prepared')
        with self.assertRaises(Exception):
            self.go()
        self.assertFalse((self.base / install.RECEIPT).exists())
        (self.base / 'activation-transaction.json').unlink()
        self.go()
        with self.assertRaises(Exception):
            self.go()

    def test_native_selection_and_unknown_live_dependency_refuse_restore(self):
        self.go()
        with self.assertRaises(Exception):
            self.restore(dependency_check=lambda *_: None)
        self.selected.write_bytes((self.root / 'stage/candidate-release.json').read_bytes())
        with self.assertRaises(Exception):
            self.restore()

    def test_missing_malformed_receipt_and_symlink_fail_closed(self):
        with self.assertRaises(Exception):
            self.restore()
        (self.base / install.RECEIPT).write_text('{}')
        with self.assertRaises(Exception):
            self.restore()
        (self.base / install.RECEIPT).unlink()
        original = self.base / 'production_launcher.py'
        original.rename(self.base / 'saved.py')
        original.symlink_to(self.base / 'saved.py')
        with self.assertRaises(Exception):
            self.go()

    def test_explicit_opt_in_and_existing_artifact(self):
        with self.assertRaises(Exception):
            install.install(self.root / 'stage', self.base, self.home, runner=self.verifier)
        (self.home / 'Applications/Verity.app').mkdir()
        with self.assertRaises(Exception):
            self.go()

    def test_corrupt_stage_and_control_extra_file(self):
        version = self.root / 'stage/control-versions/native-v1'
        (version / 'surprise.py').write_text('raise RuntimeError()')
        with self.assertRaises(Exception):
            self.go()
        self.assertFalse((self.base / install.RECEIPT).exists())


if __name__ == '__main__':
    unittest.main()
