"""Offline install tests; no native commands, app imports or real state access."""
import copy
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
from restart_production import ControlError, Host


class InstallTests(unittest.TestCase):
    def setUp(self):
        StageTests.setUp(self)
        (self.home / 'Applications').mkdir()
        (self.base / 'control-versions').mkdir()
        (self.base / 'control.lock').touch(mode=0o600)
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
        python = self.manifest['services']['agent']['argv'][0]
        self.manifest['services']['agent']['argv'] = [
            python, '-m', 'hermes_cli.stderr_timestamp', '--error-log', str(self.root / 'fixture.error.log'),
            '--', python, '-m', 'hermes_cli.main', 'gateway', 'run', '--external-supervisor']
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

    def test_lock_prerequisite_and_recovery_under_group_writable_umask(self):
        lock = self.base / 'control.lock'
        lock.unlink()
        prior = os.umask(0o002)
        self.addCleanup(os.umask, prior)
        # A schema-2 install must not create a lock that its restore would reject.
        with patch.object(install, 'copy_tree', wraps=install.copy_tree) as copying:
            with self.assertRaisesRegex(ControlError, 'Missing path'):
                self.go()
            copying.assert_not_called()
        self.assertFalse(lock.exists())
        self.assertFalse((self.base / install.RECEIPT).exists())
        lock.touch(mode=0o666)
        with self.assertRaisesRegex(ControlError, 'Writable-by-others'):
            self.go()
        lock.chmod(0o600)  # Fixture provisioning, never a production repair.
        write = install.atomic_write
        def fail(path, data):
            write(path, data)
            if Path(path) == self.base / 'production_launcher.py':
                raise OSError('injected after publication under umask 0002')
        with patch.object(install, 'atomic_write', side_effect=fail):
            with self.assertRaisesRegex(OSError, 'after publication'):
                self.go()
        self.assertEqual(lock.stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.restore()['status'], 'restored_artifacts_retained')
        for name, original in self.originals.items():
            self.assertEqual(install.snapshot(self.base / name), original)
        receipt_before = (self.base / install.RECEIPT).read_bytes()
        lock.unlink()
        with self.assertRaisesRegex(ControlError, 'Missing path'):
            self.restore()
        self.assertFalse(lock.exists())
        self.assertEqual((self.base / install.RECEIPT).read_bytes(), receipt_before)
        self.preserved()

    def test_default_restore_dependency_checker_uses_both_identity_layers(self):
        self.go()
        c = install.Controller(self.base)
        definitions = c.definitions(self.manifest)
        jobs = {c.target(self.manifest, role): {
            'pid': 110 + index, 'argv': definitions[role]['ProgramArguments'],
            'cwd': definitions[role]['WorkingDirectory']}
            for index, role in enumerate(stage.ROLES)}
        records = {110 + index: dict(pid=110 + index, ppid=1, uid=os.getuid(),
            argv=self.manifest['services'][role]['argv'],
            executable=str(Path(self.manifest['services'][role]['argv'][0]).resolve()),
            start_time=100.0 + index) for index, role in enumerate(stage.ROLES)}
        with patch.object(Host, 'job', side_effect=lambda target: copy.deepcopy(jobs[target])), \
                patch.object(Host, 'process_identity', side_effect=lambda pid: copy.deepcopy(records[pid])):
            # Do not inject dependency_check: actual default + definitions/loaded run.
            self.assertEqual(install.restore(self.base, self.home, approve=True)['status'],
                             'restored_artifacts_retained')
        for role in stage.ROLES:
            for mutation in ('executable', 'argv', 'ppid', 'uid', 'birth', 'missing_pid', 'native_cached', 'unavailable'):
                with self.subTest(role=role, mutation=mutation):
                    bad_jobs, bad_records = copy.deepcopy(jobs), copy.deepcopy(records)
                    target = c.target(self.manifest, role)
                    pid = jobs[target]['pid']
                    if mutation in ('executable', 'argv', 'ppid', 'uid'):
                        bad_records[pid][mutation] = {
                            'executable': '/fixture/wrong-python', 'argv': ['/fixture/wrong-command'],
                            'ppid': 42, 'uid': os.getuid() + 1}[mutation]
                    elif mutation == 'missing_pid':
                        bad_jobs[target]['pid'] = None
                    elif mutation == 'native_cached':
                        bad_jobs[target]['argv'] = ['/fixture/VerityServiceHost', role]
                    calls = {}
                    def identity(value):
                        if mutation == 'unavailable' and value == pid:
                            raise OSError('fixture identity unavailable')
                        record = copy.deepcopy(bad_records[value])
                        calls[value] = calls.get(value, 0) + 1
                        if mutation == 'birth' and value == pid and calls[value] > 1:
                            record['start_time'] += 1
                        return record
                    before = (self.base / install.RECEIPT).read_bytes()
                    with patch.object(Host, 'job', side_effect=lambda t: copy.deepcopy(bad_jobs[t])), \
                            patch.object(Host, 'process_identity', side_effect=identity), \
                            patch.object(install, 'atomic_write', wraps=install.atomic_write) as writes:
                        with self.assertRaises((ControlError, KeyError, OSError)):
                            install.restore(self.base, self.home, approve=True)
                        writes.assert_not_called()
                    self.assertEqual((self.base / install.RECEIPT).read_bytes(), before)
                    for name, original in self.originals.items():
                        self.assertEqual(install.snapshot(self.base / name), original)

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
