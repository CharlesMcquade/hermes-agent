"""One-hop real filesystem composition; native/signature observations are fixtures."""
import json
from pathlib import Path
import unittest
from unittest.mock import patch

import install_production_native as install
from restart_production import ControlError, Host
import stage_production_native as stage
from test_install_production_native import InstallTests


class UpgradeTests(unittest.TestCase):
    def setUp(self):
        self.fixture = InstallTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        f = self.fixture
        f.go()
        self.root_bytes = (f.base / install.RECEIPT).read_bytes()
        self.pin = stage.digest(self.root_bytes)
        self.app = f.home / 'Applications/Verity.app'
        self.inode = self.app.stat().st_ino
        self.v1 = {n: install.snapshot(f.base / n) for n in f.originals}
        self.fresh = f.root / 'fresh-stage'
        def fake_native(argv, **kwargs):
            if argv[0] == '/usr/bin/xcrun':
                Path(argv[-1]).write_bytes(b'fixture compiler output, not native code')
                Path(argv[-1]).chmod(0o700)
            else:
                self.assertEqual(argv[0], '/usr/bin/codesign')
                self.assertTrue(Path(argv[-1]).is_relative_to(self.fresh))
        f.stage(root=self.fresh, control_id='native-v2', runner=fake_native)
        self.original_stage_tree = install.tree(f.root / 'stage')
        self.v1_controls = install.tree(f.base / 'control-versions/native-v1')

    def verifier(self, argv, **kwargs):
        self.assertEqual(argv[:3], ['/usr/bin/codesign', '--verify', '--strict'])
        self.assertTrue(Path(argv[-1]).is_relative_to(self.fixture.root))

    def go(self):
        f = self.fixture
        self.assertTrue(callable(getattr(install, 'upgrade', None)), 'bounded upgrade API missing')
        return install.upgrade(self.fresh, f.base, f.home, original_stage=f.root / 'stage',
                               root_sha256=self.pin, approve=True, runner=self.verifier,
                               dependency_check=lambda *_: True)

    def mark_returned(self, upgrade_pin):
        # Synthetic future-controller completion receipt, NOT an executed return.
        f = self.fixture
        install.Controller(f.base).save_transaction(dict(reload=True, operation_id='fixture-return',
            authorization='verified-live-fallback', operation='return-retained-baseline',
            baseline_sha256=self.pin, upgrade_sha256=upgrade_pin), 'verified')

    def test_unreturned_legacy_state_does_not_authorize_wrapper_restore(self):
        self.go()
        f = self.fixture
        with self.assertRaisesRegex(ControlError, 'verified upgraded return'):
            install.restore_upgraded_wrappers(f.base, f.home, root_sha256=self.pin,
                upgrade_sha256=stage.digest((f.base / install.UPGRADE_RECEIPT).read_bytes()),
                approve=True, runner=self.verifier, dependency_check=lambda *_: True)

    def test_first_install_fresh_stage_upgrade_and_postreturn_restore(self):
        f = self.fixture
        result = self.go()
        self.assertEqual(result['status'], 'upgraded_not_activated')
        self.assertEqual((f.base / install.RECEIPT).read_bytes(), self.root_bytes)
        self.assertEqual((f.home / 'Applications/Verity.upgrade-v1.app').stat().st_ino, self.inode)
        for n, text in stage.wrappers(f.base, f.base / 'control-versions/native-v2').items():
            self.assertEqual(install.snapshot(f.base / n), dict(self.v1[n], data=install.base64.b64encode(text.encode()).decode()))
        committed = (f.base / install.UPGRADE_RECEIPT).read_bytes()
        install.recover_upgrade(f.base, f.home, root_sha256=self.pin, approve=True,
                                runner=self.verifier, dependency_check=lambda *_: True)
        self.mark_returned(stage.digest(committed))
        install.restore_upgraded_wrappers(f.base, f.home, root_sha256=self.pin,
                                         upgrade_sha256=stage.digest(committed), approve=True,
                                         runner=self.verifier, dependency_check=lambda *_: True)
        self.assertEqual((f.base / install.UPGRADE_RECEIPT).read_bytes(), committed)
        self.assertEqual((f.base / install.RECEIPT).read_bytes(), self.root_bytes)
        for n, record in f.originals.items():
            self.assertEqual(install.snapshot(f.base / n), record)
        f.preserved()
        self.assertEqual(install.tree(f.root / 'stage'), self.original_stage_tree)
        self.assertEqual(install.tree(f.base / 'control-versions/native-v1'), self.v1_controls)

    def recover(self):
        f = self.fixture
        return install.recover_upgrade(f.base, f.home, root_sha256=self.pin, approve=True,
                                       runner=self.verifier, dependency_check=lambda *_: True)

    def assert_recovered(self):
        f = self.fixture
        self.assertEqual(self.recover()['status'], 'recovered_v1_artifacts_retained')
        self.assertEqual(self.app.stat().st_ino, self.inode)
        self.assertEqual(install.tree(self.app), install.tree(f.root / 'stage/Verity.app'))
        self.assertEqual((f.base / install.RECEIPT).read_bytes(), self.root_bytes)
        self.assertEqual(install.tree(f.root / 'stage'), self.original_stage_tree)
        self.assertEqual(install.tree(f.base / 'control-versions/native-v1'), self.v1_controls)
        for n, record in self.v1.items():
            self.assertEqual(install.snapshot(f.base / n), record)
        f.preserved()
        with self.assertRaises(ControlError):
            self.go()

    def test_every_prewrite_journal_boundary_recovers_without_forward_retry(self):
        phases = ['copy_controls', 'copy_app', 'retain_v1', 'publish_v2',
                  *('publish_' + n for n in self.v1), 'commit']
        for phase in phases:
            for after in (False, True):
                with self.subTest(phase=phase, after=after):
                    f = UpgradeTests()
                    f.setUp()
                    try:
                        observed = []
                        save = install.upgrade_journal
                        def fail(base, plan, actual):
                            observed.append(actual)
                            if actual == phase and not after:
                                raise OSError('target journal boundary')
                            save(base, plan, actual)
                            if actual == phase:
                                raise OSError('target journal boundary')
                        with patch.object(install, 'upgrade_journal', side_effect=fail):
                            with self.assertRaisesRegex(OSError, 'target journal boundary'):
                                f.go()
                        self.assertEqual(observed[-1], phase)
                        if phase == 'copy_controls' and not after:
                            self.assertFalse((f.fixture.base / install.UPGRADE_JOURNAL).exists())
                            self.assertEqual(f.app.stat().st_ino, f.inode)
                        else:
                            f.assert_recovered()
                    finally:
                        f.doCleanups()

    def test_after_each_wrapper_rename_and_app_rename_fsync_failure(self):
        targets = ['retain_v1', 'publish_v2', *self.v1, 'commit']
        for target in targets:
            with self.subTest(target=target):
                f = UpgradeTests()
                f.setUp()
                try:
                    hit = []
                    rename, write = install.os.rename, install.atomic_write
                    def fail_rename(source, dest):
                        rename(source, dest)
                        kind = {'Verity.upgrade-v1.app': 'retain_v1', 'Verity.app': 'publish_v2',
                                install.UPGRADE_RECEIPT: 'commit'}.get(Path(dest).name)
                        if target == kind:
                            hit.append(kind)
                            raise OSError('rename succeeded before fsync')
                    def fail_write(path, data):
                        write(path, data)
                        if Path(path) == f.fixture.base / target:
                            hit.append(target)
                            raise OSError('wrapper rename succeeded')
                    with patch.object(install.os, 'rename', side_effect=fail_rename), \
                            patch.object(install, 'atomic_write', side_effect=fail_write):
                        with self.assertRaises(OSError):
                            f.go()
                    self.assertEqual(hit, [target])
                    if target == 'commit':
                        self.assertEqual(f.recover()['status'], 'committed_verified')
                    else:
                        f.assert_recovered()
                finally:
                    f.doCleanups()

    def test_legacy_restore_cannot_rewrite_root_provenance_after_upgrade(self):
        self.go()
        f = self.fixture
        before = (f.base / install.RECEIPT).read_bytes()
        committed = (f.base / install.UPGRADE_RECEIPT).read_bytes()
        self.mark_returned(stage.digest(committed))
        install.restore_upgraded_wrappers(f.base, f.home, root_sha256=self.pin,
                                         upgrade_sha256=stage.digest(committed), approve=True,
                                         runner=self.verifier, dependency_check=lambda *_: True)
        with self.assertRaisesRegex(ControlError, 'upgrade'):
            f.restore()
        self.assertEqual((f.base / install.RECEIPT).read_bytes(), before)

    def test_unknown_paths_modes_receipts_and_app_bytes_fail_closed(self):
        f = self.fixture
        retained = f.home / 'Applications/Verity.upgrade-v1.app'
        retained.symlink_to(f.home / 'missing')
        with self.assertRaises((ControlError, RuntimeError)):
            self.go()
        retained.unlink()  # fixture-only setup
        self.go()
        committed = (f.base / install.UPGRADE_RECEIPT).read_bytes()
        (self.app / 'Contents/Info.plist').write_bytes(b'unknown')
        with self.assertRaisesRegex(ControlError, 'Unknown artifact'):
            self.recover()
        self.assertEqual((f.base / install.UPGRADE_RECEIPT).read_bytes(), committed)
        self.assertEqual((f.base / install.RECEIPT).read_bytes(), self.root_bytes)

    def test_partial_copy_is_retained_unknown_bytes_not_recovered(self):
        copy = install.copy_tree
        f = self.fixture
        def fail(source, dest, **kwargs):
            if dest.name == 'Verity.upgrade-v2.app':
                dest.mkdir(mode=0o700)
                (dest / 'unknown').write_bytes(b'unknown partial artifact')
                raise OSError('partial copy')
            return copy(source, dest, **kwargs)
        with patch.object(install, 'copy_tree', side_effect=fail):
            with self.assertRaisesRegex(OSError, 'partial copy'):
                self.go()
        with self.assertRaisesRegex(ControlError, 'Unknown artifact'):
            self.recover()
        self.assertEqual(self.app.stat().st_ino, self.inode)
        for n, record in self.v1.items():
            self.assertEqual(install.snapshot(f.base / n), record)

    def test_broad_default_census_rejects_independent_and_changing_process(self):
        # Only OS observations are mocked: actual default dependency algorithm runs.
        import copy
        import os
        f = self.fixture
        c = install.Controller(f.base)
        definitions = c.definitions(f.manifest)
        jobs = {c.target(f.manifest, role): dict(pid=110 + index,
                argv=definitions[role]['ProgramArguments'], cwd=definitions[role]['WorkingDirectory'])
                for index, role in enumerate(stage.ROLES)}
        records = {110 + index: dict(pid=110 + index, ppid=1, uid=os.getuid(),
                   argv=f.manifest['services'][role]['argv'], start_time=10.0,
                   executable=str(Path(f.manifest['services'][role]['argv'][0]).resolve()))
                   for index, role in enumerate(stage.ROLES)}
        records[999] = dict(pid=999, ppid=1, uid=os.getuid(), start_time=20.0,
                            argv=['/usr/bin/innocent'], executable='/usr/bin/innocent')
        with patch.object(Host, 'job', side_effect=lambda target: copy.deepcopy(jobs[target])), \
                patch.object(install, 'census_pids', return_value={110, 111, 999}) as census, \
                patch.object(Host, 'process_identity', side_effect=lambda pid: copy.deepcopy(records[pid])):
            self.assertTrue(install.upgrade_dependency_check(f.base, f.manifest))
            for path in (str(self.app / 'Contents/MacOS/VerityServiceHost'),
                         str(f.base / 'control-versions/native-v1/restart_production.py'),
                         str(f.base / 'restart_production.py')):
                records[999]['argv'] = [path]
                with self.assertRaisesRegex(ControlError, 'Independent native/control dependency'):
                    install.upgrade_dependency_check(f.base, f.manifest)
            records[999]['argv'] = ['/usr/bin/innocent']
            records[999]['start_time'] = None
            with self.assertRaisesRegex(ControlError, 'Unknown process identity'):
                install.upgrade_dependency_check(f.base, f.manifest)
            records[999]['start_time'] = 20.0
            records[999]['executable'] = '/fixture/python3'
            records[999]['argv'] = ['/fixture/python3', '-c', 'opaque']
            with self.assertRaisesRegex(ControlError, 'Opaque interpreter'):
                install.upgrade_dependency_check(f.base, f.manifest)
            records[999]['executable'] = '/usr/bin/innocent'
            records[999]['argv'] = ['/usr/bin/innocent']
            census.side_effect = [{110, 111, 999}, {110, 111}]
            with self.assertRaisesRegex(ControlError, 'census changed'):
                install.upgrade_dependency_check(f.base, f.manifest)

    def test_kernel_census_adapter_is_bounded_and_excludes_only_system_pids(self):
        import ctypes
        from unittest.mock import Mock
        def list_pids(buffer, size):
            if buffer is None:
                return 4
            for index, pid in enumerate((0, 1, 110, 999)):
                buffer[index] = pid
            return 4
        lib = Mock()
        lib.proc_listallpids.side_effect = list_pids
        with patch.object(ctypes, 'CDLL', return_value=lib):
            self.assertEqual(install.census_pids(None), {110, 999})
            lib.proc_listallpids.side_effect = lambda *_: -1
            with self.assertRaisesRegex(ControlError, 'Unknown process census'):
                install.census_pids(None)

    def test_final_path_signature_is_checked_before_v2_wrapper_publication(self):
        seen = []
        def reject(argv, **kwargs):
            if Path(argv[-1]) == self.app:
                seen.append(install.tree(self.app))
                if seen[-1] == install.tree(self.fresh / 'Verity.app'):
                    raise OSError('final path signature failed')
            self.verifier(argv, **kwargs)
        f = self.fixture
        with self.assertRaisesRegex(OSError, 'final path signature failed'):
            install.upgrade(self.fresh, f.base, f.home, original_stage=f.root / 'stage',
                            root_sha256=self.pin, approve=True, runner=reject,
                            dependency_check=lambda *_: True)
        self.assertTrue(seen)
        for n, record in self.v1.items():
            self.assertEqual(install.snapshot(f.base / n), record)
        self.assert_recovered()

    def test_restore_receipt_mode_and_unknown_phase_are_not_authority(self):
        self.go()
        f = self.fixture
        path = f.base / install.UPGRADE_RECEIPT
        path.chmod(0o600)
        with self.assertRaisesRegex(ControlError, 'mode'):
            self.recover()
        path.chmod(0o444)
        journal = f.base / install.UPGRADE_JOURNAL
        data = json.loads(journal.read_bytes())
        data['payload']['phase'] = 'invented'
        data['sha256'] = stage.digest(stage.encoded(data['payload']))
        journal.write_bytes(stage.encoded(data))
        with self.assertRaisesRegex(ControlError, 'phase'):
            self.recover()

    def test_recovery_and_restore_interruption_use_observed_state(self):
        f = self.fixture
        save = install.upgrade_journal
        def stop(base, plan, phase):
            save(base, plan, phase)
            if phase == 'commit':
                raise OSError('before commit')
        with patch.object(install, 'upgrade_journal', side_effect=stop):
            with self.assertRaisesRegex(OSError, 'before commit'):
                self.go()
        rename = install.rename_artifact
        hit = []
        def stop_recovery(source, target):
            rename(source, target)
            if target == self.app:
                hit.append('restored v1')
                raise OSError('recovery fsync')
        with patch.object(install, 'rename_artifact', side_effect=stop_recovery):
            with self.assertRaisesRegex(OSError, 'recovery fsync'):
                self.recover()
        self.assertEqual(hit, ['restored v1'])
        self.assert_recovered()
        # Separate committed fixture: interrupted legacy-wrapper publication is retryable.
        other = UpgradeTests()
        other.setUp()
        try:
            other.go()
            g = other.fixture
            pin = stage.digest((g.base / install.UPGRADE_RECEIPT).read_bytes())
            other.mark_returned(pin)
            write = install.atomic_write
            hit = []
            def fail(path, data):
                write(path, data)
                if path == g.base / 'production_launcher.py':
                    hit.append(path.name)
                    raise OSError('restore publication')
            def restore():
                return install.restore_upgraded_wrappers(g.base, g.home, root_sha256=other.pin,
                    upgrade_sha256=pin, approve=True, runner=other.verifier, dependency_check=lambda *_: True)
            with patch.object(install, 'atomic_write', side_effect=fail):
                with self.assertRaisesRegex(OSError, 'restore publication'):
                    restore()
            self.assertEqual(hit, ['production_launcher.py'])
            restore()
            for n, record in g.originals.items():
                self.assertEqual(install.snapshot(g.base / n), record)
        finally:
            other.doCleanups()

    def test_baseline_and_dependency_revalidated_after_journal_before_mutation(self):
        f = self.fixture
        save = install.upgrade_journal
        phases = []
        def drift(base, plan, phase):
            save(base, plan, phase)
            phases.append(phase)
            if phase == 'retain_v1':
                f.selected.write_bytes(f.selected_before + b' ')
        with patch.object(install, 'upgrade_journal', side_effect=drift):
            with self.assertRaisesRegex(ControlError, 'baseline drift'):
                self.go()
        self.assertEqual(phases[-1], 'retain_v1')
        self.assertEqual(self.app.stat().st_ino, self.inode)
        f.selected.write_bytes(f.selected_before)  # fixture repair, never live reconciliation
        self.assert_recovered()

    def test_revocation_is_revalidated_and_dangling_policy_is_unknown(self):
        f = self.fixture
        policy = f.base / 'revoked-releases.json'
        policy.write_bytes(stage.encoded(dict(schema_version=1,
            release_ids=['fixture'], content_digests=[])))
        with self.assertRaisesRegex(ControlError, 'revoked'):
            self.go()
        self.assertFalse((f.base / install.UPGRADE_JOURNAL).exists())
        policy.unlink()
        policy.symlink_to(f.base / 'missing-policy')
        with self.assertRaises((ControlError, RuntimeError)):
            self.go()
        self.assertFalse((f.base / install.UPGRADE_JOURNAL).exists())

    def test_cli_requires_pins_and_explicit_operation(self):
        with patch.object(install, 'upgrade', return_value={'status': 'fixture'}) as call:
            result = install.main(['--base', '/fixture/base', '--home', '/fixture/home',
                                   '--stage', '/fixture/v2', '--original-stage', '/fixture/v1',
                                   '--root-sha256', 'a' * 64, '--approve-upgrade'])
        self.assertEqual(result['status'], 'fixture')
        self.assertTrue(call.call_args.kwargs['approve'])
