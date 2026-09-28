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

    def legacy_topology(self):
        """OS adapters only; definitions, loaded ownership and default checker stay real."""
        import copy
        import os
        import sys
        from contextlib import ExitStack
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
        parent = records[110]
        command = parent['argv']
        self.assertEqual(command[1:4], ['-m', 'hermes_cli.stderr_timestamp', '--error-log'])
        self.assertEqual(command[5:], ['--', command[0], '-m', 'hermes_cli.main',
                                      'gateway', 'run', '--external-supervisor'])
        records[112] = dict(pid=112, ppid=110, uid=os.getuid(), start_time=11.0,
                            executable=parent['executable'], argv=command[6:])
        records[os.getpid()] = dict(pid=os.getpid(), ppid=50, uid=os.getuid(), start_time=12.0,
            executable=str(Path(sys.executable).resolve()),
            argv=[sys.executable, '-B', str(Path(install.__file__).resolve()), '--approve-upgrade'])
        stack = ExitStack()
        stack.enter_context(patch.object(Host, 'job', side_effect=lambda target: copy.deepcopy(jobs[target])))
        census = stack.enter_context(patch.object(install, 'census_pids', side_effect=lambda host: set(records)))
        identity = stack.enter_context(patch.object(Host, 'process_identity',
                                                  side_effect=lambda pid: copy.deepcopy(records[pid])))
        return stack, jobs, records, census, identity

    def default_upgrade(self):
        f = self.fixture
        return install.upgrade(self.fresh, f.base, f.home, original_stage=f.root / 'stage',
                               root_sha256=self.pin, approve=True, runner=self.verifier)

    def test_default_generated_gateway_child_and_direct_installer_complete_lifecycle(self):
        stack, jobs, records, census, identity = self.legacy_topology()
        f = self.fixture
        with stack:
            self.assertEqual(self.default_upgrade()['status'], 'upgraded_not_activated')
            self.assertGreater(census.call_count, 4)
            self.assertEqual(install.recover_upgrade(f.base, f.home, root_sha256=self.pin,
                approve=True, runner=self.verifier)['status'], 'committed_verified')
            committed = (f.base / install.UPGRADE_RECEIPT).read_bytes()
            self.mark_returned(stage.digest(committed))  # synthetic completion only
            install.restore_upgraded_wrappers(f.base, f.home, root_sha256=self.pin,
                upgrade_sha256=stage.digest(committed), approve=True, runner=self.verifier)
        self.assertEqual((f.base / install.RECEIPT).read_bytes(), self.root_bytes)
        for name, record in f.originals.items():
            self.assertEqual(install.snapshot(f.base / name), record)
        f.preserved()

    def test_default_topology_refuses_unowned_unknown_and_drifting_identities(self):
        import copy
        import os
        cases = ['unowned', 'reparented', 'uid', 'executable', 'start', 'missing_uid',
                 'missing_ppid', 'unreadable', 'parent_missing', 'parent_replaced',
                 'parent_birth', 'parent_job', 'census', 'grandchild', 'other_child',
                 'opaque', 'control', 'selected_clone', 'uid_drift', 'executable_drift',
                 'bad_start', 'predates_parent', 'duplicate_child']
        for case in cases:
            with self.subTest(case=case):
                self.setUp()  # independent filesystem even if a regression unexpectedly writes
                stack, jobs, records, census, identity = self.legacy_topology()
                with stack:
                    child = records[112]
                    if case == 'unowned':
                        child['ppid'] = 50
                    elif case == 'uid':
                        child['uid'] = os.getuid() + 1
                    elif case == 'executable':
                        child['executable'] = '/fixture/not-python'
                    elif case.startswith('missing_'):
                        child.pop(case[8:])
                    elif case == 'bad_start':
                        child['start_time'] = 'unknown'
                    elif case == 'predates_parent':
                        child['start_time'] = 1.0
                    elif case == 'duplicate_child':
                        records[114] = dict(child, pid=114)
                    elif case == 'unreadable':
                        def unreadable(pid):
                            if pid == 112:
                                raise OSError('unreadable child')
                            return copy.deepcopy(records[pid])
                        identity.side_effect = unreadable
                    elif case == 'parent_missing':
                        census.side_effect = lambda host: set(records) - {110}
                    elif case == 'parent_replaced':
                        target = install.Controller(self.fixture.base).target(self.fixture.manifest, 'agent')
                        jobs[target]['pid'] = 113
                        records[113] = dict(records[110], pid=113)
                    elif case == 'parent_job':
                        job = Host.job.side_effect
                        calls = []
                        def replacement(target):
                            calls.append(target)
                            result = job(target)
                            if len(calls) > 4:
                                result['pid'] += 100
                            return result
                        Host.job.side_effect = replacement
                    elif case == 'census':
                        census.side_effect = [set(records), set(records) - {112}]
                    elif case in ('grandchild', 'other_child', 'opaque', 'control', 'selected_clone'):
                        records[114] = dict(pid=114, ppid=112 if case == 'grandchild' else 111,
                            uid=os.getuid(), start_time=13.0, executable='/usr/bin/innocent',
                            argv=['/usr/bin/innocent'])
                        if case == 'opaque':
                            records[114].update(ppid=50, executable='/fixture/python', argv=['/fixture/python'])
                        elif case == 'control':
                            records[114]['argv'] = [str(self.fixture.base / 'restart_production.py')]
                        elif case == 'selected_clone':
                            records[114] = dict(records[110], pid=114, ppid=50)
                    else:
                        seen = {}
                        def drift(pid):
                            seen[pid] = seen.get(pid, 0) + 1
                            result = copy.deepcopy(records[pid])
                            target = 110 if case == 'parent_birth' else 112
                            if pid == target and seen[pid] > (2 if pid == 110 else 1):
                                if case == 'uid_drift':
                                    result['uid'] += 1
                                elif case == 'executable_drift':
                                    result['executable'] += '.changed'
                                else:
                                    result['ppid' if case == 'reparented' else 'start_time'] += 1
                            return result
                        identity.side_effect = drift
                    with self.assertRaises((ControlError, OSError)):
                        self.default_upgrade()
                    self.assertFalse((self.fixture.base / install.UPGRADE_JOURNAL).exists())
                    self.assertEqual((self.fixture.base / install.RECEIPT).read_bytes(), self.root_bytes)
                    self.assertEqual(self.app.stat().st_ino, self.inode)

    def test_default_own_direct_installer_exemption_is_narrow(self):
        import os
        import sys
        cases = ['plain', 'bytecode_flag', 'wrong_pid', 'wrong_path', 'wrong_interpreter',
                 'argv_interpreter', 'script_argument', '-c', '-m', 'uid', 'missing_start',
                 'nonpython_interpreter']
        for case in cases:
            with self.subTest(case=case):
                self.setUp()  # independent filesystem even if a regression unexpectedly writes
                stack, jobs, records, census, identity = self.legacy_topology()
                with stack:
                    own = records[os.getpid()]
                    if case == 'plain':
                        own['argv'].remove('-B')
                    elif case == 'wrong_pid':
                        records[114] = dict(records.pop(os.getpid()), pid=114)
                    elif case == 'wrong_path':
                        own['argv'][2] += '.other'
                    elif case == 'wrong_interpreter':
                        own['executable'] = '/fixture/python'
                    elif case == 'nonpython_interpreter':
                        own['executable'] = '/usr/bin/innocent'
                    elif case == 'argv_interpreter':
                        own['argv'][0] = '/fixture/python'
                    elif case == 'script_argument':
                        own['argv'].insert(2, '/fixture/other.py')
                    elif case in ('-c', '-m'):
                        own['argv'] = [sys.executable, case, str(Path(install.__file__).resolve())]
                    elif case == 'uid':
                        own['uid'] += 1
                    elif case == 'missing_start':
                        own['start_time'] = None
                    if case in ('plain', 'bytecode_flag'):
                        self.assertTrue(install.upgrade_dependency_check(self.fixture.base, self.fixture.manifest))
                    else:
                        with self.assertRaises(ControlError):
                            self.default_upgrade()
                        self.assertFalse((self.fixture.base / install.UPGRADE_JOURNAL).exists())

    def test_default_topology_revalidated_after_each_upgrade_journal(self):
        phases = ['copy_controls', 'copy_app', 'retain_v1', 'publish_v2',
                  *('publish_' + name for name in self.v1), 'commit']
        for phase in phases:
            with self.subTest(phase=phase):
                other = UpgradeTests()
                other.setUp()
                try:
                    stack, jobs, records, census, identity = other.legacy_topology()
                    save = install.upgrade_journal
                    hit = []
                    def invalidate(base, plan, actual):
                        save(base, plan, actual)
                        if actual == phase:
                            hit.append(actual)
                            records[112]['ppid'] = 50
                    with stack:
                        with patch.object(install, 'upgrade_journal', side_effect=invalidate):
                            with self.assertRaisesRegex(ControlError, 'Opaque interpreter'):
                                other.default_upgrade()
                        self.assertEqual(hit, [phase])
                        self.assertFalse((other.fixture.base / install.UPGRADE_RECEIPT).exists())
                        records[112]['ppid'] = 110  # fixture only; never production repair
                        result = install.recover_upgrade(other.fixture.base, other.fixture.home,
                            root_sha256=other.pin, approve=True, runner=other.verifier)
                        self.assertEqual(result['status'], 'recovered_v1_artifacts_retained')
                        self.assertEqual(other.app.stat().st_ino, other.inode)
                        for name, record in other.v1.items():
                            self.assertEqual(install.snapshot(other.fixture.base / name), record)
                finally:
                    other.doCleanups()

    def test_default_recovery_and_postreturn_recheck_job_ownership_after_journal(self):
        recovery_phases = ['recover_retain_v2', 'recover_v1_app',
                           *('recover_' + name for name in self.v1),
                           'recovered_v1_artifacts_retained']
        restore_phases = ['restore_legacy_' + name for name in self.v1]
        for phase in recovery_phases + restore_phases:
            with self.subTest(phase=phase):
                other = UpgradeTests()
                other.setUp()
                try:
                    f = other.fixture
                    stack, jobs, records, census, identity = other.legacy_topology()
                    save = install.upgrade_journal
                    with stack:
                        if phase in recovery_phases:
                            def stop(base, plan, actual):
                                save(base, plan, actual)
                                if actual == 'commit':
                                    raise OSError('fixture before commit')
                            with patch.object(install, 'upgrade_journal', side_effect=stop):
                                with self.assertRaisesRegex(OSError, 'fixture before commit'):
                                    other.default_upgrade()
                            def operation():
                                return install.recover_upgrade(f.base, f.home, root_sha256=other.pin,
                                    approve=True, runner=other.verifier)
                        else:
                            other.default_upgrade()
                            pin = stage.digest((f.base / install.UPGRADE_RECEIPT).read_bytes())
                            other.mark_returned(pin)
                            def operation():
                                return install.restore_upgraded_wrappers(f.base, f.home,
                                    root_sha256=other.pin, upgrade_sha256=pin,
                                    approve=True, runner=other.verifier)
                        hit = []
                        before = {}
                        target = install.Controller(f.base).target(f.manifest, 'agent')
                        def invalidate(base, plan, actual):
                            save(base, plan, actual)
                            if actual == phase:
                                hit.append(actual)
                                before.update({name: install.snapshot(f.base / name) for name in other.v1})
                                # Existing live parent is no longer owned by the selected job.
                                jobs[target]['pid'] = 113
                                records[113] = dict(records[110], pid=113)
                        with patch.object(install, 'upgrade_journal', side_effect=invalidate):
                            with self.assertRaisesRegex(ControlError, 'Opaque interpreter'):
                                operation()
                        self.assertEqual(hit, [phase])
                        for name, record in before.items():
                            self.assertEqual(install.snapshot(f.base / name), record)
                        jobs[target]['pid'] = 110
                        records.pop(113)
                        operation()
                        self.assertEqual((f.base / install.RECEIPT).read_bytes(), other.root_bytes)
                        f.preserved()
                finally:
                    other.doCleanups()

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
