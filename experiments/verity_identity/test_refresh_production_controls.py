"""Hermetic filesystem refresh tests; use guarded_main for pre-import tripwires.

No installed files, application probes, subprocesses, native APIs or network are
allowed. The legacy restart and postactivation return proofs are controller
results, not synthetic future completion records. OS readiness is a fixture.
"""
import contextlib
import io
import json
import os
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

# Imports are deferred until the guarded runner installed its tripwires.


def modules():
    import install_production_native as original
    import refresh_production_controls as refresh
    return original, refresh


class RefreshTests(unittest.TestCase):
    def fixture(self):
        from test_upgrade_return_composition import ServiceFixture
        from test_restart_control import Clock, FakeHost
        import restart_production
        original, refresh = modules()
        f = ServiceFixture()
        f.setUp()
        self.addCleanup(f.doCleanups)
        f.go()
        f.write_gateway = lambda pid: original.save_json(f.root / 'state/gateway_state.json', dict(
            pid=pid, gateway_state='running', code_sha=f.manifest['services']['agent']['commit'], updated_at=clock()))
        f.plists = {r: Path(f.manifest['services'][r]['plist_path']) for r in ('agent', 'webui')}
        clock = f.clock = Clock()
        host = FakeHost(f)
        host.service = lambda target: target.rsplit('.', 1)[-1]
        host.process_identity = lambda pid: dict(pid=pid, ppid=1, uid=os.getuid(),
            argv=host.jobs['agent' if pid == host.jobs['agent']['pid'] else 'webui']['argv'],
            executable=str(Path(host.jobs['agent' if pid == host.jobs['agent']['pid'] else 'webui']['argv'][0]).resolve()), start_time=host.started)
        f.write_gateway(101)
        c = restart_production.Controller(f.base, host, clock=clock, monotonic=clock,
            sleep=clock.sleep, owner=lambda: 1, timeout=5, stable_seconds=1)
        self.assertEqual(c.restart(yes=True)['status'], 'verified')
        f.original_transaction = original.snapshot(f.base / refresh.TRANSACTION)
        f.root_pin = refresh.digest((f.base / original.RECEIPT).read_bytes())
        f.fresh = f.root / 'refresh-stage'
        refresh.stage(f.fresh, f.base, f.home, original_stage=f.root / 'stage', root_sha256=f.root_pin, version_name='fenced-v2')
        f.stage_pin = refresh.digest((f.fresh / refresh.STAGE_REPORT).read_bytes())
        f.kw = dict(stage_sha256=f.stage_pin, root_sha256=f.root_pin, approve=True)
        f.old_wrappers = {n: original.snapshot(f.base / n) for n in refresh.MANAGEMENT}
        f.immutable = self.immutable(f)
        return f

    def immutable(self, f):
        original, refresh = modules()
        paths = [f.home / 'Applications/Verity.app', f.base / 'control-versions/native-v1', f.root / 'stage']
        result = {}
        for root in paths:
            for path in (root, *root.rglob('*')):
                info = path.stat()
                result[str(path)] = (info.st_dev, info.st_ino, info.st_mode, info.st_uid,
                                     None if path.is_dir() else path.read_bytes())
        for path in (f.base / original.RECEIPT, f.base / 'production_launcher.py', f.base / 'control.lock'):
            info = path.stat()
            result[str(path)] = (info.st_dev, info.st_ino, info.st_mode, info.st_uid, path.read_bytes())
        return result

    def go(self, f):
        return modules()[1].install(f.fresh, f.base, f.home, **f.kw)

    def recover(self, f):
        return modules()[1].recover(f.fresh, f.base, f.home, **f.kw)

    def assert_restored(self, f):
        original, refresh = modules()
        self.assertEqual(original.snapshot(f.base / refresh.TRANSACTION), f.original_transaction)
        self.assertEqual({n: original.snapshot(f.base / n) for n in refresh.MANAGEMENT}, f.old_wrappers)
        self.assertEqual(self.immutable(f), f.immutable)
        f.preserved()

    def test_complete_install_runtime_provenance_and_preactivation_undo(self):
        import control_refresh
        f = self.fixture()
        original, refresh = modules()
        result = self.go(f)
        data = (f.base / refresh.RECEIPT).read_bytes()
        receipt = json.loads(data)
        self.assertEqual(result['control_refresh_sha256'], refresh.digest(data))
        self.assertEqual(receipt['original_transaction'], f.original_transaction)
        self.assertEqual(json.loads((f.base / refresh.TRANSACTION).read_bytes())['schema_version'], 2)
        home = patch.dict(os.environ, HOME=str(f.home), HERMES_HOME=str(f.root / 'state'))
        home.start()
        self.addCleanup(home.stop)
        runtime, replacements, unchanged = control_refresh.load(f.base, refresh.digest(data),
            f.base / 'control-refresh-versions/fenced-v2/restart_production.py')
        self.assertEqual(runtime, receipt)
        self.assertEqual(set(replacements), set(refresh.MANAGEMENT) | {'production_launcher.py'})
        unchanged()
        self.assertEqual(self.immutable(f), f.immutable)
        self.recover(f)
        self.assert_restored(f)
        self.recover(f)
        self.assert_restored(f)
        with self.assertRaises(Exception):
            unchanged()
        with self.assertRaises(Exception):
            self.go(f)

    def test_all_install_write_boundaries_recover_exact_original(self):
        """Interrupt before/after every journal, READY, fence, wrapper and commit."""
        original, refresh = modules()
        expected = [refresh.JOURNAL, refresh.READY, refresh.JOURNAL, refresh.TRANSACTION,
                    refresh.JOURNAL, refresh.JOURNAL, refresh.MANAGEMENT[0], refresh.JOURNAL,
                    refresh.MANAGEMENT[1], refresh.JOURNAL, refresh.MANAGEMENT[2], refresh.JOURNAL, refresh.RECEIPT]
        class PowerLoss(BaseException):
            pass
        for boundary in range(len(expected)):
            for after in (False, True):
                with self.subTest(boundary=boundary, after=after):
                    f = self.fixture()
                    real, sealed = refresh.atomic_write, refresh.sealed_write
                    calls = []
                    def perform(fn, path, data):
                        calls.append(Path(path).name)
                        if len(calls) - 1 == boundary and not after:
                            raise PowerLoss()
                        fn(path, data)
                        if len(calls) - 1 == boundary and after:
                            raise PowerLoss()
                    with patch.object(refresh, 'atomic_write', side_effect=lambda p,d: perform(real,p,d)), \
                         patch.object(refresh, 'sealed_write', side_effect=lambda p,d: perform(sealed,p,d)):
                        with self.assertRaises(PowerLoss):
                            self.go(f)
                    self.assertEqual(calls, expected[:boundary + 1])
                    self.assertEqual(self.immutable(f), f.immutable)
                    if boundary == 0 and not after:
                        self.assert_restored(f)
                        self.assertFalse((f.base / 'control-refresh-versions').exists())
                    else:
                        self.recover(f)
                        self.assert_restored(f)

    def test_rename_and_fsync_failures_preserve_fence_and_recover(self):
        original, refresh = modules()
        class PowerLoss(BaseException):
            pass
        # Exact targets exclude copied modules sharing stable wrapper filenames.
        for name in (refresh.READY, refresh.TRANSACTION, *refresh.MANAGEMENT, refresh.RECEIPT):
            for after in (False, True):
                with self.subTest(name=name, after=after):
                    f = self.fixture()
                    replace = os.replace
                    hit = []
                    def fault(source, dest):
                        if Path(dest) == f.base / name:
                            hit.append(name)
                            if not after:
                                raise PowerLoss()
                            replace(source, dest)
                            raise PowerLoss()
                        return replace(source, dest)
                    with patch.object(os, 'replace', side_effect=fault):
                        with self.assertRaises(PowerLoss):
                            self.go(f)
                    self.assertEqual(hit, [name])
                    self.assertEqual(self.immutable(f), f.immutable)
                    self.recover(f)
                    self.assert_restored(f)
        # Real fsync failure both before rename and after it, at every stable file.
        for name in (refresh.JOURNAL, refresh.READY, refresh.TRANSACTION, *refresh.MANAGEMENT, refresh.RECEIPT):
            for after_rename in (False, True):
                with self.subTest(fsync=name, after_rename=after_rename):
                    f = self.fixture()
                    active = [None]
                    renamed = [False]
                    hit = []
                    write, sealed, fsync, replace = refresh.atomic_write, refresh.sealed_write, os.fsync, os.replace
                    def scope(fn, path, data):
                        active[0], renamed[0] = Path(path), False
                        try:
                            return fn(path, data)
                        finally:
                            active[0] = None
                    def rename(a, b):
                        replace(a, b)
                        if Path(b) == active[0]:
                            renamed[0] = True
                    def sync(fd):
                        if active[0] == f.base / name and renamed[0] == after_rename:
                            hit.append(name)
                            raise PowerLoss()
                        return fsync(fd)
                    with patch.object(refresh, 'atomic_write', side_effect=lambda p,d: scope(write,p,d)), \
                         patch.object(refresh, 'sealed_write', side_effect=lambda p,d: scope(sealed,p,d)), \
                         patch.object(os, 'replace', side_effect=rename), patch.object(os, 'fsync', side_effect=sync):
                        with self.assertRaises(PowerLoss):
                            self.go(f)
                    self.assertEqual(hit, [name])
                    self.assertEqual(self.immutable(f), f.immutable)
                    if (f.base / refresh.JOURNAL).exists():
                        self.recover(f)
                    self.assert_restored(f)

    def test_all_recovery_publications_and_final_schema1_fsync(self):
        original, refresh = modules()
        class PowerLoss(BaseException):
            pass
        for name in (*refresh.MANAGEMENT, refresh.TRANSACTION):
            for after in (False, True):
                with self.subTest(name=name, after=after):
                    f = self.fixture()
                    self.go(f)
                    replace = os.replace
                    hits = []
                    def fault(a, b):
                        if Path(b) == f.base / name:
                            hits.append(name)
                            if not after:
                                raise PowerLoss()
                            replace(a,b)
                            raise PowerLoss()
                        replace(a,b)
                    with patch.object(os, 'replace', side_effect=fault):
                        with self.assertRaises(PowerLoss):
                            self.recover(f)
                    self.assertEqual(hits, [name])
                    if name != refresh.TRANSACTION or not after:
                        self.assertEqual(json.loads((f.base / refresh.TRANSACTION).read_bytes())['schema_version'], 2)
                    self.recover(f)
                    self.assert_restored(f)

    def test_every_undo_fsync_boundary_keeps_recoverable_proof(self):
        from test_control_refresh_composition import ControlRefreshCompositionTests
        original, refresh = modules()
        class PowerLoss(BaseException):
            pass
        for postreturn in (False, True):
            targets = ((refresh.JOURNAL,) if postreturn else ()) + (
                refresh.JOURNAL, *refresh.MANAGEMENT, refresh.JOURNAL, refresh.TRANSACTION)
            for boundary, name in enumerate(targets):
                for after_rename in (False, True):
                    with self.subTest(postreturn=postreturn, boundary=boundary, after_rename=after_rename):
                        c = None
                        if postreturn:
                            c = ControlRefreshCompositionTests()
                            c.setUp()
                            c.activate()
                            self.assertEqual(c.return_exact()['status'], 'verified')
                            operation = c.restore
                        else:
                            f = self.fixture()
                            self.go(f)
                            operation = lambda: self.recover(f)
                        active, renamed, seen, hit = [None], [False], [], []
                        write, replace, fsync = refresh.atomic_write, os.replace, os.fsync
                        def scope(path, data):
                            seen.append(Path(path).name)
                            active[0], renamed[0] = Path(path), False
                            try:
                                return write(path, data)
                            finally:
                                active[0] = None
                        def rename(a,b):
                            replace(a,b)
                            if Path(b) == active[0]:
                                renamed[0] = True
                        def sync(fd):
                            if active[0] is not None and len(seen) - 1 == boundary and renamed[0] == after_rename:
                                hit.append(name)
                                raise PowerLoss()
                            return fsync(fd)
                        try:
                            with patch.object(refresh, 'atomic_write', side_effect=scope), \
                                 patch.object(os, 'replace', side_effect=rename), patch.object(os, 'fsync', side_effect=sync):
                                with self.assertRaises(PowerLoss):
                                    operation()
                            self.assertEqual(hit, [name])
                            self.assertEqual(seen, list(targets[:boundary + 1]))
                            operation()
                            if postreturn:
                                self.assertEqual((c.f.base / refresh.TRANSACTION).read_bytes(), c.original_transaction)
                                c.assert_artifacts_unchanged()
                            else:
                                self.assert_restored(f)
                        finally:
                            if c is not None:
                                c.doCleanups()

    def test_refusals_are_prepublication_and_capture_terminal_under_lock(self):
        original, refresh = modules()
        for mutation in ('root-pin', 'stage-pin', 'no-approval', 'missing-txn', 'nonterminal', 'wrapper', 'lock', 'app', 'controls'):
            with self.subTest(mutation=mutation):
                f = self.fixture()
                kwargs = dict(f.kw)
                if mutation == 'root-pin':
                    kwargs['root_sha256'] = '0' * 64
                elif mutation == 'stage-pin':
                    kwargs['stage_sha256'] = '0' * 64
                elif mutation == 'no-approval':
                    kwargs['approve'] = False
                elif mutation == 'missing-txn':
                    (f.base / refresh.TRANSACTION).unlink()
                elif mutation == 'nonterminal':
                    txn = json.loads((f.base / refresh.TRANSACTION).read_bytes())['transaction']
                    import restart_production
                    restart_production.Controller(f.base).save_transaction(txn, 'prepared')
                elif mutation == 'wrapper':
                    (f.base / refresh.MANAGEMENT[0]).write_bytes(b'unknown wrapper')
                elif mutation == 'lock':
                    (f.base / 'control.lock').unlink()
                elif mutation == 'app':
                    (f.home / 'Applications/Verity.app').chmod(0o700)
                else:
                    (f.fresh / 'controls/watchdog.py').chmod(0o600)
                with patch.object(refresh, 'atomic_write', wraps=refresh.atomic_write) as writes, \
                     patch.object(original, 'copy_tree', wraps=original.copy_tree) as copies:
                    with self.assertRaises(Exception):
                        refresh.install(f.fresh, f.base, f.home, **kwargs)
                    writes.assert_not_called()
                    copies.assert_not_called()
                self.assertFalse((f.base / refresh.JOURNAL).exists())

    def test_recovery_refuses_drift_and_postactivation_without_writes(self):
        original, refresh = modules()
        for mutation in ('transaction', 'wrapper', 'lock', 'stage', 'controls', 'receipt'):
            with self.subTest(mutation=mutation):
                f = self.fixture()
                self.go(f)
                paths = dict(transaction=f.base / refresh.TRANSACTION, wrapper=f.base / refresh.MANAGEMENT[0],
                    lock=f.base / 'control.lock', stage=f.fresh / refresh.STAGE_REPORT,
                    controls=f.base / 'control-refresh-versions/fenced-v2/watchdog.py', receipt=f.base / refresh.RECEIPT)
                path = paths[mutation]
                if mutation == 'lock':
                    path.rename(path.with_suffix('.retained'))
                    path.touch(mode=0o600)
                else:
                    path.chmod(0o600)
                    path.write_bytes(b'unknown')
                with patch.object(refresh, 'atomic_write', wraps=refresh.atomic_write) as writes:
                    with self.assertRaises(Exception):
                        self.recover(f)
                    writes.assert_not_called()

    def test_partial_control_copy_fsync_boundaries_are_retained(self):
        original, refresh = modules()
        class PowerLoss(BaseException):
            pass
        for target in (*refresh.CONTROL_FILES, 'control-receipt.json'):
            for after in (False, True):
                with self.subTest(target=target, after=after):
                    f = self.fixture()
                    version = f.base / 'control-refresh-versions/fenced-v2'
                    write = original.atomic_write
                    hits = []
                    def fault(path, data):
                        if Path(path) == version / target:
                            hits.append(target)
                            if not after:
                                raise PowerLoss()
                            write(path, data)
                            raise PowerLoss()
                        write(path, data)
                    with patch.object(original, 'atomic_write', side_effect=fault):
                        with self.assertRaises(PowerLoss):
                            self.go(f)
                    self.assertEqual(hits, [target])
                    retained = original.tree(version)
                    self.assertFalse((f.base / refresh.READY).exists())
                    self.assert_restored(f)
                    self.recover(f)
                    self.assert_restored(f)
                    self.assertEqual(original.tree(version), retained)

    def test_journal_edge_drift_refuses_before_any_further_publication(self):
        original, refresh = modules()
        phases = ['prepared', 'ready', 'fenced', *('publish_' + n for n in refresh.MANAGEMENT), 'committed']
        for phase in phases:
            with self.subTest(phase=phase):
                f = self.fixture()
                write = refresh.atomic_write
                seen, at_fault = [], []
                def fault(path, data):
                    seen.append(Path(path).name)
                    write(path, data)
                    if Path(path) == f.base / refresh.JOURNAL and json.loads(data)['payload']['phase'] == phase:
                        f.selected.write_bytes(b'unknown selection')
                        at_fault.append((list(seen), original.tree(f.base), self.immutable(f)))
                with patch.object(refresh, 'atomic_write', side_effect=fault):
                    with self.assertRaises(Exception):
                        self.go(f)
                self.assertEqual(len(at_fault), 1)
                self.assertEqual(seen, at_fault[0][0])
                self.assertEqual(original.tree(f.base), at_fault[0][1])
                self.assertEqual(self.immutable(f), at_fault[0][2])

    def test_stage_refuses_invalid_scope_without_creating_output(self):
        original, refresh = modules()
        f = self.fixture()
        for name, root_pin in (('../escape', f.root_pin), ('valid', '0' * 64)):
            output = f.root / 'rejected-stage'
            with self.assertRaises(Exception):
                refresh.stage(output, f.base, f.home, original_stage=f.root / 'stage',
                              root_sha256=root_pin, version_name=name)
            self.assertFalse(output.exists())
        for output in (f.home / 'Applications/Verity.app/new-stage', f.root / 'stage/nested-stage',
                       f.base / 'control-refresh-versions/valid'):
            with self.assertRaises(Exception):
                refresh.stage(output, f.base, f.home, original_stage=f.root / 'stage',
                              root_sha256=f.root_pin, version_name='valid')
            self.assertFalse(output.exists())
        with self.assertRaises(Exception):
            refresh.stage(f.fresh, f.base, f.home, original_stage=f.root / 'stage',
                          root_sha256=f.root_pin, version_name='valid')
        self.assertEqual(self.immutable(f), f.immutable)

    def test_original_transaction_is_captured_inside_existing_lock(self):
        original, refresh = modules()
        import restart_production
        f = self.fixture()
        locking = refresh.control_lock
        captured = []
        @contextlib.contextmanager
        def interleaved(base, expected_identity=None):
            with locking(base, expected_identity=expected_identity):
                txn = json.loads((base / refresh.TRANSACTION).read_bytes())['transaction']
                txn['operation_id'] = 'newer-fixture-terminal-before-lock-admission'
                restart_production.Controller(base).save_transaction(txn, 'verified')
                captured.append(original.snapshot(base / refresh.TRANSACTION))
                yield
        with patch.object(refresh, 'control_lock', interleaved):
            self.go(f)
        receipt = json.loads((f.base / refresh.RECEIPT).read_bytes())
        self.assertEqual(receipt['original_transaction'], captured[0])
        self.assertNotEqual(captured[0], f.original_transaction)
        self.recover(f)
        self.assertEqual(original.snapshot(f.base / refresh.TRANSACTION), captured[0])

    def test_removed_lock_at_open_is_not_recreated(self):
        _, refresh = modules()
        for operation in ('install', 'recover'):
            with self.subTest(operation=operation):
                f = self.fixture()
                if operation == 'recover':
                    self.go(f)
                before = (f.base / refresh.TRANSACTION).read_bytes()
                locking = refresh.control_lock
                hit = []
                def remove_at_open(base, expected_identity=None):
                    hit.append(True)
                    (base / 'control.lock').unlink()
                    return locking(base, expected_identity=expected_identity)
                with patch.object(refresh, 'control_lock', side_effect=remove_at_open), \
                        patch.object(refresh, 'atomic_write', wraps=refresh.atomic_write) as writes:
                    with self.assertRaises(Exception):
                        (self.go if operation == 'install' else self.recover)(f)
                    writes.assert_not_called()
                self.assertEqual(hit, [True])
                self.assertFalse((f.base / 'control.lock').exists())
                self.assertEqual((f.base / refresh.TRANSACTION).read_bytes(), before)

    def test_cli_requires_explicit_scope_and_pins(self):
        _, refresh = modules()
        f = self.fixture()
        args = ['install', '--stage', str(f.fresh), '--base', str(f.base), '--home', str(f.home),
                '--root-sha256', f.root_pin, '--stage-sha256', f.stage_pin, '--approve']
        with self.assertRaises(Exception):
            refresh.main(args + ['--root-sha256', f.root_pin])
        result = refresh.main(args)
        self.assertEqual(result['status'], 'installed')
        self.recover(f)
        self.assert_restored(f)

    def test_real_return_restore_crash_boundaries_and_default_fail_closed(self):
        # Reuse the parent's actual installed-controller composition fixture; no
        # future verified transaction is invented by these installer tests.
        from test_control_refresh_composition import ControlRefreshCompositionTests
        original, refresh = modules()
        class PowerLoss(BaseException):
            pass
        targets = (refresh.JOURNAL, refresh.JOURNAL, *refresh.MANAGEMENT, refresh.JOURNAL, refresh.TRANSACTION)
        for boundary, name in enumerate(targets):
            for after in (False, True):
                with self.subTest(boundary=boundary, name=name, after=after):
                    c = ControlRefreshCompositionTests()
                    c.setUp()
                    try:
                        c.activate()
                        self.assertEqual(c.return_exact()['status'], 'verified')
                        proof = original.snapshot(c.f.base / refresh.TRANSACTION)
                        write = refresh.atomic_write
                        hits = []
                        def fault(path, data):
                            hits.append(Path(path).name)
                            if len(hits) - 1 == boundary:
                                if not after:
                                    raise PowerLoss()
                                write(path,data)
                                raise PowerLoss()
                            write(path,data)
                        with patch.object(refresh, 'atomic_write', side_effect=fault):
                            with self.assertRaises(PowerLoss):
                                c.restore()
                        self.assertEqual(hits, list(targets[:boundary + 1]))
                        c.assert_artifacts_unchanged()
                        c.restore()
                        payload = json.loads((c.f.base / refresh.JOURNAL).read_bytes())['payload']
                        self.assertEqual(payload['return_proof'], proof)
                        self.assertEqual((c.f.base / refresh.TRANSACTION).read_bytes(), c.original_transaction)
                        c.restore()
                    finally:
                        c.doCleanups()
        c = ControlRefreshCompositionTests()
        c.setUp()
        try:
            c.activate()
            self.assertEqual(c.return_exact()['status'], 'verified')
            kwargs = dict(stage_sha256=c.stage_pin, root_sha256=c.root_pin, refresh_sha256=c.refresh_pin, approve=True)
            with patch.object(refresh, 'atomic_write', wraps=refresh.atomic_write) as writes:
                with self.assertRaisesRegex(AssertionError, 'Offline boundary'):
                    refresh.restore(c.fresh, c.f.base, c.f.home, **kwargs)  # host tripwire: real default, not True
                writes.assert_not_called()
            c.restore()
        finally:
            c.doCleanups()


def guarded_main():
    """Runnable stdlib entry point; guard BEFORE importing any production modules."""
    import ctypes
    import socket
    import subprocess
    import tempfile
    import urllib.request
    scratch = Path(os.environ['TMPDIR']).resolve()
    require_isolated = all(Path(os.environ[k]).resolve().is_relative_to(scratch) for k in
                           ('HOME', 'HERMES_HOME', 'HERMES_WEBUI_STATE_DIR'))
    if not require_isolated:
        raise RuntimeError('Isolated HOME/state must be children of explicit TMPDIR')
    tempfile.tempdir = str(scratch)
    repository = Path(__file__).resolve().parents[2]
    read_roots = (scratch, repository, Path(sys.prefix).resolve(), Path(sys.base_prefix).resolve())
    def audit(event, args):
        if event == 'open' and isinstance(args[0], (str, bytes, os.PathLike)):
            path = Path(os.fsdecode(args[0])).absolute().resolve()
            mode, flags = args[1:3]
            writing = (isinstance(mode, str) and any(c in mode for c in 'wax+')) or (
                isinstance(flags, int) and bool(flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC)))
            allowed = (scratch,) if writing else read_roots
            if not any(path.is_relative_to(root) for root in allowed):
                raise AssertionError('Offline file scope violation: ' + str(path))
        if event in {'os.system', 'os.fork', 'os.posix_spawn', 'os.exec', 'os.kill', 'socket.connect', 'ctypes.dlopen'}:
            raise AssertionError('Offline process/native/network event: ' + event)
        if event == 'import' and args[0].split('.')[0] in {'run_agent', 'hermes_cli', 'webui', 'gateway'}:
            raise AssertionError('Application import forbidden')
    sys.addaudithook(audit)
    def forbidden(*args, **kwargs):
        raise AssertionError('Offline boundary: host/native/network execution forbidden')
    with contextlib.ExitStack() as stack:
        for obj, name in ((subprocess, 'Popen'), (subprocess, 'run'), (subprocess, 'check_output'),
                          (os, 'system'), (ctypes, 'CDLL'), (ctypes, 'PyDLL'),
                          (socket, 'socket'), (socket, 'create_connection'), (urllib.request, 'urlopen')):
            stack.enter_context(patch.object(obj, name, side_effect=forbidden))
        sys.dont_write_bytecode = True
        import hashlib
        inputs = [*repository.joinpath('scripts/production_control').glob('*.py'),
                  *Path(__file__).parent.glob('*.py')]
        before = {str(p.relative_to(repository)): hashlib.sha256(p.read_bytes()).hexdigest() for p in inputs}
        class CountedResult(unittest.TextTestResult):
            subtests = 0
            def addSubTest(self, test, subtest, error):
                self.subtests += 1
                super().addSubTest(test, subtest, error)
        suite = unittest.defaultTestLoader.loadTestsFromTestCase(RefreshTests)
        output = io.StringIO()
        result = unittest.TextTestRunner(stream=output, verbosity=2, resultclass=CountedResult).run(suite)
        after = {str(p.relative_to(repository)): hashlib.sha256(p.read_bytes()).hexdigest() for p in inputs}
        print(output.getvalue())
        print(json.dumps(dict(tests=result.testsRun, subtests=result.subtests,
                              failures=len(result.failures), errors=len(result.errors),
                              python=sys.version, success=result.wasSuccessful() and before == after,
                              inputs_unchanged=before == after, input_sha256=before), sort_keys=True))
        return 0 if result.wasSuccessful() and before == after else 1


if __name__ == '__main__':
    raise SystemExit(guarded_main())
