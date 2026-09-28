"""Offline only: real filesystem transactions and identity validators, fake OS I/O."""
import json
import os
from pathlib import Path
import struct
import time
import unittest
from unittest.mock import patch

import verify_production_continuity as h
import test_production_permissions as fixtures


def macho(text=b'AAAA', uuid=b'U' * 16):
    # Real-format segment/section/load commands; not real executable code.
    offset = 32 + 152 + 24 + 16
    header = struct.pack('<8I', 0xFEEDFACF, 0x0100000C, 0, 2, 3, offset - 32, 0, 0)
    segment = struct.pack('<II16s4Q4I', 0x19, 152, b'__TEXT', 0, offset + len(text),
                          0, offset + len(text), 5, 5, 1, 0)
    section = struct.pack('<16s16sQQ8I', b'__text', b'__TEXT', offset, len(text),
                          offset, 2, 0, 0, 0x80000400, 0, 0, 0)
    return (header + segment + section + struct.pack('<II16s', 0x1b, 24, uuid)
            + struct.pack('<4I', 0x1d, 16, offset + len(text), 16) + text + b'S' * 16)


class KernelFixture(h.Live):
    """Only OS observation/command seam is fake; never override identity/cleanup."""
    def __init__(self, root, plan, failure=None):
        self.root, self.plan, self.failure = root, plan, failure
        self.loaded, self.processes, self.groups = {}, {}, {}
        self.calls, self.n = [], 0

    def absent(self, name):
        return name not in self.loaded

    def bootstrap(self, name, case):
        self.calls.append(('bootstrap', name))
        intent = h.read_json(case / 'intent.json')
        assert intent['target'] == name
        assert (self.root / 'swap-receipt.json').exists()
        index = intent['index']
        self.n += 1
        host, supervisor, guard, worker = range(800000 + index * 10, 800004 + index * 10)
        self.loaded[name] = host
        role = h.MATRIX[index][1]
        exe = str(Path(self.plan['home']) / 'Applications/Verity.app' / h.base.BINARY)
        python = self.plan['bootstrap']
        wp = str(case / 'permission-python')
        rows = [(host, 1, exe, [exe, role]),
                (supervisor, host, python, [python, '-I', '-B', str(self.root / 'production_launcher.py'),
                                          role, '--manifest', str(self.root / 'production-release.json')]),
                (guard, host, exe, [exe, '--group-guard', '7', '8']),
                (worker, supervisor, wp, [wp, '-S', '-s', '-P', '-u', '-B',
                                         str(case / 'production_launcher.py'), '--worker'])]
        for pid, ppid, executable, argv in rows:
            self.processes[pid] = dict(pid=pid, ppid=ppid, uid=os.getuid(), executable=executable,
                                       argv=argv, start_time=time.time())
            self.groups[pid] = host
        if self.failure == 'before-event':
            raise OSError('partial bootstrap before first event')
        if self.failure == 'identity':
            self.processes[worker]['ppid'] = 22
        results = [dict(event='permission', name='Camera', status='authorized', allowed=True,
                        requested=False, error_type=None)]
        records = [dict(event='service-host', pid=host, ppid=1, pgid=host, child_pid=supervisor,
                        guard_pid=guard, role=role),
                   dict(event='supervisor-ready', pid=supervisor, ppid=host, pgid=host, worker=worker),
                   dict(event='worker-ready', pid=worker, ppid=supervisor, pgid=host, nonce=f'{index:048x}'),
                   dict(event='worker-complete', exit_code=0, results=results),
                   dict(event='supervisor-exit', exit_code=0),
                   dict(event='service-exit', status=0, child_pid=supervisor)]
        if self.failure == 'supervisor':
            records[-2]['exit_code'] = 7
        (case / 'agent.out').write_text('\n'.join(json.dumps(r) for r in records))

    def job_pid(self, name):
        return self.loaded[name]

    def process(self, pid):
        return dict(self.processes[pid])

    def group(self, pid):
        return self.groups[pid]

    def running_signature(self, pid):
        return self.failure != 'signer'

    def census(self):
        return {pid: (r['uid'], self.groups[pid]) for pid, r in self.processes.items()}

    def clean(self, name):
        self.calls.append(('clean', name))
        if self.failure == 'cleanup':
            raise OSError('cleanup refused')
        self.loaded.pop(name, None)
        self.processes.clear()
        self.groups.clear()

    def exited(self, p):
        return {'exit_code': 0}


class ContinuityTests(unittest.TestCase):
    def setUp(self):
        self.f = fixtures.PermissionTests('test_prepare_is_only_staging_and_child_is_independent')
        self.f.setUp()
        self.addCleanup(self.f.doCleanups)
        for name in ('root', 'base', 'home', 'app', 'python', 'python_home', 'bridge'):
            setattr(self, name, getattr(self.f, name))
        (self.app / h.base.BINARY).write_bytes(macho())
        self.original = h.base.tree(self.app)
        self.runtime314 = self.f.top / 'runtime314'
        (self.runtime314 / 'bin').mkdir(parents=True, mode=0o700)
        (self.runtime314 / 'bin/python3.14').write_bytes(b'offline314')
        (self.runtime314 / 'bin/python3.14').chmod(0o700)
        self.compilers, self.signs = [], []

    def runner(self, argv, **kwargs):
        if argv[0] == '/usr/bin/xcrun':
            self.compilers.append((argv, kwargs))
            self.assertIn('-O', argv)
            for key in ('HOME', 'TMPDIR', 'CLANG_MODULE_CACHE_PATH', 'SWIFT_MODULECACHE_PATH'):
                self.assertTrue(Path(kwargs['env'][key]).is_relative_to(self.root))
            self.assertNotIn('PYTHONPATH', kwargs['env'])
            Path(argv[-1]).write_bytes(macho(b'BBBB'))
        else:
            self.f.runner(argv, **kwargs)
            if '--sign' in argv:
                self.signs.append(argv)

    def prepare(self):
        return h.prepare(self.root, self.base, self.home, self.python,
                         {'3.11': self.python_home, '3.14': self.runtime314},
                         {'3.11': self.bridge, '3.14': self.bridge}, 'Camera',
                         approve_sign=True, runner=self.runner)

    def run_it(self, failure=None):
        plan = self.prepare()
        adapter = KernelFixture(self.root, plan, failure)
        report = h.run(self.root, live=True, runner=self.runner, adapter=adapter, dependency=lambda *_: True)
        return plan, adapter, report

    def test_text_change_not_uuid_or_signature(self):
        self.assertEqual(h.text_section(macho()), b'AAAA')
        self.assertEqual(h.text_section(macho(uuid=b'V' * 16)), b'AAAA')
        self.assertEqual(h.text_section(macho()[:-16] + b'Z' * 16), b'AAAA')
        self.assertNotEqual(h.text_section(macho(b'BBBB')), h.text_section(macho()))
        for data in (b'', macho()[:60], fixtures.macho(), b'\0' * 400):
            with self.subTest(data=len(data)), self.assertRaises(ValueError):
                h.text_section(data)

    def test_complete_fixed_matrix_and_original_restoration(self):
        plan, adapter, report = self.run_it()
        self.assertEqual(report['status'], 'completed')
        self.assertTrue(report['cleanup_verified'] and report['restored'])
        self.assertEqual([(r['build'], r['role'], r['abi']) for r in report['cases']], list(h.MATRIX))
        self.assertEqual(h.base.tree(self.app), self.original)
        self.assertEqual(len(self.compilers), 1)
        self.assertEqual(len(self.signs), 2)
        h.preflight(self.root, self.runner)
        self.assertFalse(adapter.loaded or adapter.processes)
        for i in range(len(h.MATRIX)):
            self.assertTrue((h.case_dir(self.root, i) / 'GO').exists())
        self.assertEqual((self.root / 'builds/A.app' / h.base.SETTINGS).read_bytes(),
                         (self.root / 'builds/B.app' / h.base.SETTINGS).read_bytes())
        with self.assertRaises(ValueError):
            h.run(self.root, live=True, runner=self.runner, adapter=adapter, dependency=lambda *_: True)

    def test_failures_restore_or_retain_for_recovery(self):
        for failure in ('before-event', 'identity', 'signer', 'supervisor', 'cleanup'):
            with self.subTest(failure=failure):
                self.root = self.home / '.hermes/experiments' / failure
                plan, adapter, report = self.run_it(failure)
                self.assertEqual(report['status'], 'failed')
                self.assertEqual(report['restored'], failure != 'cleanup')
                if failure == 'cleanup':
                    self.assertEqual(h.base.tree(self.root / 'original.app'), self.original)
                    adapter.failure = None
                    with patch.object(h.base, 'unchanged') as unchanged:
                        result = h.recover(self.root, live=True, runner=self.runner, adapter=adapter)
                        self.assertTrue(result['restored'])
                        self.assertTrue(all(len(call.args) == 3 for call in unchanged.call_args_list))
                self.assertEqual(h.base.tree(self.app), self.original)

    def test_mid_build_and_mid_sign_leave_original(self):
        for failure in ('compile', 'sign-A', 'sign-B'):
            with self.subTest(failure=failure):
                self.root = self.home / '.hermes/experiments' / failure
                real = self.runner
                reached = []
                def fail(argv, **kwargs):
                    real(argv, **kwargs)
                    if argv[0] == '/usr/bin/xcrun':
                        point = 'compile'
                    elif '--sign' in argv:
                        point = 'sign-' + Path(argv[-1]).stem
                    else:
                        return
                    reached.append(point)
                    if point == failure:
                        raise OSError('injected-' + point)
                with patch.object(self, 'runner', side_effect=fail), self.assertRaisesRegex(
                    OSError, '^injected-' + failure + '$'
                ):
                    self.prepare()
                expected = ['sign-A', 'compile', 'sign-B']
                self.assertEqual(reached, expected[:expected.index(failure) + 1])
                self.assertTrue((self.root / 'prepare-start.json').exists())
                self.assertFalse((self.root / 'prepared.json').exists())
                self.assertEqual(h.base.tree(self.app), self.original)

    def test_rename_faults_after_each_mutation_recover(self):
        for position in (1, 2, 3, 4, 5, 6):
            with self.subTest(position=position):
                self.root = self.home / '.hermes/experiments' / f'rename-{position}'
                plan = self.prepare()
                adapter = KernelFixture(self.root, plan)
                move = h.base.move
                count = [0]
                def fail(a, b):
                    move(a, b)
                    count[0] += 1
                    if count[0] == position:
                        raise OSError('post-rename interrupt')
                with patch.object(h.base, 'move', side_effect=fail):
                    report = h.run(self.root, live=True, runner=self.runner, adapter=adapter,
                                   dependency=lambda *_: True)
                if not report['restored']:
                    h.recover(self.root, live=True, runner=self.runner, adapter=adapter)
                self.assertEqual(h.base.tree(self.app), self.original)

    def test_durable_intent_fault_and_report_fault(self):
        for destination in ('intent.json', 'GO', 'result.json'):
            with self.subTest(destination=destination):
                self.root = self.home / '.hermes/experiments' / destination.replace('.', '-')
                plan = self.prepare()
                adapter = KernelFixture(self.root, plan)
                durable = h.base.durable
                once = [False]
                def fail(root, name, value):
                    durable(root, name, value)
                    if name == destination and not once[0]:
                        once[0] = True
                        raise OSError('after durable write')
                with patch.object(h.base, 'durable', side_effect=fail):
                    h.run(self.root, live=True, runner=self.runner, adapter=adapter, dependency=lambda *_: True)
                self.assertEqual(h.base.tree(self.app), self.original)
                self.assertFalse(adapter.processes)

    def test_real_identity_validator_rejects_each_identity_field(self):
        p = self.prepare()
        case = h.case_dir(self.root, 0)
        h.base.durable(self.root, 'swap-receipt.json', {})
        since = time.time() - 1
        h.base.durable(case, 'intent.json', dict(index=0, target=h.target(p, 0), since=since))
        adapter = KernelFixture(self.root, p)
        adapter.bootstrap(h.target(p, 0), case)
        self.assertTrue(h.identity(case, self.root, p, 0, adapter, since))
        for pid in list(adapter.processes):
            for key, value in (('pid', 7), ('uid', -1), ('ppid', 7), ('argv', ['wrong']),
                               ('executable', '/wrong'), ('start_time', float('nan')),
                               ('start_time', since - 20)):
                with self.subTest(pid=pid, key=key):
                    before = dict(adapter.processes[pid])
                    adapter.processes[pid][key] = value
                    with self.assertRaises(ValueError):
                        h.identity(case, self.root, p, 0, adapter, since)
                    adapter.processes[pid] = before

    def test_absence_does_not_trust_missing_events_or_job(self):
        p = self.prepare()
        adapter = KernelFixture(self.root, p)
        pid = 700000
        r = dict(pid=pid, uid=os.getuid(), executable=str(self.root / 'any-executable'), argv=[],
                 ppid=1, start_time=time.time())
        adapter.processes[pid] = r
        adapter.groups[pid] = pid
        self.assertFalse(h.artifact_absent(self.root, p, adapter))
        with patch.object(adapter, 'process', side_effect=OSError('unreadable')):
            self.assertFalse(h.artifact_absent(self.root, p, adapter))
        adapter.processes.clear()
        self.assertTrue(h.artifact_absent(self.root, p, adapter))
        for i in (0, 1):
            h.base.durable(h.case_dir(self.root, i), 'intent.json',
                           dict(index=i, target=h.target(p, i), since=time.time()))
        attempted = []
        def clean(name):
            attempted.append(name)
            if name == h.target(p, 0):
                raise OSError('earlier target unknown')
        with patch.object(adapter, 'clean', side_effect=clean), self.assertRaises(ValueError):
            h.cleanup(self.root, p, adapter)
        self.assertEqual(attempted, [h.target(p, 0), h.target(p, 1)])

    def test_optins_and_exclusions_do_not_touch_inputs(self):
        with patch.object(h.base, 'helpers', side_effect=AssertionError('must not inspect')):
            for fn in (h.run, h.recover):
                with self.assertRaises(ValueError):
                    fn(self.root)
            for name in ('Location', 'Location Diagnostic', 'Local Network', 'arbitrary'):
                with self.assertRaises(ValueError):
                    h.prepare(self.root, self.base, self.home, self.python, {}, {}, name, approve_sign=True)
        self.assertFalse(self.root.exists())

    def test_sealed_worker_rejects_arbitrary_invocation(self):
        p = self.prepare()
        for i in range(len(h.MATRIX)):
            source = (h.case_dir(self.root, i) / 'production_launcher.py').read_bytes()
            with patch.object(h.sys, 'argv', ['fixture', 'webui']), self.assertRaises(ValueError):
                exec(compile(source, 'sealed-fixture', 'exec'), {})
        with patch.object(h.sys, 'argv', ['fixture', 'agent']), self.assertRaises(ValueError):
            exec(compile(h.launcher_source(self.root, p['configs']), 'sealed-fixture', 'exec'), {})

    def test_tamper_inputs_and_identical_optimization_fail_closed(self):
        p = self.prepare()
        launcher = self.root / 'production_launcher.py'
        launcher.write_bytes(launcher.read_bytes() + b'\n')
        with self.assertRaises(ValueError):
            h.preflight(self.root, self.runner)
        self.assertEqual(h.base.tree(self.app), self.original)
        self.root = self.home / '.hermes/experiments/no-code-change'
        runner = self.runner
        def same(argv, **kwargs):
            runner(argv, **kwargs)
            if argv[0] == '/usr/bin/xcrun':
                Path(argv[-1]).write_bytes(macho(uuid=b'V' * 16))
        with patch.object(self, 'runner', side_effect=same), self.assertRaises(ValueError):
            self.prepare()
        self.assertFalse((self.root / 'prepared.json').exists())

    def test_final_report_failure_and_saved_original_drift(self):
        p = self.prepare()
        adapter = KernelFixture(self.root, p)
        durable = h.base.durable
        def fail(root, name, value):
            if root == self.root and name == 'result.json':
                raise OSError('final report unavailable')
            return durable(root, name, value)
        with patch.object(h.base, 'durable', side_effect=fail), self.assertRaises(OSError):
            h.run(self.root, live=True, runner=self.runner, adapter=adapter, dependency=lambda *_: True)
        self.assertEqual(h.base.tree(self.app), self.original)
        self.assertTrue(h.recover(self.root, live=True, runner=self.runner, adapter=adapter)['restored'])
        self.root = self.home / '.hermes/experiments/saved-original-drift'
        p, adapter, result = self.run_it('cleanup')
        self.assertFalse(result['restored'])
        saved = self.root / 'original.app' / h.base.BINARY
        saved.write_bytes(b'foreign')
        adapter.failure = None
        with self.assertRaises(ValueError):
            h.recover(self.root, live=True, runner=self.runner, adapter=adapter)
        self.assertEqual(saved.read_bytes(), b'foreign')
        self.assertFalse(adapter.loaded or adapter.processes)

    def test_generated_supervisor_and_worker_execute_only_sealed_case(self):
        import contextlib
        import io
        from types import SimpleNamespace as NS
        from unittest.mock import Mock
        p = self.prepare()
        case = h.case_dir(self.root, 0)
        (case / 'intent.json').write_text('{}')
        output = io.StringIO()
        child = NS(pid=900000, wait=lambda timeout: 0)
        with patch.object(h.sys, 'argv', ['fixture', 'agent', '--manifest', str(self.root / 'production-release.json')]), \
                patch.object(h.subprocess, 'Popen', return_value=child) as popen, contextlib.redirect_stdout(output):
            with self.assertRaises(SystemExit) as done:
                exec(compile(h.launcher_source(self.root, p['configs']), 'sealed-supervisor', 'exec'), {})
            self.assertEqual(done.exception.code, 0)
        argv = popen.call_args.args[0]
        self.assertEqual(argv, [str(case / 'permission-python'), '-S', '-s', '-P', '-u', '-B',
                                str(case / 'production_launcher.py'), '--worker'])
        self.assertEqual(popen.call_args.kwargs['env']['HOME'], str(case / 'home'))
        self.assertEqual(popen.call_args.kwargs['env']['HERMES_WEBUI_STATE_DIR'], str(case / 'webui-state'))
        abi = list(h.sys.version_info[:2])
        i = next(i for i, c in enumerate(p['configs']) if c['abi'] == abi)
        c = p['configs'][i]
        case = h.case_dir(self.root, i)
        nonce = b'n' * 24
        ready = dict(event='worker-ready', pid=os.getpid(), ppid=os.getppid(), pgid=os.getpgrp(), nonce=nonce.hex())
        (case / 'GO').write_text(json.dumps(ready))
        probe = NS(FILE_PATHS={})
        calls = []
        def native(name, request):
            calls.append((name, request))
            probe.emit('permission', name=name, status='authorized', allowed=True, requested=False, error_type=None)
        probe.native = native
        spec = NS(loader=NS(exec_module=Mock()))
        with patch.object(h.base.importlib.util, 'spec_from_file_location', return_value=spec), \
                patch.object(h.base.importlib.util, 'module_from_spec', return_value=probe), \
                patch.object(os, 'urandom', return_value=nonce), \
                patch.object(h.sys, 'argv', ['fixture', '--worker']), \
                patch.object(h.sys, 'path', list(h.sys.path)), \
                patch.dict(os.environ, HOME=str(case / 'home'), HERMES_HOME=str(case / 'state')), \
                contextlib.redirect_stdout(io.StringIO()) as out:
            with self.assertRaises(SystemExit) as done:
                exec(compile(h.worker_source(c), 'sealed-worker', 'exec'), {})
            self.assertEqual(done.exception.code, 0)
        self.assertEqual(calls, [('Camera', False)])
        self.assertEqual(json.loads(out.getvalue().splitlines()[0]), ready)
        self.assertTrue(h.strict_results(json.loads(out.getvalue().splitlines()[1])['results'], 'Camera')[1])

    def test_dependency_and_finder_contracts(self):
        p = self.prepare()
        row = dict(event='permission', name='Automation: Finder', status='authorized', osstatus=0,
                   allowed=True, requested=False, error_type=None)
        self.assertTrue(h.strict_results([row], 'Automation: Finder')[1])
        self.assertFalse(h.strict_results([dict(row, status='not_determined', osstatus=-1744, allowed=None)],
                                         'Automation: Finder')[1])
        self.python.write_bytes(b'drift')
        with self.assertRaises(ValueError):
            h.preflight(self.root, self.runner)
        # Explicitly supplied bridge roots cannot smuggle an external file link.
        (self.bridge / 'escape').symlink_to(self.python)
        with self.assertRaises(ValueError):
            h.dependency_inventory(self.bridge)

    def test_strict_results_no_denial_duplicate_or_requested_pass(self):
        row = dict(event='permission', name='Camera', status='authorized', allowed=True,
                   requested=False, error_type=None)
        self.assertTrue(h.strict_results([row], 'Camera')[1])
        self.assertFalse(h.strict_results([dict(row, status='denied')], 'Camera')[1])
        for rows in ([row, row], [dict(row, requested=True)], [dict(row, extra='private')]):
            with self.assertRaises(ValueError):
                h.strict_results(rows, 'Camera')


if __name__ == '__main__':
    unittest.main()
