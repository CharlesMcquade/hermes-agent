"""Offline only: real filesystem transactions and identity validators, fake OS I/O."""
import json
import os
from pathlib import Path
import struct
import time
import unittest
import weakref
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


def inventory_fixture(per_root_bytes):
    """Real inventory-shaped rows and short paths, without any on-disk tree."""
    _, stage = h.base.helpers()
    row = [0o100600, os.getuid(), None, 'a' * 64]
    def encoded(inventory):
        return len(stage.encoded({'dependencies': {k: inventory for k in ('a', 'b', 'c')}}))
    overhead = encoded({})
    unit = encoded({'00000000.py': row, '00000001.py': row}) - encoded({'00000000.py': row})
    count = (per_root_bytes * 3 - overhead) // unit
    assert 0 < count < 100000
    return {f'{i:08d}.py': row for i in range(count)}


class KernelFixture(h.Live):
    """Only OS observation/command seam is fake; never override identity/cleanup."""
    instances = weakref.WeakSet()

    def __init__(self, root, plan, failure=None):
        self.instances.add(self)
        self.pending = {}
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
        (case / 'agent.out').write_text('\n'.join(json.dumps(r) for r in records[:3]))
        self.pending[case] = (time.monotonic(), records[3:])

    def tick(self):
        # Model the frozen worker: no permission result without matching GO;
        # lifetime starts at ready, not when the harness finishes its validation.
        for case, (started, completion) in list(self.pending.items()):
            if time.monotonic() - started >= 30:
                raise TimeoutError('fixture worker lifetime expired')
            if (case / 'GO').exists():
                rows = [json.loads(s) for s in (case / 'agent.out').read_text().splitlines()]
                assert h.read_json(case / 'GO') == rows[2]
                with (case / 'agent.out').open('a') as stream:
                    stream.write('\n' + '\n'.join(json.dumps(r) for r in completion))
                del self.pending[case]

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
        self.pending.clear()

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
        wait = h.base.wait
        def scheduled(predicate, seconds):
            def step():
                for adapter in list(KernelFixture.instances):
                    if adapter.root.is_relative_to(self.f.top):
                        adapter.tick()
                return predicate()
            return wait(step, seconds)
        scheduler = patch.object(h.base, 'wait', side_effect=scheduled)
        scheduler.start()
        self.addCleanup(scheduler.stop)

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

    def test_late_first_signal_restoration_durably_invalidates(self):
        import signal
        for recovery in (False, True):
            for restored_sig in (signal.SIGINT, signal.SIGTERM):
                for sig in (signal.SIGINT, signal.SIGTERM):
                    for after in (False, True):
                        with self.subTest(recovery=recovery, restored_sig=restored_sig, sig=sig, after=after):
                            self.root = self.home / '.hermes/experiments' / f'late-{recovery}-{restored_sig}-{sig}-{after}'
                            p = self.prepare()
                            adapter = KernelFixture(self.root, p)
                            if recovery:
                                h.run(self.root, live=True, runner=self.runner, adapter=adapter,
                                      dependency=lambda *_: True)
                            actual = signal.signal
                            callers = {s: signal.getsignal(s) for s in (signal.SIGINT, signal.SIGTERM)}
                            mask = signal.pthread_sigmask(signal.SIG_BLOCK, [])
                            hit, delivered = [], []
                            def caller(*args):
                                delivered.append(args[0])
                            for s in callers:
                                actual(s, caller)
                            def swap(s, handler):
                                inject = s == restored_sig and handler is caller and not hit
                                if inject and not after:
                                    hit.append(True)
                                    signal.raise_signal(sig)
                                result = actual(s, handler)
                                if inject and after:
                                    hit.append(True)
                                    signal.raise_signal(sig)
                                return result
                            try:
                                with patch.object(h.signal, 'signal', side_effect=swap):
                                    report = (h.recover(self.root, live=True, runner=self.runner, adapter=adapter)
                                              if recovery else h.run(self.root, live=True, runner=self.runner,
                                              adapter=adapter, dependency=lambda *_: True))
                                names = list(self.root.glob('recovery-*.json')) if recovery else [self.root / 'result.json']
                                names = [n for n in names if not n.name.endswith('.settled.json')]
                                self.assertEqual(len(names), 1)
                                stored = h.read_json(names[0])
                                invalidators = [h.read_json(n) for n in self.root.glob('interrupt-*.json')]
                                self.assertEqual(hit, [True])
                                self.assertEqual(report['status'], 'failed')
                                self.assertTrue(stored['status'] == 'failed' or any(
                                    r == dict(status='failed', interrupted=True, report=names[0].name)
                                    for r in invalidators), 'No durable invalidation of successful report')
                                self.assertFalse(delivered)
                                self.assertTrue(all(signal.getsignal(s) is caller for s in callers))
                                self.assertEqual(signal.pthread_sigmask(signal.SIG_BLOCK, []), mask)
                                self.assertTrue(report['restored'])
                                self.assertFalse(adapter.loaded or adapter.processes)
                                self.assertEqual(h.base.tree(self.app), self.original)
                            finally:
                                for s, handler in callers.items():
                                    actual(s, handler)
                                signal.pthread_sigmask(signal.SIG_SETMASK, mask)

    def test_raising_caller_cannot_escape_partial_handler_restoration(self):
        import signal
        for recovery in (False, True):
            for boundary in (signal.SIGINT, signal.SIGTERM):
                with self.subTest(recovery=recovery, boundary=boundary):
                    self.root = self.home / '.hermes/experiments' / f'raising-{recovery}-{boundary}'
                    p = self.prepare()
                    adapter = KernelFixture(self.root, p)
                    if recovery:
                        h.run(self.root, live=True, runner=self.runner, adapter=adapter, dependency=lambda *_: True)
                    actual = signal.signal
                    previous = {s: signal.getsignal(s) for s in (signal.SIGINT, signal.SIGTERM)}
                    mask = signal.pthread_sigmask(signal.SIG_BLOCK, [])
                    hit, errors = [], []
                    def caller(*_):
                        raise KeyboardInterrupt('caller must not run during partial restoration')
                    for s in previous:
                        actual(s, caller)
                    def swap(s, handler):
                        result = actual(s, handler)
                        if s == boundary and handler is caller and not hit:
                            hit.append(True)
                            signal.raise_signal(signal.SIGINT)
                        return result
                    try:
                        with patch.object(h.signal, 'signal', side_effect=swap):
                            try:
                                report = (h.recover(self.root, live=True, runner=self.runner, adapter=adapter)
                                          if recovery else h.run(self.root, live=True, runner=self.runner,
                                          adapter=adapter, dependency=lambda *_: True))
                            except KeyboardInterrupt:
                                errors.append('caller escaped')
                        self.assertTrue(all(signal.getsignal(s) is caller for s in previous),
                                        'Transaction handler leaked into caller')
                        self.assertFalse(errors)
                        self.assertEqual(report['status'], 'failed')
                        receipts = [h.read_json(n) for n in self.root.glob('interrupt-*.json')]
                        self.assertEqual(len(receipts), 1)
                        name = receipts[0]['report']
                        self.assertEqual(receipts[0], dict(status='failed', interrupted=True, report=name))
                        self.assertTrue(name.startswith('recovery-') if recovery else name == 'result.json')
                        self.assertTrue((self.root / name).is_file())
                        self.assertEqual(signal.pthread_sigmask(signal.SIG_BLOCK, []), mask)
                        self.assertFalse(adapter.loaded or adapter.processes)
                        self.assertEqual(h.base.tree(self.app), self.original)
                    finally:
                        for s, handler in previous.items():
                            actual(s, handler)
                        signal.pthread_sigmask(signal.SIG_SETMASK, mask)

    def test_terminal_boundary_pending_signals_belong_to_exact_owner(self):
        import signal
        for recovery in (False, True):
            for sig in (signal.SIGINT, signal.SIGTERM):
                for boundary in ('block-before', 'block-after', 'decision-before', 'decision-after',
                                 'settlement-before', 'settlement-after', 'unmask-before', 'unmask-after'):
                    with self.subTest(recovery=recovery, sig=sig, boundary=boundary):
                        self.root = self.home / '.hermes/experiments' / f'boundary-{recovery}-{sig}-{boundary}'
                        p = self.prepare()
                        adapter = KernelFixture(self.root, p)
                        if recovery:
                            h.run(self.root, live=True, runner=self.runner, adapter=adapter, dependency=lambda *_: True)
                        previous = {s: signal.getsignal(s) for s in (signal.SIGINT, signal.SIGTERM)}
                        actual_mask, actual_pending, actual_write = signal.pthread_sigmask, signal.sigpending, h.durable
                        mask = actual_mask(signal.SIG_BLOCK, [])
                        hit, delivered = [], []
                        def caller(s, *_):
                            self.assertTrue(all(signal.getsignal(n) is caller for n in previous))
                            delivered.append(s)
                        for s in previous:
                            signal.signal(s, caller)
                        def inject(at):
                            if at == boundary and not hit:
                                hit.append(at)
                                signal.raise_signal(sig)
                        def masking(how, values):
                            label = 'block' if how == signal.SIG_BLOCK else 'unmask'
                            inject(label + '-before')
                            result = actual_mask(how, values)
                            inject(label + '-after')
                            return result
                        def pending():
                            inject('decision-before')
                            result = actual_pending()
                            inject('decision-after')
                            return result
                        def writing(root, name, value):
                            if name.startswith('settled-'):
                                inject('settlement-before')
                            actual_write(root, name, value)
                            if name.startswith('settled-'):
                                inject('settlement-after')
                        try:
                            with patch.object(signal, 'pthread_sigmask', side_effect=masking), \
                                    patch.object(signal, 'sigpending', side_effect=pending), \
                                    patch.object(h, 'durable', side_effect=writing):
                                report = (h.recover(self.root, live=True, runner=self.runner, adapter=adapter)
                                          if recovery else h.run(self.root, live=True, runner=self.runner,
                                          adapter=adapter, dependency=lambda *_: True))
                            name = next(self.root.glob('recovery-*.json')).name if recovery else 'result.json'
                            owned = boundary in ('block-before', 'block-after', 'decision-before')
                            self.assertEqual(hit, [boundary])
                            self.assertEqual(report['status'], 'failed' if owned else ('restored' if recovery else 'completed'))
                            self.assertEqual(h.report_status(self.root, name), report['status'])
                            self.assertEqual(delivered, [] if owned else [sig])
                            self.assertEqual(actual_mask(signal.SIG_BLOCK, []), mask)
                            self.assertFalse(adapter.loaded or adapter.processes)
                            self.assertEqual(h.base.tree(self.app), self.original)
                        finally:
                            for s, handler in previous.items():
                                signal.signal(s, handler)
                            actual_mask(signal.SIG_SETMASK, mask)

    def test_postdecision_raising_caller_does_not_mutate_settled_report(self):
        import signal
        for recovery in (False, True):
            for sig in (signal.SIGINT, signal.SIGTERM):
                with self.subTest(recovery=recovery, sig=sig):
                    self.root = self.home / '.hermes/experiments' / f'postdecision-{recovery}-{sig}'
                    p = self.prepare()
                    adapter = KernelFixture(self.root, p)
                    if recovery:
                        h.run(self.root, live=True, runner=self.runner, adapter=adapter, dependency=lambda *_: True)
                    previous = {s: signal.getsignal(s) for s in (signal.SIGINT, signal.SIGTERM)}
                    mask = signal.pthread_sigmask(signal.SIG_BLOCK, [])
                    actual, reports = h.durable, []
                    def caller(*_):
                        self.assertTrue(all(signal.getsignal(s) is caller for s in previous))
                        raise KeyboardInterrupt('caller-owned after settlement')
                    def writing(root, name, value):
                        actual(root, name, value)
                        if root == self.root and (name == 'result.json' or name.startswith('recovery-')):
                            reports.append((name, value))
                        if name.startswith('settled-'):
                            signal.raise_signal(sig)
                    for s in previous:
                        signal.signal(s, caller)
                    try:
                        with patch.object(h, 'durable', side_effect=writing), self.assertRaises(KeyboardInterrupt):
                            if recovery:
                                h.recover(self.root, live=True, runner=self.runner, adapter=adapter)
                            else:
                                h.run(self.root, live=True, runner=self.runner, adapter=adapter, dependency=lambda *_: True)
                        self.assertEqual(len(reports), 1)
                        name, report = reports[0]
                        self.assertEqual(report['status'], 'restored' if recovery else 'completed')
                        self.assertEqual(h.report_status(self.root, name), report['status'])
                        self.assertTrue(all(signal.getsignal(s) is caller for s in previous))
                        self.assertEqual(signal.pthread_sigmask(signal.SIG_BLOCK, []), mask)
                        self.assertFalse(adapter.loaded or adapter.processes)
                        self.assertEqual(h.base.tree(self.app), self.original)
                    finally:
                        for s, handler in previous.items():
                            signal.signal(s, handler)
                        signal.pthread_sigmask(signal.SIG_SETMASK, mask)

    def test_terminal_publication_faults_never_leave_authoritative_success(self):
        import signal
        for recovery in (False, True):
            for boundary in ('report-before', 'report-after', 'interrupt-before', 'interrupt-after',
                             'settlement-before', 'settlement-after'):
                with self.subTest(recovery=recovery, boundary=boundary):
                    self.root = self.home / '.hermes/experiments' / f'fault-{recovery}-{boundary}'
                    p = self.prepare()
                    adapter = KernelFixture(self.root, p)
                    if recovery:
                        h.run(self.root, live=True, runner=self.runner, adapter=adapter, dependency=lambda *_: True)
                    actual, hit = h.durable, []
                    previous = {s: signal.getsignal(s) for s in (signal.SIGINT, signal.SIGTERM)}
                    mask = signal.pthread_sigmask(signal.SIG_BLOCK, [])
                    report_names = []
                    def writing(root, name, value):
                        if root != self.root:
                            return actual(root, name, value)
                        label = ('report' if name == 'result.json' or name.startswith('recovery-') else
                                 'interrupt' if name.startswith('interrupt-') else
                                 'settlement' if name.startswith('settled-') else None)
                        if label == 'report':
                            report_names.append(name)
                        if label and boundary == label + '-before':
                            hit.append(boundary)
                            raise OSError('fixture write fault')
                        actual(root, name, value)
                        if label == 'report':
                            signal.raise_signal(signal.SIGINT)
                        if label and boundary == label + '-after':
                            hit.append(boundary)
                            raise OSError('fixture after-write fault')
                    with patch.object(h, 'durable', side_effect=writing), self.assertRaises(OSError):
                        if recovery:
                            h.recover(self.root, live=True, runner=self.runner, adapter=adapter)
                        else:
                            h.run(self.root, live=True, runner=self.runner, adapter=adapter, dependency=lambda *_: True)
                    self.assertEqual(hit, [boundary])
                    self.assertEqual(len(report_names), 1)
                    name = report_names[0]
                    if boundary in ('report-before', 'interrupt-before', 'interrupt-after', 'settlement-before'):
                        from restart_production import ControlError
                        with self.assertRaisesRegex(ControlError, 'Missing path:'):
                            h.report_status(self.root, name)
                    else:
                        self.assertEqual(h.report_status(self.root, name), 'failed')
                    self.assertTrue(all(signal.getsignal(s) is previous[s] for s in previous))
                    self.assertEqual(signal.pthread_sigmask(signal.SIG_BLOCK, []), mask)
                    self.assertFalse(adapter.loaded or adapter.processes)
                    self.assertEqual(h.base.tree(self.app), self.original)
                    before = set(self.root.glob('recovery-*.json'))
                    later = h.recover(self.root, live=True, runner=self.runner, adapter=adapter)
                    later_name = (set(self.root.glob('recovery-*.json')) - before).pop().name
                    self.assertEqual(later['status'], 'restored')
                    self.assertEqual(h.report_status(self.root, later_name), 'restored')
                    self.assertTrue(all(h.read_json(n)['report'] == name for n in self.root.glob('interrupt-*.json')))

    def test_caller_mask_pending_and_ignored_dispositions_are_restored(self):
        import signal
        for ignored in (False, True):
            with self.subTest(ignored=ignored):
                self.root = self.home / '.hermes/experiments' / f'caller-mask-{ignored}'
                p = self.prepare()
                adapter = KernelFixture(self.root, p)
                previous = signal.getsignal(signal.SIGTERM)
                mask = signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGTERM} if not ignored else set())
                pending = signal.sigpending
                hit = []
                def observe():
                    hit.append(True)
                    signal.raise_signal(signal.SIGTERM)
                    return pending()
                try:
                    if ignored:
                        signal.signal(signal.SIGTERM, signal.SIG_IGN)
                    with patch.object(signal, 'sigpending', side_effect=observe):
                        report = h.run(self.root, live=True, runner=self.runner, adapter=adapter, dependency=lambda *_: True)
                    self.assertEqual(hit, [True])
                    self.assertEqual(report['status'], 'failed' if ignored else 'completed')
                    self.assertEqual(h.report_status(self.root, 'result.json'), report['status'])
                    self.assertEqual(signal.getsignal(signal.SIGTERM), signal.SIG_IGN if ignored else previous)
                    self.assertEqual(signal.pthread_sigmask(signal.SIG_BLOCK, []),
                                     mask if ignored else mask | {signal.SIGTERM})
                    self.assertEqual(signal.SIGTERM in pending(), not ignored)
                    if not ignored:
                        signal.sigwait({signal.SIGTERM})
                finally:
                    signal.signal(signal.SIGTERM, previous)
                    signal.pthread_sigmask(signal.SIG_SETMASK, mask)

    def test_terminal_evidence_schema_fails_closed(self):
        self.run_it()
        decision = self.root / 'settled-result.json'
        good = decision.read_bytes()
        for row in ({}, {'report': 'other.json', 'status': 'completed'},
                    {'report': 'result.json', 'status': True},
                    {'report': 'result.json', 'status': 'completed', 'extra': 1}):
            decision.write_text(json.dumps(row))
            with self.subTest(row=row), self.assertRaises(ValueError):
                h.report_status(self.root, 'result.json')
        decision.write_bytes(good)
        invalidator = self.root / ('interrupt-' + 'a' * 32 + '.json')
        for row in ({}, {'report': 'result.json', 'status': 'failed', 'interrupted': 1},
                    {'report': '../result.json', 'status': 'failed', 'interrupted': True},
                    {'report': 'result.json', 'status': 'failed', 'interrupted': True, 'extra': 1}):
            invalidator.write_text(json.dumps(row))
            with self.subTest(row=row), self.assertRaises(ValueError):
                h.report_status(self.root, 'result.json')
        invalidator.write_text(json.dumps(dict(report='result.json', status='failed', interrupted=True)))
        self.assertEqual(h.report_status(self.root, 'result.json'), 'failed')

    def test_frozen_host_failures_restore_and_recover(self):
        for event in (dict(event='host-refused', error_type='DecodingError'),
                      dict(event='spawn-error', errno=2)):
            for recovery in (False, True):
                with self.subTest(event=event, recovery=recovery):
                    self.root = self.home / '.hermes/experiments' / (event['event'] + str(recovery))
                    p = self.prepare()
                    adapter = KernelFixture(self.root, p, 'cleanup' if recovery else None)
                    def failed_bootstrap(name, case):
                        adapter.loaded[name] = 800000
                        (case / 'agent.out').write_text(json.dumps(event))
                        raise OSError('frozen host exited')
                    with patch.object(adapter, 'bootstrap', side_effect=failed_bootstrap):
                        result = h.run(self.root, live=True, runner=self.runner, adapter=adapter,
                                       dependency=lambda *_: True)
                    self.assertEqual(result['status'], 'failed')
                    if recovery:
                        self.assertFalse(result['restored'])
                        adapter.failure = None
                        result = h.recover(self.root, live=True, runner=self.runner, adapter=adapter)
                    self.assertTrue(result['restored'])
                    self.assertEqual(h.base.tree(self.app), self.original)
                    self.assertFalse(adapter.loaded or adapter.processes)
                    self.assertFalse((h.case_dir(self.root, 0) / 'GO').exists())

    def test_failure_event_schema_is_closed_and_never_success(self):
        p = self.prepare()
        case = h.case_dir(self.root, 0)
        for row in (dict(event='host-refused', error_type=7),
                    dict(event='host-refused', error_type='private exception content'),
                    dict(event='host-refused', error_type='DecodingError', message='private'),
                    dict(event='spawn-error', errno=True), dict(event='spawn-error', errno='2'),
                    dict(event='spawn-error', errno=0), dict(event='spawn-error', errno=2, extra=0)):
            (case / 'agent.out').write_text(json.dumps(row))
            with self.subTest(row=row), self.assertRaises(ValueError):
                h.events(case)
        adapter = KernelFixture(self.root, p)
        h.base.durable(self.root, 'swap-receipt.json', {})
        since = time.time() - 1
        h.base.durable(case, 'intent.json', dict(index=0, target=h.target(p, 0), since=since))
        adapter.bootstrap(h.target(p, 0), case)
        with (case / 'agent.out').open('a') as stream:
            stream.write('\n' + json.dumps(dict(event='spawn-error', errno=2)))
        with self.assertRaises(ValueError):
            h.identity(case, self.root, p, 0, adapter, since)

    def test_first_interrupt_reconciles_every_phase_and_restores_handlers(self):
        import signal
        phases = ('body', 'case-clean', 'final-clean', 'restore-build', 'restore-original', 'report', 'report-after')
        for sig in (signal.SIGINT, signal.SIGTERM):
            for phase in phases:
                with self.subTest(signal=sig, phase=phase):
                    self.root = self.home / '.hermes/experiments' / f'interrupt-{sig}-{phase}'
                    p = self.prepare()
                    adapter = KernelFixture(self.root, p)
                    hit = []
                    clean, move, durable = adapter.clean, h.base.move, h.base.durable
                    def fire():
                        if not hit:
                            hit.append(phase)
                            signal.raise_signal(sig)
                    def cleaning(name):
                        if phase == 'case-clean' or (phase == 'final-clean' and
                                (h.case_dir(self.root, 11) / 'result.json').exists()):
                            fire()
                        return clean(name)
                    def moving(source, dest):
                        if (h.case_dir(self.root, 11) / 'result.json').exists():
                            if phase == 'restore-build' and source == self.app:
                                fire()
                            if phase == 'restore-original' and source == self.root / 'original.app':
                                fire()
                        return move(source, dest)
                    def writing(root, name, value):
                        if phase == 'body' and name == 'GO':
                            fire()
                        if phase == 'report' and root == self.root and name == 'result.json':
                            fire()
                        result = durable(root, name, value)
                        if phase == 'report-after' and root == self.root and name == 'result.json':
                            fire()
                        return result
                    def caller_handler(*_):
                        raise KeyboardInterrupt()
                    previous = {s: signal.signal(s, caller_handler) for s in (signal.SIGINT, signal.SIGTERM)}
                    try:
                        with patch.object(adapter, 'clean', side_effect=cleaning), \
                                patch.object(h.base, 'move', side_effect=moving), \
                                patch.object(h.base, 'durable', side_effect=writing):
                            try:
                                result = h.run(self.root, live=True, runner=self.runner, adapter=adapter,
                                               dependency=lambda *_: True)
                            except KeyboardInterrupt:
                                self.fail('First interrupt escaped reconciliation')
                        self.assertEqual(hit, [phase])
                        self.assertTrue(list(self.root.glob('interrupt-*.json')))
                        self.assertEqual(result['status'], 'failed')
                        self.assertTrue(result['restored'])
                        self.assertEqual(h.base.tree(self.app), self.original)
                        self.assertFalse(adapter.loaded or adapter.processes)
                        self.assertTrue(all(signal.getsignal(s) is caller_handler for s in previous))
                        intended = {h.target(p, i) for i in range(len(h.MATRIX))
                                    if (h.case_dir(self.root, i) / 'intent.json').exists()}
                        self.assertTrue({n for op, n in adapter.calls if op == 'clean'} <= intended)
                        self.assertEqual(adapter.n, 1 if phase in ('body', 'case-clean') else 12)
                    finally:
                        for s, handler in previous.items():
                            signal.signal(s, handler)
                        # Permit independent subtests on the unfixed baseline.
                        if (self.root / 'original.app').exists():
                            adapter.failure = None
                            h.cleanup(self.root, p, adapter)
                            h.restore(self.root, p, self.runner)

    def test_first_interrupt_during_recover_is_deferred(self):
        import signal
        for sig in (signal.SIGINT, signal.SIGTERM):
            for phase in ('clean', 'restore-build', 'restore-original', 'report', 'report-after'):
                with self.subTest(signal=sig, phase=phase):
                    self.root = self.home / '.hermes/experiments' / f'recover-{sig}-{phase}'
                    p, adapter, result = self.run_it('cleanup')
                    self.assertFalse(result['restored'])
                    adapter.failure = None
                    clean, move, durable = adapter.clean, h.base.move, h.base.durable
                    hit = []
                    def fire():
                        if not hit:
                            hit.append(phase)
                            signal.raise_signal(sig)
                    def cleaning(name):
                        if phase == 'clean':
                            fire()
                        return clean(name)
                    def moving(source, dest):
                        if phase == 'restore-build' and source == self.app:
                            fire()
                        if phase == 'restore-original' and source == self.root / 'original.app':
                            fire()
                        return move(source, dest)
                    def writing(root, name, value):
                        if phase == 'report' and name.startswith('recovery-'):
                            fire()
                        result = durable(root, name, value)
                        if phase == 'report-after' and name.startswith('recovery-'):
                            fire()
                        return result
                    def caller_handler(*_):
                        raise KeyboardInterrupt()
                    previous = {s: signal.signal(s, caller_handler) for s in (signal.SIGINT, signal.SIGTERM)}
                    try:
                        with patch.object(adapter, 'clean', side_effect=cleaning), \
                                patch.object(h.base, 'move', side_effect=moving), \
                                patch.object(h.base, 'durable', side_effect=writing):
                            try:
                                result = h.recover(self.root, live=True, runner=self.runner, adapter=adapter)
                            except KeyboardInterrupt:
                                self.fail('First recovery interrupt escaped reconciliation')
                        self.assertEqual(hit, [phase])
                        self.assertTrue(result['restored'])
                        self.assertEqual(result['status'], 'failed')
                        self.assertEqual(h.base.tree(self.app), self.original)
                        self.assertFalse(adapter.loaded or adapter.processes)
                        self.assertEqual(adapter.n, 1)  # Recovery never resumes execution.
                        self.assertTrue(all(signal.getsignal(s) is caller_handler for s in previous))
                    finally:
                        for s, handler in previous.items():
                            signal.signal(s, handler)
                        if (self.root / 'original.app').exists():
                            h.cleanup(self.root, p, adapter)
                            h.restore(self.root, p, self.runner)

    def test_oversized_inputs_refuse_before_compile_or_sign(self):
        # Three distinct inventory roots, without allocating a large file tree.
        for size in (1_500_000, 1_240_000):
            with self.subTest(size=size):
                self.root = self.home / '.hermes/experiments' / f'oversize-{size}'
                self.compilers.clear()
                self.signs.clear()
                inventory = inventory_fixture(size)
                with patch.object(h, 'dependency_inventory', return_value=inventory):
                    with self.assertRaisesRegex(ValueError, 'receipt|Receipt'):
                        self.prepare()
                self.assertFalse(self.compilers or self.signs)
                self.assertFalse((self.root / 'prepared.json').exists())
                self.assertEqual(h.base.tree(self.app), self.original)

    def test_swap_receipt_bound_precedes_all_app_mutation(self):
        p = self.prepare()
        adapter = KernelFixture(self.root, p)
        old, saved = h.base.baseline(self.base)
        saved = dict(saved, oversized='x' * (4 * 1024 * 1024))
        with patch.object(h.base, 'baseline', return_value=(old, saved)), \
                patch.object(h.base, 'unchanged'), patch.object(h.base, 'move', wraps=h.base.move) as move:
            with self.assertRaisesRegex(ValueError, 'receipt|Receipt'):
                h.run(self.root, live=True, runner=self.runner, adapter=adapter, dependency=lambda *_: True)
            move.assert_not_called()
        self.assertFalse((self.root / 'swap-receipt.json').exists())
        self.assertEqual(h.base.tree(self.app), self.original)

    def test_receipt_encoding_boundary_and_near_limit_preparation(self):
        self.root.mkdir(mode=0o700)
        value = {'padding': '\u2603'}
        value['padding'] += 'x' * (h.RECEIPT_LIMIT - h.receipt_size(value))
        self.assertEqual(h.receipt_size(value), h.RECEIPT_LIMIT)
        h.durable(self.root, 'exact.json', value)
        self.assertEqual((self.root / 'exact.json').stat().st_size, h.RECEIPT_LIMIT)
        self.assertEqual(h.read_json(self.root / 'exact.json'), value)
        value['padding'] += 'x'
        with self.assertRaises(ValueError):
            h.durable(self.root, 'over.json', value)
        self.assertFalse((self.root / 'over.json').exists())
        # The same inventory representation that refused above still admits
        # substantial inputs below the conservative pre-sign envelope.
        self.root = self.home / '.hermes/experiments/near-limit'
        inventory = inventory_fixture(1_210_000)
        with patch.object(h, 'dependency_inventory', return_value=inventory):
            p = self.prepare()
            self.assertEqual(h.load_plan(self.root), p)
        self.assertGreater(h.receipt_size(p), h.RECEIPT_LIMIT - h.SIGNING_RECEIPT_RESERVE - 100_000)
        self.assertLessEqual(h.receipt_size(p), h.RECEIPT_LIMIT)
        self.assertEqual(h.base.tree(self.app), self.original)

    def test_unexpected_signer_inventory_never_publishes_oversized_plan(self):
        tree = h.base.tree
        def expansive(path):
            value = tree(path)
            if path == self.root / 'builds/B.app':
                value['unexpected-signer-output'] = 'x' * h.RECEIPT_LIMIT
            return value
        with patch.object(h.base, 'tree', side_effect=expansive), self.assertRaises(ValueError):
            self.prepare()
        self.assertEqual(len(self.signs), 2)
        self.assertFalse((self.root / 'prepared.json').exists())
        self.assertEqual(h.base.tree(self.app), self.original)

    def test_slow_validation_is_outside_worker_lifetime(self):
        p = self.prepare()
        adapter = KernelFixture(self.root, p)
        clock = [1000.0]
        verify = h.verify_inputs
        observations = []
        def slow(root, plan):
            observations.append(bool(adapter.pending))
            clock[0] += 31
            return verify(root, plan)
        with patch.object(h.time, 'monotonic', side_effect=lambda: clock[0]), \
                patch.object(h, 'verify_inputs', side_effect=slow):
            result = h.run(self.root, live=True, runner=self.runner, adapter=adapter,
                           dependency=lambda *_: True)
        self.assertEqual(result['status'], 'completed')
        self.assertFalse(any(observations), 'Full inventory executed with worker waiting')
        self.assertTrue(result['restored'])
        self.assertEqual(adapter.n, len(h.MATRIX))

    def test_expired_or_changed_worker_never_receives_go(self):
        for failure in ('expired', 'dead', 'changed', 'premature'):
            with self.subTest(failure=failure):
                self.root = self.home / '.hermes/experiments' / ('gate-' + failure)
                p = self.prepare()
                adapter = KernelFixture(self.root, p)
                clock = [1000.0]
                identity = h.identity
                hit = []
                def observed(*args):
                    ready = identity(*args)
                    if ready and not hit:
                        hit.append(failure)
                        if failure == 'expired':
                            clock[0] += 31
                        elif failure == 'dead':
                            del adapter.processes[ready['pid']]
                        elif failure == 'changed':
                            adapter.processes[ready['pid']]['argv'] = ['foreign']
                        else:
                            case = args[0]
                            _, completion = adapter.pending[case]
                            with (case / 'agent.out').open('a') as stream:
                                stream.write('\n' + json.dumps(completion[0]))
                    return ready
                with patch.object(h.time, 'monotonic', side_effect=lambda: clock[0]), \
                        patch.object(h, 'identity', side_effect=observed):
                    result = h.run(self.root, live=True, runner=self.runner, adapter=adapter,
                                   dependency=lambda *_: True)
                self.assertEqual(hit, [failure])
                self.assertEqual(result['status'], 'failed')
                self.assertTrue(result['restored'])
                self.assertFalse((h.case_dir(self.root, 0) / 'GO').exists())
                self.assertFalse(adapter.loaded or adapter.processes)

    def test_point_of_use_drift_and_budget_never_publish_go(self):
        for failure in ('slow-gate', 'copied-worker', 'dependency-root', 'oversized-worker', 'slow-intent'):
            with self.subTest(failure=failure):
                self.root = self.home / '.hermes/experiments' / failure
                p = self.prepare()
                adapter = KernelFixture(self.root, p)
                clock = [1000.0]
                gate, durable = h.verify_gate_inputs, h.base.durable
                hit = []
                def checking(root, plan, i, roots, deadline):
                    hit.append(failure)
                    worker = h.case_dir(root, i) / 'permission-python'
                    if failure == 'copied-worker':
                        worker.write_bytes(b'drift')
                    elif failure == 'dependency-root':
                        self.bridge.chmod(0o500)
                    elif failure == 'oversized-worker':
                        with worker.open('wb') as stream:
                            stream.truncate(65 * 1024 * 1024)
                    result = gate(root, plan, i, roots, deadline)
                    if failure == 'slow-gate':
                        clock[0] += 31
                    return result
                def writing(root, name, value):
                    if failure == 'slow-intent' and name == 'intent.json':
                        hit.append(failure)
                        clock[0] += 31
                    return durable(root, name, value)
                try:
                    with patch.object(h.time, 'monotonic', side_effect=lambda: clock[0]), \
                            patch.object(h, 'verify_gate_inputs', side_effect=checking), \
                            patch.object(h.base, 'durable', side_effect=writing):
                        result = h.run(self.root, live=True, runner=self.runner, adapter=adapter,
                                       dependency=lambda *_: True)
                    self.assertEqual(hit, [failure])
                    self.assertEqual(result['status'], 'failed')
                    self.assertTrue(result['restored'])
                    self.assertFalse((h.case_dir(self.root, 0) / 'GO').exists())
                    self.assertEqual(adapter.n, 0 if failure == 'slow-intent' else 1)
                finally:
                    self.bridge.chmod(0o700)

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
        # Execute the actual generated frozen worker with NO GO. Its timeout
        # must precede loading even the mocked permission module.
        (case / 'GO').unlink()
        calls.clear()
        with patch.object(h.base.importlib.util, 'spec_from_file_location') as load_probe, \
                patch.object(h.sys, 'argv', ['fixture', '--worker']), \
                patch.dict(os.environ, HOME=str(case / 'home'), HERMES_HOME=str(case / 'state')), \
                patch.object(h.time, 'monotonic', side_effect=[0, 31]), \
                contextlib.redirect_stdout(io.StringIO()) as waiting:
            with self.assertRaisesRegex(ValueError, 'Identity gate timeout'):
                exec(compile(h.worker_source(c), 'sealed-worker-no-go', 'exec'), {})
        load_probe.assert_not_called()
        self.assertFalse(calls)
        self.assertEqual([json.loads(line)['event'] for line in waiting.getvalue().splitlines()], ['worker-ready'])

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
