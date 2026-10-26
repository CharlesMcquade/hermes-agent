"""Real controller/pending/native contracts with a disposable simulated OS."""
import copy
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import safe_pending_activation as engine
import watchdog as pending
from restart_production import ControlError, save_json
import test_pending_user_restart as fixtures


class EngineTests(unittest.TestCase):
    def setUp(self):
        scratch = os.environ.get('TMPDIR')
        if not scratch or not Path(scratch).is_dir():
            raise RuntimeError('Tests require an explicit existing TMPDIR scratch fixture')
        temp_patch = patch.object(tempfile, 'tempdir', scratch)
        temp_patch.start()
        self.addCleanup(temp_patch.stop)
        self.f = fixtures.PendingTests()
        self.f.setUp()
        self.addCleanup(self.f.doCleanups)
        self.c, self.host, self.clock = self.f.c, self.f.host, self.f.clock
        self.events = []
        self.scheduled = True
        self.sleep_hook = None
        self.c.sleep = self.sleep
        self.host.kickstart = self.kick
        self.check_hook = None

    def stage(self):
        self.f.select()
        self.pin = self.f.pin
        self.receipt = (self.c.base / pending.RECEIPT).read_bytes()
        self.fence = self.c.transaction_path.read_bytes()

    def checkpoint(self, phase, **fields):
        self.events.append((phase, fields))
        if self.check_hook:
            self.check_hook(phase, fields)

    def kick(self, target):
        role = self.host.service(target)
        self.assertEqual(self.events[-1][0], 'before_kick')
        self.assertEqual(self.events[-1][1]['service'], role)
        self.host.calls.append(('kickstart', role))
        self.f.launch(role, new=self.c.manifest_path.read_bytes() != self.f.old)

    def sleep(self, duration):
        self.clock.sleep(duration)
        if self.sleep_hook:
            self.sleep_hook()
        if self.scheduled:
            # Emulate a separate scheduled daemon, only while the engine yields.
            # A nonblocking lock acquisition proves the engine released its lock.
            import fcntl
            with (self.c.base / 'control.lock').open('rb') as fd:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                fcntl.flock(fd, fcntl.LOCK_UN)
            with self.c.locked():
                pending.observe(self.c, self.pin)

    def run_engine(self, **kwargs):
        options = dict(service_timeout=4, settle_timeout=12, stable_seconds=2)
        options.update(kwargs)
        return engine.run_activation(self.c, pending, self.pin, self.checkpoint, **options)

    def test_order_health_assets_native_and_natural_settlement(self):
        self.stage()
        result = self.run_engine()
        self.assertEqual(result['status'], 'verified')
        self.assertEqual(self.host.calls, [('kickstart', 'webui'), ('kickstart', 'agent')])
        self.assertEqual(result['settlement']['candidate_identity'], result['proof']['process_identity'])
        self.assertEqual((self.c.base / pending.RECEIPT).read_bytes(), self.receipt)
        self.assertEqual(self.c.transaction_path.read_bytes(), self.fence)

    def test_no_watchdog_forced_by_engine(self):
        self.stage()
        self.scheduled = False
        with patch.object(pending, 'tick', side_effect=AssertionError('forced tick')), \
             patch.object(pending, 'observe', side_effect=AssertionError('private observe')):
            with self.assertRaisesRegex(RuntimeError, 'settlement timeout'):
                self.run_engine()
        self.assertFalse((self.c.base / pending.RESULT).exists())

    def test_waiting_for_watchdog_leaves_real_process_lock_available(self):
        import subprocess
        import sys

        self.stage()
        self.f.launch('webui')
        self.f.launch('agent')
        self.scheduled = False
        retained = self.c.retained_file
        lock_results = []

        def probe_result(path):
            if path == self.c.base / pending.RESULT:
                # A separate OS process, not the simulated scheduler's sleep
                # hook: result polling must not monopolize the publisher lock.
                probe = subprocess.run([
                    sys.executable, '-I', '-B', '-c',
                    'import fcntl,sys; f=open(sys.argv[1], "rb"); '
                    'fcntl.flock(f, fcntl.LOCK_EX | fcntl.LOCK_NB)',
                    str(self.c.base / 'control.lock'),
                ], capture_output=True, timeout=10)
                lock_results.append(probe.returncode)
            return retained(path)

        for observation in (None, {'status': 'candidate_observed'},
                            {'status': 'verified', 'receipt_sha256': 'foreign'}):
            with self.subTest(observation=observation):
                if observation is not None:
                    save_json(self.c.base / pending.RESULT, observation)
                lock_results.clear()
                with patch.object(self.c, 'retained_file', side_effect=probe_result), \
                     patch.object(self.c, 'preflight', wraps=self.c.preflight) as preflight, \
                     patch.object(self.c, 'snapshot', wraps=self.c.snapshot) as snapshot:
                    with self.assertRaisesRegex(RuntimeError, 'settlement timeout'):
                        engine._settle(self.c, pending, self.pin, 'new', 4, 1)
                self.assertTrue(lock_results)
                self.assertEqual(set(lock_results), {0}, 'watchdog publisher was locked out')
                preflight.assert_not_called()
                snapshot.assert_not_called()

    def _hold_lock_in_other_process(self, seconds):
        import subprocess
        import sys
        proc = subprocess.Popen([
            sys.executable, '-I', '-B', '-c',
            'import fcntl,sys,time; f=open(sys.argv[1], "rb"); '
            'fcntl.flock(f, fcntl.LOCK_EX); print("held", flush=True); time.sleep(float(sys.argv[2]))',
            str(self.c.base / 'control.lock'), str(seconds),
        ], stdout=subprocess.PIPE, text=True)
        self.addCleanup(proc.kill)
        self.assertEqual(proc.stdout.readline().strip(), 'held')
        return proc

    def test_scheduled_tick_owning_lock_is_waited_out_not_escalated(self):
        """A3 regression: a watchdog tick holding control.lock must not raise out
        of the engine (the runner used to restart the whole activation)."""
        import time as real_time
        self.stage()
        self.scheduled = False
        self.sleep_hook = lambda: real_time.sleep(0.1)
        self._hold_lock_in_other_process(1.0)
        with self.assertRaises(ControlError):
            with self.c.locked():
                pass
        with engine._patient_lock(self.c):
            pass  # acquired after the holder released, without raising
        self.assertGreaterEqual(self.c.monotonic(), 1)

    def test_lock_patience_is_bounded(self):
        self.stage()
        self.scheduled = False
        self._hold_lock_in_other_process(30)
        with self.assertRaisesRegex(ControlError, 'owns control.lock'):
            with engine._patient_lock(self.c, patience=3):
                pass

    def test_readiness_wait_yields_lock_for_a_whole_tick(self):
        """Between locked readiness probes the lock must stay free for >= 5 s,
        so a scheduled watchdog tick can run instead of reporting busy."""
        self.stage()
        self.scheduled = False
        gaps = []
        last = [None]
        real_locked = self.c.locked
        def spy_locked():
            now = self.c.monotonic()
            if last[0] is not None:
                gaps.append(now - last[0])
            last[0] = now
            return real_locked()
        with patch.object(self.c, 'locked', side_effect=spy_locked), \
             patch.object(engine, '_ready', side_effect=RuntimeError('not yet')):
            with self.assertRaisesRegex(RuntimeError, 'readiness timeout'):
                engine._wait_service(self.c, pending, self.pin, 'new', 'webui', 12)
        self.assertTrue(gaps)
        self.assertTrue(all(g >= engine.READINESS_YIELD_SECONDS for g in gaps), gaps)

    def test_missing_watchdog_proof_has_visible_phase_and_observation(self):
        self.stage()
        self.scheduled = False
        with self.assertRaisesRegex(RuntimeError, 'settlement timeout'):
            self.run_engine()
        waiting = [fields for phase, fields in self.events if phase == 'awaiting_watchdog']
        self.assertTrue(waiting, 'post-restart settlement must not be a silent phase')
        self.assertEqual(waiting[0]['observation'], 'missing')
        self.assertGreaterEqual(waiting[-1]['elapsed_seconds'], 0)
        self.assertEqual(self.host.calls, [('kickstart', 'webui'), ('kickstart', 'agent')])

    def test_partial_resumption_skips_exact_webui(self):
        self.stage()
        self.f.launch('webui')
        result = self.run_engine()
        self.assertTrue(result['services']['webui']['skipped_kick'])
        self.assertEqual(self.host.calls, [('kickstart', 'agent')])

    def test_equivalent_role_skips_even_when_watchdog_classifies_old(self):
        self.f.new['services']['agent'] = copy.deepcopy(self.f.f.manifest['services']['agent'])
        save_json(self.f.candidate, self.f.new)
        self.stage()
        result = self.run_engine()
        self.assertTrue(result['services']['agent']['skipped_kick'])
        self.assertEqual(result['settlement']['running']['agent'], 'old')
        self.assertEqual(self.host.calls, [('kickstart', 'webui')])

    def test_invalid_pin_and_selector_no_signals(self):
        self.stage()
        with self.assertRaises(ControlError):
            engine.run_activation(self.c, pending, '0' * 64, self.checkpoint)
        self.c.manifest_path.write_bytes(self.f.old)
        with self.assertRaisesRegex(RuntimeError, 'selector mismatch'):
            self.run_engine()
        self.assertEqual(self.host.calls, [])

    def test_unknown_healthy_owner_refused(self):
        self.stage()
        self.f.f.processes[201]['argv'].append('--foreign')
        with self.assertRaisesRegex(ControlError, 'Unknown pending'):
            self.run_engine()
        self.assertEqual(self.host.calls, [])

    def test_unreadable_owner_is_not_absent(self):
        self.stage()
        self.host.process_identity = lambda pid: (_ for _ in ()).throw(OSError('unreadable'))
        with self.assertRaisesRegex(OSError, 'unreadable'):
            self.run_engine()
        self.assertEqual(self.host.calls, [])

    def test_guards_rechecked_after_checkpoint(self):
        self.stage()
        def change(phase, fields):
            self.c.manifest_path.write_bytes(self.f.old)
        self.check_hook = change
        with self.assertRaisesRegex(RuntimeError, 'selector mismatch'):
            self.run_engine()
        self.assertEqual(self.host.calls, [])

    def test_guards_rechecked_between_services(self):
        self.stage()
        kick = self.kick
        def change(target):
            kick(target)
            self.c.manifest_path.write_bytes(self.f.old)
        self.host.kickstart = change
        with self.assertRaisesRegex(RuntimeError, 'selector mismatch'):
            self.run_engine()
        self.assertEqual(self.host.calls, [('kickstart', 'webui')])

    def test_wrong_child_after_kick_is_not_healthy_success(self):
        self.stage()
        self.scheduled = False
        kick = self.kick
        def wrong(target):
            kick(target)
            self.f.f.processes[self.host.jobs['webui']['pid'] + 1]['argv'] = ['foreign']
        self.host.kickstart = wrong
        with self.assertRaisesRegex(RuntimeError, 'webui readiness timeout'):
            self.run_engine()
        self.assertEqual(self.host.calls, [('kickstart', 'webui')])

    def test_transient_missing_job_after_kick_retried_without_duplicate_signal(self):
        self.stage()
        job = self.host.job
        missing = [0]
        kick = self.kick
        def transient(target):
            kick(target)
            missing[0] = 2
        def read(target):
            if missing[0]:
                missing[0] -= 1
                raise ControlError('Missing launchd job')
            return job(target)
        self.host.kickstart, self.host.job = transient, read
        # Readiness probes are spaced READINESS_YIELD_SECONDS apart (lock yield).
        self.assertEqual(self.run_engine(service_timeout=20)['status'], 'verified')
        self.assertEqual(self.host.calls, [('kickstart', 'webui'), ('kickstart', 'agent')])

    def test_assets_gate_gateway(self):
        self.stage()
        self.scheduled = False
        self.host.asset_bad = True
        with self.assertRaisesRegex(RuntimeError, 'Served asset mismatch'):
            self.run_engine()
        self.assertEqual(self.host.calls, [('kickstart', 'webui')])

    def test_forged_or_stale_scheduled_result_never_completes(self):
        self.stage()
        self.scheduled = False
        self.f.launch('webui')
        self.f.launch('agent')
        with self.c.locked():
            pending.observe(self.c, self.pin)
        self.clock.sleep(2)
        with self.c.locked():
            good = pending.observe(self.c, self.pin)
        for field, value in [('operation_id', 'foreign'), ('receipt_sha256', '0' * 64),
                             ('selected', 'old'), ('candidate_identity', {}),
                             ('process_identity', {}), ('status', 'transition')]:
            with self.subTest(field=field):
                save_json(self.c.base / pending.RESULT, dict(good, **{field: value}))
                with self.assertRaisesRegex(RuntimeError, 'settlement timeout'):
                    self.run_engine(settle_timeout=4)
        self.assertEqual(self.host.calls, [])

    def test_rollback_restores_process_pair_in_order_and_preserves_authority(self):
        self.stage()
        self.f.launch('webui')
        self.f.launch('agent')
        result = engine.rollback_pending(self.c, pending, self.pin, self.checkpoint)
        self.assertEqual(result['status'], 'rolled_back')
        self.assertEqual(self.c.manifest_path.read_bytes(), self.f.old)
        self.assertEqual(self.host.calls, [('kickstart', 'webui'), ('kickstart', 'agent')])
        self.assertEqual(self.events[0][0], 'before_restore_selection')
        self.assertEqual((self.c.base / pending.RECEIPT).read_bytes(), self.receipt)
        self.assertEqual(self.c.transaction_path.read_bytes(), self.fence)
        self.c.snapshot(self.f.f.manifest, self.c.definitions(self.f.f.manifest))

    def test_rollback_unknown_owner_leaves_selection_unchanged(self):
        self.stage()
        before = self.c.manifest_path.read_bytes()
        self.f.f.processes[101]['argv'] = ['unknown']
        with self.assertRaises(ControlError):
            engine.rollback_pending(self.c, pending, self.pin, self.checkpoint)
        self.assertEqual(self.c.manifest_path.read_bytes(), before)
        self.assertEqual(self.host.calls, [])

    def test_webui_regression_at_gateway_signal_boundary_blocks_gateway(self):
        self.stage()
        def regress(phase, fields):
            if fields.get('service') == 'agent':
                self.host.asset_bad = True
        self.check_hook = regress
        with self.assertRaisesRegex(RuntimeError, 'Served asset mismatch'):
            self.run_engine()
        self.assertEqual(self.host.calls, [('kickstart', 'webui')])

    def test_revocation_at_signal_boundary_blocks_kick(self):
        self.stage()
        def revoke(phase, fields):
            save_json(self.c.base / 'revoked-releases.json', dict(
                schema_version=1, release_ids=['candidate'], content_digests=[]))
        self.check_hook = revoke
        with self.assertRaises(ControlError):
            self.run_engine()
        self.assertEqual(self.host.calls, [])
        # Explicit fallback remains usable with a revoked candidate.
        self.check_hook = None
        self.assertEqual(engine.rollback_pending(
            self.c, pending, self.pin, self.checkpoint)['status'], 'rolled_back')

    def test_rollback_preflight_failure_does_not_restore_selector(self):
        self.stage()
        before = self.c.manifest_path.read_bytes()
        with patch.object(self.c, 'preflight', side_effect=ControlError('bad fallback inventory')):
            with self.assertRaisesRegex(ControlError, 'bad fallback inventory'):
                engine.rollback_pending(self.c, pending, self.pin, self.checkpoint)
        self.assertEqual(self.c.manifest_path.read_bytes(), before)
        self.assertEqual(self.host.calls, [])

    def test_rollback_timeout_does_not_claim_selector_only_success(self):
        self.stage()
        self.f.launch('webui')
        self.f.launch('agent')
        self.scheduled = False
        self.host.kickstart = lambda target: self.host.calls.append(('failed-kick', target))
        with self.assertRaisesRegex(RuntimeError, 'webui readiness timeout'):
            engine.rollback_pending(self.c, pending, self.pin, self.checkpoint)
        self.assertEqual(self.c.manifest_path.read_bytes(), self.f.old)
        self.assertEqual(len(self.host.calls), 1)
        self.assertEqual((self.c.base / pending.RECEIPT).read_bytes(), self.receipt)

    def test_down_owner_rollback_fails_closed_without_bootstrap_authority(self):
        self.stage()
        self.host.jobs['agent']['pid'] = None
        with self.assertRaises((ControlError, KeyError)):
            engine.rollback_pending(self.c, pending, self.pin, self.checkpoint)
        self.assertEqual(self.host.calls, [])


if __name__ == '__main__':
    unittest.main()
