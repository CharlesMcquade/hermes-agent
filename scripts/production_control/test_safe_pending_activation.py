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
        self.assertEqual(self.run_engine()['status'], 'verified')
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
