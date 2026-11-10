"""Disposable native-identity fixtures; no real app, launchctl or service execution."""
import copy
import json
import os
from pathlib import Path
import unittest
from unittest.mock import patch

import test_native_identity as native_fixture
from restart_production import ControlError, save_json
from watchdog import (RECEIPT, RESULT, decode, digest, load, observe, prepare,
                      select, tick)


class PendingTests(unittest.TestCase):
    def setUp(self):
        f = native_fixture.NativeTests()
        f.setUp()
        self.addCleanup(f.doCleanups)
        self.f = f
        self.c, self.host, self.clock, self.base = f.c, f.host, f.clock, f.base
        self.old = self.c.manifest_path.read_bytes()
        self.new = copy.deepcopy(f.manifest)
        self.new['release_id'] = 'candidate'
        for role in ('agent', 'webui'):
            self.new['services'][role]['argv'] = ['/usr/bin/python3', '-B', str(self.base / ('new-' + role + '.py'))]
            self.new['services'][role]['commit'] = 'new-' + role
        self.candidate = self.base / 'candidate.json'
        save_json(self.candidate, self.new)
        import base64
        self.c.save_transaction(dict(operation_id='previous', reload=False,
            authorization='verified-live-fallback', manifest=base64.b64encode(self.old).decode(),
            plists={s: base64.b64encode(p.read_bytes()).decode() for s, p in f.plists.items()}), 'verified')

    def stage(self):
        prepared = prepare(self.c, self.candidate, expected_old_sha256=digest(self.old),
                           expected_new_sha256=digest(self.candidate.read_bytes()), timeout=60)
        self.pin = prepared['receipt_sha256']
        return prepared

    def select(self):
        self.stage()
        return select(self.c, self.pin)

    def launch(self, role, new=True):
        # Model a user/spontaneous independent native launch with fresh birth identity.
        old_pid = self.host.jobs[role]['pid']
        pid = old_pid + 10
        manifest = self.new if new else self.f.manifest
        self.host.jobs[role]['pid'] = pid
        for before, after in ((old_pid, pid), (old_pid + 1, pid + 1)):
            value = copy.deepcopy(self.f.processes[before])
            value.update(pid=after, start_time=self.clock())
            if before == old_pid + 1:
                value.update(ppid=pid, argv=manifest['services'][role]['argv'])
            self.f.processes[after] = value
        if role == 'webui':
            self.host.listener = lambda url: {pid + 1}
            self.host.started = self.clock()
        else:
            save_json(self.base / 'gateway_state.json', dict(pid=pid+1, gateway_state='running',
                code_sha=manifest['services']['agent']['commit'], updated_at=self.clock()))

    def observation(self, **kw):
        with self.c.locked():
            return observe(self.c, self.pin, **kw)

    def test_prepare_select_and_both_user_orders_keep_watchdog_active(self):
        for first, second in (('webui', 'agent'), ('agent', 'webui')):
            with self.subTest(first=first):
                if hasattr(self, 'pin'):
                    self.setUp()
                self.stage()
                self.assertEqual(self.c.manifest_path.read_bytes(), self.old)
                self.assertEqual(tick(self.c, grace=0)['status'], 'healthy')
                select(self.c, self.pin)
                self.assertEqual(tick(self.c, grace=0)['pending']['status'], 'awaiting_user_restart')
                self.clock.sleep(2)
                self.launch(first)
                result = tick(self.c, grace=0)
                self.assertEqual(result['status'], 'healthy')
                self.assertEqual(result['pending']['running'][first], 'new')
                self.assertEqual(result['pending']['running'][second], 'old')
                self.launch(second)
                self.assertEqual(self.observation()['status'], 'candidate_observed')
                self.clock.sleep(2)
                self.assertEqual(self.observation()['status'], 'verified')
                self.clock.sleep(90)
                self.assertEqual(self.observation()['selected'], 'new')
                self.assertEqual(self.host.calls, [])

    def test_timeout_and_explicit_rollback_are_selection_only_even_mixed(self):
        self.select()
        self.launch('agent')
        self.clock.sleep(61)
        result = self.observation()
        self.assertEqual(result['status'], 'rollback_user_restart_required')
        self.assertEqual(self.c.manifest_path.read_bytes(), self.old)
        self.assertEqual(result['reason'], 'expired')
        # An already-admitted candidate WebUI can still arrive after rollback.
        self.launch('webui')
        self.assertEqual(self.observation(rollback=True)['selected'], 'old')
        self.assertEqual(self.host.calls, [])

    def test_pending_lock_tolerates_volume_reid_but_not_replacement(self):
        self.stage()
        lock = self.base / 'control.lock'
        original_stat = type(lock).stat
        def changed_stat(field, delta):
            def observe(path, *args, **kwargs):
                value = original_stat(path, *args, **kwargs)
                if Path(path) == lock:
                    fields = list(value)
                    fields[field] += delta
                    return os.stat_result(fields)
                return value
            return observe
        original_device = lock.stat().st_dev
        with patch.object(type(lock), 'stat', new=changed_stat(2, 17)):
            self.assertEqual(lock.stat().st_dev, original_device + 17)
            _, _, _, unchanged = load(self.c, self.pin)
            unchanged()
        with patch.object(type(lock), 'stat', new=changed_stat(1, 1)):
            with self.assertRaisesRegex(ControlError, 'Pending lock changed'):
                load(self.c, self.pin)

    def test_all_pending_retained_identities_tolerate_volume_reid(self):
        self.stage()
        original = self.c.retained_file
        def reidentified(path):
            raw, (target, ancestors) = original(path)
            def rotate(record):
                return [record[0] + 17, *record[1:]]
            return raw, (rotate(target), [rotate(item) for item in ancestors])
        with patch.object(self.c, 'retained_file', side_effect=reidentified):
            _, _, _, unchanged = load(self.c, self.pin)
            unchanged()

    def test_legacy_pending_receipt_requires_explicit_recovery(self):
        self.stage()
        path = self.base / RECEIPT
        value = json.loads(path.read_bytes())
        value.pop('volume_uuid')
        for name in ('old', 'new', 'original_transaction'):
            value[name].pop('volume_uuid')
        for item in value['plists'].values():
            item.pop('volume_uuid')
        value['schema_version'] = 1
        save_json(path, value)
        self.pin = digest(path.read_bytes())
        with self.assertRaisesRegex(ControlError, 'Foreign pending authority'):
            load(self.c, self.pin)

    def test_pending_select_survives_volume_reid_fenced_and_unfenced(self):
        for crashed in (False, True):
            with self.subTest(crashed=crashed):
                self.setUp()
                if crashed:
                    with patch.object(self.c, 'save_transaction', side_effect=OSError('fixture crash')):
                        with self.assertRaises(OSError):
                            self.stage()
                    self.pin = digest((self.base / RECEIPT).read_bytes())
                else:
                    self.stage()
                original_stat = type(self.base).stat
                def rotated_stat(path, *args, **kwargs):
                    from types import SimpleNamespace
                    result = original_stat(path, *args, **kwargs)
                    values = {name: getattr(result, name)
                              for name in dir(result) if name.startswith('st_')}
                    values['st_dev'] += 17
                    return SimpleNamespace(**values)
                with patch.object(type(self.base), 'stat', new=rotated_stat):
                    self.assertEqual(select(self.c, self.pin)['status'],
                                     'selected_awaiting_user_restart')

    def test_bad_pin_drift_reuse_and_generic_restart_fail_without_signals(self):
        self.stage()
        with self.assertRaisesRegex(ControlError, 'pin mismatch'):
            select(self.c, '0' * 64)
        self.f.processes[201]['start_time'] += .1
        with self.assertRaisesRegex(ControlError, 'identity changed'):
            select(self.c, self.pin)
        with self.assertRaisesRegex(ControlError, 'Pending user restart'):
            self.c.restart(yes=True)
        with self.c.locked(), self.assertRaisesRegex(ControlError, 'pointer-only'):
            self.c.recover_locked()
        self.c.manifest_path.write_bytes(self.old + b' ')
        with self.assertRaisesRegex(ControlError, 'selection drift'):
            self.observation(rollback=True)
        self.assertEqual(self.host.calls, [])

    def test_unknown_identity_and_deep_failure_never_kill_old_webui(self):
        self.select()
        self.host.deep = False
        self.assertEqual(tick(self.c, grace=0)['status'], 'degraded')
        self.f.processes[201]['argv'] = ['foreign']
        for _ in range(3):
            self.assertEqual(tick(self.c, grace=0)['status'], 'blocked')
        self.assertEqual(self.host.calls, [])
        self.assertEqual(self.c.manifest_path.read_bytes(), self.candidate.read_bytes())

    def test_real_shallow_failure_repairs_old_only_after_restoring_old_selection(self):
        self.select()
        self.host.shallow = False
        self.assertEqual(tick(self.c, grace=0)['status'], 'suspect')
        # A fake kick records exactly which selector a real native launch would consume.
        selections = []
        self.host.kickstart = lambda target: selections.append(self.c.manifest_path.read_bytes())
        self.assertEqual(tick(self.c, grace=0)['status'], 'restart_requested')
        self.assertEqual(selections, [self.old])

    def test_revocation_and_rollback_cas_never_change_foreign_selector(self):
        self.select()
        save_json(self.base / 'revoked-releases.json', dict(schema_version=1,
                  release_ids=['candidate'], content_digests=[]))
        self.assertEqual(self.observation()['reason'], 'revoked')
        self.assertEqual(self.c.manifest_path.read_bytes(), self.old)
        self.c.manifest_path.write_bytes(b'{"foreign":true}')
        with self.assertRaises(ControlError):
            self.observation(rollback=True)
        self.assertEqual(self.c.manifest_path.read_bytes(), b'{"foreign":true}')
        self.assertEqual(self.host.calls, [])

    def test_plist_and_receipt_tampering_block_even_when_selector_is_new(self):
        self.select()
        self.f.plists['webui'].write_bytes(self.f.plists['webui'].read_bytes() + b' ')
        self.assertEqual(tick(self.c, grace=0)['status'], 'blocked')
        self.assertEqual(self.host.calls, [])

    def test_crash_after_receipt_before_fence_is_blocked_not_recovered(self):
        with patch.object(self.c, 'save_transaction', side_effect=OSError('fixture crash')):
            with self.assertRaises(OSError):
                self.stage()
        self.assertTrue((self.base / RECEIPT).exists())
        self.assertEqual(tick(self.c, grace=0)['status'], 'blocked')
        self.assertEqual(self.c.manifest_path.read_bytes(), self.old)
        self.assertEqual(self.host.calls, [])
        pin = digest((self.base / RECEIPT).read_bytes())
        self.assertEqual(select(self.c, pin)['status'], 'selected_awaiting_user_restart')
        self.assertEqual(select(self.c, pin)['status'], 'already_selected')
        self.assertEqual(self.host.calls, [])

    def test_rollback_has_no_authority_to_restart_serving_candidate_webui(self):
        self.select()
        self.launch('webui')
        self.observation(rollback=True)
        self.host.shallow = False
        self.assertEqual(tick(self.c, grace=0)['status'], 'suspect')
        self.assertEqual(tick(self.c, grace=0)['status'], 'blocked')
        self.assertEqual(self.host.calls, [])

    def test_refreshed_six_file_bundle_pending_fence_composition(self):
        import test_control_refresh_runtime as refresh_fixture
        f = refresh_fixture.RefreshRuntimeTests()
        f.setUp()
        self.addCleanup(f.doCleanups)
        self.assertEqual(f.activate()['status'], 'verified')  # Mock host only.
        before_calls = list(f.host.calls)
        before = f.c.manifest_path.read_bytes()
        candidate = json.loads(before)
        candidate['release_id'] = 'pending-fixture'
        path = f.base / 'pending-candidate.json'
        save_json(path, candidate)
        prepared = prepare(f.c, path, expected_old_sha256=digest(before),
                           expected_new_sha256=digest(path.read_bytes()))
        pin = prepared['receipt_sha256']
        self.assertEqual(tick(f.c, grace=0)['status'], 'healthy')
        self.assertEqual(select(f.c, pin)['status'], 'selected_awaiting_user_restart')
        self.assertEqual(f.host.calls, before_calls)
        self.assertEqual(f.c.read_transaction()['pending_restart_sha256'], pin)
        self.assertEqual(json.loads(f.c.transaction_path.read_bytes())['schema_version'], 2)
        for path, expected in f.protected.items():
            self.assertEqual((path.read_bytes(), path.stat().st_ino, path.stat().st_mode), expected)

    def test_missing_receipt_keeps_transaction_fence_active(self):
        self.select()
        (self.base / RECEIPT).unlink()
        self.c.pending_restart_sha256 = None  # A fresh scheduled invocation.
        self.assertEqual(tick(self.c, grace=0)['status'], 'blocked')
        with self.assertRaisesRegex(ControlError, 'Pending user restart'):
            self.c.restart(yes=True)
        self.assertEqual(self.host.calls, [])

    def test_receipt_bytes_are_pinned_independently_of_transaction(self):
        self.select()
        path = self.base / RECEIPT
        value = json.loads(path.read_bytes())
        value['deadline'] += 1
        save_json(path, value)
        self.assertEqual(tick(self.c, grace=0)['status'], 'blocked')
        self.assertEqual(self.host.calls, [])

    def test_receipt_and_transaction_tampering_fail_closed(self):
        self.select()
        txn = self.c.read_transaction()
        assert txn is not None
        txn['operation_id'] = 'foreign'
        self.c.save_transaction(txn, txn['phase'])
        self.assertEqual(tick(self.c, grace=0)['status'], 'blocked')
        self.assertEqual(self.host.calls, [])


if __name__ == '__main__':
    unittest.main()
